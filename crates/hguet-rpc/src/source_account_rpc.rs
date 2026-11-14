//! Read only *used, independently signed* source token accounts omitted by
//! simulateTransaction's token-balance-derived account snapshot.
//!
//! The caller must pass TokenSourceLimitReview produced only after verifying
//! an independently pinned Ed25519 PaymentIntent. This RPC is opt-in,
//! single-provider, read-only, bounded, and NEVER an authorization proof.
use super::{checked_result, JsonRpcTransport, RpcError};
use crate::{
    token_account_rpc::TokenAccountRpcSnapshot,
    token_account_state::{parse_token_2022_account, Token2022AccountState, MAX_ACCOUNT_BYTES},
    token_semantics::{TOKEN_2022_PROGRAM, TOKEN_PROGRAM},
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hguet_core::TokenSourceLimitReview;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const MAX_SOURCE_QUERIES: usize = 32;
const MAX_B64_BYTES: usize = MAX_ACCOUNT_BYTES.div_ceil(3) * 4 + 4;

#[derive(Debug, Clone, Serialize)]
pub struct SignedSourceAccountObservation {
    pub address: String,
    pub signed_mint: String,
    pub declared_token_program: String,
    /// token_2022, legacy_token, other_program, missing
    pub status: &'static str,
    pub state: Option<Token2022AccountState>,
    pub mint_matches_signed_scope: Option<bool>,
    pub program_matches_signed_scope: Option<bool>,
}
#[derive(Debug, Clone, Serialize)]
pub struct SignedSourceAccountRpcSnapshot {
    pub simulation_slot: u64,
    pub context_slot: u64,
    pub atomic_with_simulation: bool,
    pub accounts: Vec<SignedSourceAccountObservation>,
    pub limitation: &'static str,
}
fn valid_pubkey(value: &str) -> bool {
    bs58::decode(value)
        .into_vec()
        .map(|raw| raw.len() == 32 && bs58::encode(&raw).into_string() == value)
        .unwrap_or(false)
}
fn missing_signed_sources(
    signed: &TokenSourceLimitReview,
    earlier: Option<&TokenAccountRpcSnapshot>,
) -> Result<Vec<(String, String, String)>, RpcError> {
    if signed.debits.len() > MAX_SOURCE_QUERIES {
        return Err(RpcError::TooLarge);
    }
    let mut distinct = BTreeMap::<String, (String, String)>::new();
    for row in &signed.debits {
        if !valid_pubkey(&row.source_token_account)
            || !valid_pubkey(&row.mint)
            || row.token_program != TOKEN_PROGRAM && row.token_program != TOKEN_2022_PROGRAM
        {
            return Err(RpcError::InvalidResponse);
        }
        let addr = &row.source_token_account;
        let attrs = (row.mint.clone(), row.token_program.clone());
        if let Some(prev) = distinct.insert(addr.clone(), attrs.clone()) {
            if prev != attrs {
                return Err(RpcError::InvalidResponse);
            }
        }
    }
    if let Some(snapshot) = earlier {
        let mut seen = std::collections::BTreeSet::new();
        if snapshot.accounts.len() > 16
            || snapshot
                .accounts
                .iter()
                .any(|item| !seen.insert(&item.address))
        {
            return Err(RpcError::InvalidResponse);
        }
        distinct.retain(|addr, _| !seen.contains(addr));
    }
    Ok(distinct
        .into_iter()
        .map(|(address, (mint, program))| (address, mint, program))
        .collect())
}

/// Exactly one extra getMultipleAccounts batch, only if signed, USED source
/// accounts were omitted by the primary token-balance candidate snapshot.
/// No arbitrary user address list, and no lookup in offline/failed simulation.
pub fn fetch_missing_signed_sources<T: JsonRpcTransport>(
    transport: &T,
    endpoint: &str,
    simulation_slot: u64,
    signed: &TokenSourceLimitReview,
    earlier: Option<&TokenAccountRpcSnapshot>,
) -> Result<Option<SignedSourceAccountRpcSnapshot>, RpcError> {
    if simulation_slot == 0 {
        return Err(RpcError::InvalidResponse);
    }
    if let Some(previous) = earlier {
        if previous.simulation_slot != simulation_slot
            || previous.context_slot < simulation_slot
            || previous.atomic_with_simulation
        {
            return Err(RpcError::InvalidResponse);
        }
    }
    let candidates = missing_signed_sources(signed, earlier)?;
    if candidates.is_empty() {
        return Ok(None);
    }
    let min_slot = earlier.map_or(simulation_slot, |s| s.context_slot.max(simulation_slot));
    let request = json!({"jsonrpc":"2.0","id":6,"method":"getMultipleAccounts",
        "params":[candidates.iter().map(|c|c.0.clone()).collect::<Vec<_>>(),
                  {"encoding":"base64","commitment":"confirmed","minContextSlot":min_slot}]
    });
    let response = checked_result(transport.post_json(endpoint, &request)?, 6)?;
    let slot = response
        .get("context")
        .and_then(|c| c.get("slot"))
        .and_then(Value::as_u64)
        .filter(|n| *n >= min_slot)
        .ok_or(RpcError::InvalidResponse)?;
    let values = response
        .get("value")
        .and_then(Value::as_array)
        .ok_or(RpcError::InvalidResponse)?;
    if values.len() != candidates.len() {
        return Err(RpcError::InvalidResponse);
    }
    let mut accounts = Vec::with_capacity(candidates.len());
    for ((address, mint, expected_program), entry) in candidates.into_iter().zip(values) {
        let mut item = SignedSourceAccountObservation {
            address: address.clone(),
            signed_mint: mint.clone(),
            declared_token_program: expected_program.clone(),
            status: "missing",
            state: None,
            mint_matches_signed_scope: None,
            program_matches_signed_scope: None,
        };
        if entry.is_null() {
            accounts.push(item);
            continue;
        }
        let obj = entry.as_object().ok_or(RpcError::InvalidResponse)?;
        if obj.get("executable").and_then(Value::as_bool) != Some(false) {
            return Err(RpcError::InvalidResponse);
        }
        let owner = obj
            .get("owner")
            .and_then(Value::as_str)
            .ok_or(RpcError::InvalidResponse)?;
        if owner != TOKEN_PROGRAM && owner != TOKEN_2022_PROGRAM {
            item.status = "other_program";
            item.program_matches_signed_scope = Some(false);
            accounts.push(item);
            continue;
        }
        let data = obj
            .get("data")
            .and_then(Value::as_array)
            .ok_or(RpcError::InvalidResponse)?;
        if data.len() != 2 || data[1].as_str() != Some("base64") {
            return Err(RpcError::InvalidResponse);
        }
        let b64 = data[0].as_str().ok_or(RpcError::InvalidResponse)?;
        if b64.len() > MAX_B64_BYTES {
            return Err(RpcError::TooLarge);
        }
        let bytes = STANDARD
            .decode(b64)
            .map_err(|_| RpcError::InvalidResponse)?;
        let state = parse_token_2022_account(&address, owner, &bytes)?;
        item.status = if owner == TOKEN_PROGRAM {
            "legacy_token"
        } else {
            "token_2022"
        };
        item.program_matches_signed_scope = Some(owner == expected_program);
        item.mint_matches_signed_scope = Some(state.mint == mint);
        item.state = Some(state);
        accounts.push(item);
    }
    Ok(Some(SignedSourceAccountRpcSnapshot{
        simulation_slot,context_slot:slot,atomic_with_simulation:false,accounts,
        limitation:"Extra signed source accounts were read from the same user-selected RPC in a separate confirmed minimum-slot batch after simulation. Addresses come only from used, independently verified signed source scopes not already covered by simulated token-balance metadata. Even a matched program, mint, owner or delegate is non-atomic and cannot authorize or bound executed spending.",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token_account_rpc::TokenAccountObservation;
    use hguet_core::DeclaredSourceDebit;
    use std::cell::Cell;
    fn k(n: u8) -> String {
        bs58::encode([n; 32]).into_string()
    }
    fn review(address: u8, mint: u8, program: &str) -> TokenSourceLimitReview {
        TokenSourceLimitReview {
            debits: vec![DeclaredSourceDebit {
                token_program: program.into(),
                mint: k(mint),
                source_token_account: k(address),
                declared_authority: k(9),
                declared_raw: "5".into(),
                signed_limit_raw: "10".into(),
            }],
            checked_direct_debit_instructions: 1,
            transaction_required_signer_role_checked: true,
            transaction_signatures_verified: false,
            token_account_owner_verified: false,
            total_spending_proven: false,
            coverage: "test",
            limitation: "test",
        }
    }
    fn data(mint: u8, owner: u8, token_program: &str) -> Value {
        let mut bytes = vec![0u8; 165];
        bytes[..32].fill(mint);
        bytes[32..64].fill(owner);
        bytes[64..72].copy_from_slice(&100u64.to_le_bytes());
        bytes[108] = 1;
        json!({"owner":token_program,"executable":false,
            "data":[STANDARD.encode(bytes),"base64"]})
    }
    fn earlier(address: u8) -> TokenAccountRpcSnapshot {
        TokenAccountRpcSnapshot {
            context_slot: 510,
            simulation_slot: 500,
            atomic_with_simulation: false,
            accounts: vec![TokenAccountObservation {
                address: k(address),
                simulation_reported_mint: k(2),
                status: "missing".into(),
                state: None,
                mint_matches_simulation_report: None,
                authority_matches_simulation_report: None,
                matching_mint_state_observed: false,
            }],
            limitation: "test".into(),
        }
    }
    struct Fake {
        calls: Cell<usize>,
        slot: u64,
        values: Value,
    }
    impl JsonRpcTransport for Fake {
        fn post_json(&self, _endpoint: &str, req: &Value) -> Result<Value, RpcError> {
            self.calls.set(self.calls.get() + 1);
            assert_eq!(req["method"], "getMultipleAccounts");
            assert_eq!(req["id"], 6);
            assert_eq!(req["params"][1]["commitment"], "confirmed");
            assert_eq!(req["params"][1]["encoding"], "base64");
            Ok(json!({"jsonrpc":"2.0","id":6,"result":{
                "context":{"slot":self.slot},"value":self.values}}))
        }
    }
    #[test]
    fn only_missing_signed_sources_are_fetched_once_at_later_slot() {
        let f = Fake {
            calls: Cell::new(0),
            slot: 511,
            values: json!([data(2, 9, TOKEN_PROGRAM)]),
        };
        let mut sources = review(1, 2, TOKEN_PROGRAM);
        sources.debits.push(DeclaredSourceDebit {
            token_program: TOKEN_PROGRAM.into(),
            mint: k(2),
            source_token_account: k(3),
            declared_authority: k(9),
            declared_raw: "7".into(),
            signed_limit_raw: "10".into(),
        });
        let original = earlier(3);
        let r =
            fetch_missing_signed_sources(&f, "https://example.org", 500, &sources, Some(&original))
                .unwrap()
                .unwrap();
        assert_eq!(f.calls.get(), 1);
        assert_eq!(r.accounts.len(), 1);
        assert_eq!(r.accounts[0].address, k(1));
        assert_eq!(r.accounts[0].status, "legacy_token");
        assert_eq!(r.accounts[0].program_matches_signed_scope, Some(true));
        assert_eq!(r.accounts[0].mint_matches_signed_scope, Some(true));
        assert_eq!(r.context_slot, 511);
        assert!(!r.atomic_with_simulation);
    }
    #[test]
    fn no_new_rpc_if_all_signed_sources_are_already_in_balance_candidates() {
        let f = Fake {
            calls: Cell::new(0),
            slot: 511,
            values: json!([]),
        };
        let r = fetch_missing_signed_sources(
            &f,
            "https://example.org",
            500,
            &review(3, 2, TOKEN_PROGRAM),
            Some(&earlier(3)),
        )
        .unwrap();
        assert!(r.is_none());
        assert_eq!(f.calls.get(), 0);
    }
    #[test]
    fn missing_other_program_and_wrong_mint_are_kept_separate() {
        let f = Fake {
            calls: Cell::new(0),
            slot: 500,
            values: json!([data(4, 9, TOKEN_2022_PROGRAM)]),
        };
        let r = fetch_missing_signed_sources(
            &f,
            "https://example.org",
            500,
            &review(1, 2, TOKEN_PROGRAM),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.accounts[0].status, "token_2022");
        assert_eq!(r.accounts[0].program_matches_signed_scope, Some(false));
        assert_eq!(r.accounts[0].mint_matches_signed_scope, Some(false));
        let f = Fake {
            calls: Cell::new(0),
            slot: 500,
            values: json!([null]),
        };
        let r = fetch_missing_signed_sources(
            &f,
            "https://example.org",
            500,
            &review(1, 2, TOKEN_2022_PROGRAM),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.accounts[0].status, "missing");
        assert!(r.accounts[0].state.is_none());
        let f = Fake {
            calls: Cell::new(0),
            slot: 500,
            values: json!([{
                "owner":"11111111111111111111111111111111",
                "executable":false
            }]),
        };
        let r = fetch_missing_signed_sources(
            &f,
            "https://example.org",
            500,
            &review(1, 2, TOKEN_2022_PROGRAM),
            None,
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.accounts[0].status, "other_program");
    }
    #[test]
    fn stale_slot_and_malformed_account_fail_without_forged_authorization() {
        let f = Fake {
            calls: Cell::new(0),
            slot: 499,
            values: json!([null]),
        };
        assert_eq!(
            fetch_missing_signed_sources(
                &f,
                "https://example.org",
                500,
                &review(1, 2, TOKEN_PROGRAM),
                None
            )
            .unwrap_err(),
            RpcError::InvalidResponse
        );
        let f = Fake {
            calls: Cell::new(0),
            slot: 500,
            values: json!([{"owner":TOKEN_2022_PROGRAM,
                "executable":false,"data":["!!!","base64"]}]),
        };
        assert_eq!(
            fetch_missing_signed_sources(
                &f,
                "https://example.org",
                500,
                &review(1, 2, TOKEN_2022_PROGRAM),
                None
            )
            .unwrap_err(),
            RpcError::InvalidResponse
        );
    }
    #[test]
    fn too_many_or_conflicting_signed_sources_fail_before_network() {
        let f = Fake {
            calls: Cell::new(0),
            slot: 500,
            values: json!([]),
        };
        let mut sources = review(1, 2, TOKEN_PROGRAM);
        for id in 3..=34 {
            sources.debits.push(DeclaredSourceDebit {
                token_program: TOKEN_PROGRAM.into(),
                mint: k(2),
                source_token_account: k(id),
                declared_authority: k(9),
                declared_raw: "1".into(),
                signed_limit_raw: "10".into(),
            });
        }
        assert_eq!(
            fetch_missing_signed_sources(&f, "https://example.org", 500, &sources, None)
                .unwrap_err(),
            RpcError::TooLarge
        );
        assert_eq!(f.calls.get(), 0);
        let mut conflicting = review(1, 2, TOKEN_PROGRAM);
        conflicting.debits.push(DeclaredSourceDebit {
            token_program: TOKEN_2022_PROGRAM.into(),
            mint: k(4),
            source_token_account: k(1),
            declared_authority: k(9),
            declared_raw: "1".into(),
            signed_limit_raw: "10".into(),
        });
        assert_eq!(
            fetch_missing_signed_sources(&f, "https://example.org", 500, &conflicting, None)
                .unwrap_err(),
            RpcError::InvalidResponse
        );
    }
    #[test]
    fn fetched_scope_is_minimum_slot_not_an_atomic_bank() {
        let f = Fake {
            calls: Cell::new(0),
            slot: 510,
            values: json!([null]),
        };
        let s = earlier(3);
        let r = fetch_missing_signed_sources(
            &f,
            "https://example.org",
            500,
            &review(1, 2, TOKEN_PROGRAM),
            Some(&s),
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.context_slot, 510);
        assert!(!r.atomic_with_simulation);
    }
}
