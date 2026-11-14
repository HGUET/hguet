//! Advisory, bounded one-provider mint-state lookup AFTER successful simulation.
//! Never an atomic snapshot with simulateTransaction or an authorization proof.
use super::{checked_result, JsonRpcTransport, RpcError};
use crate::{
    effects::SimulationEffects,
    mint_state::{parse_token_2022_mint, Token2022MintState, MAX_MINT_BYTES},
    token_semantics::TOKEN_2022_PROGRAM,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeSet;

const MAX_MINT_QUERIES: usize = 16;

#[derive(Debug, Clone, Serialize)]
pub struct MintAccountObservation {
    pub address: String,
    /// "token_2022", "not_token_2022", "missing".
    pub status: String,
    pub state: Option<Token2022MintState>,
}
#[derive(Debug, Clone, Serialize)]
pub struct MintRpcSnapshot {
    pub context_slot: u64,
    pub simulation_slot: u64,
    pub atomic_with_simulation: bool,
    pub accounts: Vec<MintAccountObservation>,
    pub limitation: String,
}
fn candidates(effects: &SimulationEffects) -> Result<Vec<String>, RpcError> {
    let mut set = BTreeSet::new();
    if let Some(rows) = &effects.token_deltas {
        for row in rows {
            set.insert(row.mint.clone());
        }
    }
    for item in &effects.cpi.token_instructions {
        if item.program_id == TOKEN_2022_PROGRAM {
            if let Some(mint) = &item.mint {
                set.insert(mint.clone());
            }
        }
    }
    for item in &effects.cpi.token_2022_extension_observations {
        if let Some(mint) = &item.mint {
            set.insert(mint.clone());
        }
    }
    if set.len() > MAX_MINT_QUERIES {
        return Err(RpcError::TooLarge);
    }
    Ok(set.into_iter().collect())
}
/// Uses only mint pubkeys visible in the selected provider's transaction
/// effects. A raw transaction or actor-supplied arbitrary URL is never added.
/// JSON-RPC getMultipleAccounts.minContextSlot is a lower bound, NOT an atomic
/// block-state pin, hence all fields remain partial_untrusted_rpc.
pub fn fetch_candidate_mints<T: JsonRpcTransport>(
    transport: &T,
    endpoint: &str,
    simulation_slot: u64,
    effects: &SimulationEffects,
) -> Result<Option<MintRpcSnapshot>, RpcError> {
    let addresses = candidates(effects)?;
    if addresses.is_empty() {
        return Ok(None);
    }
    if simulation_slot == 0 {
        return Err(RpcError::InvalidResponse);
    }
    let request = json!({
        "jsonrpc":"2.0","id":4,"method":"getMultipleAccounts",
        "params":[addresses,{"encoding":"base64","commitment":"confirmed",
                             "minContextSlot":simulation_slot}]
    });
    let reply = checked_result(transport.post_json(endpoint, &request)?, 4)?;
    let slot = reply
        .get("context")
        .and_then(|v| v.get("slot"))
        .and_then(Value::as_u64)
        .filter(|v| *v >= simulation_slot)
        .ok_or(RpcError::InvalidResponse)?;
    let array = reply
        .get("value")
        .and_then(Value::as_array)
        .ok_or(RpcError::InvalidResponse)?;
    let requested = request["params"][0]
        .as_array()
        .ok_or(RpcError::InvalidResponse)?;
    if array.len() != requested.len() {
        return Err(RpcError::InvalidResponse);
    }
    let mut accounts = Vec::with_capacity(array.len());
    for (address, value) in requested.iter().zip(array) {
        let address = address.as_str().ok_or(RpcError::InvalidResponse)?;
        if value.is_null() {
            accounts.push(MintAccountObservation {
                address: address.into(),
                status: "missing".into(),
                state: None,
            });
            continue;
        }
        let obj = value.as_object().ok_or(RpcError::InvalidResponse)?;
        let owner = obj
            .get("owner")
            .and_then(Value::as_str)
            .ok_or(RpcError::InvalidResponse)?;
        if obj.get("executable").and_then(Value::as_bool) != Some(false) {
            return Err(RpcError::InvalidResponse);
        }
        if owner != TOKEN_2022_PROGRAM {
            accounts.push(MintAccountObservation {
                address: address.into(),
                status: "not_token_2022".into(),
                state: None,
            });
            continue;
        }
        let data = obj
            .get("data")
            .and_then(Value::as_array)
            .ok_or(RpcError::InvalidResponse)?;
        if data.len() != 2 || data[1].as_str() != Some("base64") {
            return Err(RpcError::InvalidResponse);
        }
        let encoded = data[0].as_str().ok_or(RpcError::InvalidResponse)?;
        // Strict transport limits, plus small per-account data bounds.
        if encoded.len() > MAX_MINT_BYTES.div_ceil(3) * 4 + 4 {
            return Err(RpcError::TooLarge);
        }
        let bytes = STANDARD
            .decode(encoded)
            .map_err(|_| RpcError::InvalidResponse)?;
        let state = parse_token_2022_mint(address, owner, &bytes)?;
        accounts.push(MintAccountObservation {
            address: address.into(),
            status: "token_2022".into(),
            state: Some(state),
        });
    }
    Ok(Some(MintRpcSnapshot {
        context_slot:slot,simulation_slot,atomic_with_simulation:false,accounts,
        limitation:"Mint state was read in a separate RPC call at a context slot >= simulation slot. This does NOT prove the same pre-execution state, full extension effects, or final settlement".into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effects::CpiObservation;
    use crate::effects::SimulationEffects;
    use crate::effects::TokenBalanceDelta;
    use std::cell::Cell;
    struct Fake {
        slot: u64,
        payload: Value,
        calls: Cell<usize>,
    }
    impl JsonRpcTransport for Fake {
        fn post_json(&self, _endpoint: &str, request: &Value) -> Result<Value, RpcError> {
            assert_eq!(request["method"], "getMultipleAccounts");
            assert_eq!(request["params"][1]["minContextSlot"], 500);
            self.calls.set(self.calls.get() + 1);
            Ok(json!({"jsonrpc":"2.0","id":4,"result":{
                "context":{"slot":self.slot},"value":self.payload}}))
        }
    }
    fn effects(mints: Vec<String>) -> SimulationEffects {
        SimulationEffects {
            lamport_deltas: None,
            token_deltas: Some(
                mints
                    .into_iter()
                    .enumerate()
                    .map(|(index, mint)| TokenBalanceDelta {
                        account_index: index,
                        token_account: "unused".into(),
                        mint,
                        owner: None,
                        decimals: 6,
                        before_raw_amount: None,
                        after_raw_amount: None,
                        delta_raw_amount: None,
                        complete_pair: false,
                    })
                    .collect(),
            ),
            cpi: CpiObservation {
                captured: true,
                group_count: Some(0),
                instruction_count: Some(0),
                invoked_program_ids: vec![],
                token_instructions: vec![],
                token_2022_extension_observations: vec![],
                opaque_token_instruction_count: 0,
                token_2022_extension_instruction_count: 0,
                missing_compiled_token_data_count: 0,
                requires_semantic_review: false,
                limitations: vec![],
            },
            simulated_fee_lamports: None,
            observed_fields: vec![],
            missing_fields: vec![],
            warnings: vec![],
            security_coverage: "partial_untrusted_rpc".into(),
        }
    }
    fn mint_base() -> Vec<u8> {
        let mut v = vec![0u8; 166];
        v[45] = 1;
        v[165] = 1;
        v
    }
    #[test]
    fn snapshot_min_context_and_risky_mint_are_explicitly_non_atomic() {
        let mut mint = mint_base();
        mint.extend(12u16.to_le_bytes());
        mint.extend(32u16.to_le_bytes());
        mint.extend([7u8; 32]);
        let fake = Fake {
            slot: 501,
            calls: Cell::new(0),
            payload: json!([{
            "owner":TOKEN_2022_PROGRAM,"executable":false,
            "data":[STANDARD.encode(mint),"base64"]}]),
        };
        let key = bs58::encode([8u8; 32]).into_string();
        let snap = fetch_candidate_mints(&fake, "https://rpc.example", 500, &effects(vec![key]))
            .unwrap()
            .unwrap();
        assert_eq!(fake.calls.get(), 1);
        assert!(!snap.atomic_with_simulation);
        assert_eq!(snap.context_slot, 501);
        let state = snap.accounts[0].state.as_ref().unwrap();
        assert_eq!(state.extensions[0].family, "permanent_delegate");
        assert!(state.permanent_delegate.is_some());
    }
    #[test]
    fn absent_mints_trigger_no_read_and_missing_accounts_are_not_zeroed() {
        let f = Fake {
            slot: 500,
            calls: Cell::new(0),
            payload: json!([]),
        };
        assert!(
            fetch_candidate_mints(&f, "https://rpc.example", 500, &effects(vec![]))
                .unwrap()
                .is_none()
        );
        assert_eq!(f.calls.get(), 0);
        let f = Fake {
            slot: 500,
            calls: Cell::new(0),
            payload: json!([null]),
        };
        let r = fetch_candidate_mints(
            &f,
            "https://rpc.example",
            500,
            &effects(vec![bs58::encode([2u8; 32]).into_string()]),
        )
        .unwrap()
        .unwrap();
        assert_eq!(r.accounts[0].status, "missing");
        assert!(r.accounts[0].state.is_none());
    }
    #[test]
    fn old_context_wrong_base64_and_wrong_owner_are_not_mint_proofs() {
        let key = bs58::encode([2u8; 32]).into_string();
        let f = Fake {
            slot: 499,
            calls: Cell::new(0),
            payload: json!([null]),
        };
        assert_eq!(
            fetch_candidate_mints(&f, "https://rpc.example", 500, &effects(vec![key.clone()]))
                .unwrap_err(),
            RpcError::InvalidResponse
        );
        let f = Fake {
            slot: 500,
            calls: Cell::new(0),
            payload: json!([{"owner":TOKEN_2022_PROGRAM,
            "executable":false,"data":["$invalid","base64"]}]),
        };
        assert_eq!(
            fetch_candidate_mints(&f, "https://rpc.example", 500, &effects(vec![key.clone()]))
                .unwrap_err(),
            RpcError::InvalidResponse
        );
        let f = Fake {
            slot: 500,
            calls: Cell::new(0),
            payload: json!([{"owner":"other",
            "executable":false,"data":["ignored","base64"]}]),
        };
        let r = fetch_candidate_mints(&f, "https://rpc.example", 500, &effects(vec![key]))
            .unwrap()
            .unwrap();
        assert_eq!(r.accounts[0].status, "not_token_2022");
        assert!(r.accounts[0].state.is_none());
    }
    #[test]
    fn too_many_candidates_must_not_contact_provider() {
        let f = Fake {
            slot: 500,
            calls: Cell::new(0),
            payload: json!([]),
        };
        let keys = (1u8..=17)
            .map(|i| bs58::encode([i; 32]).into_string())
            .collect();
        assert_eq!(
            fetch_candidate_mints(&f, "https://rpc.example", 500, &effects(keys)).unwrap_err(),
            RpcError::TooLarge
        );
        assert_eq!(f.calls.get(), 0);
    }
}
