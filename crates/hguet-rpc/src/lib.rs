//! Opt-in, read-only Solana JSON-RPC client for HGUET CLI.
//! This crate NEVER sends a transaction, signs, broadcasts, or treats a successful
//! simulation as permission to spend. One RPC provider is untrusted evidence.
//!
//! Security boundaries:
//! - caller explicitly supplies an HTTPS endpoint; no connection in offline mode
//! - pin the intended cluster using getGenesisHash BEFORE simulation
//! - do not follow redirects; never log the URL/query/auth tokens
//! - bounded request/response sizes and deadlines
//! - use replaceRecentBlockhash=true AND sigVerify=false (they conflict)
//! - no wallet keys, seeds, accounts, balances, or Cloud requests.
mod alt;
mod effects;
mod effect_graph;
mod direct_token;
mod extension_semantics;
mod mint_state;
mod mint_rpc;
mod token_account_rpc;
mod token_account_state;
mod authority_review;
mod token_semantics;
pub use token_semantics::TokenCpiInstruction;
pub use extension_semantics::Token2022ExtensionObservation;
pub use mint_rpc::{MintRpcSnapshot, MintAccountObservation};
pub use mint_state::{Token2022MintState, MintExtension, MintTransferFeeConfig, MintTransferHook, FeeSchedule};
pub use token_account_rpc::{TokenAccountRpcSnapshot, TokenAccountObservation};
pub use token_account_state::{Token2022AccountState, TokenAccountExtension};
pub use authority_review::{correlate_signed_source_authority,correlate_signed_source_authority_with_mints,SourceAuthorityReview,SourceAuthorityObservation};
pub use alt::LookupResolution;
pub use effects::{SimulationEffects,CpiObservation,TokenBalanceDelta,NativeBalanceDelta};
pub use direct_token::{inspect_direct_tokens, DirectTokenAnalysis, DirectTokenInstruction, OpaqueDirectTokenInstruction};
pub use effect_graph::{EffectGraph,EffectNode,EffectEdge,GraphSourceSlot};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;
use serde_json::{json, Value};
use std::{io::Read, time::Duration};

const MAX_RPC_RESPONSE: u64 = 1_048_576;
const MAX_SIMULATION_TX: usize = 4096;
const MAX_SIMULATION_ERROR_CHARS: usize = 1024;

pub const MAINNET_GENESIS: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
pub const DEVNET_GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
pub const TESTNET_GENESIS: &str = "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RpcError {
    InvalidEndpoint,
    UnsupportedNetwork,
    Transport,
    TooLarge,
    InvalidResponse,
    RpcRejected,
    GenesisMismatch,
}
impl RpcError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidEndpoint => "RPC_ENDPOINT_INVALID",
            Self::UnsupportedNetwork => "RPC_NETWORK_UNSUPPORTED",
            Self::Transport => "RPC_TRANSPORT_FAILURE",
            Self::TooLarge => "RPC_RESPONSE_TOO_LARGE",
            Self::InvalidResponse => "RPC_RESPONSE_INVALID",
            Self::RpcRejected => "RPC_REQUEST_REJECTED",
            Self::GenesisMismatch => "RPC_GENESIS_MISMATCH",
        }
    }
}

pub fn expected_genesis(network: &str) -> Result<&'static str, RpcError> {
    match network {
        "mainnet" => Ok(MAINNET_GENESIS),
        "devnet" => Ok(DEVNET_GENESIS),
        "testnet" => Ok(TESTNET_GENESIS),
        _ => Err(RpcError::UnsupportedNetwork),
    }
}

/// Only HTTPS RPC endpoints are accepted, even for testing. Explicit opt-in
/// is required at CLI level, and query tokens must never be logged.
pub fn validate_endpoint(endpoint: &str) -> Result<(), RpcError> {
    if endpoint.is_empty() || endpoint.len() > 2048 || endpoint.chars().any(char::is_whitespace) {
        return Err(RpcError::InvalidEndpoint);
    }
    let parsed = url::Url::parse(endpoint).map_err(|_| RpcError::InvalidEndpoint)?;
    if parsed.scheme() != "https" || parsed.host_str().is_none() ||
       !parsed.username().is_empty() || parsed.password().is_some() ||
       parsed.fragment().is_some() {
        return Err(RpcError::InvalidEndpoint);
    }
    Ok(())
}

/// Injectable transport allows all security-sensitive parsing to be tested
/// without contacting a blockchain, third-party RPC or payment infrastructure.
pub trait JsonRpcTransport {
    fn post_json(&self, endpoint: &str, request: &Value) -> Result<Value, RpcError>;
}

pub struct HttpsTransport {
    agent: ureq::Agent,
}
impl Default for HttpsTransport {
    fn default() -> Self {
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(Duration::from_secs(4))
            .timeout_read(Duration::from_secs(10))
            .timeout_write(Duration::from_secs(5))
            .build();
        Self { agent }
    }
}
impl JsonRpcTransport for HttpsTransport {
    fn post_json(&self, endpoint: &str, request: &Value) -> Result<Value, RpcError> {
        validate_endpoint(endpoint)?;
        let bytes = serde_json::to_vec(request).map_err(|_| RpcError::InvalidResponse)?;
        if bytes.len() > 16_384 { return Err(RpcError::TooLarge); }
        let response = self.agent.post(endpoint)
            .set("Accept", "application/json")
            .set("Content-Type", "application/json")
            .send_bytes(&bytes)
            .map_err(|_| RpcError::Transport)?;
        if response.status() != 200 { return Err(RpcError::Transport); }
        let mut body = Vec::new();
        response.into_reader().take(MAX_RPC_RESPONSE+1)
            .read_to_end(&mut body).map_err(|_| RpcError::Transport)?;
        if body.len() as u64 > MAX_RPC_RESPONSE { return Err(RpcError::TooLarge); }
        serde_json::from_slice(&body).map_err(|_| RpcError::InvalidResponse)
    }
}

fn checked_result(response: Value, id: u64) -> Result<Value, RpcError> {
    let obj = response.as_object().ok_or(RpcError::InvalidResponse)?;
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") ||
       obj.get("id").and_then(Value::as_u64) != Some(id) {
        return Err(RpcError::InvalidResponse);
    }
    if obj.contains_key("error") && !obj["error"].is_null() {
        return Err(RpcError::RpcRejected);
    }
    obj.get("result").cloned().ok_or(RpcError::InvalidResponse)
}

pub fn verify_rpc_genesis<T: JsonRpcTransport>(
    transport: &T, endpoint: &str, network: &str,
) -> Result<String, RpcError> {
    validate_endpoint(endpoint)?;
    let expected = expected_genesis(network)?;
    let request = json!({
        "jsonrpc":"2.0","id":1,"method":"getGenesisHash","params":[]
    });
    let reply = checked_result(transport.post_json(endpoint,&request)?,1)?;
    let got = reply.as_str().ok_or(RpcError::InvalidResponse)?;
    if got != expected { return Err(RpcError::GenesisMismatch); }
    Ok(got.to_owned())
}

#[derive(Debug, Clone, Serialize)]
pub struct SimulationEvidence {
    pub network: String,
    pub verified_genesis_hash: String,
    pub context_slot: u64,
    pub simulated_message_sha256: String,
    pub status: String, // rpc_succeeded / rpc_failed
    pub error_summary: Option<String>,
    pub units_consumed: Option<u64>,
    pub logs_count: Option<usize>,
    pub inner_instructions_present: bool,
    pub inner_instruction_groups: Option<usize>,
    pub replacement_blockhash_present: bool,
    pub lookup_resolution: Option<LookupResolution>,
    pub effect_analysis: SimulationEffects,
    pub direct_token_analysis: DirectTokenAnalysis,
    pub mint_snapshot: Option<MintRpcSnapshot>,
    pub token_account_snapshot: Option<TokenAccountRpcSnapshot>,
    pub effect_graph: EffectGraph,
    pub limitation: String,
}

/// Simulation must be requested explicitly. The signed wire message is unchanged
/// by us; the Solana RPC node MAY replace its recent blockhash during simulation,
/// so it does NOT prove that the original transaction will execute on-chain.
/// We do not request signature validation here because replacement conflicts with it.
pub fn simulate_with<T: JsonRpcTransport>(
    transport: &T, endpoint: &str, network: &str, wire: &[u8],
) -> Result<SimulationEvidence, RpcError> {
    if wire.is_empty() || wire.len() > MAX_SIMULATION_TX { return Err(RpcError::TooLarge); }
    // Reject malformed, unknown or unsupported wire formats before any RPC call.
    let decoded = hguet_core::parse_transaction(wire).map_err(|_| RpcError::InvalidResponse)?;
    let genesis = verify_rpc_genesis(transport, endpoint, network)?;
    let lookup_resolution = if decoded.lookup_table_count > 0 {
        Some(alt::resolve_v0_lookups(transport, endpoint, &decoded)?)
    } else { None };
    // Decode original message bytes, not simulated transaction metadata.
    // Only ALT addresses (if any) are resolved through the selected RPC.
    let direct_token_analysis=direct_token::inspect_direct_tokens(
        &decoded, lookup_resolution.as_ref())?;
    let mut request = json!({
        "jsonrpc": "2.0", "id": 2, "method": "simulateTransaction",
        "params": [STANDARD.encode(wire), {
            "encoding": "base64",
            "commitment": "confirmed",
            "sigVerify": false,
            "replaceRecentBlockhash": true,
            "innerInstructions": true,
            "innerInstructionsEncoding": "json"
        }]
    });
    if let Some(ref lookup) = lookup_resolution {
        // Avoid simulating at an older bank context than the observed lookup.
        // This still does NOT give an atomic single-slot snapshot.
        request["params"][1]["minContextSlot"]=json!(lookup.context_slot);
    }
    let reply = checked_result(transport.post_json(endpoint,&request)?,2)?;
    let result = reply.as_object().ok_or(RpcError::InvalidResponse)?;
    let slot = result.get("context").and_then(|c| c.get("slot"))
        .and_then(Value::as_u64).filter(|slot| *slot > 0)
        .ok_or(RpcError::InvalidResponse)?;
    if lookup_resolution.as_ref().is_some_and(|lookup| slot<lookup.context_slot) {
        return Err(RpcError::InvalidResponse);
    }
    let body = result.get("value").and_then(Value::as_object)
        .ok_or(RpcError::InvalidResponse)?;
    if !body.contains_key("err") { return Err(RpcError::InvalidResponse); }
    let err = body.get("err").expect("validated key");
    let status = if err.is_null() { "rpc_succeeded" } else { "rpc_failed" };
    let error_summary = if err.is_null() { None } else {
        let mut s = err.to_string();
        if s.len() > MAX_SIMULATION_ERROR_CHARS { s.truncate(MAX_SIMULATION_ERROR_CHARS); }
        Some(s)
    };
    let logs_count = match body.get("logs") {
        None | Some(Value::Null) => None,
        Some(Value::Array(v)) => Some(v.len()),
        Some(_) => return Err(RpcError::InvalidResponse)
    };
    let inner_instruction_groups = match body.get("innerInstructions") {
        None | Some(Value::Null) => None,
        Some(Value::Array(v)) => Some(v.len()),
        Some(_) => return Err(RpcError::InvalidResponse)
    };
    let units = match body.get("unitsConsumed") {
        None | Some(Value::Null) => None,
        Some(Value::Number(v)) => Some(v.as_u64().ok_or(RpcError::InvalidResponse)?),
        Some(_) => return Err(RpcError::InvalidResponse)
    };
    let effect_analysis=effects::inspect_simulation_effects(body,&decoded,lookup_resolution.as_ref())?;
    // Never contact a second endpoint, and do not fetch additional mint state
    // for failed simulations. This optional request goes to the same explicitly
    // selected provider, with a lower slot bound but no atomicity guarantee.
    let mint_snapshot=if status=="rpc_succeeded" {
        mint_rpc::fetch_candidate_mints(transport,endpoint,slot,&effect_analysis)?
    } else { None };
    // A second, separately slot-scoped observation: only token holding
    // accounts appearing in paired simulation balance metadata. This does
    // not re-create the simulation bank nor resolve CPI-only accounts.
    let token_account_snapshot=if status=="rpc_succeeded" {
        token_account_rpc::fetch_candidate_token_accounts(
            transport,endpoint,slot,&effect_analysis,mint_snapshot.as_ref())?
    } else { None };
    let effect_graph=effect_graph::correlate_effects(
        &decoded,status,slot,&effect_analysis,Some(&direct_token_analysis),
        mint_snapshot.as_ref(),token_account_snapshot.as_ref(),
    )?;
    Ok(SimulationEvidence {
        network: network.into(),
        verified_genesis_hash: genesis,
        context_slot: slot,
        simulated_message_sha256: decoded.message_sha256,
        status: status.into(),
        error_summary,
        units_consumed: units,
        logs_count,
        inner_instructions_present: inner_instruction_groups.is_some(),
        inner_instruction_groups,
        replacement_blockhash_present: body.get("replacementBlockhash")
            .is_some_and(|x| !x.is_null()),
        lookup_resolution,
        effect_analysis,
        direct_token_analysis,
        mint_snapshot,
        token_account_snapshot,
        effect_graph,
        limitation: "Single-provider RPC simulation is advisory, uses replacement blockhash and does not verify resulting onchain execution, CPI completeness, authorization, or future account state".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    struct Fake {
        genesis: &'static str,
        simulation: Value,
        calls: Cell<usize>,
        requests: RefCell<Vec<Value>>,
    }
    impl JsonRpcTransport for Fake {
        fn post_json(&self, _endpoint: &str, request: &Value) -> Result<Value, RpcError> {
            self.calls.set(self.calls.get()+1);
            self.requests.borrow_mut().push(request.clone());
            let id=request["id"].as_u64().unwrap();
            match id {
                1 => Ok(json!({"jsonrpc":"2.0","id":1,"result":self.genesis})),
                2 => Ok(json!({"jsonrpc":"2.0","id":2,"result":self.simulation})),
                4 => {
                    // This mock explicitly represents a later, separate mint
                    // account read; it is not a simulated atomic snapshot.
                    let mut mint=vec![0u8;82];
                    mint[45]=1; // initialized Token-2022 base mint
                    let keys=request["params"][0].as_array().ok_or(RpcError::InvalidResponse)?;
                    let accounts=keys.iter().map(|_|json!({
                        "owner":crate::token_semantics::TOKEN_2022_PROGRAM,
                        "executable":false,
                        "data":[STANDARD.encode(&mint),"base64"]
                    })).collect::<Vec<_>>();
                    Ok(json!({"jsonrpc":"2.0","id":4,"result":{
                        "context":{"slot":60001},
                        "value":accounts
                    }}))
                },
                5 => {
                    let mint=bs58::decode(self.simulation["value"]["preTokenBalances"][0]["mint"]
                        .as_str().ok_or(RpcError::InvalidResponse)?)
                        .into_vec().map_err(|_|RpcError::InvalidResponse)?;
                    if mint.len()!=32 {return Err(RpcError::InvalidResponse);}
                    let keys=request["params"][0].as_array().ok_or(RpcError::InvalidResponse)?;
                    let entries=keys.iter().map(|_|{
                        let mut data=vec![0u8;166];
                        data[..32].copy_from_slice(&mint);
                        data[32..64].fill(3);
                        data[108]=1;data[165]=2;
                        json!({"owner":crate::token_semantics::TOKEN_2022_PROGRAM,
                            "executable":false,"data":[STANDARD.encode(data),"base64"]})
                    }).collect::<Vec<_>>();
                    Ok(json!({"jsonrpc":"2.0","id":5,"result":{
                        "context":{"slot":60002},"value":entries
                    }}))
                },
                _ => Err(RpcError::InvalidResponse)
            }
        }
    }
    fn fake(genesis: &'static str, err: Value) -> Fake {
        Fake {
            genesis,
            simulation: json!({"context":{"slot":400000},"value":{
                "err":err,"logs":["synthetic"],"innerInstructions":[],
                "unitsConsumed":123,"replacementBlockhash":{"blockhash":"synthetic"}
            }}),
            calls:Cell::new(0),requests:RefCell::new(vec![])
        }
    }
    fn legacy_unsigned() -> Vec<u8> {
        let mut v=vec![1u8];v.extend([0u8;64]);v.extend([1,0,0,1]);
        v.extend([7u8;32]);v.extend([8u8;32]);v.push(0);v
    }
    #[test] fn require_explicit_https_no_credentials_or_redirects() {
        assert!(validate_endpoint("https://api.devnet.solana.com").is_ok());
        assert!(validate_endpoint("https://rpc.example.org/custom?api-key=secret").is_ok());
        for bad in [
            "http://api.devnet.solana.com","http://127.0.0.1:8899",
            "https://username:secret@rpc.example.com","https://rpc.example.com/#frag",
            "file:///etc/passwd","ssh://debian@vps.example.com",
            "https://", "https://rpc.example.com something",
        ] {
            assert_eq!(validate_endpoint(bad),Err(RpcError::InvalidEndpoint),"{bad}");
        }
    }
    #[test] fn simulation_exposes_exact_balance_and_token_effects_without_allow() {
        let mut provider=fake(DEVNET_GENESIS,Value::Null);
        let mint=bs58::encode([4u8;32]).into_string();
        let token_row=|amount:&str|json!({
            "accountIndex":0,"mint":mint,
            "uiTokenAmount":{"amount":amount,"decimals":9}
        });
        provider.simulation=json!({"context":{"slot":60000},"value":{
            "err":null,"preBalances":[5000],"postBalances":[4500],
            "preTokenBalances":[token_row("999999999999")],
            "postTokenBalances":[token_row("999999999998")],
            "innerInstructions":[],"logs":[],"unitsConsumed":123,
            "fee":500,"loadedAddresses":{"writable":[],"readonly":[]}
        }});
        let result=simulate_with(&provider,"https://rpc.example","devnet",&legacy_unsigned()).unwrap();
        assert_eq!(result.mint_snapshot.as_ref().unwrap().context_slot,60001);
        assert!(!result.mint_snapshot.as_ref().unwrap().atomic_with_simulation);
        assert_eq!(result.token_account_snapshot.as_ref().unwrap().context_slot,60002);
        assert!(!result.token_account_snapshot.as_ref().unwrap().atomic_with_simulation);
        assert_eq!(result.token_account_snapshot.as_ref().unwrap().accounts.len(),1);
        assert_eq!(result.token_account_snapshot.as_ref().unwrap().accounts[0]
            .mint_matches_simulation_report,Some(true));
        let effects=result.effect_analysis;
        assert_eq!(effects.lamport_deltas.as_ref().unwrap()[0].delta_lamports,"-500");
        assert_eq!(effects.token_deltas.as_ref().unwrap()[0].delta_raw_amount.as_deref(),Some("-1"));
        assert!(effects.cpi.captured);
        assert!(effects.cpi.invoked_program_ids.is_empty());
        assert_eq!(effects.simulated_fee_lamports.as_deref(),Some("500"));
        assert!(effects.missing_fields.is_empty());
        assert_eq!(effects.security_coverage,"partial_untrusted_rpc");
    }

    #[test] fn incomplete_or_forged_rpc_effects_fail_closed() {
        let mut provider=fake(DEVNET_GENESIS,Value::Null);
        provider.simulation=json!({"context":{"slot":100},"value":{
            "err":null,"preBalances":[1,2],"postBalances":[1],
            "innerInstructions":[]}
        });
        assert_eq!(simulate_with(&provider,"https://rpc.example","devnet",&legacy_unsigned()).unwrap_err(),
            RpcError::InvalidResponse);
        provider.simulation=json!({"context":{"slot":100},"value":{
            "err":null,"preBalances":[1],
            "innerInstructions":null}
        });
        let r=simulate_with(&provider,"https://rpc.example","devnet",&legacy_unsigned()).unwrap();
        assert!(r.effect_analysis.lamport_deltas.is_none());
        assert!(!r.effect_analysis.cpi.captured);
        assert!(!r.effect_analysis.missing_fields.is_empty());
    }

    #[test]
    fn failed_simulation_with_token_snapshots_does_not_fetch_mints() {
        let mut f=fake(DEVNET_GENESIS,json!({"InstructionError":[0,"Custom"]}));
        let mint=bs58::encode([4u8;32]).into_string();
        f.simulation=json!({"context":{"slot":700},"value":{
            "err":{"InstructionError":[0,"Custom"]},
            "preTokenBalances":[{"accountIndex":0,"mint":mint,
                "uiTokenAmount":{"amount":"10","decimals":6}}],
            "postTokenBalances":[{"accountIndex":0,"mint":mint,
                "uiTokenAmount":{"amount":"9","decimals":6}}],
            "innerInstructions":[]
        }});
        let r=simulate_with(&f,"https://rpc.example","devnet",&legacy_unsigned()).unwrap();
        assert_eq!(r.status,"rpc_failed");
        assert!(r.mint_snapshot.is_none());
        assert!(r.token_account_snapshot.is_none());
        assert_eq!(f.calls.get(),2); // genesis + simulation only, no mint read
        assert!(!f.requests.borrow().iter().any(|x|x["id"]==4));
    }
    #[test] fn network_genesis_checked_before_any_simulation() {
        let fake=fake(MAINNET_GENESIS,Value::Null);
        let err=simulate_with(&fake,"https://example.org","devnet",&legacy_unsigned()).unwrap_err();
        assert_eq!(err,RpcError::GenesisMismatch);
        assert_eq!(fake.calls.get(),1);
    }
    #[test] fn simulation_uses_base64_and_safe_blockhash_configuration() {
        let fake=fake(DEVNET_GENESIS,Value::Null);
        let wire=legacy_unsigned();
        let result=simulate_with(&fake,"https://example.org","devnet",&wire).unwrap();
        assert_eq!(result.status,"rpc_succeeded");
        assert_eq!(result.context_slot,400000);
        assert_eq!(result.units_consumed,Some(123));
        assert_eq!(fake.calls.get(),2);
        let requests=fake.requests.borrow();
        assert_eq!(requests[1]["method"],"simulateTransaction");
        assert_eq!(requests[1]["params"][0],STANDARD.encode(wire));
        assert_eq!(requests[1]["params"][1]["sigVerify"],false);
        assert_eq!(requests[1]["params"][1]["replaceRecentBlockhash"],true);
        assert_eq!(requests[1]["params"][1]["innerInstructions"],true);
        assert_eq!(requests[1]["params"][1]["innerInstructionsEncoding"],"json");
    }
    #[test] fn rpc_errors_and_onchain_simulation_errors_are_not_false_success() {
        let bad=fake(DEVNET_GENESIS,json!({"InstructionError":[0,"Custom"]}));
        let r=simulate_with(&bad,"https://example.org","devnet",&legacy_unsigned()).unwrap();
        assert_eq!(r.status,"rpc_failed");
        assert!(r.error_summary.is_some());
        let mut invalid=fake(DEVNET_GENESIS,Value::Null);
        invalid.simulation=json!({"context":{"slot":1},"value":{"logs":[]}});
        assert_eq!(simulate_with(&invalid,"https://example.org","devnet",&legacy_unsigned()).unwrap_err(),
            RpcError::InvalidResponse);
    }
    #[test] fn malformed_payload_must_not_contact_provider() {
        let f=fake(DEVNET_GENESIS,Value::Null);
        assert_eq!(simulate_with(&f,"https://example.org","devnet",b"bad").unwrap_err(),
            RpcError::InvalidResponse);
        assert_eq!(f.calls.get(),0);
    }
    #[test] fn response_id_and_error_fail_closed() {
        assert_eq!(checked_result(json!({"jsonrpc":"2.0","id":3,"result":"ok"}),2),
            Err(RpcError::InvalidResponse));
        assert_eq!(checked_result(json!({"jsonrpc":"2.0","id":2,"error":{"code":-32000}}),2),
            Err(RpcError::RpcRejected));
    }
    #[test] fn v0_lookup_is_resolved_before_simulation_with_min_context_slot() {
        struct FakeV0 { requested_min_context: std::cell::Cell<bool> }
        impl JsonRpcTransport for FakeV0 {
            fn post_json(&self,_endpoint:&str,request:&Value)->Result<Value,RpcError> {
                match request["id"].as_u64() {
                    Some(1)=>Ok(json!({"jsonrpc":"2.0","id":1,"result":DEVNET_GENESIS})),
                    Some(3)=>{
                        assert_eq!(request["method"],"getMultipleAccounts");
                        let mut data=vec![0u8;56];
                        data[0..4].copy_from_slice(&1u32.to_le_bytes());
                        data[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
                        data[12..20].copy_from_slice(&100u64.to_le_bytes());
                        data[20]=1; // previous extension index, not warm
                        data.extend_from_slice(&[55u8;32]);
                        Ok(json!({"jsonrpc":"2.0","id":3,"result":{
                            "context":{"slot":500},
                            "value":[{"owner":crate::alt::ALT_PROGRAM,
                                      "executable":false,
                                      "data":[STANDARD.encode(data),"base64"]}]
                        }}))
                    }
                    Some(2)=>{
                        if request["params"][1]["minContextSlot"].as_u64()==Some(500) {
                            self.requested_min_context.set(true);
                        }
                        Ok(json!({"jsonrpc":"2.0","id":2,"result":{
                            "context":{"slot":501},
                            "value":{"err":null,"logs":[],"innerInstructions":[],
                                     "unitsConsumed":300}
                        }}))
                    }
                    _=>Err(RpcError::InvalidResponse)
                }
            }
        }
        let mut wire=legacy_unsigned();
        wire.insert(65,0x80); // version=0, after signature bytes
        wire.push(1); // one lookup table
        wire.extend([9u8;32]); // table pubkey
        wire.extend([1,0,0]); // one writable index 0, no readonly indexes
        let provider=FakeV0{requested_min_context:std::cell::Cell::new(false)};
        let result=simulate_with(&provider,"https://rpc.example","devnet",&wire).unwrap();
        let lookup=result.lookup_resolution.unwrap();
        assert_eq!(lookup.context_slot,500);
        assert_eq!(lookup.resolved_writable_accounts,
            vec![bs58::encode([55u8;32]).into_string()]);
        assert!(provider.requested_min_context.get());
        assert_eq!(result.status,"rpc_succeeded");
    }

}
