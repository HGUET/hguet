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
    let request = json!({
        "jsonrpc": "2.0", "id": 2, "method": "simulateTransaction",
        "params": [STANDARD.encode(wire), {
            "encoding": "base64",
            "commitment": "confirmed",
            "sigVerify": false,
            "replaceRecentBlockhash": true,
            "innerInstructions": true
        }]
    });
    let reply = checked_result(transport.post_json(endpoint,&request)?,2)?;
    let result = reply.as_object().ok_or(RpcError::InvalidResponse)?;
    let slot = result.get("context").and_then(|c| c.get("slot"))
        .and_then(Value::as_u64).filter(|slot| *slot > 0)
        .ok_or(RpcError::InvalidResponse)?;
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
}
