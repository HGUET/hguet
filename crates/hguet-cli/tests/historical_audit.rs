//! Signed synthetic historical fixtures; never contacts an RPC or real funds.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use hguet::audit;
use hguet_core::{parse_transaction, TransactionSignatureStatus};
use hguet_rpc::{JsonRpcTransport, RpcError, DEVNET_GENESIS};
use serde_json::{json, Value};
use std::cell::RefCell;

struct Provider {
    result: Value,
    genesis: &'static str,
    methods: RefCell<Vec<String>>,
}

impl JsonRpcTransport for Provider {
    fn post_json(&self, _endpoint: &str, request: &Value) -> Result<Value, RpcError> {
        let method = request["method"].as_str().unwrap();
        self.methods.borrow_mut().push(method.to_owned());
        match method {
            "getGenesisHash" => Ok(json!({"jsonrpc":"2.0","id":1,"result":self.genesis})),
            "getTransaction" => {
                assert_eq!(
                    request["params"][1],
                    json!({"encoding":"base64","commitment":"finalized",
                           "maxSupportedTransactionVersion":1})
                );
                assert!(request["params"][0].as_str().is_some());
                Ok(json!({"jsonrpc":"2.0","id":2,"result":self.result}))
            }
            _ => panic!("unexpected RPC call: {method}"),
        }
    }
}

fn provider(result: Value) -> Provider {
    Provider {
        result,
        genesis: DEVNET_GENESIS,
        methods: RefCell::new(Vec::new()),
    }
}

fn signed_wire(v0: bool) -> (String, Vec<u8>) {
    let signer = SigningKey::from_bytes(&[7; 32]);
    let mut message = Vec::new();
    if v0 {
        message.push(0x80);
    }
    message.extend([1, 0, 1, if v0 { 2 } else { 3 }]);
    message.extend(signer.verifying_key().to_bytes());
    if !v0 {
        message.extend([8; 32]); // recipient
    }
    message.extend([0; 32]); // system program
    message.extend([9; 32]); // blockhash
    let program = if v0 { 1 } else { 2 };
    let recipient = if v0 { 2 } else { 1 };
    message.extend([1, program, 2, 0, recipient, 12, 2, 0, 0, 0]);
    message.extend(500u64.to_le_bytes());
    if v0 {
        message.push(1);
        message.extend([10; 32]); // lookup table
        message.extend([1, 0, 0]); // writable index 0, no readonly
    }
    let signature = signer.sign(&message).to_bytes();
    let mut wire = vec![1];
    wire.extend(signature);
    wire.extend(message);
    assert_eq!(
        parse_transaction(&wire)
            .unwrap()
            .transaction_signature_status,
        TransactionSignatureStatus::Verified
    );
    (bs58::encode(signature).into_string(), wire)
}

fn signed_v1() -> (String, Vec<u8>) {
    let mut wire = STANDARD
        .decode(include_str!("../../../tests/fixtures/v1-system-transfer.base64").trim())
        .unwrap();
    let parsed = parse_transaction(&wire).unwrap();
    assert_eq!(parsed.required_signatures, 1);
    let signer = SigningKey::from_bytes(&[11; 32]);
    // v1's fixed header ends at byte 42; the first key is the fee payer.
    wire[42..74].copy_from_slice(&signer.verifying_key().to_bytes());
    let message_end = wire.len() - 64;
    let signature = signer.sign(&wire[..message_end]).to_bytes();
    wire[message_end..].copy_from_slice(&signature);
    assert_eq!(
        parse_transaction(&wire)
            .unwrap()
            .transaction_signature_status,
        TransactionSignatureStatus::Verified
    );
    (bs58::encode(signature).into_string(), wire)
}

fn response(wire: &[u8], version: Value, meta: Value) -> Value {
    json!({"slot":1234,"blockTime":1700000000,"version":version,
           "transaction":[STANDARD.encode(wire),"base64"],"meta":meta})
}

fn run(signature: &str, provider: &Provider) -> audit::AuditReport {
    audit::inspect(signature, "devnet", "https://rpc.example", provider).unwrap()
}

#[test]
fn signed_legacy_historical_metadata_is_separate_from_wire() {
    let (signature, wire) = signed_wire(false);
    let p = provider(response(
        &wire,
        json!("legacy"),
        json!({"err":null,"fee":5000,"preBalances":[10000,1000,1],
               "postBalances":[4500,1500,1],"innerInstructions":[]}),
    ));
    let report = run(&signature, &p);
    assert_eq!(report.status, "FOUND_SIGNATURE_VERIFIED");
    assert!(report.signatures_verified);
    assert!(!report.execution_proven);
    assert_eq!(report.signing_authorization, "NOT_AUTHORIZED");
    let value = serde_json::to_value(report).unwrap();
    assert_eq!(
        value["wire"]["asset_totals"][0]["declared_debit_raw"],
        "500"
    );
    assert!(value["wire"]["actual_network_fee_lamports"].is_null());
    assert_eq!(value["historical"]["reported_fee_lamports"], "5000");
    assert_eq!(
        value["historical"]["effects"]["lamport_deltas"][0]["delta_lamports"],
        "-5500"
    );
    assert_eq!(
        value["historical"]["effects"]["lamport_deltas"][1]["delta_lamports"],
        "500"
    );
    assert_eq!(
        p.methods.into_inner(),
        vec!["getGenesisHash", "getTransaction"]
    );
}

#[test]
fn failed_execution_keeps_reported_fee_and_wire_declaration() {
    let (signature, wire) = signed_wire(false);
    let p = provider(response(
        &wire,
        json!("legacy"),
        json!({"err":{"InstructionError":[0,1]},"fee":5000,
               "preBalances":[10000,1000,1],"postBalances":[5000,1000,1]}),
    ));
    let report = run(&signature, &p);
    assert_eq!(report.status, "FOUND_SIGNATURE_VERIFIED");
    let historical = report.historical.unwrap();
    assert_eq!(historical.status, "RPC_REPORTED_FAILURE");
    assert_eq!(historical.reported_fee_lamports.as_deref(), Some("5000"));
    assert_eq!(
        report.wire.unwrap().asset_totals[0].declared_debit_raw,
        "500"
    );
    assert!(!report.execution_proven);
}

#[test]
fn not_found_and_missing_metadata_are_distinct() {
    let (signature, wire) = signed_wire(false);
    let p = provider(Value::Null);
    let report = run(&signature, &p);
    assert_eq!(report.status, "NOT_FOUND_AT_REQUESTED_COMMITMENT");
    assert!(report.wire.is_none());
    let p = provider(response(&wire, json!("legacy"), Value::Null));
    let report = run(&signature, &p);
    assert!(report.signatures_verified);
    let history = report.historical.unwrap();
    assert_eq!(history.status, "METADATA_UNAVAILABLE");
    assert!(history.effects.is_none());
}

#[test]
fn v0_uses_historical_loaded_addresses_only() {
    let (signature, wire) = signed_wire(true);
    let recipient = bs58::encode([8; 32]).into_string();
    let p = provider(response(
        &wire,
        json!(0),
        json!({"err":null,"preBalances":[10000,1,1000],
               "postBalances":[9500,1,1500],
               "loadedAddresses":{"writable":[recipient],"readonly":[]}}),
    ));
    let report = run(&signature, &p);
    let value = serde_json::to_value(report).unwrap();
    assert_eq!(value["status"], "FOUND_SIGNATURE_VERIFIED");
    assert!(value["wire"]["flows"][0]["to"]["address"].is_null());
    assert_eq!(
        value["historical"]["effects"]["lamport_deltas"][1]["address"],
        recipient
    );
    assert_eq!(
        p.methods.into_inner(),
        vec!["getGenesisHash", "getTransaction"]
    );
    let missing = provider(response(&wire, json!(0), json!({"err":null,"fee":1})));
    let report = run(&signature, &missing);
    let history = report.historical.unwrap();
    assert_eq!(history.effects_status, "HISTORICAL_LOOKUPS_UNAVAILABLE");
    assert!(history.effects.is_none());
    let malformed = provider(response(
        &wire,
        json!(0),
        json!({"err":null,"loadedAddresses":{"writable":[],"readonly":[]}}),
    ));
    assert_eq!(run(&signature, &malformed).status, "RPC_UNAVAILABLE");
}

#[test]
fn v1_signature_suffix_is_verified() {
    let (signature, wire) = signed_v1();
    let p = provider(response(&wire, json!(1), json!({"err":null})));
    let report = run(&signature, &p);
    assert_eq!(report.status, "FOUND_SIGNATURE_VERIFIED");
    assert_eq!(report.wire.unwrap().program_report.wire_format, "v1");
}

#[test]
fn signature_substitution_tampering_and_bad_metadata_fail_closed() {
    let (signature, wire) = signed_wire(false);
    let other = bs58::encode([6; 64]).into_string();
    let p = provider(response(&wire, json!("legacy"), Value::Null));
    assert_eq!(run(&other, &p).status, "RPC_UNAVAILABLE");
    let mut tampered = wire.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let invalid = [
        response(&tampered, json!("legacy"), Value::Null),
        response(&wire, json!(0), Value::Null),
        response(&wire, json!("legacy"), json!({"err":false})),
        response(&wire, json!("legacy"), json!({"err":null,"fee":"12"})),
        response(
            &wire,
            json!("legacy"),
            json!({"err":null,"preBalances":[1],"postBalances":[1]}),
        ),
    ];
    for result in invalid {
        let report = run(&signature, &provider(result));
        assert_eq!(report.status, "RPC_UNAVAILABLE");
        assert!(!report.signatures_verified);
        assert!(report.wire.is_none());
        assert_eq!(report.rpc_error, Some("RPC_RESPONSE_INVALID"));
    }
}

#[test]
fn invalid_inputs_and_wrong_genesis_stop_before_history_request() {
    let p = provider(Value::Null);
    assert!(audit::inspect("invalid", "devnet", "https://rpc.example", &p).is_err());
    let (signature, _) = signed_wire(false);
    assert!(audit::inspect(&signature, "devnet", "http://rpc.example", &p).is_err());
    assert!(p.methods.borrow().is_empty());
    let mut p = provider(Value::Null);
    p.genesis = "wrong-cluster";
    let report = run(&signature, &p);
    assert_eq!(report.rpc_error, Some("RPC_GENESIS_MISMATCH"));
    assert_eq!(p.methods.into_inner(), vec!["getGenesisHash"]);
}
