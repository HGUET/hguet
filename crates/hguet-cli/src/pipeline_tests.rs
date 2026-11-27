//! End-to-end tests of the `check` pipeline with an injected RPC transport.
//!
//! The Python benchmark cannot reach the successful-RPC paths: the CLI only talks to HTTPS
//! endpoints validated against public roots, and the benchmark will not weaken TLS to fake one.
//! These tests drive the real `execute_with` (file reading, parsing, policy, intent, RPC
//! correlation, signing boundary) and replace only the network hop.
use super::{execute_with, Args};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use hguet_rpc::{JsonRpcTransport, RpcError};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const DEVNET_GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const MAINNET_GENESIS: &str = "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d";
const SYSTEM: &str = "11111111111111111111111111111111";
const ALT_PROGRAM: &str = "AddressLookupTab1e1111111111111111111111111";

/// Answers by JSON-RPC method and records every request it was sent.
struct FakeRpc {
    genesis: &'static str,
    simulation: Value,
    lookup_address: [u8; 32],
    requests: RefCell<Vec<Value>>,
}
impl FakeRpc {
    fn new(simulation: Value) -> Self {
        Self {
            genesis: DEVNET_GENESIS,
            simulation,
            lookup_address: [55u8; 32],
            requests: RefCell::new(Vec::new()),
        }
    }
    fn methods(&self) -> Vec<String> {
        self.requests
            .borrow()
            .iter()
            .map(|r| r["method"].as_str().unwrap_or("?").to_owned())
            .collect()
    }
}
impl JsonRpcTransport for FakeRpc {
    fn post_json(&self, _endpoint: &str, request: &Value) -> Result<Value, RpcError> {
        self.requests.borrow_mut().push(request.clone());
        let id = request["id"].clone();
        let result = match request["method"].as_str() {
            Some("getGenesisHash") => json!(self.genesis),
            Some("simulateTransaction") => self.simulation.clone(),
            Some("getMultipleAccounts") if request["id"] != 3 => {
                let count = request["params"][0].as_array().unwrap().len();
                json!({"context":{"slot":900},"value":vec![Value::Null;count]})
            }
            Some("getMultipleAccounts") => {
                // One active lookup table holding a single address.
                let mut data = vec![0u8; 56];
                data[0..4].copy_from_slice(&1u32.to_le_bytes());
                data[4..12].copy_from_slice(&u64::MAX.to_le_bytes());
                data[12..20].copy_from_slice(&100u64.to_le_bytes());
                data[20] = 1;
                data.extend_from_slice(&self.lookup_address);
                json!({"context":{"slot":500},"value":[{
                    "owner":ALT_PROGRAM,"executable":false,
                    "data":[STANDARD.encode(data),"base64"]}]})
            }
            _ => return Err(RpcError::InvalidResponse),
        };
        Ok(json!({"jsonrpc":"2.0","id":id,"result":result}))
    }
}

/// A transport that must never be reached.
struct Unreachable;
impl JsonRpcTransport for Unreachable {
    fn post_json(&self, _endpoint: &str, _request: &Value) -> Result<Value, RpcError> {
        panic!("the RPC provider was contacted on a path that must stay offline");
    }
}

struct RejectRead {
    rpc: FakeRpc,
    id: u64,
    invalid_response: bool,
    rejected: std::cell::Cell<bool>,
}
impl JsonRpcTransport for RejectRead {
    fn post_json(&self, endpoint: &str, request: &Value) -> Result<Value, RpcError> {
        if request["id"].as_u64() == Some(self.id) {
            self.rejected.set(true);
            return if self.invalid_response {
                Ok(
                    json!({"jsonrpc":"2.0","id":self.id,"result":{"context":{"slot":900},"value":"malformed"}}),
                )
            } else {
                Err(RpcError::Transport)
            };
        }
        self.rpc.post_json(endpoint, request)
    }
}

#[test]
fn failed_additional_source_reads_preserve_unknown_and_signed_caps() {
    let wire = STANDARD
        .decode(
            include_str!(
                "../../../tests/fixtures/legacy-spl-transfer-checked-authority-signer.base64"
            )
            .trim(),
        )
        .unwrap();
    let parsed = hguet_core::parse_transaction(&wire).unwrap();
    let envelope: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/signed-direct-token-source-cap-equal.json"
    ))
    .unwrap();
    for (id, code) in [
        (6, "RPC_SIGNED_SOURCE_ADDITIONAL_READ_UNAVAILABLE"),
        (7, "RPC_CPI_SOURCE_READ_UNAVAILABLE"),
    ] {
        for invalid_response in [false, true] {
            let count = parsed.static_account_count;
            let mut response =
                simulation(900, Value::Null, &vec![10000; count], &vec![10000; count]);
            let mut request = args(&wire, true);
            if id == 6 {
                request.intent = Some(temp_file(
                    "source-read-intent.json",
                    include_bytes!(
                        "../../../tests/fixtures/signed-direct-token-source-cap-equal.json"
                    ),
                ));
                request.trusted_key = Some(envelope["signer_pubkey_b58"].as_str().unwrap().into());
            } else {
                let ix = &parsed.compiled_top_level_instructions[0];
                response["value"]["innerInstructions"] = json!([{"index":0,"instructions":[{
                    "programIdIndex":ix.program_index,"accounts":ix.account_indices,"data":ix.data_base58
                }]}]);
            }
            let rpc = RejectRead {
                rpc: FakeRpc::new(response),
                id,
                invalid_response,
                rejected: std::cell::Cell::new(false),
            };
            let (report, exit) = execute_with(request, &rpc);
            assert!(rpc.rejected.get(), "additional read was not exercised");
            assert_never_permits(&report, exit);
            assert_eq!(exit, 30);
            assert!(codes(&report).contains(&code.to_owned()), "{report}");
            if id == 6 {
                assert_eq!(report["verdict"]["intent_status"], "signature_verified");
                assert!(codes(&report)
                    .contains(&"SIGNED_INTENT_SOURCE_SCOPE_PARTIAL_COVERAGE".to_owned()));
            }
        }
    }
}

fn temp_file(name: &str, contents: &[u8]) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut path: PathBuf = std::env::temp_dir();
    path.push(format!(
        "hguet-pipeline-{}-{}-{name}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, contents).expect("write temporary test input");
    path.to_string_lossy().into_owned()
}

fn payer() -> [u8; 32] {
    [7u8; 32]
}
fn b58(key: &[u8; 32]) -> String {
    bs58::encode(key).into_string()
}

/// Unsigned legacy transfer of `lamports` from the payer to [2;32].
fn legacy_transfer(lamports: u64) -> Vec<u8> {
    let mut wire = vec![1];
    wire.extend([0u8; 64]);
    wire.extend([1, 0, 1, 3]);
    wire.extend(payer());
    wire.extend([2u8; 32]);
    wire.extend([0u8; 32]);
    wire.extend([3u8; 32]);
    wire.extend([1, 2, 2, 0, 1, 12]);
    wire.extend(2u32.to_le_bytes());
    wire.extend(lamports.to_le_bytes());
    wire
}

/// The same transfer as a v0 message whose RECIPIENT is index 0 of a lookup table.
fn v0_transfer_to_lookup(lamports: u64) -> Vec<u8> {
    let mut wire = vec![1];
    wire.extend([0u8; 64]);
    wire.push(0x80);
    wire.extend([1, 0, 1, 2]);
    wire.extend(payer());
    wire.extend([0u8; 32]);
    wire.extend([3u8; 32]);
    wire.extend([1, 1, 2, 0, 2, 12]);
    wire.extend(2u32.to_le_bytes());
    wire.extend(lamports.to_le_bytes());
    wire.push(1);
    wire.extend([9u8; 32]);
    wire.extend([1, 0, 0]);
    wire
}

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[42u8; 32])
}
fn issuer_key() -> String {
    bs58::encode(issuer().verifying_key().to_bytes()).into_string()
}

fn signed_payload_file(payload: &Value) -> String {
    let bytes = serde_json::to_vec(payload).unwrap();
    let mut signed = b"HGUET-PAYMENT-INTENT\0".to_vec();
    signed.extend(&bytes);
    let envelope = json!({"payload_b64":STANDARD.encode(&bytes),"signer_pubkey_b58":issuer_key(),
        "signature_b58":bs58::encode(issuer().sign(&signed).to_bytes()).into_string()});
    temp_file(
        "signed-payload.json",
        &serde_json::to_vec(&envelope).unwrap(),
    )
}

/// A signed intent bound to `wire`, valid now, System program only.
fn intent_file(wire: &[u8], max_spend: &str) -> String {
    let parsed = hguet_core::parse_transaction(wire).expect("test transaction parses");
    let payload = json!({
        "schema_version":1,"kind":"hguet_payment_intent","intent_id":"pipeline-test",
        "network":"devnet","message_sha256":parsed.message_sha256,
        "not_before_unix":1,"expires_at_unix":4102444800u64,
        "allowed_program_ids":[SYSTEM],"max_spend_lamports":max_spend
    });
    let bytes = serde_json::to_vec(&payload).unwrap();
    let mut message = b"HGUET-PAYMENT-INTENT\0".to_vec();
    message.extend(&bytes);
    let envelope = json!({
        "payload_b64":STANDARD.encode(&bytes),
        "signer_pubkey_b58":issuer_key(),
        "signature_b58":bs58::encode(issuer().sign(&message).to_bytes()).into_string()
    });
    temp_file("intent.json", &serde_json::to_vec(&envelope).unwrap())
}

fn args(wire: &[u8], rpc: bool) -> Args {
    Args {
        command: "check".into(),
        file: temp_file("tx.bin", wire),
        network: "devnet".into(),
        encoding: "binary".into(),
        intent: None,
        trusted_key: None,
        policy: None,
        rpc_url: rpc.then(|| "https://rpc.invalid".to_owned()),
        mode: "local".into(),
        offline: !rpc,
    }
}

fn simulation(slot: u64, err: Value, pre: &[u64], post: &[u64]) -> Value {
    json!({"context":{"slot":slot},"value":{
        "err":err,"logs":[],"innerInstructions":[],"unitsConsumed":150,
        "preBalances":pre,"postBalances":post,"fee":5000,
        "loadedAddresses":{"writable":[],"readonly":[]}
    }})
}

fn codes(report: &Value) -> Vec<String> {
    report["verdict"]["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|f| f["code"].as_str().unwrap().to_owned())
        .collect()
}

/// Invariants every report must satisfy, whatever the inputs and the provider say.
fn assert_never_permits(report: &Value, exit: i32) {
    let decision = report["verdict"]["decision"].as_str().unwrap();
    assert!(
        decision == "DENY" || decision == "UNKNOWN",
        "decision {decision}"
    );
    assert!(exit == 20 || exit == 30, "exit {exit}");
    assert_eq!(exit == 20, decision == "DENY");
    if let Some(boundary) = report.get("signing_boundary").filter(|b| !b.is_null()) {
        assert_eq!(boundary["signing_gate"], "block");
        assert_eq!(boundary["automated_signing_permitted"], false);
        assert_eq!(boundary["total_native_sol_spending_proven"], false);
        assert_eq!(boundary["total_gross_token_spending_proven"], false);
    }
}

#[test]
fn successful_simulation_is_reported_but_never_permits_signing() {
    let wire = legacy_transfer(75);
    let rpc = FakeRpc::new(simulation(
        900,
        Value::Null,
        &[10_000, 0, 1],
        &[4_925, 75, 1],
    ));
    let (report, exit) = execute_with(args(&wire, true), &rpc);
    assert_never_permits(&report, exit);
    assert_eq!(exit, 30);
    assert_eq!(report["verdict"]["simulation_status"], "rpc_succeeded");
    let found = codes(&report);
    assert!(
        found.contains(&"RPC_SIMULATION_ONLY".to_owned()),
        "{found:?}"
    );
    assert!(found.contains(&"INTENT_UNVERIFIED".to_owned()), "{found:?}");
    let coverage = report["verdict"]["coverage"].to_string();
    for needed in [
        "solana_rpc_genesis_verified",
        "rpc_paired_native_balance_snapshots",
        "block_only_signing_boundary",
    ] {
        assert!(coverage.contains(needed), "missing coverage {needed}");
    }
    assert_eq!(rpc.methods(), ["getGenesisHash", "simulateTransaction"]);
    // The original bytes are what was simulated, without signature verification by the node.
    let request = rpc.requests.borrow()[1].clone();
    assert_eq!(request["params"][0], STANDARD.encode(&wire));
    assert_eq!(request["params"][1]["sigVerify"], false);
    let v2 = hguet::report_v2::from_v1(report.clone(), exit, false);
    for (scope, expected) in [
        ("single_provider_compiled_cpi_declarations", "PARTIAL"),
        ("single_provider_native_account_net_changes", "PARTIAL"),
        ("single_provider_token_account_net_changes", "UNSUPPORTED"),
        ("later_non_atomic_rpc_account_state", "UNSUPPORTED"),
    ] {
        assert_eq!(
            v2.coverage
                .iter()
                .find(|entry| entry.scope == scope)
                .unwrap()
                .status,
            expected
        );
    }
    assert_eq!(v2.evidence, report);
    assert_eq!(v2.signing_authorization, "NOT_AUTHORIZED");
}

#[test]
fn failed_simulation_and_wrong_cluster_are_unknown_not_safe() {
    let wire = legacy_transfer(75);
    let failed = FakeRpc::new(simulation(
        900,
        json!({"InstructionError":[0,"Custom"]}),
        &[10_000, 0, 1],
        &[10_000, 0, 1],
    ));
    let (report, exit) = execute_with(args(&wire, true), &failed);
    assert_never_permits(&report, exit);
    assert_eq!(report["verdict"]["simulation_status"], "rpc_failed");
    assert!(codes(&report).contains(&"RPC_SIMULATION_FAILED".to_owned()));

    let mut wrong = FakeRpc::new(simulation(900, Value::Null, &[1, 1, 1], &[1, 1, 1]));
    wrong.genesis = MAINNET_GENESIS;
    let (report, exit) = execute_with(args(&wire, true), &wrong);
    assert_never_permits(&report, exit);
    assert_eq!(report["verdict"]["simulation_status"], "rpc_unavailable");
    assert!(codes(&report).contains(&"RPC_GENESIS_MISMATCH".to_owned()));
    // The transaction is never sent to a provider on the wrong cluster.
    assert_eq!(wrong.methods(), ["getGenesisHash"]);
}

#[test]
fn a_local_hard_deny_is_decided_before_the_provider_sees_the_transaction() {
    let wire = legacy_transfer(75);
    let policy = temp_file(
        "policy.toml",
        b"version = 1\nnetwork = \"devnet\"\nmax_declared_system_transfer_lamports = \"74\"\n",
    );
    let mut request = args(&wire, true);
    request.policy = Some(policy);
    let (report, exit) = execute_with(request, &Unreachable);
    assert_eq!(exit, 20);
    assert_eq!(report["verdict"]["decision"], "DENY");
    assert!(codes(&report).contains(&"POLICY_SOL_TRANSFER_CAP".to_owned()));

    // A rejected intent and an invalid transaction signature stop before the RPC as well.
    let mut over_cap = args(&wire, true);
    over_cap.intent = Some(intent_file(&wire, "74"));
    over_cap.trusted_key = Some(issuer_key());
    let (report, exit) = execute_with(over_cap, &Unreachable);
    assert_eq!(exit, 20);
    assert!(codes(&report).contains(&"INTENT_REJECTED".to_owned()));

    let mut forged = wire.clone();
    forged[1..65].fill(9);
    let (report, exit) = execute_with(args(&forged, true), &Unreachable);
    assert_eq!(exit, 20);
    assert!(codes(&report).contains(&"INVALID_TRANSACTION_SIGNATURE".to_owned()));
}

#[test]
fn verified_intent_is_compared_with_simulated_payer_outflow() {
    let wire = legacy_transfer(75);
    let mut request = args(&wire, true);
    request.intent = Some(intent_file(&wire, "100"));
    request.trusted_key = Some(issuer_key());
    // The declared transfer (75) fits the cap (100); the simulated payer loss (5075) does not.
    let rpc = FakeRpc::new(simulation(
        900,
        Value::Null,
        &[10_000, 0, 1],
        &[4_925, 75, 1],
    ));
    let (report, exit) = execute_with(request, &rpc);
    assert_never_permits(&report, exit);
    assert_eq!(exit, 30, "an advisory RPC observation never becomes a DENY");
    assert_eq!(report["verdict"]["intent_status"], "signature_verified");
    assert!(codes(&report).contains(&"RPC_FEE_PAYER_NET_OUTFLOW_OVER_CAP".to_owned()));
    assert_eq!(
        report["signing_boundary"]["independent_intent_verified_by_caller"],
        true
    );

    // Inside the cap: no outflow finding.
    let mut request = args(&wire, true);
    request.intent = Some(intent_file(&wire, "100"));
    request.trusted_key = Some(issuer_key());
    let rpc = FakeRpc::new(simulation(
        900,
        Value::Null,
        &[10_000, 0, 1],
        &[9_925, 75, 1],
    ));
    let (report, _) = execute_with(request, &rpc);
    assert!(!codes(&report).contains(&"RPC_FEE_PAYER_NET_OUTFLOW_OVER_CAP".to_owned()));
}

#[test]
fn lookup_table_with_a_signed_intent_reaches_the_rpc_and_stays_advisory() {
    let wire = v0_transfer_to_lookup(75);
    let mut request = args(&wire, true);
    request.intent = Some(intent_file(&wire, "100"));
    request.trusted_key = Some(issuer_key());
    // Accounts: payer, System program, then the looked-up recipient.
    let mut response = simulation(501, Value::Null, &[10_000, 1, 0], &[4_925, 1, 75]);
    // The provider's own view of the loaded addresses must agree with the table it served.
    response["value"]["loadedAddresses"] = json!({"writable":[b58(&[55u8; 32])],"readonly":[]});
    let rpc = FakeRpc::new(response);
    let (report, exit) = execute_with(request, &rpc);
    assert_never_permits(&report, exit);
    assert_eq!(exit, 30);
    assert_eq!(
        rpc.methods(),
        [
            "getGenesisHash",
            "getMultipleAccounts",
            "simulateTransaction"
        ],
        "the lookup table must be resolved and the transaction simulated"
    );
    assert_eq!(report["verdict"]["simulation_status"], "rpc_succeeded");
    assert_eq!(
        report["verdict"]["intent_status"],
        "signature_verified_scope_incomplete"
    );
    let found = codes(&report);
    for needed in [
        "INTENT_COVERAGE_INCOMPLETE",
        "INTENT_SCOPE_ADVISORY_ONLY",
        "RPC_FEE_PAYER_NET_OUTFLOW_OVER_CAP",
    ] {
        assert!(
            found.contains(&needed.to_owned()),
            "missing {needed}: {found:?}"
        );
    }
    assert_eq!(report["coverage_gaps"][0]["reason"], "ALT_UNRESOLVED");
    assert_eq!(report["coverage_gaps"][0]["violation_proven"], false);
    // The intent is NOT treated as verified for the signing boundary.
    assert_eq!(
        report["signing_boundary"]["independent_intent_verified_by_caller"],
        false
    );
    assert_eq!(
        report["rpc_analysis"]["lookup_resolution"]["resolved_writable_accounts"][0],
        b58(&[55u8; 32])
    );

    // A provider whose simulation contradicts the lookup table it just served is not believed.
    let mut contradicting = args(&wire, true);
    contradicting.intent = Some(intent_file(&wire, "100"));
    contradicting.trusted_key = Some(issuer_key());
    let mut response = simulation(501, Value::Null, &[10_000, 1, 0], &[4_925, 1, 75]);
    response["value"]["loadedAddresses"] = json!({"writable":[b58(&[66u8; 32])],"readonly":[]});
    let (report, exit) = execute_with(contradicting, &FakeRpc::new(response));
    assert_never_permits(&report, exit);
    assert_eq!(report["verdict"]["simulation_status"], "rpc_unavailable");

    // Without --rpc-url the same input stops at the coverage gap and contacts nobody.
    let mut offline = args(&wire, false);
    offline.intent = Some(intent_file(&wire, "100"));
    offline.trusted_key = Some(issuer_key());
    let (report, exit) = execute_with(offline, &Unreachable);
    assert_eq!(exit, 30);
    assert_eq!(report["verdict"]["simulation_status"], "not_performed");
    assert!(codes(&report).contains(&"INTENT_COVERAGE_INCOMPLETE".to_owned()));
}

#[test]
fn a_static_violation_is_denied_even_when_a_lookup_table_is_unresolved() {
    // 75 lamports to a looked-up recipient against a signed cap of 74.
    let wire = v0_transfer_to_lookup(75);
    let mut request = args(&wire, true);
    request.intent = Some(intent_file(&wire, "74"));
    request.trusted_key = Some(issuer_key());
    let (report, exit) = execute_with(request, &Unreachable);
    assert_eq!(exit, 20);
    assert!(codes(&report).contains(&"INTENT_REJECTED".to_owned()));
}

#[test]
fn a_provider_that_claims_approval_or_lies_cannot_produce_allow() {
    let wire = legacy_transfer(75);
    let hostile = [
        // Extra fields claiming permission.
        json!({"context":{"slot":900},"value":{"err":null,"logs":[],"innerInstructions":[],
            "decision":"ALLOW","signing_gate":"allow","automated_signing_permitted":true,
            "preBalances":[1,1,1],"postBalances":[1,1,1]}}),
        // No evidence at all.
        json!({"context":{"slot":900},"value":{"err":null}}),
        // Balances that do not match the account list.
        json!({"context":{"slot":900},"value":{"err":null,"preBalances":[1],"postBalances":[1,2,3]}}),
        // Slot zero, wrong shapes, missing value.
        json!({"context":{"slot":0},"value":{"err":null}}),
        json!({"context":{"slot":900},"value":"ok"}),
        json!({"context":{"slot":900}}),
        json!("ALLOW"),
        Value::Null,
    ];
    for simulation in hostile {
        let rpc = FakeRpc::new(simulation.clone());
        let (report, exit) = execute_with(args(&wire, true), &rpc);
        assert_never_permits(&report, exit);
        assert_eq!(exit, 30, "provider response {simulation}");
        let text = report.to_string();
        assert!(
            !text.contains("\"ALLOW\""),
            "ALLOW leaked from {simulation}"
        );
        assert!(!text.contains("\"signing_gate\":\"allow\""));
    }
}

#[test]
fn check_without_an_intent_and_offline_inspection_stay_local() {
    let wire = legacy_transfer(75);
    let (report, exit) = execute_with(args(&wire, false), &Unreachable);
    assert_never_permits(&report, exit);
    assert_eq!(exit, 30);
    assert_eq!(
        report["verdict"]["intent_status"],
        "unverified_no_independent_trust_key"
    );
    assert!(codes(&report).contains(&"NO_SIMULATION".to_owned()));

    // A pinned key without an intent is reported, with a schema-valid status.
    let mut keyed = args(&wire, false);
    keyed.trusted_key = Some(issuer_key());
    let (report, _) = execute_with(keyed, &Unreachable);
    assert_eq!(report["verdict"]["intent_status"], "not_checked");
    assert!(codes(&report).contains(&"INTENT_UNVERIFIED".to_owned()));

    let mut inspect = args(&wire, false);
    inspect.command = "inspect".into();
    let (report, exit) = execute_with(inspect, &Unreachable);
    assert_eq!(exit, 0);
    assert_eq!(report["verdict"]["decision"], "UNKNOWN");
}

#[test]
fn every_input_encoding_yields_the_same_inspection() {
    let wire = legacy_transfer(75);
    let mut reports = Vec::new();
    for (encoding, contents) in [
        ("binary", wire.clone()),
        (
            "base64",
            format!("{}\n", STANDARD.encode(&wire)).into_bytes(),
        ),
        (
            "base58",
            format!("{}\n", bs58::encode(&wire).into_string()).into_bytes(),
        ),
    ] {
        let mut request = args(&wire, false);
        request.file = temp_file("tx.enc", &contents);
        request.encoding = encoding.into();
        let (report, exit) = execute_with(request, &Unreachable);
        assert_eq!(exit, 30, "{encoding}");
        reports.push(report["inspection"].clone());
    }
    assert_eq!(reports[0], reports[1]);
    assert_eq!(reports[0], reports[2]);
    assert_eq!(reports[0]["declared_system_transfer_lamports"], "75");
}

#[test]
fn unreadable_oversized_and_malformed_inputs_are_errors_not_verdicts_of_safety() {
    let mut missing = args(&legacy_transfer(1), false);
    missing.file = "this-file-does-not-exist.bin".into();
    let (report, exit) = execute_with(missing, &Unreachable);
    assert_eq!((exit, report["code"].as_str()), (40, Some("BAD_INPUT")));

    let (report, exit) = execute_with(args(&vec![0u8; 16_385], false), &Unreachable);
    assert_eq!((exit, report["code"].as_str()), (40, Some("BAD_INPUT")));

    let mut truncated = legacy_transfer(75);
    truncated.truncate(100);
    let (report, exit) = execute_with(args(&truncated, false), &Unreachable);
    assert_eq!(exit, 40);
    assert_eq!(report["verdict"]["decision"], "DENY");
    assert!(codes(&report).contains(&"MALFORMED_TRANSACTION".to_owned()));

    let mut bad_policy = args(&legacy_transfer(75), false);
    bad_policy.policy = Some(temp_file(
        "policy.toml",
        b"version = 1\nnetwork = \"devnet\"\nsurprise = true\n",
    ));
    let (report, exit) = execute_with(bad_policy, &Unreachable);
    assert_eq!((exit, report["code"].as_str()), (40, Some("BAD_POLICY")));
}

#[test]
fn unsupported_version_is_unknown_and_never_contacts_rpc() {
    let mut wire = legacy_transfer(75);
    wire[65] = 0x82;
    let (report, exit) = execute_with(args(&wire, true), &Unreachable);
    assert_eq!(exit, 30);
    assert_eq!(report["verdict"]["decision"], "UNKNOWN");
    assert!(codes(&report).contains(&"UNSUPPORTED_FORMAT".to_owned()));
    let (supported, _) = execute_with(args(&legacy_transfer(75), false), &Unreachable);
    assert!(!codes(&supported).contains(&"UNSUPPORTED_FORMAT".to_owned()));
}

#[test]
fn oversized_token_instruction_retains_decoder_coverage_gap() {
    let wire = STANDARD
        .decode(include_str!("../../../tests/fixtures/token-oversized-instruction.base64").trim())
        .unwrap();
    let (report, exit) = execute_with(args(&wire, false), &Unreachable);
    assert_never_permits(&report, exit);
    assert_eq!(exit, 30);
    assert!(codes(&report).contains(&"WIRE_TOKEN_DIRECT_DECODER_UNAVAILABLE".to_owned()));
    let normal = STANDARD
        .decode(include_str!("../../../tests/fixtures/legacy-spl-transfer-checked.base64").trim())
        .unwrap();
    let (report, _) = execute_with(args(&normal, false), &Unreachable);
    assert!(!codes(&report).contains(&"WIRE_TOKEN_DIRECT_DECODER_UNAVAILABLE".to_owned()));
}

#[test]
fn missing_rpc_effect_fields_are_reported_without_inventing_zeroes() {
    let wire = legacy_transfer(75);
    let mut response = simulation(900, Value::Null, &[10000, 0, 1], &[4925, 75, 1]);
    response["value"]
        .as_object_mut()
        .unwrap()
        .remove("preBalances");
    response["value"]
        .as_object_mut()
        .unwrap()
        .remove("innerInstructions");
    let (report, exit) = execute_with(args(&wire, true), &FakeRpc::new(response));
    assert_never_permits(&report, exit);
    assert!(codes(&report).contains(&"RPC_EFFECT_EVIDENCE_INCOMPLETE".to_owned()));
    assert!(report["rpc_analysis"]["effect_analysis"]["lamport_deltas"].is_null());
}

#[test]
fn unpaired_token_balance_is_unknown_instead_of_zero_loss() {
    let wire = legacy_transfer(75);
    let mut response = simulation(900, Value::Null, &[10000, 0, 1], &[4925, 75, 1]);
    response["value"]["preTokenBalances"] = json!([{
        "accountIndex":1,"mint":b58(&[9;32]),"owner":b58(&payer()),
        "uiTokenAmount":{"amount":"123","decimals":6}
    }]);
    response["value"]["postTokenBalances"] = json!([]);
    let (report, exit) = execute_with(args(&wire, true), &FakeRpc::new(response));
    assert_never_permits(&report, exit);
    assert!(
        codes(&report).contains(&"RPC_TOKEN_DELTA_UNDETERMINED".to_owned()),
        "{report}"
    );
    assert!(
        report["rpc_analysis"]["effect_analysis"]["token_deltas"][0]["delta_raw_amount"].is_null()
    );
    let mut complete = simulation(900, Value::Null, &[10000, 0, 1], &[4925, 75, 1]);
    complete["value"]["preTokenBalances"] = json!([]);
    complete["value"]["postTokenBalances"] = json!([]);
    let (report, _) = execute_with(args(&wire, true), &FakeRpc::new(complete));
    assert!(!codes(&report).contains(&"RPC_TOKEN_DELTA_UNDETERMINED".to_owned()));
}

#[test]
fn cpi_outside_signed_program_scope_is_advisory_and_not_authorization() {
    let wire = legacy_transfer(75);
    for (program_index, expected) in [(1, true), (2, false)] {
        let mut request = args(&wire, true);
        request.intent = Some(intent_file(&wire, "10000"));
        request.trusted_key = Some(issuer_key());
        let mut response = simulation(900, Value::Null, &[10000, 0, 1], &[4925, 75, 1]);
        response["value"]["innerInstructions"] = json!([{"index":0,"instructions":[
            {"programIdIndex":program_index,"accounts":[0,1],"data":"1"}
        ]}]);
        let (report, exit) = execute_with(request, &FakeRpc::new(response));
        assert_never_permits(&report, exit);
        assert_eq!(exit, 30);
        assert_eq!(
            codes(&report).contains(&"RPC_CPI_OUTSIDE_SIGNED_INTENT".to_owned()),
            expected
        );
    }
}

#[test]
fn signed_token_cap_findings_preserve_scope_and_reject_overages_before_rpc() {
    for (wire_text, envelope_text, partial) in [
        (
            include_str!("../../../tests/fixtures/legacy-spl-transfer-checked.base64"),
            include_str!("../../../tests/fixtures/signed-direct-token-cap-equal.json"),
            "SIGNED_INTENT_TOKEN_CAP_PARTIAL_COVERAGE",
        ),
        (
            include_str!(
                "../../../tests/fixtures/legacy-spl-transfer-checked-authority-signer.base64"
            ),
            include_str!("../../../tests/fixtures/signed-direct-token-source-cap-equal.json"),
            "SIGNED_INTENT_SOURCE_SCOPE_PARTIAL_COVERAGE",
        ),
    ] {
        let wire = STANDARD.decode(wire_text.trim()).unwrap();
        let original: Value = serde_json::from_str(envelope_text).unwrap();
        let mut request = args(&wire, false);
        request.intent = Some(temp_file("equal-intent.json", envelope_text.as_bytes()));
        request.trusted_key = Some(original["signer_pubkey_b58"].as_str().unwrap().into());
        let (report, exit) = execute_with(request, &Unreachable);
        assert_eq!(exit, 30);
        assert!(codes(&report).contains(&partial.to_owned()));
        let mut payload: Value = serde_json::from_slice(
            &STANDARD
                .decode(original["payload_b64"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();
        payload["token_spend_limits"][0]["max_debit_raw"] = json!("1233");
        let bytes = serde_json::to_vec(&payload).unwrap();
        let mut signed = b"HGUET-PAYMENT-INTENT\0".to_vec();
        signed.extend(&bytes);
        let envelope = json!({"payload_b64":STANDARD.encode(&bytes),"signer_pubkey_b58":issuer_key(),
            "signature_b58":bs58::encode(issuer().sign(&signed).to_bytes()).into_string()});
        let mut request = args(&wire, true);
        request.intent = Some(temp_file(
            "over-intent.json",
            &serde_json::to_vec(&envelope).unwrap(),
        ));
        request.trusted_key = Some(issuer_key());
        let (report, exit) = execute_with(request, &Unreachable);
        assert_eq!(exit, 20);
        assert!(codes(&report).contains(&"INTENT_REJECTED".to_owned()));
        assert!(!codes(&report).contains(&partial.to_owned()));
        if payload.get("token_source_limits").is_some() {
            payload["token_spend_limits"][0]["max_debit_raw"] = json!("1234");
            payload["token_source_limits"][0]["max_debit_raw"] = json!("1233");
            let mut request = args(&wire, true);
            request.intent = Some(signed_payload_file(&payload));
            request.trusted_key = Some(issuer_key());
            let (report, exit) = execute_with(request, &Unreachable);
            assert_eq!(exit, 20);
            assert!(codes(&report).contains(&"INTENT_REJECTED".to_owned()));
            assert!(!codes(&report).contains(&partial.to_owned()));
        }
        payload
            .as_object_mut()
            .unwrap()
            .remove("token_spend_limits");
        payload
            .as_object_mut()
            .unwrap()
            .remove("token_source_limits");
        let mut request = args(&wire, false);
        request.intent = Some(signed_payload_file(&payload));
        request.trusted_key = Some(issuer_key());
        let (report, exit) = execute_with(request, &Unreachable);
        assert_eq!(exit, 30);
        assert!(codes(&report).contains(&"SIGNED_INTENT_TOKEN_CAP_UNSPECIFIED".to_owned()));
        assert!(!codes(&report).contains(&partial.to_owned()));
    }
}

#[test]
fn duplicate_wire_accounts_are_rejected_before_rpc_aggregation() {
    let mut wire = legacy_transfer(75);
    wire[101..133].copy_from_slice(&payer());
    let (report, exit) = execute_with(args(&wire, true), &Unreachable);
    assert_eq!(exit, 40);
    assert!(
        codes(&report).contains(&"MALFORMED_TRANSACTION".to_owned()),
        "{report}"
    );
    assert!(!codes(&report).contains(&"RPC_AGGREGATE_TOKEN_ANALYSIS_INVALID".to_owned()));

    let wire = legacy_transfer(75);
    let mut response = simulation(900, Value::Null, &[10000, 10000, 1], &[10000, 10000, 1]);
    for (field, amount) in [("preTokenBalances", "100"), ("postTokenBalances", "90")] {
        response["value"][field] = json!([0, 1]
            .into_iter()
            .map(|index| json!({
                "accountIndex":index,"mint":b58(&[9;32]),"owner":b58(&payer()),
                "uiTokenAmount":{"amount":amount,"decimals":6}
            }))
            .collect::<Vec<_>>());
    }
    let (report, exit) = execute_with(args(&wire, true), &FakeRpc::new(response));
    assert_never_permits(&report, exit);
    assert_eq!(exit, 30);
    assert!(!codes(&report).contains(&"RPC_AGGREGATE_TOKEN_ANALYSIS_INVALID".to_owned()));
    assert!(report["aggregate_token_spending"].is_object(), "{report}");
}

#[test]
fn changing_provider_mint_identity_is_rejected_before_aggregation() {
    for changed in [false, true] {
        let wire = legacy_transfer(75);
        let mut response = simulation(900, Value::Null, &[10000, 10000, 1], &[10000, 10000, 1]);
        for (field, amount, mint) in [
            ("preTokenBalances", "100", [9; 32]),
            (
                "postTokenBalances",
                "90",
                if changed { [8; 32] } else { [9; 32] },
            ),
        ] {
            response["value"][field] = json!([{
                "accountIndex":1,"mint":b58(&mint),"owner":b58(&payer()),
                "uiTokenAmount":{"amount":amount,"decimals":6}
            }]);
        }
        let (report, exit) = execute_with(args(&wire, true), &FakeRpc::new(response));
        assert_never_permits(&report, exit);
        assert_eq!(exit, 30);
        assert_eq!(
            codes(&report).contains(&"RPC_RESPONSE_INVALID".to_owned()),
            changed,
            "{report}"
        );
        if changed {
            assert!(report["aggregate_token_spending"].is_null());
        } else {
            assert!(report["aggregate_token_spending"].is_object());
        }
    }
}

#[test]
fn cpi_item_limit_is_enforced_before_source_correlation_and_aggregation() {
    let token_program = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    let mut data = vec![12];
    data.extend(1u64.to_le_bytes());
    data.push(6);
    for count in [512, 513] {
        let wire = legacy_transfer(75);
        let mut response = simulation(900, Value::Null, &[10000, 0, 1], &[4925, 75, 1]);
        let ix = json!({"programId":token_program,"accounts":[0,1,1,0],
            "data":bs58::encode(&data).into_string()});
        response["value"]["innerInstructions"] = json!([{"index":0,"instructions":vec![ix;count]}]);
        let rpc = FakeRpc::new(response);
        let (report, exit) = execute_with(args(&wire, true), &rpc);
        assert_never_permits(&report, exit);
        assert_eq!(exit, 30);
        assert_eq!(
            codes(&report).contains(&"RPC_RESPONSE_INVALID".to_owned()),
            count == 513,
            "{report}"
        );
        for code in [
            "RPC_CPI_SOURCE_CORRELATION_INVALID",
            "RPC_AGGREGATE_TOKEN_ANALYSIS_INVALID",
        ] {
            assert!(!codes(&report).contains(&code.to_owned()), "{report}");
        }
        if count == 512 {
            assert_eq!(
                report["cpi_source_coverage"]["entries"]
                    .as_array()
                    .unwrap()
                    .len(),
                512
            );
            assert_eq!(
                report["aggregate_token_spending"]["mints"][0]["rpc_cpi_checked_debit_raw"],
                "512"
            );
            assert!(rpc
                .requests
                .borrow()
                .iter()
                .any(|request| request["id"] == 7));
        } else {
            assert!(report["aggregate_token_spending"].is_null());
            assert!(!rpc
                .requests
                .borrow()
                .iter()
                .any(|request| request["id"] == 7));
        }
    }
}

#[test]
fn conflicting_cpi_token_programs_do_not_invent_source_authority() {
    let legacy = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
    let token2022 = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
    let mut data = vec![12];
    data.extend(1u64.to_le_bytes());
    data.push(6);
    for conflicting in [false, true] {
        let wire = legacy_transfer(75);
        let mut response = simulation(900, Value::Null, &[10000, 0, 1], &[4925, 75, 1]);
        response["value"]["innerInstructions"] = json!([{"index":0,"instructions":
            ([legacy, if conflicting { token2022 } else { legacy }].into_iter().map(|program|
                json!({"programId":program,"accounts":[0,1,1,0],"data":bs58::encode(&data).into_string()})
            ).collect::<Vec<_>>())
        }]);
        let rpc = FakeRpc::new(response);
        let (report, exit) = execute_with(args(&wire, true), &rpc);
        assert_never_permits(&report, exit);
        assert_eq!(exit, 30);
        assert_eq!(
            codes(&report).contains(&"RPC_CPI_SOURCE_READ_UNAVAILABLE".to_owned()),
            conflicting,
            "{report}"
        );
        assert_eq!(
            rpc.requests
                .borrow()
                .iter()
                .any(|request| request["id"] == 7),
            !conflicting
        );
        let entries = report["cpi_source_coverage"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 2);
        for entry in entries {
            assert_eq!(entry["authorization_proven"], false);
            assert_eq!(entry["authority_relationship"], "unobserved");
            assert!(entry["observed_owner"].is_null());
            assert_eq!(
                entry["observation_source"],
                if conflicting {
                    "unobserved"
                } else {
                    "cpi_source_rpc"
                }
            );
        }
        assert_eq!(
            report["aggregate_token_spending"]["mints"][0]["rpc_cpi_checked_debit_raw"],
            "2"
        );
        assert_eq!(
            report["aggregate_token_spending"]["total_gross_token_spend_proven"],
            false
        );
    }
}

#[test]
fn typed_rpc_errors_preserve_their_finding_codes_and_refusal() {
    struct ErrorRpc(RpcError);
    impl JsonRpcTransport for ErrorRpc {
        fn post_json(&self, _: &str, _: &Value) -> Result<Value, RpcError> {
            Err(self.0.clone())
        }
    }
    for (error, code) in [
        (RpcError::InvalidEndpoint, "RPC_ENDPOINT_INVALID"),
        (RpcError::UnsupportedNetwork, "RPC_NETWORK_UNSUPPORTED"),
        (RpcError::Transport, "RPC_TRANSPORT_FAILURE"),
        (RpcError::TooLarge, "RPC_RESPONSE_TOO_LARGE"),
        (RpcError::InvalidResponse, "RPC_RESPONSE_INVALID"),
        (RpcError::RpcRejected, "RPC_REQUEST_REJECTED"),
        (RpcError::GenesisMismatch, "RPC_GENESIS_MISMATCH"),
    ] {
        let wire = legacy_transfer(75);
        let (report, exit) = execute_with(args(&wire, true), &ErrorRpc(error));
        assert_eq!(exit, 30);
        assert_never_permits(&report, exit);
        assert!(codes(&report).contains(&code.to_owned()), "{report}");
        assert_eq!(report["verdict"]["simulation_status"], "rpc_unavailable");
        let (normal, normal_exit) = execute_with(
            args(&wire, true),
            &FakeRpc::new(simulation(900, Value::Null, &[10000, 0, 1], &[4925, 75, 1])),
        );
        assert_never_permits(&normal, normal_exit);
        assert!(!codes(&normal).contains(&code.to_owned()));
    }
}
