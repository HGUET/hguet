//! A whole paid check with real ML-DSA-87 signatures (OpenSSL >= 3.5): receipt + assessment signed by a server key, verified
//! against a pinned key. Skipped when OpenSSL cannot do ML-DSA-87 unless HGUET_REQUIRE_PQ_SIGNING is set.

use hguet_cloud::jcs::canonicalize_signed_payload;
use hguet_cloud::quote::QuoteBindings;
use hguet_cloud::report::{
    verify_paid_check, AnalysisState, AssessmentExpectations, ReceiptExpectations,
};
use hguet_cloud::trust::{Domain, PinnedKey, SIGNING_ALGORITHM};
use hguet_cloud::wire::v1::SignedPayload;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

const GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const RECEIVER: &str = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn temp(label: &str, data: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("hguet-paid-{}-{label}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(&path).unwrap().write_all(data).unwrap();
    path
}

fn sign(private: &PathBuf, domain: Domain, payload: &[u8], label: &str) -> Vec<u8> {
    let message = temp(label, &[domain.bytes(), payload].concat());
    let output = Command::new("openssl")
        .args(["pkeyutl", "-sign", "-rawin", "-inkey"])
        .arg(private)
        .arg("-in")
        .arg(&message)
        .output()
        .unwrap();
    let _ = std::fs::remove_file(message);
    assert!(output.status.success());
    output.stdout
}

#[test]
fn a_signed_receipt_and_assessment_verify_and_every_substitution_is_refused() {
    let generated = Command::new("openssl")
        .args(["genpkey", "-algorithm", "ML-DSA-87"])
        .output();
    let generated = match generated {
        Ok(output) if output.status.success() => output,
        _ if std::env::var_os("HGUET_REQUIRE_PQ_SIGNING").is_none() => {
            eprintln!("ML-DSA-87 unavailable; paid-check signing test skipped");
            return;
        }
        _ => panic!("ML-DSA-87 is required but unavailable"),
    };
    let private = temp("key.pem", &generated.stdout);
    let public = Command::new("openssl")
        .args(["pkey", "-pubout", "-in"])
        .arg(&private)
        .output()
        .unwrap();
    let key = PinnedKey::from_public_pem(&public.stdout, "openssl").unwrap();
    let qid = "a".repeat(32);

    let assessment = canonicalize_signed_payload(&json!({
        "schema_version": 1, "kind": "cloud_assessment", "network": "devnet", "genesis_hash": GENESIS,
        "message_sha256": hex(&[1; 32]), "intent_sha256": null, "requested_profile": "strict",
        "capabilities_performed": ["network_health"], "capabilities_unavailable": [], "risk_snapshot_id": "s",
        "ruleset_version": "v1", "evidence_digest": hex(&[7; 32]), "sources": [], "findings": [],
        "coverage": {"required": ["network_health"], "passed": ["network_health"], "unknown": []},
        "issued_at": "2025-10-09T08:53:20Z", "expires_at": "2025-10-09T09:08:20Z", "quote_id": qid,
        "environment": "sandbox", "data_scope": "metadata_only", "subjects_sha256": hex(&[3; 32]),
        "transaction_sha256": null
    }))
    .unwrap();
    let receipt = canonicalize_signed_payload(&json!({
        "schema_version": 1, "kind": "native_sol_payment_receipt", "quote_id": qid, "environment": "sandbox",
        "network": "devnet", "genesis_hash": GENESIS, "message_sha256": hex(&[1; 32]),
        "payment_signature": bs58::encode([5u8; 64]).into_string(), "payment_instruction_index": 0,
        "lamports_paid": "4000", "receiver": RECEIVER, "settled_slot": 9, "settled_commitment": "finalized",
        "analysis_state": "completed", "cloud_assessment_sha256": hex(&Sha256::digest(&assessment)),
        "issued_at": "2025-10-09T08:54:00Z"
    }))
    .unwrap();

    let signed = |payload: &[u8], domain: Domain, label: &str| SignedPayload {
        signature: sign(&private, domain, payload, label),
        canonical_payload: payload.to_vec(),
        key_id: key.key_id().to_owned(),
        signing_algorithm: SIGNING_ALGORITHM.to_owned(),
    };
    let signed_receipt = signed(&receipt, Domain::PaymentReceipt, "r");
    let signed_assessment = signed(&assessment, Domain::CloudAssessment, "a");

    let quote = QuoteBindings {
        quote_id: qid.clone(),
        receiver: RECEIVER.into(),
        memo_reference: format!("HGUET:{qid}"),
        lamports_due: 4000,
        issued_at_unix: 1_760_000_000,
        expires_at_unix: 1_760_000_900,
    };
    let capabilities = vec!["network_health".to_owned()];
    let receipt_expectations = ReceiptExpectations {
        quote: &quote,
        network: "devnet",
        genesis_hash: GENESIS,
        message_sha256: [1; 32],
        assessment_payload: None,
    };
    let assessment_expectations = AssessmentExpectations {
        quote_id: &qid,
        network: "devnet",
        genesis_hash: GENESIS,
        message_sha256: [1; 32],
        intent_sha256: None,
        transaction_sha256: None,
        subjects_sha256: [3; 32],
        profile: "strict",
        requested_capabilities: &capabilities,
        now_unix: 1_760_000_100,
    };

    let ok = verify_paid_check(
        &signed_receipt,
        Some(&signed_assessment),
        &key,
        &receipt_expectations,
        &assessment_expectations,
    )
    .unwrap();
    assert_eq!(ok.receipt.analysis_state, AnalysisState::Completed);
    assert!(!ok.assessment.unwrap().evidence_verified);

    // An assessment signed under the receipt domain is refused even though its bytes hash correctly.
    let wrong_domain = signed(&assessment, Domain::PaymentReceipt, "w");
    let code = |r: &SignedPayload, a: Option<&SignedPayload>| {
        verify_paid_check(r, a, &key, &receipt_expectations, &assessment_expectations)
            .unwrap_err()
            .code()
    };
    assert_eq!(
        code(&signed_receipt, Some(&wrong_domain)),
        "ASSESSMENT_SIGNATURE_INVALID"
    );
    // A different, validly signed assessment cannot be paired with this receipt.
    let mut other = serde_json::from_slice::<serde_json::Value>(&assessment).unwrap();
    other["risk_snapshot_id"] = json!("other");
    let other = signed(
        &canonicalize_signed_payload(&other).unwrap(),
        Domain::CloudAssessment,
        "o",
    );
    assert_eq!(
        code(&signed_receipt, Some(&other)),
        "RECEIPT_NOT_BOUND_TO_ASSESSMENT"
    );
    // A completed receipt without its assessment, and a forged receipt signature, are refused.
    assert_eq!(
        code(&signed_receipt, None),
        "RECEIPT_NOT_BOUND_TO_ASSESSMENT"
    );
    let mut forged = signed_receipt.clone();
    forged.signature[0] ^= 1;
    assert_eq!(
        code(&forged, Some(&signed_assessment)),
        "RECEIPT_SIGNATURE_INVALID_SERVER"
    );
    let _ = std::fs::remove_file(private);
}
