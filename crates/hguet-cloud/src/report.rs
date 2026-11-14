//! Binding checks for a payment receipt and a CloudAssessment, plus the combined paid-check verification.
//!
//! Rules this module enforces and never relaxes:
//! * a receipt must repeat what the client's verified quote said (quote id, network, genesis, message, environment,
//!   receiver), show at least the amount due, a canonical Solana signature, a finalized settlement, and - when the analysis
//!   completed - the SHA-256 of exactly the assessment bytes the client received;
//! * an assessment must be bound to this quote, this message/intent/transaction/subject set, this network and genesis, and
//!   be inside its validity window; its capability lists must be consistent with what was requested;
//! * a Cloud assessment is ADVISORY. The client holds no independent evidence for a real server's observations, so every
//!   finding is reported as unverified and [`final_decision`] never changes the local decision: Cloud can neither lower a
//!   local DENY/WARN nor turn anything into ALLOW.

use crate::jcs;
use crate::quote::{parse_timestamp, QuoteBindings};
use crate::trust::{Domain, PinnedKey};
use crate::wire::v1::SignedPayload;
use crate::{solana_signature, Error, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn optional_hex(value: Option<[u8; 32]>) -> Value {
    value.map_or(Value::Null, |d| Value::String(hex(&d)))
}

fn decimal(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    (!text.is_empty()
        && text.len() <= 20
        && text.bytes().all(|b| b.is_ascii_digit())
        && !text.starts_with('0'))
    .then(|| text.parse().ok())
    .flatten()
}

fn exact_keys(
    object: &serde_json::Map<String, Value>,
    keys: &[&str],
    error: &'static str,
) -> Result<()> {
    let have: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    if have == keys.iter().copied().collect::<BTreeSet<_>>() {
        Ok(())
    } else {
        Err(Error(error))
    }
}

fn string_set(value: &Value) -> Option<BTreeSet<String>> {
    let items = value.as_array()?;
    let set: BTreeSet<String> = items
        .iter()
        .map(|v| v.as_str().map(str::to_owned))
        .collect::<Option<_>>()?;
    (set.len() == items.len()).then_some(set)
}

// ------------------------------------------------------------------ receipt

const RECEIPT_KEYS: [&str; 16] = [
    "schema_version",
    "kind",
    "quote_id",
    "environment",
    "network",
    "genesis_hash",
    "message_sha256",
    "payment_signature",
    "payment_instruction_index",
    "lamports_paid",
    "receiver",
    "settled_slot",
    "settled_commitment",
    "analysis_state",
    "cloud_assessment_sha256",
    "issued_at",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnalysisState {
    Completed,
    Retryable,
    RefundRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptBindings {
    pub analysis_state: AnalysisState,
    pub lamports_paid: u64,
    pub payment_signature: String,
}

pub struct ReceiptExpectations<'a> {
    pub quote: &'a QuoteBindings,
    pub network: &'a str,
    pub genesis_hash: &'a str,
    pub message_sha256: [u8; 32],
    /// The canonical payload of the assessment delivered with the receipt, if any.
    pub assessment_payload: Option<&'a [u8]>,
}

pub fn verify_receipt_bindings(
    canonical_payload: &[u8],
    e: &ReceiptExpectations<'_>,
) -> Result<ReceiptBindings> {
    let value = jcs::parse_canonical(canonical_payload)?;
    let object = value.as_object().ok_or(Error("RECEIPT_KEYS"))?;
    exact_keys(object, &RECEIPT_KEYS, "RECEIPT_KEYS")?;
    if object["schema_version"].as_u64() != Some(1)
        || object["kind"].as_str() != Some("native_sol_payment_receipt")
    {
        return Err(Error("RECEIPT_KIND"));
    }
    let environment = if e.network == "mainnet" {
        "production"
    } else {
        "sandbox"
    };
    if object["quote_id"].as_str() != Some(e.quote.quote_id.as_str())
        || object["network"].as_str() != Some(e.network)
        || object["genesis_hash"].as_str() != Some(e.genesis_hash)
        || object["message_sha256"].as_str() != Some(hex(&e.message_sha256).as_str())
        || object["environment"].as_str() != Some(environment)
    {
        return Err(Error("RECEIPT_BINDING_MISMATCH"));
    }
    let signature = object["payment_signature"]
        .as_str()
        .ok_or(Error("RECEIPT_SIGNATURE_INVALID"))?;
    solana_signature(signature).map_err(|_| Error("RECEIPT_SIGNATURE_INVALID"))?;
    let paid = decimal(&object["lamports_paid"]).ok_or(Error("RECEIPT_AMOUNT_INVALID"))?;
    if paid < e.quote.lamports_due || object["receiver"].as_str() != Some(e.quote.receiver.as_str())
    {
        return Err(Error("RECEIPT_PAYMENT_MISMATCH"));
    }
    if object["settled_commitment"].as_str() != Some("finalized")
        || object["payment_instruction_index"].as_u64().is_none()
        || object["settled_slot"].as_u64().is_none()
        || object["issued_at"]
            .as_str()
            .and_then(parse_timestamp)
            .is_none()
    {
        return Err(Error("RECEIPT_SETTLEMENT_INVALID"));
    }
    let state = match object["analysis_state"].as_str() {
        Some("completed") => AnalysisState::Completed,
        Some("retryable") => AnalysisState::Retryable,
        Some("refund_required") => AnalysisState::RefundRequired,
        _ => return Err(Error("RECEIPT_STATE_INVALID")),
    };
    let bound = &object["cloud_assessment_sha256"];
    match (state, e.assessment_payload) {
        (AnalysisState::Completed, Some(payload))
            if bound.as_str() == Some(hex(&Sha256::digest(payload)).as_str()) => {}
        (AnalysisState::Completed, _) => return Err(Error("RECEIPT_NOT_BOUND_TO_ASSESSMENT")),
        (_, None) if bound.is_null() => {}
        _ => return Err(Error("RECEIPT_STATE_INVALID")),
    }
    Ok(ReceiptBindings {
        analysis_state: state,
        lamports_paid: paid,
        payment_signature: signature.to_owned(),
    })
}

// --------------------------------------------------------------- assessment

const ASSESSMENT_KEYS: [&str; 22] = [
    "schema_version",
    "kind",
    "network",
    "genesis_hash",
    "message_sha256",
    "intent_sha256",
    "requested_profile",
    "capabilities_performed",
    "capabilities_unavailable",
    "risk_snapshot_id",
    "ruleset_version",
    "evidence_digest",
    "sources",
    "findings",
    "coverage",
    "issued_at",
    "expires_at",
    "quote_id",
    "environment",
    "data_scope",
    "subjects_sha256",
    "transaction_sha256",
];

pub struct AssessmentExpectations<'a> {
    pub quote_id: &'a str,
    pub network: &'a str,
    pub genesis_hash: &'a str,
    pub message_sha256: [u8; 32],
    pub intent_sha256: Option<[u8; 32]>,
    pub transaction_sha256: Option<[u8; 32]>,
    pub subjects_sha256: [u8; 32],
    pub profile: &'a str,
    pub requested_capabilities: &'a [String],
    pub now_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvisoryFinding {
    pub code: String,
    pub severity: String,
    pub claimed_enforcement: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssessmentView {
    pub capabilities_performed: BTreeSet<String>,
    pub capabilities_unavailable: BTreeSet<String>,
    pub coverage_passed: BTreeSet<String>,
    pub coverage_unknown: BTreeSet<String>,
    /// Always false for a real server: the client holds no independent record of the server's observations.
    pub evidence_verified: bool,
    pub findings: Vec<AdvisoryFinding>,
}

pub fn verify_assessment_bindings(
    canonical_payload: &[u8],
    e: &AssessmentExpectations<'_>,
) -> Result<AssessmentView> {
    let value = jcs::parse_canonical(canonical_payload)?;
    let object = value.as_object().ok_or(Error("ASSESSMENT_KEYS"))?;
    exact_keys(object, &ASSESSMENT_KEYS, "ASSESSMENT_KEYS")?;
    if object["schema_version"].as_u64() != Some(1)
        || object["kind"].as_str() != Some("cloud_assessment")
    {
        return Err(Error("ASSESSMENT_KIND"));
    }
    let environment = if e.network == "mainnet" {
        "production"
    } else {
        "sandbox"
    };
    let bound = object["quote_id"].as_str() == Some(e.quote_id)
        && object["network"].as_str() == Some(e.network)
        && object["genesis_hash"].as_str() == Some(e.genesis_hash)
        && object["environment"].as_str() == Some(environment)
        && object["message_sha256"].as_str() == Some(hex(&e.message_sha256).as_str())
        && object["intent_sha256"] == optional_hex(e.intent_sha256)
        && object["transaction_sha256"] == optional_hex(e.transaction_sha256)
        && object["subjects_sha256"].as_str() == Some(hex(&e.subjects_sha256).as_str())
        && object["requested_profile"].as_str() == Some(e.profile)
        && object["data_scope"].as_str() == Some("metadata_only");
    if !bound {
        return Err(Error("ASSESSMENT_BINDING_MISMATCH"));
    }
    let issued = object["issued_at"]
        .as_str()
        .and_then(parse_timestamp)
        .ok_or(Error("ASSESSMENT_TIMESTAMP_INVALID"))?;
    let expires = object["expires_at"]
        .as_str()
        .and_then(parse_timestamp)
        .ok_or(Error("ASSESSMENT_TIMESTAMP_INVALID"))?;
    if !(issued <= e.now_unix && e.now_unix < expires) {
        return Err(Error("ASSESSMENT_EXPIRED_OR_NOT_YET_VALID"));
    }
    let requested: BTreeSet<String> = e.requested_capabilities.iter().cloned().collect();
    let performed = string_set(&object["capabilities_performed"])
        .ok_or(Error("ASSESSMENT_CAPABILITIES_INVALID"))?;
    let unavailable = string_set(&object["capabilities_unavailable"])
        .ok_or(Error("ASSESSMENT_CAPABILITIES_INVALID"))?;
    let coverage = object["coverage"]
        .as_object()
        .ok_or(Error("ASSESSMENT_COVERAGE_INVALID"))?;
    exact_keys(
        coverage,
        &["required", "passed", "unknown"],
        "ASSESSMENT_COVERAGE_INVALID",
    )?;
    let required = string_set(&coverage["required"]).ok_or(Error("ASSESSMENT_COVERAGE_INVALID"))?;
    let passed = string_set(&coverage["passed"]).ok_or(Error("ASSESSMENT_COVERAGE_INVALID"))?;
    let unknown = string_set(&coverage["unknown"]).ok_or(Error("ASSESSMENT_COVERAGE_INVALID"))?;
    // Nothing unrequested; performed and unavailable disjoint; a pass needs a performed capability and cannot also be
    // unknown; every requested capability is accounted for as passed or unknown.
    let consistent = performed.is_disjoint(&unavailable)
        && performed.union(&unavailable).all(|c| requested.contains(c))
        && required == requested
        && passed.is_subset(&performed)
        && passed.is_disjoint(&unknown)
        && passed.union(&unknown).cloned().collect::<BTreeSet<_>>() == required
        && unavailable.is_subset(&unknown);
    if !consistent {
        return Err(Error("ASSESSMENT_COVERAGE_INCONSISTENT"));
    }
    let findings = object["findings"]
        .as_array()
        .ok_or(Error("ASSESSMENT_FINDINGS_INVALID"))?
        .iter()
        .map(|f| {
            let item = f.as_object()?;
            Some(AdvisoryFinding {
                code: item.get("code")?.as_str()?.to_owned(),
                severity: item.get("severity")?.as_str()?.to_owned(),
                claimed_enforcement: item.get("enforcement")?.as_str()?.to_owned(),
                evidence_refs: item
                    .get("evidence_refs")?
                    .as_array()?
                    .iter()
                    .map(|r| r.as_str().map(str::to_owned))
                    .collect::<Option<_>>()?,
            })
        })
        .collect::<Option<Vec<_>>>()
        .ok_or(Error("ASSESSMENT_FINDINGS_INVALID"))?;
    Ok(AssessmentView {
        capabilities_performed: performed,
        capabilities_unavailable: unavailable,
        coverage_passed: passed,
        coverage_unknown: unknown,
        evidence_verified: false,
        findings,
    })
}

/// The decision the CLI acts on. A Cloud assessment is advisory and unverifiable by this client, so the local decision
/// is returned unchanged: never lowered, never raised, never turned into ALLOW by Cloud.
pub fn final_decision(local_decision: &str, _assessment: Option<&AssessmentView>) -> String {
    local_decision.to_owned()
}

// ------------------------------------------------------------ paid check

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedPaidCheck {
    pub receipt: ReceiptBindings,
    pub assessment: Option<AssessmentView>,
}

/// Verifies the receipt (and the assessment when the analysis completed): signatures with the pinned key first, then
/// bindings. Both signed documents must pass; a completed receipt must hash exactly the assessment that came with it.
/// Backwards-compatible verifier when an issuer intentionally uses one
/// independently pinned ML-DSA-87 key for both report domains. Prefer
/// verify_paid_check_with_keys for separately rotated assessment/receipt keys.
pub fn verify_paid_check(
    signed_receipt: &SignedPayload,
    signed_assessment: Option<&SignedPayload>,
    key: &PinnedKey,
    receipt_expectations: &ReceiptExpectations<'_>,
    assessment_expectations: &AssessmentExpectations<'_>,
) -> Result<VerifiedPaidCheck> {
    verify_paid_check_with_keys(
        signed_receipt,
        signed_assessment,
        key,
        key,
        receipt_expectations,
        assessment_expectations,
    )
}

/// Verifies each independently signed artifact against its OWN authenticated
/// ML-DSA-87 issuer key. This matches the server's separate signer roles and
/// supports secure per-domain key rotation without skipping any signature.
/// Both keys MUST be pinned through an authenticated out-of-band channel.
pub fn verify_paid_check_with_keys(
    signed_receipt: &SignedPayload,
    signed_assessment: Option<&SignedPayload>,
    receipt_key: &PinnedKey,
    assessment_key: &PinnedKey,
    receipt_expectations: &ReceiptExpectations<'_>,
    assessment_expectations: &AssessmentExpectations<'_>,
) -> Result<VerifiedPaidCheck> {
    if !receipt_key.verify(
        Domain::PaymentReceipt,
        &signed_receipt.canonical_payload,
        &signed_receipt.signature,
        &signed_receipt.key_id,
        &signed_receipt.signing_algorithm,
    ) {
        return Err(Error("RECEIPT_SIGNATURE_INVALID_SERVER"));
    }
    if let Some(assessment) = signed_assessment {
        if !assessment_key.verify(
            Domain::CloudAssessment,
            &assessment.canonical_payload,
            &assessment.signature,
            &assessment.key_id,
            &assessment.signing_algorithm,
        ) {
            return Err(Error("ASSESSMENT_SIGNATURE_INVALID"));
        }
    }
    let assessment_payload = signed_assessment.map(|s| s.canonical_payload.as_slice());
    let expectations = ReceiptExpectations {
        quote: receipt_expectations.quote,
        network: receipt_expectations.network,
        genesis_hash: receipt_expectations.genesis_hash,
        message_sha256: receipt_expectations.message_sha256,
        assessment_payload,
    };
    let receipt = verify_receipt_bindings(&signed_receipt.canonical_payload, &expectations)?;
    let assessment = match assessment_payload {
        Some(payload) => Some(verify_assessment_bindings(
            payload,
            assessment_expectations,
        )?),
        None => None,
    };
    Ok(VerifiedPaidCheck {
        receipt,
        assessment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{b58_test_signature, jcs::canonicalize_signed_payload};
    use serde_json::json;

    const GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
    const RECEIVER: &str = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
    const NOW: i64 = 1_760_000_100;

    fn quote() -> QuoteBindings {
        QuoteBindings {
            quote_id: "a".repeat(32),
            receiver: RECEIVER.into(),
            memo_reference: format!("HGUET:{}", "a".repeat(32)),
            lamports_due: 4000,
            issued_at_unix: 1_760_000_000,
            expires_at_unix: 1_760_000_900,
        }
    }

    fn assessment_json() -> Value {
        json!({
            "schema_version": 1, "kind": "cloud_assessment", "network": "devnet", "genesis_hash": GENESIS,
            "message_sha256": hex(&[1; 32]), "intent_sha256": null, "requested_profile": "strict",
            "capabilities_performed": ["network_health"], "capabilities_unavailable": [],
            "risk_snapshot_id": "snap", "ruleset_version": "v1", "evidence_digest": hex(&[7; 32]),
            "sources": [], "findings": [], "coverage": {"required": ["network_health"], "passed": ["network_health"], "unknown": []},
            "issued_at": "2025-10-09T08:53:20Z", "expires_at": "2025-10-09T09:08:20Z", "quote_id": "a".repeat(32),
            "environment": "sandbox", "data_scope": "metadata_only", "subjects_sha256": hex(&[3; 32]),
            "transaction_sha256": null
        })
    }

    fn assessment_expectations(capabilities: &[String]) -> AssessmentExpectations<'_> {
        AssessmentExpectations {
            quote_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            network: "devnet",
            genesis_hash: GENESIS,
            message_sha256: [1; 32],
            intent_sha256: None,
            transaction_sha256: None,
            subjects_sha256: [3; 32],
            profile: "strict",
            requested_capabilities: capabilities,
            now_unix: NOW,
        }
    }

    fn receipt_json(assessment: &[u8]) -> Value {
        json!({
            "schema_version": 1, "kind": "native_sol_payment_receipt", "quote_id": "a".repeat(32),
            "environment": "sandbox", "network": "devnet", "genesis_hash": GENESIS, "message_sha256": hex(&[1; 32]),
            "payment_signature": b58_test_signature(5), "payment_instruction_index": 0, "lamports_paid": "4000",
            "receiver": RECEIVER, "settled_slot": 123, "settled_commitment": "finalized", "analysis_state": "completed",
            "cloud_assessment_sha256": hex(&Sha256::digest(assessment)), "issued_at": "2025-10-09T08:54:00Z"
        })
    }

    fn bytes(value: &Value) -> Vec<u8> {
        canonicalize_signed_payload(value).unwrap()
    }

    fn receipt_code(value: &Value, assessment: Option<&[u8]>) -> &'static str {
        let q = quote();
        let e = ReceiptExpectations {
            quote: &q,
            network: "devnet",
            genesis_hash: GENESIS,
            message_sha256: [1; 32],
            assessment_payload: assessment,
        };
        verify_receipt_bindings(&bytes(value), &e)
            .unwrap_err()
            .code()
    }

    #[test]
    fn an_honest_receipt_and_assessment_pass() {
        let capabilities = vec!["network_health".to_owned()];
        let assessment = bytes(&assessment_json());
        let q = quote();
        let e = ReceiptExpectations {
            quote: &q,
            network: "devnet",
            genesis_hash: GENESIS,
            message_sha256: [1; 32],
            assessment_payload: Some(&assessment),
        };
        let receipt = verify_receipt_bindings(&bytes(&receipt_json(&assessment)), &e).unwrap();
        assert_eq!(receipt.analysis_state, AnalysisState::Completed);
        let view = verify_assessment_bindings(&assessment, &assessment_expectations(&capabilities))
            .unwrap();
        assert!(!view.evidence_verified);
        assert!(view.coverage_passed.contains("network_health"));
    }

    #[test]
    fn receipts_must_repeat_the_quote_and_hash_the_exact_assessment() {
        let assessment = bytes(&assessment_json());
        let a = Some(assessment.as_slice());
        for (key, value, code) in [
            (
                "quote_id",
                json!("b".repeat(32)),
                "RECEIPT_BINDING_MISMATCH",
            ),
            ("network", json!("mainnet"), "RECEIPT_BINDING_MISMATCH"),
            (
                "message_sha256",
                json!(hex(&[9; 32])),
                "RECEIPT_BINDING_MISMATCH",
            ),
            (
                "environment",
                json!("production"),
                "RECEIPT_BINDING_MISMATCH",
            ),
            ("lamports_paid", json!("3999"), "RECEIPT_PAYMENT_MISMATCH"),
            (
                "receiver",
                json!("11111111111111111111111111111111"),
                "RECEIPT_PAYMENT_MISMATCH",
            ),
            ("lamports_paid", json!("0"), "RECEIPT_AMOUNT_INVALID"),
            (
                "payment_signature",
                json!("SYNTHETIC-DEVNET-PAYMENT-1"),
                "RECEIPT_SIGNATURE_INVALID",
            ),
            (
                "settled_commitment",
                json!("confirmed"),
                "RECEIPT_SETTLEMENT_INVALID",
            ),
            ("analysis_state", json!("done"), "RECEIPT_STATE_INVALID"),
            (
                "cloud_assessment_sha256",
                json!(hex(&[0; 32])),
                "RECEIPT_NOT_BOUND_TO_ASSESSMENT",
            ),
        ] {
            let mut r = receipt_json(&assessment);
            r[key] = value;
            assert_eq!(receipt_code(&r, a), code, "{key}");
        }
        assert_eq!(
            receipt_code(&receipt_json(&assessment), None),
            "RECEIPT_NOT_BOUND_TO_ASSESSMENT"
        );
        // Overpaying is fine; a non-completed state carries no assessment.
        let mut over = receipt_json(&assessment);
        over["lamports_paid"] = json!("9000");
        let q = quote();
        let e = ReceiptExpectations {
            quote: &q,
            network: "devnet",
            genesis_hash: GENESIS,
            message_sha256: [1; 32],
            assessment_payload: a,
        };
        assert_eq!(
            verify_receipt_bindings(&bytes(&over), &e)
                .unwrap()
                .lamports_paid,
            9000
        );
        let mut refund = receipt_json(&assessment);
        refund["analysis_state"] = json!("refund_required");
        refund["cloud_assessment_sha256"] = Value::Null;
        let none = ReceiptExpectations {
            quote: &q,
            network: "devnet",
            genesis_hash: GENESIS,
            message_sha256: [1; 32],
            assessment_payload: None,
        };
        assert_eq!(
            verify_receipt_bindings(&bytes(&refund), &none)
                .unwrap()
                .analysis_state,
            AnalysisState::RefundRequired
        );
    }

    #[test]
    fn assessments_must_be_bound_fresh_and_consistent() {
        let capabilities = vec!["network_health".to_owned()];
        let e = assessment_expectations(&capabilities);
        let code = |v: &Value, e: &AssessmentExpectations<'_>| {
            verify_assessment_bindings(&bytes(v), e).unwrap_err().code()
        };
        for (key, value) in [
            ("quote_id", json!("b".repeat(32))),
            ("network", json!("mainnet")),
            ("genesis_hash", json!("other")),
            ("message_sha256", json!(hex(&[9; 32]))),
            ("subjects_sha256", json!(hex(&[9; 32]))),
            ("requested_profile", json!("review")),
            ("data_scope", json!("raw_transaction")),
            ("environment", json!("production")),
            ("intent_sha256", json!(hex(&[9; 32]))),
        ] {
            let mut a = assessment_json();
            a[key] = value;
            assert_eq!(code(&a, &e), "ASSESSMENT_BINDING_MISMATCH", "{key}");
        }
        let mut late = assessment_expectations(&capabilities);
        late.now_unix = 1_760_001_000;
        assert_eq!(
            code(&assessment_json(), &late),
            "ASSESSMENT_EXPIRED_OR_NOT_YET_VALID"
        );
        // Coverage inconsistencies a lying server could use to claim more than it did.
        let mut claims_unrequested = assessment_json();
        claims_unrequested["capabilities_performed"] = json!(["network_health", "program_risk"]);
        assert_eq!(
            code(&claims_unrequested, &e),
            "ASSESSMENT_COVERAGE_INCONSISTENT"
        );
        let mut passed_without_performing = assessment_json();
        passed_without_performing["capabilities_performed"] = json!([]);
        assert_eq!(
            code(&passed_without_performing, &e),
            "ASSESSMENT_COVERAGE_INCONSISTENT"
        );
        let mut passed_and_unknown = assessment_json();
        passed_and_unknown["coverage"]["unknown"] = json!(["network_health"]);
        assert_eq!(
            code(&passed_and_unknown, &e),
            "ASSESSMENT_COVERAGE_INCONSISTENT"
        );
        let mut missing = assessment_json();
        missing["coverage"] = json!({"required": ["network_health"], "passed": [], "unknown": []});
        assert_eq!(code(&missing, &e), "ASSESSMENT_COVERAGE_INCONSISTENT");
        let mut bonus = assessment_json();
        bonus["extra"] = json!(1);
        assert_eq!(code(&bonus, &e), "ASSESSMENT_KEYS");
    }

    #[test]
    fn separately_pinned_report_keys_verify_their_own_domains() {
        use std::fs::{self, OpenOptions};
        use std::io::Write;
        use std::process::Command;
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        struct EphemeralKey {
            private: std::path::PathBuf,
            public: Vec<u8>,
        }
        impl Drop for EphemeralKey {
            fn drop(&mut self) {
                let _ = fs::remove_file(&self.private);
            }
        }
        fn key() -> Option<EphemeralKey> {
            let generated = Command::new("openssl")
                .args(["genpkey", "-algorithm", "ML-DSA-87"])
                .output()
                .ok()?;
            if !generated.status.success() {
                if std::env::var_os("HGUET_REQUIRE_PQ_SIGNING").is_some() {
                    panic!("ML-DSA-87 separate issuer-key test cannot skip");
                }
                return None;
            }
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("hguet-report-keys-{}-{id}.pem", std::process::id()));
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut output = options.open(&path).unwrap();
            output.write_all(&generated.stdout).unwrap();
            let derived = Command::new("openssl")
                .args(["pkey", "-in"])
                .arg(&path)
                .arg("-pubout")
                .output()
                .unwrap();
            assert!(derived.status.success());
            Some(EphemeralKey {
                private: path,
                public: derived.stdout,
            })
        }
        fn sign(key: &EphemeralKey, domain: Domain, payload: &[u8]) -> Vec<u8> {
            struct SignedInput(std::path::PathBuf);
            impl Drop for SignedInput {
                fn drop(&mut self) {
                    let _ = fs::remove_file(&self.0);
                }
            }
            let id = COUNTER.fetch_add(1, Ordering::Relaxed);
            let file = SignedInput(std::env::temp_dir().join(format!(
                "hguet-report-message-{}-{id}.bin",
                std::process::id()
            )));
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut output = options.open(&file.0).unwrap();
            output
                .write_all(&[domain.bytes(), payload].concat())
                .unwrap();
            output.sync_all().unwrap();
            drop(output);
            let result = Command::new("openssl")
                .args(["pkeyutl", "-sign", "-rawin", "-inkey"])
                .arg(&key.private)
                .arg("-in")
                .arg(&file.0)
                .output()
                .unwrap();
            assert!(result.status.success());
            result.stdout
        }
        let (Some(receipt_key), Some(assessment_key)) = (key(), key()) else {
            return;
        };
        let receipt_pin = PinnedKey::from_public_pem(&receipt_key.public, "openssl").unwrap();
        let assessment_pin = PinnedKey::from_public_pem(&assessment_key.public, "openssl").unwrap();
        assert_ne!(receipt_pin.key_id(), assessment_pin.key_id());

        let assessment_payload = bytes(&assessment_json());
        let receipt_payload = bytes(&receipt_json(&assessment_payload));
        let signed_assessment = SignedPayload {
            signature: sign(
                &assessment_key,
                Domain::CloudAssessment,
                &assessment_payload,
            ),
            canonical_payload: assessment_payload.clone(),
            key_id: assessment_pin.key_id().into(),
            signing_algorithm: "ML-DSA-87".into(),
        };
        let signed_receipt = SignedPayload {
            signature: sign(&receipt_key, Domain::PaymentReceipt, &receipt_payload),
            canonical_payload: receipt_payload,
            key_id: receipt_pin.key_id().into(),
            signing_algorithm: "ML-DSA-87".into(),
        };
        let quote = quote();
        let receipt_expectations = ReceiptExpectations {
            quote: &quote,
            network: "devnet",
            genesis_hash: GENESIS,
            message_sha256: [1; 32],
            assessment_payload: Some(&assessment_payload),
        };
        let caps = vec!["network_health".to_owned()];
        let assessment_expectations = assessment_expectations(&caps);
        assert!(
            verify_paid_check_with_keys(
                &signed_receipt,
                Some(&signed_assessment),
                &receipt_pin,
                &assessment_pin,
                &receipt_expectations,
                &assessment_expectations
            )
            .is_ok(),
            "domain-specific pinned keys must independently verify"
        );
        assert!(
            verify_paid_check_with_keys(
                &signed_receipt,
                Some(&signed_assessment),
                &assessment_pin,
                &receipt_pin,
                &receipt_expectations,
                &assessment_expectations
            )
            .is_err(),
            "swapped issuer keys must never verify"
        );
        assert!(
            verify_paid_check(
                &signed_receipt,
                Some(&signed_assessment),
                &receipt_pin,
                &receipt_expectations,
                &assessment_expectations
            )
            .is_err(),
            "legacy single-key helper cannot silently accept different keys"
        );
    }

    #[test]
    fn cloud_findings_never_change_the_local_decision() {
        let capabilities = vec!["network_health".to_owned()];
        let mut a = assessment_json();
        a["findings"] = json!([{"code": "ANYTHING", "severity": "critical", "enforcement": "hard_deny", "evidence_refs": ["x"], "summary": "s"}]);
        a["capabilities_performed"] = json!(["network_health"]);
        let view = verify_assessment_bindings(&bytes(&a), &assessment_expectations(&capabilities))
            .unwrap();
        assert_eq!(view.findings[0].claimed_enforcement, "hard_deny");
        assert!(!view.evidence_verified);
        for local in ["ALLOW", "UNKNOWN", "WARN", "DENY"] {
            assert_eq!(final_decision(local, Some(&view)), local);
            assert_eq!(final_decision(local, None), local);
        }
    }
}
