//! Deterministic offline Solana wire inspection and independently signed intent verification.
//! This crate checks supported original-wire formats and transaction Ed25519
//! signatures, but DOES NOT simulate execution, resolve ALTs, authenticate
//! token-account ownership or authorize spending. Never turn a parsed transaction into ALLOW.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_INTENT: usize = 16_384;
const INTENT_DOMAIN: &[u8] = b"HGUET-PAYMENT-INTENT\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision {
    Allow,
    Warn,
    Deny,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub code: String,
    pub severity: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityVerdict {
    pub schema_version: u32,
    pub kind: String,
    pub decision: Decision,
    pub network: String,
    pub message_sha256: Option<String>,
    pub transaction_sha256: Option<String>,
    pub intent_status: String,
    pub simulation_status: String,
    pub coverage: Vec<String>,
    pub findings: Vec<Finding>,
    pub limitations: Vec<String>,
}

impl SecurityVerdict {
    pub fn unknown(network: &str) -> Self {
        Self {
            schema_version: 1, kind: "security_verdict".into(),
            decision: Decision::Unknown, network: network.into(),
            message_sha256: None, transaction_sha256: None,
            intent_status: "not_checked".into(), simulation_status: "not_performed".into(),
            coverage: vec![], findings: vec![],
            limitations: vec!["No onchain execution simulation or customer-controlled signer enforcement has been performed".into()],
        }
    }
    pub fn finding(&mut self, code: &str, severity: &str, summary: impl Into<String>) {
        self.findings.push(Finding {
            code: code.into(),
            severity: severity.into(),
            summary: summary.into(),
        });
    }
}

pub mod intent_scope;
pub mod solana_engine;
mod source_limits;
#[cfg(test)]
mod token_intent_tests;
mod token_limits;
pub use intent_scope::{review_account_control, ReviewFailure, ScopeFinding};
pub use solana_engine::{
    parse_transaction, ParsedTransaction, SystemTransfer, TransactionSignatureStatus, V1Resources,
};
pub use source_limits::{
    review_declared_source_limits, review_declared_source_limits_detailed, DeclaredSourceDebit,
    TokenSourceLimitReview,
};
pub use token_limits::{
    review_declared_token_limits, review_declared_token_limits_detailed, DeclaredMintDebit,
    TokenSpendLimitReview,
};

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPaymentIntent {
    pub payload_b64: String,
    pub signer_pubkey_b58: String,
    pub signature_b58: String,
}
/// Raw base-unit upper bound on directly declared checked Token Program
/// debits for one mint. This is NOT a transaction-wide/onchain spend limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenSpendLimit {
    pub mint: String,
    pub max_debit_raw: String,
}
/// Optional signed account-scoped direct token-debit limit. The authority
/// is a required signer in the transaction header, NOT a verified token
/// account owner. Multi-signature token authorities remain unsupported.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenSourceLimit {
    pub mint: String,
    pub source_token_account: String,
    pub authority: String,
    pub max_debit_raw: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentIntentPayload {
    pub schema_version: u32,
    pub kind: String,
    pub intent_id: String,
    pub network: String,
    pub message_sha256: String,
    pub not_before_unix: u64,
    pub expires_at_unix: u64,
    pub allowed_program_ids: Vec<String>,
    pub max_spend_lamports: String,
    /// Optional extension of the existing signed v1 payload. Absence keeps
    /// legacy SOL-only intent semantics and exact-byte signature compatibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_spend_limits: Option<Vec<TokenSpendLimit>>,
    /// Optional independent source/required-signer scopes. If supplied,
    /// every direct token debit must satisfy the named source scope,
    /// independently of any mint-wide limits also supplied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_source_limits: Option<Vec<TokenSourceLimit>>,
}

fn decode_fixed_b58<const N: usize>(s: &str, what: &str) -> Result<[u8; N], String> {
    let b = bs58::decode(s)
        .into_vec()
        .map_err(|_| format!("{what} is not Base58"))?;
    b.try_into()
        .map_err(|_| format!("{what} must decode to {N} bytes"))
}

/// Why an intent could not be accepted. The two variants must never be merged:
/// a [`IntentFailure::Violation`] is a PROVEN breach (DENY); a
/// [`IntentFailure::Coverage`] means the facts could not be established (UNKNOWN).
#[derive(Debug, Clone)]
pub enum IntentFailure {
    Violation {
        message: String,
        /// Structured scope findings with evidence references, when available.
        findings: Vec<ScopeFinding>,
    },
    Coverage {
        reason: &'static str,
        message: String,
    },
}

impl IntentFailure {
    fn violation(message: impl Into<String>) -> Self {
        Self::Violation {
            message: message.into(),
            findings: vec![],
        }
    }
    pub fn message(&self) -> &str {
        match self {
            Self::Violation { message, .. } | Self::Coverage { message, .. } => message,
        }
    }
}

impl From<ReviewFailure> for IntentFailure {
    fn from(value: ReviewFailure) -> Self {
        match value.coverage_reason {
            Some(reason) => Self::Coverage {
                reason,
                message: value.message,
            },
            None => Self::violation(value.message),
        }
    }
}

/// A fully verified intent plus coverage gaps that are NOT violations.
#[derive(Debug, Clone)]
pub struct VerifiedIntent {
    pub intent: PaymentIntentPayload,
    pub scope_gaps: Vec<ScopeFinding>,
}

/// Legacy entry point kept for callers that only need pass/fail. Any coverage
/// gap on an intent that carries token limits is still a failure here (fail
/// closed); callers that must distinguish DENY from UNKNOWN use
/// [`verify_intent_detailed`].
pub fn verify_intent(
    envelope: &SignedPaymentIntent,
    independently_pinned_key: &str,
    actual_network: &str,
    parsed: &ParsedTransaction,
    now: u64,
) -> Result<PaymentIntentPayload, String> {
    let verified = verify_intent_detailed(
        envelope,
        independently_pinned_key,
        actual_network,
        parsed,
        now,
    )
    .map_err(|failure| failure.message().to_string())?;
    let limited = verified.intent.token_spend_limits.is_some()
        || verified.intent.token_source_limits.is_some();
    if limited && !verified.scope_gaps.is_empty() {
        return Err(verified.scope_gaps[0].summary.clone());
    }
    Ok(verified.intent)
}

pub fn verify_intent_detailed(
    envelope: &SignedPaymentIntent,
    independently_pinned_key: &str,
    actual_network: &str,
    parsed: &ParsedTransaction,
    now: u64,
) -> Result<VerifiedIntent, IntentFailure> {
    let v = |m: &str| IntentFailure::violation(m);
    // The key MUST be configured independently, not sourced from the untrusted JSON.
    let pin = decode_fixed_b58::<32>(independently_pinned_key, "trusted signer key")
        .map_err(|e| v(&e))?;
    let presented = decode_fixed_b58::<32>(&envelope.signer_pubkey_b58, "presented signer")
        .map_err(|e| v(&e))?;
    if pin != presented {
        return Err(v("intent signing key is not independently trusted"));
    }
    let payload = STANDARD
        .decode(envelope.payload_b64.trim())
        .map_err(|_| v("invalid intent Base64"))?;
    if payload.is_empty() || payload.len() > MAX_INTENT {
        return Err(v("intent payload size out of range"));
    }
    let sig =
        decode_fixed_b58::<64>(&envelope.signature_b58, "intent signature").map_err(|e| v(&e))?;
    let verifying = VerifyingKey::from_bytes(&pin).map_err(|_| v("invalid trusted public key"))?;
    if verifying.is_weak() {
        return Err(v("weak trusted public key"));
    }
    let mut signed = Vec::with_capacity(INTENT_DOMAIN.len() + payload.len());
    signed.extend_from_slice(INTENT_DOMAIN);
    signed.extend_from_slice(&payload);
    verifying
        .verify_strict(&signed, &Signature::from_bytes(&sig))
        .map_err(|_| v("intent cryptographic signature invalid"))?;
    let intent: PaymentIntentPayload =
        serde_json::from_slice(&payload).map_err(|_| v("intent JSON payload invalid"))?;
    if intent.schema_version != 1 || intent.kind != "hguet_payment_intent" {
        return Err(v("intent schema/kind unsupported"));
    }
    if intent.intent_id.is_empty() || intent.intent_id.len() > 128 {
        return Err(v("intent_id length invalid"));
    }
    if intent.network != actual_network {
        return Err(v("intent network mismatch"));
    }
    if intent.message_sha256 != parsed.message_sha256 {
        return Err(v("intent message SHA256 mismatch"));
    }
    if intent.expires_at_unix <= intent.not_before_unix
        || now < intent.not_before_unix
        || now >= intent.expires_at_unix
    {
        return Err(v("intent not currently authorized"));
    }
    if intent.allowed_program_ids.len() > 64 {
        return Err(v("program allowlist too large"));
    }
    let spending_limit: u64 = intent
        .max_spend_lamports
        .parse()
        .map_err(|_| v("intent spend cap invalid"))?;
    if spending_limit == 0 || intent.max_spend_lamports.starts_with('0') {
        return Err(v(
            "intent spending limit must be positive canonical integer",
        ));
    }
    // Violations PROVEN from statically resolved data win over a coverage gap: an
    // unresolved lookup table cannot hide a program or a spend that is already
    // visible and out of scope.
    for program in &parsed.program_ids {
        if intent_scope::is_unresolved_program(program) {
            continue;
        }
        if !intent.allowed_program_ids.contains(program) {
            return Err(v("transaction program not on trusted intent allowlist"));
        }
    }
    // A strictly decoded top-level System Transfer is a known lower bound on
    // declared native SOL movement. Reject an intent when even this lower
    // bound exceeds its signed maximum. All CPI/other program effects remain
    // UNKNOWN, even if this test passes.
    let declared: u128 = parsed
        .declared_system_transfer_lamports
        .parse()
        .map_err(|_| v("decoded native transfer total invalid"))?;
    if declared > u128::from(spending_limit) {
        return Err(v(
            "declared System transfers exceed signed intent max_spend_lamports",
        ));
    }
    if parsed.unresolved_lookup_addresses > 0 {
        return Err(IntentFailure::Coverage {
            reason: "ALT_UNRESOLVED",
            message: "unresolved ALT addresses: program identities and accounts behind the lookup table cannot be checked against the intent allowlist; no violation is proven".into(),
        });
    }
    // Account-control operations (SetAuthority / CloseAccount) judged in context.
    let scope = review_account_control(parsed, &intent.intent_id);
    if let Some(first) = scope.iter().find(|f| f.violation) {
        return Err(IntentFailure::Violation {
            message: first.summary.clone(),
            findings: scope,
        });
    }
    // Signed mint caps are one-sided direct-wire lower-bound checks only:
    // unknown direct token instructions must NOT be marked cap-covered.
    if let Some(ref limits) = intent.token_spend_limits {
        token_limits::review_declared_token_limits_detailed(parsed, limits)?;
    }
    if let Some(ref sources) = intent.token_source_limits {
        source_limits::review_declared_source_limits_detailed(parsed, sources)?;
    }
    // Verified intent is NOT proof of total spending, fees or execution success.
    Ok(VerifiedIntent {
        intent,
        scope_gaps: scope,
    })
}

pub fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "system clock before Unix epoch".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn example_legacy() -> Vec<u8> {
        let mut v = vec![1u8];
        v.extend([0u8; 64]);
        v.extend([1, 0, 0, 1]);
        v.extend([7u8; 32]);
        v.extend([8u8; 32]);
        v.push(0);
        v
    }
    #[test]
    fn legacy_parse_and_hash() {
        let v = example_legacy();
        let p = parse_transaction(&v).unwrap();
        assert_eq!(p.wire_format, "legacy");
        assert_eq!(p.static_account_count, 1);
        assert_eq!(p.signature_count, 1);
        assert_eq!(p.instruction_count, 0);
        assert_eq!(p.message_sha256, sha256_hex(&v[65..]));
    }
    #[test]
    fn bad_and_unknown_are_not_silently_accepted() {
        assert!(parse_transaction(&[]).is_err());
        let mut extra = example_legacy();
        extra.push(0);
        assert!(parse_transaction(&extra).is_err());
        assert!(parse_transaction(&[0x81, 0, 0]).is_err()); // malformed v1 is rejected
        let mut v = example_legacy();
        v[0] = 0x80;
        v.insert(1, 0);
        assert!(parse_transaction(&v).is_err());
    }
    #[test]
    fn v0_with_lookup_requires_resolution() {
        let mut v = example_legacy();
        v.insert(65, 0x80);
        v.push(1);
        v.extend([1u8; 32]);
        v.push(1);
        v.push(7);
        v.push(0);
        let p = parse_transaction(&v).unwrap();
        assert_eq!(p.wire_format, "v0");
        assert_eq!(p.unresolved_lookup_addresses, 1);
        assert_eq!(p.lookup_table_count, 1);
    }
    #[test]
    fn strictly_verify_intent_against_pinned_key() {
        let p = parse_transaction(&example_legacy()).unwrap();
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let key = bs58::encode(signing.verifying_key().to_bytes()).into_string();
        let payload = PaymentIntentPayload {
            schema_version: 1,
            kind: "hguet_payment_intent".into(),
            intent_id: "test-intent".into(),
            network: "devnet".into(),
            message_sha256: p.message_sha256.clone(),
            not_before_unix: 1,
            expires_at_unix: 4102444800,
            allowed_program_ids: vec![],
            max_spend_lamports: "1000".into(),
            token_spend_limits: None,
            token_source_limits: None,
        };
        let b = serde_json::to_vec(&payload).unwrap();
        let mut msg = INTENT_DOMAIN.to_vec();
        msg.extend(&b);
        let sig = signing.sign(&msg);
        let signed = SignedPaymentIntent {
            payload_b64: STANDARD.encode(b),
            signer_pubkey_b58: key.clone(),
            signature_b58: bs58::encode(sig.to_bytes()).into_string(),
        };
        assert!(verify_intent(&signed, &key, "devnet", &p, 100).is_ok());
        assert!(verify_intent(&signed, &key, "mainnet", &p, 100).is_err());
        assert!(verify_intent(&signed, &key, "devnet", &p, 4102444800).is_err());
        let mut tampered = signed.clone();
        tampered.signature_b58 = "bad".into();
        assert!(verify_intent(&tampered, &key, "devnet", &p, 100).is_err());
    }
}
