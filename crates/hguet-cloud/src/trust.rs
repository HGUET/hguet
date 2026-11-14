//! ML-DSA-87 verification of server-signed payloads against an explicitly PINNED public key, then the binding checks.
//!
//! Verification is delegated to the OpenSSL command line (>= 3.5, native ML-DSA-87): the CLI never hand-rolls
//! cryptography and holds no private key here. The pinned key must come from an authenticated channel (configuration the
//! operator trusts), never from the server's own reply. There is no classical fallback and no TOFU.

use crate::quote::{verify_quote_bindings, QuoteBindings, QuoteExpectations};
use crate::wire::v1::SignedPayload;
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const SIGNING_ALGORITHM: &str = "ML-DSA-87";
pub const SIGNATURE_BYTES: usize = 4627;
const MAX_PAYLOAD_BYTES: usize = 262_144;

/// The signing context of a report; the domain bytes are prepended to the canonical payload before signing, so a
/// signature made for one document type can never be replayed as another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Domain {
    PriceQuote,
    CloudAssessment,
    PaymentReceipt,
}

impl Domain {
    pub const fn bytes(self) -> &'static [u8] {
        match self {
            Self::PriceQuote => b"HGUET-SOL-QUOTE/v1\0",
            Self::CloudAssessment => b"HGUET-CLOUD-ASSESSMENT/v1\0",
            Self::PaymentReceipt => b"HGUET-SOL-PAYMENT-RECEIPT/v1\0",
        }
    }
}

/// A temporary file that is removed on drop (created exclusively; never reused).
struct TempFile(PathBuf);

impl TempFile {
    fn new(label: &str, data: &[u8]) -> Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = std::env::temp_dir().join(format!(
            "hguet-{}-{nanos}-{unique}.{label}",
            std::process::id()
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&path)
            .map_err(|_| Error("VERIFIER_TEMP_FILE"))?;
        file.write_all(data)
            .map_err(|_| Error("VERIFIER_TEMP_FILE"))?;
        Ok(Self(path))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// A pinned ML-DSA-87 public key.
pub struct PinnedKey {
    public_pem: Vec<u8>,
    key_id: String,
    openssl: String,
}

impl PinnedKey {
    /// Accepts only an ML-DSA-87 public key (anything else - classical, other PQ sets, private keys - is refused).
    pub fn from_public_pem(public_pem: &[u8], openssl: &str) -> Result<Self> {
        let der = run_openssl(
            openssl,
            &["pkey", "-pubin", "-inform", "PEM", "-outform", "DER"],
            public_pem,
        )
        .map_err(|_| Error("PINNED_KEY_INVALID"))?;
        let text = run_openssl(
            openssl,
            &["pkey", "-pubin", "-inform", "DER", "-text", "-noout"],
            &der,
        )
        .map_err(|_| Error("PINNED_KEY_INVALID"))?;
        if !String::from_utf8_lossy(&text).starts_with("ML-DSA-87 Public-Key:") {
            return Err(Error("PINNED_KEY_NOT_MLDSA87"));
        }
        let digest = Sha256::digest(&der);
        Ok(Self {
            public_pem: public_pem.to_vec(),
            key_id: digest[..16].iter().map(|b| format!("{b:02x}")).collect(),
            openssl: openssl.to_owned(),
        })
    }

    /// `hex(SHA-256(SubjectPublicKeyInfo DER)[..16])`, the identifier servers put in `SignedPayload.key_id`.
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// True only if `signature` is a valid ML-DSA-87 signature by this key over `domain || canonical_payload`.
    pub fn verify(
        &self,
        domain: Domain,
        canonical_payload: &[u8],
        signature: &[u8],
        key_id: &str,
        algorithm: &str,
    ) -> bool {
        if algorithm != SIGNING_ALGORITHM
            || key_id != self.key_id
            || signature.len() != SIGNATURE_BYTES
            || canonical_payload.len() > MAX_PAYLOAD_BYTES
        {
            return false;
        }
        let message = [domain.bytes(), canonical_payload].concat();
        let (Ok(key), Ok(input), Ok(sig)) = (
            TempFile::new("pub", &self.public_pem),
            TempFile::new("msg", &message),
            TempFile::new("sig", signature),
        ) else {
            return false;
        };
        Command::new(&self.openssl)
            .args(["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey"])
            .arg(key.path())
            .arg("-in")
            .arg(input.path())
            .arg("-sigfile")
            .arg(sig.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}

fn run_openssl(openssl: &str, args: &[&str], stdin: &[u8]) -> Result<Vec<u8>> {
    let mut child = Command::new(openssl)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error("OPENSSL_UNAVAILABLE"))?;
    child
        .stdin
        .take()
        .ok_or(Error("OPENSSL_UNAVAILABLE"))?
        .write_all(stdin)
        .map_err(|_| Error("OPENSSL_UNAVAILABLE"))?;
    let output = child
        .wait_with_output()
        .map_err(|_| Error("OPENSSL_UNAVAILABLE"))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(Error("OPENSSL_REJECTED"))
    }
}

/// Signature first, bindings second. A quote is returned only if BOTH hold; the order matters because bindings on an
/// unauthenticated payload prove nothing.
pub fn verify_signed_quote(
    signed: &SignedPayload,
    key: &PinnedKey,
    expected: &QuoteExpectations<'_>,
) -> Result<QuoteBindings> {
    if !key.verify(
        Domain::PriceQuote,
        &signed.canonical_payload,
        &signed.signature,
        &signed.key_id,
        &signed.signing_algorithm,
    ) {
        return Err(Error("QUOTE_SIGNATURE_INVALID"));
    }
    verify_quote_bindings(&signed.canonical_payload, expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jcs::canonicalize_signed_payload;
    use serde_json::json;

    struct Keys {
        private: TempFile,
        public_pem: Vec<u8>,
    }

    /// None when OpenSSL cannot generate ML-DSA-87 here (skipped unless HGUET_REQUIRE_PQ_SIGNING is set).
    fn keys() -> Option<Keys> {
        let generated = Command::new("openssl")
            .args(["genpkey", "-algorithm", "ML-DSA-87"])
            .output();
        let generated = match generated {
            Ok(output) if output.status.success() => output,
            _ if std::env::var_os("HGUET_REQUIRE_PQ_SIGNING").is_none() => {
                eprintln!("ML-DSA-87 unavailable; trust tests skipped");
                return None;
            }
            _ => panic!("ML-DSA-87 is required but unavailable"),
        };
        let private = TempFile::new("key", &generated.stdout).unwrap();
        let public = Command::new("openssl")
            .args(["pkey", "-pubout", "-in"])
            .arg(private.path())
            .output()
            .unwrap();
        assert!(public.status.success());
        Some(Keys {
            private,
            public_pem: public.stdout,
        })
    }

    fn sign(keys: &Keys, domain: Domain, payload: &[u8]) -> Vec<u8> {
        let message = TempFile::new("msg", &[domain.bytes(), payload].concat()).unwrap();
        let output = Command::new("openssl")
            .args(["pkeyutl", "-sign", "-rawin", "-inkey"])
            .arg(keys.private.path())
            .arg("-in")
            .arg(message.path())
            .output()
            .unwrap();
        assert!(output.status.success());
        output.stdout
    }

    #[test]
    fn a_valid_signature_verifies_and_every_tampering_is_refused() {
        let Some(keys) = keys() else { return };
        let pinned = PinnedKey::from_public_pem(&keys.public_pem, "openssl").unwrap();
        assert_eq!(pinned.key_id().len(), 32);
        let payload = br#"{"schema_version":1}"#;
        let sig = sign(&keys, Domain::PriceQuote, payload);
        assert_eq!(sig.len(), SIGNATURE_BYTES);
        let id = pinned.key_id().to_owned();
        assert!(pinned.verify(Domain::PriceQuote, payload, &sig, &id, SIGNING_ALGORITHM));
        // Wrong domain, altered payload, altered signature, wrong key id, wrong algorithm, truncated signature.
        assert!(!pinned.verify(
            Domain::PaymentReceipt,
            payload,
            &sig,
            &id,
            SIGNING_ALGORITHM
        ));
        assert!(!pinned.verify(
            Domain::CloudAssessment,
            payload,
            &sig,
            &id,
            SIGNING_ALGORITHM
        ));
        assert!(!pinned.verify(
            Domain::PriceQuote,
            br#"{"schema_version":2}"#,
            &sig,
            &id,
            SIGNING_ALGORITHM
        ));
        let mut flipped = sig.clone();
        flipped[10] ^= 1;
        assert!(!pinned.verify(
            Domain::PriceQuote,
            payload,
            &flipped,
            &id,
            SIGNING_ALGORITHM
        ));
        assert!(!pinned.verify(
            Domain::PriceQuote,
            payload,
            &sig,
            &"0".repeat(32),
            SIGNING_ALGORITHM
        ));
        assert!(!pinned.verify(Domain::PriceQuote, payload, &sig, &id, "Ed25519"));
        assert!(!pinned.verify(
            Domain::PriceQuote,
            payload,
            &sig[..SIGNATURE_BYTES - 1],
            &id,
            SIGNING_ALGORITHM
        ));
        // A different key cannot verify it even when the attacker copies the key id.
        let other = keys_pair();
        let other_pinned = PinnedKey::from_public_pem(&other, "openssl").unwrap();
        assert!(!other_pinned.verify(
            Domain::PriceQuote,
            payload,
            &sig,
            other_pinned.key_id(),
            SIGNING_ALGORITHM
        ));
        assert!(!other_pinned.verify(Domain::PriceQuote, payload, &sig, &id, SIGNING_ALGORITHM));
    }

    fn keys_pair() -> Vec<u8> {
        keys().expect("ML-DSA-87 available").public_pem
    }

    #[test]
    fn only_ml_dsa_87_public_keys_can_be_pinned() {
        let Some(keys) = keys() else { return };
        // A private key, an Ed25519 public key and garbage are all refused.
        let private_pem = std::fs::read(keys.private.path()).unwrap();
        assert!(PinnedKey::from_public_pem(&private_pem, "openssl").is_err());
        assert!(PinnedKey::from_public_pem(b"not a key", "openssl").is_err());
        let ed = Command::new("openssl")
            .args(["genpkey", "-algorithm", "ED25519"])
            .output()
            .unwrap();
        let ed_private = TempFile::new("ed", &ed.stdout).unwrap();
        let ed_public = Command::new("openssl")
            .args(["pkey", "-pubout", "-in"])
            .arg(ed_private.path())
            .output()
            .unwrap();
        assert_eq!(
            PinnedKey::from_public_pem(&ed_public.stdout, "openssl")
                .err()
                .map(|e| e.code()),
            Some("PINNED_KEY_NOT_MLDSA87")
        );
        assert_eq!(
            PinnedKey::from_public_pem(&keys.public_pem, "/definitely/not/openssl")
                .err()
                .map(|e| e.code()),
            Some("PINNED_KEY_INVALID")
        );
    }

    #[test]
    fn a_signed_quote_needs_both_a_valid_signature_and_matching_bindings() {
        let Some(keys) = keys() else { return };
        let pinned = PinnedKey::from_public_pem(&keys.public_pem, "openssl").unwrap();
        let receiver = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
        let genesis = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
        let id = "a".repeat(32);
        let hex = |b: u8| format!("{b:02x}").repeat(32);
        let quote = json!({
            "schema_version": 1, "kind": "native_sol_price_quote", "quote_id": id, "environment": "sandbox",
            "network": "devnet", "genesis_hash": genesis, "asset": "SOL", "receiver": receiver,
            "memo_reference": format!("HGUET:{id}"), "message_sha256": hex(1), "transaction_sha256": null,
            "intent_sha256": null, "requested_profile": "strict", "requested_capabilities": ["network_health"],
            "data_scope": "metadata_only", "subjects_sha256": hex(3), "claim_secret_sha256": hex(2),
            "usd_price_micros": "1000", "sol_usd_price_micros": "100000000", "oracle_source_id": "SYNTHETIC",
            "oracle_published_at": "2025-10-09T08:53:00Z", "oracle_confidence_bps": 20, "lamports_due": "4000",
            "issued_at": "2025-10-09T08:53:20Z", "expires_at": "2025-10-09T09:08:20Z",
            "pricing_policy_version": "draft", "pricing_tier": "basic",
            "complexity": {"transaction_bytes": 0, "top_level_instructions": 0, "resolved_accounts": 0,
                           "lookup_tables": 0, "distinct_programs": 0, "risk_subjects": 1,
                           "verified_from_raw_transaction": false},
            "max_lamports_requested": "5000"
        });
        let payload = canonicalize_signed_payload(&quote).unwrap();
        let signed = SignedPayload {
            signature: sign(&keys, Domain::PriceQuote, &payload),
            canonical_payload: payload,
            key_id: pinned.key_id().to_owned(),
            signing_algorithm: SIGNING_ALGORITHM.to_owned(),
        };
        let capabilities = vec!["network_health".to_owned()];
        let expected = QuoteExpectations {
            network: "devnet",
            genesis_hash: genesis,
            message_sha256: [1; 32],
            intent_sha256: None,
            transaction_sha256: None,
            claim_secret_sha256: [2; 32],
            subjects_sha256: [3; 32],
            profile: "strict",
            requested_capabilities: &capabilities,
            maximum_lamports: 5000,
            now_unix: 1_760_000_000,
        };
        assert_eq!(
            verify_signed_quote(&signed, &pinned, &expected)
                .unwrap()
                .lamports_due,
            4000
        );
        // Right signature, wrong expectations: refused by the bindings.
        let mut cheaper_cap = expected.clone();
        cheaper_cap.maximum_lamports = 3000;
        assert_eq!(
            verify_signed_quote(&signed, &pinned, &cheaper_cap)
                .unwrap_err()
                .code(),
            "QUOTE_PRICE_EXCEEDS_CAP"
        );
        // Perfect bindings, forged signature: refused before the bindings are even considered.
        let mut forged = signed.clone();
        forged.signature[0] ^= 1;
        assert_eq!(
            verify_signed_quote(&forged, &pinned, &expected)
                .unwrap_err()
                .code(),
            "QUOTE_SIGNATURE_INVALID"
        );
        let mut other_domain = signed.clone();
        other_domain.signature = sign(&keys, Domain::PaymentReceipt, &signed.canonical_payload);
        assert_eq!(
            verify_signed_quote(&other_domain, &pinned, &expected)
                .unwrap_err()
                .code(),
            "QUOTE_SIGNATURE_INVALID"
        );
    }
}
