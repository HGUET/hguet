//! Pure, network-free building blocks of the HGUET Cloud protocol for the client (S7.1 PROPOSAL, see
//! HGUET/server docs/architecture/canonical-contract-s7.md). No I/O, no keys, no transport: the Cloud transport
//! is NOT implemented in the CLI yet and nothing here sends anything.
//!
//! Every function returns a stable error code that matches the server's golden vectors
//! (`tests/vectors.rs` reproduces them from `testing/cloud-value/protocol/s7-client-vectors.json`).

pub mod proto_policy;
#[rustfmt::skip] // generated file: kept byte-identical to gen_proto_table.py output
mod proto_table;

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub &'static str);

impl Error {
    pub const fn code(&self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Error {}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Canonical Base58 of exactly 32 bytes (re-encodes to the same text).
fn canonical_b58_32(text: &str) -> bool {
    bs58::decode(text)
        .into_vec()
        .is_ok_and(|raw| raw.len() == 32 && bs58::encode(&raw).into_string() == text)
}

// ---------------------------------------------------------------- subjects

pub const SUBJECT_CATEGORIES: [&str; 4] = ["program", "mint", "destination", "merchant"];
pub const NETWORKS: [&str; 3] = ["mainnet", "devnet", "testnet"];
pub const MAX_SUBJECTS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub category: String,
    pub network: String,
    pub subject_id: String,
}

fn merchant_ok(id: &str) -> bool {
    (1..=96).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// Validates against the request network and returns the subjects in canonical (byte-wise) order.
/// Duplicates are rejected: the digest binds exactly the set the client sends.
pub fn canonical_subjects(network: &str, subjects: &[Subject]) -> Result<Vec<Subject>> {
    if !NETWORKS.contains(&network) {
        return Err(Error("NETWORK_UNKNOWN"));
    }
    if subjects.len() > MAX_SUBJECTS {
        return Err(Error("SUBJECT_SET_TOO_LARGE"));
    }
    let mut seen = BTreeSet::new();
    for s in subjects {
        if !SUBJECT_CATEGORIES.contains(&s.category.as_str()) {
            return Err(Error("SUBJECT_UNKNOWN_CATEGORY"));
        }
        if !NETWORKS.contains(&s.network.as_str()) {
            return Err(Error("NETWORK_UNKNOWN"));
        }
        if s.network != network {
            return Err(Error("SUBJECT_NETWORK_MISMATCH"));
        }
        let valid = if s.category == "merchant" {
            merchant_ok(&s.subject_id)
        } else {
            canonical_b58_32(&s.subject_id)
        };
        if !valid {
            return Err(Error("SUBJECT_ID_INVALID"));
        }
        if !seen.insert((s.category.clone(), s.network.clone(), s.subject_id.clone())) {
            return Err(Error("SUBJECT_DUPLICATE"));
        }
    }
    let mut sorted = subjects.to_vec();
    sorted.sort_by(|a, b| {
        (
            a.category.as_bytes(),
            a.network.as_bytes(),
            a.subject_id.as_bytes(),
        )
            .cmp(&(
                b.category.as_bytes(),
                b.network.as_bytes(),
                b.subject_id.as_bytes(),
            ))
    });
    Ok(sorted)
}

/// JCS string for an already-validated ASCII value.
fn jcs_string(value: &str, out: &mut String) {
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `JCS([{"category":..,"network":..,"subject_id":..}, ..])` of the canonical subject set.
pub fn canonical_subjects_json(network: &str, subjects: &[Subject]) -> Result<String> {
    let mut out = String::from("[");
    for (i, s) in canonical_subjects(network, subjects)?.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"category\":");
        jcs_string(&s.category, &mut out);
        out.push_str(",\"network\":");
        jcs_string(&s.network, &mut out);
        out.push_str(",\"subject_id\":");
        jcs_string(&s.subject_id, &mut out);
        out.push('}');
    }
    out.push(']');
    Ok(out)
}

/// The 32 bytes the client puts in `PriceQuoteRequest.subjects_sha256`.
pub fn subjects_sha256(network: &str, subjects: &[Subject]) -> Result<[u8; 32]> {
    Ok(Sha256::digest(canonical_subjects_json(network, subjects)?.as_bytes()).into())
}

pub fn subjects_sha256_hex(network: &str, subjects: &[Subject]) -> Result<String> {
    Ok(hex(&subjects_sha256(network, subjects)?))
}

// -------------------------------------------------------------------- memo

/// The exact memo the payment must carry: `HGUET:<quote_id>` (32 lowercase hex), nothing else.
pub fn memo_reference(quote_id: &str) -> Result<String> {
    if quote_id.len() == 32
        && quote_id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(format!("HGUET:{quote_id}"))
    } else {
        Err(Error("QUOTE_ID_INVALID"))
    }
}

/// True only if the quote's `memo_reference` is exactly the canonical memo of its `quote_id`.
pub fn quote_memo_is_canonical(quote_id: &str, memo_reference_field: &str) -> bool {
    memo_reference(quote_id).is_ok_and(|expected| expected == memo_reference_field)
}

// --------------------------------------------------------------- signature

/// Canonical Solana signature: Base58 of exactly 64 bytes, re-encoding to the same text, not all zero.
pub fn solana_signature(text: &str) -> Result<[u8; 64]> {
    if text.is_empty() || !text.is_ascii() {
        return Err(Error("SIGNATURE_MALFORMED"));
    }
    let raw = bs58::decode(text)
        .into_vec()
        .map_err(|_| Error("SIGNATURE_BASE58_INVALID"))?;
    let bytes: [u8; 64] = raw
        .try_into()
        .map_err(|_| Error("SIGNATURE_LENGTH_INVALID"))?;
    if bs58::encode(bytes).into_string() != text {
        return Err(Error("SIGNATURE_NOT_CANONICAL"));
    }
    if bytes.iter().all(|b| *b == 0) {
        return Err(Error("SIGNATURE_ALL_ZERO"));
    }
    Ok(bytes)
}

// ----------------------------------------------------------- client evidence

pub const CLIENT_EVIDENCE_DECISIONS: [&str; 4] = ["ALLOW", "WARN", "DENY", "UNKNOWN"];

fn code_ok(text: &str) -> bool {
    let b = text.as_bytes();
    (1..=128).contains(&b.len())
        && b[0].is_ascii_uppercase()
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

fn coverage_ok(text: &str) -> bool {
    let b = text.as_bytes();
    (1..=96).contains(&b.len())
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

fn name_array(
    items: &[String],
    limit: usize,
    ok: fn(&str) -> bool,
    error: &'static str,
) -> Result<String> {
    if items.len() > limit || items.iter().any(|s| !ok(s)) {
        return Err(Error(error));
    }
    let mut sorted: Vec<&String> = items.iter().collect();
    sorted.sort();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return Err(Error("CLIENT_EVIDENCE_NOT_SORTED_UNIQUE"));
    }
    let mut out = String::from("[");
    for (i, item) in sorted.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(item); // validated: [A-Za-z0-9_] only, nothing to escape
        out.push('"');
    }
    out.push(']');
    Ok(out)
}

/// Canonical redacted local evidence: ONLY the decision, finding codes and coverage names - never accounts,
/// programs, amounts, instruction data, RPC URLs, paths, intents or signatures. Inputs are sorted for the caller;
/// duplicates and out-of-profile names are errors. An empty `canonical_local_evidence_json` (absent) is also valid
/// on the wire; this function always produces the explicit form.
pub fn build_client_evidence(
    local_decision: &str,
    finding_codes: &[String],
    coverage: &[String],
) -> Result<Vec<u8>> {
    if !CLIENT_EVIDENCE_DECISIONS.contains(&local_decision) {
        return Err(Error("CLIENT_EVIDENCE_DECISION"));
    }
    let codes = name_array(finding_codes, 64, code_ok, "CLIENT_EVIDENCE_CODES")?;
    let cover = name_array(coverage, 32, coverage_ok, "CLIENT_EVIDENCE_COVERAGE")?;
    let body = format!(
        "{{\"coverage\":{cover},\"finding_codes\":{codes},\"kind\":\"hguet_client_evidence\",\"local_decision\":\"{local_decision}\",\"schema_version\":1}}"
    );
    if body.len() > 4096 {
        return Err(Error("CLIENT_EVIDENCE_TOO_LARGE"));
    }
    Ok(body.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_subject_set_digest_is_sha256_of_an_empty_json_array() {
        assert_eq!(
            subjects_sha256_hex("devnet", &[]).unwrap(),
            "4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945"
        );
    }

    #[test]
    fn memo_must_be_exact() {
        let id = "a".repeat(32);
        assert_eq!(memo_reference(&id).unwrap(), format!("HGUET:{id}"));
        assert!(quote_memo_is_canonical(&id, &format!("HGUET:{id}")));
        for bad in [
            id.as_str(),
            &format!("HGUET:{id} "),
            &format!("hguet:{id}"),
            &format!("HGUET:{}", id.to_uppercase()),
        ] {
            assert!(!quote_memo_is_canonical(&id, bad), "{bad}");
        }
        assert!(memo_reference("quote-123").is_err());
    }

    #[test]
    fn evidence_builder_is_canonical_and_rejects_leaks() {
        let bytes = build_client_evidence(
            "WARN",
            &["Z_CODE".into(), "A_CODE".into()],
            &["rpc_agreement".into(), "alt".into()],
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(bytes).unwrap(),
            r#"{"coverage":["alt","rpc_agreement"],"finding_codes":["A_CODE","Z_CODE"],"kind":"hguet_client_evidence","local_decision":"WARN","schema_version":1}"#
        );
        // Anything that could carry an account, URL, path or amount is outside the profile.
        for leak in [
            "https://rpc.example",
            "C:\\Users\\me",
            "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi",
            "lamports=5",
        ] {
            assert!(
                build_client_evidence("UNKNOWN", &[leak.into()], &[]).is_err(),
                "{leak}"
            );
            assert!(
                build_client_evidence("UNKNOWN", &[], &[leak.into()]).is_err(),
                "{leak}"
            );
        }
        assert!(build_client_evidence("MAYBE", &[], &[]).is_err());
        assert!(build_client_evidence("ALLOW", &["A".into(), "A".into()], &[]).is_err());
    }
}
