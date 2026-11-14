//! Client-side binding checks for a signed price quote (S7.1 PROPOSAL rules).
//!
//! IMPORTANT: this verifies what a quote SAYS against what the client ASKED FOR. It does NOT verify the ML-DSA-87
//! signature - a quote must be treated as untrusted until a signature check over exactly these canonical bytes (with the
//! `HGUET-SOL-QUOTE/v1` domain, against a pinned key) has also succeeded. Nothing may be paid on bindings alone.

use crate::{canonical_b58_32, jcs, memo_reference, Error, Result};
use serde_json::Value;
use std::collections::BTreeSet;

const REQUIRED_KEYS: [&str; 29] = [
    "schema_version",
    "kind",
    "quote_id",
    "environment",
    "network",
    "genesis_hash",
    "asset",
    "receiver",
    "memo_reference",
    "message_sha256",
    "transaction_sha256",
    "intent_sha256",
    "requested_profile",
    "requested_capabilities",
    "data_scope",
    "subjects_sha256",
    "claim_secret_sha256",
    "usd_price_micros",
    "sol_usd_price_micros",
    "oracle_source_id",
    "oracle_published_at",
    "oracle_confidence_bps",
    "lamports_due",
    "issued_at",
    "expires_at",
    "pricing_policy_version",
    "pricing_tier",
    "complexity",
    "max_lamports_requested",
];

/// What the client asked for; every one of these must come back unchanged.
#[derive(Debug, Clone)]
pub struct QuoteExpectations<'a> {
    pub network: &'a str,
    pub genesis_hash: &'a str,
    pub message_sha256: [u8; 32],
    pub intent_sha256: Option<[u8; 32]>,
    pub transaction_sha256: Option<[u8; 32]>,
    pub claim_secret_sha256: [u8; 32],
    pub subjects_sha256: [u8; 32],
    pub profile: &'a str,
    pub requested_capabilities: &'a [String],
    pub maximum_lamports: u64,
    pub now_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteBindings {
    pub quote_id: String,
    pub receiver: String,
    pub memo_reference: String,
    pub lamports_due: u64,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
}

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
        && (text == "0" || !text.starts_with('0')))
    .then(|| text.parse().ok())
    .flatten()
}

/// `YYYY-MM-DDTHH:MM:SSZ` (a real calendar instant, UTC, whole seconds) to Unix seconds.
pub fn parse_timestamp(text: &str) -> Option<i64> {
    let b = text.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
    {
        return None;
    }
    let num = |range: std::ops::Range<usize>| -> Option<i64> {
        let slice = text.get(range)?;
        slice
            .bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| slice.parse().ok())
            .flatten()
    };
    let (y, mo, d, h, mi, s) = (
        num(0..4)?,
        num(5..7)?,
        num(8..10)?,
        num(11..13)?,
        num(14..16)?,
        num(17..19)?,
    );
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let days_in_month = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if y < 1 || !(1..=days_in_month).contains(&d) || h > 23 || mi > 59 || s > 59 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + mi * 60 + s)
}

/// Checks the canonical payload of a quote against the client's expectations. See the module warning: no signature check.
pub fn verify_quote_bindings(
    canonical_payload: &[u8],
    expected: &QuoteExpectations<'_>,
) -> Result<QuoteBindings> {
    let value = jcs::parse_canonical(canonical_payload)?;
    let object = value.as_object().ok_or(Error("QUOTE_KEYS"))?;
    let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    if keys != REQUIRED_KEYS.iter().copied().collect::<BTreeSet<_>>() {
        return Err(Error("QUOTE_KEYS"));
    }
    if object["schema_version"].as_u64() != Some(1)
        || object["kind"].as_str() != Some("native_sol_price_quote")
        || object["asset"].as_str() != Some("SOL")
    {
        return Err(Error("QUOTE_KIND"));
    }
    let quote_id = object["quote_id"]
        .as_str()
        .ok_or(Error("QUOTE_ID_INVALID"))?;
    let canonical_memo = memo_reference(quote_id).map_err(|_| Error("QUOTE_ID_INVALID"))?;
    if object["memo_reference"].as_str() != Some(canonical_memo.as_str()) {
        return Err(Error("QUOTE_MEMO_NOT_CANONICAL"));
    }
    let environment = if expected.network == "mainnet" {
        "production"
    } else {
        "sandbox"
    };
    let mut capabilities: Vec<&str> = expected
        .requested_capabilities
        .iter()
        .map(String::as_str)
        .collect();
    capabilities.sort_unstable();
    let quoted_capabilities: Option<Vec<&str>> = object["requested_capabilities"]
        .as_array()
        .and_then(|items| items.iter().map(Value::as_str).collect());
    let mut quoted_capabilities = quoted_capabilities.ok_or(Error("QUOTE_BINDING_MISMATCH"))?;
    quoted_capabilities.sort_unstable();
    let bound = object["environment"].as_str() == Some(environment)
        && object["network"].as_str() == Some(expected.network)
        && object["genesis_hash"].as_str() == Some(expected.genesis_hash)
        && object["message_sha256"].as_str() == Some(hex(&expected.message_sha256).as_str())
        && object["intent_sha256"] == optional_hex(expected.intent_sha256)
        && object["transaction_sha256"] == optional_hex(expected.transaction_sha256)
        && object["claim_secret_sha256"].as_str()
            == Some(hex(&expected.claim_secret_sha256).as_str())
        && object["subjects_sha256"].as_str() == Some(hex(&expected.subjects_sha256).as_str())
        && object["requested_profile"].as_str() == Some(expected.profile)
        && object["data_scope"].as_str() == Some("metadata_only")
        && quoted_capabilities == capabilities;
    if !bound {
        return Err(Error("QUOTE_BINDING_MISMATCH"));
    }
    if object["complexity"]["verified_from_raw_transaction"].as_bool() != Some(false) {
        return Err(Error("QUOTE_BINDING_MISMATCH"));
    }
    let receiver = object["receiver"]
        .as_str()
        .filter(|r| canonical_b58_32(r))
        .ok_or(Error("QUOTE_RECEIVER_INVALID"))?;
    let lamports_due = decimal(&object["lamports_due"])
        .filter(|n| *n > 0)
        .ok_or(Error("QUOTE_AMOUNT_INVALID"))?;
    if lamports_due > expected.maximum_lamports {
        return Err(Error("QUOTE_PRICE_EXCEEDS_CAP"));
    }
    if decimal(&object["max_lamports_requested"]) != Some(expected.maximum_lamports) {
        return Err(Error("QUOTE_BINDING_MISMATCH"));
    }
    let issued = object["issued_at"]
        .as_str()
        .and_then(parse_timestamp)
        .ok_or(Error("QUOTE_TIMESTAMP_INVALID"))?;
    let expires = object["expires_at"]
        .as_str()
        .and_then(parse_timestamp)
        .ok_or(Error("QUOTE_TIMESTAMP_INVALID"))?;
    if !(issued <= expected.now_unix && expected.now_unix < expires && issued < expires) {
        return Err(Error("QUOTE_EXPIRED_OR_NOT_YET_VALID"));
    }
    Ok(QuoteBindings {
        quote_id: quote_id.to_owned(),
        receiver: receiver.to_owned(),
        memo_reference: canonical_memo,
        lamports_due,
        issued_at_unix: issued,
        expires_at_unix: expires,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
    const RECEIVER: &str = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";
    const NOW: i64 = 1_760_000_000;

    fn caps() -> Vec<String> {
        vec!["network_health".into()]
    }

    fn expected(capabilities: &[String]) -> QuoteExpectations<'_> {
        QuoteExpectations {
            network: "devnet",
            genesis_hash: GENESIS,
            message_sha256: [1; 32],
            intent_sha256: None,
            transaction_sha256: None,
            claim_secret_sha256: [2; 32],
            subjects_sha256: [3; 32],
            profile: "strict",
            requested_capabilities: capabilities,
            maximum_lamports: 5000,
            now_unix: NOW,
        }
    }

    fn quote() -> Value {
        let id = "a".repeat(32);
        json!({
            "schema_version": 1, "kind": "native_sol_price_quote", "quote_id": id,
            "environment": "sandbox", "network": "devnet", "genesis_hash": GENESIS, "asset": "SOL",
            "receiver": RECEIVER, "memo_reference": format!("HGUET:{id}"),
            "message_sha256": hex(&[1; 32]), "transaction_sha256": null, "intent_sha256": null,
            "requested_profile": "strict", "requested_capabilities": ["network_health"],
            "data_scope": "metadata_only", "subjects_sha256": hex(&[3; 32]),
            "claim_secret_sha256": hex(&[2; 32]), "usd_price_micros": "1000", "sol_usd_price_micros": "100000000",
            "oracle_source_id": "SYNTHETIC", "oracle_published_at": "2025-10-09T08:53:00Z", "oracle_confidence_bps": 20,
            "lamports_due": "4000", "issued_at": "2025-10-09T08:53:20Z", "expires_at": "2025-10-09T09:08:20Z",
            "pricing_policy_version": "draft", "pricing_tier": "basic",
            "complexity": {"transaction_bytes": 0, "top_level_instructions": 0, "resolved_accounts": 0,
                           "lookup_tables": 0, "distinct_programs": 0, "risk_subjects": 1,
                           "verified_from_raw_transaction": false},
            "max_lamports_requested": "5000"
        })
    }

    fn bytes(value: &Value) -> Vec<u8> {
        jcs::canonicalize_signed_payload(value).unwrap()
    }

    fn code(value: &Value, e: &QuoteExpectations<'_>) -> &'static str {
        verify_quote_bindings(&bytes(value), e).unwrap_err().code()
    }

    #[test]
    fn timestamps_convert_to_unix_seconds() {
        assert_eq!(parse_timestamp("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_timestamp("2025-10-09T08:53:20Z"), Some(1_760_000_000));
        assert_eq!(parse_timestamp("2024-02-29T00:00:00Z"), Some(1_709_164_800));
        for bad in [
            "2025-02-29T00:00:00Z",
            "2025-10-09T08:53:60Z",
            "2025-10-09 08:53:20Z",
            "2025-10-09T08:53:20+00:00",
            "0000-01-01T00:00:00Z",
            "2025-13-01T00:00:00Z",
        ] {
            assert_eq!(parse_timestamp(bad), None, "{bad}");
        }
    }

    #[test]
    fn an_honest_quote_passes_every_binding() {
        let c = caps();
        let bound = verify_quote_bindings(&bytes(&quote()), &expected(&c)).unwrap();
        assert_eq!(bound.lamports_due, 4000);
        assert_eq!(bound.memo_reference, format!("HGUET:{}", "a".repeat(32)));
        assert_eq!(bound.expires_at_unix - bound.issued_at_unix, 900);
    }

    #[test]
    fn any_altered_binding_is_refused() {
        let c = caps();
        let e = expected(&c);
        let other = hex(&[9; 32]);
        for (key, value) in [
            ("network", json!("mainnet")),
            (
                "genesis_hash",
                json!("5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"),
            ),
            ("message_sha256", json!(other)),
            ("intent_sha256", json!(other)),
            ("transaction_sha256", json!(other)),
            ("claim_secret_sha256", json!(other)),
            ("subjects_sha256", json!(other)),
            ("requested_profile", json!("review")),
            ("data_scope", json!("raw_transaction")),
            ("environment", json!("production")),
            ("requested_capabilities", json!(["program_risk"])),
            ("max_lamports_requested", json!("6000")),
        ] {
            let mut q = quote();
            q[key] = value;
            assert_eq!(code(&q, &e), "QUOTE_BINDING_MISMATCH", "{key}");
        }
        let mut claimed = quote();
        claimed["complexity"]["verified_from_raw_transaction"] = json!(true);
        assert_eq!(code(&claimed, &e), "QUOTE_BINDING_MISMATCH");
    }

    #[test]
    fn memo_amount_receiver_and_time_rules() {
        let c = caps();
        let e = expected(&c);
        let mut q = quote();
        q["memo_reference"] = json!("a".repeat(32)); // the bare id is not the memo
        assert_eq!(code(&q, &e), "QUOTE_MEMO_NOT_CANONICAL");
        let mut q = quote();
        q["lamports_due"] = json!("5001");
        assert_eq!(code(&q, &e), "QUOTE_PRICE_EXCEEDS_CAP");
        for bad in ["0", "05", "-1", "1.5", ""] {
            let mut q = quote();
            q["lamports_due"] = json!(bad);
            assert_eq!(code(&q, &e), "QUOTE_AMOUNT_INVALID", "{bad}");
        }
        let mut q = quote();
        q["receiver"] = json!("not-a-pubkey");
        assert_eq!(code(&q, &e), "QUOTE_RECEIVER_INVALID");
        let mut late = expected(&c);
        late.now_unix = NOW + 900; // exactly at expiry
        assert_eq!(code(&quote(), &late), "QUOTE_EXPIRED_OR_NOT_YET_VALID");
        let mut early = expected(&c);
        early.now_unix = NOW - 21;
        assert_eq!(code(&quote(), &early), "QUOTE_EXPIRED_OR_NOT_YET_VALID");
    }

    #[test]
    fn structure_and_canonical_form_are_enforced() {
        let c = caps();
        let e = expected(&c);
        let mut missing = quote();
        missing
            .as_object_mut()
            .unwrap()
            .remove("claim_secret_sha256");
        assert_eq!(code(&missing, &e), "QUOTE_KEYS");
        let mut extra = quote();
        extra["bonus"] = json!(1);
        assert_eq!(code(&extra, &e), "QUOTE_KEYS");
        let mut kind = quote();
        kind["asset"] = json!("USDC");
        assert_eq!(code(&kind, &e), "QUOTE_KIND");
        let pretty = serde_json::to_vec_pretty(&quote()).unwrap();
        assert_eq!(
            verify_quote_bindings(&pretty, &e).unwrap_err().code(),
            "JSON_NOT_CANONICAL"
        );
        let mut duplicate = bytes(&quote());
        duplicate.splice(1..1, br#""kind":"x","#.iter().copied());
        assert_eq!(
            verify_quote_bindings(&duplicate, &e).unwrap_err().code(),
            "JSON_DUPLICATE_KEY"
        );
        assert_eq!(
            verify_quote_bindings(b"[]", &e).unwrap_err().code(),
            "QUOTE_KEYS"
        );
        assert!(verify_quote_bindings(b"\xef\xbb\xbf{}", &e).is_err());
    }
}
