use hguet_cloud::{
    quote::QuoteExpectations,
    transport::exchange,
    trust::{verify_signed_quote, PinnedKey},
    wire::{
        build_price_quote_request, envelope_with,
        v1::{envelope::Payload, ErrorCode, ResultCode},
        QuoteParams,
    },
    Subject,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;

fn digest(value: &str) -> Result<[u8; 32], &'static str> {
    if value.len() != 64 || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("EXPECTED_SHA256_HEX");
    }
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "EXPECTED_SHA256_HEX")?;
    }
    Ok(bytes)
}

pub fn run(mut args: impl Iterator<Item = String>) -> Result<Value, &'static str> {
    let program = args.next().ok_or("PROGRAM_REQUIRED")?;
    let mut flags = BTreeMap::new();
    while let Some(flag) = args.next() {
        if flag == "--json" {
            continue;
        }
        if !matches!(
            flag.as_str(),
            "--message-sha256" | "--claim-sha256" | "--max-lamports" | "--ca-file" | "--quote-key"
        ) {
            return Err("UNKNOWN_QUOTE_OPTION");
        }
        let value = args
            .next()
            .filter(|v| !v.is_empty() && !v.starts_with("--"))
            .ok_or("MISSING_OPTION_VALUE")?;
        if flags.insert(flag, value).is_some() {
            return Err("DUPLICATE_OPTION");
        }
    }
    let option = |flag: &str| {
        flags
            .get(flag)
            .map(String::as_str)
            .ok_or("MISSING_QUOTE_OPTION")
    };
    let params = QuoteParams {
        network: "devnet".into(),
        genesis_hash: "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG".into(),
        message_sha256: digest(option("--message-sha256")?)?,
        claim_secret_sha256: digest(option("--claim-sha256")?)?,
        maximum_lamports: option("--max-lamports")?
            .parse()
            .map_err(|_| "QUOTE_MAXIMUM_INVALID")?,
        intent_sha256: None,
        transaction_sha256: None,
        profile: "strict".into(),
        requested_capabilities: vec!["program_upgrade_history".into()],
        subjects: vec![Subject {
            category: "program".into(),
            network: "devnet".into(),
            subject_id: program.clone(),
        }],
    };
    let request = build_price_quote_request(&params).map_err(|e| e.code())?;
    let subjects_sha256 = request
        .subjects_sha256
        .as_slice()
        .try_into()
        .map_err(|_| "INVALID_SUBJECT_DIGEST")?;
    let key_bytes =
        super::limited_file(option("--quote-key")?, 32768).map_err(|_| "QUOTE_KEY_UNREADABLE")?;
    let key = PinnedKey::from_public_pem(&key_bytes, "openssl").map_err(|e| e.code())?;
    let profile = super::cloud_config::loopback_profile(option("--ca-file")?.into());
    let envelope = envelope_with(
        params.claim_secret_sha256[..16].try_into().unwrap(),
        Payload::PriceQuoteRequest(request),
    );
    let reply = exchange(&profile, &envelope).map_err(|e| e.code())?;
    if reply.request_id != envelope.request_id
        || (reply.protocol_major, reply.protocol_minor) != (1, 0)
    {
        return Err("QUOTE_RESPONSE_MISMATCH");
    }
    let signed = match reply.payload {
        Some(Payload::PriceQuoteResult(result))
            if result.result == ResultCode::ResultAccepted as i32 =>
        {
            result.signed_quote.ok_or("SIGNED_QUOTE_MISSING")?
        }
        Some(Payload::Error(error)) if error.code == ErrorCode::ErrorUnavailable as i32 => {
            return Err("QUOTE_UNAVAILABLE")
        }
        _ => return Err("QUOTE_REQUEST_REJECTED"),
    };
    let expected = QuoteExpectations {
        network: &params.network,
        genesis_hash: &params.genesis_hash,
        message_sha256: params.message_sha256,
        intent_sha256: None,
        transaction_sha256: None,
        claim_secret_sha256: params.claim_secret_sha256,
        subjects_sha256,
        profile: &params.profile,
        requested_capabilities: &params.requested_capabilities,
        maximum_lamports: params.maximum_lamports,
        now_unix: hguet_core::unix_now().map_err(|_| "CLOCK_UNAVAILABLE")? as i64,
    };
    let verified = verify_signed_quote(&signed, &key, &expected).map_err(|e| e.code())?;
    Ok(
        json!({"network":"devnet","program":program,"quote_id":verified.quote_id,
        "lamports_due":verified.lamports_due.to_string(),"expires_at_unix":verified.expires_at_unix}),
    )
}
