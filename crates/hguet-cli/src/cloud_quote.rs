use base64::{engine::general_purpose::STANDARD, Engine};
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
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedOrder {
    version: u8,
    program: String,
    message_sha256: [u8; 32],
    claim_sha256: [u8; 32],
    maximum_lamports: u64,
    verified_at: i64,
    quote_frame_base64: String,
}

fn save_order(path: &Path, order: &SavedOrder) -> Result<(), &'static str> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|_| "ORDER_CREATE_FAILED")?;
    serde_json::to_writer(tmp.as_file_mut(), order).map_err(|_| "ORDER_WRITE_FAILED")?;
    tmp.as_file().sync_all().map_err(|_| "ORDER_WRITE_FAILED")?;
    tmp.persist_noclobber(path)
        .map_err(|_| "ORDER_PERSIST_FAILED")?;
    Ok(())
}

fn pinned(path: &str) -> Result<PinnedKey, &'static str> {
    let bytes = super::limited_file(path, 32768).map_err(|_| "KEY_UNREADABLE")?;
    PinnedKey::from_public_pem(&bytes, "openssl").map_err(|e| e.code())
}

fn options(
    args: impl Iterator<Item = String>,
    allowed: &[&str],
) -> Result<BTreeMap<String, String>, &'static str> {
    let mut args = args;
    let mut flags = BTreeMap::new();
    while let Some(flag) = args.next() {
        if flag == "--json" {
            continue;
        }
        if !allowed.contains(&flag.as_str()) {
            return Err("UNKNOWN_OPTION");
        }
        let value = args
            .next()
            .filter(|v| !v.is_empty() && !v.starts_with("--"))
            .ok_or("MISSING_OPTION_VALUE")?;
        if flags.insert(flag, value).is_some() {
            return Err("DUPLICATE_OPTION");
        }
    }
    Ok(flags)
}

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

pub fn order_request(
    mut args: impl Iterator<Item = String>,
    submit: bool,
) -> Result<Value, &'static str> {
    use hguet_cloud::report::{
        verify_archived_paid_check_with_keys, AnalysisState, AssessmentExpectations,
        ReceiptExpectations,
    };
    use hguet_cloud::wire::v1::{self, PaidCheckStatus};
    let path = args.next().ok_or("ORDER_REQUIRED")?;
    let flags = options(
        args,
        if submit {
            &[
                "--claim-file",
                "--ca-file",
                "--quote-key",
                "--payment-signature",
            ]
        } else {
            &[
                "--claim-file",
                "--ca-file",
                "--quote-key",
                "--assessment-key",
                "--receipt-key",
            ]
        },
    )?;
    let option = |name: &str| {
        flags
            .get(name)
            .map(String::as_str)
            .ok_or("MISSING_STATUS_OPTION")
    };
    let bytes = super::limited_file(&path, 131072).map_err(|_| "ORDER_UNREADABLE")?;
    let order: SavedOrder = serde_json::from_slice(&bytes).map_err(|_| "INVALID_ORDER")?;
    if order.version != 1 {
        return Err("UNSUPPORTED_ORDER_VERSION");
    }
    let secret =
        super::limited_file(option("--claim-file")?, 32).map_err(|_| "CLAIM_FILE_INVALID")?;
    if secret.len() != 32 || digest(&hguet_core::sha256_hex(&secret))? != order.claim_sha256 {
        return Err("CLAIM_MISMATCH");
    }
    let now = hguet_core::unix_now().map_err(|_| "CLOCK_UNAVAILABLE")? as i64;
    if order.verified_at > now {
        return Err("INVALID_ORDER_TIME");
    }
    let genesis = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
    let capabilities = vec!["program_upgrade_history".to_owned()];
    let subjects_sha256 = hguet_cloud::subjects_sha256(
        "devnet",
        &[Subject {
            network: "devnet".into(),
            category: "program".into(),
            subject_id: order.program.clone(),
        }],
    )
    .map_err(|e| e.code())?;
    let expected = QuoteExpectations {
        network: "devnet",
        genesis_hash: genesis,
        message_sha256: order.message_sha256,
        claim_secret_sha256: order.claim_sha256,
        maximum_lamports: order.maximum_lamports,
        intent_sha256: None,
        transaction_sha256: None,
        subjects_sha256,
        profile: "strict",
        requested_capabilities: &capabilities,
        now_unix: order.verified_at,
    };
    let frame = STANDARD
        .decode(order.quote_frame_base64)
        .map_err(|_| "INVALID_ORDER")?;
    let original = hguet_cloud::wire::decode_frame(&frame).map_err(|e| e.code())?;
    let signed = match original.payload {
        Some(Payload::PriceQuoteResult(r)) if r.result == ResultCode::ResultAccepted as i32 => {
            r.signed_quote.ok_or("INVALID_ORDER")?
        }
        _ => return Err("INVALID_ORDER"),
    };
    let quote = verify_signed_quote(&signed, &pinned(option("--quote-key")?)?, &expected)
        .map_err(|e| e.code())?;
    let quote_id: Vec<u8> = (0..quote.quote_id.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&quote.quote_id[i..i + 2], 16).map_err(|_| "QUOTE_ID_INVALID"))
        .collect::<Result<_, _>>()?;
    let mut profile = super::cloud_config::loopback_profile(option("--ca-file")?.into());
    if submit {
        profile.timeout = std::time::Duration::from_secs(70);
        let signature = option("--payment-signature")?;
        hguet_cloud::solana_signature(signature).map_err(|e| e.code())?;
        let request = envelope_with(
            quote_id
                .as_slice()
                .try_into()
                .map_err(|_| "QUOTE_ID_INVALID")?,
            Payload::PaidCheckRequest(v1::PaidCheckRequest {
                quote_id: quote_id.clone(),
                claim_secret: secret,
                payment_transaction_signature: signature.to_owned(),
                message_sha256: order.message_sha256.to_vec(),
                network: "devnet".into(),
                genesis_hash: genesis.into(),
                profile: "strict".into(),
                requested_capabilities: capabilities,
                scope: v1::DataScope::MetadataOnly as i32,
                evidence: Some(v1::ClientEvidence {
                    subjects: vec![v1::Subject {
                        category: "program".into(),
                        network: "devnet".into(),
                        subject_id: order.program,
                    }],
                    local_decision: "UNKNOWN".into(),
                    ..Default::default()
                }),
                subjects_sha256: subjects_sha256.to_vec(),
                quoted_complexity: Some(v1::ComplexityMetrics {
                    distinct_programs: 1,
                    risk_subjects: 1,
                    ..Default::default()
                }),
                ..Default::default()
            }),
        );
        let reply = exchange(&profile, &request).map_err(|e| e.code())?;
        if reply.request_id != request.request_id
            || (reply.protocol_major, reply.protocol_minor) != (1, 0)
        {
            return Err("SUBMISSION_RESPONSE_MISMATCH");
        }
        return match reply.payload {
            Some(Payload::CheckReceipt(r))
                if r.quote_id == quote_id
                    && r.result == ResultCode::ResultAccepted as i32
                    && r.state == "payment_finalized" =>
            {
                Ok(json!({"status":"payment_finalized","quote_id":quote.quote_id}))
            }
            Some(Payload::Error(_)) => Err("SUBMISSION_UNAVAILABLE"),
            _ => Err("SUBMISSION_RESPONSE_MISMATCH"),
        };
    }
    let receipt_key = pinned(option("--receipt-key")?)?;
    let assessment_key = pinned(option("--assessment-key")?)?;
    let request = envelope_with(
        quote_id
            .as_slice()
            .try_into()
            .map_err(|_| "QUOTE_ID_INVALID")?,
        Payload::PaidCheckStatus(PaidCheckStatus {
            quote_id: quote_id.clone(),
            claim_secret: secret,
        }),
    );
    let reply = exchange(&profile, &request).map_err(|e| e.code())?;
    if reply.request_id != request.request_id
        || (reply.protocol_major, reply.protocol_minor) != (1, 0)
    {
        return Err("STATUS_RESPONSE_MISMATCH");
    }
    let result = match reply.payload {
        Some(Payload::CheckResult(r))
            if r.result == ResultCode::ResultCompleted as i32 && r.quote_id == quote_id =>
        {
            r
        }
        Some(Payload::Error(e)) if e.code == ErrorCode::ErrorUnavailable as i32 => {
            return Err("STATUS_UNAVAILABLE")
        }
        _ => return Err("STATUS_RESPONSE_MISMATCH"),
    };
    let receipt = result.signed_payment_receipt.ok_or("RECEIPT_MISSING")?;
    let assessment = result.signed_cloud_assessment.ok_or("ASSESSMENT_MISSING")?;
    let verified = verify_archived_paid_check_with_keys(
        &receipt,
        Some(&assessment),
        &receipt_key,
        &assessment_key,
        &ReceiptExpectations {
            quote: &quote,
            network: "devnet",
            genesis_hash: genesis,
            message_sha256: order.message_sha256,
            assessment_payload: None,
        },
        &AssessmentExpectations {
            quote_id: &quote.quote_id,
            network: "devnet",
            genesis_hash: genesis,
            message_sha256: order.message_sha256,
            intent_sha256: None,
            transaction_sha256: None,
            subjects_sha256,
            profile: "strict",
            requested_capabilities: &capabilities,
            now_unix: now,
        },
    )
    .map_err(|e| e.code())?;
    if verified.receipt.analysis_state != AnalysisState::Completed {
        return Err("INCOMPLETE_RECEIPT");
    }
    let report: Value =
        serde_json::from_slice(&assessment.canonical_payload).map_err(|_| "INVALID_REPORT")?;
    let payment: Value =
        serde_json::from_slice(&receipt.canonical_payload).map_err(|_| "INVALID_RECEIPT")?;
    let expires = report["expires_at"]
        .as_str()
        .and_then(hguet_cloud::quote::parse_timestamp)
        .ok_or("INVALID_REPORT_TIME")?;
    Ok(
        json!({"assessment_fresh":now < expires,"assessment_expires_at_unix":expires,"status":"completed","quote_id":quote.quote_id,"program":order.program,"assessment":report,"receipt":payment}),
    )
}

pub fn run(mut args: impl Iterator<Item = String>) -> Result<Value, &'static str> {
    let program = args.next().ok_or("PROGRAM_REQUIRED")?;
    let flags = options(
        args,
        &[
            "--message-sha256",
            "--claim-sha256",
            "--max-lamports",
            "--ca-file",
            "--quote-key",
            "--save-order",
        ],
    )?;
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
    let signed = match &reply.payload {
        Some(Payload::PriceQuoteResult(result))
            if result.result == ResultCode::ResultAccepted as i32 =>
        {
            result.signed_quote.as_ref().ok_or("SIGNED_QUOTE_MISSING")?
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
    let verified = verify_signed_quote(signed, &key, &expected).map_err(|e| e.code())?;
    if let Some(path) = flags.get("--save-order") {
        let frame = hguet_cloud::wire::encode_frame(&reply).map_err(|e| e.code())?;
        save_order(
            Path::new(path),
            &SavedOrder {
                version: 1,
                program: program.clone(),
                message_sha256: params.message_sha256,
                claim_sha256: params.claim_secret_sha256,
                maximum_lamports: params.maximum_lamports,
                verified_at: expected.now_unix,
                quote_frame_base64: STANDARD.encode(frame),
            },
        )?;
    }
    Ok(
        json!({"network":"devnet","program":program,"quote_id":verified.quote_id,
        "lamports_due":verified.lamports_due.to_string(),"expires_at_unix":verified.expires_at_unix}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saving_another_quote_cannot_replace_a_recoverable_order() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("order.json");
        let mut order = SavedOrder {
            version: 1,
            program: String::from("first"),
            message_sha256: [1; 32],
            claim_sha256: [2; 32],
            maximum_lamports: 50,
            verified_at: 100,
            quote_frame_base64: String::new(),
        };
        save_order(&path, &order).unwrap();
        order.program = String::from("second");
        assert_eq!(save_order(&path, &order), Err("ORDER_PERSIST_FAILED"));
        let saved: SavedOrder = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(saved.program, "first");
    }

    fn args(values: &[&str]) -> impl Iterator<Item = String> {
        values
            .iter()
            .map(|value| (*value).to_owned())
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// Writes a saved order and its claim file. The order carries no signed
    /// quote, so every case below must fail before any network exchange.
    fn order_fixture(directory: &Path, claim: [u8; 32], committed: [u8; 32]) -> (String, String) {
        let order = directory.join("order.json");
        save_order(
            &order,
            &SavedOrder {
                version: 1,
                program: String::from("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi"),
                message_sha256: [1; 32],
                claim_sha256: committed,
                maximum_lamports: 1_000_000,
                verified_at: 100,
                quote_frame_base64: String::new(),
            },
        )
        .unwrap();
        let claim_file = directory.join("claim.bin");
        std::fs::write(&claim_file, claim).unwrap();
        (
            order.to_string_lossy().into_owned(),
            claim_file.to_string_lossy().into_owned(),
        )
    }

    fn claim_commitment(claim: [u8; 32]) -> [u8; 32] {
        digest(&hguet_core::sha256_hex(&claim)).unwrap()
    }

    #[test]
    fn submit_and_status_accept_only_their_own_options() {
        let directory = tempfile::tempdir().unwrap();
        let (order, claim) = order_fixture(directory.path(), [7; 32], claim_commitment([7; 32]));
        // Status-only verification keys are not accepted by submit, and a
        // payment signature is never accepted by the read-only status command.
        for (submit, flag) in [
            (true, "--assessment-key"),
            (true, "--receipt-key"),
            (false, "--payment-signature"),
        ] {
            assert_eq!(
                order_request(args(&[&order, "--claim-file", &claim, flag, "x"]), submit),
                Err("UNKNOWN_OPTION"),
                "{flag} with submit={submit}"
            );
        }
        assert_eq!(order_request(args(&[]), true), Err("ORDER_REQUIRED"));
        assert_eq!(
            order_request(
                args(&[
                    &order,
                    "--payment-signature",
                    "a",
                    "--payment-signature",
                    "b"
                ]),
                true
            ),
            Err("DUPLICATE_OPTION")
        );
        assert_eq!(
            order_request(args(&[&order, "--payment-signature", "--json"]), true),
            Err("MISSING_OPTION_VALUE")
        );
        assert_eq!(
            order_request(
                args(&[&order, "--payment-signature", "sig", "--json"]),
                true
            ),
            Err("MISSING_STATUS_OPTION"),
            "a claim file is required before any network exchange"
        );
    }

    #[test]
    fn submit_requires_the_committed_claim_secret_before_any_exchange() {
        let directory = tempfile::tempdir().unwrap();
        let (order, claim) = order_fixture(directory.path(), [8; 32], claim_commitment([9; 32]));
        assert_eq!(
            order_request(
                args(&[&order, "--claim-file", &claim, "--payment-signature", "sig"]),
                true
            ),
            Err("CLAIM_MISMATCH")
        );
        let short_claim = directory.path().join("short.bin");
        std::fs::write(&short_claim, [9; 31]).unwrap();
        assert_eq!(
            order_request(
                args(&[
                    &order,
                    "--claim-file",
                    &short_claim.to_string_lossy(),
                    "--payment-signature",
                    "sig"
                ]),
                true
            ),
            Err("CLAIM_MISMATCH")
        );
        let missing = directory.path().join("missing.json");
        assert_eq!(
            order_request(
                args(&[&missing.to_string_lossy(), "--payment-signature", "sig"]),
                true
            ),
            Err("ORDER_UNREADABLE")
        );
    }

    #[test]
    fn submit_rejects_an_order_without_a_verified_quote_frame() {
        let directory = tempfile::tempdir().unwrap();
        let (order, claim) = order_fixture(directory.path(), [10; 32], claim_commitment([10; 32]));
        let result = order_request(
            args(&[
                &order,
                "--claim-file",
                &claim,
                "--ca-file",
                "unused.pem",
                "--quote-key",
                "unused.pem",
                "--payment-signature",
                "sig",
            ]),
            true,
        );
        assert!(result.is_err(), "an unsigned order must never be submitted");
        assert_ne!(result, Err("SUBMISSION_UNAVAILABLE"));
    }
}
