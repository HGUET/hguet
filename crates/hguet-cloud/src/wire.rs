//! Frame codec and typed request builders over the public Protobuf messages (S7.1 PROPOSAL rules applied).
//! Still network-free: this module turns typed input into bytes and bytes into checked messages. The TLS transport
//! (TLS 1.3, SecP384r1MLKEM1024, authenticated ML-DSA-87 server identity) is NOT implemented here or in the CLI.

use crate::{canonical_subjects, proto_policy, subjects_sha256, Error, Result, Subject};
use prost::Message;
use std::collections::BTreeSet;

/// Messages generated at build time from `protocol/v1/hguet.proto`.
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/hguet.protocol.v1.rs"));
}

pub const MAX_FRAME_BYTES: usize = 1 << 20;
pub const PROFILES: [&str; 3] = ["strict", "review", "explore"];
/// Capability identifiers of the HGUET/server registry. Only `network_health` is evaluated by a real server today.
pub const SERVER_CAPABILITY_IDS: [&str; 9] = [
    "network_health",
    "program_risk",
    "program_upgrade_history",
    "behavior_window",
    "token_extensions",
    "authority_changes",
    "cpi_metadata",
    "independent_rpc_simulation",
    "extra_feed_lookup",
];

/// `4-byte big-endian length || Envelope`. A frame is never empty and never exceeds 1 MiB.
pub fn encode_frame(envelope: &v1::Envelope) -> Result<Vec<u8>> {
    let body = envelope.encode_to_vec();
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        return Err(Error("FRAME_INVALID_LENGTH"));
    }
    let mut frame = Vec::with_capacity(4 + body.len());
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    Ok(frame)
}

/// Decodes one Envelope body after the critical/unknown-field policy: prost alone skips unknown fields and lets a
/// duplicate silently win, which a hash-binding protocol cannot allow.
pub fn decode_envelope(body: &[u8]) -> Result<v1::Envelope> {
    proto_policy::check_envelope(body)?;
    v1::Envelope::decode(body).map_err(|_| Error("PROTO_DECODE"))
}

/// Decodes exactly one frame (header + body, nothing more).
pub fn decode_frame(frame: &[u8]) -> Result<v1::Envelope> {
    let header: [u8; 4] = frame
        .get(..4)
        .and_then(|h| h.try_into().ok())
        .ok_or(Error("FRAME_TRUNCATED"))?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(Error("FRAME_INVALID_LENGTH"));
    }
    let body = frame.get(4..).ok_or(Error("FRAME_TRUNCATED"))?;
    match body.len().cmp(&length) {
        std::cmp::Ordering::Less => Err(Error("FRAME_TRUNCATED")),
        std::cmp::Ordering::Greater => Err(Error("FRAME_TRAILING_BYTES")),
        std::cmp::Ordering::Equal => decode_envelope(body),
    }
}

/// Typed, already-validated inputs of a quote request. Raw transactions are never part of a metadata-only request.
#[derive(Debug, Clone)]
pub struct QuoteParams {
    pub network: String,
    pub genesis_hash: String,
    pub message_sha256: [u8; 32],
    pub intent_sha256: Option<[u8; 32]>,
    pub transaction_sha256: Option<[u8; 32]>,
    pub profile: String,
    pub requested_capabilities: Vec<String>,
    /// SHA-256 of the buyer-held claim secret; the secret itself never appears in a quote request.
    pub claim_secret_sha256: [u8; 32],
    pub maximum_lamports: u64,
    pub subjects: Vec<Subject>,
}

/// Builds a metadata-only `PriceQuoteRequest`: canonical sorted subjects, the S7.1 `subjects_sha256`, a decimal cap,
/// and complexity limited to what the client can state (`verified_from_raw_transaction` is always false).
pub fn build_price_quote_request(params: &QuoteParams) -> Result<v1::PriceQuoteRequest> {
    if !PROFILES.contains(&params.profile.as_str()) {
        return Err(Error("QUOTE_PROFILE_INVALID"));
    }
    let unique: BTreeSet<&str> = params
        .requested_capabilities
        .iter()
        .map(String::as_str)
        .collect();
    if unique.is_empty()
        || unique.len() != params.requested_capabilities.len()
        || unique.iter().any(|id| !SERVER_CAPABILITY_IDS.contains(id))
    {
        return Err(Error("QUOTE_CAPABILITY_INVALID"));
    }
    if params.maximum_lamports == 0 {
        return Err(Error("QUOTE_MAXIMUM_INVALID"));
    }
    let subjects = canonical_subjects(&params.network, &params.subjects)?;
    let digest = subjects_sha256(&params.network, &params.subjects)?;
    Ok(v1::PriceQuoteRequest {
        network: params.network.clone(),
        genesis_hash: params.genesis_hash.clone(),
        message_sha256: params.message_sha256.to_vec(),
        intent_sha256: params.intent_sha256.map(|d| d.to_vec()).unwrap_or_default(),
        profile: params.profile.clone(),
        requested_capabilities: params.requested_capabilities.clone(),
        scope: v1::DataScope::MetadataOnly as i32,
        claim_secret_sha256: params.claim_secret_sha256.to_vec(),
        maximum_lamports: params.maximum_lamports.to_string(),
        complexity: Some(v1::ComplexityMetrics {
            risk_subjects: subjects.len() as u32,
            verified_from_raw_transaction: false,
            ..Default::default()
        }),
        subjects: subjects
            .into_iter()
            .map(|s| v1::Subject {
                category: s.category,
                network: s.network,
                subject_id: s.subject_id,
            })
            .collect(),
        subjects_sha256: digest.to_vec(),
        transaction_sha256: params
            .transaction_sha256
            .map(|d| d.to_vec())
            .unwrap_or_default(),
        raw_transaction: Vec::new(),
        raw_transaction_consent: false,
    })
}

/// Wraps a request in a v1.0 Envelope.
pub fn envelope_with(request_id: [u8; 16], payload: v1::envelope::Payload) -> v1::Envelope {
    v1::Envelope {
        protocol_major: 1,
        protocol_minor: 0,
        request_id: request_id.to_vec(),
        payload: Some(payload),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
    const PROGRAM: &str = "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi";

    fn params() -> QuoteParams {
        QuoteParams {
            network: "devnet".into(),
            genesis_hash: GENESIS.into(),
            message_sha256: [1; 32],
            intent_sha256: None,
            transaction_sha256: None,
            profile: "strict".into(),
            requested_capabilities: vec!["network_health".into()],
            claim_secret_sha256: [2; 32],
            maximum_lamports: 5000,
            subjects: vec![Subject {
                category: "program".into(),
                network: "devnet".into(),
                subject_id: PROGRAM.into(),
            }],
        }
    }

    fn hello() -> v1::Envelope {
        envelope_with(
            [7; 16],
            v1::envelope::Payload::ClientHello(v1::ClientHello {
                supported_majors: vec![1],
                max_minor: 0,
                requested_capabilities: vec![],
                cli_release: "test".into(),
            }),
        )
    }

    #[test]
    fn a_quote_request_round_trips_through_a_frame_and_binds_its_subjects() {
        let request = build_price_quote_request(&params()).unwrap();
        assert_eq!(request.scope, v1::DataScope::MetadataOnly as i32);
        assert!(
            !request
                .complexity
                .as_ref()
                .unwrap()
                .verified_from_raw_transaction
        );
        assert_eq!(
            request.subjects_sha256,
            subjects_sha256("devnet", &params().subjects)
                .unwrap()
                .to_vec()
        );
        let frame = encode_frame(&envelope_with(
            [9; 16],
            v1::envelope::Payload::PriceQuoteRequest(request.clone()),
        ))
        .unwrap();
        let decoded = decode_frame(&frame).unwrap();
        assert_eq!(decoded.request_id, vec![9; 16]);
        assert_eq!(
            decoded.payload,
            Some(v1::envelope::Payload::PriceQuoteRequest(request))
        );
    }

    #[test]
    fn invalid_inputs_never_become_a_request() {
        let bad = |mutate: fn(&mut QuoteParams)| {
            let mut p = params();
            mutate(&mut p);
            build_price_quote_request(&p).unwrap_err().code()
        };
        assert_eq!(bad(|p| p.profile = "yolo".into()), "QUOTE_PROFILE_INVALID");
        assert_eq!(
            bad(|p| p.requested_capabilities = vec![]),
            "QUOTE_CAPABILITY_INVALID"
        );
        assert_eq!(
            bad(|p| p.requested_capabilities = vec!["subject_reputation_lookup".into()]),
            "QUOTE_CAPABILITY_INVALID"
        );
        assert_eq!(
            bad(|p| p.requested_capabilities =
                vec!["network_health".into(), "network_health".into()]),
            "QUOTE_CAPABILITY_INVALID"
        );
        assert_eq!(bad(|p| p.maximum_lamports = 0), "QUOTE_MAXIMUM_INVALID");
        assert_eq!(
            bad(|p| p.subjects[0].network = "mainnet".into()),
            "SUBJECT_NETWORK_MISMATCH"
        );
        assert_eq!(
            bad(|p| p.subjects.push(p.subjects[0].clone())),
            "SUBJECT_DUPLICATE"
        );
        assert_eq!(bad(|p| p.network = "moon".into()), "NETWORK_UNKNOWN");
    }

    #[test]
    fn frames_have_strict_bounds() {
        let frame = encode_frame(&hello()).unwrap();
        assert!(decode_frame(&frame).is_ok());
        assert_eq!(
            decode_frame(&frame[..frame.len() - 1]).unwrap_err().code(),
            "FRAME_TRUNCATED"
        );
        assert_eq!(
            decode_frame(&frame[..3]).unwrap_err().code(),
            "FRAME_TRUNCATED"
        );
        assert_eq!(
            decode_frame(&[frame.clone(), vec![0]].concat())
                .unwrap_err()
                .code(),
            "FRAME_TRAILING_BYTES"
        );
        assert_eq!(
            decode_frame(&[0, 0, 0, 0]).unwrap_err().code(),
            "FRAME_INVALID_LENGTH"
        );
        let oversized = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        assert_eq!(
            decode_frame(&oversized).unwrap_err().code(),
            "FRAME_INVALID_LENGTH"
        );
    }

    #[test]
    fn unknown_critical_fields_and_duplicates_are_refused_not_skipped() {
        let mut body = hello().encode_to_vec();
        let ok = body.clone();
        body.extend_from_slice(&[0x98, 0x06, 0x01]); // unknown field 99
        assert_eq!(
            decode_envelope(&body).unwrap_err().code(),
            "PROTO_UNKNOWN_CRITICAL_FIELD"
        );
        let mut extension = ok.clone();
        extension.extend_from_slice(&[0xc2, 0x3e, 0x01, 0x00]); // field 1000: non-critical extension, ignored
        assert!(decode_envelope(&extension).is_ok());
        let mut duplicate = ok;
        duplicate.extend_from_slice(&[0x08, 0x02]); // protocol_major repeated
        assert_eq!(
            decode_envelope(&duplicate).unwrap_err().code(),
            "PROTO_DUPLICATE_FIELD"
        );
    }
}
