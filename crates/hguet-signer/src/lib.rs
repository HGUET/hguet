//! Isolated customer signer integration seam (unreleased, BLOCK-ONLY).
//! No keys, wallet implementation, transaction broadcast, or RPC trust here.
#![forbid(unsafe_code)]

use hguet_core::{
    parse_transaction, verify_intent, ParsedTransaction, SignedPaymentIntent,
    TransactionSignatureStatus,
};
use hguet_rpc::{assess_signing_boundary, inspect_direct_tokens, SigningBoundary};
use serde::Serialize;
use std::convert::Infallible;

// No SignerBackend trait is exposed: a public sign_transaction method would
// be a misleading and unnecessary escape hatch in a BLOCK-only crate.
// A real wallet/device integration requires an explicitly reviewed redesign.

/// Only original transaction bytes, an untrusted signed intent envelope, an
/// independently pinned trust key, cluster and trusted local time. No JSON
/// risk verdict, RPC report or agent-generated approval is accepted.
#[derive(Clone, Copy)]
pub struct SignerRequest<'a> {
    pub original_transaction: &'a [u8],
    pub signed_intent: Option<&'a SignedPaymentIntent>,
    pub independently_pinned_intent_signer: Option<&'a str>,
    pub network: &'a str,
    pub now_unix: u64,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SignerRefusal {
    pub version: u32,
    pub signing_gate: &'static str,
    pub signing_permitted: bool,
    pub signer_backend_invoked: bool,
    pub signature_created: bool,
    pub transaction_broadcast: bool,
    pub original_transaction_sha256: Option<String>,
    pub original_message_sha256: Option<String>,
    pub independent_intent_signature_verified: bool,
    pub reason_code: &'static str,
    pub signing_boundary: Option<SigningBoundary>,
    pub limitation: &'static str,
}
const LIMITATION:&str=
    "Block-only local signer seam. No private keys or signer-device calls, signing or broadcast, onchain authorization, independent bank proof or enforceable gross SOL/token spend limit. Agent or selected RPC cannot grant permission.";

fn refused(
    reason: &'static str,
    parsed: Option<&ParsedTransaction>,
    intent_verified: bool,
    boundary: Option<SigningBoundary>,
) -> SignerRefusal {
    SignerRefusal {
        version: 1,
        signing_gate: "block",
        signing_permitted: false,
        signer_backend_invoked: false,
        signature_created: false,
        transaction_broadcast: false,
        original_transaction_sha256: parsed.map(|p| p.transaction_sha256.clone()),
        original_message_sha256: parsed.map(|p| p.message_sha256.clone()),
        independent_intent_signature_verified: intent_verified,
        reason_code: reason,
        signing_boundary: boundary,
        limitation: LIMITATION,
    }
}

/// Recompute source identity from raw bytes, verify signed intent independently,
/// and return a refusal. A matching signature never becomes signing consent.
pub fn inspect_signer_request(input: SignerRequest<'_>) -> SignerRefusal {
    if !matches!(input.network, "mainnet" | "devnet" | "testnet") {
        return refused("UNSUPPORTED_NETWORK", None, false, None);
    }
    let parsed = match parse_transaction(input.original_transaction) {
        Ok(p) => p,
        Err(_) => return refused("MALFORMED_OR_UNSUPPORTED_TRANSACTION", None, false, None),
    };
    let direct = if parsed.unresolved_lookup_addresses == 0 {
        inspect_direct_tokens(&parsed, None).ok()
    } else {
        None
    };
    let (intent, reason) = match (
        input.signed_intent,
        input.independently_pinned_intent_signer,
    ) {
        (None, _) => (None, "SIGNED_INTENT_MISSING"),
        (_, None) => (None, "INDEPENDENT_TRUST_KEY_MISSING"),
        (Some(envelope), Some(pin)) => {
            match verify_intent(envelope, pin, input.network, &parsed, input.now_unix) {
                Ok(valid) => (Some(valid), "SIGNER_SIDE_ENFORCEMENT_NOT_IMPLEMENTED"),
                Err(_) => (None, "SIGNED_INTENT_VERIFICATION_FAILED"),
            }
        }
    };
    let boundary = assess_signing_boundary(&parsed, intent.as_ref(), direct.as_ref(), None);
    let reason = if parsed.transaction_signature_status == TransactionSignatureStatus::Invalid {
        "TRANSACTION_SIGNATURE_INVALID"
    } else {
        reason
    };
    refused(reason, Some(&parsed), intent.is_some(), Some(boundary))
}

/// Requests have an uninhabited success type and NO backend argument.
/// The only operation is refusal, even when the intent passes cryptography.
#[allow(clippy::result_large_err)] // refusal carries a full report; this fn is never Ok (Infallible)
pub fn guarded_sign(input: SignerRequest<'_>) -> Result<Infallible, SignerRefusal> {
    Err(inspect_signer_request(input))
}

pub mod isolation;
#[cfg(test)]
mod tests;
