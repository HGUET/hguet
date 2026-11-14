//! Signing boundary for *potential future signer integrations*.
//!
//! This is a deliberately non-authorizing interface. A valid signed intent
//! can bound direct, decoded original-wire declarations but NOT total SOL or
//! token effects. RPC data cannot upgrade its conclusions. Nothing here signs,
//! submits or approves a transaction, and no other component should interpret
//! this report as permission to do so.
use crate::{DirectTokenAnalysis,AggregateTokenSpending};
use hguet_core::{ParsedTransaction,PaymentIntentPayload,TransactionSignatureStatus,
    review_declared_token_limits,review_declared_source_limits};
use serde::Serialize;
use std::collections::BTreeSet;

const TOKEN_PROGRAM:&str="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM:&str="TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const SYSTEM_PROGRAM:&str="11111111111111111111111111111111";
const COMPUTE_BUDGET:&str="ComputeBudget111111111111111111111111111111";
const MEMO_PROGRAM:&str="MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

#[derive(Debug,Clone,Serialize)]
pub struct SigningBoundary {
    pub version:u32,
    pub message_sha256:String,
    pub transaction_signature_status:TransactionSignatureStatus,
    pub independent_intent_verified_by_caller:bool,
    pub native_sol_direct_transfer_declared_raw:String,
    pub direct_token_program_present:bool,
    /// A signed cap validated against original-wire checked Token/Token-2022
    /// instructions is a declaration bound, NOT a global spending limit.
    pub direct_mint_declaration_bound_checked:bool,
    pub direct_source_declaration_bound_checked:bool,
    pub original_wire_program_allowlist_checked:bool,
    pub rpc_advisory_aggregate_available:bool,
    pub rpc_advisory_cap_anomalies:bool,
    pub original_wire_lookup_identity_unresolved:bool,
    pub unsupported_program_execution_surface:bool,
    pub direct_token_semantics_incomplete:bool,
    pub signer_side_enforcement_integrated:bool,
    pub execution_bank_authenticated:bool,
    pub total_native_sol_spending_proven:bool,
    pub total_gross_token_spending_proven:bool,
    pub automated_signing_permitted:bool,
    /// Always "block": an explicit refusal to produce a signing grant.
    pub signing_gate:&'static str,
    pub block_reasons:Vec<&'static str>,
    pub limitation:&'static str,
}

/// The intent argument must be the *success* of core::verify_intent with an
/// independently pinned public key. A caller must never pass an agent-supplied
/// JSON payload here, and this API does not itself verify signatures.
///
/// A completed RPC simulation/aggregate is purely advisory and cannot remove
/// any blocker. The gate is block-only, including with Verified transaction
/// signatures (which prove bytes were signed, not payer consent or execution).
pub fn assess_signing_boundary(
    parsed:&ParsedTransaction,
    verified_intent:Option<&PaymentIntentPayload>,
    original_wire_token_decode:Option<&DirectTokenAnalysis>,
    rpc_aggregate:Option<&AggregateTokenSpending>,
)->SigningBoundary {
    let mut reasons=BTreeSet::new();
    let original_wire_lookup_identity_unresolved=parsed.unresolved_lookup_addresses>0;
    let direct_token_program_present=parsed.program_ids.iter()
        .any(|p|matches!(p.as_str(),TOKEN_PROGRAM|TOKEN_2022_PROGRAM));
    let unsupported_program_execution_surface=parsed.program_ids.iter().any(|p|
        !matches!(p.as_str(),SYSTEM_PROGRAM|TOKEN_PROGRAM|TOKEN_2022_PROGRAM|
            COMPUTE_BUDGET|MEMO_PROGRAM));
    let orig_complete=original_wire_token_decode.is_some_and(|v|
        v.opaque.is_empty() &&
        v.total_token_program_instructions==v.recognized.len() &&
        !v.recognized.iter().any(|ix|
            ix.program_address_from_lookup||ix.account_addresses_from_lookup));
    let direct_token_semantics_incomplete=
        direct_token_program_present && !orig_complete ||
        original_wire_token_decode.is_none();
    let mut mint_bound=false;
    let mut source_bound=false;
    let mut program_allowlist_checked=false;
    let mut verified=false;
    if let Some(intent)=verified_intent {
        // Never claim a bound when the caller accidentally passed an
        // unrelated intent or when the on-wire message still uses ALTs.
        if intent.message_sha256==parsed.message_sha256 &&
           !original_wire_lookup_identity_unresolved {
            verified=true;
            program_allowlist_checked=parsed.program_ids.iter()
                .all(|p|intent.allowed_program_ids.contains(p));
            if let Some(limits)=intent.token_spend_limits.as_ref() {
                mint_bound=review_declared_token_limits(parsed,limits).is_ok();
            }
            if let Some(limits)=intent.token_source_limits.as_ref() {
                source_bound=review_declared_source_limits(parsed,limits).is_ok();
            }
        }else{
            reasons.insert("INTENT_MESSAGE_OR_LOOKUP_UNRESOLVED");
        }
    }
    if !verified {reasons.insert("NO_INDEPENDENT_VERIFIED_INTENT");}
    if verified && !program_allowlist_checked {
        reasons.insert("SIGNED_PROGRAM_ALLOWLIST_NOT_SATISFIED");
    }
    if original_wire_lookup_identity_unresolved {
        reasons.insert("ORIGINAL_WIRE_ALT_IDENTITY_UNRESOLVED");
    }
    if unsupported_program_execution_surface {
        reasons.insert("CUSTOM_OR_UNSUPPORTED_PROGRAM_EFFECTS");
    }
    if direct_token_semantics_incomplete {
        reasons.insert("DIRECT_TOKEN_SEMANTICS_INCOMPLETE");
    }
    if direct_token_program_present && !mint_bound {
        reasons.insert("DIRECT_TOKEN_MINT_LIMIT_NOT_VERIFIED");
    }
    if direct_token_program_present && !source_bound {
        reasons.insert("DIRECT_TOKEN_SOURCE_LIMIT_NOT_VERIFIED");
    }
    if parsed.transaction_signature_status==TransactionSignatureStatus::Invalid {
        reasons.insert("TRANSACTION_SIGNATURE_INVALID");
    }
    // Signature absence is a normal pre-signing state. Distinguish it from
    // a hard cryptographic invalid signature; neither permits auto-sign.
    if rpc_aggregate.is_none() {
        reasons.insert("RPC_EFFECT_COVERAGE_UNAVAILABLE");
    }
    let rpc_advisory_cap_anomalies=rpc_aggregate.is_some_and(|v|v.any_signed_cap_warning);
    if rpc_advisory_cap_anomalies {
        reasons.insert("RPC_CAP_ANOMALIES_ADVISORY");
    }
    if rpc_aggregate.is_some_and(|v|
        v.opaque_direct_token_instructions>0||
        v.opaque_rpc_cpi_token_instructions>0||
        v.unattributed_cpi_debit_instructions>0||
        v.unattributed_direct_debit_instructions>0||
        v.cpi_source_coverage_missing_or_incomplete||
        v.missing_token_balance_snapshot){
        reasons.insert("RPC_GROSS_DEBIT_COVERAGE_INCOMPLETE");
    }
    // Invariants: no signer integration, no verified bank snapshot, no
    // transaction-wide gross token or native SOL enforcement. This is a
    // blocking analysis surface, not a signer permission oracle.
    reasons.insert("SIGNER_SIDE_ENFORCEMENT_NOT_INTEGRATED");
    reasons.insert("EXECUTION_BANK_NOT_AUTHENTICATED");
    reasons.insert("TOTAL_NATIVE_SOL_SPEND_NOT_PROVEN");
    reasons.insert("TOTAL_GROSS_TOKEN_SPEND_NOT_PROVEN");
    SigningBoundary {
        version:1,message_sha256:parsed.message_sha256.clone(),
        transaction_signature_status:parsed.transaction_signature_status.clone(),
        independent_intent_verified_by_caller:verified,
        native_sol_direct_transfer_declared_raw:
            parsed.declared_system_transfer_lamports.clone(),
        direct_token_program_present,direct_mint_declaration_bound_checked:mint_bound,
        direct_source_declaration_bound_checked:source_bound,
        original_wire_program_allowlist_checked:program_allowlist_checked,
        rpc_advisory_aggregate_available:rpc_aggregate.is_some(),
        rpc_advisory_cap_anomalies,original_wire_lookup_identity_unresolved,
        unsupported_program_execution_surface,direct_token_semantics_incomplete,
        signer_side_enforcement_integrated:false,
        execution_bank_authenticated:false,
        total_native_sol_spending_proven:false,
        total_gross_token_spending_proven:false,
        automated_signing_permitted:false,
        signing_gate:"block",
        block_reasons:reasons.into_iter().collect(),
        limitation:"This read-only gate never authorizes or signs. Only separately verified signed message/direct checked token declarations can be locally bounded. Missing intent, ALT, custom programs, Token-2022 extensions, unknown CPI, fees, account ownership, RPC simulation and final execution prevent proof of transaction-wide gross spending. A trusted, enforceable customer signer is not integrated; BLOCK is unconditional.",
    }
}
