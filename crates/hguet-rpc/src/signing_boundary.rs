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

#[cfg(test)]
mod tests{
    use super::*;
    use crate::inspect_direct_tokens;
    use hguet_core::{parse_transaction,TokenSpendLimit,TokenSourceLimit};
    fn k(n:u8)->String{bs58::encode([n;32]).into_string()}
    fn tx()->ParsedTransaction{
        let mut v=vec![1];
        v.extend([0u8;64]);
        v.extend([1,0,1,5]);
        for s in [k(1),k(2),k(3),k(4),TOKEN_PROGRAM.into()] {
            v.extend(bs58::decode(s).into_vec().unwrap());
        }
        v.extend([9u8;32]);
        v.extend([1,4,4,1,2,3,0,10,12]);
        v.extend(40u64.to_le_bytes());
        v.push(6);
        parse_transaction(&v).unwrap()
    }
    fn intent(p:&ParsedTransaction)->PaymentIntentPayload{
        PaymentIntentPayload{
            schema_version:1,kind:"hguet_payment_intent".into(),
            intent_id:"synthetic".into(),network:"devnet".into(),
            message_sha256:p.message_sha256.clone(),
            not_before_unix:1,expires_at_unix:4102444800,
            allowed_program_ids:vec![TOKEN_PROGRAM.into()],
            max_spend_lamports:"500".into(),
            token_spend_limits:Some(vec![TokenSpendLimit{
                mint:k(3),max_debit_raw:"40".into(),
            }]),
            token_source_limits:Some(vec![TokenSourceLimit{
                mint:k(3),source_token_account:k(2),authority:k(1),
                max_debit_raw:"40".into(),
            }]),
        }
    }
    #[test]
    fn signed_direct_declaration_caps_can_be_checked_but_never_grant_signing(){
        let p=tx();
        let decoded=inspect_direct_tokens(&p,None).unwrap();
        assert_eq!(decoded.recognized[0].decoded.amount_raw.as_deref(),Some("40"));
        let intent=intent(&p);
        let result=assess_signing_boundary(&p,Some(&intent),Some(&decoded),None);
        assert!(result.independent_intent_verified_by_caller);
        assert!(result.direct_token_program_present);
        assert!(result.direct_mint_declaration_bound_checked);
        assert!(result.direct_source_declaration_bound_checked);
        assert!(result.original_wire_program_allowlist_checked);
        assert_eq!(result.signing_gate,"block");
        assert!(!result.automated_signing_permitted);
        assert!(!result.total_native_sol_spending_proven);
        assert!(!result.total_gross_token_spending_proven);
        assert!(!result.signer_side_enforcement_integrated);
        assert!(result.block_reasons.contains(&"SIGNER_SIDE_ENFORCEMENT_NOT_INTEGRATED"));
        assert!(result.block_reasons.contains(&"TOTAL_GROSS_TOKEN_SPEND_NOT_PROVEN"));
        assert!(!result.block_reasons.contains(&"DIRECT_TOKEN_MINT_LIMIT_NOT_VERIFIED"));
    }
    #[test]
    fn untrusted_absent_intent_never_gets_direct_declaration_cap_status(){
        let p=tx();
        let decoded=inspect_direct_tokens(&p,None).unwrap();
        let r=assess_signing_boundary(&p,None,Some(&decoded),None);
        assert!(!r.independent_intent_verified_by_caller);
        assert!(!r.direct_mint_declaration_bound_checked);
        assert!(!r.direct_source_declaration_bound_checked);
        assert!(r.block_reasons.contains(&"NO_INDEPENDENT_VERIFIED_INTENT"));
        assert!(r.block_reasons.contains(&"DIRECT_TOKEN_MINT_LIMIT_NOT_VERIFIED"));
        assert!(r.block_reasons.contains(&"DIRECT_TOKEN_SOURCE_LIMIT_NOT_VERIFIED"));
        assert!(!r.automated_signing_permitted);
    }
    #[test]
    fn invalid_or_mismatched_intent_and_overcap_never_create_a_verified_bound(){
        let p=tx();
        let decoded=inspect_direct_tokens(&p,None).unwrap();
        let mut i=intent(&p);
        i.message_sha256="f".repeat(64);
        let r=assess_signing_boundary(&p,Some(&i),Some(&decoded),None);
        assert!(!r.independent_intent_verified_by_caller);
        assert!(!r.direct_mint_declaration_bound_checked);
        assert!(r.block_reasons.contains(&"INTENT_MESSAGE_OR_LOOKUP_UNRESOLVED"));
        i.message_sha256=p.message_sha256.clone();
        i.token_source_limits.as_mut().unwrap()[0].max_debit_raw="39".into();
        let r=assess_signing_boundary(&p,Some(&i),Some(&decoded),None);
        assert!(r.direct_mint_declaration_bound_checked);
        assert!(!r.direct_source_declaration_bound_checked);
        assert!(r.block_reasons.contains(&"DIRECT_TOKEN_SOURCE_LIMIT_NOT_VERIFIED"));
        assert!(!r.automated_signing_permitted);
    }
    #[test]
    fn verified_transaction_signature_does_not_prove_business_consent(){
        let mut p=tx();
        p.transaction_signature_status=TransactionSignatureStatus::Verified;
        let decoded=inspect_direct_tokens(&p,None).unwrap();
        let r=assess_signing_boundary(&p,Some(&intent(&p)),Some(&decoded),None);
        assert_eq!(r.transaction_signature_status,TransactionSignatureStatus::Verified);
        assert!(!r.automated_signing_permitted);
        assert!(!r.execution_bank_authenticated);
    }
    #[test]
    fn rpc_derived_alt_and_unknown_decoder_are_explicit_signing_blockers(){
        let mut p=tx();
        let decoded=inspect_direct_tokens(&p,None).unwrap();
        p.unresolved_lookup_addresses=1;
        let r=assess_signing_boundary(&p,Some(&intent(&p)),None,None);
        assert!(r.original_wire_lookup_identity_unresolved);
        assert!(r.block_reasons.contains(&"ORIGINAL_WIRE_ALT_IDENTITY_UNRESOLVED"));
        assert!(!r.direct_mint_declaration_bound_checked);
        assert!(!r.automated_signing_permitted);
        let p=tx();
        let mut d=decoded;
        d.recognized[0].account_addresses_from_lookup=true;
        let r=assess_signing_boundary(&p,Some(&intent(&p)),Some(&d),None);
        assert!(r.direct_token_semantics_incomplete);
        assert!(r.block_reasons.contains(&"DIRECT_TOKEN_SEMANTICS_INCOMPLETE"));
        assert!(!r.automated_signing_permitted);
    }
    #[test]
    fn original_wire_custom_program_is_explicit_unbounded_effect_surface(){
        let mut p=tx();
        p.program_ids.push(k(7));
        let r=assess_signing_boundary(&p,Some(&intent(&p)),None,None);
        assert!(r.unsupported_program_execution_surface);
        assert!(r.block_reasons.contains(&"CUSTOM_OR_UNSUPPORTED_PROGRAM_EFFECTS"));
        assert!(r.block_reasons.contains(&"SIGNED_PROGRAM_ALLOWLIST_NOT_SATISFIED"));
        assert!(!r.automated_signing_permitted);
    }
    #[test]
    fn mint_only_and_source_only_caps_are_never_conflated(){
        let p=tx();
        let d=inspect_direct_tokens(&p,None).unwrap();
        let mut i=intent(&p);
        i.token_source_limits=None;
        let mint_only=assess_signing_boundary(&p,Some(&i),Some(&d),None);
        assert!(mint_only.direct_mint_declaration_bound_checked);
        assert!(!mint_only.direct_source_declaration_bound_checked);
        assert!(!mint_only.automated_signing_permitted);
        i.token_source_limits=intent(&p).token_source_limits;
        i.token_spend_limits=None;
        let source_only=assess_signing_boundary(&p,Some(&i),Some(&d),None);
        assert!(!source_only.direct_mint_declaration_bound_checked);
        assert!(source_only.direct_source_declaration_bound_checked);
        assert!(!source_only.automated_signing_permitted);
    }
    #[test]
    fn empty_signed_mint_cap_still_blocks_checked_token_transfer(){
        let p=tx();let direct=inspect_direct_tokens(&p,None).unwrap();
        let mut i=intent(&p);
        i.token_spend_limits=Some(vec![]);
        let r=assess_signing_boundary(&p,Some(&i),Some(&direct),None);
        assert!(!r.direct_mint_declaration_bound_checked);
        assert!(r.block_reasons.contains(&"DIRECT_TOKEN_MINT_LIMIT_NOT_VERIFIED"));
    }
}
