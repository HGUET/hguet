//! Advisory comparison of independently signed direct source scopes with a
//! *later*, single-provider token-account snapshot. Never treats a matching
//! owner/delegate as authorization at the simulation bank or transaction time.
use crate::{
    mint_rpc::MintRpcSnapshot,
    token_account_rpc::TokenAccountRpcSnapshot,
    source_account_rpc::SignedSourceAccountRpcSnapshot,
    token_semantics::{TOKEN_PROGRAM,TOKEN_2022_PROGRAM},
    RpcError,
};
use hguet_core::TokenSourceLimitReview;
use serde::Serialize;
use std::collections::BTreeSet;

const MAX_SOURCES:usize=32;

#[derive(Debug,Clone,Serialize)]
pub struct SourceAuthorityObservation {
    pub mint:String,
    pub source_token_account:String,
    pub declared_token_program:String,
    pub declared_authority:String,
    pub declared_debit_raw:String,
    /// observed_owner, observed_delegate, observed_permanent_delegate, unmatched, unobserved
    pub authority_relationship:&'static str,
    /// token_2022, legacy_token, missing, other_program, unobserved
    pub account_observation:&'static str,
    pub context_slot:Option<u64>,
    pub observed_token_owner:Option<String>,
    pub observed_delegate:Option<String>,
    pub observed_mint_permanent_delegate:Option<String>,
    pub mint_permanent_delegate_matches_authority:Option<bool>,
    pub program_matches_wire:Option<bool>,
    pub mint_matches_signed_scope:Option<bool>,
    pub delegate_allowance_covers_declared:Option<bool>,
    pub later_account_balance_covers_declared:Option<bool>,
    pub frozen_at_observation:Option<bool>,
    pub restricted_or_opaque_extensions:Option<bool>,
    /// Evidence agreement is NOT an onchain or signer authorization proof.
    pub authorization_proven:bool,
}
#[derive(Debug,Clone,Serialize)]
pub struct SourceAuthorityReview {
    pub simulation_slot:u64,
    pub token_account_context_slot:Option<u64>,
    pub missing_signed_source_context_slot:Option<u64>,
    pub mint_context_slot:Option<u64>,
    pub atomic_with_simulation:bool,
    pub sources:Vec<SourceAuthorityObservation>,
    pub authorization_proven:bool,
    pub total_spending_proven:bool,
    pub limitation:&'static str,
}
pub fn correlate_signed_source_authority(
    source_review:&TokenSourceLimitReview,
    snapshot:Option<&TokenAccountRpcSnapshot>,
    simulation_slot:u64,
)->Result<SourceAuthorityReview,RpcError>{
    correlate_signed_source_authority_with_mints(
        source_review,snapshot,None,simulation_slot)
}
/// The mint permanent delegate is a third Token-2022 authority role.
/// It is read from yet another non-atomic single-provider snapshot.
pub fn correlate_signed_source_authority_with_mints(
    source_review:&TokenSourceLimitReview,
    snapshot:Option<&TokenAccountRpcSnapshot>,
    mints:Option<&MintRpcSnapshot>,
    simulation_slot:u64,
)->Result<SourceAuthorityReview,RpcError>{
    correlate_signed_source_authority_with_additional_sources(
        source_review,snapshot,None,mints,simulation_slot)
}
/// Optional signed-only source reads complement (never overwrite) balance
/// metadata account reads. Each observation retains its own RPC context slot.
pub fn correlate_signed_source_authority_with_additional_sources(
    source_review:&TokenSourceLimitReview,
    snapshot:Option<&TokenAccountRpcSnapshot>,
    additional:Option<&SignedSourceAccountRpcSnapshot>,
    mints:Option<&MintRpcSnapshot>,
    simulation_slot:u64,
)->Result<SourceAuthorityReview,RpcError>{
    if simulation_slot==0||source_review.debits.len()>MAX_SOURCES {
        return Err(RpcError::InvalidResponse);
    }
    if let Some(s)=snapshot {
        if s.simulation_slot!=simulation_slot || s.context_slot<simulation_slot ||
            s.atomic_with_simulation {
            return Err(RpcError::InvalidResponse);
        }
        if s.accounts.len()>16 {return Err(RpcError::TooLarge);}
        let mut seen=BTreeSet::new();
        if s.accounts.iter().any(|a|!seen.insert(&a.address)) {
            return Err(RpcError::InvalidResponse);
        }
    }
    if let Some(extra)=additional {
        if extra.simulation_slot!=simulation_slot ||
           extra.context_slot<simulation_slot || extra.atomic_with_simulation ||
           extra.accounts.len()>MAX_SOURCES {
            return Err(RpcError::InvalidResponse);
        }
        let mut seen=BTreeSet::new();
        for account in &extra.accounts {
            if !seen.insert(&account.address) {return Err(RpcError::InvalidResponse);}
            if snapshot.is_some_and(|s|s.accounts.iter().any(|a|a.address==account.address)) {
                return Err(RpcError::InvalidResponse);
            }
        }
    }
    if let Some(m)=mints {
        if m.simulation_slot!=simulation_slot || m.context_slot<simulation_slot ||
            m.atomic_with_simulation {return Err(RpcError::InvalidResponse);}
        if m.accounts.len()>16 {return Err(RpcError::TooLarge);}
        let mut seen=BTreeSet::new();
        for account in &m.accounts {
            if !seen.insert(&account.address) {return Err(RpcError::InvalidResponse);}
            if let Some(state)=&account.state {
                if account.status!="token_2022" || state.mint_address!=account.address {
                    return Err(RpcError::InvalidResponse);
                }
            }
        }
    }
    let mut out=Vec::with_capacity(source_review.debits.len());
    for source in &source_review.debits {
        let mut observation=SourceAuthorityObservation {
            mint:source.mint.clone(),
            source_token_account:source.source_token_account.clone(),
            declared_token_program:source.token_program.clone(),
            declared_authority:source.declared_authority.clone(),
            declared_debit_raw:source.declared_raw.clone(),
            authority_relationship:"unobserved",
            account_observation:"unobserved",
            context_slot:None,
            observed_token_owner:None,observed_delegate:None,
            observed_mint_permanent_delegate:None,
            mint_permanent_delegate_matches_authority:None,
            program_matches_wire:None,mint_matches_signed_scope:None,
            delegate_allowance_covers_declared:None,
            later_account_balance_covers_declared:None,
            frozen_at_observation:None,restricted_or_opaque_extensions:None,
            authorization_proven:false,
        };
        if source.token_program==TOKEN_2022_PROGRAM {
            if let Some(mint)=mints.and_then(|m|m.accounts.iter()
                .find(|item|item.address==source.mint && item.status=="token_2022"))
                .and_then(|item|item.state.as_ref()) {
                observation.observed_mint_permanent_delegate=mint.permanent_delegate.clone();
                observation.mint_permanent_delegate_matches_authority=Some(
                    mint.permanent_delegate.as_deref()==Some(source.declared_authority.as_str()));
            }
        }
        let from_balances=snapshot.and_then(|s|s.accounts.iter()
            .find(|a|a.address==source.source_token_account));
        let from_signed=additional.and_then(|s|s.accounts.iter()
            .find(|a|a.address==source.source_token_account));
        let (status,state,address,slot) = match (from_balances,from_signed) {
            (Some(_),Some(_))=>return Err(RpcError::InvalidResponse),
            (Some(account),None)=>(
                account.status.as_str(),account.state.as_ref(),
                account.address.as_str(),snapshot.map(|s|s.context_slot),
            ),
            (None,Some(account))=>{
                if account.signed_mint!=source.mint ||
                    account.declared_token_program!=source.token_program {
                    return Err(RpcError::InvalidResponse);
                }
                (account.status,account.state.as_ref(),account.address.as_str(),
                    additional.map(|s|s.context_slot))
            },
            (None,None)=>{
                out.push(observation);
                continue;
            }
        };
        observation.context_slot=slot;
        observation.account_observation=match status {
            "token_2022"=>"token_2022",
            "legacy_token"=>"legacy_token",
            "missing"=>"missing",
            "not_token_2022"|"other_program"=>"other_program",
            _=>return Err(RpcError::InvalidResponse),
        };
        let expected_program=match source.token_program.as_str(){
            TOKEN_PROGRAM=>"legacy_token",
            TOKEN_2022_PROGRAM=>"token_2022",
            _=>return Err(RpcError::InvalidResponse),
        };
        observation.program_matches_wire=match status {
            "token_2022"|"legacy_token"=>Some(status==expected_program),
            "missing"=>None,
            _=>Some(false),
        };
        if let Some(state)=state {
            if !matches!(status,"token_2022"|"legacy_token") ||
                state.token_account!=address {
                return Err(RpcError::InvalidResponse);
            }
            let declared=source.declared_raw.parse::<u128>()
                .map_err(|_|RpcError::InvalidResponse)?;
            let amount=state.amount_raw.parse::<u64>()
                .map_err(|_|RpcError::InvalidResponse)?;
            observation.later_account_balance_covers_declared=
                Some(u128::from(amount)>=declared);
            observation.mint_matches_signed_scope=Some(state.mint==source.mint);
            observation.observed_token_owner=Some(state.token_authority.clone());
            observation.observed_delegate=state.delegate.clone();
            observation.frozen_at_observation=Some(state.account_state=="frozen");
            observation.restricted_or_opaque_extensions=Some(
                state.non_transferable_account||
                state.confidential_extension_present||
                state.opaque_extension_count>0||
                state.transfer_hook_transferring==Some(true)
            );
            if state.token_authority==source.declared_authority {
                observation.authority_relationship="observed_owner";
            } else if state.delegate.as_deref()==Some(source.declared_authority.as_str()) {
                observation.authority_relationship="observed_delegate";
                let delegated=state.delegated_amount_raw.parse::<u64>()
                    .map_err(|_|RpcError::InvalidResponse)?;
                observation.delegate_allowance_covers_declared=
                    Some(u128::from(delegated)>=declared);
            } else if observation.mint_permanent_delegate_matches_authority==Some(true) {
                observation.authority_relationship="observed_permanent_delegate";
            } else {
                observation.authority_relationship="unmatched";
            }
        } else if matches!(status,"token_2022"|"legacy_token") {
            return Err(RpcError::InvalidResponse);
        }
        out.push(observation);
    }
    Ok(SourceAuthorityReview{
        simulation_slot,
        token_account_context_slot:snapshot.map(|s|s.context_slot),
        missing_signed_source_context_slot:additional.map(|s|s.context_slot),
        mint_context_slot:mints.map(|m|m.context_slot),
        atomic_with_simulation:false,
        sources:out,authorization_proven:false,total_spending_proven:false,
        limitation:"Signed source/mint/required-signer roles are original-wire declarations. Balance-derived token accounts, extra signed-only source accounts and Token-2022 mint permanent-delegate fields can come from three separate single-provider RPC reads at different slots, NOT the execution bank. State may have changed; multisig/PDA authority, CPI and hook effects remain unverified. Neither matching owner, account delegate nor mint permanent delegate proves permission at execution or supports ALLOW.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        token_account_rpc::TokenAccountObservation,
        token_account_state::Token2022AccountState,
    };
    use hguet_core::DeclaredSourceDebit;
    fn pubkey(b:u8)->String {bs58::encode([b;32]).into_string()}
    fn signed(program:&str,authority:u8,raw:&str)->TokenSourceLimitReview {
        TokenSourceLimitReview {
            debits:vec![DeclaredSourceDebit {
                token_program:program.into(),mint:pubkey(2),
                source_token_account:pubkey(3),
                declared_authority:pubkey(authority),
                declared_raw:raw.into(),signed_limit_raw:"300".into(),
            }],
            checked_direct_debit_instructions:1,
            transaction_required_signer_role_checked:true,
            transaction_signatures_verified:false,
            token_account_owner_verified:false,total_spending_proven:false,
            coverage:"test",limitation:"test",
        }
    }
    fn state(owner:u8,delegate:Option<u8>,amount:u64,allowance:u64)
        ->Token2022AccountState{
        Token2022AccountState{
            token_account:pubkey(3),mint:pubkey(2),token_authority:pubkey(owner),
            amount_raw:amount.to_string(),
            delegate:delegate.map(pubkey),
            delegated_amount_raw:allowance.to_string(),
            account_state:"initialized",
            native_reserve_lamports:None,close_authority:None,
            transfer_fee_withheld_raw:None,requires_incoming_memo:None,
            cpi_guard_locked:None,transfer_hook_transferring:None,
            immutable_owner:false,non_transferable_account:false,
            confidential_extension_present:false,opaque_extension_count:0,
            unknown_extension_count:0,extensions:vec![],limitation:"test".into(),
        }
    }
    fn snap(program:&str,state:Option<Token2022AccountState>)->TokenAccountRpcSnapshot{
        TokenAccountRpcSnapshot {
            context_slot:601,simulation_slot:600,atomic_with_simulation:false,
            accounts:vec![TokenAccountObservation {
                address:pubkey(3),simulation_reported_mint:pubkey(2),
                status:program.into(),state,mint_matches_simulation_report:Some(true),
                authority_matches_simulation_report:Some(true),
                matching_mint_state_observed:false,
            }],
            limitation:"test".into(),
        }
    }
    #[test]
    fn matching_owner_is_observed_not_verified_even_if_account_has_balance(){
        let r=correlate_signed_source_authority(
            &signed(TOKEN_2022_PROGRAM,4,"120"),
            Some(&snap("token_2022",Some(state(4,None,200,0)))),600
        ).unwrap();
        assert_eq!(r.sources[0].authority_relationship,"observed_owner");
        assert_eq!(r.sources[0].program_matches_wire,Some(true));
        assert_eq!(r.sources[0].mint_matches_signed_scope,Some(true));
        assert_eq!(r.sources[0].later_account_balance_covers_declared,Some(true));
        assert!(!r.authorization_proven);
        assert!(!r.atomic_with_simulation);
        assert_eq!(r.token_account_context_slot,Some(601));
    }
    #[test]
    fn delegated_authority_is_not_false_owner_conflict_and_allowance_is_bounded(){
        let snap=snap("token_2022",Some(state(4,Some(5),250,150)));
        let ok=correlate_signed_source_authority(
            &signed(TOKEN_2022_PROGRAM,5,"120"),Some(&snap),600).unwrap();
        assert_eq!(ok.sources[0].authority_relationship,"observed_delegate");
        assert_eq!(ok.sources[0].delegate_allowance_covers_declared,Some(true));
        let short=correlate_signed_source_authority(
            &signed(TOKEN_2022_PROGRAM,5,"200"),Some(&snap),600).unwrap();
        assert_eq!(short.sources[0].delegate_allowance_covers_declared,Some(false));
    }
    #[test]
    fn legacy_token_owner_and_delegate_are_inspected_without_token2022_tlv(){
        let r=correlate_signed_source_authority(
            &signed(TOKEN_PROGRAM,4,"100"),
            Some(&snap("legacy_token",Some(state(4,None,150,0)))),600
        ).unwrap();
        assert_eq!(r.sources[0].account_observation,"legacy_token");
        assert_eq!(r.sources[0].program_matches_wire,Some(true));
        assert_eq!(r.sources[0].authority_relationship,"observed_owner");
        assert!(!r.sources[0].authorization_proven);
    }
    #[test]
    fn frozen_mint_and_program_conflicts_remain_explicit(){
        let mut wrong=state(8,None,10,0);
        wrong.mint=pubkey(9);
        wrong.account_state="frozen";
        let r=correlate_signed_source_authority(
            &signed(TOKEN_2022_PROGRAM,4,"120"),
            Some(&snap("legacy_token",Some(wrong))),600
        ).unwrap();
        let a=&r.sources[0];
        assert_eq!(a.program_matches_wire,Some(false));
        assert_eq!(a.mint_matches_signed_scope,Some(false));
        assert_eq!(a.authority_relationship,"unmatched");
        assert_eq!(a.frozen_at_observation,Some(true));
        assert_eq!(a.later_account_balance_covers_declared,Some(false));
    }
    #[test]
    fn missing_or_uncovered_account_is_not_silently_safe(){
        let none=correlate_signed_source_authority(
            &signed(TOKEN_2022_PROGRAM,4,"100"),None,600).unwrap();
        assert_eq!(none.sources[0].account_observation,"unobserved");
        assert_eq!(none.sources[0].program_matches_wire,None);
        let gone=correlate_signed_source_authority(
            &signed(TOKEN_2022_PROGRAM,4,"100"),
            Some(&snap("missing",None)),600).unwrap();
        assert_eq!(gone.sources[0].account_observation,"missing");
        assert_eq!(gone.sources[0].authority_relationship,"unobserved");
        assert!(!gone.authorization_proven);
    }
    #[test]
    fn token2022_mint_permanent_delegate_is_a_third_observed_authority_role(){
        use crate::{
            mint_rpc::{MintAccountObservation,MintRpcSnapshot},
            mint_state::Token2022MintState,
        };
        let mint=MintRpcSnapshot {
            context_slot:602,simulation_slot:600,atomic_with_simulation:false,
            accounts:vec![MintAccountObservation {
                address:pubkey(2),status:"token_2022".into(),
                state:Some(Token2022MintState {
                    mint_address:pubkey(2),supply_raw:"5000".into(),decimals:6,
                    extensions:vec![],fee_config:None,hook:None,
                    permanent_delegate:Some(pubkey(5)),
                    unknown_extension_count:0,confidential_extension_present:false,
                    limitations:"test".into(),
                }),
            }],
            limitation:"test".into(),
        };
        let token=snap("token_2022",Some(state(4,None,250,0)));
        let scope=signed(TOKEN_2022_PROGRAM,5,"100");
        let r=correlate_signed_source_authority_with_mints(
            &scope,Some(&token),Some(&mint),600).unwrap();
        assert_eq!(r.sources[0].authority_relationship,"observed_permanent_delegate");
        assert_eq!(r.sources[0].mint_permanent_delegate_matches_authority,Some(true));
        assert_eq!(r.sources[0].observed_mint_permanent_delegate.as_deref(),
            Some(pubkey(5).as_str()));
        assert_eq!(r.mint_context_slot,Some(602));
        assert!(!r.authorization_proven);
        assert!(!r.total_spending_proven);
        assert!(!r.atomic_with_simulation);
        let legacy=correlate_signed_source_authority_with_mints(
            &signed(TOKEN_PROGRAM,5,"100"),Some(&snap("legacy_token",Some(state(4,None,250,0)))),
            Some(&mint),600).unwrap();
        assert_eq!(legacy.sources[0].authority_relationship,"unmatched");
        assert_eq!(legacy.sources[0].mint_permanent_delegate_matches_authority,None);
    }
    #[test]
    fn invalid_mint_snapshot_slot_does_not_create_false_authority(){
        use crate::mint_rpc::MintRpcSnapshot;
        let review=signed(TOKEN_2022_PROGRAM,5,"100");
        let mut mint=MintRpcSnapshot {
            context_slot:599,simulation_slot:600,atomic_with_simulation:false,
            accounts:vec![],limitation:"test".into(),
        };
        assert_eq!(correlate_signed_source_authority_with_mints(
            &review,None,Some(&mint),600).unwrap_err(),RpcError::InvalidResponse);
        mint.context_slot=601;
        mint.atomic_with_simulation=true;
        assert_eq!(correlate_signed_source_authority_with_mints(
            &review,None,Some(&mint),600).unwrap_err(),RpcError::InvalidResponse);
    }
    #[test]
    fn old_slot_atomic_claim_duplicate_or_inconsistent_state_is_rejected(){
        let signed=signed(TOKEN_2022_PROGRAM,4,"100");
        let mut s=snap("token_2022",Some(state(4,None,200,0)));
        s.context_slot=599;
        assert_eq!(correlate_signed_source_authority(&signed,Some(&s),600).unwrap_err(),RpcError::InvalidResponse);
        s.context_slot=601;s.atomic_with_simulation=true;
        assert_eq!(correlate_signed_source_authority(&signed,Some(&s),600).unwrap_err(),RpcError::InvalidResponse);
        s.atomic_with_simulation=false;
        s.accounts.push(s.accounts[0].clone());
        assert_eq!(correlate_signed_source_authority(&signed,Some(&s),600).unwrap_err(),RpcError::InvalidResponse);
        s.accounts.pop();
        s.accounts[0].state.as_mut().unwrap().token_account=pubkey(7);
        assert_eq!(correlate_signed_source_authority(&signed,Some(&s),600).unwrap_err(),RpcError::InvalidResponse);
    }
}
