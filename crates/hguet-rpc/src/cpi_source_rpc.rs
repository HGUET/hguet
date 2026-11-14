//! Single-provider, read-only CPI token source discovery and separate account
//! snapshots. CPI instructions are compiled-byte interpretations supplied by
//! the selected RPC, never signed transaction declarations or execution proof.
//! No implied mint, no account balance attribution, no spend authorization.
use super::{checked_result,JsonRpcTransport,RpcError};
use crate::{
    effects::SimulationEffects,
    source_account_rpc::SignedSourceAccountRpcSnapshot,
    token_account_rpc::TokenAccountRpcSnapshot,
    token_account_state::{parse_token_2022_account,Token2022AccountState,MAX_ACCOUNT_BYTES},
    token_semantics::{TOKEN_PROGRAM,TOKEN_2022_PROGRAM},
};
use base64::{engine::general_purpose::STANDARD,Engine as _};
use serde::Serialize;
use serde_json::{json,Value};
use std::collections::{BTreeMap,BTreeSet};
const MAX_CPI_SOURCE_QUERIES:usize=32;
const MAX_ENCODED:usize=MAX_ACCOUNT_BYTES.div_ceil(3)*4+4;

#[derive(Debug,Clone,Serialize)]
pub struct CpiSourceClaim {
    pub parent_instruction_index:usize,
    pub inner_instruction_index:usize,
    pub operation:String,
    pub source_account:String,
    pub declared_program:String,
    /// Can be absent for unchecked CPI transfer; do not guess it from user
    /// input or silently replace it with later observed mint.
    pub declared_mint:Option<String>,
    pub declared_authority:Option<String>,
    pub declared_raw_amount:Option<String>,
}
#[derive(Debug,Clone,Serialize)]
pub struct CpiSourceAccountObservation {
    pub address:String,
    pub declared_program:String,
    pub program_matches_cpi:Option<bool>,
    pub status:&'static str,
    pub state:Option<Token2022AccountState>,
}
#[derive(Debug,Clone,Serialize)]
pub struct CpiSourceRpcSnapshot {
    pub simulation_slot:u64,
    pub context_slot:u64,
    pub atomic_with_simulation:bool,
    pub accounts:Vec<CpiSourceAccountObservation>,
    pub limitation:&'static str,
}
#[derive(Debug,Clone,Serialize)]
pub struct CpiSourceEvidence {
    pub claim:CpiSourceClaim,
    /// balance_rpc, signed_source_rpc, cpi_source_rpc, unobserved.
    pub observation_source:&'static str,
    pub context_slot:Option<u64>,
    /// token_2022, legacy_token, other_program, missing, unobserved
    pub account_status:&'static str,
    pub observed_mint:Option<String>,
    pub observed_owner:Option<String>,
    pub observed_delegate:Option<String>,
    pub program_matches_cpi:Option<bool>,
    pub mint_matches_cpi:Option<bool>,
    pub authority_relationship:&'static str,
    pub later_balance_covers_declared:Option<bool>,
    pub later_delegate_allowance_covers_declared:Option<bool>,
    pub frozen_at_observation:Option<bool>,
    pub authorization_proven:bool,
}
#[derive(Debug,Clone,Serialize)]
pub struct CpiSourceCoverage {
    pub simulation_slot:u64,
    pub cpi_account_context_slot:Option<u64>,
    pub atomic_with_simulation:bool,
    pub cpi_captured:bool,
    pub opaque_token_instruction_count:usize,
    pub token_2022_extension_instruction_count:usize,
    pub unsupported_or_missing_cpi_source_semantics:bool,
    pub entries:Vec<CpiSourceEvidence>,
    pub unobserved_sources:usize,
    pub total_gross_token_spending_proven:bool,
    pub authorization_proven:bool,
    pub security_coverage:&'static str,
    pub limitation:&'static str,
}
fn canonical(value:&str)->bool {
    bs58::decode(value).into_vec().map(|v|
        v.len()==32 && bs58::encode(&v).into_string()==value
    ).unwrap_or(false)
}
fn relevant(op:&str)->bool{
    matches!(op,"transfer"|"transfer_checked"|"burn"|"burn_checked"|
        "approve"|"approve_checked"|"revoke"|"close_account"|
        "freeze_account"|"thaw_account"|"sync_native")
}
fn plausible_amount(amount:&Option<String>)->bool {
    amount.as_ref().is_none_or(|v|!v.is_empty()&&v.len()<=20&&
        v.bytes().all(|b|b.is_ascii_digit())&&v.parse::<u64>().is_ok())
}
/// A claim is based on one provider's decoded CPI bytes, never proof that the
/// instruction actually reached a token account or that its source is owned.
pub fn cpi_source_claims(effects:&SimulationEffects)->Result<Vec<CpiSourceClaim>,RpcError>{
    if effects.cpi.token_instructions.len()>512 ||
        effects.cpi.token_2022_extension_observations.len()>512 {
        return Err(RpcError::TooLarge);
    }
    let mut out=Vec::new();
    for ix in &effects.cpi.token_instructions {
        if !relevant(ix.operation.as_str()){continue;}
        if ix.program_id!=TOKEN_PROGRAM&&ix.program_id!=TOKEN_2022_PROGRAM{
            return Err(RpcError::InvalidResponse);
        }
        let source=ix.source_account.as_deref().filter(|s|canonical(s))
            .ok_or(RpcError::InvalidResponse)?;
        if ix.mint.as_deref().is_some_and(|s|!canonical(s)) ||
           ix.authority.as_deref().is_some_and(|s|!canonical(s)) ||
           !plausible_amount(&ix.amount_raw) {
            return Err(RpcError::InvalidResponse);
        }
        out.push(CpiSourceClaim {
            parent_instruction_index:ix.parent_instruction_index,
            inner_instruction_index:ix.inner_instruction_index,
            operation:ix.operation.clone(),source_account:source.into(),
            declared_program:ix.program_id.clone(),declared_mint:ix.mint.clone(),
            declared_authority:ix.authority.clone(),
            declared_raw_amount:ix.amount_raw.clone(),
        });
    }
    for ix in &effects.cpi.token_2022_extension_observations {
        if ix.operation!="transfer_checked_with_fee"||!ix.layout_checked {continue;}
        let source=ix.source_account.as_deref().filter(|s|canonical(s))
            .ok_or(RpcError::InvalidResponse)?;
        let mint=ix.mint.as_deref().filter(|s|canonical(s))
            .ok_or(RpcError::InvalidResponse)?;
        let authority=ix.authority.as_deref().filter(|s|canonical(s))
            .ok_or(RpcError::InvalidResponse)?;
        if !plausible_amount(&ix.declared_amount_raw) || ix.declared_amount_raw.is_none(){
            return Err(RpcError::InvalidResponse);
        }
        out.push(CpiSourceClaim {
            parent_instruction_index:ix.parent_instruction_index,
            inner_instruction_index:ix.inner_instruction_index,
            operation:ix.operation.into(),source_account:source.into(),
            declared_program:TOKEN_2022_PROGRAM.into(),declared_mint:Some(mint.into()),
            declared_authority:Some(authority.into()),
            declared_raw_amount:ix.declared_amount_raw.clone(),
        });
    }
    if out.len()>512{return Err(RpcError::TooLarge);}
    out.sort_by(|a,b|(
        a.parent_instruction_index,a.inner_instruction_index,&a.source_account,
        &a.operation).cmp(&(
        b.parent_instruction_index,b.inner_instruction_index,&b.source_account,
        &b.operation)));
    Ok(out)
}
fn existing_address_sets(
    simulation_slot:u64,primary:Option<&TokenAccountRpcSnapshot>,
    signed:Option<&SignedSourceAccountRpcSnapshot>,
)->Result<(BTreeSet<String>,u64),RpcError>{
    if simulation_slot==0{return Err(RpcError::InvalidResponse);}
    let mut existing=BTreeSet::new();
    let mut min_slot=simulation_slot;
    if let Some(p)=primary {
        if p.simulation_slot!=simulation_slot||p.context_slot<simulation_slot||
           p.atomic_with_simulation||p.accounts.len()>16 {
            return Err(RpcError::InvalidResponse);
        }
        min_slot=min_slot.max(p.context_slot);
        for account in &p.accounts{
            if !canonical(&account.address)||!existing.insert(account.address.clone()){
                return Err(RpcError::InvalidResponse);
            }
        }
    }
    if let Some(s)=signed {
        if s.simulation_slot!=simulation_slot||s.context_slot<simulation_slot||
           s.atomic_with_simulation||s.accounts.len()>32 {
            return Err(RpcError::InvalidResponse);
        }
        min_slot=min_slot.max(s.context_slot);
        for account in &s.accounts {
            if !canonical(&account.address)||!existing.insert(account.address.clone()){
                return Err(RpcError::InvalidResponse);
            }
        }
    }
    Ok((existing,min_slot))
}
fn missing_addresses(
    claims:&[CpiSourceClaim],existing:&BTreeSet<String>,
)->Result<Vec<(String,String)>,RpcError>{
    let mut missing=BTreeMap::<String,String>::new();
    for claim in claims {
        if !canonical(&claim.source_account) ||
           !matches!(claim.declared_program.as_str(),TOKEN_PROGRAM|TOKEN_2022_PROGRAM){
            return Err(RpcError::InvalidResponse);
        }
        if existing.contains(&claim.source_account){continue;}
        if let Some(prev)=missing.insert(
            claim.source_account.clone(),claim.declared_program.clone()
        ) {
            if prev!=claim.declared_program{return Err(RpcError::InvalidResponse);}
        }
        if missing.len()>MAX_CPI_SOURCE_QUERIES{return Err(RpcError::TooLarge);}
    }
    Ok(missing.into_iter().collect())
}
/// One extra bounded request for accounts known ONLY from selected provider
/// CPI compiled instructions. A prior balance- or signed-source snapshot is
/// never overwritten or re-fetched; all contexts remain non-atomic.
pub fn fetch_missing_cpi_sources<T:JsonRpcTransport>(
    transport:&T,endpoint:&str,simulation_slot:u64,
    effects:&SimulationEffects,
    primary:Option<&TokenAccountRpcSnapshot>,
    signed:Option<&SignedSourceAccountRpcSnapshot>,
)->Result<Option<CpiSourceRpcSnapshot>,RpcError>{
    if !effects.cpi.captured{return Ok(None);}
    let claims=cpi_source_claims(effects)?;
    let (existing,min_slot)=existing_address_sets(simulation_slot,primary,signed)?;
    let missing=missing_addresses(&claims,&existing)?;
    if missing.is_empty(){return Ok(None);}
    let request=json!({"jsonrpc":"2.0","id":7,"method":"getMultipleAccounts",
        "params":[missing.iter().map(|(s,_)|s).collect::<Vec<_>>(),
                  {"encoding":"base64","commitment":"confirmed",
                   "minContextSlot":min_slot}]
    });
    let response=checked_result(transport.post_json(endpoint,&request)?,7)?;
    let slot=response.get("context").and_then(|v|v.get("slot"))
        .and_then(Value::as_u64).filter(|slot|*slot>=min_slot)
        .ok_or(RpcError::InvalidResponse)?;
    let values=response.get("value").and_then(Value::as_array)
        .ok_or(RpcError::InvalidResponse)?;
    if values.len()!=missing.len(){return Err(RpcError::InvalidResponse);}
    let mut accounts=Vec::with_capacity(missing.len());
    for ((addr,program),response) in missing.into_iter().zip(values) {
        let mut item=CpiSourceAccountObservation {
            address:addr.clone(),declared_program:program.clone(),
            program_matches_cpi:None,status:"missing",state:None,
        };
        if response.is_null(){accounts.push(item);continue;}
        let obj=response.as_object().ok_or(RpcError::InvalidResponse)?;
        if obj.get("executable").and_then(Value::as_bool)!=Some(false){
            return Err(RpcError::InvalidResponse);
        }
        let owner=obj.get("owner").and_then(Value::as_str)
            .ok_or(RpcError::InvalidResponse)?;
        if owner!=TOKEN_PROGRAM&&owner!=TOKEN_2022_PROGRAM {
            item.status="other_program";
            item.program_matches_cpi=Some(false);
            accounts.push(item);continue;
        }
        let data=obj.get("data").and_then(Value::as_array)
            .ok_or(RpcError::InvalidResponse)?;
        if data.len()!=2||data[1].as_str()!=Some("base64"){
            return Err(RpcError::InvalidResponse);
        }
        let b64=data[0].as_str().ok_or(RpcError::InvalidResponse)?;
        if b64.len()>MAX_ENCODED{return Err(RpcError::TooLarge);}
        let decoded=STANDARD.decode(b64).map_err(|_|RpcError::InvalidResponse)?;
        let state=parse_token_2022_account(&addr,owner,&decoded)?;
        item.status=if owner==TOKEN_2022_PROGRAM{"token_2022"}else{"legacy_token"};
        item.program_matches_cpi=Some(owner==program);
        item.state=Some(state);
        accounts.push(item);
    }
    Ok(Some(CpiSourceRpcSnapshot{
        simulation_slot,context_slot:slot,atomic_with_simulation:false,accounts,
        limitation:"Selected RPC compiled CPI instructions, not independently signed wire, chose these source addresses. getMultipleAccounts was a separate later minimum-slot single-provider read. CPI execution, source ownership, gross debits, Token-2022 hooks and total spend remain unverified; missing data is not zero and no ALLOW is possible.",
    }))
}

/// Map every decoded CPI claim to exactly one of three distinct RPC snapshot
/// sources, preserving the per-observation slot. No inferred mint is turned
/// into a CPI-declared mint. Opaque instructions remain an explicit gap.
pub fn correlate_cpi_source_coverage(
    simulation_slot:u64,effects:&SimulationEffects,
    primary:Option<&TokenAccountRpcSnapshot>,
    signed:Option<&SignedSourceAccountRpcSnapshot>,
    cpi:Option<&CpiSourceRpcSnapshot>,
)->Result<CpiSourceCoverage,RpcError>{
    let claims=cpi_source_claims(effects)?;
    let (existing,_)=existing_address_sets(simulation_slot,primary,signed)?;
    if let Some(c)=cpi {
        let min_slot=simulation_slot
            .max(primary.map_or(simulation_slot,|p|p.context_slot))
            .max(signed.map_or(simulation_slot,|p|p.context_slot));
        if c.simulation_slot!=simulation_slot||c.context_slot<min_slot||
           c.atomic_with_simulation||c.accounts.len()>MAX_CPI_SOURCE_QUERIES {
            return Err(RpcError::InvalidResponse);
        }
        let mut seen=BTreeSet::new();
        for item in &c.accounts {
            if !canonical(&item.address)||!seen.insert(&item.address)||
                existing.contains(&item.address) {
                return Err(RpcError::InvalidResponse);
            }
            let source_claims=claims.iter().filter(|x|x.source_account==item.address)
                .collect::<Vec<_>>();
            if source_claims.is_empty() ||
               source_claims.iter().any(|x|x.declared_program!=item.declared_program) {
                return Err(RpcError::InvalidResponse);
            }
            match (item.status,item.state.as_ref()) {
                ("missing",None) if item.program_matches_cpi.is_none()=>{},
                ("other_program",None) if item.program_matches_cpi==Some(false)=>{},
                ("legacy_token",Some(state)) if state.token_account==item.address &&
                    item.program_matches_cpi==Some(item.declared_program==TOKEN_PROGRAM)=>{},
                ("token_2022",Some(state)) if state.token_account==item.address &&
                    item.program_matches_cpi==Some(item.declared_program==TOKEN_2022_PROGRAM)=>{},
                _=>return Err(RpcError::InvalidResponse),
            }
        }
    }
    let mut entries=Vec::with_capacity(claims.len());
    let mut unobserved=0;
    for claim in claims {
        let from_balance=primary.and_then(|p|p.accounts.iter()
            .find(|a|a.address==claim.source_account));
        let from_signed=signed.and_then(|p|p.accounts.iter()
            .find(|a|a.address==claim.source_account));
        let from_cpi=cpi.and_then(|p|p.accounts.iter()
            .find(|a|a.address==claim.source_account));
        let (source,status,state,slot,program_match)=match (
            from_balance,from_signed,from_cpi
        ){
            (Some(a),None,None)=>(
                "balance_rpc",a.status.as_str(),a.state.as_ref(),
                primary.map(|p|p.context_slot),None),
            (None,Some(a),None)=>(
                "signed_source_rpc",a.status,a.state.as_ref(),
                signed.map(|p|p.context_slot),
                Some(a.declared_token_program==claim.declared_program)),
            (None,None,Some(a))=>(
                "cpi_source_rpc",a.status,a.state.as_ref(),
                cpi.map(|p|p.context_slot),a.program_matches_cpi),
            (None,None,None)=>("unobserved","unobserved",None,None,None),
            _=>return Err(RpcError::InvalidResponse),
        };
        let account_status=match status {
            "token_2022"=>"token_2022",
            "legacy_token"=>"legacy_token",
            "missing"=>"missing",
            "unobserved"=>"unobserved",
            "other_program"|"not_token_2022"=>"other_program",
            _=>return Err(RpcError::InvalidResponse),
        };
        let actual_program=match account_status{
            "token_2022"=>Some(TOKEN_2022_PROGRAM),
            "legacy_token"=>Some(TOKEN_PROGRAM),_=>None,
        };
        let program_matches=actual_program.map(|p|p==claim.declared_program)
            .or(program_match);
        let mut item=CpiSourceEvidence {
            claim,observation_source:source,context_slot:slot,
            account_status,observed_mint:None,observed_owner:None,
            observed_delegate:None,program_matches_cpi:program_matches,
            mint_matches_cpi:None,authority_relationship:"unobserved",
            later_balance_covers_declared:None,
            later_delegate_allowance_covers_declared:None,
            frozen_at_observation:None,authorization_proven:false,
        };
        if let Some(state)=state {
            if !matches!(account_status,"token_2022"|"legacy_token") ||
                state.token_account!=item.claim.source_account{
                return Err(RpcError::InvalidResponse);
            }
            item.observed_mint=Some(state.mint.clone());
            item.observed_owner=Some(state.token_authority.clone());
            item.observed_delegate=state.delegate.clone();
            item.mint_matches_cpi=item.claim.declared_mint.as_deref()
                .map(|mint|mint==state.mint);
            item.frozen_at_observation=Some(state.account_state=="frozen");
            let amount=state.amount_raw.parse::<u64>()
                .map_err(|_|RpcError::InvalidResponse)?;
            let declared=item.claim.declared_raw_amount.as_deref()
                .map(|n|n.parse::<u64>().map_err(|_|RpcError::InvalidResponse))
                .transpose()?;
            item.later_balance_covers_declared=declared
                .map(|n|amount>=n);
            if let Some(authority)=item.claim.declared_authority.as_deref(){
                if state.token_authority==authority {
                    item.authority_relationship="observed_owner";
                } else if state.delegate.as_deref()==Some(authority) {
                    item.authority_relationship="observed_delegate";
                    let allowance=state.delegated_amount_raw.parse::<u64>()
                        .map_err(|_|RpcError::InvalidResponse)?;
                    item.later_delegate_allowance_covers_declared=declared
                        .map(|n|allowance>=n);
                } else {
                    // Could be a Token-2022 mint permanent delegate or PDA.
                    item.authority_relationship="unmatched_or_mint_delegate_unobserved";
                }
            }
        }else{
            unobserved+=1;
            if matches!(account_status,"token_2022"|"legacy_token"){
                return Err(RpcError::InvalidResponse);
            }
        }
        entries.push(item);
    }
    let unsupported=!effects.cpi.captured||
        effects.cpi.opaque_token_instruction_count>0||
        effects.cpi.missing_compiled_token_data_count>0||
        effects.cpi.token_2022_extension_observations.iter().any(|x|
            x.operation!="transfer_checked_with_fee"||!x.layout_checked);
    Ok(CpiSourceCoverage {
        simulation_slot,cpi_account_context_slot:cpi.map(|c|c.context_slot),
        atomic_with_simulation:false,cpi_captured:effects.cpi.captured,
        opaque_token_instruction_count:effects.cpi.opaque_token_instruction_count,
        token_2022_extension_instruction_count:effects.cpi.token_2022_extension_instruction_count,
        unsupported_or_missing_cpi_source_semantics:unsupported,
        entries,unobserved_sources:unobserved,
        total_gross_token_spending_proven:false,authorization_proven:false,
        security_coverage:"partial_untrusted_rpc",
        limitation:"Every CPI source is from an untrusted RPC compiled inner instruction, not original signed wire. Token account state is a later non-atomic RPC read with per-source slot and provenance. No full CPI coverage, account authority, exact gross spend, signer enforcement or safe ALLOW is established.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        effects::CpiObservation,
        token_semantics::TokenCpiInstruction,
        extension_semantics::Token2022ExtensionObservation,
        token_account_rpc::TokenAccountObservation,
        source_account_rpc::SignedSourceAccountObservation,
    };
    use std::cell::Cell;
    fn key(n:u8)->String{bs58::encode([n;32]).into_string()}
    fn claim(op:&str,source:u8,mint:Option<u8>)->TokenCpiInstruction {
        TokenCpiInstruction {
            parent_instruction_index:0,inner_instruction_index:1,
            program_id:TOKEN_PROGRAM.into(),operation:op.into(),
            source_account:Some(key(source)),destination_account:Some(key(4)),
            mint:mint.map(key),authority:Some(key(9)),delegate:None,
            amount_raw:Some("20".into()),decimals:Some(6),
            authority_type:None,new_authority:None,
        }
    }
    fn effects(ix:Vec<TokenCpiInstruction>)->SimulationEffects{
        SimulationEffects {
            lamport_deltas:None,token_deltas:None,
            cpi:CpiObservation {
                captured:true,group_count:Some(1),instruction_count:Some(ix.len()),
                invoked_program_ids:vec![],token_instructions:ix,
                token_2022_extension_observations:vec![],
                opaque_token_instruction_count:0,
                token_2022_extension_instruction_count:0,
                missing_compiled_token_data_count:0,
                requires_semantic_review:true,limitations:vec![],
            },
            simulated_fee_lamports:None,observed_fields:vec![],
            missing_fields:vec![],warnings:vec![],
            security_coverage:"partial_untrusted_rpc".into(),
        }
    }
    fn data(mint:u8,owner:u8)->Value{
        let mut bytes=vec![0u8;165];
        bytes[..32].fill(mint);bytes[32..64].fill(owner);
        bytes[64..72].copy_from_slice(&100u64.to_le_bytes());
        bytes[108]=1;
        json!({"owner":TOKEN_PROGRAM,"executable":false,
            "data":[STANDARD.encode(bytes),"base64"]})
    }
    struct Fake{calls:Cell<usize>,slot:u64,values:Value}
    impl JsonRpcTransport for Fake{
        fn post_json(&self,_endpoint:&str,req:&Value)->Result<Value,RpcError>{
            self.calls.set(self.calls.get()+1);
            assert_eq!(req["method"],"getMultipleAccounts");
            assert_eq!(req["id"],7);
            assert_eq!(req["params"][1]["commitment"],"confirmed");
            Ok(json!({"jsonrpc":"2.0","id":7,"result":{
                "context":{"slot":self.slot},"value":self.values}}))
        }
    }
    #[test]
    fn checked_cpi_source_missing_from_balance_is_read_and_labeled(){
        let f=Fake{calls:Cell::new(0),slot:603,values:json!([data(2,9)])};
        let effects=effects(vec![claim("transfer_checked",3,Some(2))]);
        let read=fetch_missing_cpi_sources(
            &f,"https://example.org",600,&effects,None,None).unwrap().unwrap();
        assert_eq!(f.calls.get(),1);
        assert_eq!(read.accounts[0].address,key(3));
        assert_eq!(read.context_slot,603);
        let result=correlate_cpi_source_coverage(600,&effects,None,None,Some(&read)).unwrap();
        assert_eq!(result.entries.len(),1);
        assert_eq!(result.entries[0].observation_source,"cpi_source_rpc");
        assert_eq!(result.entries[0].mint_matches_cpi,Some(true));
        assert_eq!(result.entries[0].program_matches_cpi,Some(true));
        assert_eq!(result.entries[0].authority_relationship,"observed_owner");
        assert!(!result.authorization_proven);
        assert!(!result.total_gross_token_spending_proven);
    }
    #[test]
    fn unchecked_cpi_transfer_has_no_declared_mint_even_if_account_has_one(){
        let f=Fake{calls:Cell::new(0),slot:600,values:json!([data(2,9)])};
        let effects=effects(vec![claim("transfer",3,None)]);
        let read=fetch_missing_cpi_sources(
            &f,"https://example.org",600,&effects,None,None).unwrap().unwrap();
        let result=correlate_cpi_source_coverage(600,&effects,None,None,Some(&read)).unwrap();
        assert_eq!(result.entries[0].claim.declared_mint,None);
        assert_eq!(result.entries[0].observed_mint.as_deref(),Some(key(2).as_str()));
        assert_eq!(result.entries[0].mint_matches_cpi,None);
    }
    #[test]
    fn prior_balance_and_signed_snapshot_are_reused_without_rpc_duplicates(){
        let effects=effects(vec![claim("burn_checked",3,Some(2))]);
        let balance=TokenAccountRpcSnapshot {
            simulation_slot:600,context_slot:606,atomic_with_simulation:false,
            accounts:vec![TokenAccountObservation {
                address:key(3),simulation_reported_mint:key(2),
                status:"legacy_token".into(),
                state:Some(parse_token_2022_account(
                    &key(3),TOKEN_PROGRAM,&{
                        let mut b=vec![0;165];
                        b[..32].fill(2);b[32..64].fill(9);b[108]=1;b
                    }).unwrap()),
                mint_matches_simulation_report:Some(true),
                authority_matches_simulation_report:Some(true),
                matching_mint_state_observed:false,
            }],
            limitation:"test".into(),
        };
        let f=Fake{calls:Cell::new(0),slot:600,values:json!([])};
        assert!(fetch_missing_cpi_sources(&f,"https://example.org",600,
            &effects,Some(&balance),None).unwrap().is_none());
        assert_eq!(f.calls.get(),0);
        let result=correlate_cpi_source_coverage(600,&effects,Some(&balance),None,None).unwrap();
        assert_eq!(result.entries[0].observation_source,"balance_rpc");
        assert_eq!(result.entries[0].context_slot,Some(606));
        let signed=SignedSourceAccountRpcSnapshot{
            simulation_slot:600,context_slot:607,atomic_with_simulation:false,
            accounts:vec![SignedSourceAccountObservation{
                address:key(3),signed_mint:key(2),
                declared_token_program:TOKEN_PROGRAM.into(),
                status:"legacy_token",
                state:balance.accounts[0].state.clone(),
                mint_matches_signed_scope:Some(true),
                program_matches_signed_scope:Some(true),
            }],
            limitation:"test",
        };
        assert!(fetch_missing_cpi_sources(&f,"https://example.org",600,
            &effects,None,Some(&signed)).unwrap().is_none());
        let result=correlate_cpi_source_coverage(600,&effects,None,Some(&signed),None).unwrap();
        assert_eq!(result.entries[0].observation_source,"signed_source_rpc");
        assert_eq!(result.entries[0].context_slot,Some(607));
    }
    #[test]
    fn opaque_and_unseen_cpi_sources_never_get_silent_safe_coverage(){
        let mut e=effects(vec![claim("transfer",3,None)]);
        e.cpi.opaque_token_instruction_count=1;
        let result=correlate_cpi_source_coverage(600,&e,None,None,None).unwrap();
        assert_eq!(result.unobserved_sources,1);
        assert!(result.unsupported_or_missing_cpi_source_semantics);
        assert_eq!(result.entries[0].account_status,"unobserved");
        assert!(!result.total_gross_token_spending_proven);
        e.cpi.captured=false;
        assert!(fetch_missing_cpi_sources(
            &Fake{calls:Cell::new(0),slot:600,values:json!([])},
            "https://example.org",600,&e,None,None).unwrap().is_none());
    }
    #[test]
    fn too_many_or_conflicting_cpi_source_programs_fail_before_network(){
        let f=Fake{calls:Cell::new(0),slot:600,values:json!([])};
        let lots=(1..=33).map(|n|claim("transfer_checked",n,Some(2)))
            .collect::<Vec<_>>();
        assert_eq!(fetch_missing_cpi_sources(&f,"https://example.org",600,
            &effects(lots),None,None).unwrap_err(),RpcError::TooLarge);
        assert_eq!(f.calls.get(),0);
        let mut second=claim("transfer_checked",3,Some(2));
        second.program_id=TOKEN_2022_PROGRAM.into();
        assert_eq!(fetch_missing_cpi_sources(&f,"https://example.org",600,
            &effects(vec![claim("transfer_checked",3,Some(2)),second]),None,None)
            .unwrap_err(),RpcError::InvalidResponse);
    }
    #[test]
    fn stale_snapshot_slot_and_malformed_response_do_not_create_claims(){
        let e=effects(vec![claim("transfer_checked",3,Some(2))]);
        let f=Fake{calls:Cell::new(0),slot:599,values:json!([data(2,9)])};
        assert_eq!(fetch_missing_cpi_sources(&f,"https://example.org",600,
            &e,None,None).unwrap_err(),RpcError::InvalidResponse);
        let f=Fake{calls:Cell::new(0),slot:600,
            values:json!([{"owner":TOKEN_PROGRAM,"executable":false,
                "data":["!!!","base64"]}])};
        assert_eq!(fetch_missing_cpi_sources(&f,"https://example.org",600,
            &e,None,None).unwrap_err(),RpcError::InvalidResponse);
    }
    #[test]
    fn supplemental_snapshot_cannot_claim_unrelated_source_or_older_bank(){
        let e=effects(vec![claim("transfer_checked",3,Some(2))]);
        let extra=CpiSourceRpcSnapshot{
            simulation_slot:600,context_slot:602,atomic_with_simulation:false,
            accounts:vec![CpiSourceAccountObservation{
                address:key(4),declared_program:TOKEN_PROGRAM.into(),
                program_matches_cpi:None,status:"missing",state:None,
            }],
            limitation:"test",
        };
        assert_eq!(correlate_cpi_source_coverage(600,&e,None,None,Some(&extra))
            .unwrap_err(),RpcError::InvalidResponse);
        let mut wrong=extra;
        wrong.accounts[0].address=key(3);
        wrong.accounts[0].declared_program=TOKEN_2022_PROGRAM.into();
        assert_eq!(correlate_cpi_source_coverage(600,&e,None,None,Some(&wrong))
            .unwrap_err(),RpcError::InvalidResponse);
        wrong.accounts[0].declared_program=TOKEN_PROGRAM.into();
        wrong.context_slot=599;
        assert_eq!(correlate_cpi_source_coverage(600,&e,None,None,Some(&wrong))
            .unwrap_err(),RpcError::InvalidResponse);
    }
    #[test]
    fn checked_fee_extension_source_is_distinguished_from_opaque_fee_flow(){
        let mut e=effects(vec![]);
        e.cpi.token_2022_extension_instruction_count=1;
        e.cpi.token_2022_extension_observations.push(Token2022ExtensionObservation{
            parent_instruction_index:2,inner_instruction_index:1,opcode:26,
            sub_opcode:Some(1),family:"transfer_fee",
            operation:"transfer_checked_with_fee",layout_checked:true,
            source_account:Some(key(3)),mint:Some(key(2)),authority:Some(key(9)),
            new_authority:None,hook_program_id:None,
            declared_amount_raw:Some("100".into()),expected_fee_raw:Some("2".into()),
            fee_basis_points:None,maximum_fee_raw:None,
        });
        let claims=cpi_source_claims(&e).unwrap();
        assert_eq!(claims.len(),1);
        assert_eq!(claims[0].operation,"transfer_checked_with_fee");
        assert_eq!(claims[0].source_account,key(3));
        assert_eq!(claims[0].declared_mint.as_deref(),Some(key(2).as_str()));
        assert!(!correlate_cpi_source_coverage(600,&e,None,None,None).unwrap()
            .unsupported_or_missing_cpi_source_semantics);
        e.cpi.token_2022_extension_observations[0].layout_checked=false;
        assert!(correlate_cpi_source_coverage(600,&e,None,None,None).unwrap()
            .unsupported_or_missing_cpi_source_semantics);
    }
}
