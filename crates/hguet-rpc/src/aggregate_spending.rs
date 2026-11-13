//! Advisory, deterministic token spend *evidence views*. The three views
//! (original-wire declarations, provider CPI declarations and provider net
//! losses) are NEVER added to one fabricated total. Both original and inner
//! instructions may describe overlapping economic activity; net loss can
//! hide outgoing debit with incoming credit. None proves executed gross spend.
use crate::{
    cpi_source_rpc::{cpi_source_claims,CpiSourceCoverage},
    direct_token::DirectTokenAnalysis,
    effects::SimulationEffects,
    RpcError,
};
use hguet_core::PaymentIntentPayload;
use serde::Serialize;
use std::collections::{BTreeMap,BTreeSet};

const MAX_GROUPS:usize=1024;
const MAX_CAP_MINTS:usize=16;
const MAX_CAP_SOURCES:usize=32;

#[derive(Debug,Clone,Default)]
struct ThreeViews {
    wire:u128,
    cpi:u128,
    negative_net:u128,
    wire_seen:bool,
    cpi_seen:bool,
    net_seen:bool,
}
impl ThreeViews {
    fn add(&mut self,origin:&str,amount:u128)->Result<(),RpcError>{
        let (total,seen)=match origin {
            "wire"=>(&mut self.wire,&mut self.wire_seen),
            "cpi"=>(&mut self.cpi,&mut self.cpi_seen),
            "net"=>(&mut self.negative_net,&mut self.net_seen),
            _=>return Err(RpcError::InvalidResponse),
        };
        *total=total.checked_add(amount).ok_or(RpcError::TooLarge)?;
        *seen=true;
        Ok(())
    }
}
#[derive(Debug,Clone,Serialize)]
pub struct AggregateMintView {
    pub mint:String,
    pub signed_mint_cap_raw:Option<String>,
    /// Original-wire checked direct transfer/burn and checked-fee declarations.
    pub wire_checked_debit_raw:String,
    /// Single-provider compiled token CPI checked transfer/burn/fee declarations.
    pub rpc_cpi_checked_debit_raw:String,
    /// Sum of negative complete-pair provider token-account net deltas;
    /// not gross outflow, may include accounts outside the intended payer.
    pub rpc_negative_account_net_raw:String,
    pub wire_exceeds_signed_cap:bool,
    pub rpc_cpi_exceeds_signed_cap:bool,
    pub rpc_negative_net_exceeds_signed_cap:bool,
    pub rpc_cpi_or_net_outside_signed_mint_list:bool,
}
#[derive(Debug,Clone,Serialize)]
pub struct AggregateSourceView {
    pub mint:String,
    pub source_token_account:String,
    pub signed_source_cap_raw:Option<String>,
    pub wire_checked_debit_raw:String,
    pub rpc_cpi_checked_debit_raw:String,
    pub rpc_negative_account_net_raw:String,
    pub wire_exceeds_signed_cap:bool,
    pub rpc_cpi_exceeds_signed_cap:bool,
    pub rpc_negative_net_exceeds_signed_cap:bool,
    pub rpc_cpi_or_net_outside_signed_source_list:bool,
}
#[derive(Debug,Clone,Serialize)]
pub struct AggregateTokenSpending {
    pub simulation_slot:u64,
    pub simulation_status:&'static str,
    pub signed_caps_supplied_by_verified_caller:bool,
    pub mints:Vec<AggregateMintView>,
    pub sources:Vec<AggregateSourceView>,
    pub opaque_direct_token_instructions:usize,
    pub opaque_rpc_cpi_token_instructions:usize,
    pub unattributed_direct_debit_instructions:usize,
    pub unattributed_cpi_debit_instructions:usize,
    pub incomplete_token_balance_rows:usize,
    pub missing_token_balance_snapshot:bool,
    pub cpi_source_coverage_missing_or_incomplete:bool,
    pub authority_or_nondebit_operations_observed:bool,
    pub any_signed_cap_warning:bool,
    /// Overlapping wire/CPI/net views MUST NEVER be summed.
    pub wire_cpi_and_net_amounts_never_added:bool,
    pub total_gross_token_spend_proven:bool,
    pub onchain_spend_limit_enforced:bool,
    pub execution_proven:bool,
    pub security_coverage:&'static str,
    pub limitation:&'static str,
}
fn valid_key(s:&str)->bool{
    bs58::decode(s).into_vec().map(|v|
        v.len()==32 && bs58::encode(&v).into_string()==s
    ).unwrap_or(false)
}
fn raw_u64(s:&str)->Result<u64,RpcError>{
    if s.is_empty()||s.len()>20||
       (s.len()>1&&s.starts_with('0'))||
       !s.bytes().all(|c|c.is_ascii_digit()){
        return Err(RpcError::InvalidResponse);
    }
    s.parse().map_err(|_|RpcError::InvalidResponse)
}
fn insert(
    mints:&mut BTreeMap<String,ThreeViews>,
    sources:&mut BTreeMap<(String,String),ThreeViews>,
    mint:&str,source:&str,amount:u64,origin:&str,
)->Result<(),RpcError>{
    if !valid_key(mint)||!valid_key(source){
        return Err(RpcError::InvalidResponse);
    }
    if !mints.contains_key(mint)&&mints.len()>=MAX_GROUPS {
        return Err(RpcError::TooLarge);
    }
    mints.entry(mint.to_owned()).or_default().add(origin,u128::from(amount))?;
    let key=(mint.to_owned(),source.to_owned());
    if !sources.contains_key(&key)&&sources.len()>=MAX_GROUPS {
        return Err(RpcError::TooLarge);
    }
    sources.entry(key).or_default().add(origin,u128::from(amount))?;
    Ok(())
}
fn caps(
    trusted:Option<&PaymentIntentPayload>,
)->Result<(BTreeMap<String,u64>,BTreeMap<(String,String),u64>,bool,bool),RpcError>{
    let mut mint_caps=BTreeMap::new();
    let mut source_caps=BTreeMap::new();
    let mut has_mint=false;
    let mut has_source=false;
    if let Some(intent)=trusted {
        if let Some(rows)=&intent.token_spend_limits {
            if rows.len()>MAX_CAP_MINTS{return Err(RpcError::TooLarge);}
            has_mint=true;
            for row in rows {
                if !valid_key(&row.mint) || mint_caps.insert(
                    row.mint.clone(),raw_u64(&row.max_debit_raw)?
                ).is_some() {
                    return Err(RpcError::InvalidResponse);
                }
            }
        }
        if let Some(rows)=&intent.token_source_limits {
            if rows.len()>MAX_CAP_SOURCES{return Err(RpcError::TooLarge);}
            has_source=true;
            let mut unique_sources=BTreeSet::new();
            for row in rows {
                if !valid_key(&row.mint)||!valid_key(&row.source_token_account)||
                   !valid_key(&row.authority)||
                   !unique_sources.insert(row.source_token_account.clone())||
                   source_caps.insert(
                       (row.mint.clone(),row.source_token_account.clone()),
                       raw_u64(&row.max_debit_raw)?
                   ).is_some() {
                    return Err(RpcError::InvalidResponse);
                }
            }
        }
    }
    Ok((mint_caps,source_caps,has_mint,has_source))
}
fn checked_debit(op:&str)->bool{
    matches!(op,"transfer_checked"|"burn_checked"|"transfer_checked_with_fee")
}
fn unchecked_debit(op:&str)->bool{
    matches!(op,"transfer"|"burn")
}
/// Input intent MUST be independently verified by the caller before passing
/// it in. This function is *not* a signature verifier, signer, policy enforcer
/// or an onchain gross debit calculator.
pub fn analyze_aggregate_token_spending(
    status:&str,simulation_slot:u64,direct:&DirectTokenAnalysis,
    effects:&SimulationEffects,cpi_coverage:Option<&CpiSourceCoverage>,
    verified_intent:Option<&PaymentIntentPayload>,
)->Result<AggregateTokenSpending,RpcError>{
    if status!="rpc_succeeded"||simulation_slot==0 {
        return Err(RpcError::InvalidResponse);
    }
    if direct.recognized.len()+direct.opaque.len()>64||
       direct.total_token_program_instructions!=
            direct.recognized.len()+direct.opaque.len(){
        return Err(RpcError::InvalidResponse);
    }
    if let Some(coverage)=cpi_coverage {
        if coverage.simulation_slot!=simulation_slot||
            coverage.atomic_with_simulation||coverage.authorization_proven||
            coverage.total_gross_token_spending_proven {
            return Err(RpcError::InvalidResponse);
        }
    }
    let (mint_caps,source_caps,has_mint,has_source)=caps(verified_intent)?;
    let mut mints=BTreeMap::<String,ThreeViews>::new();
    let mut sources=BTreeMap::<(String,String),ThreeViews>::new();
    let mut direct_unknown=0usize;
    let mut cpi_unknown=0usize;
    let mut opaque_direct=0usize;
    let mut authority_ops=false;
    let mut seen_wire=BTreeSet::new();
    for item in &direct.recognized {
        if !seen_wire.insert(item.instruction_index){
            return Err(RpcError::InvalidResponse);
        }
        let op=item.decoded.operation.as_str();
        if checked_debit(op){
            let mint=item.decoded.mint.as_deref().ok_or(RpcError::InvalidResponse)?;
            let source=item.decoded.source_account.as_deref()
                .ok_or(RpcError::InvalidResponse)?;
            let amount=raw_u64(item.decoded.amount_raw.as_deref()
                .ok_or(RpcError::InvalidResponse)?)?;
            insert(&mut mints,&mut sources,mint,source,amount,"wire")?;
        }else if unchecked_debit(op){
            // Unchecked token Transfer has no mint argument. Observed account
            // state is NOT allowed to backfill this original-wire declaration.
            direct_unknown+=1;
        }else{
            authority_ops=true; // approvals/authority/sync/mint, not a source debit
        }
    }
    for item in &direct.opaque {
        if !seen_wire.insert(item.instruction_index){
            return Err(RpcError::InvalidResponse);
        }
        let checked_fee=item.extension_hint.as_ref().filter(|hint|
            hint.operation=="transfer_checked_with_fee"&&hint.layout_checked);
        if let Some(hint)=checked_fee {
            let mint=hint.mint.as_deref().ok_or(RpcError::InvalidResponse)?;
            let source=hint.source_account.as_deref()
                .ok_or(RpcError::InvalidResponse)?;
            let amount=raw_u64(hint.declared_amount_raw.as_deref()
                .ok_or(RpcError::InvalidResponse)?)?;
            insert(&mut mints,&mut sources,mint,source,amount,"wire")?;
        }else{
            opaque_direct+=1;
        }
    }
    let claims=cpi_source_claims(effects)?;
    let mut seen_cpi=BTreeSet::new();
    for claim in &claims {
        if !seen_cpi.insert((claim.parent_instruction_index,
                            claim.inner_instruction_index)){
            return Err(RpcError::InvalidResponse);
        }
        if checked_debit(&claim.operation){
            let mint=claim.declared_mint.as_deref().ok_or(RpcError::InvalidResponse)?;
            let amount=raw_u64(claim.declared_raw_amount.as_deref()
                .ok_or(RpcError::InvalidResponse)?)?;
            insert(&mut mints,&mut sources,mint,&claim.source_account,amount,"cpi")?;
        }else if unchecked_debit(&claim.operation) {
            cpi_unknown+=1;
        }else{
            authority_ops=true;
        }
    }
    let mut incomplete_rows=0usize;
    let mut seen_net=BTreeSet::<String>::new();
    if let Some(rows)=&effects.token_deltas {
        if rows.len()>256{return Err(RpcError::TooLarge);}
        for row in rows {
            if !valid_key(&row.mint)||!valid_key(&row.token_account)||
               !seen_net.insert(row.token_account.clone()){
                return Err(RpcError::InvalidResponse);
            }
            if !row.complete_pair {
                incomplete_rows+=1;
                continue;
            }
            let Some(raw)=row.delta_raw_amount.as_deref() else{
                incomplete_rows+=1;
                continue;
            };
            let delta=raw.parse::<i128>().map_err(|_|RpcError::InvalidResponse)?;
            if delta<0 {
                let amount=u64::try_from(delta.unsigned_abs())
                    .map_err(|_|RpcError::InvalidResponse)?;
                insert(&mut mints,&mut sources,&row.mint,&row.token_account,amount,"net")?;
            }
        }
    }
    let missing_balances=effects.token_deltas.is_none();
    for mint in mint_caps.keys(){
        if !mints.contains_key(mint)&&mints.len()>=MAX_GROUPS{
            return Err(RpcError::TooLarge);
        }
        mints.entry(mint.clone()).or_default();
    }
    for key in source_caps.keys(){
        if !sources.contains_key(key)&&sources.len()>=MAX_GROUPS{
            return Err(RpcError::TooLarge);
        }
        sources.entry(key.clone()).or_default();
    }
    let mut any_warning=false;
    let mut mint_results=Vec::with_capacity(mints.len());
    for (mint,views) in mints {
        let cap=mint_caps.get(&mint).copied();
        let cpi_outside=has_mint&&cap.is_none()&&(views.cpi_seen||views.net_seen);
        let over=cap.is_some_and(|n|views.wire>u128::from(n));
        let cpi_over=cap.is_some_and(|n|views.cpi>u128::from(n));
        let net_over=cap.is_some_and(|n|views.negative_net>u128::from(n));
        any_warning|=over||cpi_over||net_over||cpi_outside;
        mint_results.push(AggregateMintView {
            mint,signed_mint_cap_raw:cap.map(|n|n.to_string()),
            wire_checked_debit_raw:views.wire.to_string(),
            rpc_cpi_checked_debit_raw:views.cpi.to_string(),
            rpc_negative_account_net_raw:views.negative_net.to_string(),
            wire_exceeds_signed_cap:over,
            rpc_cpi_exceeds_signed_cap:cpi_over,
            rpc_negative_net_exceeds_signed_cap:net_over,
            rpc_cpi_or_net_outside_signed_mint_list:cpi_outside,
        });
    }
    let mut source_results=Vec::with_capacity(sources.len());
    for ((mint,source),views) in sources {
        let cap=source_caps.get(&(mint.clone(),source.clone())).copied();
        let outside=has_source&&cap.is_none()&&(views.cpi_seen||views.net_seen);
        let over=cap.is_some_and(|n|views.wire>u128::from(n));
        let cpi_over=cap.is_some_and(|n|views.cpi>u128::from(n));
        let net_over=cap.is_some_and(|n|views.negative_net>u128::from(n));
        any_warning|=over||cpi_over||net_over||outside;
        source_results.push(AggregateSourceView {
            mint,source_token_account:source,
            signed_source_cap_raw:cap.map(|n|n.to_string()),
            wire_checked_debit_raw:views.wire.to_string(),
            rpc_cpi_checked_debit_raw:views.cpi.to_string(),
            rpc_negative_account_net_raw:views.negative_net.to_string(),
            wire_exceeds_signed_cap:over,rpc_cpi_exceeds_signed_cap:cpi_over,
            rpc_negative_net_exceeds_signed_cap:net_over,
            rpc_cpi_or_net_outside_signed_source_list:outside,
        });
    }
    let coverage_missing=cpi_coverage.is_none()||
        !effects.cpi.captured||
        cpi_coverage.is_some_and(|c|c.unsupported_or_missing_cpi_source_semantics||
            c.unobserved_sources>0);
    let unknown_cpi=effects.cpi.opaque_token_instruction_count+
        effects.cpi.missing_compiled_token_data_count;
    Ok(AggregateTokenSpending {
        simulation_slot,simulation_status:"rpc_succeeded",
        signed_caps_supplied_by_verified_caller:verified_intent.is_some(),
        mints:mint_results,sources:source_results,
        opaque_direct_token_instructions:opaque_direct,
        opaque_rpc_cpi_token_instructions:unknown_cpi,
        unattributed_direct_debit_instructions:direct_unknown,
        unattributed_cpi_debit_instructions:cpi_unknown,
        incomplete_token_balance_rows:incomplete_rows,
        missing_token_balance_snapshot:missing_balances,
        cpi_source_coverage_missing_or_incomplete:coverage_missing,
        authority_or_nondebit_operations_observed:authority_ops,
        any_signed_cap_warning:any_warning,
        wire_cpi_and_net_amounts_never_added:true,
        total_gross_token_spend_proven:false,
        onchain_spend_limit_enforced:false,execution_proven:false,
        security_coverage:"partial_untrusted_rpc",
        limitation:"Three separately observed views are NEVER added: original-wire direct checked declarations, single-provider compiled CPI checked declarations, and negative provider token-account net deltas can describe overlapping or compensating activity. No verified execution bank, source ownership, gross outflow, fees/hooks, CPI completeness or transaction-wide spend cap can be proven from this evidence. Signed limits are used only after caller verification; RPC overages are advisory and never ALLOW.",
    })
}
