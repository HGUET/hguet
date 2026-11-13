//! Bounded optional Token-2022 holding-account lookup after simulation.
//! This uses a separate one-provider request at a MINIMUM slot, not the
//! execution bank. Correlation is warning evidence, never authorization.
use super::{checked_result, JsonRpcTransport, RpcError};
use crate::{
    effects::{SimulationEffects, TokenBalanceDelta},
    mint_rpc::MintRpcSnapshot,
    token_account_state::{parse_token_2022_account, Token2022AccountState, MAX_ACCOUNT_BYTES},
    token_semantics::TOKEN_2022_PROGRAM,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const MAX_ACCOUNT_QUERIES: usize=16;

#[derive(Debug, Clone, Serialize)]
pub struct TokenAccountObservation {
    pub address: String,
    pub simulation_reported_mint: String,
    /// "token_2022", "not_token_2022", or "missing"
    pub status: String,
    pub state: Option<Token2022AccountState>,
    pub mint_matches_simulation_report: Option<bool>,
    pub authority_matches_simulation_report: Option<bool>,
    /// Whether the optional mint lookup captured this exact mint as Token-2022.
    /// A false value is missing correlation, NOT a validated bad mint.
    pub matching_mint_state_observed: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct TokenAccountRpcSnapshot {
    pub context_slot: u64,
    pub simulation_slot: u64,
    pub atomic_with_simulation: bool,
    pub accounts: Vec<TokenAccountObservation>,
    pub limitation: String,
}
fn candidates(effects:&SimulationEffects)->Result<Vec<TokenBalanceDelta>,RpcError>{
    let mut unique=BTreeMap::<String,TokenBalanceDelta>::new();
    if let Some(rows)=&effects.token_deltas {
        for row in rows {
            let valid=|s:&str|bs58::decode(s).into_vec()
                .map(|v|v.len()==32).unwrap_or(false);
            if !valid(&row.token_account)||!valid(&row.mint)||
                row.owner.as_deref().is_some_and(|s|!valid(s)) {
                return Err(RpcError::InvalidResponse);
            }
            if let Some(previous)=unique.insert(row.token_account.clone(),row.clone()) {
                if previous.mint!=row.mint||previous.owner!=row.owner {
                    return Err(RpcError::InvalidResponse);
                }
            }
        }
    }
    if unique.len()>MAX_ACCOUNT_QUERIES{return Err(RpcError::TooLarge);}
    Ok(unique.into_values().collect())
}
pub fn fetch_candidate_token_accounts<T:JsonRpcTransport>(
    transport:&T, endpoint:&str, simulation_slot:u64,
    effects:&SimulationEffects, mints:Option<&MintRpcSnapshot>,
)->Result<Option<TokenAccountRpcSnapshot>,RpcError>{
    let rows=candidates(effects)?;
    if rows.is_empty(){return Ok(None);}
    if simulation_slot==0{return Err(RpcError::InvalidResponse);}
    let addresses=rows.iter().map(|r|r.token_account.clone()).collect::<Vec<_>>();
    let request=json!({"jsonrpc":"2.0","id":5,"method":"getMultipleAccounts",
        "params":[addresses,{"encoding":"base64","commitment":"confirmed",
                             "minContextSlot":simulation_slot}]
    });
    let reply=checked_result(transport.post_json(endpoint,&request)?,5)?;
    let slot=reply.get("context").and_then(|v|v.get("slot"))
        .and_then(Value::as_u64).filter(|slot|*slot>=simulation_slot)
        .ok_or(RpcError::InvalidResponse)?;
    let values=reply.get("value").and_then(Value::as_array)
        .ok_or(RpcError::InvalidResponse)?;
    if values.len()!=rows.len(){return Err(RpcError::InvalidResponse);}
    let mut accounts=Vec::with_capacity(rows.len());
    for (row,value) in rows.iter().zip(values) {
        let mut observation=TokenAccountObservation{
            address:row.token_account.clone(),
            simulation_reported_mint:row.mint.clone(),
            status:String::new(),state:None,
            mint_matches_simulation_report:None,
            authority_matches_simulation_report:None,
            matching_mint_state_observed:false,
        };
        if value.is_null() {
            observation.status="missing".into();
            accounts.push(observation);
            continue;
        }
        let obj=value.as_object().ok_or(RpcError::InvalidResponse)?;
        if obj.get("executable").and_then(Value::as_bool)!=Some(false) {
            return Err(RpcError::InvalidResponse);
        }
        let owner=obj.get("owner").and_then(Value::as_str)
            .ok_or(RpcError::InvalidResponse)?;
        if owner!=TOKEN_2022_PROGRAM {
            observation.status="not_token_2022".into();
            accounts.push(observation);
            continue;
        }
        let data=obj.get("data").and_then(Value::as_array)
            .ok_or(RpcError::InvalidResponse)?;
        if data.len()!=2||data[1].as_str()!=Some("base64") {
            return Err(RpcError::InvalidResponse);
        }
        let encoded=data[0].as_str().ok_or(RpcError::InvalidResponse)?;
        if encoded.len()>(MAX_ACCOUNT_BYTES+2)/3*4+4 {
            return Err(RpcError::TooLarge);
        }
        let bytes=STANDARD.decode(encoded).map_err(|_|RpcError::InvalidResponse)?;
        let state=parse_token_2022_account(&row.token_account,owner,&bytes)?;
        observation.mint_matches_simulation_report=Some(state.mint==row.mint);
        // Never correlate a later account to the *reported* mint when its own
        // decoded mint differs; that would create a false mint-state link.
        observation.matching_mint_state_observed=mints.is_some_and(|snapshot|
            snapshot.accounts.iter().any(|mint|
                mint.address==state.mint && mint.address==row.mint &&
                mint.status=="token_2022" && mint.state.is_some()));
        observation.authority_matches_simulation_report=
            row.owner.as_ref().map(|reported|state.token_authority==*reported);
        observation.status="token_2022".into();
        observation.state=Some(state);
        accounts.push(observation);
    }
    Ok(Some(TokenAccountRpcSnapshot{
        context_slot:slot,simulation_slot,atomic_with_simulation:false,accounts,
        limitation:"Token holding accounts were read after simulation in a separate single-provider call at a minimum context slot; holdings, owner and extension state may have changed. Only accounts named by paired token-balance metadata are examined; CPI-only accounts remain unverified".into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::effects::CpiObservation;
    use std::cell::Cell;
    struct Fake {slot:u64, response:Value,calls:Cell<usize>}
    impl JsonRpcTransport for Fake {
        fn post_json(&self,_endpoint:&str,req:&Value)->Result<Value,RpcError>{
            assert_eq!(req["method"],"getMultipleAccounts");
            assert_eq!(req["id"],5);
            assert_eq!(req["params"][1]["minContextSlot"],500);
            self.calls.set(self.calls.get()+1);
            Ok(json!({"jsonrpc":"2.0","id":5,"result":{
                "context":{"slot":self.slot},"value":self.response}}))
        }
    }
    fn effects(rows:Vec<TokenBalanceDelta>)->SimulationEffects{
        SimulationEffects{
            lamport_deltas:None,token_deltas:Some(rows),
            cpi:CpiObservation{captured:false,group_count:None,instruction_count:None,
                invoked_program_ids:vec![],token_instructions:vec![],
                token_2022_extension_observations:vec![],
                opaque_token_instruction_count:0,
                token_2022_extension_instruction_count:0,
                missing_compiled_token_data_count:0,
                requires_semantic_review:true,limitations:vec![]},
            simulated_fee_lamports:None,observed_fields:vec![],
            missing_fields:vec![],warnings:vec![],
            security_coverage:"partial_untrusted_rpc".into(),
        }
    }
    fn row(id:u8,mint:u8,owner:Option<u8>)->TokenBalanceDelta{
        TokenBalanceDelta{
            account_index:0,token_account:bs58::encode([id;32]).into_string(),
            mint:bs58::encode([mint;32]).into_string(),
            owner:owner.map(|id|bs58::encode([id;32]).into_string()),
            decimals:6,before_raw_amount:None,after_raw_amount:None,
            delta_raw_amount:None,complete_pair:false,
        }
    }
    fn account(mint:u8,owner:u8)->Value {
        let mut data=vec![0u8;166];
        data[..32].fill(mint);data[32..64].fill(owner);
        data[108]=1;data[165]=2;
        data.extend(2u16.to_le_bytes());
        data.extend(8u16.to_le_bytes());
        data.extend(42u64.to_le_bytes());
        json!({"owner":TOKEN_2022_PROGRAM,"executable":false,
            "data":[STANDARD.encode(data),"base64"]})
    }
    #[test]
    fn token_account_mint_and_owner_correlate_without_atomic_claim(){
        let fake=Fake{slot:501,response:json!([account(2,3)]),calls:Cell::new(0)};
        let r=fetch_candidate_token_accounts(&fake,"https://example.org",500,
            &effects(vec![row(1,2,Some(3))]),None).unwrap().unwrap();
        assert_eq!(fake.calls.get(),1);
        assert_eq!(r.accounts.len(),1);
        assert_eq!(r.context_slot,501);
        assert!(!r.atomic_with_simulation);
        assert_eq!(r.accounts[0].mint_matches_simulation_report,Some(true));
        assert_eq!(r.accounts[0].authority_matches_simulation_report,Some(true));
        assert!(!r.accounts[0].matching_mint_state_observed);
        assert_eq!(r.accounts[0].state.as_ref().unwrap().transfer_fee_withheld_raw.as_deref(),Some("42"));
    }
    #[test]
    fn later_slot_mint_and_authority_mismatch_are_evidence_not_authorization(){
        let fake=Fake{slot:600,response:json!([account(4,5)]),calls:Cell::new(0)};
        let r=fetch_candidate_token_accounts(&fake,"https://example.org",500,
            &effects(vec![row(1,2,Some(3))]),None).unwrap().unwrap();
        assert_eq!(r.accounts[0].mint_matches_simulation_report,Some(false));
        assert_eq!(r.accounts[0].authority_matches_simulation_report,Some(false));
        assert_eq!(r.accounts[0].status,"token_2022");
    }
    #[test]
    fn missing_and_non_token2022_accounts_are_not_decoded_as_token2022(){
        let f=Fake{slot:500,response:json!([null,{"owner":"11111111111111111111111111111111",
            "executable":false}]),calls:Cell::new(0)};
        let r=fetch_candidate_token_accounts(&f,"https://example.org",500,
            &effects(vec![row(1,2,None),row(3,4,None)]),None).unwrap().unwrap();
        assert_eq!(r.accounts[0].status,"missing");
        assert_eq!(r.accounts[1].status,"not_token_2022");
        assert!(r.accounts.iter().all(|a|a.state.is_none()));
    }
    #[test]
    fn invalid_response_or_old_slot_rejected_and_no_extra_rpc_for_no_rows(){
        let key=row(1,2,None);
        let f=Fake{slot:499,response:json!([null]),calls:Cell::new(0)};
        assert_eq!(fetch_candidate_token_accounts(&f,"https://example.org",500,
            &effects(vec![key.clone()]),None).unwrap_err(),RpcError::InvalidResponse);
        let f=Fake{slot:500,response:json!([{"owner":TOKEN_2022_PROGRAM,
            "executable":false,"data":["BAD?!","base64"]}]),calls:Cell::new(0)};
        assert_eq!(fetch_candidate_token_accounts(&f,"https://example.org",500,
            &effects(vec![key]),None).unwrap_err(),RpcError::InvalidResponse);
        let f=Fake{slot:500,response:json!([]),calls:Cell::new(0)};
        assert!(fetch_candidate_token_accounts(&f,"https://example.org",500,
            &effects(vec![]),None).unwrap().is_none());
        assert_eq!(f.calls.get(),0);
    }
    #[test]
    fn excessive_or_conflicting_candidates_are_rejected_before_network(){
        let f=Fake{slot:500,response:json!([]),calls:Cell::new(0)};
        let too_many=(1..=17).map(|id|row(id,20,None)).collect::<Vec<_>>();
        assert_eq!(fetch_candidate_token_accounts(&f,"https://example.org",500,
            &effects(too_many),None).unwrap_err(),RpcError::TooLarge);
        let same_address_two_mints=vec![row(1,2,None),row(1,3,None)];
        assert_eq!(fetch_candidate_token_accounts(&f,"https://example.org",500,
            &effects(same_address_two_mints),None).unwrap_err(),RpcError::InvalidResponse);
        assert_eq!(f.calls.get(),0);
    }
}
