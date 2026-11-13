//! Strict, bounded interpretation of *optional* Solana simulation metadata.
//! These are observations from one user-selected RPC, NOT independent proof of
//! execution, sender authorization, total debit, or safe signing.
//! Missing data is missing coverage, NEVER zero balance / no CPI / no tokens.
use crate::{alt::LookupResolution, extension_semantics::Token2022ExtensionObservation,
    token_semantics::{decode_token_cpi, is_token_program, TokenCpiDecode, TokenCpiInstruction}, RpcError};
use hguet_core::ParsedTransaction;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

const MAX_TOKEN_ROWS: usize = 256;
const MAX_CPI_GROUPS: usize = 64;
const MAX_CPI_ITEMS: usize = 512;

#[derive(Debug, Clone, Serialize)]
pub struct NativeBalanceDelta {
    pub account_index: usize,
    pub address: String,
    pub before_lamports: String,
    pub after_lamports: String,
    pub delta_lamports: String, // signed decimal, *never* a float
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenBalanceDelta {
    pub account_index: usize,
    pub token_account: String,
    pub mint: String,
    pub owner: Option<String>,
    pub decimals: u8,
    pub before_raw_amount: Option<String>,
    pub after_raw_amount: Option<String>,
    pub delta_raw_amount: Option<String>,
    pub complete_pair: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CpiObservation {
    pub captured: bool,
    pub group_count: Option<usize>,
    pub instruction_count: Option<usize>,
    pub invoked_program_ids: Vec<String>,
    pub token_instructions: Vec<TokenCpiInstruction>,
    pub token_2022_extension_observations: Vec<Token2022ExtensionObservation>,
    pub opaque_token_instruction_count: usize,
    pub token_2022_extension_instruction_count: usize,
    pub missing_compiled_token_data_count: usize,
    pub requires_semantic_review: bool,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SimulationEffects {
    pub lamport_deltas: Option<Vec<NativeBalanceDelta>>,
    pub token_deltas: Option<Vec<TokenBalanceDelta>>,
    pub cpi: CpiObservation,
    pub simulated_fee_lamports: Option<String>,
    pub observed_fields: Vec<String>,
    pub missing_fields: Vec<String>,
    pub warnings: Vec<String>,
    pub security_coverage: String, // "partial_untrusted_rpc" always, NEVER "safe"
}

fn valid_pubkey(value: &str) -> bool {
    bs58::decode(value).into_vec().map(|v| v.len()==32).unwrap_or(false)
}

fn account_addresses(parsed: &ParsedTransaction, resolution: Option<&LookupResolution>)
    -> Result<Vec<String>, RpcError>
{
    if parsed.static_account_keys.len()!=parsed.static_account_count {
        return Err(RpcError::InvalidResponse);
    }
    let mut keys = parsed.static_account_keys.clone();
    if parsed.unresolved_lookup_addresses>0 {
        let data = resolution.ok_or(RpcError::InvalidResponse)?;
        keys.extend(data.resolved_writable_accounts.iter().cloned());
        keys.extend(data.resolved_readonly_accounts.iter().cloned());
    }
    if keys.len()!=parsed.total_address_count || keys.iter().any(|s|!valid_pubkey(s)) {
        return Err(RpcError::InvalidResponse);
    }
    Ok(keys)
}

fn array_field<'a>(body: &'a serde_json::Map<String,Value>, field: &str)
    -> Result<Option<&'a Vec<Value>>,RpcError>
{
    match body.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => Ok(Some(items)),
        Some(_) => Err(RpcError::InvalidResponse)
    }
}

fn parse_u64_balances(items: &[Value], count: usize) -> Result<Vec<u64>, RpcError> {
    if items.len()!=count || count>256 { return Err(RpcError::InvalidResponse); }
    items.iter().map(|v|v.as_u64().ok_or(RpcError::InvalidResponse)).collect()
}

#[derive(Clone)]
struct TokenRow {
    index:usize,
    mint:String,
    owner:Option<String>,
    program:Option<String>,
    decimals:u8,
    raw:u64,
}
fn token_rows(items: &[Value], keys: &[String])
    -> Result<BTreeMap<(usize,String),TokenRow>,RpcError>
{
    if items.len()>MAX_TOKEN_ROWS { return Err(RpcError::TooLarge); }
    let mut rows=BTreeMap::new();
    let mut seen_account_indices=BTreeSet::new();
    for item in items {
        let value=item.as_object().ok_or(RpcError::InvalidResponse)?;
        let index=value.get("accountIndex").and_then(Value::as_u64)
            .and_then(|n|usize::try_from(n).ok()).ok_or(RpcError::InvalidResponse)?;
        if index>=keys.len() || !seen_account_indices.insert(index) {
            // A token account cannot have two different mints in the same
            // pre/post snapshot. Otherwise an untrusted provider could spoof
            // contradictory mint evidence at one index.
            return Err(RpcError::InvalidResponse);
        }
        let mint=value.get("mint").and_then(Value::as_str)
            .filter(|x|valid_pubkey(x)).ok_or(RpcError::InvalidResponse)?.to_owned();
        let owner=value.get("owner").and_then(Value::as_str).map(str::to_owned);
        let program=value.get("programId").and_then(Value::as_str).map(str::to_owned);
        if owner.as_deref().is_some_and(|v|!valid_pubkey(v)) ||
           program.as_deref().is_some_and(|v|!valid_pubkey(v)) {
            return Err(RpcError::InvalidResponse);
        }
        let amount=value.get("uiTokenAmount").and_then(Value::as_object)
            .ok_or(RpcError::InvalidResponse)?;
        let raw_str=amount.get("amount").and_then(Value::as_str)
            .ok_or(RpcError::InvalidResponse)?;
        if raw_str.is_empty() || raw_str.len()>20 ||
           (raw_str.len()>1 && raw_str.starts_with('0')) ||
           !raw_str.bytes().all(|b|b.is_ascii_digit()) {
            return Err(RpcError::InvalidResponse);
        }
        let raw=raw_str.parse::<u64>().map_err(|_|RpcError::InvalidResponse)?;
        let decimals=amount.get("decimals").and_then(Value::as_u64)
            .and_then(|v|u8::try_from(v).ok()).ok_or(RpcError::InvalidResponse)?;
        let row=TokenRow {index,mint:mint.clone(),owner,program,decimals,raw};
        if rows.insert((index,mint),row).is_some(){
            return Err(RpcError::InvalidResponse); // repeated balance row
        }
    }
    Ok(rows)
}
fn validate_loaded_addresses(
    body: &serde_json::Map<String,Value>,
    parsed: &ParsedTransaction,
    lookup: Option<&LookupResolution>
) -> Result<bool,RpcError> {
    let Some(value)=body.get("loadedAddresses").filter(|x|!x.is_null()) else {return Ok(false)};
    let obj=value.as_object().ok_or(RpcError::InvalidResponse)?;
    let addresses=|field:&str| -> Result<Vec<String>,RpcError> {
        let array=obj.get(field).and_then(Value::as_array).ok_or(RpcError::InvalidResponse)?;
        if array.len()>256 { return Err(RpcError::TooLarge); }
        array.iter().map(|x|x.as_str().filter(|s|valid_pubkey(s))
            .map(str::to_owned).ok_or(RpcError::InvalidResponse)).collect()
    };
    let writable=addresses("writable")?;
    let readonly=addresses("readonly")?;
    if let Some(l)=lookup {
        if writable!=l.resolved_writable_accounts || readonly!=l.resolved_readonly_accounts {
            return Err(RpcError::InvalidResponse); // provider disagrees about resolved keys
        }
    } else if parsed.unresolved_lookup_addresses>0 || !writable.is_empty() || !readonly.is_empty() {
        return Err(RpcError::InvalidResponse);
    }
    Ok(true)
}

pub fn inspect_simulation_effects(
    body: &serde_json::Map<String,Value>,
    parsed: &ParsedTransaction,
    lookup: Option<&LookupResolution>,
) -> Result<SimulationEffects,RpcError> {
    let keys=account_addresses(parsed,lookup)?;
    let mut observed=Vec::new();
    let mut missing=Vec::new();
    let mut warnings=Vec::new();
    let lamports=match (array_field(body,"preBalances")?,array_field(body,"postBalances")?) {
        (Some(before),Some(after)) => {
            let b=parse_u64_balances(before,keys.len())?;
            let a=parse_u64_balances(after,keys.len())?;
            observed.push("paired_native_balance_snapshots".into());
            Some(b.iter().zip(a.iter()).enumerate().filter_map(|(i,(before,after))| {
                if before==after {return None}
                Some(NativeBalanceDelta {
                    account_index:i,address:keys[i].clone(),
                    before_lamports:before.to_string(),after_lamports:after.to_string(),
                    delta_lamports:(i128::from(*after)-i128::from(*before)).to_string()
                })
            }).collect())
        }
        (None,None) => {
            missing.push("paired_native_balance_snapshots".into());
            None
        }
        _ => {
            missing.push("paired_native_balance_snapshots".into());
            warnings.push("Only one native balance side is present; no native delta was inferred".into());
            None
        }
    };
    let tokens=match (array_field(body,"preTokenBalances")?,array_field(body,"postTokenBalances")?) {
        (Some(before),Some(after)) => {
            let b=token_rows(before,&keys)?;
            let a=token_rows(after,&keys)?;
            observed.push("paired_token_balance_snapshots".into());
            let joined=b.keys().chain(a.keys()).cloned().collect::<BTreeSet<_>>();
            let mut result=Vec::with_capacity(joined.len());
            for (index,mint) in joined {
                let pre=b.get(&(index,mint.clone()));
                let post=a.get(&(index,mint.clone()));
                let picked=pre.or(post).ok_or(RpcError::InvalidResponse)?;
                let consistent=match (pre,post) {
                    (Some(p),Some(q)) => p.decimals==q.decimals &&
                        p.owner==q.owner && p.program==q.program &&
                        p.index==q.index && p.mint==q.mint,
                    _=>false,
                };
                if !consistent {
                    warnings.push(format!(
                        "Token balance identity/side incomplete at account index {index}; no zero-fill or exact delta inferred"
                    ));
                }
                let delta=if consistent {
                    Some((i128::from(post.expect("paired").raw)-
                          i128::from(pre.expect("paired").raw)).to_string())
                }else{None};
                result.push(TokenBalanceDelta {
                    account_index:index,token_account:keys[index].clone(),mint,
                    owner:picked.owner.clone(),decimals:picked.decimals,
                    before_raw_amount:pre.map(|r|r.raw.to_string()),
                    after_raw_amount:post.map(|r|r.raw.to_string()),
                    delta_raw_amount:delta,complete_pair:consistent,
                });
            }
            Some(result)
        }
        (None,None)=>{
            missing.push("paired_token_balance_snapshots".into());
            None
        }
        _=>{
            missing.push("paired_token_balance_snapshots".into());
            warnings.push("Only one token balance side present; token changes not inferred".into());
            None
        }
    };
    let cpi=match array_field(body,"innerInstructions")? {
        None=>{
            missing.push("cpi_recording".into());
            CpiObservation {
                captured:false,group_count:None,instruction_count:None,
                invoked_program_ids:vec![],
                token_instructions:vec![],
                token_2022_extension_observations:vec![],
                opaque_token_instruction_count:0,
                token_2022_extension_instruction_count:0,
                missing_compiled_token_data_count:0,
                requires_semantic_review:true,
                limitations:vec!["CPI recording missing; unknown effects cannot be ruled out".into()]
            }
        }
        Some(groups)=>{
            if groups.len()>MAX_CPI_GROUPS { return Err(RpcError::TooLarge); }
            let mut count=0usize;
            let mut seen=BTreeSet::new();
            let mut programs=BTreeSet::new();
            let mut token_instructions=Vec::new();
            let mut extension_observations=Vec::new();
            let mut opaque_token_instruction_count=0usize;
            let mut token_2022_extension_instruction_count=0usize;
            let mut missing_compiled_token_data_count=0usize;
            for group in groups {
                let group=group.as_object().ok_or(RpcError::InvalidResponse)?;
                let index=group.get("index").and_then(Value::as_u64)
                    .and_then(|n|usize::try_from(n).ok()).ok_or(RpcError::InvalidResponse)?;
                if index>=parsed.instruction_count || !seen.insert(index) {
                    return Err(RpcError::InvalidResponse);
                }
                let items=group.get("instructions").and_then(Value::as_array)
                    .ok_or(RpcError::InvalidResponse)?;
                count=count.checked_add(items.len()).ok_or(RpcError::TooLarge)?;
                if count>MAX_CPI_ITEMS || items.iter().any(|x|!x.is_object()) {
                    return Err(RpcError::InvalidResponse);
                }
                for (inner_index,ix) in items.iter().enumerate() {
                    let indexed=if let Some(id)=ix.get("programIdIndex") {
                        let index=id.as_u64().and_then(|n|usize::try_from(n).ok())
                            .ok_or(RpcError::InvalidResponse)?;
                        Some(keys.get(index).ok_or(RpcError::InvalidResponse)?.as_str())
                    } else { None };
                    let named=if let Some(id)=ix.get("programId") {
                        Some(id.as_str().filter(|s|valid_pubkey(s))
                            .ok_or(RpcError::InvalidResponse)?)
                    } else { None };
                    let program=match (indexed,named) {
                        (Some(i),Some(n)) if i==n=>i,
                        (Some(_),Some(_))=>return Err(RpcError::InvalidResponse),
                        (Some(i),None)=>i,
                        (None,Some(n))=>n,
                        (None,None)=>return Err(RpcError::InvalidResponse)
                    };
                    if is_token_program(program) {
                        match decode_token_cpi(
                            program, ix.as_object().ok_or(RpcError::InvalidResponse)?,
                            &keys, index, inner_index
                        )? {
                            TokenCpiDecode::Recognized(item) => token_instructions.push(item),
                            TokenCpiDecode::Opaque { extension, missing_compiled, observation } => {
                                opaque_token_instruction_count+=1;
                                if extension { token_2022_extension_instruction_count+=1; }
                                if missing_compiled { missing_compiled_token_data_count+=1; }
                                if let Some(hint)=observation { extension_observations.push(hint); }
                            }
                        }
                    }
                    programs.insert(program.to_owned());
                }
            }
            observed.push("cpi_recording".into());
            CpiObservation {
                captured:true,group_count:Some(groups.len()),instruction_count:Some(count),
                invoked_program_ids:programs.into_iter().collect(),
                token_instructions,
                token_2022_extension_observations:extension_observations,
                opaque_token_instruction_count,
                token_2022_extension_instruction_count,
                missing_compiled_token_data_count,
                requires_semantic_review:count>0,
                limitations:vec!["Selected token CPI instruction arguments are decoded from one RPC; semantics, token extensions, hooks and actual execution remain unverified".into()]
            }
        }
    };
    let fee=match body.get("fee") {
        None | Some(Value::Null)=>{
            missing.push("simulated_fee".into());None
        }
        Some(value)=>{
            let amount=value.as_u64().ok_or(RpcError::InvalidResponse)?;
            observed.push("simulated_fee".into());Some(amount.to_string())
        }
    };
    let loaded_confirmed=validate_loaded_addresses(body,parsed,lookup)?;
    if parsed.unresolved_lookup_addresses>0 {
        if loaded_confirmed {
            observed.push("loaded_addresses_confirmation".into());
        } else {
            missing.push("loaded_addresses_confirmation".into());
        }
    } else if loaded_confirmed {
        // For legacy and v1, no ALT resolution is required. Omission of this
        // optional metadata is not an incomplete security check on its own.
        observed.push("loaded_addresses_confirmation".into());
    }
    if lamports.is_none() || tokens.is_none() || !cpi.captured {
        warnings.push("Simulation evidence is incomplete; absent metadata is not proof of zero change".into());
    }
    Ok(SimulationEffects {
        lamport_deltas:lamports,token_deltas:tokens,cpi,
        simulated_fee_lamports:fee,
        observed_fields:observed,missing_fields:missing,warnings,
        security_coverage:"partial_untrusted_rpc".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use hguet_core::{TransactionSignatureStatus, SystemTransfer};
    fn tx()->ParsedTransaction {
        let a=bs58::encode([1u8;32]).into_string();
        let b=bs58::encode([2u8;32]).into_string();
        ParsedTransaction {
            wire_format:"legacy".into(), transaction_bytes:120,
            transaction_sha256:"a".repeat(64),message_sha256:"b".repeat(64),
            required_signatures:1,signature_count:1,transaction_signature_status:TransactionSignatureStatus::Unsigned,
            static_account_count:2, static_account_keys:vec![a,b],total_address_count:2,
            instruction_count:1,lookup_table_count:0,unresolved_lookup_addresses:0,
            address_table_lookups:vec![], program_ids:vec![],
            system_transfers:Vec::<SystemTransfer>::new(),declared_system_transfer_lamports:"0".into(),
            resource_config:None, limitations:vec![],
        }
    }
    fn mint()->String {bs58::encode([7u8;32]).into_string()}
    fn row(index:usize,amount:&str)->Value {
        json!({"accountIndex":index,"mint":mint(),
            "uiTokenAmount":{"amount":amount,"decimals":6}})
    }
    #[test] fn full_balances_are_exact_integers_and_cpi_is_reported() {
        let data=json!({
            "preBalances":[1000,50],"postBalances":[850,200],
            "preTokenBalances":[row(1,"100000000000")],
            "postTokenBalances":[row(1,"99999999990")],
            "innerInstructions":[{"index":0,"instructions":[{"programIdIndex":0}]}],
            "loadedAddresses":{"writable":[],"readonly":[]},"fee":5000
        });
        let result=inspect_simulation_effects(data.as_object().unwrap(),&tx(),None).unwrap();
        assert_eq!(result.lamport_deltas.as_ref().unwrap()[0].delta_lamports,"-150");
        assert_eq!(result.lamport_deltas.as_ref().unwrap()[1].delta_lamports,"150");
        assert_eq!(result.token_deltas.as_ref().unwrap()[0].delta_raw_amount.as_deref(),Some("-10"));
        assert_eq!(result.cpi.instruction_count,Some(1));
        assert!(result.missing_fields.is_empty());
        assert_eq!(result.security_coverage,"partial_untrusted_rpc");
    }
    #[test] fn missing_is_not_zero_and_no_phantom_cpi() {
        let data=json!({"preBalances":[100,200],"postTokenBalances":[row(0,"0")],
            "innerInstructions":null});
        let result=inspect_simulation_effects(data.as_object().unwrap(),&tx(),None).unwrap();
        assert!(result.lamport_deltas.is_none());
        assert!(result.token_deltas.is_none());
        assert!(!result.cpi.captured);
        assert!(result.missing_fields.contains(&"paired_token_balance_snapshots".to_owned()));
        assert!(!result.missing_fields.contains(&"loaded_addresses_confirmation".to_owned()));
    }
    #[test] fn newly_created_token_account_is_not_implicitly_zero() {
        let data=json!({"preTokenBalances":[],"postTokenBalances":[row(1,"5000")]});
        let r=inspect_simulation_effects(data.as_object().unwrap(),&tx(),None).unwrap();
        let delta=&r.token_deltas.unwrap()[0];
        assert_eq!(delta.before_raw_amount,None);
        assert_eq!(delta.after_raw_amount.as_deref(),Some("5000"));
        assert_eq!(delta.delta_raw_amount,None);
        assert!(!delta.complete_pair);
    }
    #[test] fn reject_malformed_balance_arrays_indices_and_duplicates() {
        let invalid=[
            json!({"preBalances":[10,10],"postBalances":[1]}),
            json!({"preBalances":[10,"10"],"postBalances":[1,1]}),
            json!({"preTokenBalances":[row(7,"10")],"postTokenBalances":[]}),
            json!({"preTokenBalances":[row(1,"1"),row(1,"2")],"postTokenBalances":[]}),
            json!({"preTokenBalances":[row(1,"1"),{"accountIndex":1,
                "mint":bs58::encode([99u8;32]).into_string(),
                "uiTokenAmount":{"amount":"3","decimals":6}}],
                "postTokenBalances":[]}),
            json!({"preTokenBalances":[row(1,"1.2")],"postTokenBalances":[]}),
            json!({"innerInstructions":[{"index":42,"instructions":[]}]}),
            json!({"innerInstructions":[{"index":0,"instructions":[{"programIdIndex":99}]}]}),
        ];
        for item in invalid {
            assert!(inspect_simulation_effects(item.as_object().unwrap(),&tx(),None).is_err());
        }
    }
    #[test] fn token_2022_cpi_binary_transfer_and_opaque_extension_are_separate() {
        let mut t = tx();
        t.static_account_keys = (1..=5).map(|i| bs58::encode([i; 32]).into_string()).collect();
        t.static_account_keys[0] = crate::token_semantics::TOKEN_2022_PROGRAM.into();
        t.static_account_count = 5;
        t.total_address_count = 5;
        let checked_transfer = [12u8, 232, 3, 0, 0, 0, 0, 0, 0, 6];
        let data = json!({"innerInstructions":[{"index":0,"instructions":[
            {"programIdIndex":0,"accounts":[1,2,3,4],
             "data":bs58::encode(checked_transfer).into_string()},
            {"programIdIndex":0,"accounts":[1,2],
             "data":bs58::encode([36u8,1,2]).into_string()}
        ]}]});
        let r=inspect_simulation_effects(data.as_object().unwrap(),&t,None).unwrap();
        assert!(r.cpi.captured);
        assert_eq!(r.cpi.instruction_count,Some(2));
        assert_eq!(r.cpi.token_instructions.len(),1);
        assert_eq!(r.cpi.token_instructions[0].operation,"transfer_checked");
        assert_eq!(r.cpi.token_instructions[0].amount_raw.as_deref(),Some("1000"));
        assert_eq!(r.cpi.token_instructions[0].parent_instruction_index,0);
        assert_eq!(r.cpi.token_instructions[0].inner_instruction_index,0);
        assert_eq!(r.cpi.opaque_token_instruction_count,1);
        assert_eq!(r.cpi.token_2022_extension_instruction_count,1);
        assert_eq!(r.cpi.missing_compiled_token_data_count,0);
        assert_eq!(r.security_coverage,"partial_untrusted_rpc");
    }
    #[test] fn classify_observed_fee_hook_delegate_and_confidential_extensions_without_authorization() {
        let mut t=tx();
        t.static_account_keys = (1..=5).map(|i|bs58::encode([i;32]).into_string()).collect();
        t.static_account_keys[0]=crate::token_semantics::TOKEN_2022_PROGRAM.into();
        t.static_account_count=5;
        t.total_address_count=5;
        let mut fee=vec![26,1];
        fee.extend(100u64.to_le_bytes());
        fee.push(9);
        fee.extend(4u64.to_le_bytes());
        let mut delegate=vec![35];
        delegate.extend([7u8;32]);
        let mut hook=vec![36,1];
        hook.extend([9u8;32]);
        let data=json!({"innerInstructions":[{"index":0,"instructions":[
            {"programIdIndex":0,"accounts":[1,2,3,4],
             "data":bs58::encode(&fee).into_string()},
            {"programIdIndex":0,"accounts":[1],
             "data":bs58::encode(&delegate).into_string()},
            {"programIdIndex":0,"accounts":[1,2],
             "data":bs58::encode(&hook).into_string()},
            {"programIdIndex":0,"accounts":[1,2],
             "data":bs58::encode([27u8,3,0]).into_string()}
        ]}]});
        let r=inspect_simulation_effects(data.as_object().unwrap(),&t,None).unwrap();
        assert!(r.cpi.token_instructions.is_empty());
        assert_eq!(r.cpi.opaque_token_instruction_count,4);
        assert_eq!(r.cpi.token_2022_extension_instruction_count,4);
        assert_eq!(r.cpi.token_2022_extension_observations.len(),4);
        assert_eq!(r.cpi.token_2022_extension_observations[0].family,"transfer_fee");
        assert!(r.cpi.token_2022_extension_observations[0].layout_checked);
        assert_eq!(r.cpi.token_2022_extension_observations[0].expected_fee_raw.as_deref(),Some("4"));
        assert_eq!(r.cpi.token_2022_extension_observations[1].family,"permanent_delegate");
        assert!(r.cpi.token_2022_extension_observations[1].layout_checked);
        assert_eq!(r.cpi.token_2022_extension_observations[2].family,"transfer_hook");
        assert!(r.cpi.token_2022_extension_observations[2].layout_checked);
        assert_eq!(r.cpi.token_2022_extension_observations[3].family,"confidential_transfer");
        assert!(!r.cpi.token_2022_extension_observations[3].layout_checked);
        assert_eq!(r.security_coverage,"partial_untrusted_rpc");
    }

    #[test] fn truncated_fee_extension_is_only_family_hint() {
        let mut t=tx();
        t.static_account_keys[0]=crate::token_semantics::TOKEN_2022_PROGRAM.into();
        let data=json!({"innerInstructions":[{"index":0,"instructions":[
            {"programIdIndex":0,"accounts":[0,1],
             "data":bs58::encode([26u8,1,99]).into_string()}
        ]}]});
        let r=inspect_simulation_effects(data.as_object().unwrap(),&t,None).unwrap();
        assert_eq!(r.cpi.token_2022_extension_observations.len(),1);
        assert!(!r.cpi.token_2022_extension_observations[0].layout_checked);
        assert_eq!(r.cpi.token_2022_extension_observations[0].declared_amount_raw,None);
        assert_eq!(r.cpi.token_2022_extension_observations[0].expected_fee_raw,None);
        assert_eq!(r.cpi.opaque_token_instruction_count,1);
    }
    #[test] fn provider_supplied_parsed_token_cpi_is_not_trusted_as_binary_decode() {
        let mut t = tx();
        t.static_account_keys[0] = crate::token_semantics::TOKEN_PROGRAM.into();
        let data = json!({"innerInstructions":[{"index":0,"instructions":[
            {"programIdIndex":0,"programId":crate::token_semantics::TOKEN_PROGRAM,
             "parsed":{"type":"setAuthority","info":{}}}
        ]}]});
        let r=inspect_simulation_effects(data.as_object().unwrap(),&t,None).unwrap();
        assert!(r.cpi.token_instructions.is_empty());
        assert_eq!(r.cpi.opaque_token_instruction_count,1);
        assert_eq!(r.cpi.missing_compiled_token_data_count,1);
        let invalid = json!({"innerInstructions":[{"index":0,"instructions":[
            {"programIdIndex":0,"accounts":[0,99],"data":"4NQ"}
        ]}]});
        assert!(inspect_simulation_effects(invalid.as_object().unwrap(),&t,None).is_err());
    }
    #[test] fn refuse_unverified_or_disagreeing_lookup_addresses() {
        let mut t=tx();
        t.wire_format="v0".into();
        t.total_address_count=3;
        t.unresolved_lookup_addresses=1;
        let data=json!({"loadedAddresses":{"writable":[mint()],"readonly":[]}});
        assert!(inspect_simulation_effects(data.as_object().unwrap(),&t,None).is_err());
        let lookup=LookupResolution{
            context_slot:123,table_addresses:vec![],
            resolved_writable_accounts:vec![bs58::encode([55u8;32]).into_string()],
            resolved_readonly_accounts:vec![],
            limitation:String::new(),
        };
        assert!(inspect_simulation_effects(data.as_object().unwrap(),&t,Some(&lookup)).is_err());
    }
}
