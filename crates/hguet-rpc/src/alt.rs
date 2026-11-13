//! Read-only Solana v0 Address Lookup Table resolution from account data.
//! All addresses are single-provider, slot-scoped advisory evidence, NOT trusted
//! authorization or consensus. Invalid owner/metadata/warmup fails closed.
use super::{checked_result, JsonRpcTransport, RpcError};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hguet_core::solana_engine::{AddressTableLookup, ParsedTransaction};
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::HashSet;

pub const ALT_PROGRAM: &str = "AddressLookupTab1e1111111111111111111111111";
const LOOKUP_META_SIZE: usize = 56;
const MAX_ALT_ENTRIES: usize = 256;

#[derive(Debug, Clone, Serialize)]
pub struct LookupResolution {
    pub context_slot: u64,
    pub table_addresses: Vec<String>,
    pub resolved_writable_accounts: Vec<String>,
    pub resolved_readonly_accounts: Vec<String>,
    pub limitation: String,
}

fn parse_account(account: &Value, slot: u64) -> Result<Vec<[u8;32]>, RpcError> {
    let v = account.as_object().ok_or(RpcError::InvalidResponse)?;
    if v.get("owner").and_then(Value::as_str) != Some(ALT_PROGRAM) ||
       v.get("executable").and_then(Value::as_bool) != Some(false) {
        return Err(RpcError::InvalidResponse);
    }
    let data = v.get("data").and_then(Value::as_array).ok_or(RpcError::InvalidResponse)?;
    if data.len()!=2 || data[1].as_str()!=Some("base64") {
        return Err(RpcError::InvalidResponse);
    }
    let base64 = data[0].as_str().ok_or(RpcError::InvalidResponse)?;
    if base64.len() > 12000 { return Err(RpcError::TooLarge); }
    let bytes = STANDARD.decode(base64).map_err(|_| RpcError::InvalidResponse)?;
    if bytes.len() < LOOKUP_META_SIZE ||
       (bytes.len()-LOOKUP_META_SIZE)%32 != 0 ||
       bytes.len() > LOOKUP_META_SIZE+MAX_ALT_ENTRIES*32 {
        return Err(RpcError::InvalidResponse);
    }
    let discriminator = u32::from_le_bytes(bytes[0..4].try_into().map_err(|_|RpcError::InvalidResponse)?);
    if discriminator != 1 { return Err(RpcError::InvalidResponse); }
    let deactivation_slot = u64::from_le_bytes(bytes[4..12].try_into().map_err(|_|RpcError::InvalidResponse)?);
    // A deactivating table MAY remain usable briefly depending on SlotHashes,
    // but we cannot prove that from a single account RPC response; fail closed.
    if deactivation_slot != u64::MAX { return Err(RpcError::InvalidResponse); }
    let last_extended_slot = u64::from_le_bytes(bytes[12..20].try_into().map_err(|_|RpcError::InvalidResponse)?);
    let last_extended_start = bytes[20] as usize;
    let count=(bytes.len()-LOOKUP_META_SIZE)/32;
    if last_extended_slot > slot || last_extended_start > count {
        return Err(RpcError::InvalidResponse);
    }
    let addresses = bytes[LOOKUP_META_SIZE..].chunks_exact(32)
        .map(|v|v.try_into().expect("exact 32-byte account")).collect::<Vec<[u8;32]>>();
    Ok(addresses)
}

fn resolve_indices(
    descriptor: &AddressTableLookup,
    addresses: &[[u8;32]],
    context_slot: u64,
    bytes: &[u8],
    result: &mut Vec<String>,
) -> Result<(), RpcError> {
    let last_extended_slot=u64::from_le_bytes(bytes[12..20].try_into().map_err(|_|RpcError::InvalidResponse)?);
    let start=bytes[20] as usize;
    // Just-added addresses are not yet usable in their extension slot.
    for i in descriptor.writable_indexes.iter().chain(descriptor.readonly_indexes.iter()) {
        let index=*i as usize;
        if index>=addresses.len() ||
           (last_extended_slot==context_slot && index>=start) {
            return Err(RpcError::InvalidResponse);
        }
    }
    for i in &descriptor.writable_indexes {
        result.push(bs58::encode(addresses[*i as usize]).into_string());
    }
    Ok(())
}

/// Call after a separate getGenesisHash verified the requested cluster.
/// Fails closed on missing/bad account, wrong owner, inactive/just-added table,
/// bad index or inconsistent provider response. Never silently treats loaded
/// addresses as signatures or substitutes network state for trusted intent.
pub fn resolve_v0_lookups<T: JsonRpcTransport>(
    transport: &T, endpoint: &str, parsed: &ParsedTransaction,
) -> Result<LookupResolution,RpcError> {
    if parsed.wire_format!="v0" || parsed.address_table_lookups.is_empty() ||
       parsed.address_table_lookups.len()>32 {
        return Err(RpcError::InvalidResponse);
    }
    let list=&parsed.address_table_lookups;
    let keys: Vec<String>=list.iter().map(|d|d.table_address.clone()).collect();
    let request=json!({
        "jsonrpc":"2.0","id":3,"method":"getMultipleAccounts",
        "params":[keys,{"encoding":"base64","commitment":"confirmed"}]
    });
    let reply=checked_result(transport.post_json(endpoint,&request)?,3)?;
    let ctx=reply.get("context").and_then(|x|x.get("slot"))
        .and_then(Value::as_u64).filter(|x|*x>0).ok_or(RpcError::InvalidResponse)?;
    let accounts=reply.get("value").and_then(Value::as_array).ok_or(RpcError::InvalidResponse)?;
    if accounts.len()!=list.len() { return Err(RpcError::InvalidResponse); }
    let mut writable=Vec::new();
    let mut readonly=Vec::new();
    // The Solana runtime concatenates writable keys from ALL tables first,
    // then readonly keys from ALL tables, NOT alternating by table.
    let mut parsed_tables=Vec::new();
    for account in accounts {
        let addresses=parse_account(account,ctx)?;
        let encoded=account["data"][0].as_str().ok_or(RpcError::InvalidResponse)?;
        let bytes=STANDARD.decode(encoded).map_err(|_|RpcError::InvalidResponse)?;
        parsed_tables.push((addresses,bytes));
    }
    for (lookup,(addresses,data)) in list.iter().zip(&parsed_tables) {
        resolve_indices(lookup,addresses,ctx,data,&mut writable)?;
    }
    for (lookup,(addresses,data)) in list.iter().zip(&parsed_tables) {
        let last_extended_slot=u64::from_le_bytes(data[12..20].try_into().map_err(|_|RpcError::InvalidResponse)?);
        let start=data[20] as usize;
        for index in &lookup.readonly_indexes {
            let n=*index as usize;
            if n>=addresses.len() || (last_extended_slot==ctx && n>=start) {
                return Err(RpcError::InvalidResponse);
            }
            readonly.push(bs58::encode(addresses[n]).into_string());
        }
    }
    if writable.len()+readonly.len()!=parsed.unresolved_lookup_addresses {
        return Err(RpcError::InvalidResponse);
    }
    let mut unique=HashSet::new();
    for address in writable.iter().chain(readonly.iter()) {
        if !unique.insert(address) { return Err(RpcError::InvalidResponse); }
    }
    Ok(LookupResolution {
        context_slot:ctx, table_addresses:list.iter().map(|v|v.table_address.clone()).collect(),
        resolved_writable_accounts:writable,
        resolved_readonly_accounts:readonly,
        limitation:"ALT keys were supplied by one RPC provider at an observed slot; this is not a pinned execution-state proof, and unseen program effects remain UNKNOWN".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::JsonRpcTransport;
    fn account(last_extended: u64, start: u8, deactivation: u64) -> Value {
        let mut data=vec![0u8;56];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        data[4..12].copy_from_slice(&deactivation.to_le_bytes());
        data[12..20].copy_from_slice(&last_extended.to_le_bytes());
        data[20]=start;
        data.extend_from_slice(&[11u8;32]);
        data.extend_from_slice(&[22u8;32]);
        json!({"owner":ALT_PROGRAM,"executable":false,"data":[STANDARD.encode(&data),"base64"]})
    }
    struct Fake { value:Value }
    impl JsonRpcTransport for Fake {
        fn post_json(&self,_endpoint:&str,request:&Value)->Result<Value,RpcError> {
            assert_eq!(request["method"],"getMultipleAccounts");
            Ok(json!({"jsonrpc":"2.0","id":3,"result":self.value}))
        }
    }
    fn sample() -> ParsedTransaction {
        use hguet_core::TransactionSignatureStatus;
        ParsedTransaction {
            wire_format:"v0".into(),transaction_bytes:200,
            transaction_sha256:"0".repeat(64),message_sha256:"1".repeat(64),
            required_signatures:1,signature_count:1,
            transaction_signature_status:TransactionSignatureStatus::Unsigned,
            static_account_count:3,static_account_keys:vec![
                bs58::encode([1u8;32]).into_string(),bs58::encode([2u8;32]).into_string(),
                "11111111111111111111111111111111".into()],total_address_count:5,
            instruction_count:1,lookup_table_count:1,unresolved_lookup_addresses:2,
            address_table_lookups:vec![AddressTableLookup{
                table_address:bs58::encode([7u8;32]).into_string(),
                writable_indexes:vec![0],readonly_indexes:vec![1]
            }],
            program_ids:vec![],compiled_top_level_instructions:vec![],system_transfers:vec![],
            declared_system_transfer_lamports:"0".into(),resource_config:None,limitations:vec![]
        }
    }
    #[test] fn valid_table_address_indexes_and_result_order() {
        let f=Fake{value:json!({"context":{"slot":500},"value":[account(499,2,u64::MAX)]})};
        let r=resolve_v0_lookups(&f,"https://rpc.example", &sample()).unwrap();
        assert_eq!(r.context_slot,500);
        assert_eq!(r.resolved_writable_accounts,vec![bs58::encode([11u8;32]).into_string()]);
        assert_eq!(r.resolved_readonly_accounts,vec![bs58::encode([22u8;32]).into_string()]);
    }
    #[test] fn reject_missing_deactivated_wrong_owner_or_warmup() {
        let f=Fake{value:json!({"context":{"slot":500},"value":[Value::Null]})};
        assert!(resolve_v0_lookups(&f,"https://rpc.example",&sample()).is_err());
        let f=Fake{value:json!({"context":{"slot":500},"value":[account(499,2,3)]})};
        assert!(resolve_v0_lookups(&f,"https://rpc.example",&sample()).is_err());
        let f=Fake{value:json!({"context":{"slot":500},"value":[account(500,0,u64::MAX)]})};
        assert!(resolve_v0_lookups(&f,"https://rpc.example",&sample()).is_err());
        let mut wrong=account(499,2,u64::MAX);
        wrong["owner"]=json!("11111111111111111111111111111111");
        let f=Fake{value:json!({"context":{"slot":500},"value":[wrong]})};
        assert!(resolve_v0_lookups(&f,"https://rpc.example",&sample()).is_err());
    }
}
