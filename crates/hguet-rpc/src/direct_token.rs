//! Decode top-level SPL Token/Token-2022 instructions directly from the
//! *original transaction message*, never from jsonParsed or simulated metadata.
//! ALT addresses have single-RPC provenance, unlike static wire account keys.
//! Byte-level declarations are NOT execution effects or a signer authorization.
use crate::{
    alt::LookupResolution,
    effects::account_addresses,
    extension_semantics::Token2022ExtensionObservation,
    token_semantics::{decode_token_cpi,is_token_program,TokenCpiDecode,TokenCpiInstruction},
    RpcError,
};
use hguet_core::ParsedTransaction;
use serde::Serialize;
use serde_json::json;

#[derive(Debug,Clone,Serialize)]
pub struct DirectTokenInstruction {
    pub instruction_index: usize,
    pub program_address_from_lookup: bool,
    pub account_addresses_from_lookup: bool,
    pub decoded: TokenCpiInstruction,
}
#[derive(Debug,Clone,Serialize)]
pub struct OpaqueDirectTokenInstruction {
    pub instruction_index: usize,
    pub program_id: String,
    pub program_address_from_lookup: bool,
    pub token_2022_extension: bool,
    /// Optional prefix classification; binary arguments may still be opaque.
    pub extension_hint: Option<Token2022ExtensionObservation>,
}
#[derive(Debug,Clone,Serialize)]
pub struct DirectTokenAnalysis {
    pub recognized: Vec<DirectTokenInstruction>,
    pub opaque: Vec<OpaqueDirectTokenInstruction>,
    pub total_token_program_instructions: usize,
    pub limitation: &'static str,
}
/// Input must be the parsed ORIGINAL wire transaction, with address lookup
/// resolution if the message uses ALT. The program ID, account indices and data
/// MUST come from the wire; a provider cannot replace them without breaking
/// this parser's input.
pub fn inspect_direct_tokens(
    parsed:&ParsedTransaction,
    lookup:Option<&LookupResolution>,
)->Result<DirectTokenAnalysis,RpcError>{
    if parsed.compiled_top_level_instructions.len()!=parsed.instruction_count ||
       parsed.program_ids.len()!=parsed.instruction_count {
        return Err(RpcError::InvalidResponse);
    }
    let addresses=account_addresses(parsed,lookup)?;
    let mut recognized=Vec::new();
    let mut opaque=Vec::new();
    let mut total=0usize;
    for (i,ix) in parsed.compiled_top_level_instructions.iter().enumerate() {
        if ix.instruction_index!=i || ix.program_index>=addresses.len() ||
           ix.account_indices.iter().any(|&index|index>=addresses.len()) {
            return Err(RpcError::InvalidResponse);
        }
        let program=&addresses[ix.program_index];
        let program_from_lookup=ix.program_index>=parsed.static_account_count;
        let accounts_from_lookup=ix.account_indices.iter()
            .any(|&index|index>=parsed.static_account_count);
        let declared=&parsed.program_ids[i];
        if !program_from_lookup && declared!=program ||
           program_from_lookup && declared!="<unresolved-ALT-program>" {
            return Err(RpcError::InvalidResponse);
        }
        if !is_token_program(program) {continue;}
        total+=1;
        let data=json!({
            "programIdIndex":ix.program_index,
            "accounts":ix.account_indices,
            "data":ix.data_base58,
        });
        let map=data.as_object().ok_or(RpcError::InvalidResponse)?;
        match decode_token_cpi(program,map,&addresses,i,0)? {
            TokenCpiDecode::Recognized(decoded)=>recognized.push(DirectTokenInstruction {
                instruction_index:i,program_address_from_lookup:program_from_lookup,
                account_addresses_from_lookup:accounts_from_lookup,decoded,
            }),
            TokenCpiDecode::Opaque {extension,observation,..}=>opaque.push(
                OpaqueDirectTokenInstruction {
                    instruction_index:i,program_id:program.clone(),
                    program_address_from_lookup:program_from_lookup,
                    token_2022_extension:extension,extension_hint:observation,
                }
            ),
        }
    }
    Ok(DirectTokenAnalysis {
        recognized,opaque,total_token_program_instructions:total,
        limitation:"Direct instruction bytes come from original wire, but ALT program/account identities may depend on one RPC; recognized operations are declarations only, not proof of signer authorization, executed transfers, gross debit, CPI effects or mint extensions",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hguet_core::{parse_transaction,solana_engine::CompiledTopLevelInstruction};
    use crate::token_semantics::{TOKEN_PROGRAM,TOKEN_2022_PROGRAM};
    fn key(n:u8)->String{bs58::encode([n;32]).into_string()}
    fn legacy(program:&str,data:&[u8],accounts:&[u8])->Vec<u8>{
        let mut wire=vec![1u8];
        wire.extend([0u8;64]);
        let keys=[
            key(1),key(2),key(3),key(4),key(5),program.into(),
        ];
        wire.extend([1,0,1,keys.len() as u8]);
        for value in keys {
            let bytes=bs58::decode(&value).into_vec().unwrap();
            wire.extend(bytes);
        }
        wire.extend([9u8;32]); // blockhash
        wire.push(1); // one instruction
        wire.push(5); // token program ID
        wire.push(accounts.len() as u8);
        wire.extend(accounts);
        wire.push(data.len() as u8);
        wire.extend(data);
        wire
    }
    #[test]
    fn raw_legacy_top_level_transfer_checked_is_direct_not_cpi(){
        let mut bytes=vec![12];
        bytes.extend(1234u64.to_le_bytes());
        bytes.push(6);
        let wire=legacy(TOKEN_PROGRAM,&bytes,&[1,3,2,4]);
        let parsed=parse_transaction(&wire).unwrap();
        assert_eq!(parsed.compiled_top_level_instructions.len(),1);
        assert_eq!(parsed.compiled_top_level_instructions[0].data_base58,
            bs58::encode(&bytes).into_string());
        let result=inspect_direct_tokens(&parsed,None).unwrap();
        assert_eq!(result.total_token_program_instructions,1);
        assert_eq!(result.opaque.len(),0);
        assert_eq!(result.recognized.len(),1);
        let ix=&result.recognized[0];
        assert_eq!(ix.instruction_index,0);
        assert!(!ix.program_address_from_lookup);
        assert_eq!(ix.decoded.operation,"transfer_checked");
        assert_eq!(ix.decoded.amount_raw.as_deref(),Some("1234"));
        assert_eq!(ix.decoded.mint.as_deref(),Some(key(4).as_str()));
        assert_eq!(ix.decoded.source_account.as_deref(),Some(key(2).as_str()));
        assert_eq!(ix.decoded.destination_account.as_deref(),Some(key(3).as_str()));
    }
    #[test]
    fn token_2022_unknown_extension_stays_opaque_direct_wire(){
        let wire=legacy(TOKEN_2022_PROGRAM,&[36,1,0,0],&[1,2]);
        let p=parse_transaction(&wire).unwrap();
        let result=inspect_direct_tokens(&p,None).unwrap();
        assert!(result.recognized.is_empty());
        assert_eq!(result.opaque.len(),1);
        assert!(result.opaque[0].token_2022_extension);
        assert_eq!(result.opaque[0].extension_hint.as_ref().unwrap().family,
            "transfer_hook");
        assert!(!result.opaque[0].extension_hint.as_ref().unwrap().layout_checked);
    }
    #[test]
    fn unsupported_and_malformed_direct_token_bytes_never_become_safe_transfer(){
        let wire=legacy(TOKEN_PROGRAM,&[12,0,1],&[1,3,2,4]);
        let p=parse_transaction(&wire).unwrap();
        let result=inspect_direct_tokens(&p,None).unwrap();
        assert!(result.recognized.is_empty());
        assert_eq!(result.opaque.len(),1);
        let mut forged=p;
        forged.compiled_top_level_instructions[0].program_index=6;
        assert_eq!(inspect_direct_tokens(&forged,None).unwrap_err(),
            RpcError::InvalidResponse);
    }
    #[test]
    fn program_index_mismatch_and_missing_compiled_table_fail_closed(){
        let p=parse_transaction(&legacy(TOKEN_PROGRAM,&[5],&[1,2])).unwrap();
        let mut no_ix=p.clone();
        no_ix.compiled_top_level_instructions.clear();
        assert_eq!(inspect_direct_tokens(&no_ix,None).unwrap_err(),RpcError::InvalidResponse);
        let mut wrong=p;
        wrong.program_ids[0]=TOKEN_2022_PROGRAM.into();
        assert_eq!(inspect_direct_tokens(&wrong,None).unwrap_err(),RpcError::InvalidResponse);
    }
    #[test]
    fn lookup_program_identity_is_labeled_rpc_resolved_not_static(){
        let mut p=parse_transaction(&legacy(TOKEN_PROGRAM,&[5],&[1,2])).unwrap();
        p.compiled_top_level_instructions=vec![CompiledTopLevelInstruction {
            instruction_index:0,program_index:6,
            account_indices:vec![1,2],data_base58:bs58::encode([5u8]).into_string(),
        }];
        p.program_ids=vec!["<unresolved-ALT-program>".into()];
        p.total_address_count=7;
        p.unresolved_lookup_addresses=1;
        let lookup=LookupResolution{
            context_slot:700,
            table_addresses:vec![key(9)],
            resolved_writable_accounts:vec![TOKEN_PROGRAM.into()],
            resolved_readonly_accounts:vec![],
            limitation:"one-provider".into(),
        };
        let out=inspect_direct_tokens(&p,Some(&lookup)).unwrap();
        assert_eq!(out.opaque.len(),0);
        assert_eq!(out.recognized.len(),1);
        assert_eq!(out.recognized[0].decoded.operation,"revoke");
        assert!(out.recognized[0].program_address_from_lookup);
        // ALT is untrusted: no program ID becomes a signed authority claim.
    }
}
