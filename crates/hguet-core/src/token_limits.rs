//! Optional, signed per-mint limits on *direct, declared* SPL token debits.
//! This module reads original wire bytes; no RPC, CPI, mint/account state,
//! signer authority or total execution spending is verified.
use crate::solana_engine::ParsedTransaction;
use crate::TokenSpendLimit;
use serde::Serialize;
use std::collections::{BTreeMap,BTreeSet};

const TOKEN_LEGACY:&str="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022:&str="TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const MAX_MINTS:usize=16;
const MAX_INSTRUCTION_BYTES:usize=512;

#[derive(Debug,Clone,Serialize)]
pub struct DeclaredMintDebit {
    pub mint:String,
    pub declared_raw:String,
    pub signed_limit_raw:String,
}
#[derive(Debug,Clone,Serialize)]
pub struct TokenSpendLimitReview {
    pub debits:Vec<DeclaredMintDebit>,
    pub decoded_direct_debit_instructions:usize,
    pub limits_enforced_on_direct_wire_declarations:bool,
    pub total_spending_proven:bool,
    pub coverage:&'static str,
    pub limitation:&'static str,
}
fn canonical_pubkey(s:&str)->bool{
    match bs58::decode(s).into_vec() {
        Ok(raw) if raw.len()==32 => bs58::encode(&raw).into_string()==s,
        _=>false,
    }
}
fn canonical_raw(s:&str)->Option<u64>{
    if s.is_empty()||s.len()>20 ||
       (s.len()>1&&s.starts_with('0'))||
       !s.bytes().all(|b|b.is_ascii_digit()){return None;}
    s.parse::<u64>().ok()
}
/// A strict lower-bound check, not an upper bound on actual gross debits.
/// To avoid confusing unknown direct opcodes with covered instructions, the
/// optional signed cap mode rejects every direct Token Program operation other
/// than TransferChecked, BurnChecked and Token-2022 TransferCheckedWithFee.
/// This is an intentionally conservative initial contract.
pub fn review_declared_token_limits(
    parsed:&ParsedTransaction,limits:&[TokenSpendLimit],
)->Result<TokenSpendLimitReview,String>{
    if limits.len()>MAX_MINTS{return Err("signed token limit list exceeds 16 mints".into());}
    let mut caps=BTreeMap::<String,u64>::new();
    let mut seen=BTreeSet::new();
    for cap in limits {
        if !canonical_pubkey(&cap.mint){
            return Err("signed token limit mint is not a canonical 32-byte Base58 pubkey".into());
        }
        let limit=canonical_raw(&cap.max_debit_raw)
            .ok_or("signed token debit maximum must be canonical u64 raw units")?;
        if !seen.insert(cap.mint.clone()){
            return Err("duplicate signed token mint cap".into());
        }
        caps.insert(cap.mint.clone(),limit);
    }
    if parsed.unresolved_lookup_addresses>0 {
        return Err("unresolved ALT addresses cannot establish signed token debit coverage".into());
    }
    if parsed.compiled_top_level_instructions.len()!=parsed.instruction_count ||
        parsed.program_ids.len()!=parsed.instruction_count {
        return Err("missing original compiled instruction bytes for signed token caps".into());
    }
    let mut totals=BTreeMap::<String,u128>::new();
    let mut count=0usize;
    for (i,ix) in parsed.compiled_top_level_instructions.iter().enumerate() {
        if ix.instruction_index!=i || ix.program_index>=parsed.static_account_keys.len()||
           ix.account_indices.iter().any(|&n|n>=parsed.static_account_keys.len()) {
            return Err("original token instruction references an invalid account".into());
        }
        let program=&parsed.static_account_keys[ix.program_index];
        if parsed.program_ids[i]!=*program {
            return Err("original program identity differs from compiled instruction".into());
        }
        if program!=TOKEN_LEGACY&&program!=TOKEN_2022 {continue;}
        if ix.data_base58.len()>1024 {
            return Err("direct token instruction data exceeds signed cap decoder bound".into());
        }
        let bytes=bs58::decode(&ix.data_base58).into_vec()
            .map_err(|_|"invalid direct token instruction Base58 data")?;
        if bytes.len()>MAX_INSTRUCTION_BYTES {
            return Err("direct token instruction data exceeds signed cap decoder bound".into());
        }
        let (mint_index,amount) = match bytes.as_slice(){
            // SPL Token TransferChecked and BurnChecked (both token programs):
            // opcode + u64 raw debit + u8 decimals; mint is account index 1.
            _ if bytes.len()==10 &&
                ((bytes[0]==12 && ix.account_indices.len()>=4) ||
                 (bytes[0]==15 && ix.account_indices.len()>=3)) => {
                let raw=u64::from_le_bytes(bytes[1..9].try_into()
                    .map_err(|_|"invalid checked token debit amount")?);
                (1,raw)
            },
            // Token-2022 TransferCheckedWithFee: opcode 26, subtype 1,
            // u64 amount, u8 decimals, u64 expected fee. Fee is *withheld*
            // from recipient; the declared source debit is the amount.
            [26,1,..] if program==TOKEN_2022 &&
                bytes.len()==19 && ix.account_indices.len()>=4 => {
                let raw=u64::from_le_bytes(bytes[2..10].try_into()
                    .map_err(|_|"invalid Token-2022 fee transfer amount")?);
                (1,raw)
            },
            _=>return Err("direct token instruction cannot be bounded by signed mint debit limits (unchecked, authority, opaque or malformed operation)".into()),
        };
        let mint_account=ix.account_indices[mint_index];
        let mint=parsed.static_account_keys.get(mint_account)
            .ok_or("direct token mint index outside message")?;
        let cap=caps.get(mint)
            .ok_or("direct token debit mint is missing from signed token_spend_limits")?;
        let new=totals.get(mint).copied().unwrap_or(0)
            .checked_add(u128::from(amount))
            .ok_or("direct token declared debit sum overflow")?;
        if new>u128::from(*cap) {
            return Err("declared direct token debits exceed signed per-mint max_debit_raw".into());
        }
        totals.insert(mint.clone(),new);
        count+=1;
    }
    Ok(TokenSpendLimitReview{
        debits:totals.into_iter().map(|(mint,amount)|DeclaredMintDebit{
            signed_limit_raw:caps[&mint].to_string(),
            mint,declared_raw:amount.to_string(),
        }).collect(),
        decoded_direct_debit_instructions:count,
        limits_enforced_on_direct_wire_declarations:true,
        total_spending_proven:false,coverage:"direct_checked_wire_declarations_only",
        limitation:"Signed caps reject uncovered direct Token Program instructions and direct declared debit overages. They do NOT cover CPI, fees, hooks, custom program side effects, wrapped SOL, account delegation or independent onchain execution; they do NOT authorize any transaction.",
    })
}

#[cfg(test)]
mod tests{
    use super::*;
    use crate::parse_transaction;
    fn k(n:u8)->String{bs58::encode([n;32]).into_string()}
    fn op(tag:u8,amount:u64)->Vec<u8>{
        let mut data=vec![tag];
        data.extend(amount.to_le_bytes());
        data.push(6);
        data
    }
    fn wire(ops:&[(Vec<u8>,Vec<u8>,bool)])->ParsedTransaction{
        let mut v=vec![1];
        v.extend([0u8;64]);
        let keys=[k(1),k(2),k(3),k(4),k(5),TOKEN_LEGACY.into(),TOKEN_2022.into()];
        v.extend([1,0,1,7]);
        for key in &keys {v.extend(bs58::decode(key).into_vec().unwrap());}
        v.extend([9u8;32]);
        v.push(ops.len() as u8);
        for (data,accounts,token_2022) in ops{
            v.push(if *token_2022 {6}else{5});
            v.push(accounts.len() as u8);
            v.extend(accounts);
            v.push(data.len() as u8);
            v.extend(data);
        }
        parse_transaction(&v).unwrap()
    }
    fn cap(mint:u8,max:&str)->TokenSpendLimit{
        TokenSpendLimit{mint:k(mint),max_debit_raw:max.into()}
    }
    #[test]
    fn checked_debits_are_summed_per_mint_without_floats_or_wraparound(){
        let tx=wire(&[
            (op(12,70),vec![1,3,2,4],false),
            (op(15,31),vec![1,3,4],false),
        ]);
        let review=review_declared_token_limits(&tx,&[cap(4,"101")]).unwrap();
        assert_eq!(review.debits.len(),1);
        assert_eq!(review.debits[0].declared_raw,"101");
        assert_eq!(review.decoded_direct_debit_instructions,2);
        assert!(!review.total_spending_proven);
        assert!(review_declared_token_limits(&tx,&[cap(4,"100")]).is_err());
        assert!(review_declared_token_limits(&tx,&[cap(5,"999")]).is_err());
    }
    #[test]
    fn safe_zero_and_full_u64_limits_are_canonical_and_bounded(){
        let empty=wire(&[]);
        assert!(review_declared_token_limits(&empty,&[cap(4,"0")]).is_ok());
        assert!(review_declared_token_limits(&empty,&[cap(4,"00")]).is_err());
        assert!(review_declared_token_limits(&empty,&[cap(4,"01")]).is_err());
        assert!(review_declared_token_limits(&empty,&[cap(4,"-1")]).is_err());
        assert!(review_declared_token_limits(&empty,&[cap(4,"18446744073709551616")]).is_err());
        assert!(review_declared_token_limits(&empty,&[cap(4,"100"),cap(4,"200")]).is_err());
        assert!(review_declared_token_limits(&empty,&[TokenSpendLimit{
            mint:"bad!".into(),max_debit_raw:"10".into(),
        }]).is_err());
        assert!(review_declared_token_limits(&empty,&[]).is_ok());
    }
    #[test]
    fn unchecked_transfer_and_approval_fail_closed_in_signed_cap_mode(){
        for tag in [3u8,4,5,6,8,9,13,14,17,99]{
            let data=if matches!(tag,3|4|8|13|14){op(tag,10)}else{vec![tag]};
            let tx=wire(&[(data,vec![1,3,2,4],false)]);
            assert!(review_declared_token_limits(&tx,&[cap(4,"100")]).is_err(),
                "unsupported opcode {tag} must not imply cap safety");
        }
        let malformed=wire(&[(vec![12,1,2,3],vec![1,3,2,4],false)]);
        assert!(review_declared_token_limits(&malformed,&[cap(4,"100")]).is_err());
    }
    #[test]
    fn token2022_transfer_checked_with_fee_debits_gross_declared_amount(){
        let mut data=vec![26,1];data.extend(123u64.to_le_bytes());
        data.push(6);data.extend(3u64.to_le_bytes());
        let tx=wire(&[(data,vec![1,3,2,4],true)]);
        assert_eq!(review_declared_token_limits(&tx,&[cap(4,"123")]).unwrap()
            .debits[0].declared_raw,"123");
        assert!(review_declared_token_limits(&tx,&[cap(4,"122")]).is_err());
    }
    #[test]
    fn over_u64_cumulative_sum_is_rejected_without_overflow(){
        let tx=wire(&[
            (op(12,u64::MAX),vec![1,3,2,4],false),
            (op(12,1),vec![1,3,2,4],false),
        ]);
        assert!(review_declared_token_limits(&tx,&[cap(4,&u64::MAX.to_string())]).is_err());
    }
}
