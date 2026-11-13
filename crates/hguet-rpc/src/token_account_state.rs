//! Bounded Token-2022 token ACCOUNT (not mint) decoding.
//! An extended account has base 165 bytes, account_type=2 at 165 and TLV
//! from 166. A 165-byte legacy-layout account has no extension evidence.
//! All data is from a user-selected single provider and never authorizes spend.
use crate::{mint_state::extension_family, token_semantics::{TOKEN_PROGRAM, TOKEN_2022_PROGRAM}, RpcError};
use serde::Serialize;
use std::collections::BTreeSet;

const BASE: usize = 165;
const TLV_START: usize = 166;
pub(crate) const MAX_ACCOUNT_BYTES: usize = 16_384;
const MAX_EXTENSIONS: usize = 64;

#[derive(Debug, Clone, Serialize)]
pub struct TokenAccountExtension {
    pub type_id: u16,
    pub family: &'static str,
    pub payload_bytes: usize,
    pub layout_checked: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct Token2022AccountState {
    pub token_account: String,
    pub mint: String,
    pub token_authority: String,
    pub amount_raw: String,
    pub delegate: Option<String>,
    pub delegated_amount_raw: String,
    /// "initialized" or "frozen"; uninitialized accounts are rejected.
    pub account_state: &'static str,
    pub native_reserve_lamports: Option<String>,
    pub close_authority: Option<String>,
    pub transfer_fee_withheld_raw: Option<String>,
    pub requires_incoming_memo: Option<bool>,
    pub cpi_guard_locked: Option<bool>,
    pub transfer_hook_transferring: Option<bool>,
    pub immutable_owner: bool,
    pub non_transferable_account: bool,
    pub confidential_extension_present: bool,
    pub opaque_extension_count: usize,
    pub unknown_extension_count: usize,
    pub extensions: Vec<TokenAccountExtension>,
    pub limitation: String,
}
fn u64_le(data:&[u8],at:usize)->Result<u64,RpcError>{
    let raw=data.get(at..at+8).ok_or(RpcError::InvalidResponse)?;
    Ok(u64::from_le_bytes(raw.try_into().map_err(|_|RpcError::InvalidResponse)?))
}
fn coption_key(data:&[u8],at:usize)->Result<Option<String>,RpcError>{
    let bytes=data.get(at..at+36).ok_or(RpcError::InvalidResponse)?;
    let tag=u32::from_le_bytes(bytes[..4].try_into().map_err(|_|RpcError::InvalidResponse)?);
    match tag {
        0 => Ok(None),
        1 => Ok(Some(bs58::encode(&bytes[4..]).into_string())),
        _ => Err(RpcError::InvalidResponse)
    }
}
fn coption_native(data:&[u8],at:usize)->Result<Option<String>,RpcError>{
    let bytes=data.get(at..at+12).ok_or(RpcError::InvalidResponse)?;
    let tag=u32::from_le_bytes(bytes[..4].try_into().map_err(|_|RpcError::InvalidResponse)?);
    match tag {
        0 => Ok(None),
        1 => Ok(Some(u64_le(bytes,4)?.to_string())),
        _ => Err(RpcError::InvalidResponse)
    }
}
fn bool_payload(data:&[u8])->Result<bool,RpcError>{
    match data {
        [0] => Ok(false),
        [1] => Ok(true),
        _ => Err(RpcError::InvalidResponse),
    }
}
pub(crate) fn parse_token_2022_account(
    token_account:&str, owner_program:&str, bytes:&[u8],
)->Result<Token2022AccountState,RpcError>{
    if owner_program!=TOKEN_2022_PROGRAM && owner_program!=TOKEN_PROGRAM {
        return Err(RpcError::InvalidResponse);
    }
    if bytes.len()>MAX_ACCOUNT_BYTES {return Err(RpcError::TooLarge);}
    // Legacy SPL Token account data is *exactly* 165 bytes. Only Token-2022
    // may carry the account type and TLV suffix.
    if owner_program==TOKEN_PROGRAM && bytes.len()!=BASE {
        return Err(RpcError::InvalidResponse);
    }
    if bytes.len()!=BASE && bytes.len()<TLV_START {return Err(RpcError::InvalidResponse);}
    let status=match bytes[108] {
        1=>"initialized",
        2=>"frozen",
        _=>return Err(RpcError::InvalidResponse),
    };
    let mut out=Token2022AccountState{
        token_account:token_account.into(),
        mint:bs58::encode(&bytes[0..32]).into_string(),
        token_authority:bs58::encode(&bytes[32..64]).into_string(),
        amount_raw:u64_le(bytes,64)?.to_string(),
        delegate:coption_key(bytes,72)?,
        delegated_amount_raw:u64_le(bytes,121)?.to_string(),
        account_state:status,
        native_reserve_lamports:coption_native(bytes,109)?,
        close_authority:coption_key(bytes,129)?,
        transfer_fee_withheld_raw:None,
        requires_incoming_memo:None,
        cpi_guard_locked:None,
        transfer_hook_transferring:None,
        immutable_owner:false,
        non_transferable_account:false,
        confidential_extension_present:false,
        opaque_extension_count:0,
        unknown_extension_count:0,
        extensions:vec![],
        limitation:"Token account state from a separate, single-provider RPC slot, not a pre/post simulation proof or customer authorization".into(),
    };
    if bytes.len()==BASE{return Ok(out);}
    if bytes[BASE]!=2{return Err(RpcError::InvalidResponse);}
    let mut seen=BTreeSet::new();
    let mut at=TLV_START;
    while at<bytes.len() {
        let remaining=&bytes[at..];
        if remaining.iter().all(|b|*b==0) {break;}
        if remaining.len()<4{return Err(RpcError::InvalidResponse);}
        let ty=u16::from_le_bytes([bytes[at],bytes[at+1]]);
        let size=usize::from(u16::from_le_bytes([bytes[at+2],bytes[at+3]]));
        if ty==0 || !seen.insert(ty) || out.extensions.len()>=MAX_EXTENSIONS {
            return Err(RpcError::InvalidResponse);
        }
        let start=at+4;
        let end=start.checked_add(size).ok_or(RpcError::TooLarge)?;
        let data=bytes.get(start..end).ok_or(RpcError::InvalidResponse)?;
        // A TokenAccount must never be interpreted as a mint TLV inventory.
        if matches!(ty,1|3|4|6|9|10|12|14|16|18|19|20|21|22|23|24|25|26|28) {
            return Err(RpcError::InvalidResponse);
        }
        let checked=match ty {
            2=>{
                if data.len()!=8{return Err(RpcError::InvalidResponse);}
                out.transfer_fee_withheld_raw=Some(u64_le(data,0)?.to_string());
                true
            }
            7=>{
                if !data.is_empty(){return Err(RpcError::InvalidResponse);}
                out.immutable_owner=true;
                true
            }
            8=>{
                out.requires_incoming_memo=Some(bool_payload(data)?);
                true
            }
            11=>{
                out.cpi_guard_locked=Some(bool_payload(data)?);
                true
            }
            13=>{
                if !data.is_empty(){return Err(RpcError::InvalidResponse);}
                out.non_transferable_account=true;
                true
            }
            15=>{
                out.transfer_hook_transferring=Some(bool_payload(data)?);
                true
            }
            _=>false,
        };
        if matches!(ty,5|17){out.confidential_extension_present=true;}
        if !checked{out.opaque_extension_count+=1;}
        if extension_family(ty)=="unknown_extension"{out.unknown_extension_count+=1;}
        out.extensions.push(TokenAccountExtension{
            type_id:ty,family:extension_family(ty),payload_bytes:data.len(),layout_checked:checked
        });
        at=end;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn account()->Vec<u8>{
        let mut v=vec![0u8;166];
        v[0..32].fill(2);
        v[32..64].fill(3);
        v[64..72].copy_from_slice(&100u64.to_le_bytes());
        v[108]=1;
        v[165]=2;
        v
    }
    fn entry(buf:&mut Vec<u8>,ty:u16,data:&[u8]){
        buf.extend_from_slice(&ty.to_le_bytes());
        buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
        buf.extend_from_slice(data);
    }
    fn parse(bytes:&[u8])->Result<Token2022AccountState,RpcError>{
        parse_token_2022_account("token-account",TOKEN_2022_PROGRAM,bytes)
    }
    #[test]
    fn legacy_token_accounts_share_strict_165_byte_base_without_tlv(){
        let mut base=account();
        base.truncate(BASE);
        let legacy=parse_token_2022_account("legacy-address",TOKEN_PROGRAM,&base).unwrap();
        assert_eq!(legacy.token_account,"legacy-address");
        assert_eq!(legacy.account_state,"initialized");
        assert_eq!(legacy.amount_raw,"100");
        assert!(legacy.extensions.is_empty());
        assert!(parse_token_2022_account("legacy-address",TOKEN_PROGRAM,&account()).is_err());
        assert!(parse_token_2022_account("legacy-address","11111111111111111111111111111111",&base).is_err());
        let mut invalid=base;
        invalid[108]=0;
        assert_eq!(parse_token_2022_account("legacy-address",TOKEN_PROGRAM,&invalid).unwrap_err(),
            RpcError::InvalidResponse);
    }
    #[test]
    fn full_account_base_is_not_mint_and_reports_authorities_exactly(){
        let mut buf=account();
        buf[72..76].copy_from_slice(&1u32.to_le_bytes());
        buf[76..108].fill(4);
        buf[121..129].copy_from_slice(&90u64.to_le_bytes());
        buf[129..133].copy_from_slice(&1u32.to_le_bytes());
        buf[133..165].fill(5);
        buf[108]=2;
        let r=parse(&buf).unwrap();
        assert_eq!(r.account_state,"frozen");
        assert_eq!(r.amount_raw,"100");
        assert_eq!(r.delegated_amount_raw,"90");
        assert_eq!(r.delegate,Some(bs58::encode([4u8;32]).into_string()));
        assert_eq!(r.close_authority,Some(bs58::encode([5u8;32]).into_string()));
        assert_eq!(r.mint,bs58::encode([2u8;32]).into_string());
        assert_eq!(r.token_authority,bs58::encode([3u8;32]).into_string());
    }
    #[test]
    fn parse_transfer_fee_memo_cpi_guard_hook_and_account_extensions(){
        let mut buf=account();
        entry(&mut buf,2,&77u64.to_le_bytes());
        entry(&mut buf,7,&[]);
        entry(&mut buf,8,&[1]);
        entry(&mut buf,11,&[1]);
        entry(&mut buf,13,&[]);
        entry(&mut buf,15,&[0]);
        entry(&mut buf,5,&[9,8,7]); // confidential data remains opaque
        let r=parse(&buf).unwrap();
        assert_eq!(r.extensions.len(),7);
        assert_eq!(r.transfer_fee_withheld_raw.as_deref(),Some("77"));
        assert_eq!(r.requires_incoming_memo,Some(true));
        assert_eq!(r.cpi_guard_locked,Some(true));
        assert_eq!(r.transfer_hook_transferring,Some(false));
        assert!(r.immutable_owner);
        assert!(r.non_transferable_account);
        assert!(r.confidential_extension_present);
        assert_eq!(r.opaque_extension_count,1);
    }
    #[test]
    fn invalid_state_tags_account_type_mint_extension_and_duplicate_tlv_fail(){
        let mut bad=account();bad[108]=0;
        assert_eq!(parse(&bad).unwrap_err(),RpcError::InvalidResponse);
        bad=account();bad[165]=1;
        assert_eq!(parse(&bad).unwrap_err(),RpcError::InvalidResponse);
        bad=account();entry(&mut bad,14,&[1]);
        assert_eq!(parse(&bad).unwrap_err(),RpcError::InvalidResponse);
        bad=account();entry(&mut bad,8,&[1]);entry(&mut bad,8,&[0]);
        assert_eq!(parse(&bad).unwrap_err(),RpcError::InvalidResponse);
        bad=account();bad[72..76].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(parse(&bad).unwrap_err(),RpcError::InvalidResponse);
        bad=account();bad[109..113].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(parse(&bad).unwrap_err(),RpcError::InvalidResponse);
        bad=account();bad[129..133].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(parse(&bad).unwrap_err(),RpcError::InvalidResponse);
    }
    #[test]
    fn truncated_or_bad_boolean_and_opaque_new_extensions_never_pass_as_safety(){
        let mut bad=account();entry(&mut bad,8,&[2]);
        assert_eq!(parse(&bad).unwrap_err(),RpcError::InvalidResponse);
        bad=account();entry(&mut bad,2,&[1,2,3]);
        assert_eq!(parse(&bad).unwrap_err(),RpcError::InvalidResponse);
        bad=account();bad.extend([8,0,2,0,1]);
        assert_eq!(parse(&bad).unwrap_err(),RpcError::InvalidResponse);
        bad=account();entry(&mut bad,65000,&[1,2,3]);
        let r=parse(&bad).unwrap();
        assert_eq!(r.unknown_extension_count,1);
        assert_eq!(r.opaque_extension_count,1);
        assert_eq!(r.extensions[0].family,"unknown_extension");
        assert!(!r.extensions[0].layout_checked);
    }
    #[test]
    fn base_165_byte_account_has_no_tlv_and_never_invents_flags(){
        let buf=account();
        let r=parse(&buf[..165]).unwrap();
        assert!(r.extensions.is_empty());
        assert_eq!(r.cpi_guard_locked,None);
        assert_eq!(r.transfer_fee_withheld_raw,None);
        assert_eq!(r.requires_incoming_memo,None);
        assert!(parse_token_2022_account("a","not-token2022",&buf).is_err());
    }
}
