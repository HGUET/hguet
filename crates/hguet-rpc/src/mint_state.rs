//! Strict bounded parsing of one provider's Token-2022 mint account bytes.
//! The 82-byte mint base is padded to offset 165, AccountType=1 at 165,
//! and TLV data begins at 166 (never at offset 82).
//! This is RPC-supplied *advisory* state, not an atomic simulation snapshot.
//! Extension type IDs: spl-token-2022-interface::extension::ExtensionType.
use crate::{token_semantics::TOKEN_2022_PROGRAM, RpcError};
use serde::Serialize;
use std::collections::BTreeSet;

const BASE_MINT_SIZE: usize = 82;
const TYPE_OFFSET: usize = 165;
const TLV_OFFSET: usize = 166;
pub(crate) const MAX_MINT_BYTES: usize = 16_384;
const MAX_EXTENSIONS: usize = 64;

#[derive(Debug, Clone, Serialize)]
pub struct MintExtension {
    pub type_id: u16,
    pub family: &'static str,
    pub payload_bytes: usize,
    /// Only specific known layouts are decoded; other payloads stay opaque.
    pub layout_checked: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct FeeSchedule {
    pub epoch: String,
    pub maximum_fee_raw: String,
    pub basis_points: u16,
}
#[derive(Debug, Clone, Serialize)]
pub struct MintTransferFeeConfig {
    pub config_authority: Option<String>,
    pub withdraw_withheld_authority: Option<String>,
    pub withheld_raw: String,
    pub older: FeeSchedule,
    pub newer: FeeSchedule,
}
#[derive(Debug, Clone, Serialize)]
pub struct MintTransferHook {
    pub update_authority: Option<String>,
    pub program_id: Option<String>,
}
#[derive(Debug, Clone, Serialize)]
pub struct Token2022MintState {
    pub mint_address: String,
    pub supply_raw: String,
    pub decimals: u8,
    pub extensions: Vec<MintExtension>,
    pub fee_config: Option<MintTransferFeeConfig>,
    pub hook: Option<MintTransferHook>,
    pub permanent_delegate: Option<String>,
    pub unknown_extension_count: usize,
    pub confidential_extension_present: bool,
    pub limitations: String,
}

pub(crate) fn extension_family(ty: u16) -> &'static str {
    match ty {
        1 => "transfer_fee_config",
        2 => "transfer_fee_amount",
        3 => "mint_close_authority",
        4 => "confidential_transfer_mint",
        5 => "confidential_transfer_account",
        6 => "default_account_state",
        7 => "immutable_owner",
        8 => "memo_transfer",
        9 => "non_transferable",
        10 => "interest_bearing",
        11 => "cpi_guard",
        12 => "permanent_delegate",
        13 => "non_transferable_account",
        14 => "transfer_hook",
        15 => "transfer_hook_account",
        16 => "confidential_transfer_fee_config",
        17 => "confidential_transfer_fee_amount",
        18 => "metadata_pointer",
        19 => "token_metadata",
        20 => "group_pointer",
        21 => "token_group",
        22 => "group_member_pointer",
        23 => "token_group_member",
        24 => "confidential_mint_burn",
        25 => "scaled_ui_amount",
        26 => "pausable",
        27 => "pausable_account",
        28 => "permissioned_burn",
        _ => "unknown_extension",
    }
}
fn u64_at(data: &[u8], i: usize) -> Result<u64, RpcError> {
    let bytes = data.get(i..i + 8).ok_or(RpcError::InvalidResponse)?;
    Ok(u64::from_le_bytes(
        bytes.try_into().map_err(|_| RpcError::InvalidResponse)?,
    ))
}
fn u16_at(data: &[u8], i: usize) -> Result<u16, RpcError> {
    let bytes = data.get(i..i + 2).ok_or(RpcError::InvalidResponse)?;
    Ok(u16::from_le_bytes(
        bytes.try_into().map_err(|_| RpcError::InvalidResponse)?,
    ))
}
fn optional_key(bytes: &[u8]) -> Result<Option<String>, RpcError> {
    if bytes.len() != 32 {
        return Err(RpcError::InvalidResponse);
    }
    if bytes.iter().all(|x| *x == 0) {
        return Ok(None);
    }
    Ok(Some(bs58::encode(bytes).into_string()))
}
fn fee_schedule(data: &[u8], offset: usize) -> Result<FeeSchedule, RpcError> {
    let result = FeeSchedule {
        epoch: u64_at(data, offset)?.to_string(),
        maximum_fee_raw: u64_at(data, offset + 8)?.to_string(),
        basis_points: u16_at(data, offset + 16)?,
    };
    if result.basis_points > 10_000 {
        return Err(RpcError::InvalidResponse);
    }
    Ok(result)
}
fn valid_base_mint(data: &[u8]) -> Result<(), RpcError> {
    // COption<Pubkey> uses a 4-byte LE discriminant at offsets 0 and 46.
    // Mint::is_initialized must be true, and 82..165 is mandatory zero padding.
    for at in [0, 46] {
        let tag = u32::from_le_bytes(
            data.get(at..at + 4)
                .ok_or(RpcError::InvalidResponse)?
                .try_into()
                .map_err(|_| RpcError::InvalidResponse)?,
        );
        if tag > 1 {
            return Err(RpcError::InvalidResponse);
        }
    }
    if data.get(45) != Some(&1) {
        return Err(RpcError::InvalidResponse);
    }
    Ok(())
}

pub(crate) fn parse_token_2022_mint(
    mint_address: &str,
    owner_program: &str,
    data: &[u8],
) -> Result<Token2022MintState, RpcError> {
    if owner_program != TOKEN_2022_PROGRAM {
        return Err(RpcError::InvalidResponse);
    }
    if data.len() > MAX_MINT_BYTES {
        return Err(RpcError::TooLarge);
    }
    if data.len() != BASE_MINT_SIZE && data.len() < TLV_OFFSET {
        return Err(RpcError::InvalidResponse);
    }
    valid_base_mint(data)?;
    let mut result=Token2022MintState {
        mint_address:mint_address.into(),supply_raw:u64_at(data,36)?.to_string(),
        decimals:data[44],extensions:Vec::new(),fee_config:None,hook:None,
        permanent_delegate:None,unknown_extension_count:0,
        confidential_extension_present:false,
        limitations:"One untrusted provider at a non-atomic slot; no proof of final state, hook execution, future settings, or approval to spend".into(),
    };
    if data.len() == BASE_MINT_SIZE {
        return Ok(result);
    }
    if data[BASE_MINT_SIZE..TYPE_OFFSET]
        .iter()
        .any(|byte| *byte != 0)
        || data[TYPE_OFFSET] != 1
    {
        return Err(RpcError::InvalidResponse);
    }
    let mut pos = TLV_OFFSET;
    let mut seen = BTreeSet::new();
    while pos < data.len() {
        let remainder = &data[pos..];
        if remainder.iter().all(|v| *v == 0) {
            break;
        }
        if remainder.len() < 4 {
            return Err(RpcError::InvalidResponse);
        }
        let ty = u16_at(data, pos)?;
        let len = usize::from(u16_at(data, pos + 2)?);
        if ty == 0 || !seen.insert(ty) || result.extensions.len() >= MAX_EXTENSIONS {
            return Err(RpcError::InvalidResponse);
        }
        let start = pos.checked_add(4).ok_or(RpcError::TooLarge)?;
        let end = start.checked_add(len).ok_or(RpcError::TooLarge)?;
        let payload = data.get(start..end).ok_or(RpcError::InvalidResponse)?;
        // A mint must not contain known account-only extensions.
        if matches!(ty, 2 | 5 | 7 | 8 | 11 | 13 | 15 | 17 | 27) {
            return Err(RpcError::InvalidResponse);
        }
        let mut checked = false;
        match ty {
            1 => {
                // ConfigAuthority32 | WithdrawAuthority32 | Withheld8
                // Older {Epoch8,Max8,Bps2} | Newer {Epoch8,Max8,Bps2}
                if payload.len() != 108 {
                    return Err(RpcError::InvalidResponse);
                }
                result.fee_config = Some(MintTransferFeeConfig {
                    config_authority: optional_key(&payload[0..32])?,
                    withdraw_withheld_authority: optional_key(&payload[32..64])?,
                    withheld_raw: u64_at(payload, 64)?.to_string(),
                    older: fee_schedule(payload, 72)?,
                    newer: fee_schedule(payload, 90)?,
                });
                checked = true;
            }
            12 => {
                if payload.len() != 32 {
                    return Err(RpcError::InvalidResponse);
                }
                result.permanent_delegate = optional_key(payload)?;
                checked = true;
            }
            14 => {
                if payload.len() != 64 {
                    return Err(RpcError::InvalidResponse);
                }
                result.hook = Some(MintTransferHook {
                    update_authority: optional_key(&payload[..32])?,
                    program_id: optional_key(&payload[32..])?,
                });
                checked = true;
            }
            9 => {
                if !payload.is_empty() {
                    return Err(RpcError::InvalidResponse);
                }
                checked = true;
            }
            _ => {}
        }
        if matches!(ty, 4 | 16 | 24) {
            result.confidential_extension_present = true;
        }
        if extension_family(ty) == "unknown_extension" {
            result.unknown_extension_count += 1;
        }
        result.extensions.push(MintExtension {
            type_id: ty,
            family: extension_family(ty),
            payload_bytes: payload.len(),
            layout_checked: checked,
        });
        pos = end;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn mint() -> Vec<u8> {
        let mut v = vec![0u8; 166];
        v[45] = 1;
        v[165] = 1;
        v
    }
    fn entry(v: &mut Vec<u8>, ty: u16, payload: &[u8]) {
        v.extend_from_slice(&ty.to_le_bytes());
        v.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        v.extend_from_slice(payload);
    }
    fn parse(v: &[u8]) -> Result<Token2022MintState, RpcError> {
        parse_token_2022_mint("mint", TOKEN_2022_PROGRAM, v)
    }
    #[test]
    fn real_tlv_offset_is_166_not_83() {
        let mut data = mint();
        entry(&mut data, 9, &[]);
        let result = parse(&data).unwrap();
        assert_eq!(result.extensions.len(), 1);
        assert_eq!(result.extensions[0].type_id, 9);
        assert_eq!(result.extensions[0].family, "non_transferable");
        let mut invalid = data.clone();
        invalid[82] = 9;
        assert_eq!(parse(&invalid).unwrap_err(), RpcError::InvalidResponse);
        invalid = data;
        invalid[165] = 2;
        assert_eq!(parse(&invalid).unwrap_err(), RpcError::InvalidResponse);
    }
    #[test]
    fn parse_fee_config_hook_delegate_and_confidential_risks() {
        let mut data = mint();
        let mut fee = vec![0u8; 108];
        fee[72..80].copy_from_slice(&100u64.to_le_bytes());
        fee[80..88].copy_from_slice(&200u64.to_le_bytes());
        fee[88..90].copy_from_slice(&300u16.to_le_bytes());
        fee[90..98].copy_from_slice(&101u64.to_le_bytes());
        fee[98..106].copy_from_slice(&400u64.to_le_bytes());
        fee[106..108].copy_from_slice(&500u16.to_le_bytes());
        entry(&mut data, 1, &fee);
        entry(&mut data, 12, &[8u8; 32]);
        let mut hook = vec![0u8; 64];
        hook[32..64].copy_from_slice(&[7u8; 32]);
        entry(&mut data, 14, &hook);
        entry(&mut data, 4, &[0u8; 65]);
        let s = parse(&data).unwrap();
        assert_eq!(s.extensions.len(), 4);
        assert_eq!(s.fee_config.unwrap().newer.basis_points, 500);
        assert_eq!(
            s.permanent_delegate.as_deref(),
            Some(bs58::encode([8u8; 32]).into_string().as_str())
        );
        assert_eq!(
            s.hook.unwrap().program_id.as_deref(),
            Some(bs58::encode([7u8; 32]).into_string().as_str())
        );
        assert!(s.confidential_extension_present);
    }
    #[test]
    fn duplicate_truncated_wrong_base_and_account_extension_are_rejected() {
        let mut dup = mint();
        entry(&mut dup, 9, &[]);
        entry(&mut dup, 9, &[]);
        assert_eq!(parse(&dup).unwrap_err(), RpcError::InvalidResponse);
        let mut cut = mint();
        cut.extend([14, 0, 64, 0, 8]);
        assert_eq!(parse(&cut).unwrap_err(), RpcError::InvalidResponse);
        let mut bad = mint();
        bad[45] = 0;
        assert_eq!(parse(&bad).unwrap_err(), RpcError::InvalidResponse);
        let mut wrong = mint();
        entry(&mut wrong, 2, &[0u8; 8]);
        assert_eq!(parse(&wrong).unwrap_err(), RpcError::InvalidResponse);
    }
    #[test]
    fn unknown_extension_is_preserved_and_never_decoded_as_safe() {
        let mut data = mint();
        entry(&mut data, 65000, &[1, 2, 3]);
        let s = parse(&data).unwrap();
        assert_eq!(s.unknown_extension_count, 1);
        assert_eq!(s.extensions[0].family, "unknown_extension");
        assert!(!s.extensions[0].layout_checked);
        assert_eq!(
            parse_token_2022_mint("mint", "not-token2022", &data).unwrap_err(),
            RpcError::InvalidResponse
        );
    }
    #[test]
    fn legacy_82_byte_mint_is_not_tlv_and_invalid_fee_layout_is_rejected() {
        let base = mint()[..82].to_vec();
        let s = parse(&base).unwrap();
        assert!(s.extensions.is_empty());
        let mut invalid = mint();
        entry(&mut invalid, 1, &[0u8; 107]);
        assert_eq!(parse(&invalid).unwrap_err(), RpcError::InvalidResponse);
    }
}
