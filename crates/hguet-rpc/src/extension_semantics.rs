//! Advisory, bounded classification of Token-2022 extension CPI data.
//! Discriminants mirror spl-token-2022-interface TokenInstruction and its
//! transfer-fee/transfer-hook extension instruction enums.
//! https://docs.rs/spl-token-2022-interface/latest/src/spl_token_2022_interface/instruction.rs.html
//! https://docs.rs/spl-token-2022-interface/latest/src/spl_token_2022_interface/extension/transfer_fee/instruction.rs.html
//! https://docs.rs/spl-token-2022-interface/latest/src/spl_token_2022_interface/extension/transfer_hook/instruction.rs.html
//! Observed from one RPC: NOT account state, trusted authorization, actual
//! fee assessment, an executed hook, or final payment effects.
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Token2022ExtensionObservation {
    pub parent_instruction_index: usize,
    pub inner_instruction_index: usize,
    pub opcode: u8,
    pub sub_opcode: Option<u8>,
    pub family: &'static str,
    pub operation: &'static str,
    /// True only for a small, exact and independently specified wire layout.
    /// Even true is NOT proof of on-chain execution or mint account state.
    pub layout_checked: bool,
    pub mint: Option<String>,
    pub authority: Option<String>,
    pub new_authority: Option<String>,
    pub hook_program_id: Option<String>,
    pub declared_amount_raw: Option<String>,
    pub expected_fee_raw: Option<String>,
    pub fee_basis_points: Option<u16>,
    pub maximum_fee_raw: Option<String>,
}

fn read_u64(bytes: &[u8], start: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(start..start.checked_add(8)?)?.try_into().ok()?))
}
fn read_u16(bytes: &[u8], start: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(start..start.checked_add(2)?)?.try_into().ok()?))
}
fn nullable_address(raw: &[u8]) -> Option<String> {
    if raw.len()!=32 || raw.iter().all(|byte| *byte==0) {
        None
    } else {
        Some(bs58::encode(raw).into_string())
    }
}

/// This function only classifies *Token-2022* byte prefixes. A complete mint
/// extension inventory requires separate authenticated account-state evidence.
pub fn inspect_token_2022_extension(
    bytes: &[u8],
    accounts: &[String],
    parent_index: usize,
    inner_index: usize,
) -> Option<Token2022ExtensionObservation> {
    let tag=*bytes.first()?;
    if tag<25 { return None; }
    let sub=bytes.get(1).copied();
    let (family,operation)=match (tag,sub) {
        (25,_) => ("mint_close_authority","initialize_mint_close_authority"),
        (26,Some(0)) => ("transfer_fee","initialize_transfer_fee_config"),
        (26,Some(1)) => ("transfer_fee","transfer_checked_with_fee"),
        (26,Some(2)) => ("transfer_fee","withdraw_withheld_from_mint"),
        (26,Some(3)) => ("transfer_fee","withdraw_withheld_from_accounts"),
        (26,Some(4)) => ("transfer_fee","harvest_withheld_to_mint"),
        (26,Some(5)) => ("transfer_fee","set_transfer_fee"),
        (26,_) => ("transfer_fee","unrecognized_transfer_fee_operation"),
        (27,_) => ("confidential_transfer","confidential_transfer_instruction"),
        (28,_) => ("default_account_state","default_account_state_instruction"),
        (29,_) => ("account_reallocation","reallocate"),
        (30,_) => ("memo_transfer","memo_transfer_instruction"),
        (31,_) => ("native_mint","create_native_mint"),
        (32,_) => ("non_transferable","initialize_non_transferable_mint"),
        (33,_) => ("interest_bearing","interest_bearing_instruction"),
        (34,_) => ("cpi_guard","cpi_guard_instruction"),
        (35,_) => ("permanent_delegate","initialize_permanent_delegate"),
        (36,Some(0)) => ("transfer_hook","initialize_transfer_hook"),
        (36,Some(1)) => ("transfer_hook","update_transfer_hook"),
        (36,_) => ("transfer_hook","unrecognized_transfer_hook_operation"),
        (37,_) => ("confidential_transfer_fee","confidential_fee_instruction"),
        (38,_) => ("excess_lamports","withdraw_excess_lamports"),
        (39,_) => ("metadata_pointer","metadata_pointer_instruction"),
        (40,_) => ("group_pointer","group_pointer_instruction"),
        (41,_) => ("group_member_pointer","group_member_pointer_instruction"),
        (42,_) => ("confidential_mint_burn","confidential_mint_burn_instruction"),
        (43,_) => ("scaled_ui_amount","scaled_ui_amount_instruction"),
        (44,_) => ("pausable","pausable_instruction"),
        (45,_) => ("unwrap_lamports","unwrap_lamports"),
        (46,_) => ("permissioned_burn","permissioned_burn_instruction"),
        (47,_) => ("batch","batch_instruction"),
        _ => ("unknown_extension","unrecognized_token_2022_opcode"),
    };
    let mut result=Token2022ExtensionObservation {
        parent_instruction_index:parent_index,inner_instruction_index:inner_index,
        opcode:tag,sub_opcode:if matches!(tag,26|27|28|30|33|34|36|37|39|40|41|42|43|44|46) { sub } else { None },
        family,operation,layout_checked:false,mint:accounts.first().cloned(),
        authority:None,new_authority:None,hook_program_id:None,
        declared_amount_raw:None,expected_fee_raw:None,
        fee_basis_points:None,maximum_fee_raw:None,
    };
    match (tag,sub) {
        // [26,1,amount:u64,decimals:u8,expected_fee:u64], 4+ account roles.
        (26,Some(1)) if bytes.len()==19 && accounts.len()>=4 => {
            if let (Some(amount),Some(fee))=(read_u64(bytes,2),read_u64(bytes,11)) {
                result.layout_checked=true;
                result.mint=accounts.get(1).cloned();
                result.authority=accounts.get(3).cloned();
                result.declared_amount_raw=Some(amount.to_string());
                result.expected_fee_raw=Some(fee.to_string());
            }
        }
        // [26,5,basis_points:u16,max_fee:u64], mint + authority.
        (26,Some(5)) if bytes.len()==12 && accounts.len()>=2 => {
            if let (Some(bps),Some(maximum))=(read_u16(bytes,2),read_u64(bytes,4)) {
                result.layout_checked=true;
                result.authority=accounts.get(1).cloned();
                result.fee_basis_points=Some(bps);
                result.maximum_fee_raw=Some(maximum.to_string());
            }
        }
        // [35,new_permanent_delegate:Pubkey], mint account.
        (35,_) if bytes.len()==33 && !accounts.is_empty() => {
            result.layout_checked=true;
            result.new_authority=Some(bs58::encode(&bytes[1..33]).into_string());
        }
        // [36,0,authority:MaybeNull<Pubkey>,program:MaybeNull<Pubkey>]
        (36,Some(0)) if bytes.len()==66 && !accounts.is_empty() => {
            result.layout_checked=true;
            result.new_authority=nullable_address(&bytes[2..34]);
            result.hook_program_id=nullable_address(&bytes[34..66]);
        }
        // [36,1,program:MaybeNull<Pubkey>] mint + authority.
        (36,Some(1)) if bytes.len()==34 && accounts.len()>=2 => {
            result.layout_checked=true;
            result.authority=accounts.get(1).cloned();
            result.hook_program_id=nullable_address(&bytes[2..34]);
        }
        _ => {}
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn keys() -> Vec<String> {
        (1..=5).map(|n|bs58::encode([n;32]).into_string()).collect()
    }
    #[test]
    fn checked_transfer_fee_uses_exact_le_fields_and_account_roles() {
        let mut bytes=vec![26,1];
        bytes.extend(1_000u64.to_le_bytes());
        bytes.push(6);
        bytes.extend(23u64.to_le_bytes());
        let r=inspect_token_2022_extension(&bytes,&keys(),2,4).unwrap();
        assert_eq!(r.family,"transfer_fee");
        assert_eq!(r.operation,"transfer_checked_with_fee");
        assert!(r.layout_checked);
        assert_eq!(r.declared_amount_raw.as_deref(),Some("1000"));
        assert_eq!(r.expected_fee_raw.as_deref(),Some("23"));
        assert_eq!(r.authority.as_deref(),Some(keys()[3].as_str()));
        assert_eq!(r.parent_instruction_index,2);
    }
    #[test]
    fn transfer_fee_config_change_and_wrong_length_are_not_silently_decoded() {
        let mut b=vec![26,5];
        b.extend(250u16.to_le_bytes());
        b.extend(u64::MAX.to_le_bytes());
        let r=inspect_token_2022_extension(&b,&keys(),0,0).unwrap();
        assert!(r.layout_checked);
        assert_eq!(r.fee_basis_points,Some(250));
        assert_eq!(r.maximum_fee_raw.as_deref(),Some("18446744073709551615"));
        b.pop();
        let incomplete=inspect_token_2022_extension(&b,&keys(),0,0).unwrap();
        assert!(!incomplete.layout_checked);
        assert_eq!(incomplete.maximum_fee_raw,None);
    }
    #[test]
    fn permanent_delegate_exposes_pubkey_without_claiming_authorization() {
        let mut b=vec![35u8];b.extend([42u8;32]);
        let r=inspect_token_2022_extension(&b,&keys(),0,0).unwrap();
        assert!(r.layout_checked);
        assert_eq!(r.family,"permanent_delegate");
        assert_eq!(r.new_authority,Some(bs58::encode([42u8;32]).into_string()));
        assert!(!inspect_token_2022_extension(&[35,1],&keys(),0,0).unwrap().layout_checked);
    }
    #[test]
    fn transfer_hook_nullable_addresses_and_update_are_distinguished() {
        let mut create=vec![36,0];create.extend([0u8;32]);create.extend([7u8;32]);
        let r=inspect_token_2022_extension(&create,&keys(),0,1).unwrap();
        assert_eq!(r.operation,"initialize_transfer_hook");
        assert!(r.layout_checked);
        assert_eq!(r.new_authority,None);
        assert_eq!(r.hook_program_id,Some(bs58::encode([7u8;32]).into_string()));
        let mut update=vec![36,1];update.extend([9u8;32]);
        let u=inspect_token_2022_extension(&update,&keys(),0,2).unwrap();
        assert_eq!(u.operation,"update_transfer_hook");
        assert!(u.layout_checked);
        assert_eq!(u.authority.as_deref(),Some(keys()[1].as_str()));
    }
    #[test]
    fn confidential_and_unknown_extensions_are_hints_not_authorization() {
        for (tag,family) in [(27,"confidential_transfer"),(37,"confidential_transfer_fee"),
            (42,"confidential_mint_burn"),(99,"unknown_extension")] {
            let item=inspect_token_2022_extension(&[tag,200,0],&keys(),0,0).unwrap();
            assert_eq!(item.family,family);
            assert!(!item.layout_checked);
        }
        assert!(inspect_token_2022_extension(&[12,1,0],&keys(),0,0).is_none());
    }
}
