//! Bounded decoding of selected *compiled* SPL Token CPI instruction arguments.
//! The instruction list is supplied by ONE untrusted RPC node. These are
//! instruction claims, not a verified state transition, gross debit or consent.
//! Token-2022 extensions are intentionally opaque pending dedicated decoders.
use crate::RpcError;
use serde::Serialize;
use serde_json::{Map, Value};

pub const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022_PROGRAM: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const MAX_CPI_ACCOUNTS: usize = 64;
const MAX_CPI_DATA: usize = 512;
const MAX_CPI_B58: usize = 1024;

pub(crate) fn is_token_program(program: &str) -> bool {
    program == TOKEN_PROGRAM || program == TOKEN_2022_PROGRAM
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenCpiInstruction {
    pub parent_instruction_index: usize,
    pub inner_instruction_index: usize,
    pub program_id: String,
    pub operation: String,
    pub source_account: Option<String>,
    pub destination_account: Option<String>,
    pub mint: Option<String>,
    pub authority: Option<String>,
    pub delegate: Option<String>,
    /// The instruction's declared quantity, NOT the net onchain change.
    pub amount_raw: Option<String>,
    pub decimals: Option<u8>,
    pub authority_type: Option<u8>,
    pub new_authority: Option<String>,
}

pub(crate) enum TokenCpiDecode {
    Recognized(TokenCpiInstruction),
    Opaque { extension: bool, missing_compiled: bool },
}

fn opaque(extension: bool, missing_compiled: bool) -> TokenCpiDecode {
    TokenCpiDecode::Opaque { extension, missing_compiled }
}

/// Called only for canonical Token or Token-2022 program IDs previously
/// checked against the resolved, indexed transaction address list.
pub(crate) fn decode_token_cpi(
    program_id: &str,
    ix: &Map<String, Value>,
    account_keys: &[String],
    parent_index: usize,
    inner_index: usize,
) -> Result<TokenCpiDecode, RpcError> {
    if !is_token_program(program_id) { return Err(RpcError::InvalidResponse); }

    // jsonParsed may contain account addresses and provider-authored parsed
    // fields. Never trust those as binary-decoded semantics.
    let Some(raw_accounts) = ix.get("accounts").and_then(Value::as_array) else {
        return Ok(opaque(false, true));
    };
    if raw_accounts.len() > MAX_CPI_ACCOUNTS { return Err(RpcError::TooLarge); }
    if raw_accounts.iter().all(Value::is_string) {
        return Ok(opaque(false, true));
    }
    let mut accounts = Vec::with_capacity(raw_accounts.len());
    for raw in raw_accounts {
        let index = raw.as_u64().and_then(|x| usize::try_from(x).ok())
            .ok_or(RpcError::InvalidResponse)?;
        accounts.push(account_keys.get(index).ok_or(RpcError::InvalidResponse)?.clone());
    }

    let Some(data) = ix.get("data").and_then(Value::as_str) else {
        return Ok(opaque(false, true));
    };
    if data.len() > MAX_CPI_B58 { return Err(RpcError::TooLarge); }
    let bytes = bs58::decode(data).into_vec().map_err(|_| RpcError::InvalidResponse)?;
    if bytes.len() > MAX_CPI_DATA { return Err(RpcError::TooLarge); }
    let Some(tag) = bytes.first().copied() else { return Ok(opaque(false, false)); };
    let extension = program_id == TOKEN_2022_PROGRAM && tag >= 25;

    let mut item = TokenCpiInstruction {
        parent_instruction_index: parent_index,
        inner_instruction_index: inner_index,
        program_id: program_id.into(),
        operation: String::new(),
        source_account: None,
        destination_account: None,
        mint: None,
        authority: None,
        delegate: None,
        amount_raw: None,
        decimals: None,
        authority_type: None,
        new_authority: None,
    };
    let account = |i: usize| accounts.get(i).cloned();
    match tag {
        // Transfer, Approve, MintTo, Burn and their checked variants.
        3 | 4 | 7 | 8 | 12 | 13 | 14 | 15 => {
            let checked = matches!(tag, 12..=15);
            let min_accounts = match tag {
                3 | 4 | 7 | 8 | 14 | 15 => 3,
                12 | 13 => 4,
                _ => return Ok(opaque(extension, false)),
            };
            if bytes.len() != if checked { 10 } else { 9 } || accounts.len() < min_accounts {
                return Ok(opaque(extension, false));
            }
            let amount = u64::from_le_bytes(bytes[1..9].try_into()
                .map_err(|_| RpcError::InvalidResponse)?);
            item.amount_raw = Some(amount.to_string());
            if checked { item.decimals = Some(bytes[9]); }
            match tag {
                3 => {
                    item.operation = "transfer".into();
                    item.source_account = account(0);
                    item.destination_account = account(1);
                    item.authority = account(2);
                }
                12 => {
                    item.operation = "transfer_checked".into();
                    item.source_account = account(0);
                    item.mint = account(1);
                    item.destination_account = account(2);
                    item.authority = account(3);
                }
                4 | 13 => {
                    item.operation = if checked { "approve_checked" } else { "approve" }.into();
                    item.source_account = account(0);
                    if checked {
                        item.mint = account(1);
                        item.delegate = account(2);
                        item.authority = account(3);
                    } else {
                        item.delegate = account(1);
                        item.authority = account(2);
                    }
                }
                7 | 14 => {
                    item.operation = if checked { "mint_to_checked" } else { "mint_to" }.into();
                    item.mint = account(0);
                    item.destination_account = account(1);
                    item.authority = account(2);
                }
                8 | 15 => {
                    item.operation = if checked { "burn_checked" } else { "burn" }.into();
                    item.source_account = account(0);
                    item.mint = account(1);
                    item.authority = account(2);
                }
                _ => unreachable!("matched token opcode"),
            }
        }
        // Revoke, CloseAccount, FreezeAccount, ThawAccount, SyncNative.
        5 | 9 | 10 | 11 | 17 => {
            let needed = if tag == 17 { 1 } else if tag == 5 { 2 } else { 3 };
            if bytes.len() != 1 || accounts.len() < needed {
                return Ok(opaque(extension, false));
            }
            item.operation = match tag {
                5 => "revoke",
                9 => "close_account",
                10 => "freeze_account",
                11 => "thaw_account",
                17 => "sync_native",
                _ => unreachable!("matched token opcode"),
            }.into();
            item.source_account = account(0);
            if tag == 9 { item.destination_account = account(1); }
            if tag == 10 || tag == 11 { item.mint = account(1); }
            if tag != 17 { item.authority = account(needed - 1); }
        }
        // SetAuthority: [6, authority_type, 0|1, optional 32-byte new key].
        6 => {
            if accounts.len() < 2 || bytes.len() < 3 {
                return Ok(opaque(extension, false));
            }
            let next = match bytes[2] {
                0 if bytes.len() == 3 => None,
                1 if bytes.len() == 35 =>
                    Some(bs58::encode(&bytes[3..35]).into_string()),
                _ => return Ok(opaque(extension, false)),
            };
            item.operation = "set_authority".into();
            item.source_account = account(0);
            item.authority = account(1);
            item.authority_type = Some(bytes[1]);
            item.new_authority = next;
        }
        // Remaining base token instructions and ALL Token-2022 extensions
        // are opaque: their effects, including hooks and confidential flows,
        // may be security-critical.
        _ => return Ok(opaque(extension, false)),
    }
    Ok(TokenCpiDecode::Recognized(item))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn keys() -> Vec<String> {
        (1..=5).map(|i| bs58::encode([i; 32]).into_string()).collect()
    }
    fn ix(accounts: &[u8], data: &[u8]) -> Map<String, Value> {
        json!({
            "programIdIndex":0,
            "accounts":accounts,
            "data":bs58::encode(data).into_string()
        }).as_object().unwrap().clone()
    }
    fn recognized(data: &[u8], accounts: &[u8], program: &str) -> TokenCpiInstruction {
        match decode_token_cpi(program, &ix(accounts, data), &keys(), 2, 3).unwrap() {
            TokenCpiDecode::Recognized(item) => item,
            TokenCpiDecode::Opaque { .. } => panic!("expected recognized token instruction"),
        }
    }
    #[test]
    fn decode_raw_transfer_checked_and_authority_account_roles() {
        let item = recognized(&[12, 232, 3, 0, 0, 0, 0, 0, 0, 6],
            &[1, 2, 3, 4], TOKEN_PROGRAM);
        assert_eq!(item.operation, "transfer_checked");
        assert_eq!(item.amount_raw.as_deref(), Some("1000"));
        assert_eq!(item.decimals, Some(6));
        assert_eq!(item.source_account.as_deref(), Some(keys()[1].as_str()));
        assert_eq!(item.mint.as_deref(), Some(keys()[2].as_str()));
        assert_eq!(item.destination_account.as_deref(), Some(keys()[3].as_str()));
        assert_eq!(item.authority.as_deref(), Some(keys()[4].as_str()));
    }
    #[test]
    fn token_2022_common_authority_change_is_decoded_without_claiming_safety() {
        let mut data = vec![6, 2, 1];
        data.extend([9u8; 32]);
        let item = recognized(&data, &[0, 1], TOKEN_2022_PROGRAM);
        assert_eq!(item.operation, "set_authority");
        assert_eq!(item.authority_type, Some(2));
        assert_eq!(item.new_authority,
            Some(bs58::encode([9u8; 32]).into_string()));
        let revoked = recognized(&[6, 0, 0], &[0, 1], TOKEN_PROGRAM);
        assert_eq!(revoked.new_authority, None);
    }
    #[test]
    fn extension_unknown_and_bad_layout_never_become_decoded_transfer() {
        let extension = ix(&[0, 1], &[36, 5, 6]);
        assert!(matches!(decode_token_cpi(TOKEN_2022_PROGRAM, &extension, &keys(), 0, 0),
            Ok(TokenCpiDecode::Opaque { extension: true, .. })));
        let malformed = ix(&[0, 1, 2, 3], &[12, 0, 1]);
        assert!(matches!(decode_token_cpi(TOKEN_PROGRAM, &malformed, &keys(), 0, 0),
            Ok(TokenCpiDecode::Opaque { extension: false, .. })));
    }
    #[test]
    fn parsed_or_missing_cpi_data_is_not_trusted_as_binary_evidence() {
        let parsed = json!({
            "programId":TOKEN_PROGRAM,
            "parsed":{"type":"transferChecked","info":{"amount":"999999999"}}
        });
        assert!(matches!(decode_token_cpi(TOKEN_PROGRAM, parsed.as_object().unwrap(),
            &keys(), 0, 0), Ok(TokenCpiDecode::Opaque { missing_compiled: true, .. })));
    }
    #[test]
    fn indexed_accounts_and_base58_data_fail_closed_on_forgery() {
        let bad_index = ix(&[99, 1, 2], &[3, 1, 0, 0, 0, 0, 0, 0, 0]);
        assert!(decode_token_cpi(TOKEN_PROGRAM, &bad_index, &keys(), 0, 0).is_err());
        let bad_data = json!({"accounts":[0,1,2],"data":"%notbase58"});
        assert!(decode_token_cpi(TOKEN_PROGRAM, bad_data.as_object().unwrap(),
            &keys(), 0, 0).is_err());
    }
    #[test]
    fn different_token_operations_have_distinct_account_roles() {
        let approved = recognized(&[4, 10, 0, 0, 0, 0, 0, 0, 0],
            &[0, 1, 2], TOKEN_PROGRAM);
        assert_eq!(approved.operation, "approve");
        assert_eq!(approved.delegate.as_deref(), Some(keys()[1].as_str()));
        let minted = recognized(&[14, 1, 0, 0, 0, 0, 0, 0, 0, 9],
            &[0, 1, 2], TOKEN_2022_PROGRAM);
        assert_eq!(minted.operation, "mint_to_checked");
        assert_eq!(minted.mint.as_deref(), Some(keys()[0].as_str()));
        let closed = recognized(&[9], &[0, 1, 2], TOKEN_PROGRAM);
        assert_eq!(closed.operation, "close_account");
        assert_eq!(closed.destination_account.as_deref(), Some(keys()[1].as_str()));
    }
}
