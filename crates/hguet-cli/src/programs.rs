//! Bounded offline program declarations, separate from security verdicts.
use hguet_core::{parse_transaction, ParsedTransaction, V1Resources};
use serde::Serialize;

const SYSTEM: &str = "11111111111111111111111111111111";
const COMPUTE: &str = "ComputeBudget111111111111111111111111111111";
const MEMO: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";
const MEMO_LEGACY: &str = "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo";
const ATA: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ALT: &str = "AddressLookupTab1e1111111111111111111111111";

#[derive(Debug, Serialize)]
pub struct AccountRole {
    pub role: &'static str,
    pub message_index: usize,
    pub address: Option<String>,
    pub required_signer: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Declaration {
    ComputeBudget {
        operation: &'static str,
        value_raw: String,
        unit: &'static str,
        message_v1: bool,
    },
    Memo {
        byte_length: usize,
        valid_utf8: bool,
    },
    SystemMovement {
        operation: &'static str,
        lamports: String,
    },
    AssociatedTokenAccount {
        operation: &'static str,
        static_program_roles_match: Option<bool>,
    },
    Token {
        operation: String,
        source_account: Option<String>,
        destination_account: Option<String>,
        mint: Option<String>,
        authority: Option<String>,
        delegate: Option<String>,
        amount_raw: Option<String>,
        decimals: Option<u8>,
        authority_type: Option<u8>,
        new_authority: Option<String>,
    },
    Token2022Extension {
        family: &'static str,
        operation: &'static str,
        opcode: u8,
        sub_opcode: Option<u8>,
        layout_checked: bool,
        mint: Option<String>,
        source_account: Option<String>,
        destination_account: Option<String>,
        authority: Option<String>,
        new_authority: Option<String>,
        hook_program_id: Option<String>,
        declared_amount_raw: Option<String>,
        decimals: Option<u8>,
        expected_fee_raw: Option<String>,
        fee_basis_points: Option<u16>,
        maximum_fee_raw: Option<String>,
    },
    AddressLookupTable {
        operation: &'static str,
        recent_slot_raw: Option<String>,
        bump_seed: Option<u8>,
        new_addresses: Vec<String>,
    },
    Unsupported,
}

#[derive(Debug, Serialize)]
pub struct ProgramInstruction {
    pub instruction_index: usize,
    pub program_index: usize,
    pub program_id: Option<String>,
    pub family: &'static str,
    pub layout_status: &'static str,
    pub accounts: Vec<AccountRole>,
    pub declaration: Declaration,
}

#[derive(Debug, Serialize)]
pub struct ProgramReport {
    pub schema_version: u8,
    pub kind: &'static str,
    pub message_sha256: String,
    pub wire_format: String,
    pub resource_config: Option<V1Resources>,
    pub instructions: Vec<ProgramInstruction>,
    pub signing_authorization: &'static str,
    pub limitations: Vec<&'static str>,
}

fn compute(data: &[u8], message_v1: bool) -> Option<Declaration> {
    let (operation, value_raw, unit) = match data {
        [1, a, b, c, d] => (
            "request_heap_frame",
            u32::from_le_bytes([*a, *b, *c, *d]).to_string(),
            "bytes",
        ),
        [2, a, b, c, d] => (
            "set_compute_unit_limit",
            u32::from_le_bytes([*a, *b, *c, *d]).to_string(),
            "compute_units",
        ),
        [3, a, b, c, d, e, f, g, h] => (
            "set_compute_unit_price",
            u64::from_le_bytes([*a, *b, *c, *d, *e, *f, *g, *h]).to_string(),
            "micro_lamports_per_compute_unit",
        ),
        [4, a, b, c, d] => (
            "set_loaded_accounts_data_size_limit",
            u32::from_le_bytes([*a, *b, *c, *d]).to_string(),
            "bytes",
        ),
        _ => return None,
    };
    Some(Declaration::ComputeBudget {
        operation,
        value_raw,
        unit,
        message_v1,
    })
}

fn family(id: Option<&str>) -> &'static str {
    match id {
        Some(SYSTEM) => "system",
        Some(COMPUTE) => "compute_budget",
        Some(MEMO | MEMO_LEGACY) => "memo",
        Some(ATA) => "associated_token_account",
        Some(TOKEN) => "spl_token",
        Some(TOKEN_2022) => "token_2022",
        Some(ALT) => "address_lookup_table",
        Some(_) => "unknown_program",
        None => "unresolved_lookup_program",
    }
}

fn lookup_declaration(
    data: &[u8],
    accounts: usize,
) -> Option<(Declaration, &'static [&'static str])> {
    let tag = u32::from_le_bytes(data.get(..4)?.try_into().ok()?);
    let mut recent_slot_raw = None;
    let mut bump_seed = None;
    let mut new_addresses = Vec::new();
    let (operation, roles): (&str, &[&str]) = match tag {
        0 if data.len() == 13 && accounts == 4 => {
            recent_slot_raw = Some(u64::from_le_bytes(data[4..12].try_into().ok()?).to_string());
            bump_seed = Some(data[12]);
            (
                "create_lookup_table",
                &["lookup_table", "authority", "payer", "system_program"],
            )
        }
        1 if data.len() == 4 && accounts == 2 => {
            ("freeze_lookup_table", &["lookup_table", "authority"])
        }
        2 if matches!(accounts, 2 | 4) => {
            let count = u64::from_le_bytes(data.get(4..12)?.try_into().ok()?);
            // Bound before allocation and multiplication, independently of wire size.
            if count == 0 || count > 256 {
                return None;
            }
            let count = usize::try_from(count).ok()?;
            if data.len() != 12 + count * 32 {
                return None;
            }
            new_addresses = data[12..]
                .as_chunks::<32>()
                .0
                .iter()
                .map(|key| bs58::encode(key).into_string())
                .collect();
            let roles: &[&str] = if accounts == 4 {
                &["lookup_table", "authority", "payer", "system_program"]
            } else {
                &["lookup_table", "authority"]
            };
            ("extend_lookup_table", roles)
        }
        3 if data.len() == 4 && accounts == 2 => {
            ("deactivate_lookup_table", &["lookup_table", "authority"])
        }
        4 if data.len() == 4 && accounts == 3 => (
            "close_lookup_table",
            &["lookup_table", "authority", "recipient"],
        ),
        _ => return None,
    };
    Some((
        Declaration::AddressLookupTable {
            operation,
            recent_slot_raw,
            bump_seed,
            new_addresses,
        },
        roles,
    ))
}

fn token_roles(operation: &str) -> &'static [&'static str] {
    match operation {
        "transfer" => &["source", "destination", "authority"],
        "transfer_checked" | "transfer_checked_with_fee" => {
            &["source", "mint", "destination", "authority"]
        }
        "approve" => &["source", "delegate", "authority"],
        "approve_checked" => &["source", "mint", "delegate", "authority"],
        "mint_to" | "mint_to_checked" => &["mint", "destination", "authority"],
        "burn" | "burn_checked" => &["source", "mint", "authority"],
        "revoke" | "set_authority" => &["target", "authority"],
        "close_account" => &["source", "destination", "authority"],
        "freeze_account" | "thaw_account" => &["target", "mint", "authority"],
        "sync_native" => &["target"],
        "set_transfer_fee" | "update_transfer_hook" => &["mint", "authority"],
        "initialize_transfer_hook" | "initialize_permanent_delegate" => &["mint"],
        _ => &[],
    }
}

fn token_declaration(
    parsed: &ParsedTransaction,
    index: usize,
    data: &[u8],
) -> (Declaration, &'static str, &'static [&'static str]) {
    use hguet_rpc::StaticTokenDeclaration;
    let decoded = hguet_rpc::inspect_static_token_instruction(parsed, index);
    match decoded {
        Ok(Some(StaticTokenDeclaration::Base(value))) => {
            let roles = token_roles(&value.operation);
            (
                Declaration::Token {
                    operation: value.operation,
                    source_account: value.source_account,
                    destination_account: value.destination_account,
                    mint: value.mint,
                    authority: value.authority,
                    delegate: value.delegate,
                    amount_raw: value.amount_raw,
                    decimals: value.decimals,
                    authority_type: value.authority_type,
                    new_authority: value.new_authority,
                },
                "DECODED_DECLARATION",
                roles,
            )
        }
        Ok(Some(StaticTokenDeclaration::Extension(value))) => {
            let checked = value.layout_checked;
            let roles = if checked {
                token_roles(value.operation)
            } else {
                &[]
            };
            let destination_account = if checked && value.operation == "transfer_checked_with_fee" {
                parsed.compiled_top_level_instructions[index]
                    .account_indices
                    .get(2)
                    .and_then(|i| parsed.static_account_keys.get(*i))
                    .cloned()
            } else {
                None
            };
            (
                Declaration::Token2022Extension {
                    family: value.family,
                    operation: value.operation,
                    opcode: value.opcode,
                    sub_opcode: value.sub_opcode,
                    layout_checked: checked,
                    // Prefix-only classifications must not assign account roles.
                    mint: if checked { value.mint } else { None },
                    source_account: value.source_account,
                    destination_account,
                    authority: value.authority,
                    new_authority: value.new_authority,
                    hook_program_id: value.hook_program_id,
                    declared_amount_raw: value.declared_amount_raw,
                    decimals: if checked && value.operation == "transfer_checked_with_fee" {
                        data.get(10).copied()
                    } else {
                        None
                    },
                    expected_fee_raw: value.expected_fee_raw,
                    fee_basis_points: value.fee_basis_points,
                    maximum_fee_raw: value.maximum_fee_raw,
                },
                if checked {
                    "DECODED_DECLARATION"
                } else {
                    "PREFIX_ONLY"
                },
                roles,
            )
        }
        Ok(None) => (Declaration::Unsupported, "UNRESOLVED_ACCOUNTS", &[]),
        Ok(Some(StaticTokenDeclaration::Opaque)) => {
            (Declaration::Unsupported, "UNSUPPORTED_LAYOUT", &[])
        }
        Err(_) => (Declaration::Unsupported, "DECODER_UNAVAILABLE", &[]),
    }
}

/// Parse once, inspect only original wire bytes, and never invoke RPC.
pub fn inspect(bytes: &[u8]) -> Result<ProgramReport, String> {
    let parsed = parse_transaction(bytes)?;
    from_parsed(&parsed)
}

fn from_parsed(parsed: &ParsedTransaction) -> Result<ProgramReport, String> {
    let mut instructions = Vec::with_capacity(parsed.instruction_count);
    for ix in &parsed.compiled_top_level_instructions {
        let program_id = parsed.static_account_keys.get(ix.program_index).cloned();
        let data = bs58::decode(&ix.data_base58)
            .into_vec()
            .map_err(|_| "invalid parsed instruction data".to_owned())?;
        let mut roles: &[&str] = &[];
        let (declaration, layout_status) = match program_id.as_deref() {
            Some(COMPUTE) => match compute(&data, parsed.wire_format == "v1") {
                Some(value) => (value, "DECODED_DECLARATION"),
                None => (Declaration::Unsupported, "UNSUPPORTED_LAYOUT"),
            },
            Some(MEMO | MEMO_LEGACY) => {
                let valid_utf8 = std::str::from_utf8(&data).is_ok();
                (
                    Declaration::Memo {
                        byte_length: data.len(),
                        valid_utf8,
                    },
                    if valid_utf8 {
                        "DECODED_DECLARATION"
                    } else {
                        "INVALID_UTF8"
                    },
                )
            }
            Some(SYSTEM) => {
                match parsed
                    .system_transfers
                    .iter()
                    .find(|movement| movement.instruction_index == ix.instruction_index)
                {
                    Some(movement) => {
                        roles = match movement.kind {
                            "transfer" => &["source", "destination"],
                            "transfer_with_seed" => &["source", "base", "destination"],
                            "create_account" | "create_account_with_seed" => {
                                &["funding_account", "new_account"]
                            }
                            "withdraw_nonce_account" => &["nonce_account", "recipient"],
                            _ => &[],
                        };
                        (
                            Declaration::SystemMovement {
                                operation: movement.kind,
                                lamports: movement.lamports.clone(),
                            },
                            "DECODED_DECLARATION",
                        )
                    }
                    None => (Declaration::Unsupported, "UNSUPPORTED_LAYOUT"),
                }
            }
            Some(ATA)
                if matches!(data.as_slice(), [] | [0] | [1]) && ix.account_indices.len() == 6 =>
            {
                roles = &[
                    "funding_account",
                    "associated_token_account",
                    "wallet",
                    "mint",
                    "system_program",
                    "token_program",
                ];
                let key_at = |i: usize| parsed.static_account_keys.get(ix.account_indices[i]);
                let static_program_roles_match = match (key_at(4), key_at(5)) {
                    (Some(system), Some(token)) => {
                        Some(system == SYSTEM && matches!(token.as_str(), TOKEN | TOKEN_2022))
                    }
                    _ => None,
                };
                (
                    Declaration::AssociatedTokenAccount {
                        operation: if data == [1] {
                            "create_idempotent"
                        } else {
                            "create"
                        },
                        static_program_roles_match,
                    },
                    "DECODED_DECLARATION",
                )
            }
            Some(ALT) => match lookup_declaration(&data, ix.account_indices.len()) {
                Some((value, account_roles)) => {
                    roles = account_roles;
                    (value, "DECODED_DECLARATION")
                }
                None => (Declaration::Unsupported, "UNSUPPORTED_LAYOUT"),
            },
            Some(TOKEN | TOKEN_2022) => {
                let (value, status, token_roles) =
                    token_declaration(parsed, ix.instruction_index, &data);
                roles = token_roles;
                (value, status)
            }
            None => (Declaration::Unsupported, "UNRESOLVED_PROGRAM"),
            _ => (Declaration::Unsupported, "UNSUPPORTED_LAYOUT"),
        };
        let accounts = ix
            .account_indices
            .iter()
            .enumerate()
            .map(|(i, index)| AccountRole {
                role: roles.get(i).copied().unwrap_or("unclassified"),
                message_index: *index,
                address: parsed.static_account_keys.get(*index).cloned(),
                required_signer: *index < parsed.required_signatures,
            })
            .collect();
        instructions.push(ProgramInstruction {
            instruction_index: ix.instruction_index,
            program_index: ix.program_index,
            family: family(program_id.as_deref()),
            program_id,
            layout_status,
            accounts,
            declaration,
        });
    }
    Ok(ProgramReport {
        schema_version: 1,
        kind: "hguet_program_intelligence",
        message_sha256: parsed.message_sha256.clone(),
        wire_format: parsed.wire_format.clone(),
        resource_config: parsed.resource_config.clone(),
        instructions,
        signing_authorization: "NOT_AUTHORIZED",
        limitations: vec![
            "Decoded layout does not establish runtime validity, execution or safety.",
            "Compute Budget values are declarations, not effective fees; v1 uses message configuration.",
            "Account roles are declared, not verified ownership, PDA derivation or rent.",
            "Memo payload is deliberately omitted; UTF-8 validity is not authenticity.",
            "Unsupported instructions and unresolved ALT addresses are not safe or zero effects.",
            "Token authority roles and amounts are declarations; multisig, hooks, actual fees and account state are not verified.",
            "Lookup-table mutations do not establish table state, activation slot, authority or ability to close.",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn exact_compute_layouts_and_units() {
        for (data, op, raw, unit) in [
            (vec![1, 0, 0, 1, 0], "request_heap_frame", "65536", "bytes"),
            (
                vec![2, 64, 13, 3, 0],
                "set_compute_unit_limit",
                "200000",
                "compute_units",
            ),
            (
                vec![3, 255, 255, 255, 255, 255, 255, 255, 255],
                "set_compute_unit_price",
                "18446744073709551615",
                "micro_lamports_per_compute_unit",
            ),
            (
                vec![4, 0, 0, 1, 0],
                "set_loaded_accounts_data_size_limit",
                "65536",
                "bytes",
            ),
        ] {
            let value = serde_json::to_value(compute(&data, true).unwrap()).unwrap();
            assert_eq!(value["operation"], op);
            assert_eq!(value["value_raw"], raw);
            assert_eq!(value["unit"], unit);
            assert_eq!(value["message_v1"], true);
        }
        for data in [
            vec![],
            vec![0],
            vec![2, 1],
            vec![2, 1, 0, 0, 0, 0],
            vec![255],
        ] {
            assert!(compute(&data, false).is_none());
        }
    }

    #[test]
    fn system_fixture_preserves_declared_movement_and_refusal() {
        let bytes = STANDARD
            .decode(include_str!("../../../tests/fixtures/v1-system-transfer.base64").trim())
            .unwrap();
        let report = inspect(&bytes).unwrap();
        assert_eq!(report.instructions.len(), 1);
        assert!(matches!(
            &report.instructions[0].declaration,
            Declaration::SystemMovement { lamports, .. } if lamports == "500"
        ));
        assert_eq!(report.signing_authorization, "NOT_AUTHORIZED");
        assert!(inspect(&[0xff]).is_err());
    }
}
