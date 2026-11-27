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

/// Parse once, inspect only original wire bytes, and never invoke RPC.
pub fn inspect(bytes: &[u8]) -> Result<ProgramReport, String> {
    let parsed = parse_transaction(bytes)?;
    Ok(from_parsed(&parsed))
}

fn from_parsed(parsed: &ParsedTransaction) -> ProgramReport {
    let mut instructions = Vec::with_capacity(parsed.instruction_count);
    for ix in &parsed.compiled_top_level_instructions {
        let program_id = parsed.static_account_keys.get(ix.program_index).cloned();
        let data = bs58::decode(&ix.data_base58).into_vec().unwrap_or_default();
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
                    Some(movement) => (
                        Declaration::SystemMovement {
                            operation: movement.kind,
                            lamports: movement.lamports.clone(),
                        },
                        "DECODED_DECLARATION",
                    ),
                    None => (Declaration::Unsupported, "UNSUPPORTED_LAYOUT"),
                }
            }
            Some(ATA) if matches!(data.as_slice(), [] | [0] | [1])
                && ix.account_indices.len() == 6 =>
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
                        operation: if data == [1] { "create_idempotent" } else { "create" },
                        static_program_roles_match,
                    },
                    "DECODED_DECLARATION",
                )
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
    ProgramReport {
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
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn exact_compute_layouts_and_units() {
        for (data, op, raw, unit) in [
            (vec![1, 0, 0, 1, 0], "request_heap_frame", "65536", "bytes"),
            (vec![2, 64, 13, 3, 0], "set_compute_unit_limit", "200000", "compute_units"),
            (vec![3, 255, 255, 255, 255, 255, 255, 255, 255], "set_compute_unit_price",
                "18446744073709551615", "micro_lamports_per_compute_unit"),
            (vec![4, 0, 0, 1, 0], "set_loaded_accounts_data_size_limit", "65536", "bytes"),
        ] {
            let value = serde_json::to_value(compute(&data, true).unwrap()).unwrap();
            assert_eq!(value["operation"], op);
            assert_eq!(value["value_raw"], raw);
            assert_eq!(value["unit"], unit);
            assert_eq!(value["message_v1"], true);
        }
        for data in [vec![], vec![0], vec![2, 1], vec![2, 1, 0, 0, 0, 0], vec![255]] {
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
