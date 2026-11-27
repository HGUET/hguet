//! Bounded offline transaction comparison. No semantic-equivalence or signing grant.
use crate::{authority, flow, programs};
use hguet_core::{parse_transaction, sha256_hex, ParsedTransaction};
use serde::Serialize;
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AccountIdentity {
    pub address: Option<String>,
    pub lookup_table: Option<String>,
    pub lookup_index: Option<u8>,
    pub required_signer: bool,
    pub writable: bool,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct InstructionIdentity {
    pub program: AccountIdentity,
    pub accounts: Vec<AccountIdentity>,
    pub data_sha256: String,
    pub data_bytes: usize,
}

#[derive(Debug, Serialize)]
pub struct InstructionSnapshot {
    pub identity: InstructionIdentity,
    pub fingerprint_sha256: String,
    pub layout_status: &'static str,
    pub declaration: Value,
    pub asset_movement: Value,
    pub authority_change: Value,
}

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub transaction_sha256: String,
    pub message_sha256: String,
    pub wire_format: String,
    pub signature_status: Value,
    pub signature_count: usize,
    pub fee_payer: Option<String>,
    pub required_signers: Vec<String>,
    pub message_accounts: Vec<AccountIdentity>,
    pub recent_blockhash_sha256: String,
    pub resource_config: Value,
    pub instructions: Vec<InstructionSnapshot>,
    pub coverage_gap_indices: Vec<usize>,
}

#[derive(Debug, Serialize)]
pub struct InstructionDiff {
    pub before_index: Option<usize>,
    pub after_index: Option<usize>,
    pub status: &'static str,
    pub changed_fields: Vec<&'static str>,
    pub before_ref: Option<String>,
    pub after_ref: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DiffReport {
    pub schema_version: u8,
    pub kind: &'static str,
    pub relation: &'static str,
    pub signing_authorization: &'static str,
    pub semantic_equivalence_proven: bool,
    pub message_fields_changed: Vec<&'static str>,
    pub ordered_instruction_fingerprints_equal: bool,
    pub instruction_multiset_equal: bool,
    pub instruction_changes: Vec<InstructionDiff>,
    pub before: Snapshot,
    pub after: Snapshot,
    pub limitations: Vec<&'static str>,
}

fn message_context(
    raw: &[u8],
    parsed: &ParsedTransaction,
) -> Result<(Vec<AccountIdentity>, String), String> {
    // The core parser already validated all wire bounds and canonical counts.
    // Legacy/v0 signature count is one byte (1..=64); v1 starts at byte zero.
    let header = if parsed.wire_format == "v1" {
        1
    } else {
        1 + parsed.signature_count * 64 + usize::from(parsed.wire_format == "v0")
    };
    let signed_ro = usize::from(*raw.get(header + 1).ok_or("missing header")?);
    let unsigned_ro = usize::from(*raw.get(header + 2).ok_or("missing header")?);
    let signed_writable = parsed
        .required_signatures
        .checked_sub(signed_ro)
        .ok_or("invalid signed privileges")?;
    let unsigned_writable_end = parsed
        .static_account_count
        .checked_sub(unsigned_ro)
        .ok_or("invalid unsigned privileges")?;
    let mut accounts = Vec::with_capacity(parsed.total_address_count);
    for (i, address) in parsed.static_account_keys.iter().enumerate() {
        let required_signer = i < parsed.required_signatures;
        accounts.push(AccountIdentity {
            address: Some(address.clone()),
            lookup_table: None,
            lookup_index: None,
            required_signer,
            writable: if required_signer {
                i < signed_writable
            } else {
                i < unsigned_writable_end
            },
        });
    }
    // Runtime index order is all loaded writable keys, then all readonly keys.
    // An ALT reference is not an address and must never be treated as one.
    for writable in [true, false] {
        for lookup in &parsed.address_table_lookups {
            let indexes = if writable {
                &lookup.writable_indexes
            } else {
                &lookup.readonly_indexes
            };
            for index in indexes {
                accounts.push(AccountIdentity {
                    address: None,
                    lookup_table: Some(lookup.table_address.clone()),
                    lookup_index: Some(*index),
                    required_signer: false,
                    writable,
                });
            }
        }
    }
    if accounts.len() != parsed.total_address_count {
        return Err("account context mismatch".into());
    }
    let blockhash_offset = if parsed.wire_format == "v1" {
        8
    } else {
        header + 3 + if parsed.static_account_count < 128 { 1 } else { 2 }
            + parsed.static_account_count * 32
    };
    let blockhash = raw
        .get(blockhash_offset..blockhash_offset + 32)
        .ok_or("missing recent blockhash")?;
    Ok((accounts, sha256_hex(blockhash)))
}

fn snapshot(raw: &[u8]) -> Result<Snapshot, String> {
    let parsed = parse_transaction(raw)?;
    let (accounts, recent_blockhash_sha256) = message_context(raw, &parsed)?;
    let report = programs::from_parsed(&parsed)?;
    let mut instructions = Vec::with_capacity(parsed.instruction_count);
    let mut coverage_gap_indices = Vec::new();
    for (ix, row) in parsed
        .compiled_top_level_instructions
        .iter()
        .zip(&report.instructions)
    {
        let data = bs58::decode(&ix.data_base58)
            .into_vec()
            .map_err(|_| "invalid parsed instruction data")?;
        let identity = InstructionIdentity {
            program: accounts
                .get(ix.program_index)
                .ok_or("invalid program index")?
                .clone(),
            accounts: ix
                .account_indices
                .iter()
                .map(|&i| accounts.get(i).cloned().ok_or("invalid account index"))
                .collect::<Result<Vec<_>, _>>()?,
            data_sha256: sha256_hex(&data),
            data_bytes: data.len(),
        };
        let fingerprint_sha256 = sha256_hex(
            &serde_json::to_vec(&identity).map_err(|_| "instruction serialization failed")?,
        );
        if row.layout_status != "DECODED_DECLARATION"
            || identity.program.address.is_none()
            || identity.accounts.iter().any(|a| a.address.is_none())
        {
            coverage_gap_indices.push(ix.instruction_index);
        }
        let mut asset_movement = json!(flow::edge(row));
        let mut authority_change = json!(authority::change(row));
        // These are local summaries, not standalone reports. Remove pointers
        // to an absent standalone program_report and positional indices.
        for value in [&mut asset_movement, &mut authority_change] {
            if let Some(fields) = value.as_object_mut() {
                fields.remove("evidence_ref");
                fields.remove("instruction_index");
            }
        }
        instructions.push(InstructionSnapshot {
            identity,
            fingerprint_sha256,
            layout_status: row.layout_status,
            declaration: json!(row.declaration),
            asset_movement,
            authority_change,
        });
    }
    Ok(Snapshot {
        transaction_sha256: parsed.transaction_sha256,
        message_sha256: parsed.message_sha256,
        wire_format: parsed.wire_format,
        signature_status: json!(parsed.transaction_signature_status),
        signature_count: parsed.signature_count,
        fee_payer: parsed.static_account_keys.first().cloned(),
        required_signers: parsed.static_account_keys[..parsed.required_signatures].to_vec(),
        message_accounts: accounts,
        recent_blockhash_sha256,
        resource_config: json!(parsed.resource_config),
        instructions,
        coverage_gap_indices,
    })
}

pub fn compare(before: &[u8], after: &[u8]) -> Result<DiffReport, String> {
    let before = snapshot(before).map_err(|e| format!("before: {e}"))?;
    let after = snapshot(after).map_err(|e| format!("after: {e}"))?;
    let relation = if before.transaction_sha256 == after.transaction_sha256 {
        "IDENTICAL_TRANSACTION_BYTES"
    } else if before.message_sha256 == after.message_sha256 {
        "IDENTICAL_MESSAGE_BYTES"
    } else {
        "MESSAGE_CHANGED"
    };
    let mut message_fields_changed = Vec::new();
    if before.wire_format != after.wire_format {
        message_fields_changed.push("wire_format");
    }
    if before.fee_payer != after.fee_payer {
        message_fields_changed.push("fee_payer");
    }
    if before.required_signers != after.required_signers {
        message_fields_changed.push("required_signers");
    }
    if before.message_accounts != after.message_accounts {
        message_fields_changed.push("message_accounts");
    }
    if before.recent_blockhash_sha256 != after.recent_blockhash_sha256 {
        message_fields_changed.push("recent_blockhash");
    }
    if before.resource_config != after.resource_config {
        message_fields_changed.push("resource_config");
    }
    let fingerprints = |snapshot: &Snapshot| {
        snapshot
            .instructions
            .iter()
            .map(|ix| ix.fingerprint_sha256.clone())
            .collect::<Vec<_>>()
    };
    let mut left = fingerprints(&before);
    let mut right = fingerprints(&after);
    let ordered_instruction_fingerprints_equal = left == right;
    if !ordered_instruction_fingerprints_equal {
        message_fields_changed.push("ordered_instruction_fingerprints");
    }
    left.sort_unstable();
    right.sort_unstable();
    let instruction_multiset_equal = left == right;
    let mut instruction_changes = Vec::new();
    for index in 0..before.instructions.len().max(after.instructions.len()) {
        let a = before.instructions.get(index);
        let b = after.instructions.get(index);
        let mut fields = Vec::new();
        let status = match (a, b) {
            (Some(a), Some(b)) => {
                if a.identity.program != b.identity.program {
                    fields.push("program");
                }
                if a.identity.accounts != b.identity.accounts {
                    fields.push("accounts_or_privileges");
                }
                if a.identity.data_sha256 != b.identity.data_sha256 {
                    fields.push("instruction_data");
                }
                if a.declaration != b.declaration {
                    fields.push("decoded_declaration");
                }
                if a.asset_movement != b.asset_movement {
                    fields.push("asset_movement");
                }
                if a.authority_change != b.authority_change {
                    fields.push("authority_change");
                }
                if a.layout_status != b.layout_status {
                    fields.push("layout_status");
                }
                if fields.is_empty() {
                    continue;
                }
                "CHANGED_AT_POSITION"
            }
            (Some(_), None) => "REMOVED_AT_POSITION",
            (None, Some(_)) => "ADDED_AT_POSITION",
            (None, None) => continue,
        };
        instruction_changes.push(InstructionDiff {
            before_index: a.map(|_| index),
            after_index: b.map(|_| index),
            status,
            changed_fields: fields,
            before_ref: a.map(|_| format!("/before/instructions/{index}")),
            after_ref: b.map(|_| format!("/after/instructions/{index}")),
        });
    }
    Ok(DiffReport {
        schema_version: 1,
        kind: "hguet_transaction_diff",
        relation,
        signing_authorization: "NOT_AUTHORIZED",
        semantic_equivalence_proven: false,
        message_fields_changed,
        ordered_instruction_fingerprints_equal,
        instruction_multiset_equal,
        instruction_changes,
        before,
        after,
        limitations: vec![
            "Byte identity is not proof of safe execution or authorization.",
            "Position comparison is not an edit alignment; insertions may shift later rows.",
            "Equal multisets preserve multiplicity but do not establish equivalent order or execution.",
            "Raw instruction data is hashed, including opaque and memo payloads; hashes are not confidentiality guarantees.",
            "Account privileges are declared message flags, not verified permissions or runtime effective privileges.",
            "Lookup table references are not resolved addresses; state and CPI effects are not compared.",
            "Any message change invalidates a prior exact-message intent binding; no intent is verified here.",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn exact_identity_does_not_authorize_signing() {
        let bytes = STANDARD
            .decode(include_str!("../../../tests/fixtures/v1-system-transfer.base64").trim())
            .unwrap();
        let report = compare(&bytes, &bytes).unwrap();
        assert_eq!(report.relation, "IDENTICAL_TRANSACTION_BYTES");
        assert!(report.instruction_changes.is_empty());
        assert!(!report.semantic_equivalence_proven);
        assert_eq!(report.signing_authorization, "NOT_AUTHORIZED");
        assert!(compare(&bytes, &[255]).is_err());
    }
}
