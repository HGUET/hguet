//! Original-wire authority declarations; no account state or authorization proof.
use crate::programs::{self, AccountRole, Declaration, ProgramInstruction, ProgramReport};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AuthorityChange {
    pub instruction_index: usize,
    pub operation: String,
    pub control_scope: &'static str,
    pub action: &'static str,
    pub target: Option<String>,
    pub declared_authority: Option<String>,
    pub authority_required_signer: Option<bool>,
    pub proposed_authority: Option<String>,
    pub proposed_hook_program: Option<String>,
    pub declared_delegate_limit_raw: Option<String>,
    pub authority_type_raw: Option<u8>,
    pub recipient: Option<String>,
    pub evidence_ref: String,
}

#[derive(Debug, Serialize)]
pub struct AuthorityReport {
    pub schema_version: u8,
    pub kind: &'static str,
    pub message_sha256: String,
    pub source: &'static str,
    pub execution_proven: bool,
    pub authorization_proven: bool,
    pub signing_authorization: &'static str,
    pub changes: Vec<AuthorityChange>,
    pub unclassified_instruction_indices: Vec<usize>,
    pub program_report: ProgramReport,
    pub limitations: Vec<&'static str>,
}

fn role<'a>(row: &'a ProgramInstruction, name: &str) -> Option<&'a AccountRole> {
    row.accounts.iter().find(|a| a.role == name)
}

fn address(row: &ProgramInstruction, name: &str) -> Option<String> {
    role(row, name).and_then(|a| a.address.clone())
}

pub(crate) fn change(row: &ProgramInstruction) -> Option<AuthorityChange> {
    if row.layout_status != "DECODED_DECLARATION" {
        return None;
    }
    let mut event = AuthorityChange {
        instruction_index: row.instruction_index,
        operation: String::new(),
        control_scope: "",
        action: "",
        target: None,
        declared_authority: address(row, "authority"),
        authority_required_signer: role(row, "authority").map(|a| a.required_signer),
        proposed_authority: None,
        proposed_hook_program: None,
        declared_delegate_limit_raw: None,
        authority_type_raw: None,
        recipient: None,
        evidence_ref: format!("/program_report/instructions/{}", row.instruction_index),
    };
    match &row.declaration {
        Declaration::Token {
            operation,
            source_account,
            authority,
            delegate,
            amount_raw,
            authority_type,
            new_authority,
            destination_account,
            ..
        } => {
            event.operation = operation.clone();
            event.target = source_account.clone();
            event.declared_authority = authority.clone();
            let (scope, action) = match operation.as_str() {
                "approve" | "approve_checked" => {
                    event.proposed_authority = delegate.clone();
                    event.declared_delegate_limit_raw = amount_raw.clone();
                    ("token_delegate", "set_delegate")
                }
                "revoke" => ("token_delegate", "revoke_delegate"),
                "set_authority" => {
                    event.authority_type_raw = *authority_type;
                    event.proposed_authority = new_authority.clone();
                    let scope = match authority_type {
                        Some(0) => "mint_authority",
                        Some(1) => "freeze_authority",
                        Some(2) => "token_account_owner",
                        Some(3) => "token_close_authority",
                        _ => "unclassified_authority_type",
                    };
                    let action = if new_authority.is_some() {
                        "set_authority"
                    } else {
                        "request_authority_removal"
                    };
                    (scope, action)
                }
                "close_account" => {
                    event.recipient = destination_account.clone();
                    ("token_account", "close_account")
                }
                "freeze_account" => ("token_account_state", "freeze"),
                "thaw_account" => ("token_account_state", "thaw"),
                _ => return None,
            };
            event.control_scope = scope;
            event.action = action;
        }
        Declaration::Token2022Extension {
            operation,
            layout_checked: true,
            mint,
            authority,
            new_authority,
            hook_program_id,
            ..
        } => {
            event.operation = (*operation).into();
            event.target = mint.clone();
            event.declared_authority = authority.clone();
            event.proposed_authority = new_authority.clone();
            event.proposed_hook_program = hook_program_id.clone();
            (event.control_scope, event.action) = match *operation {
                "initialize_permanent_delegate" => ("mint_permanent_delegate", "initialize"),
                "initialize_transfer_hook" => ("mint_transfer_hook", "initialize"),
                "update_transfer_hook" => ("mint_transfer_hook", "update"),
                "set_transfer_fee" => ("mint_transfer_fee_config", "update"),
                _ => return None,
            };
        }
        Declaration::AddressLookupTable { operation, .. } => {
            event.operation = (*operation).into();
            event.target = address(row, "lookup_table");
            (event.control_scope, event.action) = match *operation {
                "create_lookup_table" => {
                    event.proposed_authority = address(row, "authority");
                    ("lookup_table", "initialize")
                }
                "extend_lookup_table" => ("lookup_table", "extend"),
                "freeze_lookup_table" => ("lookup_table", "freeze"),
                "deactivate_lookup_table" => ("lookup_table", "deactivate"),
                "close_lookup_table" => {
                    event.recipient = address(row, "recipient");
                    ("lookup_table", "close_account")
                }
                _ => return None,
            };
        }
        _ => return None,
    }
    Some(event)
}

pub fn inspect(bytes: &[u8]) -> Result<AuthorityReport, String> {
    Ok(from_program_report(programs::inspect(bytes)?))
}

pub(crate) fn from_program_report(report: ProgramReport) -> AuthorityReport {
    let mut changes = Vec::new();
    let mut unclassified_instruction_indices = Vec::new();
    for row in &report.instructions {
        if let Some(event) = change(row) {
            if event.control_scope == "unclassified_authority_type" {
                unclassified_instruction_indices.push(row.instruction_index);
            }
            changes.push(event);
        } else if row.layout_status != "DECODED_DECLARATION" {
            unclassified_instruction_indices.push(row.instruction_index);
        }
    }
    AuthorityReport {
        schema_version: 1,
        kind: "hguet_authority_intelligence",
        message_sha256: report.message_sha256.clone(),
        source: "original_wire",
        execution_proven: false,
        authorization_proven: false,
        signing_authorization: "NOT_AUTHORIZED",
        changes,
        unclassified_instruction_indices,
        program_report: report,
        limitations: vec![
            "Authority changes are original-wire declarations, not observed account state.",
            "Required signer is a message role, not a verified signature or permission.",
            "A requested removal is not proof the runtime permits it or that it is irreversible.",
            "Delegate limit is a proposed allowance, never a current debit; approvals are not additive.",
            "Unknown authority types, opaque instructions and lookup gaps do not imply absence of control changes.",
            "No ownership, multisig authorization, CPI coverage, effective hook or final state is established.",
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn transfer_is_not_an_authority_mutation() {
        let bytes = STANDARD
            .decode(
                include_str!("../../../tests/fixtures/legacy-spl-transfer-checked.base64").trim(),
            )
            .unwrap();
        let report = inspect(&bytes).unwrap();
        assert!(report.changes.is_empty());
        assert!(!report.authorization_proven);
        assert_eq!(report.signing_authorization, "NOT_AUTHORIZED");
        assert!(inspect(&[255]).is_err());
    }
}
