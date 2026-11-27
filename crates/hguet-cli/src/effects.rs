//! Original-wire declarations. Quantities never imply executed or total spending.
use serde::Serialize;

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    NativeTransfer,
    CheckedTokenTransfer,
    CheckedTokenBurn,
    DelegateApproval,
    AuthorityChange,
    AccountClosure,
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct Effect {
    pub kind: EffectKind,
    pub instruction_index: usize,
    pub source: &'static str,
    pub program_id: Option<String>,
    pub source_account: Option<String>,
    pub destination_account: Option<String>,
    pub mint: Option<String>,
    pub authority: Option<String>,
    pub delegate: Option<String>,
    pub new_authority: Option<String>,
    pub authority_type: Option<u8>,
    pub amount_raw: Option<String>,
    pub expected_fee_raw: Option<String>,
    pub evidence_ref: String,
    pub limitations: Vec<String>,
}

pub fn original_wire(bytes: &[u8]) -> Vec<Effect> {
    let Ok(parsed) = hguet_core::parse_transaction(bytes) else {
        return vec![];
    };
    from_parsed(&parsed)
}

pub(crate) fn from_parsed(parsed: &hguet_core::ParsedTransaction) -> Vec<Effect> {
    let direct = hguet_rpc::inspect_direct_tokens(parsed, None).ok();
    let mut effects = Vec::new();
    for ix in &parsed.compiled_top_level_instructions {
        let mut effect=Effect {
            kind:EffectKind::Unknown,instruction_index:ix.instruction_index,source:"original_wire",
            program_id:parsed.program_ids.get(ix.instruction_index).cloned(),
            source_account:None,destination_account:None,mint:None,authority:None,amount_raw:None,delegate:None,new_authority:None,authority_type:None,expected_fee_raw:None,
            evidence_ref:format!("/evidence/inspection/compiled_top_level_instructions/{}",ix.instruction_index),
            limitations:vec!["Declared instruction bytes do not prove execution, account ownership or total spending.".into()],
        };
        if let Some(sol) = parsed
            .system_transfers
            .iter()
            .find(|s| s.instruction_index == ix.instruction_index)
        {
            effect.kind = EffectKind::NativeTransfer;
            effect.source_account = parsed
                .static_account_keys
                .contains(&sol.source)
                .then(|| sol.source.clone());
            effect.destination_account = parsed
                .static_account_keys
                .contains(&sol.destination)
                .then(|| sol.destination.clone());
            if effect.destination_account.is_none() || effect.source_account.is_none() {
                effect
                    .limitations
                    .push("Account identity requires unresolved ALT state.".into());
            }
            effect.amount_raw = Some(sol.lamports.clone());
        } else if let Some(token) = direct.as_ref().and_then(|d| {
            d.recognized
                .iter()
                .find(|t| t.instruction_index == ix.instruction_index)
        }) {
            let t = &token.decoded;
            effect.kind = match t.operation.as_str() {
                "transfer_checked" | "transfer_checked_with_fee" => {
                    EffectKind::CheckedTokenTransfer
                }
                "burn_checked" => EffectKind::CheckedTokenBurn,
                "approve" | "approve_checked" => EffectKind::DelegateApproval,
                "set_authority" => EffectKind::AuthorityChange,
                "close_account" => EffectKind::AccountClosure,
                _ => EffectKind::Unknown,
            };
            effect.source_account = t.source_account.clone();
            effect.destination_account = t.destination_account.clone();
            effect.delegate = t.delegate.clone();
            effect.new_authority = t.new_authority.clone();
            effect.authority_type = t.authority_type;
            effect.mint = t.mint.clone();
            effect.authority = t.authority.clone();
            effect.amount_raw = t.amount_raw.clone();
        }
        if let Some(hint) = direct
            .as_ref()
            .and_then(|analysis| {
                analysis
                    .opaque
                    .iter()
                    .find(|item| item.instruction_index == ix.instruction_index)
            })
            .and_then(|item| item.extension_hint.as_ref())
            .filter(|hint| hint.layout_checked && hint.operation == "transfer_checked_with_fee")
        {
            effect.kind = EffectKind::CheckedTokenTransfer;
            effect.source_account = hint.source_account.clone();
            effect.mint = hint.mint.clone();
            effect.authority = hint.authority.clone();
            effect.amount_raw = hint.declared_amount_raw.clone();
            effect.expected_fee_raw = hint.expected_fee_raw.clone();
            effect.destination_account = ix
                .account_indices
                .get(2)
                .and_then(|index| parsed.static_account_keys.get(*index))
                .cloned();
            effect.limitations.push("Expected fee is declared in wire bytes; actual fees require mint state and execution.".into());
        }
        if effect.kind == EffectKind::Unknown {
            effect.limitations.push(
                "Instruction semantics are unsupported or unresolved in this effect model.".into(),
            );
        }
        effects.push(effect);
    }
    effects
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn existing_wire_fixtures_keep_raw_amounts_and_provenance() {
        let fixtures = [
            (
                include_str!("../../../tests/fixtures/v1-system-transfer.base64"),
                EffectKind::NativeTransfer,
                "500",
            ),
            (
                include_str!("../../../tests/fixtures/legacy-spl-transfer-checked.base64"),
                EffectKind::CheckedTokenTransfer,
                "1234",
            ),
        ];
        for (wire, kind, amount) in fixtures {
            let effects = original_wire(&STANDARD.decode(wire.trim()).unwrap());
            assert_eq!(effects.len(), 1);
            assert_eq!(effects[0].kind, kind);
            assert_eq!(effects[0].amount_raw.as_deref(), Some(amount));
            assert_eq!(effects[0].source, "original_wire");
            assert!(!effects[0].limitations.is_empty());
        }
    }
}
