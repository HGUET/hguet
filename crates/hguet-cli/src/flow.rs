//! Offline asset declarations. Never net them against runtime observations.
use crate::programs::{self, Declaration, ProgramInstruction, ProgramReport};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Asset {
    pub kind: &'static str,
    pub token_program: Option<String>,
    pub mint: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Endpoint {
    pub message_index: usize,
    pub address: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FlowEdge {
    pub instruction_index: usize,
    pub operation: String,
    pub category: &'static str,
    pub source: &'static str,
    pub asset: Asset,
    pub from: Option<Endpoint>,
    pub to: Option<Endpoint>,
    pub amount_raw: String,
    pub declared_decimals: Option<u8>,
    pub expected_fee_raw: Option<String>,
    pub evidence_ref: String,
}

#[derive(Debug, Serialize)]
pub struct AssetTotal {
    pub asset: Asset,
    pub instruction_indices: Vec<usize>,
    pub declared_debit_raw: String,
    pub declared_transfer_raw: String,
    pub declared_funding_raw: String,
    pub declared_nonce_withdrawal_raw: String,
    pub declared_mint_raw: String,
    pub declared_burn_raw: String,
    pub declared_expected_fee_raw: Option<String>,
    pub expected_fee_instruction_count: usize,
    pub declared_decimals: Vec<u8>,
    pub conflicting_declared_decimals: bool,
}

#[derive(Debug, Default)]
struct Totals {
    indices: Vec<usize>,
    debit: u128,
    transfer: u128,
    funding: u128,
    nonce: u128,
    mint: u128,
    burn: u128,
    fee: u128,
    fee_count: usize,
    decimals: BTreeSet<u8>,
}

#[derive(Debug, Serialize)]
pub struct FlowReport {
    pub schema_version: u8,
    pub kind: &'static str,
    pub source: &'static str,
    pub message_sha256: String,
    pub execution_status: &'static str,
    pub signing_authorization: &'static str,
    pub flows: Vec<FlowEdge>,
    pub asset_totals: Vec<AssetTotal>,
    pub unknown_asset_instruction_indices: Vec<usize>,
    pub unresolved_endpoint_instruction_indices: Vec<usize>,
    pub unquantified_instruction_indices: Vec<usize>,
    pub actual_network_fee_lamports: Option<String>,
    pub observed_net_changes: Option<()>,
    pub program_report: ProgramReport,
    pub limitations: Vec<&'static str>,
}

fn endpoint(row: &ProgramInstruction, role: &str) -> Option<Endpoint> {
    row.accounts
        .iter()
        .find(|account| account.role == role)
        .map(|account| Endpoint {
            message_index: account.message_index,
            address: account.address.clone(),
        })
}

fn token_asset(row: &ProgramInstruction, mint: &Option<String>) -> Asset {
    Asset {
        kind: "token",
        token_program: row.program_id.clone(),
        mint: mint.clone(),
    }
}

fn edge(row: &ProgramInstruction) -> Option<FlowEdge> {
    let (operation, category, asset, from, to, amount, decimals, fee) = match &row.declaration {
        Declaration::SystemMovement {
            operation,
            lamports,
        } => {
            let (category, from_role, to_role) = match *operation {
                "transfer" | "transfer_with_seed" => ("transfer", "source", "destination"),
                "create_account" | "create_account_with_seed" => {
                    ("funding", "funding_account", "new_account")
                }
                "withdraw_nonce_account" => ("nonce_withdrawal", "nonce_account", "recipient"),
                _ => return None,
            };
            (
                *operation,
                category,
                Asset {
                    kind: "sol",
                    token_program: None,
                    mint: None,
                },
                endpoint(row, from_role),
                endpoint(row, to_role),
                lamports,
                None,
                None,
            )
        }
        Declaration::Token {
            operation,
            mint,
            amount_raw: Some(amount),
            decimals,
            ..
        } => {
            let (category, from, to) = match operation.as_str() {
                "transfer" | "transfer_checked" => (
                    "transfer",
                    endpoint(row, "source"),
                    endpoint(row, "destination"),
                ),
                "mint_to" | "mint_to_checked" => ("mint", None, endpoint(row, "destination")),
                "burn" | "burn_checked" => ("burn", endpoint(row, "source"), None),
                _ => return None,
            };
            (
                operation.as_str(),
                category,
                token_asset(row, mint),
                from,
                to,
                amount,
                *decimals,
                None,
            )
        }
        Declaration::Token2022Extension {
            operation: "transfer_checked_with_fee",
            layout_checked: true,
            mint,
            declared_amount_raw: Some(amount),
            decimals,
            expected_fee_raw,
            ..
        } => (
            "transfer_checked_with_fee",
            "transfer",
            token_asset(row, mint),
            endpoint(row, "source"),
            endpoint(row, "destination"),
            amount,
            *decimals,
            expected_fee_raw.clone(),
        ),
        _ => return None,
    };
    Some(FlowEdge {
        instruction_index: row.instruction_index,
        operation: operation.to_owned(),
        category,
        source: "original_wire",
        asset,
        from,
        to,
        amount_raw: amount.clone(),
        declared_decimals: decimals,
        expected_fee_raw: fee,
        evidence_ref: format!("/program_report/instructions/{}", row.instruction_index),
    })
}

fn quantity(raw: &str) -> Result<u128, String> {
    raw.parse::<u64>()
        .map(u128::from)
        .map_err(|_| "invalid raw declaration quantity".to_owned())
}

/// At most one quantity edge per original instruction. Mint/burn are supply
/// changes, not transfers between invented accounts. No fee is added to debit.
pub fn inspect(bytes: &[u8]) -> Result<FlowReport, String> {
    let report = programs::inspect(bytes)?;
    let mut flows = Vec::new();
    let mut totals = BTreeMap::<Asset, Totals>::new();
    let mut unknown_asset_instruction_indices = Vec::new();
    let mut unresolved_endpoint_instruction_indices = Vec::new();
    let mut unquantified_instruction_indices = Vec::new();
    for row in &report.instructions {
        let Some(flow) = edge(row) else {
            if !matches!(
                row.declaration,
                Declaration::Memo { .. } | Declaration::ComputeBudget { .. }
            ) {
                unquantified_instruction_indices.push(row.instruction_index);
            }
            continue;
        };
        let amount = quantity(&flow.amount_raw)?;
        if (flow.category != "mint" && flow.from.as_ref().is_none_or(|a| a.address.is_none()))
            || (flow.category != "burn" && flow.to.as_ref().is_none_or(|a| a.address.is_none()))
        {
            unresolved_endpoint_instruction_indices.push(flow.instruction_index);
        }
        if flow.asset.kind == "token" && flow.asset.mint.is_none() {
            // Unchecked transfers cannot be grouped by a guessed mint.
            unknown_asset_instruction_indices.push(flow.instruction_index);
        } else {
            let total = totals.entry(flow.asset.clone()).or_default();
            total.indices.push(flow.instruction_index);
            // At most 64 u64 declarations, so u128 totals cannot overflow.
            match flow.category {
                "transfer" => total.transfer += amount,
                "funding" => total.funding += amount,
                "nonce_withdrawal" => total.nonce += amount,
                "mint" => total.mint += amount,
                "burn" => total.burn += amount,
                _ => return Err("unsupported flow category".into()),
            }
            if flow.category != "mint" {
                total.debit += amount;
            }
            if let Some(raw) = &flow.expected_fee_raw {
                total.fee += quantity(raw)?;
                total.fee_count += 1;
            }
            if let Some(decimals) = flow.declared_decimals {
                total.decimals.insert(decimals);
            }
        }
        flows.push(flow);
    }
    let asset_totals = totals
        .into_iter()
        .map(|(asset, total)| AssetTotal {
            asset,
            instruction_indices: total.indices,
            declared_debit_raw: total.debit.to_string(),
            declared_transfer_raw: total.transfer.to_string(),
            declared_funding_raw: total.funding.to_string(),
            declared_nonce_withdrawal_raw: total.nonce.to_string(),
            declared_mint_raw: total.mint.to_string(),
            declared_burn_raw: total.burn.to_string(),
            declared_expected_fee_raw: (total.fee_count > 0).then(|| total.fee.to_string()),
            expected_fee_instruction_count: total.fee_count,
            conflicting_declared_decimals: total.decimals.len() > 1,
            declared_decimals: total.decimals.into_iter().collect(),
        })
        .collect();
    Ok(FlowReport {
        schema_version: 1,
        kind: "hguet_asset_flow",
        source: "original_wire",
        message_sha256: report.message_sha256.clone(),
        execution_status: "NOT_PERFORMED",
        signing_authorization: "NOT_AUTHORIZED",
        flows,
        asset_totals,
        unknown_asset_instruction_indices,
        unresolved_endpoint_instruction_indices,
        unquantified_instruction_indices,
        actual_network_fee_lamports: None,
        observed_net_changes: None,
        program_report: report,
        limitations: vec![
            "Gross declared quantities are not executed transfers, net losses or wallet spending.",
            "Only known mint and program pairs are grouped; no guessed mint for unchecked transfers.",
            "Mint and burn are supply declarations; expected fees are included in transfer amounts, not added to debit.",
            "Missing quantities are unknown, not zero. Zero subtotals mean no decoded declarations in that category.",
            "Self-transfers, repeated transfers and incoming credits are not netted or deduplicated.",
            "CPI, hooks, actual fees, rent, account state and total execution effects are not established.",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn known_system_and_token_fixtures_are_distinct_declarations() {
        for (fixture, asset, amount) in [
            (
                include_str!("../../../tests/fixtures/v1-system-transfer.base64"),
                "sol",
                "500",
            ),
            (
                include_str!("../../../tests/fixtures/legacy-spl-transfer-checked.base64"),
                "token",
                "1234",
            ),
        ] {
            let report = inspect(&STANDARD.decode(fixture.trim()).unwrap()).unwrap();
            assert_eq!(report.flows.len(), 1);
            assert_eq!(report.asset_totals.len(), 1);
            assert_eq!(report.asset_totals[0].asset.kind, asset);
            assert_eq!(report.asset_totals[0].declared_debit_raw, amount);
            assert_eq!(report.signing_authorization, "NOT_AUTHORIZED");
            assert!(report.observed_net_changes.is_none());
            let value = serde_json::to_value(report).unwrap();
            let pointer = value["flows"][0]["evidence_ref"].as_str().unwrap();
            assert!(value.pointer(pointer).is_some());
        }
    }

    #[test]
    fn invalid_wire_is_not_an_empty_flow_report() {
        assert!(inspect(&[0xff]).is_err());
    }
}
