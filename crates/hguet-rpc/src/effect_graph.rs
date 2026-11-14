//! Deterministic, bounded *evidence correlation* graph for one Solana RPC.
//!
//! Distinguishes (1) declarations decoded from original transaction bytes,
//! (2) claims returned by simulateTransaction and (3) later, separate RPC
//! account/mint snapshots. Graph edges NEVER prove gross spending, causality,
//! account authorization, atomic state or final transaction execution.
use crate::{
    direct_token::DirectTokenAnalysis, effects::SimulationEffects, mint_rpc::MintRpcSnapshot,
    token_account_rpc::TokenAccountRpcSnapshot, RpcError,
};
use hguet_core::ParsedTransaction;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const MAX_NODES: usize = 512;
const MAX_EDGES: usize = 1024;

#[derive(Debug, Clone, Serialize)]
pub struct EffectNode {
    pub id: String,
    /// account, mint, authority, program, asset
    pub kind: &'static str,
    pub address_or_asset: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct EffectEdge {
    pub source_node: String,
    pub target_node: String,
    pub relation: &'static str,
    /// Signed delta for balance snapshots, unsigned declared amount for
    /// instructions, or None for pure role/state relationships.
    pub amount_raw: Option<String>,
    pub mint: Option<String>,
    pub source: &'static str,
    pub context_slot: Option<u64>,
    pub top_level_instruction: Option<usize>,
    pub inner_instruction: Option<usize>,
    /// Always declared_only, rpc_observed or later_non_atomic_state.
    /// Never verified_execution.
    pub attribution: &'static str,
}
#[derive(Debug, Clone, Serialize)]
pub struct GraphSourceSlot {
    pub source: &'static str,
    pub context_slot: u64,
    pub atomic_with_simulation: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct EffectGraph {
    pub version: u32,
    pub simulation_status: String,
    pub nodes: Vec<EffectNode>,
    pub edges: Vec<EffectEdge>,
    pub sources: Vec<GraphSourceSlot>,
    pub evidence_gaps: Vec<&'static str>,
    pub alerts: Vec<&'static str>,
    pub execution_proven: bool,
    pub spend_limit_enforced: bool,
    pub security_coverage: &'static str,
    pub limitation: &'static str,
}
struct Builder {
    nodes: BTreeMap<String, EffectNode>,
    edges: Vec<EffectEdge>,
    gaps: BTreeSet<&'static str>,
    alerts: BTreeSet<&'static str>,
}
fn valid_address(value: &str) -> bool {
    bs58::decode(value)
        .into_vec()
        .map(|bytes| bytes.len() == 32)
        .unwrap_or(false)
}
impl Builder {
    fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            edges: vec![],
            gaps: BTreeSet::new(),
            alerts: BTreeSet::new(),
        }
    }
    fn node(&mut self, kind: &'static str, value: &str) -> Result<String, RpcError> {
        if kind != "asset" && !valid_address(value) {
            return Err(RpcError::InvalidResponse);
        }
        let id = format!("{kind}:{value}");
        if !self.nodes.contains_key(&id) && self.nodes.len() >= MAX_NODES {
            return Err(RpcError::TooLarge);
        }
        self.nodes.entry(id.clone()).or_insert_with(|| EffectNode {
            id: id.clone(),
            kind,
            address_or_asset: value.into(),
        });
        Ok(id)
    }
    #[allow(clippy::too_many_arguments)]
    fn edge(
        &mut self,
        from: (&'static str, &str),
        to: (&'static str, &str),
        relation: &'static str,
        amount_raw: Option<String>,
        mint: Option<String>,
        source: &'static str,
        context_slot: Option<u64>,
        top_level_instruction: Option<usize>,
        inner_instruction: Option<usize>,
        attribution: &'static str,
    ) -> Result<(), RpcError> {
        if self.edges.len() >= MAX_EDGES {
            return Err(RpcError::TooLarge);
        }
        let source_node = self.node(from.0, from.1)?;
        let target_node = self.node(to.0, to.1)?;
        self.edges.push(EffectEdge {
            source_node,
            target_node,
            relation,
            amount_raw,
            mint,
            source,
            context_slot,
            top_level_instruction,
            inner_instruction,
            attribution,
        });
        Ok(())
    }
    fn finish(self, status: &str, sources: Vec<GraphSourceSlot>) -> EffectGraph {
        EffectGraph {
            version:1,simulation_status:status.into(),
            nodes:self.nodes.into_values().collect(),edges:self.edges,
            sources,evidence_gaps:self.gaps.into_iter().collect(),
            alerts:self.alerts.into_iter().collect(),
            execution_proven:false,spend_limit_enforced:false,
            security_coverage:"partial_untrusted_rpc",
            limitation:"Correlation is evidence indexing, not causality. A simulated net delta cannot be assigned to a specific CPI instruction; mint/account state from later RPC slots is not the simulated execution bank. No ALLOW or full spend bound is established.",
        }
    }
}
/// Do not call on an unparsed wire payload. All inputs have already passed the
/// local parser and strict bounded RPC decoders. One graph represents ONE
/// simulation and its later single-provider observations.
pub fn correlate_effects(
    parsed: &ParsedTransaction,
    status: &str,
    simulation_slot: u64,
    effects: &SimulationEffects,
    direct_token: Option<&DirectTokenAnalysis>,
    mint_snapshot: Option<&MintRpcSnapshot>,
    token_account_snapshot: Option<&TokenAccountRpcSnapshot>,
) -> Result<EffectGraph, RpcError> {
    if simulation_slot == 0 {
        return Err(RpcError::InvalidResponse);
    }
    let mut b = Builder::new();
    let mut sources = vec![GraphSourceSlot {
        source: "rpc_simulation",
        context_slot: simulation_slot,
        atomic_with_simulation: true, // same RPC simulation response, NOT a consensus proof
    }];
    // Program list and direct System transfers are decoded from ORIGINAL
    // wire bytes; never conflate them with RPC-executed instructions.
    for program in &parsed.program_ids {
        if valid_address(program) {
            b.node("program", program)?;
        } else {
            b.gaps.insert("wire_program_address_unresolved");
        }
    }
    for transfer in &parsed.system_transfers {
        if !valid_address(&transfer.source) || !valid_address(&transfer.destination) {
            b.gaps.insert("wire_native_transfer_address_unresolved");
            continue;
        }
        b.edge(
            ("account", &transfer.source),
            ("account", &transfer.destination),
            "declared_system_transfer",
            Some(transfer.lamports.clone()),
            None,
            "original_wire",
            None,
            Some(transfer.instruction_index),
            None,
            "declared_only",
        )?;
    }
    // Direct SPL Token instructions are declarations from the original wire.
    // They must be represented even when RPC simulation reports failure.
    if let Some(direct) = direct_token {
        for item in &direct.opaque {
            b.gaps.insert("opaque_direct_token_instruction");
            b.alerts.insert("GRAPH_DIRECT_TOKEN_OPAQUE");
            if item.token_2022_extension {
                b.gaps.insert("opaque_direct_token_2022_extension");
            }
            if item.program_address_from_lookup {
                b.gaps.insert("direct_token_program_from_untrusted_alt");
            }
        }
        for item in &direct.recognized {
            if item.program_address_from_lookup {
                b.gaps.insert("direct_token_program_from_untrusted_alt");
            }
            if item.account_addresses_from_lookup {
                b.gaps.insert("direct_token_account_from_untrusted_alt");
            }
            let decoded = &item.decoded;
            let index = Some(item.instruction_index);
            match decoded.operation.as_str() {
                "transfer" | "transfer_checked" => {
                    if let (Some(src), Some(dst)) =
                        (&decoded.source_account, &decoded.destination_account)
                    {
                        b.edge(
                            ("account", src),
                            ("account", dst),
                            "wire_declared_token_transfer",
                            decoded.amount_raw.clone(),
                            decoded.mint.clone(),
                            "original_wire",
                            None,
                            index,
                            None,
                            "declared_only",
                        )?;
                        b.alerts.insert("GRAPH_DIRECT_TOKEN_MOVEMENT");
                        if decoded.mint.is_none() {
                            b.gaps.insert("unchecked_direct_token_mint_not_declared");
                        }
                    } else {
                        b.gaps.insert("direct_token_account_role_missing");
                    }
                }
                "mint_to" | "mint_to_checked" => {
                    if let (Some(mint), Some(dst)) = (&decoded.mint, &decoded.destination_account) {
                        b.edge(
                            ("mint", mint),
                            ("account", dst),
                            "wire_declared_token_mint",
                            decoded.amount_raw.clone(),
                            Some(mint.clone()),
                            "original_wire",
                            None,
                            index,
                            None,
                            "declared_only",
                        )?;
                        b.alerts.insert("GRAPH_DIRECT_TOKEN_MOVEMENT");
                    } else {
                        b.gaps.insert("direct_token_account_role_missing");
                    }
                }
                "burn" | "burn_checked" => {
                    if let (Some(src), Some(mint)) = (&decoded.source_account, &decoded.mint) {
                        b.edge(
                            ("account", src),
                            ("mint", mint),
                            "wire_declared_token_burn",
                            decoded.amount_raw.clone(),
                            Some(mint.clone()),
                            "original_wire",
                            None,
                            index,
                            None,
                            "declared_only",
                        )?;
                        b.alerts.insert("GRAPH_DIRECT_TOKEN_MOVEMENT");
                    } else {
                        b.gaps.insert("direct_token_account_role_missing");
                    }
                }
                "approve" | "approve_checked" => {
                    if let (Some(src), Some(delegate)) =
                        (&decoded.source_account, &decoded.delegate)
                    {
                        b.edge(
                            ("account", src),
                            ("authority", delegate),
                            "wire_declared_token_approval",
                            decoded.amount_raw.clone(),
                            decoded.mint.clone(),
                            "original_wire",
                            None,
                            index,
                            None,
                            "declared_only",
                        )?;
                    } else {
                        b.gaps.insert("direct_token_account_role_missing");
                    }
                    b.alerts.insert("GRAPH_DIRECT_TOKEN_AUTHORITY");
                }
                "set_authority" | "close_account" | "revoke" | "freeze_account"
                | "thaw_account" => {
                    if let Some(src) = &decoded.source_account {
                        if let Some(authority) = &decoded.new_authority {
                            b.edge(
                                ("account", src),
                                ("authority", authority),
                                "wire_declared_token_new_authority",
                                None,
                                decoded.mint.clone(),
                                "original_wire",
                                None,
                                index,
                                None,
                                "declared_only",
                            )?;
                        }
                        if let Some(authority) = &decoded.authority {
                            b.edge(
                                ("account", src),
                                ("authority", authority),
                                "wire_declared_token_authority_operation",
                                None,
                                decoded.mint.clone(),
                                "original_wire",
                                None,
                                index,
                                None,
                                "declared_only",
                            )?;
                        }
                        if decoded.operation == "close_account" {
                            if let Some(dst) = &decoded.destination_account {
                                b.edge(
                                    ("account", src),
                                    ("account", dst),
                                    "wire_declared_token_close_destination",
                                    None,
                                    decoded.mint.clone(),
                                    "original_wire",
                                    None,
                                    index,
                                    None,
                                    "declared_only",
                                )?;
                            }
                        }
                    } else {
                        b.gaps.insert("direct_token_account_role_missing");
                    }
                    b.alerts.insert("GRAPH_DIRECT_TOKEN_AUTHORITY");
                }
                "sync_native" => {}
                _ => {
                    b.gaps.insert("direct_token_operation_not_correlated");
                }
            }
        }
    }
    if status != "rpc_succeeded" {
        b.gaps.insert("rpc_simulation_failed_no_effect_attribution");
        return Ok(b.finish(status, sources));
    }
    match &effects.lamport_deltas {
        Some(rows) => {
            for row in rows {
                b.edge(
                    ("account", &row.address),
                    ("asset", "SOL"),
                    "simulated_native_net_delta",
                    Some(row.delta_lamports.clone()),
                    None,
                    "rpc_paired_balances",
                    Some(simulation_slot),
                    None,
                    None,
                    "rpc_observed",
                )?;
            }
        }
        None => {
            b.gaps.insert("rpc_paired_native_balances_unavailable");
        }
    }
    match &effects.token_deltas {
        Some(rows) => {
            for row in rows {
                b.edge(
                    ("account", &row.token_account),
                    ("mint", &row.mint),
                    if row.complete_pair {
                        "simulated_token_net_delta"
                    } else {
                        "simulated_token_partial_balance"
                    },
                    row.delta_raw_amount.clone(),
                    Some(row.mint.clone()),
                    "rpc_token_balances",
                    Some(simulation_slot),
                    None,
                    None,
                    "rpc_observed",
                )?;
                if let Some(owner) = &row.owner {
                    b.edge(
                        ("account", &row.token_account),
                        ("authority", owner),
                        "simulated_token_owner_claim",
                        None,
                        Some(row.mint.clone()),
                        "rpc_token_balances",
                        Some(simulation_slot),
                        None,
                        None,
                        "rpc_observed",
                    )?;
                }
                if !row.complete_pair {
                    b.gaps.insert("token_balance_pair_incomplete");
                }
            }
        }
        None => {
            b.gaps.insert("rpc_paired_token_balances_unavailable");
        }
    }
    if !effects.cpi.captured {
        b.gaps.insert("rpc_cpi_recording_missing");
    }
    if effects.cpi.opaque_token_instruction_count > 0 {
        b.gaps.insert("opaque_token_cpi_semantics_unresolved");
        b.alerts.insert("GRAPH_OPAQUE_CPI_EFFECTS");
    }
    for item in &effects.cpi.token_instructions {
        let ix = Some(item.parent_instruction_index);
        let inner = Some(item.inner_instruction_index);
        match item.operation.as_str() {
            "transfer" | "transfer_checked" => {
                if let (Some(src), Some(dst)) = (&item.source_account, &item.destination_account) {
                    b.edge(
                        ("account", src),
                        ("account", dst),
                        "cpi_declared_token_transfer",
                        item.amount_raw.clone(),
                        item.mint.clone(),
                        "rpc_compiled_cpi",
                        Some(simulation_slot),
                        ix,
                        inner,
                        "rpc_observed",
                    )?;
                    b.alerts.insert("GRAPH_CPI_NET_ATTRIBUTION_UNPROVEN");
                } else {
                    b.gaps.insert("cpi_account_role_missing");
                }
            }
            "mint_to" | "mint_to_checked" => {
                if let (Some(mint), Some(dst)) = (&item.mint, &item.destination_account) {
                    b.edge(
                        ("mint", mint),
                        ("account", dst),
                        "cpi_declared_token_mint",
                        item.amount_raw.clone(),
                        Some(mint.clone()),
                        "rpc_compiled_cpi",
                        Some(simulation_slot),
                        ix,
                        inner,
                        "rpc_observed",
                    )?;
                    b.alerts.insert("GRAPH_CPI_NET_ATTRIBUTION_UNPROVEN");
                } else {
                    b.gaps.insert("cpi_account_role_missing");
                }
            }
            "burn" | "burn_checked" => {
                if let (Some(src), Some(mint)) = (&item.source_account, &item.mint) {
                    b.edge(
                        ("account", src),
                        ("mint", mint),
                        "cpi_declared_token_burn",
                        item.amount_raw.clone(),
                        Some(mint.clone()),
                        "rpc_compiled_cpi",
                        Some(simulation_slot),
                        ix,
                        inner,
                        "rpc_observed",
                    )?;
                    b.alerts.insert("GRAPH_CPI_NET_ATTRIBUTION_UNPROVEN");
                } else {
                    b.gaps.insert("cpi_account_role_missing");
                }
            }
            "approve" | "approve_checked" => {
                if let (Some(src), Some(delegate)) = (&item.source_account, &item.delegate) {
                    b.edge(
                        ("account", src),
                        ("authority", delegate),
                        "cpi_declared_delegation",
                        item.amount_raw.clone(),
                        item.mint.clone(),
                        "rpc_compiled_cpi",
                        Some(simulation_slot),
                        ix,
                        inner,
                        "rpc_observed",
                    )?;
                    b.alerts.insert("GRAPH_CPI_AUTHORITY_CONTROL");
                } else {
                    b.gaps.insert("cpi_account_role_missing");
                }
            }
            "set_authority" | "revoke" | "close_account" | "freeze_account" | "thaw_account" => {
                if let (Some(src), Some(auth)) = (&item.source_account, &item.authority) {
                    b.edge(
                        ("account", src),
                        ("authority", auth),
                        "cpi_declared_authority_operation",
                        None,
                        item.mint.clone(),
                        "rpc_compiled_cpi",
                        Some(simulation_slot),
                        ix,
                        inner,
                        "rpc_observed",
                    )?;
                } else {
                    b.gaps.insert("cpi_account_role_missing");
                }
                b.alerts.insert("GRAPH_CPI_AUTHORITY_CONTROL");
            }
            "sync_native" => {}
            _ => {
                b.gaps.insert("cpi_operation_not_correlated");
            }
        }
    }
    if !effects.cpi.token_2022_extension_observations.is_empty() {
        b.gaps
            .insert("token_2022_extension_state_dependent_effects");
    }
    if let Some(mints) = mint_snapshot {
        if mints.simulation_slot != simulation_slot
            || mints.context_slot < simulation_slot
            || mints.atomic_with_simulation
        {
            return Err(RpcError::InvalidResponse);
        }
        sources.push(GraphSourceSlot {
            source: "rpc_mint_snapshot",
            context_slot: mints.context_slot,
            atomic_with_simulation: false,
        });
        b.gaps.insert("mint_snapshot_not_atomic_with_simulation");
        for item in &mints.accounts {
            b.node("mint", &item.address)?;
            match &item.state {
                None => {
                    b.gaps.insert("mint_account_state_unavailable");
                }
                Some(state) => {
                    if state.mint_address != item.address {
                        return Err(RpcError::InvalidResponse);
                    }
                    if let Some(hook) = state.hook.as_ref().and_then(|h| h.program_id.as_ref()) {
                        b.edge(
                            ("mint", &item.address),
                            ("program", hook),
                            "mint_snapshot_transfer_hook_program",
                            None,
                            Some(item.address.clone()),
                            "rpc_later_mint_account",
                            Some(mints.context_slot),
                            None,
                            None,
                            "later_non_atomic_state",
                        )?;
                        b.alerts.insert("GRAPH_MINT_TRANSFER_HOOK");
                    }
                    if let Some(delegate) = &state.permanent_delegate {
                        b.edge(
                            ("mint", &item.address),
                            ("authority", delegate),
                            "mint_snapshot_permanent_delegate",
                            None,
                            Some(item.address.clone()),
                            "rpc_later_mint_account",
                            Some(mints.context_slot),
                            None,
                            None,
                            "later_non_atomic_state",
                        )?;
                        b.alerts.insert("GRAPH_MINT_PERMANENT_DELEGATE");
                    }
                    if state.fee_config.is_some() {
                        b.alerts.insert("GRAPH_MINT_TRANSFER_FEE");
                    }
                    if state.confidential_extension_present
                        || state.unknown_extension_count > 0
                        || state.extensions.iter().any(|ext| !ext.layout_checked)
                    {
                        b.gaps.insert("opaque_mint_extension_state");
                    }
                }
            }
        }
    } else if effects.token_deltas.as_ref().is_some_and(|v| !v.is_empty()) {
        b.gaps.insert("mint_snapshot_missing_for_token_activity");
    }
    if let Some(accounts) = token_account_snapshot {
        if accounts.simulation_slot != simulation_slot
            || accounts.context_slot < simulation_slot
            || accounts.atomic_with_simulation
        {
            return Err(RpcError::InvalidResponse);
        }
        sources.push(GraphSourceSlot {
            source: "rpc_token_account_snapshot",
            context_slot: accounts.context_slot,
            atomic_with_simulation: false,
        });
        b.gaps
            .insert("holding_account_snapshot_not_atomic_with_simulation");
        for item in &accounts.accounts {
            b.node("account", &item.address)?;
            if item.mint_matches_simulation_report == Some(false) {
                b.alerts.insert("GRAPH_ACCOUNT_MINT_DISAGREEMENT");
            }
            if item.authority_matches_simulation_report == Some(false) {
                b.alerts.insert("GRAPH_ACCOUNT_AUTHORITY_DISAGREEMENT");
            }
            match &item.state {
                None => {
                    b.gaps.insert("holding_account_state_unavailable");
                }
                Some(state) => {
                    if state.token_account != item.address {
                        return Err(RpcError::InvalidResponse);
                    }
                    b.edge(
                        ("account", &item.address),
                        ("mint", &state.mint),
                        "holding_account_snapshot_mint",
                        None,
                        Some(state.mint.clone()),
                        "rpc_later_token_account",
                        Some(accounts.context_slot),
                        None,
                        None,
                        "later_non_atomic_state",
                    )?;
                    b.edge(
                        ("account", &item.address),
                        ("authority", &state.token_authority),
                        "holding_account_snapshot_owner",
                        None,
                        Some(state.mint.clone()),
                        "rpc_later_token_account",
                        Some(accounts.context_slot),
                        None,
                        None,
                        "later_non_atomic_state",
                    )?;
                    if let Some(delegate) = &state.delegate {
                        b.edge(
                            ("account", &item.address),
                            ("authority", delegate),
                            "holding_account_snapshot_delegate",
                            Some(state.delegated_amount_raw.clone()),
                            Some(state.mint.clone()),
                            "rpc_later_token_account",
                            Some(accounts.context_slot),
                            None,
                            None,
                            "later_non_atomic_state",
                        )?;
                        b.alerts.insert("GRAPH_HOLDING_DELEGATE");
                    }
                    if state.account_state == "frozen" || state.non_transferable_account {
                        b.alerts.insert("GRAPH_HOLDING_TRANSFER_RESTRICTION");
                    }
                    if state.confidential_extension_present || state.opaque_extension_count > 0 {
                        b.gaps.insert("opaque_holding_extension_state");
                    }
                    if !item.matching_mint_state_observed {
                        b.gaps.insert("holding_mint_state_not_correlated");
                    }
                }
            }
        }
    } else if effects.token_deltas.as_ref().is_some_and(|v| !v.is_empty()) {
        b.gaps.insert("holding_snapshot_missing_for_token_activity");
    }
    // Even all present edges are only separately scoped evidence. No amounts
    // are reconciled across operations: gross token movement, CPI fee and hook
    // effects cannot be proven from net account balances.
    b.gaps
        .insert("full_execution_and_gross_spending_unverified");
    Ok(b.finish(status, sources))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        effects::{CpiObservation, NativeBalanceDelta, TokenBalanceDelta},
        mint_rpc::{MintAccountObservation, MintRpcSnapshot},
        mint_state::Token2022MintState,
        token_account_rpc::{TokenAccountObservation, TokenAccountRpcSnapshot},
        token_account_state::Token2022AccountState,
        token_semantics::{TokenCpiInstruction, TOKEN_2022_PROGRAM},
    };
    use hguet_core::{ParsedTransaction, SystemTransfer, TransactionSignatureStatus};
    fn address(n: u8) -> String {
        bs58::encode([n; 32]).into_string()
    }
    fn parsed() -> ParsedTransaction {
        ParsedTransaction {
            wire_format: "legacy".into(),
            transaction_bytes: 120,
            transaction_sha256: "a".repeat(64),
            message_sha256: "b".repeat(64),
            required_signatures: 1,
            signature_count: 1,
            transaction_signature_status: TransactionSignatureStatus::Unsigned,
            static_account_count: 2,
            static_account_keys: vec![address(1), address(2)],
            total_address_count: 2,
            instruction_count: 1,
            lookup_table_count: 0,
            unresolved_lookup_addresses: 0,
            address_table_lookups: vec![],
            program_ids: vec![address(8)],
            compiled_top_level_instructions: vec![],
            system_transfers: vec![SystemTransfer {
                instruction_index: 0,
                source: address(1),
                destination: address(2),
                lamports: "50".into(),
            }],
            declared_system_transfer_lamports: "50".into(),
            resource_config: None,
            limitations: vec![],
        }
    }
    fn effects() -> SimulationEffects {
        SimulationEffects {
            lamport_deltas: Some(vec![NativeBalanceDelta {
                account_index: 0,
                address: address(1),
                before_lamports: "100".into(),
                after_lamports: "45".into(),
                delta_lamports: "-55".into(),
            }]),
            token_deltas: Some(vec![
                TokenBalanceDelta {
                    account_index: 1,
                    token_account: address(3),
                    mint: address(9),
                    owner: Some(address(11)),
                    decimals: 6,
                    before_raw_amount: Some("100".into()),
                    after_raw_amount: Some("75".into()),
                    delta_raw_amount: Some("-25".into()),
                    complete_pair: true,
                },
                TokenBalanceDelta {
                    account_index: 2,
                    token_account: address(4),
                    mint: address(9),
                    owner: Some(address(12)),
                    decimals: 6,
                    before_raw_amount: Some("0".into()),
                    after_raw_amount: Some("24".into()),
                    delta_raw_amount: Some("24".into()),
                    complete_pair: true,
                },
            ]),
            cpi: CpiObservation {
                captured: true,
                group_count: Some(1),
                instruction_count: Some(1),
                invoked_program_ids: vec![TOKEN_2022_PROGRAM.into()],
                token_instructions: vec![TokenCpiInstruction {
                    parent_instruction_index: 0,
                    inner_instruction_index: 0,
                    program_id: TOKEN_2022_PROGRAM.into(),
                    operation: "transfer_checked".into(),
                    source_account: Some(address(3)),
                    destination_account: Some(address(4)),
                    mint: Some(address(9)),
                    authority: Some(address(11)),
                    delegate: None,
                    amount_raw: Some("25".into()),
                    decimals: Some(6),
                    authority_type: None,
                    new_authority: None,
                }],
                token_2022_extension_observations: vec![],
                opaque_token_instruction_count: 0,
                token_2022_extension_instruction_count: 0,
                missing_compiled_token_data_count: 0,
                requires_semantic_review: true,
                limitations: vec![],
            },
            simulated_fee_lamports: Some("5".into()),
            observed_fields: vec![],
            missing_fields: vec![],
            warnings: vec![],
            security_coverage: "partial_untrusted_rpc".into(),
        }
    }
    #[test]
    fn wire_declarations_simulated_net_and_cpi_claims_are_separate_edges() {
        let graph = correlate_effects(
            &parsed(),
            "rpc_succeeded",
            500,
            &effects(),
            None,
            None,
            None,
        )
        .unwrap();
        assert_eq!(graph.version, 1);
        assert_eq!(graph.simulation_status, "rpc_succeeded");
        let relations = graph.edges.iter().map(|e| e.relation).collect::<Vec<_>>();
        assert!(relations.contains(&"declared_system_transfer"));
        assert!(relations.contains(&"simulated_native_net_delta"));
        assert!(relations.contains(&"simulated_token_net_delta"));
        assert!(relations.contains(&"cpi_declared_token_transfer"));
        let transfer = graph
            .edges
            .iter()
            .find(|e| e.relation == "cpi_declared_token_transfer")
            .unwrap();
        assert_eq!(transfer.amount_raw.as_deref(), Some("25"));
        assert_eq!(transfer.top_level_instruction, Some(0));
        assert_eq!(transfer.inner_instruction, Some(0));
        assert_eq!(transfer.attribution, "rpc_observed");
        assert!(graph.alerts.contains(&"GRAPH_CPI_NET_ATTRIBUTION_UNPROVEN"));
        assert!(!graph.execution_proven);
        assert!(!graph.spend_limit_enforced);
        assert_eq!(graph.security_coverage, "partial_untrusted_rpc");
    }
    #[test]
    fn failed_simulation_only_records_wire_claims_not_rpc_effects() {
        let graph =
            correlate_effects(&parsed(), "rpc_failed", 500, &effects(), None, None, None).unwrap();
        assert_eq!(graph.edges.len(), 1);
        assert_eq!(graph.edges[0].relation, "declared_system_transfer");
        assert!(graph
            .evidence_gaps
            .contains(&"rpc_simulation_failed_no_effect_attribution"));
        assert!(!graph.alerts.contains(&"GRAPH_CPI_NET_ATTRIBUTION_UNPROVEN"));
    }
    #[test]
    fn opaque_cpi_missing_balance_coverage_never_indicates_safety() {
        let mut e = effects();
        e.lamport_deltas = None;
        e.token_deltas = None;
        e.cpi.captured = false;
        e.cpi.token_instructions.clear();
        e.cpi.opaque_token_instruction_count = 2;
        let g = correlate_effects(&parsed(), "rpc_succeeded", 500, &e, None, None, None).unwrap();
        assert!(g
            .evidence_gaps
            .contains(&"rpc_paired_native_balances_unavailable"));
        assert!(g
            .evidence_gaps
            .contains(&"rpc_paired_token_balances_unavailable"));
        assert!(g.evidence_gaps.contains(&"rpc_cpi_recording_missing"));
        assert!(g.alerts.contains(&"GRAPH_OPAQUE_CPI_EFFECTS"));
        assert!(!g.execution_proven);
    }
    #[test]
    fn later_mint_and_account_states_link_but_never_establish_atomicity() {
        let mint = MintRpcSnapshot {
            context_slot: 501,
            simulation_slot: 500,
            atomic_with_simulation: false,
            accounts: vec![MintAccountObservation {
                address: address(9),
                status: "token_2022".into(),
                state: Some(Token2022MintState {
                    mint_address: address(9),
                    supply_raw: "1000".into(),
                    decimals: 6,
                    extensions: vec![],
                    fee_config: None,
                    hook: None,
                    permanent_delegate: Some(address(10)),
                    unknown_extension_count: 0,
                    confidential_extension_present: false,
                    limitations: "mock".into(),
                }),
            }],
            limitation: "mock".into(),
        };
        let account = TokenAccountRpcSnapshot {
            context_slot: 502,
            simulation_slot: 500,
            atomic_with_simulation: false,
            accounts: vec![TokenAccountObservation {
                address: address(3),
                simulation_reported_mint: address(9),
                status: "token_2022".into(),
                state: Some(Token2022AccountState {
                    token_account: address(3),
                    mint: address(9),
                    token_authority: address(11),
                    amount_raw: "75".into(),
                    delegate: Some(address(13)),
                    delegated_amount_raw: "20".into(),
                    account_state: "initialized",
                    native_reserve_lamports: None,
                    close_authority: None,
                    transfer_fee_withheld_raw: None,
                    requires_incoming_memo: Some(true),
                    cpi_guard_locked: None,
                    transfer_hook_transferring: None,
                    immutable_owner: false,
                    non_transferable_account: false,
                    confidential_extension_present: false,
                    opaque_extension_count: 0,
                    unknown_extension_count: 0,
                    extensions: vec![],
                    limitation: "mock".into(),
                }),
                mint_matches_simulation_report: Some(true),
                authority_matches_simulation_report: Some(true),
                matching_mint_state_observed: true,
            }],
            limitation: "mock".into(),
        };
        let g = correlate_effects(
            &parsed(),
            "rpc_succeeded",
            500,
            &effects(),
            None,
            Some(&mint),
            Some(&account),
        )
        .unwrap();
        assert_eq!(g.sources.len(), 3);
        assert!(!g.sources[1].atomic_with_simulation);
        assert!(!g.sources[2].atomic_with_simulation);
        assert!(g.edges.iter().any(
            |e| e.relation == "mint_snapshot_permanent_delegate" && e.context_slot == Some(501)
        ));
        assert!(g
            .edges
            .iter()
            .any(|e| e.relation == "holding_account_snapshot_delegate"
                && e.context_slot == Some(502)));
        assert!(g
            .evidence_gaps
            .contains(&"mint_snapshot_not_atomic_with_simulation"));
        assert!(!g.execution_proven);
    }
    #[test]
    fn contradictory_non_atomic_mint_reference_is_an_alert_not_a_denial() {
        let later = TokenAccountRpcSnapshot {
            context_slot: 502,
            simulation_slot: 500,
            atomic_with_simulation: false,
            accounts: vec![TokenAccountObservation {
                address: address(3),
                simulation_reported_mint: address(9),
                status: "token_2022".into(),
                state: None,
                mint_matches_simulation_report: Some(false),
                authority_matches_simulation_report: Some(false),
                matching_mint_state_observed: false,
            }],
            limitation: "mock".into(),
        };
        let g = correlate_effects(
            &parsed(),
            "rpc_succeeded",
            500,
            &effects(),
            None,
            None,
            Some(&later),
        )
        .unwrap();
        assert!(g.alerts.contains(&"GRAPH_ACCOUNT_MINT_DISAGREEMENT"));
        assert!(g.alerts.contains(&"GRAPH_ACCOUNT_AUTHORITY_DISAGREEMENT"));
        assert!(!g.execution_proven);
    }
    #[test]
    fn invalid_slot_or_atomicity_claim_is_rejected() {
        let later = MintRpcSnapshot {
            context_slot: 499,
            simulation_slot: 500,
            atomic_with_simulation: false,
            accounts: vec![],
            limitation: "mock".into(),
        };
        assert_eq!(
            correlate_effects(
                &parsed(),
                "rpc_succeeded",
                500,
                &effects(),
                None,
                Some(&later),
                None
            )
            .unwrap_err(),
            RpcError::InvalidResponse
        );
        let bad = MintRpcSnapshot {
            context_slot: 500,
            simulation_slot: 500,
            atomic_with_simulation: true,
            accounts: vec![],
            limitation: "mock".into(),
        };
        assert_eq!(
            correlate_effects(
                &parsed(),
                "rpc_succeeded",
                500,
                &effects(),
                None,
                Some(&bad),
                None
            )
            .unwrap_err(),
            RpcError::InvalidResponse
        );
        assert_eq!(
            correlate_effects(&parsed(), "rpc_succeeded", 0, &effects(), None, None, None)
                .unwrap_err(),
            RpcError::InvalidResponse
        );
    }
    fn direct_token_transfer(op: &str) -> DirectTokenAnalysis {
        use crate::direct_token::DirectTokenInstruction;
        let decoded = TokenCpiInstruction {
            parent_instruction_index: 0,
            inner_instruction_index: 0,
            program_id: TOKEN_2022_PROGRAM.into(),
            operation: op.into(),
            source_account: Some(address(3)),
            destination_account: Some(address(4)),
            mint: Some(address(9)),
            authority: Some(address(11)),
            delegate: None,
            amount_raw: Some("25".into()),
            decimals: Some(6),
            authority_type: None,
            new_authority: None,
        };
        DirectTokenAnalysis {
            recognized: vec![DirectTokenInstruction {
                instruction_index: 0,
                program_address_from_lookup: false,
                account_addresses_from_lookup: false,
                decoded,
            }],
            opaque: vec![],
            total_token_program_instructions: 1,
            limitation: "test",
        }
    }
    #[test]
    fn direct_wire_transfer_is_separate_from_simulated_cpi_and_net_balance() {
        let direct = direct_token_transfer("transfer_checked");
        let graph = correlate_effects(
            &parsed(),
            "rpc_succeeded",
            500,
            &effects(),
            Some(&direct),
            None,
            None,
        )
        .unwrap();
        let direct_edges = graph
            .edges
            .iter()
            .filter(|x| x.relation == "wire_declared_token_transfer")
            .collect::<Vec<_>>();
        assert_eq!(direct_edges.len(), 1);
        assert_eq!(direct_edges[0].source, "original_wire");
        assert_eq!(direct_edges[0].attribution, "declared_only");
        assert_eq!(direct_edges[0].amount_raw.as_deref(), Some("25"));
        assert_eq!(direct_edges[0].context_slot, None);
        assert!(graph
            .edges
            .iter()
            .any(|x| x.relation == "cpi_declared_token_transfer"
                && x.source == "rpc_compiled_cpi"
                && x.context_slot == Some(500)));
        assert!(graph
            .edges
            .iter()
            .any(|x| x.relation == "simulated_token_net_delta"
                && x.amount_raw.as_deref() == Some("-25")));
        assert!(!graph.execution_proven);
        assert!(!graph.spend_limit_enforced);
    }
    #[test]
    fn direct_wire_declarations_survive_failed_simulation_without_forged_effects() {
        let direct = direct_token_transfer("transfer_checked");
        let graph = correlate_effects(
            &parsed(),
            "rpc_failed",
            500,
            &effects(),
            Some(&direct),
            None,
            None,
        )
        .unwrap();
        assert!(graph
            .edges
            .iter()
            .any(|x| x.relation == "wire_declared_token_transfer"));
        assert!(!graph
            .edges
            .iter()
            .any(|x| x.relation == "cpi_declared_token_transfer"
                || x.relation == "simulated_token_net_delta"));
        assert!(graph
            .evidence_gaps
            .contains(&"rpc_simulation_failed_no_effect_attribution"));
    }
    #[test]
    fn opaque_direct_token_is_a_gap_and_alt_provenance_is_not_hidden() {
        use crate::direct_token::OpaqueDirectTokenInstruction;
        let mut direct = direct_token_transfer("transfer");
        direct.recognized[0].account_addresses_from_lookup = true;
        direct.opaque.push(OpaqueDirectTokenInstruction {
            instruction_index: 1,
            program_id: TOKEN_2022_PROGRAM.into(),
            program_address_from_lookup: true,
            token_2022_extension: true,
            extension_hint: None,
        });
        direct.total_token_program_instructions = 2;
        direct.recognized[0].decoded.mint = None;
        let graph = correlate_effects(
            &parsed(),
            "rpc_succeeded",
            500,
            &effects(),
            Some(&direct),
            None,
            None,
        )
        .unwrap();
        for gap in [
            "opaque_direct_token_instruction",
            "opaque_direct_token_2022_extension",
            "direct_token_program_from_untrusted_alt",
            "direct_token_account_from_untrusted_alt",
            "unchecked_direct_token_mint_not_declared",
        ] {
            assert!(graph.evidence_gaps.contains(&gap), "missing {gap}");
        }
        assert!(graph.alerts.contains(&"GRAPH_DIRECT_TOKEN_OPAQUE"));
        assert!(graph
            .edges
            .iter()
            .any(|x| x.relation == "wire_declared_token_transfer" && x.mint.is_none()));
    }
    #[test]
    fn unresolved_wire_transfer_address_stays_a_gap_not_forged_edge() {
        let mut p = parsed();
        p.system_transfers[0].source = "<unresolved-ALT-account>".into();
        let g = correlate_effects(&p, "rpc_succeeded", 500, &effects(), None, None, None).unwrap();
        assert!(g
            .evidence_gaps
            .contains(&"wire_native_transfer_address_unresolved"));
        assert!(!g
            .edges
            .iter()
            .any(|e| e.relation == "declared_system_transfer"));
    }
}
