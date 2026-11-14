//! Advisory, deterministic token spend *evidence views*. The three views
//! (original-wire declarations, provider CPI declarations and provider net
//! losses) are NEVER added to one fabricated total. Both original and inner
//! instructions may describe overlapping economic activity; net loss can
//! hide outgoing debit with incoming credit. None proves executed gross spend.
use crate::{
    cpi_source_rpc::{cpi_source_claims, CpiSourceCoverage},
    direct_token::DirectTokenAnalysis,
    effects::SimulationEffects,
    RpcError,
};
use hguet_core::PaymentIntentPayload;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const MAX_GROUPS: usize = 1024;
const MAX_CAP_MINTS: usize = 16;
const MAX_CAP_SOURCES: usize = 32;

#[derive(Debug, Clone, Default)]
struct ThreeViews {
    wire: u128,
    cpi: u128,
    negative_net: u128,
    wire_seen: bool,
    cpi_seen: bool,
    net_seen: bool,
}
impl ThreeViews {
    fn add(&mut self, origin: &str, amount: u128) -> Result<(), RpcError> {
        let (total, seen) = match origin {
            "wire" => (&mut self.wire, &mut self.wire_seen),
            "cpi" => (&mut self.cpi, &mut self.cpi_seen),
            "net" => (&mut self.negative_net, &mut self.net_seen),
            _ => return Err(RpcError::InvalidResponse),
        };
        *total = total.checked_add(amount).ok_or(RpcError::TooLarge)?;
        *seen = true;
        Ok(())
    }
}
#[derive(Debug, Clone, Serialize)]
pub struct AggregateMintView {
    pub mint: String,
    pub signed_mint_cap_raw: Option<String>,
    /// Original-wire checked direct transfer/burn and checked-fee declarations.
    pub wire_checked_debit_raw: String,
    /// Single-provider compiled token CPI checked transfer/burn/fee declarations.
    pub rpc_cpi_checked_debit_raw: String,
    /// Sum of negative complete-pair provider token-account net deltas;
    /// not gross outflow, may include accounts outside the intended payer.
    pub rpc_negative_account_net_raw: String,
    pub wire_exceeds_signed_cap: bool,
    pub rpc_cpi_exceeds_signed_cap: bool,
    pub rpc_negative_net_exceeds_signed_cap: bool,
    pub rpc_cpi_or_net_outside_signed_mint_list: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct AggregateSourceView {
    pub mint: String,
    pub source_token_account: String,
    pub signed_source_cap_raw: Option<String>,
    pub wire_checked_debit_raw: String,
    pub rpc_cpi_checked_debit_raw: String,
    pub rpc_negative_account_net_raw: String,
    pub wire_exceeds_signed_cap: bool,
    pub rpc_cpi_exceeds_signed_cap: bool,
    pub rpc_negative_net_exceeds_signed_cap: bool,
    pub rpc_cpi_or_net_outside_signed_source_list: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct AggregateTokenSpending {
    pub simulation_slot: u64,
    pub simulation_status: &'static str,
    pub signed_caps_supplied_by_verified_caller: bool,
    pub mints: Vec<AggregateMintView>,
    pub sources: Vec<AggregateSourceView>,
    pub opaque_direct_token_instructions: usize,
    /// Original instruction bytes are signed wire, but program/account IDs
    /// referenced through ALT were resolved from one untrusted RPC provider.
    pub wire_rpc_alt_identity_dependent_instructions: usize,
    pub opaque_rpc_cpi_token_instructions: usize,
    pub unattributed_direct_debit_instructions: usize,
    pub unattributed_cpi_debit_instructions: usize,
    pub incomplete_token_balance_rows: usize,
    pub missing_token_balance_snapshot: bool,
    pub cpi_source_coverage_missing_or_incomplete: bool,
    pub authority_or_nondebit_operations_observed: bool,
    pub any_signed_cap_warning: bool,
    /// Overlapping wire/CPI/net views MUST NEVER be summed.
    pub wire_cpi_and_net_amounts_never_added: bool,
    pub total_gross_token_spend_proven: bool,
    pub onchain_spend_limit_enforced: bool,
    pub execution_proven: bool,
    pub security_coverage: &'static str,
    pub limitation: &'static str,
}
fn valid_key(s: &str) -> bool {
    bs58::decode(s)
        .into_vec()
        .map(|v| v.len() == 32 && bs58::encode(&v).into_string() == s)
        .unwrap_or(false)
}
fn raw_u64(s: &str) -> Result<u64, RpcError> {
    if s.is_empty()
        || s.len() > 20
        || (s.len() > 1 && s.starts_with('0'))
        || !s.bytes().all(|c| c.is_ascii_digit())
    {
        return Err(RpcError::InvalidResponse);
    }
    s.parse().map_err(|_| RpcError::InvalidResponse)
}
fn insert(
    mints: &mut BTreeMap<String, ThreeViews>,
    sources: &mut BTreeMap<(String, String), ThreeViews>,
    mint: &str,
    source: &str,
    amount: u64,
    origin: &str,
) -> Result<(), RpcError> {
    if !valid_key(mint) || !valid_key(source) {
        return Err(RpcError::InvalidResponse);
    }
    if !mints.contains_key(mint) && mints.len() >= MAX_GROUPS {
        return Err(RpcError::TooLarge);
    }
    mints
        .entry(mint.to_owned())
        .or_default()
        .add(origin, u128::from(amount))?;
    let key = (mint.to_owned(), source.to_owned());
    if !sources.contains_key(&key) && sources.len() >= MAX_GROUPS {
        return Err(RpcError::TooLarge);
    }
    sources
        .entry(key)
        .or_default()
        .add(origin, u128::from(amount))?;
    Ok(())
}
type AggregateParts = (
    BTreeMap<String, u64>,
    BTreeMap<(String, String), u64>,
    bool,
    bool,
);
fn caps(trusted: Option<&PaymentIntentPayload>) -> Result<AggregateParts, RpcError> {
    let mut mint_caps = BTreeMap::new();
    let mut source_caps = BTreeMap::new();
    let mut has_mint = false;
    let mut has_source = false;
    if let Some(intent) = trusted {
        if let Some(rows) = &intent.token_spend_limits {
            if rows.len() > MAX_CAP_MINTS {
                return Err(RpcError::TooLarge);
            }
            has_mint = true;
            for row in rows {
                if !valid_key(&row.mint)
                    || mint_caps
                        .insert(row.mint.clone(), raw_u64(&row.max_debit_raw)?)
                        .is_some()
                {
                    return Err(RpcError::InvalidResponse);
                }
            }
        }
        if let Some(rows) = &intent.token_source_limits {
            if rows.len() > MAX_CAP_SOURCES {
                return Err(RpcError::TooLarge);
            }
            has_source = true;
            let mut unique_sources = BTreeSet::new();
            for row in rows {
                if !valid_key(&row.mint)
                    || !valid_key(&row.source_token_account)
                    || !valid_key(&row.authority)
                    || !unique_sources.insert(row.source_token_account.clone())
                    || source_caps
                        .insert(
                            (row.mint.clone(), row.source_token_account.clone()),
                            raw_u64(&row.max_debit_raw)?,
                        )
                        .is_some()
                {
                    return Err(RpcError::InvalidResponse);
                }
            }
        }
    }
    Ok((mint_caps, source_caps, has_mint, has_source))
}
fn checked_debit(op: &str) -> bool {
    matches!(
        op,
        "transfer_checked" | "burn_checked" | "transfer_checked_with_fee"
    )
}
fn unchecked_debit(op: &str) -> bool {
    matches!(op, "transfer" | "burn")
}
/// Input intent MUST be independently verified by the caller before passing
/// it in. This function is *not* a signature verifier, signer, policy enforcer
/// or an onchain gross debit calculator.
pub fn analyze_aggregate_token_spending(
    status: &str,
    simulation_slot: u64,
    direct: &DirectTokenAnalysis,
    effects: &SimulationEffects,
    cpi_coverage: Option<&CpiSourceCoverage>,
    verified_intent: Option<&PaymentIntentPayload>,
) -> Result<AggregateTokenSpending, RpcError> {
    if status != "rpc_succeeded" || simulation_slot == 0 {
        return Err(RpcError::InvalidResponse);
    }
    if direct.recognized.len() + direct.opaque.len() > 64
        || direct.total_token_program_instructions != direct.recognized.len() + direct.opaque.len()
    {
        return Err(RpcError::InvalidResponse);
    }
    if let Some(coverage) = cpi_coverage {
        if coverage.simulation_slot != simulation_slot
            || coverage.atomic_with_simulation
            || coverage.authorization_proven
            || coverage.total_gross_token_spending_proven
        {
            return Err(RpcError::InvalidResponse);
        }
    }
    let (mint_caps, source_caps, has_mint, has_source) = caps(verified_intent)?;
    let mut mints = BTreeMap::<String, ThreeViews>::new();
    let mut sources = BTreeMap::<(String, String), ThreeViews>::new();
    let mut direct_unknown = 0usize;
    let mut cpi_unknown = 0usize;
    let mut opaque_direct = 0usize;
    let mut alt_dependent = 0usize;
    let mut authority_ops = false;
    let mut seen_wire = BTreeSet::new();
    for item in &direct.recognized {
        if item.program_address_from_lookup || item.account_addresses_from_lookup {
            alt_dependent += 1;
        }
        if !seen_wire.insert(item.instruction_index) {
            return Err(RpcError::InvalidResponse);
        }
        let op = item.decoded.operation.as_str();
        if checked_debit(op) {
            let mint = item
                .decoded
                .mint
                .as_deref()
                .ok_or(RpcError::InvalidResponse)?;
            let source = item
                .decoded
                .source_account
                .as_deref()
                .ok_or(RpcError::InvalidResponse)?;
            let amount = raw_u64(
                item.decoded
                    .amount_raw
                    .as_deref()
                    .ok_or(RpcError::InvalidResponse)?,
            )?;
            insert(&mut mints, &mut sources, mint, source, amount, "wire")?;
        } else if unchecked_debit(op) {
            // Unchecked token Transfer has no mint argument. Observed account
            // state is NOT allowed to backfill this original-wire declaration.
            direct_unknown += 1;
        } else {
            authority_ops = true; // approvals/authority/sync/mint, not a source debit
        }
    }
    for item in &direct.opaque {
        if item.program_address_from_lookup {
            alt_dependent += 1;
        }
        if !seen_wire.insert(item.instruction_index) {
            return Err(RpcError::InvalidResponse);
        }
        let checked_fee = item
            .extension_hint
            .as_ref()
            .filter(|hint| hint.operation == "transfer_checked_with_fee" && hint.layout_checked);
        if let Some(hint) = checked_fee {
            let mint = hint.mint.as_deref().ok_or(RpcError::InvalidResponse)?;
            let source = hint
                .source_account
                .as_deref()
                .ok_or(RpcError::InvalidResponse)?;
            let amount = raw_u64(
                hint.declared_amount_raw
                    .as_deref()
                    .ok_or(RpcError::InvalidResponse)?,
            )?;
            insert(&mut mints, &mut sources, mint, source, amount, "wire")?;
        } else {
            opaque_direct += 1;
        }
    }
    let claims = cpi_source_claims(effects)?;
    let mut seen_cpi = BTreeSet::new();
    for claim in &claims {
        if !seen_cpi.insert((
            claim.parent_instruction_index,
            claim.inner_instruction_index,
        )) {
            return Err(RpcError::InvalidResponse);
        }
        if checked_debit(&claim.operation) {
            let mint = claim
                .declared_mint
                .as_deref()
                .ok_or(RpcError::InvalidResponse)?;
            let amount = raw_u64(
                claim
                    .declared_raw_amount
                    .as_deref()
                    .ok_or(RpcError::InvalidResponse)?,
            )?;
            insert(
                &mut mints,
                &mut sources,
                mint,
                &claim.source_account,
                amount,
                "cpi",
            )?;
        } else if unchecked_debit(&claim.operation) {
            cpi_unknown += 1;
        } else {
            authority_ops = true;
        }
    }
    let mut incomplete_rows = 0usize;
    let mut seen_net = BTreeSet::<String>::new();
    if let Some(rows) = &effects.token_deltas {
        if rows.len() > 256 {
            return Err(RpcError::TooLarge);
        }
        for row in rows {
            if !valid_key(&row.mint)
                || !valid_key(&row.token_account)
                || !seen_net.insert(row.token_account.clone())
            {
                return Err(RpcError::InvalidResponse);
            }
            if !row.complete_pair {
                incomplete_rows += 1;
                continue;
            }
            let Some(raw) = row.delta_raw_amount.as_deref() else {
                incomplete_rows += 1;
                continue;
            };
            let delta = raw.parse::<i128>().map_err(|_| RpcError::InvalidResponse)?;
            if delta < 0 {
                let amount =
                    u64::try_from(delta.unsigned_abs()).map_err(|_| RpcError::InvalidResponse)?;
                insert(
                    &mut mints,
                    &mut sources,
                    &row.mint,
                    &row.token_account,
                    amount,
                    "net",
                )?;
            }
        }
    }
    let missing_balances = effects.token_deltas.is_none();
    for mint in mint_caps.keys() {
        if !mints.contains_key(mint) && mints.len() >= MAX_GROUPS {
            return Err(RpcError::TooLarge);
        }
        mints.entry(mint.clone()).or_default();
    }
    for key in source_caps.keys() {
        if !sources.contains_key(key) && sources.len() >= MAX_GROUPS {
            return Err(RpcError::TooLarge);
        }
        sources.entry(key.clone()).or_default();
    }
    let mut any_warning = false;
    let mut mint_results = Vec::with_capacity(mints.len());
    for (mint, views) in mints {
        let cap = mint_caps.get(&mint).copied();
        let cpi_outside = has_mint && cap.is_none() && (views.cpi_seen || views.net_seen);
        let over = cap.is_some_and(|n| views.wire > u128::from(n));
        let cpi_over = cap.is_some_and(|n| views.cpi > u128::from(n));
        let net_over = cap.is_some_and(|n| views.negative_net > u128::from(n));
        any_warning |= over || cpi_over || net_over || cpi_outside;
        mint_results.push(AggregateMintView {
            mint,
            signed_mint_cap_raw: cap.map(|n| n.to_string()),
            wire_checked_debit_raw: views.wire.to_string(),
            rpc_cpi_checked_debit_raw: views.cpi.to_string(),
            rpc_negative_account_net_raw: views.negative_net.to_string(),
            wire_exceeds_signed_cap: over,
            rpc_cpi_exceeds_signed_cap: cpi_over,
            rpc_negative_net_exceeds_signed_cap: net_over,
            rpc_cpi_or_net_outside_signed_mint_list: cpi_outside,
        });
    }
    let mut source_results = Vec::with_capacity(sources.len());
    for ((mint, source), views) in sources {
        let cap = source_caps.get(&(mint.clone(), source.clone())).copied();
        let outside = has_source && cap.is_none() && (views.cpi_seen || views.net_seen);
        let over = cap.is_some_and(|n| views.wire > u128::from(n));
        let cpi_over = cap.is_some_and(|n| views.cpi > u128::from(n));
        let net_over = cap.is_some_and(|n| views.negative_net > u128::from(n));
        any_warning |= over || cpi_over || net_over || outside;
        source_results.push(AggregateSourceView {
            mint,
            source_token_account: source,
            signed_source_cap_raw: cap.map(|n| n.to_string()),
            wire_checked_debit_raw: views.wire.to_string(),
            rpc_cpi_checked_debit_raw: views.cpi.to_string(),
            rpc_negative_account_net_raw: views.negative_net.to_string(),
            wire_exceeds_signed_cap: over,
            rpc_cpi_exceeds_signed_cap: cpi_over,
            rpc_negative_net_exceeds_signed_cap: net_over,
            rpc_cpi_or_net_outside_signed_source_list: outside,
        });
    }
    let coverage_missing = cpi_coverage.is_none()
        || !effects.cpi.captured
        || cpi_coverage.is_some_and(|c| {
            c.unsupported_or_missing_cpi_source_semantics || c.unobserved_sources > 0
        });
    let unknown_cpi =
        effects.cpi.opaque_token_instruction_count + effects.cpi.missing_compiled_token_data_count;
    Ok(AggregateTokenSpending {
        simulation_slot,simulation_status:"rpc_succeeded",
        signed_caps_supplied_by_verified_caller:verified_intent.is_some(),
        mints:mint_results,sources:source_results,
        opaque_direct_token_instructions:opaque_direct,
        wire_rpc_alt_identity_dependent_instructions:alt_dependent,
        opaque_rpc_cpi_token_instructions:unknown_cpi,
        unattributed_direct_debit_instructions:direct_unknown,
        unattributed_cpi_debit_instructions:cpi_unknown,
        incomplete_token_balance_rows:incomplete_rows,
        missing_token_balance_snapshot:missing_balances,
        cpi_source_coverage_missing_or_incomplete:coverage_missing,
        authority_or_nondebit_operations_observed:authority_ops,
        any_signed_cap_warning:any_warning,
        wire_cpi_and_net_amounts_never_added:true,
        total_gross_token_spend_proven:false,
        onchain_spend_limit_enforced:false,execution_proven:false,
        security_coverage:"partial_untrusted_rpc",
        limitation:"Three separately observed views are NEVER added: original-wire direct checked declarations, single-provider compiled CPI checked declarations, and negative provider token-account net deltas can describe overlapping or compensating activity. No verified execution bank, source ownership, gross outflow, fees/hooks, CPI completeness or transaction-wide spend cap can be proven from this evidence. Signed limits are used only after caller verification; RPC overages are advisory and never ALLOW.",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cpi_source_rpc::CpiSourceCoverage,
        direct_token::{DirectTokenInstruction, OpaqueDirectTokenInstruction},
        effects::{CpiObservation, TokenBalanceDelta},
        extension_semantics::Token2022ExtensionObservation,
        token_semantics::{TokenCpiInstruction, TOKEN_2022_PROGRAM, TOKEN_PROGRAM},
    };
    use hguet_core::{TokenSourceLimit, TokenSpendLimit};
    fn key(i: u8) -> String {
        bs58::encode([i; 32]).into_string()
    }
    fn token_ix(
        op: &str,
        source: u8,
        mint: Option<u8>,
        amount: u64,
        index: usize,
    ) -> TokenCpiInstruction {
        TokenCpiInstruction {
            parent_instruction_index: 0,
            inner_instruction_index: index,
            program_id: TOKEN_PROGRAM.into(),
            operation: op.into(),
            source_account: Some(key(source)),
            destination_account: Some(key(9)),
            mint: mint.map(key),
            authority: Some(key(8)),
            delegate: None,
            amount_raw: Some(amount.to_string()),
            decimals: Some(6),
            authority_type: None,
            new_authority: None,
        }
    }
    fn direct(items: Vec<TokenCpiInstruction>) -> DirectTokenAnalysis {
        let n = items.len();
        DirectTokenAnalysis {
            recognized: items
                .into_iter()
                .enumerate()
                .map(|(index, decoded)| DirectTokenInstruction {
                    instruction_index: index,
                    program_address_from_lookup: false,
                    account_addresses_from_lookup: false,
                    decoded,
                })
                .collect(),
            opaque: vec![],
            total_token_program_instructions: n,
            limitation: "fixture",
        }
    }
    fn effects(
        items: Vec<TokenCpiInstruction>,
        rows: Option<Vec<TokenBalanceDelta>>,
    ) -> SimulationEffects {
        SimulationEffects {
            lamport_deltas: None,
            token_deltas: rows,
            cpi: CpiObservation {
                captured: true,
                group_count: Some(1),
                instruction_count: Some(items.len()),
                invoked_program_ids: vec![],
                token_instructions: items,
                token_2022_extension_observations: vec![],
                opaque_token_instruction_count: 0,
                token_2022_extension_instruction_count: 0,
                missing_compiled_token_data_count: 0,
                requires_semantic_review: true,
                limitations: vec![],
            },
            simulated_fee_lamports: None,
            observed_fields: vec![],
            missing_fields: vec![],
            warnings: vec![],
            security_coverage: "partial_untrusted_rpc".into(),
        }
    }
    fn row(mint: u8, source: u8, raw: &str, paired: bool) -> TokenBalanceDelta {
        TokenBalanceDelta {
            account_index: usize::from(source),
            token_account: key(source),
            mint: key(mint),
            owner: Some(key(8)),
            decimals: 6,
            before_raw_amount: Some("200".into()),
            after_raw_amount: Some("130".into()),
            delta_raw_amount: Some(raw.into()),
            complete_pair: paired,
        }
    }
    fn intent(mint: Option<u8>, cap: &str, scopes: &[(u8, u8, &str)]) -> PaymentIntentPayload {
        PaymentIntentPayload {
            schema_version: 1,
            kind: "hguet_payment_intent".into(),
            intent_id: "synthetic".into(),
            network: "devnet".into(),
            message_sha256: "a".repeat(64),
            not_before_unix: 1,
            expires_at_unix: 4102444800,
            allowed_program_ids: vec![TOKEN_PROGRAM.into()],
            max_spend_lamports: "1000".into(),
            token_spend_limits: mint.map(|m| {
                vec![TokenSpendLimit {
                    mint: key(m),
                    max_debit_raw: cap.into(),
                }]
            }),
            token_source_limits: Some(
                scopes
                    .iter()
                    .map(|(mint, source, amount)| TokenSourceLimit {
                        mint: key(*mint),
                        source_token_account: key(*source),
                        authority: key(8),
                        max_debit_raw: (*amount).into(),
                    })
                    .collect(),
            ),
        }
    }
    fn analyze(
        d: &DirectTokenAnalysis,
        e: &SimulationEffects,
        p: Option<&PaymentIntentPayload>,
    ) -> AggregateTokenSpending {
        analyze_aggregate_token_spending("rpc_succeeded", 600, d, e, None, p).unwrap()
    }
    #[test]
    fn wire_cpi_and_net_70_are_three_views_not_a_fabricated_210_debit() {
        let d = direct(vec![token_ix("transfer_checked", 3, Some(2), 70, 0)]);
        let e = effects(
            vec![token_ix("transfer_checked", 3, Some(2), 70, 1)],
            Some(vec![row(2, 3, "-70", true)]),
        );
        let p = intent(Some(2), "100", &[(2, 3, "100")]);
        let r = analyze(&d, &e, Some(&p));
        assert_eq!(r.mints.len(), 1);
        assert_eq!(r.sources.len(), 1);
        assert_eq!(r.mints[0].wire_checked_debit_raw, "70");
        assert_eq!(r.mints[0].rpc_cpi_checked_debit_raw, "70");
        assert_eq!(r.mints[0].rpc_negative_account_net_raw, "70");
        assert_eq!(r.sources[0].wire_checked_debit_raw, "70");
        assert!(!r.any_signed_cap_warning);
        assert!(r.wire_cpi_and_net_amounts_never_added);
        assert!(!r.total_gross_token_spend_proven);
        assert!(!r.onchain_spend_limit_enforced);
        assert!(!r.execution_proven);
    }
    #[test]
    fn two_cpi_60_plus_50_exceed_cap_even_when_wire_and_net_are_under() {
        let d = direct(vec![token_ix("transfer_checked", 3, Some(2), 80, 0)]);
        let e = effects(
            vec![
                token_ix("transfer_checked", 3, Some(2), 60, 1),
                token_ix("burn_checked", 3, Some(2), 50, 2),
            ],
            Some(vec![row(2, 3, "-90", true)]),
        );
        let p = intent(Some(2), "100", &[(2, 3, "100")]);
        let r = analyze(&d, &e, Some(&p));
        assert_eq!(r.mints[0].wire_checked_debit_raw, "80");
        assert_eq!(r.mints[0].rpc_cpi_checked_debit_raw, "110");
        assert_eq!(r.mints[0].rpc_negative_account_net_raw, "90");
        assert!(r.mints[0].rpc_cpi_exceeds_signed_cap);
        assert!(r.sources[0].rpc_cpi_exceeds_signed_cap);
        assert!(!r.mints[0].rpc_negative_net_exceeds_signed_cap);
        assert!(r.any_signed_cap_warning);
    }
    #[test]
    fn separate_sources_can_be_under_individual_caps_but_over_total_mint_cap() {
        let d = direct(vec![]);
        let e = effects(
            vec![
                token_ix("transfer_checked", 3, Some(2), 40, 1),
                token_ix("transfer_checked", 4, Some(2), 70, 2),
            ],
            Some(vec![]),
        );
        let p = intent(Some(2), "100", &[(2, 3, "50"), (2, 4, "80")]);
        let r = analyze(&d, &e, Some(&p));
        assert_eq!(r.mints[0].rpc_cpi_checked_debit_raw, "110");
        assert!(r.mints[0].rpc_cpi_exceeds_signed_cap);
        assert_eq!(r.sources.len(), 2);
        assert!(!r.sources[0].rpc_cpi_exceeds_signed_cap);
        assert!(!r.sources[1].rpc_cpi_exceeds_signed_cap);
    }
    #[test]
    fn net_losses_are_account_scoped_and_not_blindly_reconciled_to_cpi() {
        let d = direct(vec![]);
        let e = effects(
            vec![token_ix("transfer_checked", 3, Some(2), 20, 1)],
            Some(vec![row(2, 3, "-120", true), row(2, 4, "-10", true)]),
        );
        let p = intent(Some(2), "100", &[(2, 3, "100")]);
        let r = analyze(&d, &e, Some(&p));
        assert_eq!(r.mints[0].rpc_negative_account_net_raw, "130");
        assert!(r.mints[0].rpc_negative_net_exceeds_signed_cap);
        assert!(r
            .sources
            .iter()
            .any(|s| s.source_token_account == key(3) && s.rpc_negative_net_exceeds_signed_cap));
        assert!(r.sources.iter().any(
            |s| s.source_token_account == key(4) && s.rpc_cpi_or_net_outside_signed_source_list
        ));
        assert_eq!(r.mints[0].rpc_cpi_checked_debit_raw, "20");
        assert!(r.wire_cpi_and_net_amounts_never_added);
    }
    #[test]
    fn unchecked_cpi_and_direct_have_unknown_mint_even_with_observed_delta() {
        let d = direct(vec![token_ix("transfer", 3, None, 30, 0)]);
        let e = effects(
            vec![token_ix("transfer", 3, None, 40, 1)],
            Some(vec![row(2, 3, "-30", true), row(7, 4, "-15", false)]),
        );
        let p = intent(Some(2), "100", &[(2, 3, "100")]);
        let r = analyze(&d, &e, Some(&p));
        assert_eq!(r.unattributed_direct_debit_instructions, 1);
        assert_eq!(r.unattributed_cpi_debit_instructions, 1);
        assert_eq!(r.incomplete_token_balance_rows, 1);
        assert_eq!(r.mints[0].rpc_cpi_checked_debit_raw, "0");
        assert_eq!(r.mints[0].rpc_negative_account_net_raw, "30");
        assert!(r.cpi_source_coverage_missing_or_incomplete);
    }
    #[test]
    fn explicit_fee_transfer_claims_are_counted_once_per_view() {
        let mut d = direct(vec![]);
        let mut e = effects(vec![], Some(vec![]));
        let hint = Token2022ExtensionObservation {
            parent_instruction_index: 0,
            inner_instruction_index: 0,
            opcode: 26,
            sub_opcode: Some(1),
            family: "transfer_fee",
            operation: "transfer_checked_with_fee",
            layout_checked: true,
            mint: Some(key(2)),
            source_account: Some(key(3)),
            authority: Some(key(8)),
            new_authority: None,
            hook_program_id: None,
            declared_amount_raw: Some("100".into()),
            expected_fee_raw: Some("5".into()),
            fee_basis_points: None,
            maximum_fee_raw: None,
        };
        d.opaque.push(OpaqueDirectTokenInstruction {
            instruction_index: 0,
            program_id: TOKEN_2022_PROGRAM.into(),
            program_address_from_lookup: false,
            token_2022_extension: true,
            extension_hint: Some(hint.clone()),
        });
        d.total_token_program_instructions = 1;
        let mut cpi = hint;
        cpi.inner_instruction_index = 2;
        e.cpi.token_2022_extension_observations.push(cpi);
        e.cpi.token_2022_extension_instruction_count = 1;
        e.cpi.opaque_token_instruction_count = 1;
        let p = intent(Some(2), "100", &[(2, 3, "100")]);
        let r = analyze(&d, &e, Some(&p));
        assert_eq!(r.mints[0].wire_checked_debit_raw, "100");
        assert_eq!(r.mints[0].rpc_cpi_checked_debit_raw, "100");
        assert_eq!(r.opaque_direct_token_instructions, 0);
        assert_eq!(r.opaque_rpc_cpi_token_instructions, 1);
        assert!(!r.any_signed_cap_warning);
    }
    #[test]
    fn missing_signed_mint_and_source_covers_only_advisory_rpc_findings() {
        let d = direct(vec![]);
        let e = effects(
            vec![token_ix("transfer_checked", 3, Some(6), 20, 1)],
            Some(vec![row(6, 3, "-20", true)]),
        );
        let p = intent(Some(2), "100", &[(2, 4, "100")]);
        let r = analyze(&d, &e, Some(&p));
        assert!(r
            .mints
            .iter()
            .any(|m| m.mint == key(6) && m.rpc_cpi_or_net_outside_signed_mint_list));
        assert!(r
            .sources
            .iter()
            .any(|s| s.mint == key(6) && s.rpc_cpi_or_net_outside_signed_source_list));
        assert!(r.any_signed_cap_warning);
        assert!(!r.onchain_spend_limit_enforced);
    }
    #[test]
    fn malformed_duplicate_provider_cpi_and_signed_cap_entries_are_rejected() {
        let d = direct(vec![]);
        let ix = token_ix("transfer_checked", 3, Some(2), 10, 1);
        let e = effects(vec![ix.clone(), ix], Some(vec![]));
        assert_eq!(
            analyze_aggregate_token_spending("rpc_succeeded", 600, &d, &e, None, None).unwrap_err(),
            RpcError::InvalidResponse
        );
        let e = effects(vec![], Some(vec![]));
        let mut p = intent(Some(2), "100", &[(2, 3, "100")]);
        let duplicate = p.token_source_limits.as_ref().unwrap()[0].clone();
        p.token_source_limits.as_mut().unwrap().push(duplicate);
        assert_eq!(
            analyze_aggregate_token_spending("rpc_succeeded", 600, &d, &e, None, Some(&p))
                .unwrap_err(),
            RpcError::InvalidResponse
        );
    }
    #[test]
    fn direct_token_alt_accounts_are_not_silently_reported_as_static_wire_identity() {
        let mut d = direct(vec![token_ix("transfer_checked", 3, Some(2), 15, 0)]);
        d.recognized[0].account_addresses_from_lookup = true;
        let e = effects(vec![], Some(vec![]));
        let r = analyze(&d, &e, None);
        assert_eq!(r.mints[0].wire_checked_debit_raw, "15");
        assert_eq!(r.wire_rpc_alt_identity_dependent_instructions, 1);
        assert!(!r.total_gross_token_spend_proven);
    }
    #[test]
    fn failed_simulation_and_forged_authorization_are_not_accepted() {
        let d = direct(vec![]);
        let e = effects(vec![], None);
        assert_eq!(
            analyze_aggregate_token_spending("rpc_failed", 600, &d, &e, None, None).unwrap_err(),
            RpcError::InvalidResponse
        );
        assert_eq!(
            analyze_aggregate_token_spending("rpc_succeeded", 0, &d, &e, None, None).unwrap_err(),
            RpcError::InvalidResponse
        );
        let mut forged = CpiSourceCoverage {
            simulation_slot: 600,
            cpi_account_context_slot: None,
            atomic_with_simulation: false,
            cpi_captured: true,
            opaque_token_instruction_count: 0,
            token_2022_extension_instruction_count: 0,
            unsupported_or_missing_cpi_source_semantics: false,
            entries: vec![],
            unobserved_sources: 0,
            total_gross_token_spending_proven: false,
            authorization_proven: true,
            security_coverage: "partial_untrusted_rpc",
            limitation: "test",
        };
        assert_eq!(
            analyze_aggregate_token_spending("rpc_succeeded", 600, &d, &e, Some(&forged), None)
                .unwrap_err(),
            RpcError::InvalidResponse
        );
        forged.authorization_proven = false;
        assert!(analyze_aggregate_token_spending(
            "rpc_succeeded",
            600,
            &d,
            &e,
            Some(&forged),
            None
        )
        .is_ok());
    }
    #[test]
    fn large_integer_totals_use_u128_but_are_not_real_spend() {
        let d = direct(vec![]);
        let e = effects(
            vec![
                token_ix("transfer_checked", 3, Some(2), u64::MAX, 1),
                token_ix("transfer_checked", 3, Some(2), u64::MAX, 2),
            ],
            Some(vec![]),
        );
        let p = intent(
            Some(2),
            &u64::MAX.to_string(),
            &[(2, 3, &u64::MAX.to_string())],
        );
        let r = analyze(&d, &e, Some(&p));
        assert_eq!(
            r.mints[0].rpc_cpi_checked_debit_raw,
            (2u128 * u128::from(u64::MAX)).to_string()
        );
        assert!(r.mints[0].rpc_cpi_exceeds_signed_cap);
        assert!(!r.total_gross_token_spend_proven);
    }
}
