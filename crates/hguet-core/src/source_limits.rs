//! Optional signed limits binding direct token debits to a specific source
//! token account and declared transaction signer authority. This is a strict
//! *pre-signing byte-level* check, not proof of current token-account ownership.
//! CPI, multisig and Token-2022 hook side effects remain outside this scope.
use crate::{
    solana_engine::{ParsedTransaction, TransactionSignatureStatus},
    token_limits::checked_direct_debits,
    TokenSourceLimit,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const MAX_SOURCE_LIMITS: usize = 32;

#[derive(Debug, Clone, Serialize)]
pub struct DeclaredSourceDebit {
    pub token_program: String,
    pub mint: String,
    pub source_token_account: String,
    pub declared_authority: String,
    pub declared_raw: String,
    pub signed_limit_raw: String,
}
#[derive(Debug, Clone, Serialize)]
pub struct TokenSourceLimitReview {
    pub debits: Vec<DeclaredSourceDebit>,
    pub checked_direct_debit_instructions: usize,
    pub transaction_required_signer_role_checked: bool,
    /// True ONLY when every signature on the transaction was verified.
    /// Unsigned pre-signing checks can still validate the required signer role.
    pub transaction_signatures_verified: bool,
    pub token_account_owner_verified: bool,
    pub total_spending_proven: bool,
    pub coverage: &'static str,
    pub limitation: &'static str,
}
fn canonical_pubkey(s: &str) -> bool {
    bs58::decode(s)
        .into_vec()
        .map(|bytes| bytes.len() == 32 && bs58::encode(bytes).into_string() == s)
        .unwrap_or(false)
}
fn canonical_raw(s: &str) -> Option<u64> {
    if s.is_empty()
        || s.len() > 20
        || (s.len() > 1 && s.starts_with('0'))
        || !s.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    s.parse::<u64>().ok()
}

/// Validate *all* declared direct checked token debits against exact, signed
/// (mint, source token account, authority) scopes. Every authority is required
/// to be one of the original message's static required signers (index <
/// num_required_signatures). Requiring the canonical 3/4-account form rules
/// out multisig, additional hook accounts and undeclared authority roles in
/// this conservative initial implementation.
///
/// A positive review means only that declared bytes meet those constraints.
/// Actual token-account authority, delegate privileges, fee/hook side effects,
/// CPI flows and onchain execution are NOT verified.
pub fn review_declared_source_limits(
    parsed: &ParsedTransaction,
    limits: &[TokenSourceLimit],
) -> Result<TokenSourceLimitReview, String> {
    if limits.len() > MAX_SOURCE_LIMITS {
        return Err("signed source token limit list exceeds 32 accounts".into());
    }
    if parsed.required_signatures == 0
        || parsed.required_signatures > parsed.static_account_keys.len()
    {
        return Err("invalid original transaction signer set".into());
    }
    let signers = &parsed.static_account_keys[..parsed.required_signatures];
    let mut signed = BTreeMap::<(String, String), (String, u64)>::new();
    let mut seen_sources = BTreeSet::new();
    for cap in limits {
        if !canonical_pubkey(&cap.mint)
            || !canonical_pubkey(&cap.source_token_account)
            || !canonical_pubkey(&cap.authority)
        {
            return Err("signed source token limit contains an invalid canonical pubkey".into());
        }
        let limit = canonical_raw(&cap.max_debit_raw)
            .ok_or("signed source token debit maximum must be a canonical u64 integer")?;
        if !signers.iter().any(|key| key == &cap.authority) {
            return Err(
                "signed source token authority is not a required transaction signer".into(),
            );
        }
        // A source token account may only appear once in this bounded policy,
        // regardless of mint/authority: no ambiguous competing cap entries.
        if !seen_sources.insert(cap.source_token_account.clone()) {
            return Err("duplicate signed source token account cap".into());
        }
        signed.insert(
            (cap.mint.clone(), cap.source_token_account.clone()),
            (cap.authority.clone(), limit),
        );
    }
    let debits = checked_direct_debits(parsed)?;
    let mut totals = BTreeMap::<(String, String), u128>::new();
    let mut programs = BTreeMap::<(String, String), String>::new();
    for debit in &debits {
        // Exactly one authority role, no multisig or unknown trailing accounts.
        if debit.account_count != debit.exact_single_authority_count {
            return Err(
                "signed source limits cannot validate multisig or extra token instruction accounts"
                    .into(),
            );
        }
        if !signers.iter().any(|signer| signer == &debit.authority) {
            return Err("direct token instruction authority is not a required signer".into());
        }
        let key = (debit.mint.clone(), debit.source_token_account.clone());
        if let Some(previous) = programs.insert(key.clone(), debit.token_program.clone()) {
            if previous != debit.token_program {
                return Err("same signed source has incompatible token program identities".into());
            }
        }
        let (authority, limit) = signed.get(&key).ok_or(
            "direct token debit source or mint is missing from signed token_source_limits",
        )?;
        if authority != &debit.authority {
            return Err(
                "direct token instruction authority disagrees with signed source cap".into(),
            );
        }
        let total = totals
            .get(&key)
            .copied()
            .unwrap_or(0)
            .checked_add(u128::from(debit.amount_raw))
            .ok_or("signed source token debit sum overflow")?;
        if total > u128::from(*limit) {
            return Err("declared direct token debits exceed signed source max_debit_raw".into());
        }
        totals.insert(key, total);
    }
    let results = totals
        .into_iter()
        .map(|((mint, source_token_account), raw)| {
            let (authority, limit) = &signed[&(mint.clone(), source_token_account.clone())];
            DeclaredSourceDebit {
                token_program: programs[&(mint.clone(), source_token_account.clone())].clone(),
                mint,
                source_token_account,
                declared_authority: authority.clone(),
                declared_raw: raw.to_string(),
                signed_limit_raw: limit.to_string(),
            }
        })
        .collect();
    Ok(TokenSourceLimitReview {
        debits:results,checked_direct_debit_instructions:debits.len(),
        transaction_required_signer_role_checked:true,
        transaction_signatures_verified:parsed.transaction_signature_status
            ==TransactionSignatureStatus::Verified,
        token_account_owner_verified:false,
        total_spending_proven:false,
        coverage:"signed_direct_checked_source_authority_wire_roles_only",
        limitation:"Declared authority is required to be a static signer in the Solana message. Unsigned messages may be checked pre-signing. The actual token-account owner/delegate, multisig, CPI, hooks, fees and total gross spending are not authenticated; no ALLOW is possible.",
    })
}
