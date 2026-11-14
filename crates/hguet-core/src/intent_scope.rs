//! Context-aware review of token-account *control* operations against an
//! independently verified PaymentIntent, plus the DENY/UNKNOWN split.
//!
//! Two kinds of non-success exist and must never be conflated:
//!
//! * **Violation** – the wire bytes PROVE an action that no PaymentIntent v1 can
//!   authorise (for example handing token-account ownership to a key that is
//!   neither the current authority nor a transaction signer). Result: DENY.
//! * **Coverage gap** – the tool cannot establish the facts (unresolved address
//!   lookup, multisig accounts, unsupported or merely administrative
//!   instructions). Nothing is proven violated. Result: UNKNOWN with a
//!   structured reason. A coverage gap is never reported as `INTENT_REJECTED`.
//!
//! A PaymentIntent v1 carries a program allowlist, a SOL cap and optional token
//! debit/source caps. It has no field that authorises changing who controls a
//! token account, so such a change toward a non-signing third party is outside
//! every intent by construction. Moves toward a signer of the same transaction
//! or administrative operations are *not* forbidden here: they stay UNKNOWN.

use crate::solana_engine::ParsedTransaction;
use serde::Serialize;

pub const TOKEN_LEGACY: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
pub const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const UNRESOLVED_PROGRAM: &str = "<unresolved-ALT-program>";

/// Outcome of a failed review: either a proven violation or a coverage gap.
#[derive(Debug, Clone)]
pub struct ReviewFailure {
    /// `Some(reason)` = coverage gap (UNKNOWN); `None` = proven violation (DENY).
    pub coverage_reason: Option<&'static str>,
    pub message: String,
}

impl ReviewFailure {
    pub(crate) fn violation(message: impl Into<String>) -> Self {
        Self {
            coverage_reason: None,
            message: message.into(),
        }
    }
    pub(crate) fn coverage(reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            coverage_reason: Some(reason),
            message: message.into(),
        }
    }
}

impl From<&str> for ReviewFailure {
    fn from(value: &str) -> Self {
        Self::violation(value)
    }
}

impl From<String> for ReviewFailure {
    fn from(value: String) -> Self {
        Self::violation(value)
    }
}

impl From<ReviewFailure> for String {
    fn from(value: ReviewFailure) -> Self {
        value.message
    }
}

/// One structured scope finding with machine-readable evidence references.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ScopeFinding {
    pub code: &'static str,
    pub severity: &'static str,
    /// true = proven violation (DENY); false = coverage gap (UNKNOWN).
    pub violation: bool,
    /// Machine-readable reason for a coverage gap.
    pub gap_reason: Option<&'static str>,
    pub summary: String,
    /// Stable references: `instruction:N`, `program:..`, `account:..`, `intent:..`.
    pub evidence_refs: Vec<String>,
}

fn authority_type_name(value: u8) -> String {
    match value {
        0 => "MintTokens".into(),
        1 => "FreezeAccount".into(),
        2 => "AccountOwner".into(),
        3 => "CloseAccount".into(),
        other => format!("Token2022Extension({other})"),
    }
}

/// Review direct `SetAuthority` (opcode 6) and `CloseAccount` (opcode 9)
/// instructions of the original wire against the verified intent.
pub fn review_account_control(parsed: &ParsedTransaction, intent_id: &str) -> Vec<ScopeFinding> {
    let mut out = Vec::new();
    let signers: &[String] = if parsed.required_signatures <= parsed.static_account_keys.len() {
        &parsed.static_account_keys[..parsed.required_signatures]
    } else {
        &[]
    };
    for (i, ix) in parsed.compiled_top_level_instructions.iter().enumerate() {
        let Some(program) = parsed.static_account_keys.get(ix.program_index) else {
            continue; // program behind an unresolved lookup: handled as ALT coverage elsewhere
        };
        if program != TOKEN_LEGACY && program != TOKEN_2022 {
            continue;
        }
        let Ok(data) = bs58::decode(&ix.data_base58).into_vec() else {
            continue;
        };
        let Some(&opcode) = data.first() else {
            continue;
        };
        if opcode != 6 && opcode != 9 {
            continue;
        }
        let key = |role: usize| -> Option<&String> {
            ix.account_indices
                .get(role)
                .and_then(|n| parsed.static_account_keys.get(*n))
        };
        let mut refs = vec![
            format!("instruction:{i}"),
            format!("program:{program}"),
            format!("intent:{intent_id}"),
            "intent_signature:verified_against_pinned_key".to_string(),
            "intent_scope:no_account_control_grant_in_payment_intent_v1".to_string(),
        ];
        match opcode {
            6 => {
                let (Some(account), Some(current)) = (key(0), key(1)) else {
                    out.push(gap(
                        "TOKEN_ACCOUNT_CONTROL_UNRESOLVED_ACCOUNTS",
                        "SetAuthority references an account behind an unresolved lookup or outside the message",
                        "ACCOUNT_REFERENCE_UNRESOLVED",
                        refs,
                    ));
                    continue;
                };
                let kind = data.get(1).copied().map(authority_type_name);
                refs.push(format!("account:{account}"));
                refs.push(format!("current_authority:{current}"));
                if let Some(name) = &kind {
                    refs.push(format!("authority_type:{name}"));
                }
                let new_authority = match (data.len(), data.get(2)) {
                    (35, Some(1)) => Some(bs58::encode(&data[3..35]).into_string()),
                    (3, Some(0)) => None,
                    _ => {
                        out.push(gap(
                            "TOKEN_ACCOUNT_CONTROL_UNSUPPORTED_ENCODING",
                            "SetAuthority data has an encoding this decoder does not support",
                            "UNSUPPORTED_TOKEN_INSTRUCTION",
                            refs,
                        ));
                        continue;
                    }
                };
                match new_authority {
                    None => out.push(gap(
                        "TOKEN_AUTHORITY_REVOKE_IRREVERSIBLE",
                        "SetAuthority removes an authority permanently; not forbidden, but irreversible and not covered by any signed limit",
                        "ACCOUNT_MANAGEMENT_NOT_COVERED",
                        refs,
                    )),
                    Some(new) if signers.contains(&new) || &new == current => {
                        refs.push(format!("new_authority:{new}"));
                        out.push(gap(
                            "TOKEN_AUTHORITY_CHANGE_UNPROVEN",
                            "SetAuthority targets the current authority or a signer of this transaction; whether that key belongs to the same principal cannot be established offline",
                            "ACCOUNT_CONTROL_SIGNER_BINDING_UNPROVEN",
                            refs,
                        ));
                    }
                    Some(new) => {
                        refs.push(format!("new_authority:{new}"));
                        out.push(ScopeFinding {
                            code: "INTENT_SCOPE_AUTHORITY_TRANSFER",
                            severity: "critical",
                            violation: true,
                            gap_reason: None,
                            summary: format!(
                                "SetAuthority ({}) on {account} hands control to {new}, which is neither the current authority nor a signer of this transaction; a PaymentIntent cannot authorise it (evidence: {})",
                                kind.unwrap_or_else(|| "unknown type".into()),
                                refs.join(", ")
                            ),
                            evidence_refs: refs,
                        });
                    }
                }
            }
            _ => {
                let (Some(account), Some(destination)) = (key(0), key(1)) else {
                    out.push(gap(
                        "TOKEN_ACCOUNT_CONTROL_UNRESOLVED_ACCOUNTS",
                        "CloseAccount references an account behind an unresolved lookup or outside the message",
                        "ACCOUNT_REFERENCE_UNRESOLVED",
                        refs,
                    ));
                    continue;
                };
                refs.push(format!("account:{account}"));
                refs.push(format!("destination:{destination}"));
                if signers.contains(destination) {
                    out.push(gap(
                        "TOKEN_CLOSE_DESTINATION_UNPROVEN",
                        "CloseAccount returns the balance and rent to a signer of this transaction; account-management is not forbidden, but who controls that key cannot be established offline",
                        "ACCOUNT_CONTROL_SIGNER_BINDING_UNPROVEN",
                        refs,
                    ));
                } else {
                    out.push(ScopeFinding {
                        code: "INTENT_SCOPE_CLOSE_DESTINATION",
                        severity: "critical",
                        violation: true,
                        gap_reason: None,
                        summary: format!(
                            "CloseAccount sweeps {account} (balance and rent, including wrapped SOL) to {destination}, which does not sign this transaction; no PaymentIntent grants it and it escapes max_spend_lamports (evidence: {})",
                            refs.join(", ")
                        ),
                        evidence_refs: refs,
                    });
                }
            }
        }
    }
    out
}

fn gap(
    code: &'static str,
    summary: &str,
    reason: &'static str,
    evidence_refs: Vec<String>,
) -> ScopeFinding {
    ScopeFinding {
        code,
        severity: "high",
        violation: false,
        gap_reason: Some(reason),
        summary: summary.to_string(),
        evidence_refs,
    }
}

/// True when the placeholder used by the parser for a program behind an
/// unresolved Address Lookup Table is the given string.
pub(crate) fn is_unresolved_program(program: &str) -> bool {
    program == UNRESOLVED_PROGRAM
}

/// Opcode classes of direct Token Program instructions that signed *debit*
/// limits can never bound.
pub(crate) enum Unbounded {
    /// Known operation that is a debit/authority/mint action outside every cap.
    OutOfScope,
    /// Known administrative operation or an unsupported/opaque/malformed form.
    Coverage(&'static str),
}

pub(crate) fn classify_unbounded(opcode: Option<u8>) -> Unbounded {
    match opcode {
        // Transfer, Approve, SetAuthority, MintTo, Burn, CloseAccount, ApproveChecked,
        // MintToChecked, FreezeAccount, ThawAccount: money or control moves, outside
        // the caps. SetAuthority/CloseAccount reach here only on the legacy fail-closed
        // path; verify_intent_detailed judges them in context via review_account_control.
        Some(3 | 4 | 6 | 7 | 8 | 9 | 10 | 11 | 13 | 14) => Unbounded::OutOfScope,
        // Revoke, SyncNative, Initialize*, GetAccountDataSize and friends are
        // administrative: not forbidden, just not covered.
        Some(1 | 2 | 5 | 16 | 17 | 18 | 19 | 20 | 21 | 22) => {
            Unbounded::Coverage("ACCOUNT_MANAGEMENT_NOT_COVERED")
        }
        _ => Unbounded::Coverage("UNSUPPORTED_TOKEN_INSTRUCTION"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse_transaction;

    fn k(n: u8) -> String {
        bs58::encode([n; 32]).into_string()
    }

    /// One required signer (k(1)); k(2..5) plain accounts; legacy Token program.
    fn wire(ops: &[(Vec<u8>, Vec<u8>)]) -> ParsedTransaction {
        let mut v = vec![1];
        v.extend([0u8; 64]);
        let keys = [k(1), k(2), k(3), k(4), k(5), TOKEN_LEGACY.to_string()];
        v.extend([1, 0, 1, 6]);
        for key in &keys {
            v.extend(bs58::decode(key).into_vec().unwrap());
        }
        v.extend([9u8; 32]);
        v.push(ops.len() as u8);
        for (data, accounts) in ops {
            v.push(5);
            v.push(accounts.len() as u8);
            v.extend(accounts);
            v.push(data.len() as u8);
            v.extend(data);
        }
        parse_transaction(&v).unwrap()
    }

    fn set_authority(kind: u8, new: Option<u8>) -> (Vec<u8>, Vec<u8>) {
        let mut data = vec![6, kind];
        match new {
            Some(n) => {
                data.push(1);
                data.extend([n; 32]);
            }
            None => data.push(0),
        }
        (data, vec![1, 0])
    }

    #[test]
    fn set_authority_to_a_non_signing_third_party_is_a_proven_violation_with_evidence() {
        let tx = wire(&[set_authority(2, Some(4))]);
        let found = review_account_control(&tx, "intent-1");
        assert_eq!(found.len(), 1);
        let f = &found[0];
        assert!(
            f.violation && f.code == "INTENT_SCOPE_AUTHORITY_TRANSFER" && f.gap_reason.is_none()
        );
        for needle in [
            "instruction:0",
            "intent:intent-1",
            &format!("new_authority:{}", k(4)),
            &format!("current_authority:{}", k(1)),
            "authority_type:AccountOwner",
        ] {
            assert!(
                f.evidence_refs.iter().any(|r| r == needle),
                "missing evidence {needle}"
            );
        }
    }

    #[test]
    fn set_authority_toward_a_signer_or_revocation_is_only_a_coverage_gap() {
        let to_signer = review_account_control(&wire(&[set_authority(2, Some(1))]), "i");
        assert!(!to_signer[0].violation);
        assert_eq!(
            to_signer[0].gap_reason,
            Some("ACCOUNT_CONTROL_SIGNER_BINDING_UNPROVEN")
        );
        let revoke = review_account_control(&wire(&[set_authority(0, None)]), "i");
        assert!(!revoke[0].violation);
        assert_eq!(revoke[0].code, "TOKEN_AUTHORITY_REVOKE_IRREVERSIBLE");
    }

    #[test]
    fn close_account_destination_decides_violation_versus_gap() {
        // accounts: [account=k(2), destination, owner=k(1)]
        let to_third = wire(&[(vec![9], vec![1, 3, 0])]);
        let found = review_account_control(&to_third, "i");
        assert!(found[0].violation && found[0].code == "INTENT_SCOPE_CLOSE_DESTINATION");
        let to_signer = wire(&[(vec![9], vec![1, 0, 0])]);
        let found = review_account_control(&to_signer, "i");
        assert!(!found[0].violation && found[0].code == "TOKEN_CLOSE_DESTINATION_UNPROVEN");
    }

    #[test]
    fn unrelated_token_operations_produce_no_scope_findings() {
        let transfer = wire(&[(vec![12, 1, 0, 0, 0, 0, 0, 0, 0, 6], vec![1, 3, 2, 0])]);
        assert!(review_account_control(&transfer, "i").is_empty());
    }

    #[test]
    fn unbounded_classification_separates_out_of_scope_from_coverage() {
        for out_of_scope in [3u8, 4, 6, 7, 8, 9, 10, 11, 13, 14] {
            assert!(matches!(
                classify_unbounded(Some(out_of_scope)),
                Unbounded::OutOfScope
            ));
        }
        for administrative in [5u8, 17, 1, 22] {
            assert!(matches!(
                classify_unbounded(Some(administrative)),
                Unbounded::Coverage("ACCOUNT_MANAGEMENT_NOT_COVERED")
            ));
        }
        for unknown in [Some(99u8), Some(255), None] {
            assert!(matches!(
                classify_unbounded(unknown),
                Unbounded::Coverage("UNSUPPORTED_TOKEN_INSTRUCTION")
            ));
        }
    }
}
