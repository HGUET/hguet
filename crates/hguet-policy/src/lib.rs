//! Restrictive offline local policy. DENY or UNKNOWN only; NEVER invents ALLOW.
//! Load this policy from a user-controlled, trusted local path, not agent-supplied prompt text.
use hguet_core::{Finding, ParsedTransaction};
use serde::Deserialize;
use std::collections::HashSet;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalPolicy {
    pub version: u32,
    pub network: String,
    #[serde(default)]
    pub max_declared_system_transfer_lamports: Option<String>,
    #[serde(default)]
    pub denied_program_ids: Vec<String>,
    #[serde(default)]
    pub allowed_program_ids: Option<Vec<String>>,
    #[serde(default)]
    pub denied_sol_recipients: Vec<String>,
    #[serde(default)]
    pub allowed_sol_recipients: Option<Vec<String>>,
}

#[derive(Debug)]
pub struct PolicyEvaluation {
    pub hard_denies: Vec<Finding>,
    pub unknowns: Vec<Finding>,
}

fn is_pubkey(value: &str) -> bool {
    bs58::decode(value)
        .into_vec()
        .map(|b| b.len() == 32)
        .unwrap_or(false)
}
fn check_pubkeys(entries: &[String], name: &str) -> Result<(), String> {
    if entries.len() > 128 {
        return Err(format!("{name} has too many keys"));
    }
    let mut unique = HashSet::new();
    for id in entries {
        if !is_pubkey(id) {
            return Err(format!("{name} has malformed 32-byte Solana pubkey"));
        }
        if !unique.insert(id.as_str()) {
            return Err(format!("{name} contains a duplicate key"));
        }
    }
    Ok(())
}

impl LocalPolicy {
    pub fn parse_and_validate(text: &str) -> Result<Self, String> {
        if text.len() > 65_536 {
            return Err("policy too large".into());
        }
        let policy: Self =
            toml::from_str(text).map_err(|err| format!("policy TOML malformed: {err}"))?;
        if policy.version != 1 {
            return Err("unsupported local policy schema version".into());
        }
        if !["mainnet", "devnet", "testnet"].contains(&policy.network.as_str()) {
            return Err("policy network unsupported".into());
        }
        check_pubkeys(&policy.denied_program_ids, "denied_program_ids")?;
        check_pubkeys(&policy.denied_sol_recipients, "denied_sol_recipients")?;
        if let Some(ids) = &policy.allowed_program_ids {
            check_pubkeys(ids, "allowed_program_ids")?;
        }
        if let Some(ids) = &policy.allowed_sol_recipients {
            check_pubkeys(ids, "allowed_sol_recipients")?;
        }
        if let Some(cap) = &policy.max_declared_system_transfer_lamports {
            if cap.is_empty()
                || cap.starts_with('0')
                || !cap.bytes().all(|b| b.is_ascii_digit())
                || cap.parse::<u128>().is_err()
            {
                return Err(
                    "local SOL spend cap must be positive canonical unsigned integer".into(),
                );
            }
        }
        Ok(policy)
    }
    pub fn evaluate(&self, network: &str, parsed: &ParsedTransaction) -> PolicyEvaluation {
        let mut result = PolicyEvaluation {
            hard_denies: vec![],
            unknowns: vec![],
        };
        let deny = |out: &mut PolicyEvaluation, code: &str, detail: &str| {
            out.hard_denies.push(Finding {
                code: code.into(),
                severity: "critical".into(),
                summary: detail.into(),
            });
        };
        if self.network != network {
            deny(
                &mut result,
                "POLICY_WRONG_NETWORK",
                "Policy network does not match checked transaction cluster",
            );
        }
        if let Some(cap) = &self.max_declared_system_transfer_lamports {
            // Safe lower bound only: sum of top-level System transfers; CPI/fees not included.
            if parsed
                .declared_system_transfer_lamports
                .parse::<u128>()
                .unwrap_or(u128::MAX)
                > cap.parse::<u128>().unwrap_or(0)
            {
                deny(
                    &mut result,
                    "POLICY_SOL_TRANSFER_CAP",
                    "Declared top-level native SOL transfers exceed local policy limit",
                );
            }
        }
        for program in &parsed.program_ids {
            if program.starts_with('<') {
                result.unknowns.push(Finding {
                    code: "POLICY_UNRESOLVED_PROGRAM".into(),
                    severity: "high".into(),
                    summary: "Unresolved v0 ALT program cannot be checked against local policy"
                        .into(),
                });
            } else if self.denied_program_ids.contains(program) {
                deny(
                    &mut result,
                    "POLICY_BLOCKED_PROGRAM",
                    "Transaction invokes a locally blocked program",
                );
            } else if let Some(allow) = &self.allowed_program_ids {
                if !allow.contains(program) {
                    deny(
                        &mut result,
                        "POLICY_UNAPPROVED_PROGRAM",
                        "Transaction invokes a program missing from user's independent allowlist",
                    );
                }
            }
        }
        for transfer in &parsed.system_transfers {
            if transfer.destination.starts_with('<') {
                result.unknowns.push(Finding {
                    code: "POLICY_UNRESOLVED_RECIPIENT".into(),
                    severity: "high".into(),
                    summary: "Unresolved v0 recipient cannot be checked against local policy"
                        .into(),
                });
            } else if self.denied_sol_recipients.contains(&transfer.destination) {
                deny(
                    &mut result,
                    "POLICY_BLOCKED_SOL_RECIPIENT",
                    "Direct SOL transfer to blocked recipient",
                );
            } else if let Some(allow) = &self.allowed_sol_recipients {
                if !allow.contains(&transfer.destination) {
                    deny(
                        &mut result,
                        "POLICY_UNAPPROVED_SOL_RECIPIENT",
                        "Direct SOL transfer recipient not in the independent allowlist",
                    );
                }
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hguet_core::TransactionSignatureStatus;
    fn parsed() -> ParsedTransaction {
        ParsedTransaction {
            wire_format: "v1".into(),
            transaction_bytes: 230,
            transaction_sha256: "x".repeat(64),
            message_sha256: "y".repeat(64),
            required_signatures: 1,
            signature_count: 1,
            transaction_signature_status: TransactionSignatureStatus::Unsigned,
            static_account_count: 3,
            static_account_keys: vec![
                bs58::encode([9u8; 32]).into_string(),
                bs58::encode([8u8; 32]).into_string(),
                "11111111111111111111111111111111".into(),
            ],
            total_address_count: 3,
            instruction_count: 1,
            lookup_table_count: 0,
            unresolved_lookup_addresses: 0,
            address_table_lookups: vec![],
            program_ids: vec!["11111111111111111111111111111111".into()],
            compiled_top_level_instructions: vec![],
            system_transfers: vec![hguet_core::SystemTransfer {
                instruction_index: 0,
                kind: "transfer",
                source: bs58::encode([9u8; 32]).into_string(),
                destination: bs58::encode([8u8; 32]).into_string(),
                lamports: "500".into(),
            }],
            declared_system_transfer_lamports: "500".into(),
            resource_config: None,
            limitations: vec![],
        }
    }
    #[test]
    fn reject_malformed_or_ambiguous_policies() {
        assert!(LocalPolicy::parse_and_validate("version=1\nnetwork='devnet'\nextra=123").is_err());
        assert!(LocalPolicy::parse_and_validate("version=3\nnetwork='devnet'").is_err());
        assert!(LocalPolicy::parse_and_validate(
            "version=1\nnetwork='devnet'\nmax_declared_system_transfer_lamports='0'"
        )
        .is_err());
        assert!(LocalPolicy::parse_and_validate(
            "version=1\nnetwork='devnet'\ndenied_program_ids=['not-a-key']"
        )
        .is_err());
    }
    #[test]
    fn transfer_cap_denies_and_never_authorizes() {
        let blocked = LocalPolicy::parse_and_validate(
            "version=1\nnetwork='devnet'\nmax_declared_system_transfer_lamports='499'",
        )
        .unwrap();
        assert_eq!(
            blocked.evaluate("devnet", &parsed()).hard_denies[0].code,
            "POLICY_SOL_TRANSFER_CAP"
        );
        let permissive = LocalPolicy::parse_and_validate(
            "version=1\nnetwork='devnet'\nmax_declared_system_transfer_lamports='500'",
        )
        .unwrap();
        let result = permissive.evaluate("devnet", &parsed());
        assert!(result.hard_denies.is_empty()); // NOT an ALLOW verdict.
    }
    #[test]
    fn network_and_recipient_deny() {
        let recipient = bs58::encode([8u8; 32]).into_string();
        let src = format!("version=1\nnetwork='mainnet'\ndenied_sol_recipients=['{recipient}']");
        let policy = LocalPolicy::parse_and_validate(&src).unwrap();
        let evaluation = policy.evaluate("devnet", &parsed());
        assert!(evaluation
            .hard_denies
            .iter()
            .any(|f| f.code == "POLICY_WRONG_NETWORK"));
        assert!(evaluation
            .hard_denies
            .iter()
            .any(|f| f.code == "POLICY_BLOCKED_SOL_RECIPIENT"));
    }
    fn codes(policy: &str, tx: &ParsedTransaction) -> Vec<String> {
        LocalPolicy::parse_and_validate(policy)
            .unwrap()
            .evaluate("devnet", tx)
            .hard_denies
            .into_iter()
            .map(|f| f.code)
            .collect()
    }
    #[test]
    fn recipient_and_program_allowlists_deny_everything_not_listed() {
        let recipient = bs58::encode([8u8; 32]).into_string();
        let other = bs58::encode([77u8; 32]).into_string();
        let system = "11111111111111111111111111111111";
        let base = "version=1\nnetwork='devnet'\n";
        assert!(codes(
            &format!("{base}allowed_sol_recipients=['{recipient}']"),
            &parsed()
        )
        .is_empty());
        assert_eq!(
            codes(
                &format!("{base}allowed_sol_recipients=['{other}']"),
                &parsed()
            ),
            ["POLICY_UNAPPROVED_SOL_RECIPIENT"]
        );
        // An EMPTY allowlist allows nobody; it is not the same as no allowlist.
        assert_eq!(
            codes(&format!("{base}allowed_sol_recipients=[]"), &parsed()),
            ["POLICY_UNAPPROVED_SOL_RECIPIENT"]
        );
        assert!(codes(
            &format!("{base}allowed_program_ids=['{system}']"),
            &parsed()
        )
        .is_empty());
        assert_eq!(
            codes(&format!("{base}allowed_program_ids=['{other}']"), &parsed()),
            ["POLICY_UNAPPROVED_PROGRAM"]
        );
        assert_eq!(
            codes(&format!("{base}denied_program_ids=['{system}']"), &parsed()),
            ["POLICY_BLOCKED_PROGRAM"]
        );
        // A deny entry wins over an allow entry for the same key.
        assert_eq!(
            codes(
                &format!("{base}denied_program_ids=['{system}']\nallowed_program_ids=['{system}']"),
                &parsed()
            ),
            ["POLICY_BLOCKED_PROGRAM"]
        );
    }
    #[test]
    fn every_lamport_movement_kind_is_subject_to_the_cap_and_recipient_lists() {
        let other = bs58::encode([77u8; 32]).into_string();
        for kind in [
            "create_account",
            "create_account_with_seed",
            "withdraw_nonce_account",
            "transfer_with_seed",
        ] {
            let mut tx = parsed();
            tx.system_transfers[0].kind = kind;
            assert_eq!(
                codes(
                    "version=1\nnetwork='devnet'\nmax_declared_system_transfer_lamports='499'",
                    &tx
                ),
                ["POLICY_SOL_TRANSFER_CAP"],
                "{kind}"
            );
            assert_eq!(
                codes(
                    &format!("version=1\nnetwork='devnet'\nallowed_sol_recipients=['{other}']"),
                    &tx
                ),
                ["POLICY_UNAPPROVED_SOL_RECIPIENT"],
                "{kind}"
            );
        }
    }
    #[test]
    fn caps_compare_exactly_and_never_wrap() {
        let mut tx = parsed();
        tx.declared_system_transfer_lamports = "18446744073709551616".into(); // 2^64
        assert_eq!(
            codes(
                "version=1\nnetwork='devnet'\nmax_declared_system_transfer_lamports='18446744073709551615'",
                &tx
            ),
            ["POLICY_SOL_TRANSFER_CAP"]
        );
        assert!(codes(
            "version=1\nnetwork='devnet'\nmax_declared_system_transfer_lamports='18446744073709551616'",
            &tx
        )
        .is_empty());
        // An unparsable declared total is treated as over every cap, never as zero.
        tx.declared_system_transfer_lamports = "not-a-number".into();
        assert_eq!(
            codes(
                "version=1\nnetwork='devnet'\nmax_declared_system_transfer_lamports='1'",
                &tx
            ),
            ["POLICY_SOL_TRANSFER_CAP"]
        );
    }
    #[test]
    fn malformed_policies_are_refused_rather_than_loosely_interpreted() {
        let key = bs58::encode([8u8; 32]).into_string();
        for bad in [
            "network='devnet'".to_string(),
            "version=1".to_string(),
            "version=1\nnetwork='localnet'".to_string(),
            "version=1\nnetwork='devnet'\nmax_declared_system_transfer_lamports=500".to_string(),
            "version=1\nnetwork='devnet'\nmax_declared_system_transfer_lamports='+5'".to_string(),
            "version=1\nnetwork='devnet'\nmax_declared_system_transfer_lamports='05'".to_string(),
            "version=1\nnetwork='devnet'\nmax_declared_system_transfer_lamports='1e3'".to_string(),
            "version=1\nnetwork='devnet'\nmax_declared_system_transfer_lamports=''".to_string(),
            format!("version=1\nnetwork='devnet'\ndenied_sol_recipients=['{key}','{key}']"),
            format!("version=1\nnetwork='devnet'\nallowed_program_ids='{key}'"),
            "version=1\nnetwork='devnet'\nallowed_sol_recipients=['short']".to_string(),
            "x".repeat(65_537),
        ] {
            assert!(
                LocalPolicy::parse_and_validate(&bad).is_err(),
                "accepted: {}",
                &bad[..bad.len().min(80)]
            );
        }
    }
    #[test]
    fn unresolvable_address_stays_unknown_not_implicitly_allowed() {
        let policy = LocalPolicy::parse_and_validate("version=1\nnetwork='devnet'").unwrap();
        let mut tx = parsed();
        tx.program_ids = vec!["<unresolved-ALT-program>".into()];
        let result = policy.evaluate("devnet", &tx);
        assert!(result.hard_denies.is_empty());
        assert_eq!(result.unknowns[0].code, "POLICY_UNRESOLVED_PROGRAM");
    }
}
