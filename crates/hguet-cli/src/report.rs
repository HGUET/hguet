//! Combined offline dossier from one bounded program inventory.
use crate::{authority, flow, programs};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct TransactionReport {
    pub schema_version: u8,
    pub kind: &'static str,
    pub source: &'static str,
    pub message_sha256: String,
    pub execution_proven: bool,
    pub signing_authorization: &'static str,
    pub wire: flow::FlowReport,
    pub authority: authority::AuthorityReport,
    pub limitations: Vec<&'static str>,
}

pub fn inspect(bytes: &[u8]) -> Result<TransactionReport, String> {
    let programs = programs::inspect(bytes)?;
    let authority = authority::from_program_report(programs.clone());
    let wire = flow::from_program_report(programs)?;
    Ok(TransactionReport {
        schema_version: 1,
        kind: "hguet_transaction_report",
        source: "original_wire",
        message_sha256: wire.message_sha256.clone(),
        execution_proven: false,
        signing_authorization: "NOT_AUTHORIZED",
        wire,
        authority,
        limitations: vec![
            "Both views derive from the same original message and program inventory.",
            "The repeated inventory preserves standalone report contracts; do not count it twice.",
            "No simulation, live account state, execution proof or authorization is implied.",
            "Unknown quantities, unresolved addresses and unclassified operations remain coverage gaps.",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn unified_views_match_independent_contracts() {
        let bytes = STANDARD
            .decode(include_str!("../../../tests/fixtures/v1-system-transfer.base64").trim())
            .unwrap();
        let report = inspect(&bytes).unwrap();
        assert_eq!(report.wire.message_sha256, report.authority.message_sha256);
        assert_eq!(report.message_sha256, report.wire.message_sha256);
        assert_eq!(
            serde_json::to_value(&report.wire).unwrap(),
            serde_json::to_value(flow::inspect(&bytes).unwrap()).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&report.authority).unwrap(),
            serde_json::to_value(authority::inspect(&bytes).unwrap()).unwrap()
        );
        assert!(!report.execution_proven);
        assert_eq!(report.signing_authorization, "NOT_AUTHORIZED");
    }
}
