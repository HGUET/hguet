//! Historical transaction report: signed bytes and provider metadata stay separate.
use crate::{authority, flow};
use hguet_rpc::{history, JsonRpcTransport};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct AuditReport {
    pub schema_version: u8,
    pub kind: &'static str,
    pub network: String,
    pub signature: String,
    pub status: &'static str,
    pub rpc_error: Option<&'static str>,
    pub verified_genesis_hash: Option<String>,
    pub signatures_verified: bool,
    pub execution_proven: bool,
    pub signing_authorization: &'static str,
    pub wire: Option<flow::FlowReport>,
    pub authority: Option<authority::AuthorityReport>,
    pub historical: Option<history::HistoricalEvidence>,
    pub limitations: Vec<&'static str>,
}

pub fn inspect<T: JsonRpcTransport>(
    signature: &str,
    network: &str,
    endpoint: &str,
    transport: &T,
) -> Result<AuditReport, String> {
    history::validate_signature(signature).map_err(|_| "invalid transaction signature")?;
    hguet_rpc::validate_endpoint(endpoint).map_err(|e| e.code().to_owned())?;
    hguet_rpc::expected_genesis(network).map_err(|e| e.code().to_owned())?;
    let mut report = AuditReport {
        schema_version: 1,
        kind: "hguet_historical_audit",
        network: network.into(),
        signature: signature.into(),
        status: "RPC_UNAVAILABLE",
        rpc_error: None,
        verified_genesis_hash: None,
        signatures_verified: false,
        execution_proven: false,
        signing_authorization: "NOT_AUTHORIZED",
        wire: None,
        authority: None,
        historical: None,
        limitations: vec![
            "Finalized is requested, not independently verified; genesis is a provider claim.",
            "Local signature verification binds the returned message to the requested first signature, not ledger inclusion.",
            "Historical metadata and loaded addresses are untrusted single-provider observations.",
            "No current account state, replay, simulation or authorization proof is inferred.",
            "Wire declarations, CPI claims and net balance rows must not be added together.",
            "Missing metadata is not evidence of zero change; failed transactions may still incur fees.",
        ],
    };
    match history::fetch(transport, endpoint, network, signature) {
        Err(error) => report.rpc_error = Some(error.code()),
        Ok(result) => {
            report.verified_genesis_hash = Some(result.genesis_hash);
            if let Some(transaction) = result.transaction {
                report.wire = Some(flow::inspect(&transaction.wire)?);
                report.authority = Some(authority::inspect(&transaction.wire)?);
                report.status = "FOUND_SIGNATURE_VERIFIED";
                report.signatures_verified = true;
                report.historical = Some(transaction.evidence);
            } else {
                report.status = "NOT_FOUND_AT_REQUESTED_COMMITMENT";
            }
        }
    }
    Ok(report)
}
