//! Validation of received or stored ClientEvidence bytes against the S7.1 redaction profile.
//! The order of checks is part of the contract: it fixes which error code a bad input gets.

use crate::{
    build_client_evidence, code_ok, coverage_ok, strict_json, Error, Result,
    CLIENT_EVIDENCE_DECISIONS,
};
use std::collections::BTreeSet;

pub const CLIENT_EVIDENCE_MAX_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceStatus {
    /// Empty `canonical_local_evidence_json`: no local evidence was sent.
    Absent,
    Valid,
}

fn sorted_unique_names(
    value: &serde_json::Value,
    limit: usize,
    ok: fn(&str) -> bool,
    error: &'static str,
) -> Result<Vec<String>> {
    let items = value
        .as_array()
        .filter(|a| a.len() <= limit)
        .ok_or(Error(error))?;
    let names: Option<Vec<String>> = items
        .iter()
        .map(|v| v.as_str().filter(|s| ok(s)).map(str::to_owned))
        .collect();
    let names = names.ok_or(Error(error))?;
    if names.windows(2).any(|w| w[0] >= w[1]) {
        return Err(Error("CLIENT_EVIDENCE_NOT_SORTED_UNIQUE"));
    }
    Ok(names)
}

pub fn validate_client_evidence(data: &[u8], local_decision: &str) -> Result<EvidenceStatus> {
    if data.is_empty() {
        return Ok(EvidenceStatus::Absent);
    }
    if data.len() > CLIENT_EVIDENCE_MAX_BYTES {
        return Err(Error("CLIENT_EVIDENCE_TOO_LARGE"));
    }
    let value = strict_json::parse(data)?;
    let object = value.as_object().ok_or(Error("CLIENT_EVIDENCE_KEYS"))?;
    let keys: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    if keys
        != BTreeSet::from([
            "schema_version",
            "kind",
            "local_decision",
            "finding_codes",
            "coverage",
        ])
    {
        return Err(Error("CLIENT_EVIDENCE_KEYS"));
    }
    if object["schema_version"].as_u64() != Some(1)
        || object["kind"].as_str() != Some("hguet_client_evidence")
    {
        return Err(Error("CLIENT_EVIDENCE_KIND"));
    }
    let decision = object["local_decision"]
        .as_str()
        .filter(|d| CLIENT_EVIDENCE_DECISIONS.contains(d))
        .ok_or(Error("CLIENT_EVIDENCE_DECISION"))?;
    let codes = sorted_unique_names(
        &object["finding_codes"],
        64,
        code_ok,
        "CLIENT_EVIDENCE_CODES",
    )?;
    let coverage = sorted_unique_names(
        &object["coverage"],
        32,
        coverage_ok,
        "CLIENT_EVIDENCE_COVERAGE",
    )?;
    if build_client_evidence(decision, &codes, &coverage)? != data {
        return Err(Error("CLIENT_EVIDENCE_NOT_CANONICAL"));
    }
    if decision != local_decision {
        return Err(Error("CLIENT_EVIDENCE_DECISION_MISMATCH"));
    }
    Ok(EvidenceStatus::Valid)
}
