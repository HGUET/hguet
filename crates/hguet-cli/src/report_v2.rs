//! Separately versioned presentation of v1 evidence. No authorization is inferred.
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StructuralValidity {
    Valid,
    Invalid,
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn violation_retains_partial_coverage_and_refusal() {
        let report = from_v1(
            json!({"inspection":{},
            "verdict":{"coverage":["local_restrictive_policy"],
            "limitations":["CPI unresolved"],"findings":[
                {"code":"POLICY_SOL_TRANSFER_CAP","severity":"high","summary":"cap exceeded"},
                {"code":"POLICY_UNRESOLVED_PROGRAM","severity":"high","summary":"lookup unresolved"}]}}),
            20,
            true,
        );
        assert!(matches!(report.policy_compliance, Compliance::Violation));
        assert_eq!(report.coverage[0].status, "PARTIAL");
        assert_eq!(report.signing_authorization, "NOT_AUTHORIZED");
        assert_eq!(
            report.findings[0].evidence_refs[0],
            "/evidence/verdict/findings/0"
        );
    }

    #[test]
    fn scoped_match_requires_completed_policy_evaluation() {
        let report = from_v1(
            json!({"inspection":{},"verdict":{"coverage":["local_restrictive_policy"],"findings":[]}}),
            30,
            true,
        );
        assert!(matches!(report.policy_compliance, Compliance::Match));
        let error = from_v1(json!({"code":"BAD_POLICY"}), 40, true);
        assert!(matches!(error.policy_compliance, Compliance::Unknown));
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Compliance {
    Match,
    Violation,
    Unknown,
    NotConfigured,
}

#[derive(Debug, Serialize)]
pub struct CheckCoverage {
    pub scope: String,
    pub status: &'static str,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub code: String,
    pub severity: String,
    pub summary: String,
    pub evidence_refs: Vec<String>,
    pub scope: &'static str,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct AnalysisReport {
    pub schema_version: u32,
    pub kind: &'static str,
    pub structural_validity: StructuralValidity,
    pub signature_status: Value,
    pub policy_compliance: Compliance,
    pub policy_scope: &'static str,
    pub coverage: Vec<CheckCoverage>,
    pub simulation_status: Value,
    pub findings: Vec<Finding>,
    pub evidence: Value,
    pub signing_authorization: &'static str,
    pub exit_code: i32,
}

/// Conservatively presents existing evidence without upgrading partial coverage.
pub fn from_v1(output: Value, exit_code: i32, policy_configured: bool) -> AnalysisReport {
    let inspection = &output["inspection"];
    let verdict = &output["verdict"];
    let limitations: Vec<String> = verdict["limitations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let findings = verdict["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
        .map(|(index, f)| Finding {
            rule_id: format!("HGUET.{}", f["code"].as_str().unwrap_or("UNKNOWN")),
            code: f["code"].as_str().unwrap_or("UNKNOWN").into(),
            severity: f["severity"].as_str().unwrap_or("unknown").into(),
            summary: f["summary"].as_str().unwrap_or("").into(),
            evidence_refs: vec![format!("/evidence/verdict/findings/{index}")],
            scope: "existing_v1_check",
            limitations: limitations.clone(),
        })
        .collect();
    let validity = if inspection.is_object() {
        StructuralValidity::Valid
    } else if verdict["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|f| f["code"] == "MALFORMED_TRANSACTION")
    {
        StructuralValidity::Invalid
    } else {
        StructuralValidity::Unknown
    };
    let policy_findings: Vec<_> = verdict["findings"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|f| f["code"].as_str().is_some_and(|c| c.starts_with("POLICY_")))
        .collect();
    let compliance = if !policy_configured {
        Compliance::NotConfigured
    } else if policy_findings.iter().any(|f| {
        !f["code"]
            .as_str()
            .unwrap_or("")
            .starts_with("POLICY_UNRESOLVED")
    }) {
        Compliance::Violation
    } else if !policy_findings.is_empty()
        || !verdict["coverage"]
            .as_array()
            .is_some_and(|a| a.iter().any(|c| c == "local_restrictive_policy"))
    {
        Compliance::Unknown
    } else {
        Compliance::Match
    };
    AnalysisReport {
        schema_version: 2,
        kind: "hguet_analysis_report",
        structural_validity: validity,
        signature_status: inspection["transaction_signature_status"].clone(),
        policy_compliance: compliance,
        policy_scope: "configured_local_restrictions_on_original_wire_declarations",
        coverage: verdict["coverage"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(|scope| CheckCoverage {
                scope: scope.into(),
                status: "PARTIAL",
                limitations: limitations.clone(),
            })
            .collect(),
        simulation_status: verdict["simulation_status"].clone(),
        findings,
        evidence: output,
        signing_authorization: "NOT_AUTHORIZED",
        exit_code,
    }
}
