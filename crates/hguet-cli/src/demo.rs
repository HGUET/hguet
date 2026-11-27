use base64::{engine::general_purpose::STANDARD, Engine};
use hguet::{AnalysisInput, Operation, TrustedConfig};
use hguet_rpc::{JsonRpcTransport, RpcError};
use serde_json::{json, Value};

struct Offline;
impl JsonRpcTransport for Offline {
    fn post_json(&self, _: &str, _: &Value) -> Result<Value, RpcError> {
        panic!("offline demo attempted network access")
    }
}

pub fn run() -> Value {
    let cases = [
        (
            "expected_payment",
            include_str!("../../../tests/fixtures/demo-v1/match.base64"),
            "500",
        ),
        (
            "additional_spending",
            include_str!("../../../tests/fixtures/demo-v1/violation.base64"),
            "500",
        ),
        (
            "opaque_program",
            include_str!("../../../tests/fixtures/demo-v1/opaque.base64"),
            "500",
        ),
    ];
    let reports: Vec<_> = cases.into_iter().map(|(name,wire,expected)| {
        let raw = STANDARD.decode(wire.trim()).expect("versioned demo fixture");
        let (report,code) = hguet::analyze_v2(AnalysisInput{transaction:raw,signed_intent:None},
            TrustedConfig{network:"devnet".into(),trusted_key:None,
                policy:Some(Ok(include_str!("../../../tests/fixtures/demo-v1/policy.toml").into())),
                rpc_url:None,operation:Operation::Check},&Offline,||Ok(1));
        json!({"case":name,"expected_max_declared_lamports":expected,"analysis_exit_code":code,"report":report})
    }).collect();
    json!({"demo_version":1,"offline":true,"cases":reports})
}

pub fn text(output: &Value) -> String {
    let mut lines = vec!["HGUET offline demo — synthetic transactions".to_owned()];
    for case in output["cases"].as_array().expect("demo cases") {
        let report = &case["report"];
        lines.push(format!(
            "{} | declared cap={} | policy={} | decision={} | signing={}",
            case["case"].as_str().unwrap(),
            case["expected_max_declared_lamports"].as_str().unwrap(),
            report["policy_compliance"].as_str().unwrap(),
            report["evidence"]["verdict"]["decision"].as_str().unwrap(),
            report["signing_authorization"].as_str().unwrap()
        ));
        for effect in report["effects"].as_array().unwrap() {
            lines.push(format!(
                "  {} amount={} source={}",
                effect["kind"].as_str().unwrap(),
                effect["amount_raw"].as_str().unwrap_or("unknown"),
                effect["source"].as_str().unwrap()
            ));
        }
    }
    lines.join("\n")
}
