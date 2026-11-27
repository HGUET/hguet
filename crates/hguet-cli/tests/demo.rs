use std::process::Command;

#[test]
fn demo_runs_engine_and_keeps_opaque_effects_unknown() {
    let output = Command::new(env!("CARGO_BIN_EXE_hguet"))
        .args(["demo", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let demo: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let cases = demo["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 3);
    assert_eq!(cases[0]["report"]["policy_compliance"], "MATCH");
    assert_eq!(
        cases[0]["report"]["evidence"]["verdict"]["decision"],
        "UNKNOWN"
    );
    assert_eq!(cases[1]["report"]["policy_compliance"], "VIOLATION");
    assert_eq!(
        cases[1]["report"]["evidence"]["verdict"]["decision"],
        "DENY"
    );
    assert_eq!(cases[1]["report"]["effects"].as_array().unwrap().len(), 2);
    assert_eq!(cases[2]["report"]["effects"][0]["kind"], "unknown");
    assert_eq!(
        cases[2]["report"]["evidence"]["verdict"]["decision"],
        "UNKNOWN"
    );
    for case in cases {
        assert_eq!(case["report"]["signing_authorization"], "NOT_AUTHORIZED");
    }
}
