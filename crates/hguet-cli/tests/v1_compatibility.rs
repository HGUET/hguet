use std::process::Command;

#[test]
fn engine_preserves_baseline_v1_output_and_error_precedence() {
    let cases: serde_json::Value = serde_json::from_str(include_str!("v1-golden.json")).unwrap();
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for case in cases.as_array().unwrap() {
        let args: Vec<_> = case["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        let output = Command::new(env!("CARGO_BIN_EXE_hguet"))
            .current_dir(&root)
            .args(&args)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            case["exit"].as_i64().map(|v| v as i32),
            "{args:?}"
        );
        let actual: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(actual, case["output"], "{args:?}");
    }
}
