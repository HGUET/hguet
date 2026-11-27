use std::process::Command;

#[test]
fn bounded_stdin_and_text_use_the_same_pipeline() {
    use std::io::Write;
    use std::process::Stdio;
    let binary = env!("CARGO_BIN_EXE_hguet");
    let mut child = Command::new(binary)
        .args([
            "inspect",
            "-",
            "--offline",
            "--encoding",
            "base64",
            "--text",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(include_bytes!(
            "../../../tests/fixtures/v1-system-transfer.base64"
        ))
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(result.status.success());
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(text.contains("Transaction structure: VALID"));
    assert!(text.contains("native_transfer amount=500"));
    assert!(text.contains("Signing: NOT_AUTHORIZED"));
    let invalid = Command::new(binary)
        .args(["inspect", "-", "--offline", "--text", "--json"])
        .output()
        .unwrap();
    assert_eq!(invalid.status.code(), Some(40));
    assert!(invalid.stdout.is_empty());
}

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

#[test]
fn report_v2_input_errors_keep_the_versioned_contract() {
    use std::io::Write;
    use std::process::Stdio;

    let binary = env!("CARGO_BIN_EXE_hguet");
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    for args in [
        vec![
            "inspect",
            "tests/fixtures/nonexistent-input.bin",
            "--offline",
            "--report-v2",
        ],
        vec![
            "inspect",
            "-",
            "--offline",
            "--encoding",
            "invalid",
            "--report-v2",
        ],
        vec![
            "check",
            "tests/fixtures/v1-system-transfer.base64",
            "--encoding",
            "base64",
            "--policy",
            "tests/fixtures/nonexistent-policy.toml",
            "--report-v2",
        ],
    ] {
        let result = Command::new(binary)
            .current_dir(&root)
            .args(args)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(40));
        let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["schema_version"], 2);
        assert_eq!(report["exit_code"], 40);
        assert_eq!(report["signing_authorization"], "NOT_AUTHORIZED");
        assert_eq!(report["effects"], serde_json::json!([]));
    }
    let mut child = Command::new(binary)
        .args([
            "inspect",
            "-",
            "--offline",
            "--encoding",
            "base64",
            "--report-v2",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"not valid base64!")
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(result.status.code(), Some(40));
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["schema_version"], 2);
    assert_eq!(report["signing_authorization"], "NOT_AUTHORIZED");
}
