//! Deterministic, unsigned synthetic demonstration corpus. Never signs or sends.
use crate::{diff, html, report};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Serialize;
use serde_json::{json, Value};
use std::io::Write;
use std::path::Path;

pub const CASES: [&str; 6] = [
    "payment",
    "additional-debit",
    "authority",
    "token2022",
    "uncertainty",
    "diff",
];

#[derive(Debug, Serialize)]
pub struct LabCase {
    pub lab_version: u8,
    pub kind: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub synthetic: bool,
    pub execution_performed: bool,
    pub signing_authorization: &'static str,
    pub transaction_base64: String,
    pub before_transaction_base64: Option<String>,
    pub report: Value,
}

fn fixture(text: &str) -> Result<Vec<u8>, String> {
    STANDARD
        .decode(text.trim())
        .map_err(|_| "invalid bundled fixture".into())
}

fn key(address: &str) -> Result<[u8; 32], String> {
    bs58::decode(address)
        .into_vec()
        .map_err(|_| "invalid fixture public key")?
        .try_into()
        .map_err(|_| "invalid fixture public key length".into())
}

// A small fixed legacy-wire constructor used only by the synthetic lab.
// No secret keys, real signatures or network blockhashes are generated.
fn unsigned(
    keys: &[[u8; 32]],
    readonly_unsigned: u8,
    program_index: u8,
    accounts: &[u8],
    data: &[u8],
) -> Vec<u8> {
    assert!(keys.len() < 128 && accounts.len() < 128 && data.len() < 128);
    let mut wire = vec![1];
    wire.extend([0; 64]);
    wire.extend([1, 0, readonly_unsigned, keys.len() as u8]);
    for public in keys {
        wire.extend(public);
    }
    wire.extend([9; 32]);
    wire.extend([1, program_index, accounts.len() as u8]);
    wire.extend(accounts);
    wire.push(data.len() as u8);
    wire.extend(data);
    wire
}

fn authority_wire() -> Result<Vec<u8>, String> {
    let token = key("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?;
    let mut data = vec![4];
    data.extend(99u64.to_le_bytes());
    Ok(unsigned(
        &[[7; 32], [8; 32], [6; 32], token],
        2,
        3,
        &[1, 2, 0],
        &data,
    ))
}

fn fee_wire() -> Result<Vec<u8>, String> {
    let token = key("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")?;
    let mut data = vec![26, 1];
    data.extend(123u64.to_le_bytes());
    data.push(6);
    data.extend(2u64.to_le_bytes());
    Ok(unsigned(
        &[[7; 32], [8; 32], [6; 32], [5; 32], token],
        2,
        4,
        &[1, 3, 2, 0],
        &data,
    ))
}

fn payment() -> Result<Vec<u8>, String> {
    fixture(include_str!("../../../tests/fixtures/demo-v1/match.base64"))
}

fn additional() -> Result<Vec<u8>, String> {
    fixture(include_str!(
        "../../../tests/fixtures/demo-v1/violation.base64"
    ))
}

pub fn run(name: &str) -> Result<LabCase, String> {
    let (name, description, bytes, before) = match name {
        "payment" => (
            "payment",
            "Original synthetic payment: 500 lamports.",
            payment()?,
            None,
        ),
        "additional-debit" => (
            "additional-debit",
            "A second declared debit increases gross SOL outflow; compare with payment.",
            additional()?,
            None,
        ),
        "authority" => (
            "authority",
            "Proposed delegate allowance; no immediate debit is established.",
            authority_wire()?,
            None,
        ),
        "token2022" => (
            "token2022",
            "Checked transfer fee declaration: 123 raw units includes expected fee 2.",
            fee_wire()?,
            None,
        ),
        "uncertainty" => (
            "uncertainty",
            "Opaque program: missing quantitative semantics is not zero or safety.",
            fixture(include_str!(
                "../../../tests/fixtures/demo-v1/opaque.base64"
            ))?,
            None,
        ),
        "diff" => (
            "diff",
            "Compare the original synthetic payment and additional debit.",
            additional()?,
            Some(payment()?),
        ),
        _ => return Err("unknown lab case".into()),
    };
    let report = if let Some(original) = &before {
        serde_json::to_value(diff::compare(original, &bytes)?)
    } else {
        serde_json::to_value(report::inspect(&bytes)?)
    }
    .map_err(|_| "lab report serialization failed")?;
    Ok(LabCase {
        lab_version: 1,
        kind: "hguet_lab_case",
        name,
        description,
        synthetic: true,
        execution_performed: false,
        signing_authorization: "NOT_AUTHORIZED",
        transaction_base64: STANDARD.encode(bytes),
        before_transaction_base64: before.map(|b| STANDARD.encode(b)),
        report,
    })
}

pub fn render(case: &LabCase) -> Result<String, String> {
    let document = html::render(&case.report)?;
    Ok(document.replacen(
        "<p class=\"brand\">",
        &format!(
            "<p class=\"boundary\">SYNTHETIC LAB · {} · Never broadcast</p><p>{}</p><p class=\"brand\">",
            html::escape(case.name),
            html::escape(case.description)
        ),
        1,
    ))
}

fn new_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| "cannot create lab file")?;
    file.write_all(contents)
        .map_err(|_| "cannot write lab file".into())
}

/// Export to a new directory only. On failure, a partial directory can remain;
/// absence of manifest.json means export is incomplete.
pub fn export(path: &Path) -> Result<Value, String> {
    let mut files = Vec::new();
    for name in CASES {
        let case = run(name)?;
        let json = serde_json::to_vec_pretty(&case).map_err(|_| "lab serialization failed")?;
        files.push((format!("{name}.json"), json));
        files.push((format!("{name}.html"), render(&case)?.into_bytes()));
    }
    std::fs::create_dir(path).map_err(|_| "lab output must be a new directory")?;
    let mut entries = Vec::new();
    for (name, bytes) in files {
        new_file(&path.join(&name), &bytes)?;
        entries.push(json!({"file":name,"sha256":hguet_core::sha256_hex(&bytes)}));
    }
    let manifest = json!({
        "lab_version":1,"kind":"hguet_lab_manifest","synthetic":true,"offline":true,
        "execution_performed":false,"signing_authorization":"NOT_AUTHORIZED",
        "cases":CASES,"files":entries
    });
    let serialized =
        serde_json::to_vec_pretty(&manifest).map_err(|_| "lab serialization failed")?;
    new_file(&path.join("manifest.json"), &serialized)?;
    Ok(manifest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_cases_are_deterministic_and_non_authorizing() {
        for name in CASES {
            let a = run(name).unwrap();
            let b = run(name).unwrap();
            assert_eq!(a.report, b.report);
            assert_eq!(a.transaction_base64, b.transaction_base64);
            assert_eq!(a.report["signing_authorization"], "NOT_AUTHORIZED");
            assert!(render(&a).unwrap().contains("SYNTHETIC LAB"));
        }
    }

    #[test]
    fn public_lab_labels_are_escaped() {
        let mut case = run("payment").unwrap();
        case.description = "<img src=x onerror=alert(1)>";
        let document = render(&case).unwrap();
        assert!(!document.contains("<img"));
        assert!(document.contains("&lt;img"));
    }

    #[test]
    fn values_are_engine_results_not_hardcoded_report_fields() {
        let payment = run("payment").unwrap();
        assert_eq!(
            payment.report["wire"]["asset_totals"][0]["declared_debit_raw"],
            "500"
        );
        let extra = run("additional-debit").unwrap();
        assert_eq!(
            extra.report["wire"]["asset_totals"][0]["declared_debit_raw"],
            "501"
        );
        let authority = run("authority").unwrap();
        assert_eq!(
            authority.report["authority"]["changes"][0]["declared_delegate_limit_raw"],
            "99"
        );
        assert_eq!(authority.report["wire"]["flows"], json!([]));
        let fee = run("token2022").unwrap();
        assert_eq!(
            fee.report["wire"]["asset_totals"][0]["declared_debit_raw"],
            "123"
        );
        assert_eq!(
            fee.report["wire"]["asset_totals"][0]["declared_expected_fee_raw"],
            "2"
        );
        assert_eq!(
            run("uncertainty").unwrap().report["wire"]["unquantified_instruction_indices"],
            json!([0])
        );
        assert_eq!(run("diff").unwrap().report["relation"], "MESSAGE_CHANGED");
    }
}
