//! Test adapter only: replay captured local validator metadata without network claims.
use hguet_core::sha256_hex;
use serde_json::{json, Value};
use std::io::Read;

fn main() -> Result<(), String> {
    let signature = std::env::args().nth(1).ok_or("missing signature")?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(1_048_577)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read fixture")?;
    if bytes.len() > 1_048_576 {
        return Err("fixture too large".into());
    }
    let result: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid fixture")?;
    let transaction = hguet_rpc::history::decode_untrusted_result(result, &signature)
        .map_err(|e| e.code().to_owned())?
        .ok_or("missing transaction")?;
    let report = hguet::report::inspect(&transaction.wire)?;
    let output = json!({
        "kind":"validator_test_replay",
        "source_authentication_performed":false,
        "execution_proven":false,
        "signing_authorization":"NOT_AUTHORIZED",
        "wire_sha256":sha256_hex(&transaction.wire),
        "report":report,
        "historical":transaction.evidence
    });
    println!("{output}");
    Ok(())
}
