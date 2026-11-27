mod cloud_config;
mod cloud_quote;
mod demo;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hguet_core::{unix_now, SignedPaymentIntent};
use hguet_policy::LocalPolicy;
use hguet_rpc::{validate_endpoint, HttpsTransport, JsonRpcTransport};
use serde_json::json;
use std::{env, fs, io::Read, process};

fn usage() -> &'static str {
    "HGUET unreleased CLI (offline prototype)\n\
Usage:\n\
  inspect/check accept --report-v2 for the separately versioned analysis report\n\
  inspect/check accept --text for a human-readable report\n\
  hguet inspect FILE --offline [--encoding binary|base64|base58] [--json]\n\
  hguet check FILE --mode local --network mainnet|devnet|testnet [--intent FILE --trusted-key BASE58] [--policy TRUSTED.toml] [--rpc-url HTTPS_URL] [--encoding binary|base64|base58] [--json]\n\
  hguet signer-preflight FILE --offline --network mainnet|devnet|testnet --intent FILE --trusted-key BASE58 [--encoding binary|base64|base58] [--json]
  hguet policy validate FILE [--json]\n\
  hguet config show [--json]\n\
  hguet doctor [--json]  (offline environment report)\n\
  hguet demo [--json]  (synthetic offline analysis)\n\
  hguet cloud hello --ca-file FILE [--json]  (local Devnet gateway only)\n\
  hguet cloud quote PROGRAM --message-sha256 HEX --claim-sha256 HEX --max-lamports N --ca-file FILE --quote-key FILE [--save-order FILE] [--json]\n\
  hguet cloud status ORDER --claim-file FILE --ca-file FILE --quote-key FILE --assessment-key FILE --receipt-key FILE [--json]\n\
  hguet cloud submit ORDER --claim-file FILE --ca-file FILE --quote-key FILE --payment-signature BASE58 [--json]\n\
  hguet --help\n\
  hguet --version\n\
Paid Cloud checks are unavailable. Never send real SOL to a demonstration."
}

struct Args {
    command: String,
    file: String,
    network: String,
    encoding: String,
    intent: Option<String>,
    trusted_key: Option<String>,
    policy: Option<String>,
    rpc_url: Option<String>,
    mode: String,
    offline: bool,
}
fn parse_args() -> Result<Args, String> {
    let raw: Vec<String> = env::args().skip(1).collect();
    let v2 = raw.iter().filter(|s| s.as_str() == "--report-v2").count();
    let text = raw.iter().filter(|s| s.as_str() == "--text").count();
    if text > 1
        || (text == 1
            && (raw.iter().any(|s| s == "--json")
                || !matches!(raw.first().map(String::as_str), Some("inspect" | "check"))))
    {
        return Err("--text requires inspect/check and cannot be combined with --json".into());
    }
    if v2 > 1 || (v2 == 1 && !matches!(raw.first().map(String::as_str), Some("inspect" | "check")))
    {
        return Err("--report-v2 requires inspect or check".into());
    }
    let mut a = raw
        .into_iter()
        .filter(|s| s != "--report-v2" && s != "--text");
    let cmd = a.next().ok_or("missing command")?;
    if cmd == "doctor" || cmd == "demo" {
        if let Some(option) = a.next() {
            if option != "--json" || a.next().is_some() {
                return Err("expected doctor/demo [--json]".into());
            }
        }
        return Ok(Args {
            command: cmd,
            file: String::new(),
            network: "mainnet".into(),
            encoding: "binary".into(),
            intent: None,
            trusted_key: None,
            policy: None,
            rpc_url: None,
            mode: "local".into(),
            offline: true,
        });
    }
    if cmd == "--help" || cmd == "-h" || cmd == "--version" {
        return Ok(Args {
            command: cmd,
            file: String::new(),
            network: "mainnet".into(),
            encoding: "binary".into(),
            intent: None,
            trusted_key: None,
            policy: None,
            rpc_url: None,
            mode: "local".into(),
            offline: false,
        });
    }
    if cmd == "cloud" {
        if a.next().as_deref() != Some("hello") || a.next().as_deref() != Some("--ca-file") {
            return Err("expected cloud hello --ca-file FILE [--json]".into());
        }
        let file = a
            .next()
            .filter(|p| !p.is_empty() && !p.starts_with('-'))
            .ok_or("missing trusted CA file")?;
        if let Some(option) = a.next() {
            if option != "--json" || a.next().is_some() {
                return Err("unexpected cloud hello option".into());
            }
        }
        return Ok(Args {
            command: "cloud-hello".into(),
            file,
            network: "devnet".into(),
            encoding: String::new(),
            intent: None,
            trusted_key: None,
            policy: None,
            rpc_url: None,
            mode: "local".into(),
            offline: false,
        });
    }
    if cmd == "config" {
        let sub = a.next().ok_or("missing config subcommand")?;
        if sub != "show" {
            return Err("only config show is supported".into());
        }
        if let Some(opt) = a.next() {
            if opt != "--json" || a.next().is_some() {
                return Err("unexpected config option".into());
            }
        }
        return Ok(Args {
            command: "config-show".into(),
            file: String::new(),
            network: "mainnet".into(),
            encoding: "binary".into(),
            intent: None,
            trusted_key: None,
            policy: None,
            rpc_url: None,
            mode: "local".into(),
            offline: true,
        });
    }
    if cmd == "policy" {
        if a.next().as_deref() != Some("validate") {
            return Err("only policy validate FILE is supported".into());
        }
        let file = a.next().ok_or("missing policy file")?;
        if file.starts_with('-') {
            return Err("invalid policy file path".into());
        }
        if let Some(opt) = a.next() {
            if opt != "--json" || a.next().is_some() {
                return Err("unexpected policy validation option".into());
            }
        }
        return Ok(Args {
            command: "policy-validate".into(),
            file,
            network: "mainnet".into(),
            encoding: "binary".into(),
            intent: None,
            trusted_key: None,
            policy: None,
            rpc_url: None,
            mode: "local".into(),
            offline: true,
        });
    }
    if cmd != "inspect" && cmd != "check" && cmd != "signer-preflight" {
        return Err("unknown command".into());
    }
    let file = a.next().ok_or("missing transaction path")?;
    if file.starts_with('-') && file != "-" {
        return Err("invalid transaction path".into());
    }
    if file == "-" && cmd == "signer-preflight" {
        return Err("signer-preflight requires a bounded file".into());
    }
    let mut v = Args {
        command: cmd,
        file,
        network: "mainnet".into(),
        encoding: "binary".into(),
        intent: None,
        trusted_key: None,
        policy: None,
        rpc_url: None,
        mode: "local".into(),
        offline: false,
    };
    while let Some(flag) = a.next() {
        match flag.as_str() {
            "--offline" => v.offline = true,
            "--json" => {}
            "--encoding" => v.encoding = a.next().ok_or("missing --encoding value")?,
            "--network" => v.network = a.next().ok_or("missing --network value")?,
            "--intent" => v.intent = Some(a.next().ok_or("missing --intent value")?),
            "--trusted-key" => v.trusted_key = Some(a.next().ok_or("missing --trusted-key value")?),
            "--policy" => v.policy = Some(a.next().ok_or("missing --policy path")?),
            "--rpc-url" => v.rpc_url = Some(a.next().ok_or("missing --rpc-url value")?),
            "--mode" => v.mode = a.next().ok_or("missing --mode value")?,
            _ => return Err(format!("unknown option {flag}")),
        }
    }
    if !["mainnet", "devnet", "testnet"].contains(&v.network.as_str()) {
        return Err("unsupported network".into());
    }
    if !["binary", "base64", "base58"].contains(&v.encoding.as_str()) {
        return Err("unsupported encoding".into());
    }
    if v.mode != "local" {
        return Err("Cloud/payment not implemented; no real funds may be sent".into());
    }
    if v.command == "inspect" && !v.offline {
        return Err("inspect must be explicitly --offline".into());
    }
    if v.command == "inspect" && v.policy.is_some() {
        return Err("--policy requires check command".into());
    }
    // `check` works without an intent (policy-only or inspection-grade checks);
    // the verdict then says the intent is unverified. The signer seam needs one.
    if v.command == "signer-preflight" && v.intent.is_none() {
        return Err("--intent FILE required".into());
    }
    if v.command == "signer-preflight" {
        if !v.offline {
            return Err("signer-preflight requires explicit --offline".into());
        }
        if v.trusted_key.is_none() {
            return Err(
                "signer-preflight requires an independently configured --trusted-key".into(),
            );
        }
        if v.policy.is_some() {
            return Err(
                "signer-preflight cannot substitute a policy for signer authorization".into(),
            );
        }
        if v.rpc_url.is_some() {
            return Err("signer-preflight never sends transaction bytes to RPC".into());
        }
    }
    if v.rpc_url.is_some() && (v.command != "check" || v.offline) {
        return Err("--rpc-url requires check command without --offline".into());
    }
    if let Some(url) = &v.rpc_url {
        validate_endpoint(url).map_err(|_| {
            "RPC endpoint must be an explicit HTTPS URL without credentials or fragment".to_string()
        })?;
    }
    Ok(v)
}
fn limited_file(path: &str, max: u64) -> Result<Vec<u8>, String> {
    let f = fs::File::open(path).map_err(|_| "cannot open input file")?;
    if f.metadata().map_err(|_| "cannot stat input")?.len() > max {
        return Err("input exceeds size limit".into());
    }
    let mut b = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut b)
        .map_err(|_| "cannot read input file")?;
    if b.len() as u64 > max {
        return Err("input exceeds size limit".into());
    }
    Ok(b)
}
fn read_transaction(path: &str, enc: &str) -> Result<Vec<u8>, String> {
    let raw = if path == "-" {
        let mut bytes = Vec::new();
        std::io::stdin()
            .lock()
            .take(16_385)
            .read_to_end(&mut bytes)
            .map_err(|_| "cannot read stdin")?;
        if bytes.len() > 16_384 {
            return Err("input exceeds size limit".into());
        }
        bytes
    } else {
        limited_file(path, 16_384)?
    };
    match enc {
        "binary" => Ok(raw),
        "base64" => STANDARD
            .decode(
                std::str::from_utf8(&raw)
                    .map_err(|_| "base64 input not UTF8")?
                    .trim(),
            )
            .map_err(|_| "invalid Base64 transaction".into()),
        "base58" => bs58::decode(
            std::str::from_utf8(&raw)
                .map_err(|_| "base58 input not UTF8")?
                .trim(),
        )
        .into_vec()
        .map_err(|_| "invalid Base58 transaction".into()),
        _ => Err("unrecognized encoding".into()),
    }
}

fn execute(v: Args) -> (serde_json::Value, i32) {
    execute_version(
        v,
        &HttpsTransport::default(),
        env::args().any(|arg| arg == "--report-v2" || arg == "--text"),
    )
}
#[cfg(test)]
fn execute_with<T: JsonRpcTransport>(v: Args, transport: &T) -> (serde_json::Value, i32) {
    execute_version(v, transport, false)
}
fn execute_version<T: JsonRpcTransport>(
    v: Args,
    transport: &T,
    v2: bool,
) -> (serde_json::Value, i32) {
    let data = match read_transaction(&v.file, &v.encoding) {
        Ok(data) => data,
        Err(e) => return (json!({"error":e,"code":"BAD_INPUT"}), 40),
    };
    let policy = v.policy.as_ref().map(|path| {
        limited_file(path, 65536)
            .and_then(|bytes| String::from_utf8(bytes).map_err(|_| "policy must be UTF-8".into()))
    });
    let intent = v.intent.as_ref().map(|path| limited_file(path, 16384));
    let input = hguet::AnalysisInput {
        transaction: data,
        signed_intent: intent,
    };
    let config = hguet::TrustedConfig {
        network: v.network,
        trusted_key: v.trusted_key,
        policy,
        rpc_url: v.rpc_url,
        operation: if v.command == "inspect" {
            hguet::Operation::Inspect
        } else {
            hguet::Operation::Check
        },
    };
    if v2 {
        let (report, code) = hguet::analyze_v2(input, config, transport, unix_now);
        (
            serde_json::to_value(report).expect("report serialization"),
            code,
        )
    } else {
        hguet::analyze(input, config, transport, unix_now)
    }
}
// No signer backend exists in the public API or this CLI.
fn execute_signer_preflight(v: Args) -> (serde_json::Value, i32) {
    let raw = match read_transaction(&v.file, &v.encoding) {
        Ok(raw) => raw,
        Err(e) => return (json!({"code":"BAD_INPUT","error":e}), 40),
    };
    let envelope = match v
        .intent
        .as_deref()
        .ok_or_else(|| "signed intent required".to_string())
        .and_then(|path| limited_file(path, 16_384))
        .and_then(|bytes| {
            serde_json::from_slice::<SignedPaymentIntent>(&bytes)
                .map_err(|_| "signed intent envelope malformed".to_string())
        }) {
        Ok(env) => env,
        Err(e) => return (json!({"code":"BAD_SIGNED_INTENT","error":e}), 40),
    };
    let now = match unix_now() {
        Ok(now) => now,
        Err(e) => return (json!({"code":"CLOCK_UNAVAILABLE","error":e}), 40),
    };
    let request = hguet_signer::SignerRequest {
        original_transaction: &raw,
        signed_intent: Some(&envelope),
        independently_pinned_intent_signer: v.trusted_key.as_deref(),
        network: &v.network,
        now_unix: now,
    };
    // The success type is Infallible; the port is never invoked, even for
    // syntactically valid messages and independently signed intents.
    let refusal = match hguet_signer::guarded_sign(request) {
        Err(refusal) => refusal,
        Ok(never) => match never {},
    };
    (json!({"signer_refusal":refusal}), 20)
}
fn main() {
    let mut arguments = env::args().skip(1);
    let command = (arguments.next(), arguments.next());
    if command.0.as_deref() == Some("cloud")
        && matches!(command.1.as_deref(), Some("quote" | "status" | "submit"))
    {
        let result = match command.1.as_deref() {
            Some("status") => cloud_quote::order_request(arguments, false),
            Some("submit") => cloud_quote::order_request(arguments, true),
            _ => cloud_quote::run(arguments),
        };
        match result {
            Ok(output) => println!("{output}"),
            Err(code) => {
                println!("{}", json!({"code":code}));
                process::exit(40);
            }
        }
        return;
    }
    match parse_args() {
        Ok(v) if v.command == "demo" => {
            let output = demo::run();
            if env::args().any(|arg| arg == "--json") {
                println!("{output}");
            } else {
                println!("{}", demo::text(&output));
            }
        }
        Ok(v) if v.command == "doctor" => {
            println!(
                "{}",
                json!({
                    "schema_version":1,"command":"doctor","offline":true,
                    "os":env::consts::OS,"architecture":env::consts::ARCH,
                    "package_version":env!("CARGO_PKG_VERSION"),
                    "network_access":false,"signing_authorization":"NOT_AUTHORIZED",
                    "input_limit_bytes":16384,"input_encodings":["binary","base64","base58"],
                    "cloud_required":false
                })
            );
        }
        Ok(v) if v.command == "--help" || v.command == "-h" => {
            println!("{}", usage());
            process::exit(0)
        }
        Ok(v) if v.command == "signer-preflight" => {
            let (output, code) = execute_signer_preflight(v);
            println!(
                "{}",
                serde_json::to_string_pretty(&output).expect("JSON serialization")
            );
            process::exit(code);
        }
        Ok(v) if v.command == "policy-validate" => {
            let result = limited_file(&v.file, 65_536)
                .and_then(|bytes| {
                    String::from_utf8(bytes).map_err(|_| "policy must be UTF-8".into())
                })
                .and_then(|text| LocalPolicy::parse_and_validate(&text));
            match result {
                Ok(policy) => {
                    println!(
                        "{}",
                        json!({"status":"valid","network":policy.network,"mode":"restrictive_only","cloud_network_access":false})
                    );
                    process::exit(0)
                }
                Err(error) => {
                    println!(
                        "{}",
                        json!({"status":"invalid","code":"BAD_POLICY","error":error})
                    );
                    process::exit(40)
                }
            }
        }
        Ok(v) if v.command == "cloud-hello" => match cloud_config::loopback_hello(v.file.into()) {
            Ok(output) => println!("{output}"),
            Err(error) => {
                println!("{}", json!({"code": error}));
                process::exit(40);
            }
        },
        Ok(v) if v.command == "config-show" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&cloud_config::describe())
                    .expect("JSON serialization")
            );
            process::exit(0)
        }
        Ok(v) if v.command == "--version" => {
            println!("hguet unreleased-draft (no product version or release)");
            process::exit(0)
        }
        Ok(v) => {
            let policy_configured = v.policy.is_some();
            let (output, code) = execute(v);
            let output = if env::args().any(|arg| arg == "--report-v2" || arg == "--text")
                && output.get("schema_version") != Some(&json!(2))
            {
                serde_json::to_value(hguet::report_v2::from_v1(output, code, policy_configured))
                    .expect("report serialization")
            } else {
                output
            };
            if env::args().any(|arg| arg == "--text") {
                println!("{}", hguet::report_v2::text(&output));
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&output).expect("JSON serialization")
                );
            }
            process::exit(code);
        }
        Err(e) => {
            eprintln!("hguet: {e}\n{}", usage());
            process::exit(40)
        }
    }
}

#[cfg(test)]
mod pipeline_tests;
