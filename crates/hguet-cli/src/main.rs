mod cloud_config;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hguet_core::{parse_transaction, unix_now, verify_intent, Decision, SecurityVerdict, SignedPaymentIntent, TransactionSignatureStatus};
use serde_json::json;
use hguet_policy::LocalPolicy;
use std::{env, fs, io::Read, process};

fn usage() -> &'static str {
    "HGUET unreleased CLI (offline prototype)\n\
Usage:\n\
  hguet inspect FILE --offline [--encoding binary|base64|base58] [--json]\n\
  hguet check FILE --mode local --network mainnet|devnet|testnet --intent FILE --trusted-key BASE58 [--policy TRUSTED.toml] [--encoding binary|base64|base58] [--json]\n\
  hguet policy validate FILE [--json]\n\
  hguet config show [--json]\n\
  hguet --help\n\
  hguet --version\n\
Cloud/payment commands are NOT implemented. Never send real SOL to a demonstration."
}

struct Args {
    command: String,
    file: String,
    network: String,
    encoding: String,
    intent: Option<String>,
    trusted_key: Option<String>,
    policy: Option<String>,
    mode: String,
    offline: bool,
}
fn parse_args() -> Result<Args, String> {
    let mut a=env::args().skip(1);
    let cmd=a.next().ok_or("missing command")?;
    if cmd=="--help" || cmd=="-h" || cmd=="--version" {
        return Ok(Args{command:cmd,file:String::new(),network:"mainnet".into(),encoding:"binary".into(),
            intent:None,trusted_key:None,policy:None,mode:"local".into(),offline:false});
    }
    if cmd=="config" {
        let sub=a.next().ok_or("missing config subcommand")?;
        if sub!="show" { return Err("only config show is supported".into()); }
        if let Some(opt)=a.next() {
            if opt!="--json" || a.next().is_some() { return Err("unexpected config option".into()); }
        }
        return Ok(Args{command:"config-show".into(),file:String::new(),network:"mainnet".into(),encoding:"binary".into(),
            intent:None,trusted_key:None,policy:None,mode:"local".into(),offline:true});
    }
    if cmd=="policy" {
        if a.next().as_deref()!=Some("validate") {
            return Err("only policy validate FILE is supported".into());
        }
        let file=a.next().ok_or("missing policy file")?;
        if file.starts_with('-') { return Err("invalid policy file path".into()); }
        if let Some(opt)=a.next() {
            if opt!="--json" || a.next().is_some() {
                return Err("unexpected policy validation option".into());
            }
        }
        return Ok(Args { command:"policy-validate".into(),file,
            network:"mainnet".into(),encoding:"binary".into(),intent:None,
            trusted_key:None,policy:None,mode:"local".into(),offline:true });
    }
    if cmd!="inspect" && cmd!="check" { return Err("unknown command".into()); }
    let file=a.next().ok_or("missing transaction path")?;
    if file.starts_with('-') && file!="-" { return Err("invalid transaction path".into()); }
    if file=="-" { return Err("stdin not yet supported; use a bounded file".into()); }
    let mut v=Args{command:cmd,file,network:"mainnet".into(),encoding:"binary".into(),
        intent:None,trusted_key:None,policy:None,mode:"local".into(),offline:false};
    while let Some(flag)=a.next(){
        match flag.as_str(){
            "--offline"=>v.offline=true,
            "--json"=>{},
            "--encoding"=>v.encoding=a.next().ok_or("missing --encoding value")?,
            "--network"=>v.network=a.next().ok_or("missing --network value")?,
            "--intent"=>v.intent=Some(a.next().ok_or("missing --intent value")?),
            "--trusted-key"=>v.trusted_key=Some(a.next().ok_or("missing --trusted-key value")?),
            "--policy"=>v.policy=Some(a.next().ok_or("missing --policy path")?),
            "--mode"=>v.mode=a.next().ok_or("missing --mode value")?,
            _=>return Err(format!("unknown option {flag}")),
        }
    }
    if !["mainnet","devnet","testnet"].contains(&v.network.as_str()) { return Err("unsupported network".into()); }
    if !["binary","base64","base58"].contains(&v.encoding.as_str()) { return Err("unsupported encoding".into()); }
    if v.mode!="local" {return Err("Cloud/payment not implemented; no real funds may be sent".into());}
    if v.command=="inspect" && !v.offline { return Err("inspect must be explicitly --offline".into()); }
    if v.command=="inspect" && v.policy.is_some() { return Err("--policy requires check command".into()); }
    if v.command=="check" && v.intent.is_none() { return Err("--intent FILE required".into()); }
    Ok(v)
}
fn limited_file(path:&str, max:u64)->Result<Vec<u8>,String>{
    let mut f=fs::File::open(path).map_err(|_|"cannot open input file")?;
    if f.metadata().map_err(|_|"cannot stat input")?.len()>max{return Err("input exceeds size limit".into());}
    let mut b=Vec::new();
    f.take(max+1).read_to_end(&mut b).map_err(|_|"cannot read input file")?;
    if b.len() as u64>max {return Err("input exceeds size limit".into());}
    Ok(b)
}
fn read_transaction(path:&str,enc:&str)->Result<Vec<u8>,String>{
    let raw=limited_file(path,16_384)?;
    match enc{
        "binary"=>Ok(raw),
        "base64"=>STANDARD.decode(std::str::from_utf8(&raw).map_err(|_|"base64 input not UTF8")?.trim())
            .map_err(|_|"invalid Base64 transaction".into()),
        "base58"=>bs58::decode(std::str::from_utf8(&raw).map_err(|_|"base58 input not UTF8")?.trim())
            .into_vec().map_err(|_|"invalid Base58 transaction".into()),
        _=>Err("unrecognized encoding".into())
    }
}
fn execute(v:Args)->(serde_json::Value,i32){
    let mut verdict=SecurityVerdict::unknown(&v.network);
    let data=match read_transaction(&v.file,&v.encoding){
        Ok(data)=>data,
        Err(e)=>return (json!({"error":e,"code":"BAD_INPUT"}),40)
    };
    let parsed=match parse_transaction(&data) {
        Ok(p)=>p,
        Err(e)=>{
            if e.contains("unsupported"){
                verdict.finding("UNSUPPORTED_FORMAT","high",e);
                return (json!({"inspection":null,"verdict":verdict}),30)
            }
            verdict.decision=Decision::Deny;
            verdict.finding("MALFORMED_TRANSACTION","critical",e);
            return (json!({"inspection":null,"verdict":verdict}),40)
        }
    };
    verdict.message_sha256=Some(parsed.message_sha256.clone());
    verdict.transaction_sha256=Some(parsed.transaction_sha256.clone());
    verdict.coverage.push("wire_structure".into());
    verdict.limitations.extend(parsed.limitations.clone());
    if let Some(path)=&v.policy {
        let local_policy=limited_file(path,65_536)
            .and_then(|bytes| String::from_utf8(bytes).map_err(|_|"policy must be UTF-8".into()))
            .and_then(|text| LocalPolicy::parse_and_validate(&text));
        match local_policy {
            Ok(policy)=>{
                let evaluation=policy.evaluate(&v.network,&parsed);
                verdict.coverage.push("local_restrictive_policy".into());
                for finding in evaluation.unknowns { verdict.findings.push(finding); }
                if !evaluation.hard_denies.is_empty() {
                    verdict.decision=Decision::Deny;
                    verdict.findings.extend(evaluation.hard_denies);
                    return (json!({"inspection":parsed,"verdict":verdict}),20);
                }
                verdict.findings.extend(evaluation.hard_denies);
            }
            Err(err)=>return (json!({"code":"BAD_POLICY","error":err}),40)
        }
    }
    if parsed.transaction_signature_status == TransactionSignatureStatus::Invalid {
        verdict.decision=Decision::Deny;
        verdict.finding("INVALID_TRANSACTION_SIGNATURE", "critical",
            "At least one non-zero transaction signature failed Ed25519 verification");
        // Inspect remains informational; a security check rejects provably invalid signatures.
        if v.command=="check" {
            return (json!({"inspection":parsed,"verdict":verdict}),20);
        }
    }
    if v.command=="check" {
        match (&v.intent,&v.trusted_key) {
            (Some(path),Some(key))=>{
                let result=limited_file(path,16_384).and_then(|raw|
                    serde_json::from_slice::<SignedPaymentIntent>(&raw)
                    .map_err(|_| "signed intent envelope JSON malformed".to_string())
                ).and_then(|signed| unix_now().and_then(|now|
                    verify_intent(&signed,key,&v.network,&parsed,now)
                ));
                match result {
                    Ok(_)=>{
                        verdict.intent_status="signature_verified".into();
                        verdict.coverage.push("independently_pinned_intent_signature".into());
                    }
                    Err(e)=>{
                        verdict.intent_status="rejected".into();
                        verdict.decision=Decision::Deny;
                        verdict.finding("INTENT_REJECTED","critical",e);
                        return (json!({"inspection":parsed,"verdict":verdict}),20);
                    }
                }
            }
            (_,None)=>{
                verdict.intent_status="unverified_no_independent_trust_key".into();
                verdict.finding("INTENT_UNVERIFIED","high","--trusted-key is required to verify independent authorization");
            }
            _=>{}
        }
    }
    verdict.finding("NO_SIMULATION","high","Wire inspection does not prove transfers, CPI effects, execution or wallet authorization");
    (json!({"inspection":parsed,"verdict":verdict}),if v.command=="inspect"{0}else{30})
}
fn main(){
    match parse_args(){
        Ok(v) if v.command=="--help" || v.command=="-h"=>{
            println!("{}",usage());process::exit(0)
        }
        Ok(v) if v.command=="policy-validate"=>{
            let result=limited_file(&v.file,65_536)
                .and_then(|bytes| String::from_utf8(bytes).map_err(|_|"policy must be UTF-8".into()))
                .and_then(|text| LocalPolicy::parse_and_validate(&text));
            match result {
                Ok(policy)=> {
                    println!("{}",json!({"status":"valid","network":policy.network,"mode":"restrictive_only","cloud_network_access":false}));
                    process::exit(0)
                }
                Err(error)=> {
                    println!("{}",json!({"status":"invalid","code":"BAD_POLICY","error":error}));
                    process::exit(40)
                }
            }
        }
        Ok(v) if v.command=="config-show"=>{
            println!("{}",serde_json::to_string_pretty(&cloud_config::describe()).expect("JSON serialization"));
            process::exit(0)
        }
        Ok(v) if v.command=="--version"=>{
            println!("hguet unreleased-draft (no product version or release)");process::exit(0)
        }
        Ok(v)=>{
            let (output,code)=execute(v);
            println!("{}",serde_json::to_string_pretty(&output).expect("JSON serialization"));
            process::exit(code);
        }
        Err(e)=>{
            eprintln!("hguet: {e}\n{}",usage());process::exit(40)
        }
    }
}
