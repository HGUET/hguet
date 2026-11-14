//! Minimal standalone, offline BLOCK-only process for untrusted agent payloads.
//! This is a separate executable with strict stdin JSON admission, NOT an OS
//! sandbox or a real signer. The operator must protect launch configuration.
//! No network, wallet, device, key store or transaction broadcasting paths.
#![forbid(unsafe_code)]

use hguet_signer::isolation::{OperatorTrust,MAX_AGENT_JSON_BYTES};
use serde_json::json;
use std::{env,io::{self,Read},process};

fn config()->Result<OperatorTrust,&'static str>{
    let mut args=env::args().skip(1);
    let mut network=None;
    let mut trusted_key=None;
    while let Some(arg)=args.next(){
        let (where_to,name)=match arg.as_str(){
            "--network"=>(&mut network,"--network"),
            "--trusted-key"=>(&mut trusted_key,"--trusted-key"),
            _=>return Err("only --network and --trusted-key are allowed"),
        };
        if where_to.is_some(){return Err("duplicate operator option");}
        let value=args.next().ok_or("missing operator option value")?;
        if value.starts_with('-'){return Err("invalid operator option value");}
        *where_to=Some(value);
        let _=name;
    }
    let network=network.ok_or("operator network not configured")?;
    let pin=trusted_key.ok_or("operator trusted public key not configured")?;
    OperatorTrust::new(&network,&pin).map_err(|_|"invalid operator trust configuration")
}
fn run()->Result<(),String>{
    let operator=config().map_err(str::to_string)?;
    let mut stdin=io::stdin().take((MAX_AGENT_JSON_BYTES+1) as u64);
    let mut input=Vec::new();
    stdin.read_to_end(&mut input).map_err(|_|"cannot read bounded stdin")?;
    let result=operator.inspect_agent_json(&input);
    println!("{}",json!({"signer_refusal":result}));
    process::exit(20);
}
fn main(){
    if let Err(error)=run(){
        eprintln!("signer-isolate refused operator configuration or stdin: {error}");
        process::exit(40);
    }
}
