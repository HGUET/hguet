mod cloud_config;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hguet_core::{parse_transaction, unix_now, verify_intent, Decision, PaymentIntentPayload, SecurityVerdict, SignedPaymentIntent, TransactionSignatureStatus};
use serde_json::json;
use hguet_policy::LocalPolicy;
use hguet_rpc::{simulate_with, validate_endpoint, HttpsTransport};
use std::{env, fs, io::Read, process};

fn usage() -> &'static str {
    "HGUET unreleased CLI (offline prototype)\n\
Usage:\n\
  hguet inspect FILE --offline [--encoding binary|base64|base58] [--json]\n\
  hguet check FILE --mode local --network mainnet|devnet|testnet --intent FILE --trusted-key BASE58 [--policy TRUSTED.toml] [--rpc-url HTTPS_URL] [--encoding binary|base64|base58] [--json]\n\
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
    rpc_url: Option<String>,
    mode: String,
    offline: bool,
}
fn parse_args() -> Result<Args, String> {
    let mut a=env::args().skip(1);
    let cmd=a.next().ok_or("missing command")?;
    if cmd=="--help" || cmd=="-h" || cmd=="--version" {
        return Ok(Args{command:cmd,file:String::new(),network:"mainnet".into(),encoding:"binary".into(),
            intent:None,trusted_key:None,policy:None,rpc_url:None,mode:"local".into(),offline:false});
    }
    if cmd=="config" {
        let sub=a.next().ok_or("missing config subcommand")?;
        if sub!="show" { return Err("only config show is supported".into()); }
        if let Some(opt)=a.next() {
            if opt!="--json" || a.next().is_some() { return Err("unexpected config option".into()); }
        }
        return Ok(Args{command:"config-show".into(),file:String::new(),network:"mainnet".into(),encoding:"binary".into(),
            intent:None,trusted_key:None,policy:None,rpc_url:None,mode:"local".into(),offline:true});
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
            trusted_key:None,policy:None,rpc_url:None,mode:"local".into(),offline:true });
    }
    if cmd!="inspect" && cmd!="check" { return Err("unknown command".into()); }
    let file=a.next().ok_or("missing transaction path")?;
    if file.starts_with('-') && file!="-" { return Err("invalid transaction path".into()); }
    if file=="-" { return Err("stdin not yet supported; use a bounded file".into()); }
    let mut v=Args{command:cmd,file,network:"mainnet".into(),encoding:"binary".into(),
        intent:None,trusted_key:None,policy:None,rpc_url:None,mode:"local".into(),offline:false};
    while let Some(flag)=a.next(){
        match flag.as_str(){
            "--offline"=>v.offline=true,
            "--json"=>{},
            "--encoding"=>v.encoding=a.next().ok_or("missing --encoding value")?,
            "--network"=>v.network=a.next().ok_or("missing --network value")?,
            "--intent"=>v.intent=Some(a.next().ok_or("missing --intent value")?),
            "--trusted-key"=>v.trusted_key=Some(a.next().ok_or("missing --trusted-key value")?),
            "--policy"=>v.policy=Some(a.next().ok_or("missing --policy path")?),
            "--rpc-url"=>v.rpc_url=Some(a.next().ok_or("missing --rpc-url value")?),
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
    if v.rpc_url.is_some() && (v.command!="check" || v.offline) {
        return Err("--rpc-url requires check command without --offline".into());
    }
    if let Some(url)=&v.rpc_url {
        validate_endpoint(url).map_err(|_|"RPC endpoint must be an explicit HTTPS URL without credentials or fragment".to_string())?;
    }
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

#[derive(Debug, PartialEq, Eq)]
enum RpcIntentRisk {
    CpiProgramOutsideAllowlist,
    FeePayerNetOutflowExceedsCap,
}

/// Compare *optional single-provider observations* to a separately verified
/// PaymentIntent. These findings are advisory, never grounds for ALLOW or a
/// conclusive DENY: the provider may omit, distort or simulate incomplete data.
fn rpc_intent_risks(
    intent: &PaymentIntentPayload,
    simulation_status: &str,
    cpi_captured: bool,
    cpi_program_ids: &[String],
    fee_payer_balances: Option<(u64, u64)>,
) -> Vec<RpcIntentRisk> {
    if simulation_status != "rpc_succeeded" {
        return Vec::new();
    }
    let mut risks = Vec::new();
    if cpi_captured && cpi_program_ids.iter().any(|id| !intent.allowed_program_ids.contains(id)) {
        risks.push(RpcIntentRisk::CpiProgramOutsideAllowlist);
    }
    if let Some((before, after)) = fee_payer_balances {
        // Fee-payer account 0 may also receive funds and pays network fees.
        // A net loss above the cap is suspicious but is NOT an exact spend total.
        if let (Some(net_loss), Ok(limit)) = (
            before.checked_sub(after),
            intent.max_spend_lamports.parse::<u64>(),
        ) {
            if net_loss > limit {
                risks.push(RpcIntentRisk::FeePayerNetOutflowExceedsCap);
            }
        }
    }
    risks
}

/// Security classifications of *simulated*, single-provider token CPI data.
fn token_cpi_findings(
    status: &str,
    items: &[hguet_rpc::TokenCpiInstruction],
    opaque_count: usize,
) -> Vec<(&'static str, &'static str, &'static str)> {
    if status != "rpc_succeeded" { return Vec::new(); }
    let mut findings = Vec::new();
    if items.iter().any(|item| matches!(item.operation.as_str(),
        "approve"|"approve_checked"|"revoke"|"set_authority"|
        "freeze_account"|"thaw_account"|"close_account"))
    {
        findings.push(("RPC_TOKEN_CPI_AUTHORITY_RISK","high",
            "A simulated CPI contains token delegation, authority or account-control instructions; inspect account roles and signer authorization independently"));
    }
    if items.iter().any(|item| matches!(item.operation.as_str(),
        "transfer"|"transfer_checked"|"mint_to"|"mint_to_checked"|
        "burn"|"burn_checked"))
    {
        findings.push(("RPC_TOKEN_CPI_MOVEMENT","medium",
            "Compiled token CPI declares a transfer, mint or burn; declared amounts are not independently verified net balance effects"));
    }
    if opaque_count>0 {
        findings.push(("RPC_TOKEN_CPI_OPAQUE","high",
            "One or more simulated token CPI instructions have unknown, extension-specific or unverified binary semantics; no safe effect can be inferred"));
    }
    findings
}

/// These are warnings about reported instructions, not proof that the mint
/// has a given extension or that a transaction executed successfully.
fn token_2022_extension_findings(
    status: &str,
    items: &[hguet_rpc::Token2022ExtensionObservation],
) -> Vec<(&'static str, &'static str, &'static str)> {
    if status!="rpc_succeeded" { return Vec::new(); }
    let mut findings=Vec::new();
    if items.iter().any(|item|item.family=="transfer_fee") {
        findings.push(("RPC_TOKEN_2022_TRANSFER_FEE","high",
            "Token-2022 CPI references transfer-fee configuration, expected fees, or withheld fee operations; fee state and net receipts have not been verified"));
    }
    if items.iter().any(|item|item.family=="transfer_hook") {
        findings.push(("RPC_TOKEN_2022_TRANSFER_HOOK","high",
            "Token-2022 CPI references transfer-hook configuration; hook execution and downstream program effects are not independently verified"));
    }
    if items.iter().any(|item|item.family=="permanent_delegate") {
        findings.push(("RPC_TOKEN_2022_PERMANENT_DELEGATE","high",
            "Token-2022 CPI references permanent-delegate initialization; this authority may move or burn tokens outside ordinary account-owner consent"));
    }
    if items.iter().any(|item|matches!(item.family,
        "confidential_transfer"|"confidential_transfer_fee"|"confidential_mint_burn")) {
        findings.push(("RPC_TOKEN_2022_CONFIDENTIAL_EFFECTS","high",
            "Token-2022 CPI references confidential token operations; ordinary balance snapshots cannot establish all hidden movements"));
    }
    findings
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
    let mut verified_intent: Option<PaymentIntentPayload> = None;
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
                    Ok(payload)=>{
                        verified_intent = Some(payload);
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
    if let Some(endpoint)=&v.rpc_url {
        // Explicit opt-in ONLY; never forward anything to HGUET Cloud. The
        // user-selected Solana RPC provider receives the raw transaction.
        match simulate_with(&HttpsTransport::default(),endpoint,&v.network,&data) {
            Ok(evidence)=>{
                verdict.simulation_status=evidence.status.clone();
                verdict.coverage.push("solana_rpc_genesis_verified".into());
                verdict.coverage.push("solana_rpc_simulation_single_provider".into());
                let effects=&evidence.effect_analysis;
                if effects.lamport_deltas.is_some() {
                    verdict.coverage.push("rpc_paired_native_balance_snapshots".into());
                }
                if effects.token_deltas.is_some() {
                    verdict.coverage.push("rpc_paired_token_balance_snapshots".into());
                }
                if effects.cpi.captured {
                    verdict.coverage.push("rpc_cpi_recording".into());
                }
                if !effects.missing_fields.is_empty() {
                    verdict.finding("RPC_EFFECT_EVIDENCE_INCOMPLETE","high",
                        "Solana RPC omitted balance/token/CPI fields: missing observations do not imply zero transfers");
                }
                if effects.token_deltas.as_ref().is_some_and(|items|
                    items.iter().any(|delta| !delta.complete_pair)) {
                    verdict.finding("RPC_TOKEN_DELTA_UNDETERMINED","high",
                        "Some token pre/post snapshots are missing or changed identity; exact deltas cannot be inferred");
                }
                if evidence.status=="rpc_succeeded" &&
                    !effects.cpi.token_instructions.is_empty() {
                    verdict.coverage.push("rpc_token_cpi_compiled_instruction_decode".into());
                }
                for (code,severity,message) in token_cpi_findings(
                    &evidence.status,
                    &effects.cpi.token_instructions,
                    effects.cpi.opaque_token_instruction_count,
                ) {
                    verdict.finding(code,severity,message);
                }
                for (code,severity,message) in token_2022_extension_findings(
                    &evidence.status,
                    &effects.cpi.token_2022_extension_observations,
                ) {
                    verdict.finding(code,severity,message);
                }
                if let Some(ref intent) = verified_intent {
                    // Only compare provider observations to independently
                    // verified intent; an agent-supplied intent is not trusted.
                    let payer_balances = effects.lamport_deltas.as_ref()
                        .and_then(|rows| rows.iter().find(|row| row.account_index == 0))
                        .and_then(|row| Some((
                            row.before_lamports.parse::<u64>().ok()?,
                            row.after_lamports.parse::<u64>().ok()?,
                        )));
                    for risk in rpc_intent_risks(
                        intent,
                        &evidence.status,
                        effects.cpi.captured,
                        &effects.cpi.invoked_program_ids,
                        payer_balances,
                    ) {
                        match risk {
                            RpcIntentRisk::CpiProgramOutsideAllowlist => {
                                verdict.finding("RPC_CPI_OUTSIDE_SIGNED_INTENT", "high",
                                    "Simulated inner instructions invoke a program absent from the independently signed intent allowlist; this single-provider observation needs review");
                            }
                            RpcIntentRisk::FeePayerNetOutflowExceedsCap => {
                                verdict.finding("RPC_FEE_PAYER_NET_OUTFLOW_OVER_CAP", "high",
                                    "Simulated fee-payer net lamport loss exceeds the signed SOL cap; net loss includes fees and is not a verified total spend");
                            }
                        }
                    }
                }
                if evidence.status=="rpc_failed" {
                    verdict.finding("RPC_SIMULATION_FAILED","high",
                        "The selected Solana RPC reported a failed simulation; execution is not validated");
                } else {
                    verdict.finding("RPC_SIMULATION_ONLY","medium",
                        "RPC simulation completed, but it is advisory and not evidence of total spending or future onchain success");
                }
                return (json!({"inspection":parsed,"rpc_analysis":evidence,"verdict":verdict}),30)
            }
            Err(err)=>{
                verdict.simulation_status="rpc_unavailable".into();
                verdict.finding(err.code(),"high",
                    "Solana RPC evidence unavailable or inconsistent; no successful execution should be inferred");
                return (json!({"inspection":parsed,"verdict":verdict}),30)
            }
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

#[cfg(test)]
mod token_2022_extension_tests {
    use super::*;
    fn observation(family: &'static str) -> hguet_rpc::Token2022ExtensionObservation {
        hguet_rpc::Token2022ExtensionObservation {
            parent_instruction_index:0,inner_instruction_index:0,
            opcode:26,sub_opcode:Some(1),family,operation:"test",
            layout_checked:false,mint:None,authority:None,new_authority:None,
            hook_program_id:None,declared_amount_raw:None,expected_fee_raw:None,
            fee_basis_points:None,maximum_fee_raw:None,
        }
    }
    #[test]
    fn extension_types_generate_distinct_advisory_risks() {
        let items=[
            observation("transfer_fee"),observation("transfer_hook"),
            observation("permanent_delegate"),observation("confidential_transfer_fee"),
        ];
        let codes=token_2022_extension_findings("rpc_succeeded",&items)
            .into_iter().map(|v|v.0).collect::<Vec<_>>();
        assert_eq!(codes,vec![
            "RPC_TOKEN_2022_TRANSFER_FEE","RPC_TOKEN_2022_TRANSFER_HOOK",
            "RPC_TOKEN_2022_PERMANENT_DELEGATE","RPC_TOKEN_2022_CONFIDENTIAL_EFFECTS"]);
    }
    #[test]
    fn failures_and_missing_extensions_do_not_invent_warnings() {
        assert!(token_2022_extension_findings("rpc_failed",
            &[observation("transfer_fee")]).is_empty());
        assert!(token_2022_extension_findings("rpc_unavailable",
            &[observation("transfer_hook")]).is_empty());
        assert!(token_2022_extension_findings("rpc_succeeded",
            &[observation("unknown_extension")]).is_empty());
        assert!(token_2022_extension_findings("rpc_succeeded",&[]).is_empty());
    }
}

#[cfg(test)]
mod token_cpi_classification_tests {
    use super::*;
    fn token(operation: &str) -> hguet_rpc::TokenCpiInstruction {
        hguet_rpc::TokenCpiInstruction {
            parent_instruction_index: 0,
            inner_instruction_index: 0,
            program_id: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
            operation: operation.into(),
            source_account: None,
            destination_account: None,
            mint: None,
            authority: None,
            delegate: None,
            amount_raw: None,
            decimals: None,
            authority_type: None,
            new_authority: None,
        }
    }
    fn codes(items: &[(&'static str, &'static str, &'static str)]) -> Vec<&'static str> {
        items.iter().map(|(code, _, _)| *code).collect()
    }
    #[test]
    fn authority_and_value_movements_have_distinct_advisory_findings() {
        assert_eq!(codes(&token_cpi_findings("rpc_succeeded",
            &[token("approve_checked"),token("transfer_checked")], 1)),
            vec!["RPC_TOKEN_CPI_AUTHORITY_RISK","RPC_TOKEN_CPI_MOVEMENT","RPC_TOKEN_CPI_OPAQUE"]);
    }
    #[test]
    fn missing_and_failed_simulation_never_claim_cpi_actions() {
        assert!(token_cpi_findings("rpc_failed",&[token("set_authority")],1).is_empty());
        assert!(token_cpi_findings("rpc_unavailable",&[token("burn")],1).is_empty());
        assert!(token_cpi_findings("rpc_succeeded",&[],0).is_empty());
    }
}

#[cfg(test)]
mod rpc_intent_tests {
    use super::*;

    fn signed_intent() -> PaymentIntentPayload {
        PaymentIntentPayload {
            schema_version: 1,
            kind: "hguet_payment_intent".into(),
            intent_id: "test-intent".into(),
            network: "devnet".into(),
            message_sha256: "a".repeat(64),
            not_before_unix: 100,
            expires_at_unix: 200,
            allowed_program_ids: vec![bs58::encode([1u8; 32]).into_string()],
            max_spend_lamports: "100".into(),
        }
    }

    #[test]
    fn matched_rpc_evidence_does_not_create_intent_risk() {
        let intent = signed_intent();
        assert!(rpc_intent_risks(
            &intent, "rpc_succeeded", true, &intent.allowed_program_ids, Some((1_000, 900)),
        ).is_empty());
        assert!(rpc_intent_risks(
            &intent, "rpc_succeeded", true, &intent.allowed_program_ids, Some((900, 1_000)),
        ).is_empty());
    }

    #[test]
    fn observed_cpi_and_payer_net_loss_are_advisory_risks() {
        let intent = signed_intent();
        let unlisted = bs58::encode([2u8; 32]).into_string();
        assert_eq!(rpc_intent_risks(
            &intent, "rpc_succeeded", true, &[unlisted], Some((1_000, 899)),
        ), vec![
            RpcIntentRisk::CpiProgramOutsideAllowlist,
            RpcIntentRisk::FeePayerNetOutflowExceedsCap,
        ]);
    }

    #[test]
    fn absent_or_failed_rpc_evidence_never_invents_mismatch() {
        let intent = signed_intent();
        let unlisted = bs58::encode([2u8; 32]).into_string();
        assert!(rpc_intent_risks(
            &intent, "rpc_failed", true, &[unlisted.clone()], Some((1_000, 100)),
        ).is_empty());
        assert!(rpc_intent_risks(
            &intent, "rpc_succeeded", false, &[unlisted], None,
        ).is_empty());
        assert!(rpc_intent_risks(
            &intent, "rpc_succeeded", false, &[], None,
        ).is_empty());
    }
}
