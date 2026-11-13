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
/// Compare a selected, untrusted RPC simulation against independently signed
/// per-mint limits. This is anomaly detection only: neither a CPI instruction
/// list nor a net balance snapshot proves actual gross source debits.
/// Source-scoped signed intent versus a *later*, single-RPC token-account
/// snapshot and provider-authored CPI declarations. These cannot prove who
/// owned a token account at execution or establish aggregate gross spending.
fn rpc_signed_source_scope_findings(
    intent:&PaymentIntentPayload,
    status:&str,
    effects:&hguet_rpc::SimulationEffects,
    snapshot:Option<&hguet_rpc::TokenAccountRpcSnapshot>,
)->Vec<(&'static str,&'static str,&'static str)> {
    if status!="rpc_succeeded" {return vec![];}
    let Some(scopes)=intent.token_source_limits.as_ref() else {return vec![];};
    let mut lookup=std::collections::BTreeMap::new();
    for scope in scopes {
        lookup.insert(scope.source_token_account.as_str(),scope);
    }
    let mut outside=false;
    let mut above=false;
    let mut uncertain=!effects.cpi.captured||
        effects.cpi.opaque_token_instruction_count>0||
        !effects.cpi.token_2022_extension_observations.is_empty();
    let mut totals=std::collections::BTreeMap::<&str,u128>::new();
    for ix in &effects.cpi.token_instructions {
        if matches!(ix.operation.as_str(),"transfer_checked"|"burn_checked") {
            match (ix.source_account.as_deref(),ix.mint.as_deref(),
                ix.authority.as_deref(),ix.amount_raw.as_deref()) {
                (Some(source),Some(mint),Some(authority),Some(raw))=>{
                    match lookup.get(source) {
                        Some(scope) if scope.mint==mint&&scope.authority==authority=>{
                            match (scope.max_debit_raw.parse::<u64>(),raw.parse::<u64>()) {
                                (Ok(cap),Ok(amount))=>{
                                    let sum=totals.entry(source).or_default();
                                    if let Some(new)=sum.checked_add(u128::from(amount)) {
                                        *sum=new;
                                        if new>u128::from(cap){above=true;}
                                    } else {uncertain=true;}
                                },
                                _=>{uncertain=true;}
                            }
                        }
                        _=>{outside=true;}
                    }
                },
                _=>{uncertain=true;}
            }
        } else if matches!(ix.operation.as_str(),
            "transfer"|"burn"|"approve"|"approve_checked"|
            "revoke"|"set_authority"|"close_account"|
            "freeze_account"|"thaw_account") {
            uncertain=true;
        }
    }
    let mut account_conflict=false;
    for scope in scopes {
        let Some(observed)=snapshot.and_then(|s|s.accounts.iter().find(
            |item|item.address==scope.source_token_account)) else {
            uncertain=true;
            continue;
        };
        match observed.state.as_ref() {
            Some(state) if observed.status=="token_2022" ||
                observed.status=="legacy_token"=>{
                // A delegate may legitimately be the instruction authority.
                // The later allowance still cannot prove execution-time power.
                if state.mint!=scope.mint ||
                    (state.token_authority!=scope.authority &&
                     state.delegate.as_deref()!=Some(scope.authority.as_str())) {
                    account_conflict=true;
                }
                if observed.status=="token_2022" &&
                    !observed.matching_mint_state_observed {uncertain=true;}
            }
            _=>{uncertain=true;}
        }
    }
    let mut findings=Vec::new();
    if outside {
        findings.push(("RPC_SIGNED_SOURCE_CPI_OUTSIDE_SCOPE","high",
            "Selected RPC reports checked CPI debits whose source/mint/authority roles do not match the independently signed source scope; independent execution evidence is absent"));
    }
    if above {
        findings.push(("RPC_SIGNED_SOURCE_CPI_OVER_CAP","high",
            "Selected RPC reports source-scoped checked CPI debit amounts above an independently signed raw cap; these are not proven gross onchain debits"));
    }
    if account_conflict {
        findings.push(("RPC_SIGNED_SOURCE_ACCOUNT_CONFLICT","high",
            "A separately read Token-2022 account reports a mint or owner authority different from its signed source scope; delegate and historical states remain unverified"));
    }
    if uncertain {
        findings.push(("RPC_SIGNED_SOURCE_EVIDENCE_INCOMPLETE","high",
            "Source account or CPI evidence is missing, opaque, legacy-token-only, or not paired with its mint; single-provider non-atomic snapshots cannot certify signer authority"));
    }
    findings
}

fn rpc_signed_token_cap_findings(
    intent:&PaymentIntentPayload,
    status:&str,
    effects:&hguet_rpc::SimulationEffects,
)->Vec<(&'static str,&'static str,&'static str)> {
    if status!="rpc_succeeded" {return vec![];}
    let Some(limits)=intent.token_spend_limits.as_ref() else {return vec![];};
    let caps=limits.iter().filter_map(|item|
        item.max_debit_raw.parse::<u64>().ok().map(|n|(&item.mint,n)))
        .collect::<std::collections::BTreeMap<_,_>>();
    let mut declared=std::collections::BTreeMap::<&str,u128>::new();
    let mut unknown=!effects.cpi.captured||
        effects.cpi.opaque_token_instruction_count>0;
    let mut unlisted=false;
    for ix in &effects.cpi.token_instructions {
        // Only the checked debit opcodes have explicit mint identities.
        if matches!(ix.operation.as_str(),"transfer_checked"|"burn_checked") {
            match (ix.mint.as_deref(),ix.amount_raw.as_deref()) {
                (Some(mint),Some(raw))=>{
                    if !caps.contains_key(&mint.to_string()) {unlisted=true;}
                    if let Ok(n)=raw.parse::<u64>() {
                        let sum=declared.entry(mint).or_insert(0);
                        if let Some(next)=sum.checked_add(u128::from(n)){*sum=next;}
                        else {unknown=true;}
                    }else{unknown=true;}
                }
                _=>{unknown=true;}
            }
        } else if matches!(ix.operation.as_str(),
            "transfer"|"burn"|"approve"|"approve_checked"|"revoke"|
            "set_authority"|"close_account"|"freeze_account"|"thaw_account") {
            unknown=true;
        }
    }
    // TransferCheckedWithFee is a Token-2022 extension. The typed fields
    // are still single-provider CPI declarations, not verified fee effects.
    for hint in &effects.cpi.token_2022_extension_observations {
        if hint.operation=="transfer_checked_with_fee" && hint.layout_checked {
            match (hint.mint.as_deref(),hint.declared_amount_raw.as_deref()){
                (Some(mint),Some(raw))=>{
                    if !caps.contains_key(&mint.to_string()){unlisted=true;}
                    if let Ok(n)=raw.parse::<u64>(){
                        let sum=declared.entry(mint).or_insert(0);
                        if let Some(next)=sum.checked_add(u128::from(n)){*sum=next;}
                        else {unknown=true;}
                    }else{unknown=true;}
                }
                _=>{unknown=true;}
            }
        }else{unknown=true;}
    }
    let over=declared.iter().any(|(mint,total)|
        caps.get(&mint.to_string()).is_some_and(|cap|*total>u128::from(*cap)));
    let mut net_over=false;
    if let Some(rows)=&effects.token_deltas {
        let mut losses=std::collections::BTreeMap::<&str,u128>::new();
        for row in rows {
            if !row.complete_pair {unknown=true;continue;}
            if let Some(raw)=&row.delta_raw_amount {
                match raw.parse::<i128>() {
                    Ok(value) if value<0=>{
                        let sum=losses.entry(row.mint.as_str()).or_insert(0);
                        if let Some(next)=sum.checked_add(value.unsigned_abs()) {*sum=next;}
                        else {unknown=true;}
                    }
                    Ok(_)=>{},
                    Err(_)=>{unknown=true;}
                }
            }else{unknown=true;}
        }
        net_over=losses.iter().any(|(mint,total)|
            caps.get(&mint.to_string()).is_some_and(|cap|*total>u128::from(*cap)));
        if losses.keys().any(|mint|!caps.contains_key(&mint.to_string())){
            unlisted=true;
        }
    } else {unknown=true;}
    let mut findings=Vec::new();
    if unlisted {
        findings.push(("RPC_SIGNED_TOKEN_MINT_OUTSIDE_CAPS","high",
            "Selected RPC reports CPI token debits or simulated net token losses involving a mint absent from independently signed per-mint limits; this is advisory and requires independent verification"));
    }
    if over {
        findings.push(("RPC_SIGNED_TOKEN_CPI_OVER_CAP","high",
            "Selected RPC reports checked CPI token debits whose summed raw amount exceeds the independently signed per-mint cap; this does not establish exact executed gross spending"));
    }
    if net_over {
        findings.push(("RPC_SIGNED_TOKEN_NET_LOSS_OVER_CAP","high",
            "Selected RPC reports observed token-account net losses above a signed mint cap; incoming transfers, other account owners and omitted snapshots prevent exact attribution"));
    }
    if unknown {
        findings.push(("RPC_SIGNED_TOKEN_CAP_INCOMPLETE","high",
            "CPI or token balance data is missing, opaque, unchecked or has unsupported authority/fee semantics; no full per-mint spending bound can be established"));
    }
    findings
}

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
    token_instructions: &[hguet_rpc::TokenCpiInstruction],
) -> Vec<(&'static str, &'static str, &'static str)> {
    if status!="rpc_succeeded" { return Vec::new(); }
    // SetAuthority is a *base* opcode (6). It also modifies Token-2022
    // extension authorities, so inspect it alongside extension prefixes.
    const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
    let changes = |kinds: &[u8]| token_instructions.iter().any(|item|
        item.program_id == TOKEN_2022 && item.operation=="set_authority" &&
        item.authority_type.is_some_and(|kind| kinds.contains(&kind)));
    let mut findings=Vec::new();
    if items.iter().any(|item|item.family=="transfer_fee") || changes(&[4,5]) {
        findings.push(("RPC_TOKEN_2022_TRANSFER_FEE","high",
            "Token-2022 CPI references transfer-fee configuration, authority rotation, expected fees or withheld-fee operations; fee state and net receipts are unverified"));
    }
    if items.iter().any(|item|item.family=="transfer_hook") || changes(&[10]) {
        findings.push(("RPC_TOKEN_2022_TRANSFER_HOOK","high",
            "Token-2022 CPI references transfer-hook configuration or authority rotation; hook execution and downstream effects are not independently verified"));
    }
    if items.iter().any(|item|item.family=="permanent_delegate") || changes(&[8]) {
        findings.push(("RPC_TOKEN_2022_PERMANENT_DELEGATE","high",
            "Token-2022 CPI references permanent-delegate initialization or authority rotation; this mint-wide authority may move or burn tokens without a token-account owner signature"));
    }
    if items.iter().any(|item|matches!(item.family,
        "confidential_transfer"|"confidential_transfer_fee"|"confidential_mint_burn")) || changes(&[9,11]) {
        findings.push(("RPC_TOKEN_2022_CONFIDENTIAL_EFFECTS","high",
            "Token-2022 CPI references confidential token operations; ordinary balance snapshots cannot establish all hidden movements"));
    }
    findings
}

/// A mint-state lookup happens in a separate one-provider read, not at the
/// simulated execution bank. These observations can warn but never authorize.
fn mint_snapshot_findings(
    snapshot: &hguet_rpc::MintRpcSnapshot,
) -> Vec<(&'static str, &'static str, &'static str)> {
    let mut findings=vec![("RPC_MINT_STATE_NON_ATOMIC","medium",
        "Token-2022 mint state was read after simulation in a separate RPC call; matching or later slots are not an atomic execution-state proof")];
    if snapshot.accounts.iter().any(|item|item.status=="missing") {
        findings.push(("RPC_MINT_STATE_MISSING","high",
            "At least one candidate mint account was absent from the selected RPC snapshot; mint constraints remain unknown"));
    }
    let states=snapshot.accounts.iter().filter_map(|item|item.state.as_ref()).collect::<Vec<_>>();
    if states.iter().any(|s|s.fee_config.is_some()) {
        findings.push(("RPC_MINT_TRANSFER_FEE_CONFIG","high",
            "Token-2022 mint snapshot reports transfer-fee configuration; old/new epoch fees and mutable authority must be assessed before estimating net token receipt"));
    }
    if states.iter().any(|s|s.hook.as_ref().is_some_and(|h|h.program_id.is_some())) {
        findings.push(("RPC_MINT_TRANSFER_HOOK_ACTIVE","high",
            "Token-2022 mint snapshot reports an active transfer-hook program; downstream hook code and execution effects remain unverified"));
    }
    if states.iter().any(|s|s.permanent_delegate.is_some()) {
        findings.push(("RPC_MINT_PERMANENT_DELEGATE_ACTIVE","high",
            "Token-2022 mint snapshot reports a non-null permanent delegate with mint-wide token control; holder authorization alone may not restrict its actions"));
    }
    if states.iter().any(|s|s.confidential_extension_present) {
        findings.push(("RPC_MINT_CONFIDENTIAL_EXTENSION","high",
            "Token-2022 mint snapshot includes confidential extension state; ordinary balance snapshots do not establish complete asset effects"));
    }
    if states.iter().any(|s|s.unknown_extension_count>0) {
        findings.push(("RPC_MINT_UNKNOWN_EXTENSION","high",
            "One or more Token-2022 mint TLV extension IDs are unknown to this decoder; full program effects cannot be inferred"));
    }
    if states.iter().any(|s|s.extensions.iter().any(|x|!x.layout_checked)) {
        findings.push(("RPC_MINT_OPAQUE_EXTENSION_STATE","high",
            "One or more known or unknown mint extension payloads have not been semantically decoded; presence alone cannot prove safe transfers"));
    }
    findings
}

/// Token-account and mint-state reads are *separate* single-RPC snapshots.
/// They cannot prove a pre-sign or execution-state authorization.
fn token_account_snapshot_findings(
    snapshot: &hguet_rpc::TokenAccountRpcSnapshot,
) -> Vec<(&'static str, &'static str, &'static str)> {
    let mut findings=vec![("RPC_TOKEN_ACCOUNT_NON_ATOMIC","medium",
        "Token-2022 holding account state was read separately after simulation; minimum slot does not guarantee an atomic execution snapshot")];
    if snapshot.accounts.iter().any(|x|x.status=="missing") {
        findings.push(("RPC_TOKEN_ACCOUNT_MISSING","high",
            "At least one token holding account was absent from a later RPC snapshot; balances and authorities are unresolved"));
    }
    if snapshot.accounts.iter().any(|x|x.status=="not_token_2022") {
        findings.push(("RPC_TOKEN_ACCOUNT_PROGRAM_UNVERIFIED","high",
            "A reported token account is not owned by Token-2022 in the later RPC snapshot; this reader cannot authenticate its program state or owner"));
    }
    if snapshot.accounts.iter().any(|x|x.mint_matches_simulation_report==Some(false)) {
        findings.push(("RPC_TOKEN_ACCOUNT_MINT_MISMATCH","high",
            "A token account mint in the later RPC snapshot differs from simulated balance metadata; this may be stale or inconsistent provider evidence"));
    }
    if snapshot.accounts.iter().any(|x|x.authority_matches_simulation_report==Some(false)) {
        findings.push(("RPC_TOKEN_ACCOUNT_AUTHORITY_MISMATCH","high",
            "Token account authority differs between later account state and simulated balance metadata; neither view can establish signer authorization"));
    }
    let states=snapshot.accounts.iter().filter_map(|x|x.state.as_ref()).collect::<Vec<_>>();
    if snapshot.accounts.iter().any(|x|x.state.is_some()&&!x.matching_mint_state_observed) {
        findings.push(("RPC_TOKEN_ACCOUNT_MINT_STATE_UNCONFIRMED","high",
            "Token account was read but its referenced mint was not confirmed as a Token-2022 mint in the separate mint snapshot"));
    }
    if states.iter().any(|s|s.account_state=="frozen") {
        findings.push(("RPC_TOKEN_ACCOUNT_FROZEN","high",
            "A token holding account is frozen in the later snapshot; transferability and delivery must not be assumed"));
    }
    if states.iter().any(|s|s.delegate.is_some()) {
        findings.push(("RPC_TOKEN_ACCOUNT_DELEGATE","high",
            "A token holding account has a delegate authority; delegated allowances and authorization are not independently enforced"));
    }
    if states.iter().any(|s|s.close_authority.is_some()) {
        findings.push(("RPC_TOKEN_ACCOUNT_CLOSE_AUTHORITY","medium",
            "A separate close authority is configured on a token account; account closure permissions may differ from holder permissions"));
    }
    if states.iter().any(|s|s.transfer_fee_withheld_raw.as_deref()
        .is_some_and(|amount|amount!="0")) {
        findings.push(("RPC_TOKEN_ACCOUNT_WITHHELD_FEES","high",
            "Token-2022 account snapshot contains nonzero withheld transfer fees; the gross and net token movements are not fully attributed"));
    }
    if states.iter().any(|s|s.requires_incoming_memo==Some(true)) {
        findings.push(("RPC_TOKEN_ACCOUNT_MEMO_REQUIRED","medium",
            "Token-2022 account requires incoming transfer memos; no transaction-wide memo compliance has been proven"));
    }
    if states.iter().any(|s|s.cpi_guard_locked==Some(true)) {
        findings.push(("RPC_TOKEN_ACCOUNT_CPI_GUARD","medium",
            "Token-2022 account has CPI Guard enabled; some cross-program operations may be restricted"));
    }
    if states.iter().any(|s|s.transfer_hook_transferring==Some(true)) {
        findings.push(("RPC_TOKEN_ACCOUNT_HOOK_TRANSFERRING","high",
            "Token account reports an in-progress transfer hook flag; hook state and execution cannot be independently confirmed"));
    }
    if states.iter().any(|s|s.non_transferable_account) {
        findings.push(("RPC_TOKEN_ACCOUNT_NON_TRANSFERABLE","high",
            "Token account carries NonTransferableAccount extension; token delivery and onward transfer assumptions require independent checks"));
    }
    if states.iter().any(|s|s.confidential_extension_present) {
        findings.push(("RPC_TOKEN_ACCOUNT_CONFIDENTIAL","high",
            "Token account has confidential extensions; public token balance snapshots may omit relevant encrypted flows"));
    }
    if states.iter().any(|s|s.unknown_extension_count>0||s.opaque_extension_count>0) {
        findings.push(("RPC_TOKEN_ACCOUNT_OPAQUE_EXTENSION","high",
            "Token account carries unsupported or unknown TLV extension payloads; HGUET cannot claim complete token semantics"));
    }
    findings
}

/// Correlation compares evidence sources, but never attributes simulated
/// net flows to a particular CPI or proves that later state was the bank state.
/// Later single-provider account state can show owner/delegate *agreement*,
/// but it cannot authenticate historical execution-time permissions.
fn source_authority_findings(
    review:&hguet_rpc::SourceAuthorityReview,
)->Vec<(&'static str,&'static str,&'static str)> {
    let mut findings=Vec::new();
    if review.sources.is_empty(){return findings;}
    findings.push(("RPC_SOURCE_AUTHORITY_NON_ATOMIC","medium",
        "Source authority roles are compared to a later RPC account read, never an authenticated execution-bank state"));
    if review.sources.iter().any(|s|matches!(s.account_observation,
        "unobserved"|"missing"|"other_program")) {
        findings.push(("RPC_SOURCE_AUTHORITY_UNOBSERVED","high",
            "A signed source has no supported token-account state in the later snapshot; permission is unresolved"));
    }
    if review.sources.iter().any(|s|s.program_matches_wire==Some(false)) {
        findings.push(("RPC_SOURCE_AUTHORITY_PROGRAM_CONFLICT","high",
            "Observed token account owner program differs from direct Token/Token-2022 instruction program"));
    }
    if review.sources.iter().any(|s|s.mint_matches_signed_scope==Some(false)) {
        findings.push(("RPC_SOURCE_AUTHORITY_MINT_CONFLICT","high",
            "Token-account mint in later RPC snapshot differs from independently signed source scope"));
    }
    if review.sources.iter().any(|s|s.authority_relationship=="unmatched") {
        findings.push(("RPC_SOURCE_AUTHORITY_ROLE_UNMATCHED","high",
            "Signed source authority is neither owner nor delegate in later account state; historical state is unknown"));
    }
    if review.sources.iter().any(|s|s.delegate_allowance_covers_declared==Some(false)) {
        findings.push(("RPC_SOURCE_AUTHORITY_DELEGATE_ALLOWANCE_LOW","high",
            "Later delegate allowance is smaller than signed direct declared debit; execution-time allowance is unverified"));
    }
    if review.sources.iter().any(|s|s.later_account_balance_covers_declared==Some(false)) {
        findings.push(("RPC_SOURCE_AUTHORITY_BALANCE_LOW","medium",
            "Later token-account balance is smaller than declared debit; it could be post-simulation and does not prove execution was impossible"));
    }
    if review.sources.iter().any(|s|s.frozen_at_observation==Some(true)) {
        findings.push(("RPC_SOURCE_AUTHORITY_FROZEN","high",
            "Signed source token account was frozen at later observed slot; transferability at execution was not established"));
    }
    if review.sources.iter().any(|s|s.restricted_or_opaque_extensions==Some(true)) {
        findings.push(("RPC_SOURCE_AUTHORITY_EXTENSION_UNRESOLVED","high",
            "Observed source carries restricted or opaque Token-2022 extensions; deeper execution-time semantics remain unknown"));
    }
    findings
}

fn effect_graph_findings(
    graph: &hguet_rpc::EffectGraph,
) -> Vec<(&'static str, &'static str, &'static str)> {
    if graph.simulation_status!="rpc_succeeded" {return vec![];}
    let mut results=Vec::new();
    if graph.alerts.contains(&"GRAPH_CPI_NET_ATTRIBUTION_UNPROVEN") {
        results.push(("RPC_EFFECT_GRAPH_CPI_UNATTRIBUTED","medium",
            "Declared token CPI movement and simulated net balance deltas are indexed separately; per-instruction gross spending and causality are not proven"));
    }
    if graph.alerts.iter().any(|flag|matches!(*flag,
        "GRAPH_ACCOUNT_MINT_DISAGREEMENT"|"GRAPH_ACCOUNT_AUTHORITY_DISAGREEMENT")) {
        results.push(("RPC_EFFECT_GRAPH_IDENTITY_CONFLICT","high",
            "The non-atomic token-account snapshot conflicts with simulation mint or authority metadata; neither view proves execution-time identity"));
    }
    if graph.evidence_gaps.contains(&"opaque_token_cpi_semantics_unresolved") {
        results.push(("RPC_EFFECT_GRAPH_OPAQUE_CPI","high",
            "Opaque CPI instructions prevent attribution of all token and authority effects; correlated balances cannot close this coverage gap"));
    }
    results
}

/// Direct SPL Token instructions are decoded from original wire bytes, so
/// these findings apply offline too. No RPC effect or signer authorization is
/// assumed even if the instruction is syntactically recognized.
fn wire_direct_token_findings(
    analysis:&hguet_rpc::DirectTokenAnalysis,
)->Vec<(&'static str,&'static str,&'static str)> {
    let mut findings=Vec::new();
    if analysis.recognized.iter().any(|ix|matches!(ix.decoded.operation.as_str(),
        "transfer"|"transfer_checked"|"mint_to"|"mint_to_checked"|
        "burn"|"burn_checked")) {
        findings.push(("WIRE_TOKEN_DIRECT_MOVEMENT","medium",
            "The original transaction declares direct token movement; amounts are unsigned intentions, not verified net effects, final execution or consent"));
    }
    if analysis.recognized.iter().any(|ix|ix.decoded.operation=="transfer") {
        findings.push(("WIRE_TOKEN_DIRECT_UNCHECKED_TRANSFER","high",
            "Direct Token Transfer uses an unchecked opcode without an explicit mint or decimals; no mint association or spending safety is inferred"));
    }
    if analysis.recognized.iter().any(|ix|matches!(ix.decoded.operation.as_str(),
        "approve"|"approve_checked"|"revoke"|"set_authority"|
        "close_account"|"freeze_account"|"thaw_account")) {
        findings.push(("WIRE_TOKEN_DIRECT_AUTHORITY_RISK","high",
            "Original transaction declares token delegation, authority or account-control instructions; actual authorization and execution are not proven"));
    }
    if !analysis.opaque.is_empty() {
        findings.push(("WIRE_TOKEN_DIRECT_OPAQUE","high",
            "Original transaction contains token instructions with unsupported or Token-2022 extension semantics; undecoded bytes do not imply safe effects"));
    }
    if analysis.recognized.iter().any(|ix|ix.program_address_from_lookup||
        ix.account_addresses_from_lookup) ||
       analysis.opaque.iter().any(|ix|ix.program_address_from_lookup) {
        findings.push(("WIRE_TOKEN_DIRECT_ALT_UNTRUSTED","high",
            "Top-level token program or account addresses depend on an untrusted RPC address lookup rather than static wire keys"));
    }
    findings
}

fn signed_sol_intent_cannot_cap_direct_tokens(analysis:&hguet_rpc::DirectTokenAnalysis)->bool{
    analysis.recognized.iter().any(|ix|matches!(ix.decoded.operation.as_str(),
        "transfer"|"transfer_checked"|"mint_to"|"mint_to_checked"|
        "burn"|"burn_checked"|"approve"|"approve_checked")) ||
    !analysis.opaque.is_empty()
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
    let mut offline_direct_analysis: Option<hguet_rpc::DirectTokenAnalysis> = None;
    // The offline path uses ONLY original wire bytes and static accounts.
    // v0 ALT addresses need separate RPC resolution; do not fabricate them.
    if parsed.unresolved_lookup_addresses==0 {
        match hguet_rpc::inspect_direct_tokens(&parsed,None) {
            Ok(direct)=>{
                verdict.coverage.push("wire_top_level_instruction_bytes".into());
                if direct.total_token_program_instructions>0 {
                    verdict.coverage.push("wire_direct_token_binary_decode".into());
                }
                for (code,severity,message) in wire_direct_token_findings(&direct) {
                    verdict.finding(code,severity,message);
                }
                offline_direct_analysis=Some(direct);
            }
            Err(_)=>{
                verdict.finding("WIRE_TOKEN_DIRECT_DECODER_UNAVAILABLE","high",
                    "The bounded original-wire token decoder could not establish complete direct token semantics; no safety is inferred");
            }
        }
    } else {
        verdict.finding("WIRE_TOKEN_DIRECT_ALT_UNRESOLVED","high",
            "Original v0 transaction references unresolved lookup addresses; full direct-token program/account roles require separately checked ALT evidence");
    }
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
    let mut signed_token_spend_review=None;
    let mut signed_token_source_review=None;
    if let Some(ref intent)=verified_intent {
        match &intent.token_spend_limits {
            None=>{
                if intent.token_source_limits.is_none() {
                    if let Some(ref direct)=offline_direct_analysis {
                        if signed_sol_intent_cannot_cap_direct_tokens(direct) {
                            verdict.finding("SIGNED_INTENT_TOKEN_CAP_UNSPECIFIED","high",
                                "The independently verified legacy PaymentIntent only caps native SOL lamports; direct token movement, allowances and opaque token instructions have no signed token debit limits");
                        }
                    }
                }
            }
            Some(caps)=>{
                // verify_intent already ran this same bounded direct-wire check,
                // but preserve an auditable per-mint summary in the CLI response.
                // A failure here is never treated as a successfully signed cap.
                match hguet_core::review_declared_token_limits(&parsed,caps) {
                    Ok(review)=>{
                        verdict.coverage.push("signed_direct_token_debit_limits".into());
                        verdict.finding("SIGNED_INTENT_TOKEN_CAP_PARTIAL_COVERAGE","high",
                            "Signed per-mint limits bound recognized direct checked token debit declarations only. CPI, fees, unknown program side effects and total gross spending are NOT enforceable from the original wire alone");
                        signed_token_spend_review=Some(review);
                    }
                    Err(err)=>{
                        verdict.decision=Decision::Deny;
                        verdict.finding("SIGNED_INTENT_TOKEN_CAP_INVALID","critical",err);
                        return (json!({"inspection":parsed,"verdict":verdict}),20);
                    }
                }
            }
        }
        if let Some(ref scopes)=intent.token_source_limits {
            // Exact-byte signing + source/signer-role enforcement ran in
            // verify_intent. Recompute once to expose bounded review evidence.
            match hguet_core::review_declared_source_limits(&parsed,scopes) {
                Ok(review)=>{
                    verdict.coverage.push("signed_direct_token_source_authority_roles".into());
                    verdict.finding("SIGNED_INTENT_SOURCE_SCOPE_PARTIAL_COVERAGE","high",
                        "Signed source/mint/authority scopes bind direct checked debit declarations to required message signer roles, but do not verify token-account ownership, multisig, CPI, actual signature presence before signing or total executed spending");
                    signed_token_source_review=Some(review);
                }
                Err(err)=>{
                    verdict.decision=Decision::Deny;
                    verdict.finding("SIGNED_INTENT_SOURCE_SCOPE_INVALID","critical",err);
                    return (json!({"inspection":parsed,"verdict":verdict}),20);
                }
            }
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
                    &effects.cpi.token_instructions,
                ) {
                    verdict.finding(code,severity,message);
                }
                if let Some(ref mint_snapshot) = evidence.mint_snapshot {
                    verdict.coverage.push("rpc_token_2022_mint_state_non_atomic".into());
                    for (code,severity,message) in mint_snapshot_findings(mint_snapshot) {
                        verdict.finding(code,severity,message);
                    }
                }
                if let Some(ref account_snapshot) = evidence.token_account_snapshot {
                    verdict.coverage.push("rpc_token_2022_account_state_non_atomic".into());
                    for (code,severity,message) in token_account_snapshot_findings(account_snapshot) {
                        verdict.finding(code,severity,message);
                    }
                }
                if evidence.status=="rpc_succeeded" {
                    verdict.coverage.push("rpc_effect_correlation_graph_advisory".into());
                }
                for (code,severity,message) in effect_graph_findings(&evidence.effect_graph) {
                    verdict.finding(code,severity,message);
                }
                let mut signed_source_authority_evidence=None;
                if evidence.status=="rpc_succeeded" {
                    if let Some(ref review)=signed_token_source_review {
                        match hguet_rpc::correlate_signed_source_authority(
                            review,evidence.token_account_snapshot.as_ref(),
                            evidence.context_slot) {
                            Ok(result)=>{
                                verdict.coverage.push("rpc_signed_source_authority_correlations_advisory".into());
                                for (code,severity,message) in source_authority_findings(&result) {
                                    verdict.finding(code,severity,message);
                                }
                                signed_source_authority_evidence=Some(result);
                            }
                            Err(_)=>{
                                verdict.finding("RPC_SOURCE_AUTHORITY_EVIDENCE_INVALID","high",
                                    "Authority correlation is inconsistent across later RPC snapshots; signer ownership or transfer permissions cannot be inferred");
                            }
                        }
                    }
                }
                if let Some(ref intent) = verified_intent {
                    if intent.token_spend_limits.is_some() {
                        for (code,severity,message) in rpc_signed_token_cap_findings(
                            intent,&evidence.status,effects) {
                            verdict.finding(code,severity,message);
                        }
                    }
                    if intent.token_source_limits.is_some() {
                        for (code,severity,message) in rpc_signed_source_scope_findings(
                            intent,&evidence.status,effects,evidence.token_account_snapshot.as_ref()
                        ) {
                            verdict.finding(code,severity,message);
                        }
                    }
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
                return (json!({"inspection":parsed,"rpc_analysis":evidence,
                    "signed_token_spend_review":signed_token_spend_review,
                    "signed_token_source_review":signed_token_source_review,
                    "signed_source_authority_evidence":signed_source_authority_evidence,
                    "verdict":verdict}),30)
            }
            Err(err)=>{
                verdict.simulation_status="rpc_unavailable".into();
                verdict.finding(err.code(),"high",
                    "Solana RPC evidence unavailable or inconsistent; no successful execution should be inferred");
                return (json!({"inspection":parsed,
                    "signed_token_spend_review":signed_token_spend_review,
                    "signed_token_source_review":signed_token_source_review,
                    "verdict":verdict}),30)
            }
        }
    }
    verdict.finding("NO_SIMULATION","high","Wire inspection does not prove transfers, CPI effects, execution or wallet authorization");
    (json!({"inspection":parsed,
        "signed_token_spend_review":signed_token_spend_review,
                    "signed_token_source_review":signed_token_source_review,
        "verdict":verdict}),if v.command=="inspect"{0}else{30})
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
mod signed_token_cap_rpc_tests {
    use super::*;
    use hguet_core::TokenSpendLimit;
    use hguet_rpc::{SimulationEffects,CpiObservation,TokenBalanceDelta,TokenCpiInstruction};
    fn key(i:u8)->String{bs58::encode([i;32]).into_string()}
    fn intent()->PaymentIntentPayload {
        PaymentIntentPayload {
            schema_version:1,kind:"hguet_payment_intent".into(),
            intent_id:"synthetic".into(),network:"devnet".into(),
            message_sha256:"a".repeat(64),not_before_unix:1,
            expires_at_unix:4102444800,allowed_program_ids:vec![],
            max_spend_lamports:"1000".into(),
            token_spend_limits:Some(vec![TokenSpendLimit {
                mint:key(2),max_debit_raw:"100".into(),
            }]),
            token_source_limits:None,
        }
    }
    fn checked(mint:u8,amount:&str)->TokenCpiInstruction {
        TokenCpiInstruction {
            parent_instruction_index:0,inner_instruction_index:0,
            program_id:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
            operation:"transfer_checked".into(),
            source_account:Some(key(3)),destination_account:Some(key(4)),
            mint:Some(key(mint)),authority:Some(key(5)),delegate:None,
            amount_raw:Some(amount.into()),decimals:Some(6),
            authority_type:None,new_authority:None,
        }
    }
    fn delta(mint:u8,loss:&str)->TokenBalanceDelta{
        TokenBalanceDelta{
            account_index:0,token_account:key(3),mint:key(mint),
            owner:Some(key(5)),decimals:6,
            before_raw_amount:Some("1000".into()),
            after_raw_amount:Some("900".into()),
            delta_raw_amount:Some(loss.into()),complete_pair:true,
        }
    }
    fn effects(cpi:Vec<TokenCpiInstruction>,balance:Vec<TokenBalanceDelta>)
        ->SimulationEffects{
        SimulationEffects {
            lamport_deltas:None,token_deltas:Some(balance),
            cpi:CpiObservation {
                captured:true,group_count:Some(1),instruction_count:Some(cpi.len()),
                invoked_program_ids:vec![],token_instructions:cpi,
                token_2022_extension_observations:vec![],
                opaque_token_instruction_count:0,
                token_2022_extension_instruction_count:0,
                missing_compiled_token_data_count:0,
                requires_semantic_review:true,limitations:vec![],
            },
            simulated_fee_lamports:None,observed_fields:vec![],
            missing_fields:vec![],warnings:vec![],
            security_coverage:"partial_untrusted_rpc".into(),
        }
    }
    fn codes(intent:&PaymentIntentPayload,effects:&SimulationEffects)->Vec<&'static str>{
        rpc_signed_token_cap_findings(intent,"rpc_succeeded",effects)
            .into_iter().map(|item|item.0).collect()
    }
    #[test]
    fn cpi_sum_and_simulated_losses_over_mint_cap_are_advisory(){
        let e=effects(vec![checked(2,"65"),checked(2,"45")],
            vec![delta(2,"-110")]);
        let findings=codes(&intent(),&e);
        assert!(findings.contains(&"RPC_SIGNED_TOKEN_CPI_OVER_CAP"));
        assert!(findings.contains(&"RPC_SIGNED_TOKEN_NET_LOSS_OVER_CAP"));
        assert!(!findings.contains(&"RPC_SIGNED_TOKEN_MINT_OUTSIDE_CAPS"));
        let matched=effects(vec![checked(2,"60"),checked(2,"40")],
            vec![delta(2,"-90")]);
        assert!(codes(&intent(),&matched).is_empty());
    }
    #[test]
    fn rpc_unlisted_token_and_incomplete_cpi_are_never_approved(){
        let mut e=effects(vec![checked(6,"5")],vec![delta(6,"-5")]);
        e.cpi.opaque_token_instruction_count=1;
        let findings=codes(&intent(),&e);
        assert!(findings.contains(&"RPC_SIGNED_TOKEN_MINT_OUTSIDE_CAPS"));
        assert!(findings.contains(&"RPC_SIGNED_TOKEN_CAP_INCOMPLETE"));
        e.cpi.opaque_token_instruction_count=0;
        e.cpi.captured=false;
        assert!(codes(&intent(),&e).contains(&"RPC_SIGNED_TOKEN_CAP_INCOMPLETE"));
    }
    #[test]
    fn no_verified_caps_or_failed_simulation_cannot_claim_rpc_violation(){
        let e=effects(vec![checked(2,"1000")],vec![delta(2,"-1000")]);
        assert!(rpc_signed_token_cap_findings(&intent(),"rpc_failed",&e).is_empty());
        let mut legacy=intent();
        legacy.token_spend_limits=None;
        assert!(codes(&legacy,&e).is_empty());
        assert!(rpc_signed_token_cap_findings(&intent(),"rpc_unavailable",&e).is_empty());
    }
    fn scoped_intent() -> PaymentIntentPayload {
        let mut intent=intent();
        intent.token_source_limits=Some(vec![hguet_core::TokenSourceLimit{
            mint:key(2),source_token_account:key(3),
            authority:key(5),max_debit_raw:"100".into(),
        }]);
        intent
    }
    #[test]
    fn source_scoped_rpc_cpi_anomalies_remain_advisory(){
        let checked_good=checked(2,"60");
        let e=effects(vec![checked_good.clone(),checked(2,"50")],vec![]);
        let findings=rpc_signed_source_scope_findings(
            &scoped_intent(),"rpc_succeeded",&e,None);
        let codes=findings.iter().map(|x|x.0).collect::<Vec<_>>();
        assert!(codes.contains(&"RPC_SIGNED_SOURCE_CPI_OVER_CAP"));
        assert!(codes.contains(&"RPC_SIGNED_SOURCE_EVIDENCE_INCOMPLETE"));
        let mut outside=checked_good;
        outside.source_account=Some(key(6));
        let findings=rpc_signed_source_scope_findings(
            &scoped_intent(),"rpc_succeeded",
            &effects(vec![outside],vec![]),None);
        assert!(findings.iter().any(|x|x.0=="RPC_SIGNED_SOURCE_CPI_OUTSIDE_SCOPE"));
        assert!(rpc_signed_source_scope_findings(
            &scoped_intent(),"rpc_failed",&e,None).is_empty());
    }
    #[test]
    fn later_token_account_authority_conflict_is_not_mistaken_for_execution(){
        use hguet_rpc::{TokenAccountRpcSnapshot,TokenAccountObservation,Token2022AccountState};
        let state=Token2022AccountState{
            token_account:key(3),mint:key(2),token_authority:key(6),
            amount_raw:"10".into(),delegate:None,delegated_amount_raw:"0".into(),
            account_state:"initialized",native_reserve_lamports:None,
            close_authority:None,transfer_fee_withheld_raw:None,
            requires_incoming_memo:None,cpi_guard_locked:None,
            transfer_hook_transferring:None,immutable_owner:false,
            non_transferable_account:false,confidential_extension_present:false,
            opaque_extension_count:0,unknown_extension_count:0,
            extensions:vec![],limitation:"synthetic".into(),
        };
        let snapshot=TokenAccountRpcSnapshot{
            context_slot:501,simulation_slot:500,atomic_with_simulation:false,
            accounts:vec![TokenAccountObservation{
                address:key(3),simulation_reported_mint:key(2),
                status:"token_2022".into(),state:Some(state),
                mint_matches_simulation_report:Some(true),
                authority_matches_simulation_report:Some(false),
                matching_mint_state_observed:true,
            }],
            limitation:"synthetic".into(),
        };
        let e=effects(vec![checked(2,"5")],vec![]);
        let findings=rpc_signed_source_scope_findings(
            &scoped_intent(),"rpc_succeeded",&e,Some(&snapshot));
        let codes=findings.iter().map(|x|x.0).collect::<Vec<_>>();
        assert!(codes.contains(&"RPC_SIGNED_SOURCE_ACCOUNT_CONFLICT"));
        assert!(!codes.contains(&"RPC_SIGNED_SOURCE_CPI_OVER_CAP"));
        // A matching *later* snapshot is not a permission grant either.
        assert!(rpc_signed_source_scope_findings(
            &scoped_intent(),"rpc_failed",&e,Some(&snapshot)).is_empty());
    }
}

#[cfg(test)]
mod wire_direct_token_tests {
    use super::*;
    use hguet_rpc::{
        DirectTokenAnalysis,DirectTokenInstruction,OpaqueDirectTokenInstruction,
        TokenCpiInstruction,
    };
    fn instruction(operation:&str) -> DirectTokenInstruction {
        DirectTokenInstruction{
            instruction_index:0,program_address_from_lookup:false,
            account_addresses_from_lookup:false,
            decoded:TokenCpiInstruction{
                parent_instruction_index:0,inner_instruction_index:0,
                program_id:"TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA".into(),
                operation:operation.into(),source_account:None,
                destination_account:None,mint:None,authority:None,delegate:None,
                amount_raw:None,decimals:None,authority_type:None,new_authority:None,
            },
        }
    }
    fn analysis() -> DirectTokenAnalysis {
        DirectTokenAnalysis {
            recognized:vec![],opaque:vec![],
            total_token_program_instructions:0,limitation:"test",
        }
    }
    #[test]
    fn original_wire_direct_movements_and_authority_ops_raise_distinct_warnings(){
        let mut a=analysis();
        a.recognized=vec![instruction("transfer_checked"),instruction("approve_checked")];
        let codes=wire_direct_token_findings(&a)
            .into_iter().map(|x|x.0).collect::<Vec<_>>();
        assert_eq!(codes,vec!["WIRE_TOKEN_DIRECT_MOVEMENT","WIRE_TOKEN_DIRECT_AUTHORITY_RISK"]);
        a.recognized=vec![instruction("transfer")];
        let codes=wire_direct_token_findings(&a)
            .into_iter().map(|x|x.0).collect::<Vec<_>>();
        assert_eq!(codes,vec!["WIRE_TOKEN_DIRECT_MOVEMENT","WIRE_TOKEN_DIRECT_UNCHECKED_TRANSFER"]);
    }
    #[test]
    fn opaque_direct_and_lookup_dependent_programs_cannot_be_authorized(){
        let mut a=analysis();
        a.recognized=vec![instruction("revoke")];
        a.recognized[0].account_addresses_from_lookup=true;
        a.opaque=vec![OpaqueDirectTokenInstruction{
            instruction_index:1,program_id:"token2022".into(),
            program_address_from_lookup:true,
            token_2022_extension:true,extension_hint:None,
        }];
        let codes=wire_direct_token_findings(&a)
            .into_iter().map(|x|x.0).collect::<Vec<_>>();
        assert_eq!(codes,vec![
            "WIRE_TOKEN_DIRECT_AUTHORITY_RISK",
            "WIRE_TOKEN_DIRECT_OPAQUE",
            "WIRE_TOKEN_DIRECT_ALT_UNTRUSTED",
        ]);
        assert!(wire_direct_token_findings(&analysis()).is_empty());
    }
    #[test]
    fn signed_lamport_only_intent_does_not_cap_direct_token_moves_or_approvals() {
        let mut a=analysis();
        assert!(!signed_sol_intent_cannot_cap_direct_tokens(&a));
        a.recognized=vec![instruction("transfer_checked")];
        assert!(signed_sol_intent_cannot_cap_direct_tokens(&a));
        a.recognized=vec![instruction("approve")];
        assert!(signed_sol_intent_cannot_cap_direct_tokens(&a));
        a.recognized.clear();
        a.opaque=vec![OpaqueDirectTokenInstruction{
            instruction_index:0,program_id:"opaque".into(),
            program_address_from_lookup:false,token_2022_extension:true,
            extension_hint:None,
        }];
        assert!(signed_sol_intent_cannot_cap_direct_tokens(&a));
    }
}

#[cfg(test)]
mod effect_graph_reporting_tests {
    use super::*;
    use hguet_rpc::EffectGraph;
    fn graph() -> EffectGraph {
        EffectGraph{
            version:1,simulation_status:"rpc_succeeded".into(),
            nodes:vec![],edges:vec![],sources:vec![],
            evidence_gaps:vec!["full_execution_and_gross_spending_unverified"],
            alerts:vec![],
            execution_proven:false,spend_limit_enforced:false,
            security_coverage:"partial_untrusted_rpc",
            limitation:"test fixture",
        }
    }
    #[test]
    fn graph_warning_codes_preserve_cpi_and_cross_slot_uncertainty() {
        let mut g=graph();
        g.alerts.extend([
            "GRAPH_CPI_NET_ATTRIBUTION_UNPROVEN",
            "GRAPH_ACCOUNT_MINT_DISAGREEMENT",
        ]);
        g.evidence_gaps.push("opaque_token_cpi_semantics_unresolved");
        let codes=effect_graph_findings(&g).into_iter().map(|f|f.0)
            .collect::<Vec<_>>();
        assert_eq!(codes,vec![
            "RPC_EFFECT_GRAPH_CPI_UNATTRIBUTED",
            "RPC_EFFECT_GRAPH_IDENTITY_CONFLICT",
            "RPC_EFFECT_GRAPH_OPAQUE_CPI",
        ]);
    }
    #[test]
    fn no_graph_warning_claims_authorization_or_execution() {
        let g=graph();
        assert!(effect_graph_findings(&g).is_empty());
        let mut failed=graph();
        failed.simulation_status="rpc_failed".into();
        failed.alerts.push("GRAPH_CPI_NET_ATTRIBUTION_UNPROVEN");
        failed.evidence_gaps.push("opaque_token_cpi_semantics_unresolved");
        assert!(effect_graph_findings(&failed).is_empty());
        assert!(!failed.execution_proven);
        assert!(!failed.spend_limit_enforced);
    }
}

#[cfg(test)]
mod token_account_snapshot_tests {
    use super::*;
    use hguet_rpc::{
        TokenAccountRpcSnapshot,TokenAccountObservation,
        Token2022AccountState,TokenAccountExtension,
    };
    fn sample() -> TokenAccountRpcSnapshot {
        TokenAccountRpcSnapshot {
            context_slot:600,simulation_slot:500,atomic_with_simulation:false,
            accounts:vec![TokenAccountObservation {
                address:"token-account".into(),
                simulation_reported_mint:"mint".into(),
                status:"token_2022".into(),
                state:Some(Token2022AccountState {
                    token_account:"token-account".into(),
                    mint:"other-mint".into(),
                    token_authority:"new-authority".into(),
                    amount_raw:"400".into(),
                    delegate:Some("delegate".into()),
                    delegated_amount_raw:"50".into(),
                    account_state:"frozen",
                    native_reserve_lamports:None,
                    close_authority:Some("closer".into()),
                    transfer_fee_withheld_raw:Some("5".into()),
                    requires_incoming_memo:Some(true),
                    cpi_guard_locked:Some(true),
                    transfer_hook_transferring:Some(true),
                    immutable_owner:false,non_transferable_account:true,
                    confidential_extension_present:true,
                    opaque_extension_count:1,unknown_extension_count:1,
                    extensions:vec![TokenAccountExtension {
                        type_id:65000,family:"unknown_extension",
                        payload_bytes:3,layout_checked:false,
                    }],
                    limitation:"single-provider".into(),
                }),
                mint_matches_simulation_report:Some(false),
                authority_matches_simulation_report:Some(false),
                matching_mint_state_observed:false,
            }],
            limitation:"non-atomic".into(),
        }
    }
    #[test]
    fn suspicious_token_account_attributes_create_high_risk_advisory_findings(){
        let codes=token_account_snapshot_findings(&sample())
            .into_iter().map(|(code,_,_)|code).collect::<Vec<_>>();
        for expected in [
            "RPC_TOKEN_ACCOUNT_NON_ATOMIC",
            "RPC_TOKEN_ACCOUNT_MINT_MISMATCH",
            "RPC_TOKEN_ACCOUNT_AUTHORITY_MISMATCH",
            "RPC_TOKEN_ACCOUNT_MINT_STATE_UNCONFIRMED",
            "RPC_TOKEN_ACCOUNT_FROZEN","RPC_TOKEN_ACCOUNT_DELEGATE",
            "RPC_TOKEN_ACCOUNT_CLOSE_AUTHORITY",
            "RPC_TOKEN_ACCOUNT_WITHHELD_FEES",
            "RPC_TOKEN_ACCOUNT_MEMO_REQUIRED",
            "RPC_TOKEN_ACCOUNT_CPI_GUARD",
            "RPC_TOKEN_ACCOUNT_HOOK_TRANSFERRING",
            "RPC_TOKEN_ACCOUNT_NON_TRANSFERABLE",
            "RPC_TOKEN_ACCOUNT_CONFIDENTIAL",
            "RPC_TOKEN_ACCOUNT_OPAQUE_EXTENSION",
        ] {
            assert!(codes.contains(&expected),"missing {expected}");
        }
        assert!(!codes.contains(&"ALLOW"));
    }
    #[test]
    fn unknown_token_account_program_is_not_silently_trusted(){
        let mut snap=sample();
        snap.accounts[0].status="not_token_2022".into();
        snap.accounts[0].state=None;
        snap.accounts[0].mint_matches_simulation_report=None;
        snap.accounts[0].authority_matches_simulation_report=None;
        let codes=token_account_snapshot_findings(&snap)
            .into_iter().map(|(code,_,_)|code).collect::<Vec<_>>();
        assert_eq!(codes,vec![
            "RPC_TOKEN_ACCOUNT_NON_ATOMIC",
            "RPC_TOKEN_ACCOUNT_PROGRAM_UNVERIFIED",
        ]);
    }
    #[test]
    fn missing_account_does_not_get_decoded_as_zero_or_trusted(){
        let mut snap=sample();
        snap.accounts[0].status="missing".into();
        snap.accounts[0].state=None;
        snap.accounts[0].mint_matches_simulation_report=None;
        snap.accounts[0].authority_matches_simulation_report=None;
        let codes=token_account_snapshot_findings(&snap).into_iter()
            .map(|(code,_,_)|code).collect::<Vec<_>>();
        assert_eq!(codes,vec!["RPC_TOKEN_ACCOUNT_NON_ATOMIC","RPC_TOKEN_ACCOUNT_MISSING"]);
    }
}
#[cfg(test)]
mod mint_snapshot_tests {
    use super::*;
    use hguet_rpc::{MintAccountObservation, MintRpcSnapshot, MintExtension,
        Token2022MintState, MintTransferFeeConfig, MintTransferHook, FeeSchedule};

    fn sample() -> MintRpcSnapshot {
        let schedule=FeeSchedule{epoch:"1".into(),maximum_fee_raw:"5".into(),basis_points:10};
        MintRpcSnapshot {
            context_slot:501,simulation_slot:500,atomic_with_simulation:false,
            accounts:vec![MintAccountObservation {
                address:"mint".into(),status:"token_2022".into(),
                state:Some(Token2022MintState {
                    mint_address:"mint".into(),supply_raw:"1000".into(),
                    decimals:9,extensions:vec![
                        MintExtension{type_id:1,family:"transfer_fee_config",
                            payload_bytes:108,layout_checked:true},
                        MintExtension{type_id:4,family:"confidential_transfer_mint",
                            payload_bytes:65,layout_checked:false},
                    ],
                    fee_config:Some(MintTransferFeeConfig {
                        config_authority:None,withdraw_withheld_authority:None,
                        withheld_raw:"0".into(),older:schedule.clone(),newer:schedule,
                    }),
                    hook:Some(MintTransferHook{
                        update_authority:None,program_id:Some("hook".into()),
                    }),
                    permanent_delegate:Some("delegate".into()),
                    unknown_extension_count:1,confidential_extension_present:true,
                    limitations:"single-provider".into(),
                }),
            }],
            limitation:"non-atomic".into(),
        }
    }
    #[test]
    fn every_active_mint_risk_is_advisory_and_non_atomic() {
        let findings=mint_snapshot_findings(&sample());
        let codes=findings.iter().map(|(code,_,_)|*code).collect::<Vec<_>>();
        assert!(codes.contains(&"RPC_MINT_STATE_NON_ATOMIC"));
        assert!(codes.contains(&"RPC_MINT_TRANSFER_FEE_CONFIG"));
        assert!(codes.contains(&"RPC_MINT_TRANSFER_HOOK_ACTIVE"));
        assert!(codes.contains(&"RPC_MINT_PERMANENT_DELEGATE_ACTIVE"));
        assert!(codes.contains(&"RPC_MINT_CONFIDENTIAL_EXTENSION"));
        assert!(codes.contains(&"RPC_MINT_UNKNOWN_EXTENSION"));
        assert!(codes.contains(&"RPC_MINT_OPAQUE_EXTENSION_STATE"));
        assert!(!codes.contains(&"ALLOW"));
    }
    #[test]
    fn missing_mints_never_imply_no_active_risk() {
        let mut sample=sample();
        sample.accounts=vec![MintAccountObservation {
            address:"missing".into(),status:"missing".into(),state:None,
        }];
        let codes=mint_snapshot_findings(&sample)
            .into_iter().map(|(code,_,_)|code).collect::<Vec<_>>();
        assert_eq!(codes,vec!["RPC_MINT_STATE_NON_ATOMIC","RPC_MINT_STATE_MISSING"]);
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
        let codes=token_2022_extension_findings("rpc_succeeded",&items,&[])
            .into_iter().map(|v|v.0).collect::<Vec<_>>();
        assert_eq!(codes,vec![
            "RPC_TOKEN_2022_TRANSFER_FEE","RPC_TOKEN_2022_TRANSFER_HOOK",
            "RPC_TOKEN_2022_PERMANENT_DELEGATE","RPC_TOKEN_2022_CONFIDENTIAL_EFFECTS"]);
    }
    #[test]
    fn failures_and_missing_extensions_do_not_invent_warnings() {
        assert!(token_2022_extension_findings("rpc_failed",
            &[observation("transfer_fee")],&[]).is_empty());
        assert!(token_2022_extension_findings("rpc_unavailable",
            &[observation("transfer_hook")],&[]).is_empty());
        assert!(token_2022_extension_findings("rpc_succeeded",
            &[observation("unknown_extension")],&[]).is_empty());
        assert!(token_2022_extension_findings("rpc_succeeded",&[],&[]).is_empty());
    }
    fn set_authority(program_id: &str, authority_type:u8) -> hguet_rpc::TokenCpiInstruction {
        hguet_rpc::TokenCpiInstruction {
            parent_instruction_index:0,inner_instruction_index:0,
            program_id:program_id.into(),operation:"set_authority".into(),
            source_account:None,destination_account:None,mint:None,
            authority:None,delegate:None,amount_raw:None,decimals:None,
            authority_type:Some(authority_type),new_authority:None,
        }
    }
    #[test]
    fn set_authority_rotations_of_token_2022_extensions_raise_specific_risks() {
        let token2022="TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
        let codes=token_2022_extension_findings("rpc_succeeded",&[],&[
            set_authority(token2022,4),set_authority(token2022,8),
            set_authority(token2022,10),set_authority(token2022,11),
        ]).into_iter().map(|v|v.0).collect::<Vec<_>>();
        assert_eq!(codes,vec!["RPC_TOKEN_2022_TRANSFER_FEE",
            "RPC_TOKEN_2022_TRANSFER_HOOK",
            "RPC_TOKEN_2022_PERMANENT_DELEGATE",
            "RPC_TOKEN_2022_CONFIDENTIAL_EFFECTS"]);
        let legacy="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        assert!(token_2022_extension_findings("rpc_succeeded",&[],
            &[set_authority(legacy,8)]).is_empty());
        assert!(token_2022_extension_findings("rpc_failed",&[],
            &[set_authority(token2022,8)]).is_empty());
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
            token_spend_limits:None,
            token_source_limits:None,
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
