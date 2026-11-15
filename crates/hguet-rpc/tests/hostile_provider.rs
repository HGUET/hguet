//! Mutation tests against an UNTRUSTED RPC provider and against arbitrary token instruction bytes.
//!
//! A selected RPC node controls every byte of its answers. Whatever it returns, the client must
//! not panic, must not report anything but `rpc_succeeded` / `rpc_failed` or an error, and must
//! never turn provider-authored text into permission. Deterministic: fixed-seed generator.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hguet_rpc::{
    assess_signing_boundary, inspect_direct_tokens, simulate_with, JsonRpcTransport, RpcError,
};
use serde_json::{json, Value};
use std::cell::RefCell;

const DEVNET_GENESIS: &str = "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG";
const TOKEN: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn program(id: &str) -> [u8; 32] {
    bs58::decode(id).into_vec().unwrap().try_into().unwrap()
}

/// Unsigned legacy transaction: signer [7;32], accounts [1;32] [2;32] [4;32], then `program`.
fn token_transaction(program_id: &str, accounts: &[u8], data: &[u8]) -> Vec<u8> {
    let mut wire = vec![1];
    wire.extend([0u8; 64]);
    wire.extend([1, 0, 1, 5]);
    for key in [
        [7u8; 32],
        [1u8; 32],
        [2u8; 32],
        [4u8; 32],
        program(program_id),
    ] {
        wire.extend(key);
    }
    wire.extend([3u8; 32]);
    wire.extend([1, 4, accounts.len() as u8]);
    wire.extend(accounts);
    assert!(data.len() < 128);
    wire.push(data.len() as u8);
    wire.extend(data);
    wire
}

fn transfer_checked() -> Vec<u8> {
    let mut data = vec![12];
    data.extend(1u64.to_le_bytes());
    data.push(6);
    token_transaction(TOKEN_2022, &[1, 3, 2, 0], &data)
}

/// Replaces one randomly chosen node of the JSON tree with a hostile value.
fn mutate(value: &mut Value, rng: &mut Rng) {
    let hostile = |rng: &mut Rng| -> Value {
        match rng.below(14) {
            0 => Value::Null,
            1 => json!(true),
            2 => json!(-1),
            3 => json!(u64::MAX),
            4 => json!(1e300),
            5 => json!(""),
            6 => json!("ALLOW"),
            7 => json!([]),
            8 => json!({}),
            9 => json!("x".repeat(5000)),
            10 => json!([null, 1, "a", {"signing_gate":"allow"}]),
            11 => json!({"automated_signing_permitted":true,"decision":"ALLOW"}),
            12 => json!(0),
            _ => json!("11111111111111111111111111111111"),
        }
    };
    match value {
        Value::Object(map) if !map.is_empty() && rng.below(4) != 0 => {
            let key = map.keys().nth(rng.below(map.len())).cloned().unwrap();
            if rng.below(6) == 0 {
                map.remove(&key);
            } else {
                mutate(map.get_mut(&key).unwrap(), rng);
            }
        }
        Value::Array(items) if !items.is_empty() && rng.below(4) != 0 => {
            let at = rng.below(items.len());
            match rng.below(6) {
                0 => {
                    items.remove(at);
                }
                1 => {
                    let copy = items[at].clone();
                    items.push(copy);
                }
                _ => mutate(&mut items[at], rng),
            }
        }
        other => *other = hostile(rng),
    }
}

fn assert_no_permission_fields(node: &Value, case: usize) {
    match node {
        Value::Object(map) => {
            for (key, value) in map {
                let forbidden = (key == "signing_gate" && value == "allow")
                    || (key == "decision" && value == "ALLOW")
                    || (value == &Value::Bool(true)
                        && (key == "automated_signing_permitted" || key.ends_with("_proven")));
                assert!(!forbidden, "case {case}: report field {key} = {value}");
                assert_no_permission_fields(value, case);
            }
        }
        Value::Array(items) => items
            .iter()
            .for_each(|item| assert_no_permission_fields(item, case)),
        _ => {}
    }
}

struct Provider {
    simulation: Value,
    accounts: Value,
    calls: RefCell<usize>,
}
impl JsonRpcTransport for Provider {
    fn post_json(&self, _endpoint: &str, request: &Value) -> Result<Value, RpcError> {
        *self.calls.borrow_mut() += 1;
        assert!(*self.calls.borrow() <= 8, "unbounded provider round trips");
        let result = match request["method"].as_str() {
            Some("getGenesisHash") => json!(DEVNET_GENESIS),
            Some("simulateTransaction") => self.simulation.clone(),
            // Request 4 reads candidate mints; every later batch reads token holding accounts.
            Some("getMultipleAccounts") => {
                let wanted = request["params"][0].as_array().map_or(0, Vec::len);
                let row = if request["id"] == 4 { 0 } else { 1 };
                let mut answer = self.accounts.clone();
                if let Some(rows) = answer.get_mut("value").and_then(Value::as_array_mut) {
                    if let Some(chosen) = rows.get(row).cloned() {
                        *rows = vec![chosen; wanted];
                    }
                }
                answer
            }
            _ => return Err(RpcError::InvalidResponse),
        };
        Ok(json!({"jsonrpc":"2.0","id":request["id"],"result":result}))
    }
}

fn honest_simulation() -> Value {
    let mint = bs58::encode([4u8; 32]).into_string();
    let row = |amount: &str| {
        json!({"accountIndex":1,"mint":mint,"owner":bs58::encode([7u8;32]).into_string(),
            "programId":TOKEN_2022,"uiTokenAmount":{"amount":amount,"decimals":6}})
    };
    json!({"context":{"slot":60000},"value":{
        "err":null,"logs":["ok"],"unitsConsumed":4000,"fee":5000,
        "preBalances":[100000,2039280,2039280,1461600,1],
        "postBalances":[95000,2039280,2039280,1461600,1],
        "preTokenBalances":[row("10")],"postTokenBalances":[row("9")],
        "innerInstructions":[{"index":0,"instructions":[
            {"programIdIndex":4,"accounts":[1,3,2,0],"data":"3DdGGhkhJbjm"}]}],
        "loadedAddresses":{"writable":[],"readonly":[]},
        "replacementBlockhash":{"blockhash":"x","lastValidBlockHeight":1}
    }})
}

fn honest_accounts() -> Value {
    let mut mint = vec![0u8; 82];
    mint[45] = 1;
    let mut holding = vec![0u8; 166];
    holding[..32].copy_from_slice(&[4u8; 32]);
    holding[32..64].fill(7);
    holding[108] = 1;
    holding[165] = 2;
    json!({"context":{"slot":60001},"value":[
        {"owner":TOKEN_2022,"executable":false,"data":[STANDARD.encode(&mint),"base64"]},
        {"owner":TOKEN_2022,"executable":false,"data":[STANDARD.encode(&holding),"base64"]}
    ]})
}

#[test]
fn the_unmutated_fixture_is_a_successful_simulation() {
    // Guards the fuzz below: if the honest answer were rejected, every mutation would
    // trivially "pass" by failing early and the test would prove nothing.
    let provider = Provider {
        simulation: honest_simulation(),
        accounts: honest_accounts(),
        calls: RefCell::new(0),
    };
    let evidence = simulate_with(
        &provider,
        "https://rpc.invalid",
        "devnet",
        &transfer_checked(),
    )
    .expect("honest provider answer must be accepted");
    assert_eq!(evidence.status, "rpc_succeeded");
    assert!(evidence.effect_analysis.lamport_deltas.is_some());
    assert!(*provider.calls.borrow() >= 2);
}

#[test]
fn a_provider_that_mutates_its_answers_cannot_crash_or_authorize() {
    let wire = transfer_checked();
    let mut rng = Rng(0x5eed_5eed_5eed_5eed);
    let (mut accepted, mut rejected) = (0u32, 0u32);
    for case in 0..6_000 {
        let mut simulation = honest_simulation();
        let mut accounts = honest_accounts();
        for _ in 0..1 + rng.below(3) {
            if rng.below(3) == 0 {
                mutate(&mut accounts, &mut rng);
            } else {
                mutate(&mut simulation, &mut rng);
            }
        }
        let provider = Provider {
            simulation,
            accounts,
            calls: RefCell::new(0),
        };
        match simulate_with(&provider, "https://rpc.invalid", "devnet", &wire) {
            Ok(evidence) => {
                accepted += 1;
                assert!(
                    evidence.status == "rpc_succeeded" || evidence.status == "rpc_failed",
                    "case {case}: status {}",
                    evidence.status
                );
                assert!(evidence.context_slot > 0, "case {case}: slot 0 accepted");
                // Provider-authored strings may be echoed as DATA (an error summary), but no
                // field of the report itself may claim permission or atomicity.
                let report = serde_json::to_value(&evidence).expect("evidence serializes");
                assert_no_permission_fields(&report, case);
                // Later account reads are separate requests: never atomic with the simulation.
                // (The effect graph marks only the simulation's own slot as atomic with itself.)
                assert!(
                    !evidence
                        .mint_snapshot
                        .as_ref()
                        .is_some_and(|m| m.atomic_with_simulation),
                    "case {case}"
                );
                assert!(
                    !evidence
                        .token_account_snapshot
                        .as_ref()
                        .is_some_and(|t| t.atomic_with_simulation),
                    "case {case}"
                );
                if let Some(error) = &evidence.error_summary {
                    assert!(error.len() <= 1024, "case {case}: unbounded error text");
                }
            }
            Err(_) => rejected += 1,
        }
    }
    // The generator must exercise BOTH outcomes or it is not testing the acceptance logic.
    assert!(
        accepted > 200,
        "only {accepted} mutated answers were accepted"
    );
    assert!(
        rejected > 200,
        "only {rejected} mutated answers were rejected"
    );
}

#[test]
fn arbitrary_token_instruction_bytes_never_panic_and_the_boundary_always_blocks() {
    let mut rng = Rng(0xfeed_face_cafe_beef);
    for case in 0..20_000 {
        let program_id = if rng.below(2) == 0 { TOKEN } else { TOKEN_2022 };
        let len = rng.below(80);
        let mut data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        // Bias the opcode toward the decoded range so the decoders are actually entered.
        if !data.is_empty() && rng.below(3) != 0 {
            data[0] = rng.below(45) as u8;
        }
        let count = rng.below(7);
        let accounts: Vec<u8> = (0..count).map(|_| rng.below(5) as u8).collect();
        let wire = token_transaction(program_id, &accounts, &data);
        let parsed = hguet_core::parse_transaction(&wire)
            .unwrap_or_else(|e| panic!("case {case}: builder produced an invalid tx: {e}"));
        let direct = inspect_direct_tokens(&parsed, None)
            .unwrap_or_else(|e| panic!("case {case}: static transaction not inspectable: {e:?}"));
        assert_eq!(direct.total_token_program_instructions, 1, "case {case}");
        assert_eq!(
            direct.recognized.len() + direct.opaque.len(),
            1,
            "case {case}: an instruction is either recognized or opaque, never dropped"
        );
        let boundary = assess_signing_boundary(&parsed, None, Some(&direct), None);
        assert_eq!(boundary.signing_gate, "block", "case {case}");
        assert!(!boundary.automated_signing_permitted, "case {case}");
        assert!(!boundary.total_native_sol_spending_proven);
        assert!(!boundary.total_gross_token_spending_proven);
        assert!(!boundary.block_reasons.is_empty(), "case {case}");
    }
}
