//! Deterministic property and mutation tests for the offline parser and the signed limits.
//!
//! No external fuzzing dependency: a fixed-seed xorshift generator makes every run identical, so a
//! failure is reproducible from the printed case number. These tests state properties that must
//! hold for ANY input, not expected outputs for hand-picked ones:
//!
//! * arbitrary and mutated bytes never panic, and every accepted transaction is self-consistent;
//! * a declared amount never shrinks when an instruction is padded with trailing bytes;
//! * the declared SOL total is exactly the sum of the lamport movements that were built;
//! * a signed token cap is accepted if and only if the declared debits fit inside it;
//! * no single-bit change to a signed intent or to the bound transaction survives verification.
use crate::{
    parse_transaction, review_declared_source_limits, review_declared_token_limits, verify_intent,
    PaymentIntentPayload, SignedPaymentIntent, TokenSourceLimit, TokenSpendLimit,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};

const TOKEN_LEGACY: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
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
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

fn shortvec(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            out.push(byte);
            return out;
        }
        out.push(byte | 0x80);
    }
}

fn key(n: u8) -> [u8; 32] {
    [n; 32]
}
fn b58(k: &[u8; 32]) -> String {
    bs58::encode(k).into_string()
}
fn program(id: &str) -> [u8; 32] {
    bs58::decode(id).into_vec().unwrap().try_into().unwrap()
}

type Ix = (u8, Vec<u8>, Vec<u8>);

/// Unsigned legacy transaction: one required signer (key 0), the rest plain accounts.
fn legacy(keys: &[[u8; 32]], instructions: &[Ix]) -> Vec<u8> {
    let mut wire = vec![1];
    wire.extend([0u8; 64]);
    wire.extend([1, 0, 1]);
    wire.extend(shortvec(keys.len()));
    for k in keys {
        wire.extend(k);
    }
    wire.extend([3u8; 32]);
    wire.extend(shortvec(instructions.len()));
    for (program, accounts, data) in instructions {
        wire.push(*program);
        wire.extend(shortvec(accounts.len()));
        wire.extend(accounts);
        wire.extend(shortvec(data.len()));
        wire.extend(data);
    }
    wire
}

fn v0_with_lookup() -> Vec<u8> {
    let mut wire = legacy(
        &[key(7), key(2), [0u8; 32]],
        &[(2, vec![0, 3], system_transfer(10))],
    );
    wire.insert(65, 0x80);
    wire.push(1);
    wire.extend([11u8; 32]);
    wire.extend([1, 5, 0]);
    wire
}

fn v1() -> Vec<u8> {
    let mut message = vec![0x81, 1, 0, 1];
    message.extend(0b1111_u32.to_le_bytes());
    message.extend([4u8; 32]);
    message.extend([1, 3]);
    message.extend(key(9));
    message.extend(key(8));
    message.extend([0u8; 32]);
    message.extend(99u64.to_le_bytes());
    message.extend(200_000u32.to_le_bytes());
    message.extend(65_536u32.to_le_bytes());
    message.extend([2, 2, 12, 0, 0, 1]);
    message.extend(system_transfer(100));
    message.extend([0u8; 64]);
    message
}

fn system_transfer(lamports: u64) -> Vec<u8> {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend(lamports.to_le_bytes());
    data
}

/// (data, account roles, destination key) for each System form that names an amount.
/// Accounts: 0 = signer key(7), 1 = key(2), 2 = key(5), 3 = System program.
fn system_movement(form: usize, lamports: u64) -> (Vec<u8>, Vec<u8>) {
    match form {
        0 => (system_transfer(lamports), vec![0, 1]),
        1 => {
            let mut data = 0u32.to_le_bytes().to_vec();
            data.extend(lamports.to_le_bytes());
            data.extend(165u64.to_le_bytes());
            data.extend([9u8; 32]);
            (data, vec![0, 1])
        }
        2 => {
            let mut data = 3u32.to_le_bytes().to_vec();
            data.extend([7u8; 32]);
            data.extend(3u64.to_le_bytes());
            data.extend(b"abc");
            data.extend(lamports.to_le_bytes());
            data.extend(165u64.to_le_bytes());
            data.extend([9u8; 32]);
            (data, vec![0, 1])
        }
        3 => {
            let mut data = 5u32.to_le_bytes().to_vec();
            data.extend(lamports.to_le_bytes());
            (data, vec![1, 2, 0])
        }
        _ => {
            let mut data = 11u32.to_le_bytes().to_vec();
            data.extend(lamports.to_le_bytes());
            data.extend(3u64.to_le_bytes());
            data.extend(b"abc");
            data.extend([9u8; 32]);
            (data, vec![1, 0, 2])
        }
    }
}

fn system_keys() -> Vec<[u8; 32]> {
    vec![key(7), key(2), key(5), [0u8; 32]]
}

/// Every accepted transaction must describe itself consistently.
fn assert_consistent(raw: &[u8], case: &str) {
    let Ok(p) = parse_transaction(raw) else {
        return;
    };
    assert_eq!(p.transaction_bytes, raw.len(), "{case}");
    assert_eq!(
        p.static_account_keys.len(),
        p.static_account_count,
        "{case}"
    );
    assert_eq!(
        p.compiled_top_level_instructions.len(),
        p.instruction_count,
        "{case}"
    );
    assert_eq!(p.program_ids.len(), p.instruction_count, "{case}");
    assert!(
        p.required_signatures >= 1 && p.required_signatures <= p.static_account_count,
        "{case}"
    );
    assert_eq!(
        p.total_address_count,
        p.static_account_count + p.unresolved_lookup_addresses,
        "{case}"
    );
    assert!(p.message_sha256.len() == 64 && p.transaction_sha256.len() == 64);
    let total: u128 = p
        .system_transfers
        .iter()
        .map(|t| t.lamports.parse::<u128>().expect("decimal lamports"))
        .sum();
    assert_eq!(
        p.declared_system_transfer_lamports,
        total.to_string(),
        "{case}: declared total must equal the listed movements"
    );
    for ix in &p.compiled_top_level_instructions {
        assert!(ix.program_index < p.total_address_count, "{case}");
        assert!(ix
            .account_indices
            .iter()
            .all(|n| *n < p.total_address_count));
    }
    let mut unique = std::collections::HashSet::new();
    assert!(
        p.static_account_keys.iter().all(|k| unique.insert(k)),
        "{case}: duplicate static key accepted"
    );
    // Whatever was parsed, the signed-limit reviews must not panic on it either.
    let _ = review_declared_token_limits(&p, &[]);
    let _ = review_declared_source_limits(&p, &[]);
    let _ = crate::review_account_control(&p, "fuzz");
}

#[test]
fn arbitrary_bytes_never_panic_and_accepted_inputs_are_consistent() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for case in 0..30_000 {
        let len = rng.below(1400);
        let mut raw = rng.bytes(len);
        // Steer a share of the inputs toward each wire format's entry conditions.
        match case % 4 {
            1 if !raw.is_empty() => raw[0] = 1,
            2 if !raw.is_empty() => raw[0] = 0x81,
            3 if raw.len() > 66 => {
                raw[0] = 1;
                raw[65] = 0x80;
            }
            _ => {}
        }
        assert_consistent(&raw, &format!("random case {case}"));
    }
}

#[test]
fn mutated_valid_transactions_never_panic_and_stay_consistent() {
    let (create, create_accounts) = system_movement(1, 500);
    let seeds = [
        legacy(
            &[key(7), key(2), [0u8; 32]],
            &[(2, vec![0, 1], system_transfer(75))],
        ),
        legacy(&system_keys(), &[(3, create_accounts, create)]),
        legacy(
            &[key(7), key(1), key(2), key(4), program(TOKEN_LEGACY)],
            &[(4, vec![1, 3, 2, 0], token_debit(12, 50, 0))],
        ),
        v0_with_lookup(),
        v1(),
    ];
    for seed in &seeds {
        assert!(parse_transaction(seed).is_ok(), "seed must be valid");
    }
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for case in 0..40_000 {
        let mut raw = seeds[case % seeds.len()].clone();
        for _ in 0..1 + rng.below(4) {
            match rng.below(5) {
                0 => {
                    let at = rng.below(raw.len());
                    raw[at] ^= 1 << rng.below(8);
                }
                1 => {
                    let at = rng.below(raw.len());
                    raw[at] = rng.next() as u8;
                }
                2 => {
                    let keep = rng.below(raw.len() + 1);
                    raw.truncate(keep);
                }
                3 => {
                    let at = rng.below(raw.len() + 1);
                    raw.insert(at, rng.next() as u8);
                }
                _ => {
                    let extra = 1 + rng.below(8);
                    raw.extend(rng.bytes(extra));
                }
            }
            if raw.is_empty() {
                break;
            }
        }
        assert_consistent(&raw, &format!("mutation case {case}"));
    }
}

#[test]
fn bytes_appended_to_a_valid_transaction_are_always_rejected() {
    let mut rng = Rng(42);
    for seed in [
        legacy(
            &[key(7), key(2), [0u8; 32]],
            &[(2, vec![0, 1], system_transfer(75))],
        ),
        v0_with_lookup(),
        v1(),
    ] {
        for _ in 0..200 {
            let mut raw = seed.clone();
            let extra = 1 + rng.below(16);
            raw.extend(rng.bytes(extra));
            assert!(
                parse_transaction(&raw).is_err(),
                "trailing transaction bytes accepted"
            );
        }
    }
}

#[test]
fn declared_sol_total_is_exactly_the_sum_of_built_movements_padded_or_not() {
    let mut rng = Rng(7);
    for case in 0..3_000 {
        let count = 1 + rng.below(6);
        let mut instructions = Vec::new();
        let mut expected: u128 = 0;
        for _ in 0..count {
            let lamports = match rng.below(4) {
                0 => u64::MAX,
                1 => 0,
                _ => rng.next() >> rng.below(64),
            };
            let (mut data, accounts) = system_movement(rng.below(5), lamports);
            // Padding must never remove a declared amount.
            let pad = rng.below(9);
            data.extend(rng.bytes(pad));
            expected += u128::from(lamports);
            instructions.push((3, accounts, data));
        }
        let p = parse_transaction(&legacy(&system_keys(), &instructions))
            .unwrap_or_else(|e| panic!("case {case}: {e}"));
        assert_eq!(
            p.declared_system_transfer_lamports,
            expected.to_string(),
            "case {case}"
        );
        assert_eq!(p.system_transfers.len(), count, "case {case}");
    }
}

/// TransferChecked (12), BurnChecked (15) or Token-2022 TransferCheckedWithFee (26).
fn token_debit(opcode: u8, amount: u64, pad: usize) -> Vec<u8> {
    let mut data = if opcode == 26 {
        let mut d = vec![26, 1];
        d.extend(amount.to_le_bytes());
        d.push(6);
        d.extend(1u64.to_le_bytes());
        d
    } else {
        let mut d = vec![opcode];
        d.extend(amount.to_le_bytes());
        d.push(6);
        d
    };
    data.extend(vec![0xAA; pad]);
    data
}

#[test]
fn a_signed_mint_cap_is_accepted_exactly_when_the_declared_debits_fit() {
    // keys: 0 signer/authority, 1 source, 2 destination, 3 mint, 4 Token, 5 Token-2022
    let keys = [
        key(7),
        key(1),
        key(2),
        key(4),
        program(TOKEN_LEGACY),
        program(TOKEN_2022),
    ];
    let mut rng = Rng(99);
    for case in 0..4_000 {
        let count = 1 + rng.below(5);
        let mut total: u128 = 0;
        let mut instructions = Vec::new();
        for _ in 0..count {
            let amount = rng.next() >> (rng.below(40) + 8);
            total += u128::from(amount);
            let pad = rng.below(4);
            instructions.push(match rng.below(3) {
                0 => (4, vec![1, 3, 2, 0], token_debit(12, amount, pad)),
                1 => (4, vec![1, 3, 0], token_debit(15, amount, pad)),
                _ => (5, vec![1, 3, 2, 0], token_debit(26, amount, pad)),
            });
        }
        let p = parse_transaction(&legacy(&keys, &instructions)).unwrap();
        // A cap chosen just below, at, or above the true total.
        let cap = match rng.below(3) {
            0 => total.saturating_sub(1 + rng.below(1000) as u128),
            1 => total,
            _ => total + rng.below(1000) as u128,
        };
        let Ok(cap64) = u64::try_from(cap) else {
            continue;
        };
        let limits = [TokenSpendLimit {
            mint: b58(&key(4)),
            max_debit_raw: cap64.to_string(),
        }];
        let review = review_declared_token_limits(&p, &limits);
        assert_eq!(
            review.is_ok(),
            total <= cap,
            "case {case}: total {total} cap {cap}"
        );
        if let Ok(review) = review {
            assert_eq!(review.debits[0].declared_raw, total.to_string());
            assert!(!review.total_spending_proven);
        }
        // The same debits against a cap for a DIFFERENT mint are never accepted.
        let other = [TokenSpendLimit {
            mint: b58(&key(200)),
            max_debit_raw: u64::MAX.to_string(),
        }];
        assert!(
            review_declared_token_limits(&p, &other).is_err(),
            "case {case}"
        );
        // Source-scoped caps obey the same rule for the one source account used.
        let source = [TokenSourceLimit {
            mint: b58(&key(4)),
            source_token_account: b58(&key(1)),
            authority: b58(&key(7)),
            max_debit_raw: cap64.to_string(),
        }];
        // One source account debited through BOTH token programs is refused outright:
        // an account belongs to exactly one program, so the declarations conflict.
        let one_program = instructions.iter().all(|ix| ix.0 == instructions[0].0);
        assert_eq!(
            review_declared_source_limits(&p, &source).is_ok(),
            total <= cap && one_program,
            "case {case}: source cap"
        );
    }
}

fn signed_intent(
    signer: &SigningKey,
    message_sha256: &str,
    max_spend: &str,
) -> (SignedPaymentIntent, Vec<u8>) {
    let payload = PaymentIntentPayload {
        schema_version: 1,
        kind: "hguet_payment_intent".into(),
        intent_id: "property".into(),
        network: "devnet".into(),
        message_sha256: message_sha256.into(),
        not_before_unix: 10,
        expires_at_unix: 1_000,
        allowed_program_ids: vec!["11111111111111111111111111111111".into()],
        max_spend_lamports: max_spend.into(),
        token_spend_limits: None,
        token_source_limits: None,
    };
    let bytes = serde_json::to_vec(&payload).unwrap();
    let mut message = b"HGUET-PAYMENT-INTENT\0".to_vec();
    message.extend(&bytes);
    let envelope = SignedPaymentIntent {
        payload_b64: STANDARD.encode(&bytes),
        signer_pubkey_b58: bs58::encode(signer.verifying_key().to_bytes()).into_string(),
        signature_b58: bs58::encode(signer.sign(&message).to_bytes()).into_string(),
    };
    (envelope, bytes)
}

#[test]
fn no_single_bit_change_to_a_signed_intent_or_its_transaction_verifies() {
    let wire = legacy(
        &[key(7), key(2), [0u8; 32]],
        &[(2, vec![0, 1], system_transfer(75))],
    );
    let parsed = parse_transaction(&wire).unwrap();
    let signer = SigningKey::from_bytes(&[23u8; 32]);
    let pin = bs58::encode(signer.verifying_key().to_bytes()).into_string();
    let (envelope, payload) = signed_intent(&signer, &parsed.message_sha256, "75");
    assert!(verify_intent(&envelope, &pin, "devnet", &parsed, 500).is_ok());

    let mut rng = Rng(5);
    // Payload bits.
    for _ in 0..400 {
        let mut changed = payload.clone();
        let at = rng.below(changed.len());
        changed[at] ^= 1 << rng.below(8);
        let mut tampered = envelope.clone();
        tampered.payload_b64 = STANDARD.encode(&changed);
        assert!(verify_intent(&tampered, &pin, "devnet", &parsed, 500).is_err());
    }
    // Signature bits.
    let signature = bs58::decode(&envelope.signature_b58).into_vec().unwrap();
    for _ in 0..200 {
        let mut changed = signature.clone();
        let at = rng.below(changed.len());
        changed[at] ^= 1 << rng.below(8);
        let mut tampered = envelope.clone();
        tampered.signature_b58 = bs58::encode(&changed).into_string();
        assert!(verify_intent(&tampered, &pin, "devnet", &parsed, 500).is_err());
    }
    // Any bit of the MESSAGE (everything after the signature block) breaks the binding.
    for _ in 0..400 {
        let mut changed = wire.clone();
        let at = 65 + rng.below(changed.len() - 65);
        changed[at] ^= 1 << rng.below(8);
        if let Ok(other) = parse_transaction(&changed) {
            assert!(
                verify_intent(&envelope, &pin, "devnet", &other, 500).is_err(),
                "intent verified for a different message (byte {at})"
            );
        }
    }
}

#[test]
fn intent_validity_window_and_sol_cap_boundaries_are_exact() {
    let signer = SigningKey::from_bytes(&[23u8; 32]);
    let pin = bs58::encode(signer.verifying_key().to_bytes()).into_string();
    let mut rng = Rng(11);
    for case in 0..300 {
        let lamports = 1 + (rng.next() >> 20);
        let wire = legacy(
            &[key(7), key(2), [0u8; 32]],
            &[(2, vec![0, 1], system_transfer(lamports))],
        );
        let parsed = parse_transaction(&wire).unwrap();
        for (cap, accepted) in [
            (lamports - 1, false),
            (lamports, true),
            (lamports.saturating_add(1), true),
        ] {
            if cap == 0 {
                continue;
            }
            let (envelope, _) = signed_intent(&signer, &parsed.message_sha256, &cap.to_string());
            assert_eq!(
                verify_intent(&envelope, &pin, "devnet", &parsed, 500).is_ok(),
                accepted,
                "case {case}: {lamports} lamports against cap {cap}"
            );
        }
        // Window is [not_before, expires): 10 inclusive, 1000 exclusive.
        let (envelope, _) = signed_intent(&signer, &parsed.message_sha256, &lamports.to_string());
        for (now, accepted) in [(9, false), (10, true), (999, true), (1_000, false)] {
            assert_eq!(
                verify_intent(&envelope, &pin, "devnet", &parsed, now).is_ok(),
                accepted,
                "case {case}: now={now}"
            );
        }
        // Another network or another pinned key never verifies.
        assert!(verify_intent(&envelope, &pin, "mainnet", &parsed, 500).is_err());
        let other = bs58::encode(
            SigningKey::from_bytes(&[24u8; 32])
                .verifying_key()
                .to_bytes(),
        )
        .into_string();
        assert!(verify_intent(&envelope, &other, "devnet", &parsed, 500).is_err());
    }
}
