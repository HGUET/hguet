//! Deterministic offline Solana wire inspection and independently signed intent verification.
//! This crate DOES NOT simulate execution, resolve ALTs, validate transaction signatures,
//! or authorize spending. Never turn a parsed transaction into ALLOW.
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_TX: usize = 4096;
const MAX_INTENT: usize = 16_384;
const INTENT_DOMAIN: &[u8] = b"HGUET-PAYMENT-INTENT\0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Decision { Allow, Warn, Deny, Unknown }

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub code: String,
    pub severity: String,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecurityVerdict {
    pub schema_version: u32,
    pub kind: String,
    pub decision: Decision,
    pub network: String,
    pub message_sha256: Option<String>,
    pub transaction_sha256: Option<String>,
    pub intent_status: String,
    pub simulation_status: String,
    pub coverage: Vec<String>,
    pub findings: Vec<Finding>,
    pub limitations: Vec<String>,
}

impl SecurityVerdict {
    pub fn unknown(network: &str) -> Self {
        Self {
            schema_version: 1, kind: "security_verdict".into(),
            decision: Decision::Unknown, network: network.into(),
            message_sha256: None, transaction_sha256: None,
            intent_status: "not_checked".into(), simulation_status: "not_performed".into(),
            coverage: vec![], findings: vec![],
            limitations: vec!["No onchain execution simulation or customer-controlled signer enforcement has been performed".into()],
        }
    }
    pub fn finding(&mut self, code: &str, severity: &str, summary: impl Into<String>) {
        self.findings.push(Finding { code: code.into(), severity: severity.into(), summary: summary.into() });
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ParsedTransaction {
    pub wire_format: String,
    pub transaction_bytes: usize,
    pub transaction_sha256: String,
    pub message_sha256: String,
    pub required_signatures: usize,
    pub signature_count: usize,
    pub static_account_count: usize,
    pub total_address_count: usize,
    pub instruction_count: usize,
    pub lookup_table_count: usize,
    pub unresolved_lookup_addresses: usize,
    pub program_ids: Vec<String>,
    pub limitations: Vec<String>,
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    bytes.as_ref().iter().map(|v| format!("{v:02x}")).collect()
}
pub fn sha256_hex(data: &[u8]) -> String { hex(Sha256::digest(data)) }

struct Reader<'a> { input: &'a [u8], at: usize }
impl<'a> Reader<'a> {
    fn new(input: &'a [u8]) -> Self { Self { input, at: 0 } }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.at.checked_add(n).ok_or("integer overflow")?;
        if end > self.input.len() { return Err("truncated transaction".into()); }
        let b = &self.input[self.at..end]; self.at = end; Ok(b)
    }
    fn byte(&mut self) -> Result<u8, String> { Ok(self.take(1)?[0]) }
    fn shortvec(&mut self) -> Result<usize, String> {
        // Solana compact-u16: canonical representation only, maximum 3 bytes.
        let first = self.byte()?; let mut n = (first & 0x7f) as usize;
        if first & 0x80 != 0 {
            let second = self.byte()?;
            if second == 0 { return Err("non-canonical shortvec".into()); }
            n |= ((second & 0x7f) as usize) << 7;
            if second & 0x80 != 0 {
                let third = self.byte()?;
                if third == 0 || third > 3 { return Err("invalid compact-u16".into()); }
                n |= (third as usize) << 14;
                if n < 16384 { return Err("non-canonical shortvec".into()); }
            } else if n < 128 { return Err("non-canonical shortvec".into()); }
        }
        if n > 65535 { return Err("compact-u16 overflow".into()); }
        Ok(n)
    }
}

pub fn parse_transaction(raw: &[u8]) -> Result<ParsedTransaction, String> {
    if raw.is_empty() || raw.len() > MAX_TX { return Err("transaction size outside 1..=4096 bytes".into()); }
    // Solana v1 has a completely different transaction layout (0x81 at byte 0),
    // and MUST NOT be decoded as legacy. Fail closed until the v1 decoder is tested.
    if raw[0] == 0x81 { return Err("unsupported Solana v1 transaction: decoder not implemented".into()); }
    let mut r = Reader::new(raw);
    let signature_count = r.shortvec()?;
    if signature_count == 0 || signature_count > 64 { return Err("invalid signature count".into()); }
    r.take(signature_count.checked_mul(64).ok_or("too many signatures")?)?;
    let message_start = r.at;
    let first = *r.input.get(r.at).ok_or("no message")?;
    let wire_format = if first & 0x80 != 0 {
        let version = r.byte()? & 0x7f;
        if version != 0 { return Err(format!("unsupported Solana message version {version}")); }
        "v0"
    } else { "legacy" };
    let required_signatures = r.byte()? as usize;
    let readonly_signed = r.byte()? as usize;
    let readonly_unsigned = r.byte()? as usize;
    if required_signatures == 0 || required_signatures != signature_count || readonly_signed > required_signatures {
        return Err("invalid message header/signature count".into());
    }
    let keys = r.shortvec()?;
    if keys == 0 || keys > 64 || keys < required_signatures ||
        readonly_unsigned > keys - required_signatures { return Err("invalid static account count/header".into()); }
    let key_data = r.take(keys.checked_mul(32).ok_or("account count overflow")?)?.to_vec();
    r.take(32)?; // recent blockhash
    let instructions = r.shortvec()?;
    if instructions > 64 { return Err("too many compiled instructions".into()); }
    let mut program_indices = Vec::with_capacity(instructions);
    let mut indexes = Vec::new();
    for _ in 0..instructions {
        program_indices.push(r.byte()? as usize);
        let accounts = r.shortvec()?;
        if accounts > 256 { return Err("too many instruction account references".into()); }
        indexes.extend_from_slice(r.take(accounts)?);
        let data_len = r.shortvec()?;
        r.take(data_len)?;
    }
    let mut lookups = 0usize; let mut writable = 0usize; let mut readonly = 0usize;
    if wire_format == "v0" {
        lookups = r.shortvec()?;
        if lookups > 32 { return Err("too many lookup tables".into()); }
        for _ in 0..lookups {
            r.take(32)?; // ALT address
            let n = r.shortvec()?; if n > 256 { return Err("ALT writable indices too long".into()); }
            r.take(n)?; writable += n;
            let n = r.shortvec()?; if n > 256 { return Err("ALT readonly indices too long".into()); }
            r.take(n)?; readonly += n;
        }
    }
    if r.at != raw.len() { return Err("trailing bytes in transaction".into()); }
    let total = keys + writable + readonly;
    if total > 256 { return Err("too many total address references".into()); }
    for i in program_indices.iter().copied().chain(indexes.iter().map(|v| *v as usize)) {
        if i >= total { return Err("instruction account index out of range".into()); }
    }
    let programs = program_indices.into_iter().map(|i| {
        if i < keys { bs58::encode(&key_data[i*32..i*32+32]).into_string() }
        else { "<unresolved-ALT-program>".into() }
    }).collect();
    let mut limitations = vec!["No signature cryptographic verification or Solana RPC simulation".into(),
        "No instruction effects, Token-2022 semantics or CPI decoded".into()];
    if writable + readonly > 0 {
        limitations.push("Address Lookup Table addresses are unresolved; remote RPC required".into());
    }
    Ok(ParsedTransaction {
        wire_format: wire_format.into(), transaction_bytes: raw.len(),
        transaction_sha256: sha256_hex(raw), message_sha256: sha256_hex(&raw[message_start..]),
        required_signatures, signature_count,
        static_account_count: keys, total_address_count: total,
        instruction_count: instructions, lookup_table_count: lookups,
        unresolved_lookup_addresses: writable + readonly, program_ids: programs,
        limitations,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedPaymentIntent {
    pub payload_b64: String,
    pub signer_pubkey_b58: String,
    pub signature_b58: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentIntentPayload {
    pub schema_version: u32,
    pub kind: String,
    pub intent_id: String,
    pub network: String,
    pub message_sha256: String,
    pub not_before_unix: u64,
    pub expires_at_unix: u64,
    pub allowed_program_ids: Vec<String>,
    pub max_spend_lamports: String,
}

fn decode_fixed_b58<const N: usize>(s: &str, what: &str) -> Result<[u8; N], String> {
    let b = bs58::decode(s).into_vec().map_err(|_| format!("{what} is not Base58"))?;
    b.try_into().map_err(|_| format!("{what} must decode to {N} bytes"))
}

pub fn verify_intent(
    envelope: &SignedPaymentIntent,
    independently_pinned_key: &str,
    actual_network: &str,
    parsed: &ParsedTransaction,
    now: u64,
) -> Result<PaymentIntentPayload, String> {
    // The key MUST be configured independently, not sourced from the untrusted JSON.
    let pin = decode_fixed_b58::<32>(independently_pinned_key, "trusted signer key")?;
    let presented = decode_fixed_b58::<32>(&envelope.signer_pubkey_b58, "presented signer")?;
    if pin != presented { return Err("intent signing key is not independently trusted".into()); }
    let payload = STANDARD.decode(envelope.payload_b64.trim()).map_err(|_| "invalid intent Base64")?;
    if payload.is_empty() || payload.len() > MAX_INTENT { return Err("intent payload size out of range".into()); }
    let sig = decode_fixed_b58::<64>(&envelope.signature_b58, "intent signature")?;
    let verifying = VerifyingKey::from_bytes(&pin).map_err(|_| "invalid trusted public key")?;
    if verifying.is_weak() { return Err("weak trusted public key".into()); }
    let mut signed = Vec::with_capacity(INTENT_DOMAIN.len()+payload.len());
    signed.extend_from_slice(INTENT_DOMAIN);
    signed.extend_from_slice(&payload);
    verifying.verify_strict(&signed, &Signature::from_bytes(&sig))
        .map_err(|_| "intent cryptographic signature invalid")?;
    let intent: PaymentIntentPayload = serde_json::from_slice(&payload)
        .map_err(|_| "intent JSON payload invalid")?;
    if intent.schema_version != 1 || intent.kind != "hguet_payment_intent" {
        return Err("intent schema/kind unsupported".into());
    }
    if intent.intent_id.is_empty() || intent.intent_id.len() > 128 {
        return Err("intent_id length invalid".into());
    }
    if intent.network != actual_network { return Err("intent network mismatch".into()); }
    if intent.message_sha256 != parsed.message_sha256 { return Err("intent message SHA256 mismatch".into()); }
    if intent.expires_at_unix <= intent.not_before_unix ||
       now < intent.not_before_unix || now >= intent.expires_at_unix {
        return Err("intent not currently authorized".into());
    }
    if intent.allowed_program_ids.len() > 64 { return Err("program allowlist too large".into()); }
    let spending_limit: u64 = intent.max_spend_lamports.parse()
        .map_err(|_| "intent spend cap invalid")?;
    if spending_limit == 0 || intent.max_spend_lamports.starts_with('0') {
        return Err("intent spending limit must be positive canonical integer".into());
    }
    if parsed.unresolved_lookup_addresses > 0 {
        return Err("unresolved ALT addresses cannot pass intent program allowlist".into());
    }
    for program in &parsed.program_ids {
        if !intent.allowed_program_ids.contains(program) {
            return Err("transaction program not on trusted intent allowlist".into());
        }
    }
    // Verified intent is NOT proof of transfer amounts or execution success.
    Ok(intent)
}

pub fn unix_now() -> Result<u64, String> {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs()).map_err(|_| "system clock before Unix epoch".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn example_legacy() -> Vec<u8> {
        let mut v = vec![1u8]; v.extend([0u8;64]); v.extend([1,0,0,1]);
        v.extend([7u8;32]); v.extend([8u8;32]); v.push(0); v
    }
    #[test] fn legacy_parse_and_hash() {
        let v=example_legacy();let p=parse_transaction(&v).unwrap();
        assert_eq!(p.wire_format,"legacy"); assert_eq!(p.static_account_count,1);
        assert_eq!(p.signature_count,1); assert_eq!(p.instruction_count,0);
        assert_eq!(p.message_sha256,sha256_hex(&v[65..]));
    }
    #[test] fn bad_and_unknown_are_not_silently_accepted() {
        assert!(parse_transaction(&[]).is_err());
        let mut extra=example_legacy();extra.push(0);assert!(parse_transaction(&extra).is_err());
        assert!(parse_transaction(&[0x81,0,0]).unwrap_err().contains("unsupported"));
        let mut v=example_legacy();v[0]=0x80;v.insert(1,0);assert!(parse_transaction(&v).is_err());
    }
    #[test] fn v0_with_lookup_requires_resolution() {
        let mut v=example_legacy();
        v.insert(65,0x80);v.push(1);v.extend([1u8;32]);v.push(1);v.push(7);v.push(0);
        let p=parse_transaction(&v).unwrap();assert_eq!(p.wire_format,"v0");
        assert_eq!(p.unresolved_lookup_addresses,1);assert_eq!(p.lookup_table_count,1);
    }
    #[test] fn strictly_verify_intent_against_pinned_key() {
        let p=parse_transaction(&example_legacy()).unwrap();
        let signing=SigningKey::from_bytes(&[42u8;32]);
        let key=bs58::encode(signing.verifying_key().to_bytes()).into_string();
        let payload=PaymentIntentPayload{
            schema_version:1,kind:"hguet_payment_intent".into(),intent_id:"test-intent".into(),
            network:"devnet".into(),message_sha256:p.message_sha256.clone(),
            not_before_unix:1,expires_at_unix:4102444800,
            allowed_program_ids:vec![], max_spend_lamports:"1000".into(),
        };
        let b=serde_json::to_vec(&payload).unwrap();
        let mut msg=INTENT_DOMAIN.to_vec();msg.extend(&b);
        let sig=signing.sign(&msg);
        let signed=SignedPaymentIntent{payload_b64:STANDARD.encode(b),signer_pubkey_b58:key.clone(),signature_b58:bs58::encode(sig.to_bytes()).into_string()};
        assert!(verify_intent(&signed,&key,"devnet",&p,100).is_ok());
        assert!(verify_intent(&signed,&key,"mainnet",&p,100).is_err());
        assert!(verify_intent(&signed,&key,"devnet",&p,4102444800).is_err());
        let mut tampered=signed.clone();tampered.signature_b58="bad".into();
        assert!(verify_intent(&tampered,&key,"devnet",&p,100).is_err());
    }
}
