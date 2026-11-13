//! Solana legacy / v0 / v1 offline **wire** decoding.
//! Read-only and fail-closed: never simulates execution, signs or sends transactions.
//! Official formats: https://solana.com/docs/core/transactions/versioned-transactions
use crate::sha256_hex;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Serialize;

const MAX_LEGACY_V0_SIZE: usize = 1_232;
const MAX_V1_SIZE: usize = 4_096;
const MAX_INSTRUCTIONS: usize = 64;
const MAX_V1_ACCOUNTS: usize = 96;
const SYSTEM_PROGRAM: &str = "11111111111111111111111111111111";
const COMPUTE_BUDGET: &str = "ComputeBudget111111111111111111111111111111";
const MEMO_PROGRAM: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransactionSignatureStatus {
    Unsigned,
    PartiallySigned,
    Verified,
    Invalid,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemTransfer {
    pub instruction_index: usize,
    pub source: String,
    pub destination: String,
    pub lamports: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct V1Resources {
    pub config_mask: u32,
    pub priority_fee_lamports: Option<u64>,
    pub compute_unit_limit: Option<u32>,
    pub loaded_accounts_data_size_limit: Option<u32>,
    pub requested_heap_size: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParsedTransaction {
    pub wire_format: String,
    pub transaction_bytes: usize,
    pub transaction_sha256: String,
    pub message_sha256: String,
    pub required_signatures: usize,
    pub signature_count: usize,
    pub transaction_signature_status: TransactionSignatureStatus,
    pub static_account_count: usize,
    pub total_address_count: usize,
    pub instruction_count: usize,
    pub lookup_table_count: usize,
    pub unresolved_lookup_addresses: usize,
    pub program_ids: Vec<String>,
    pub system_transfers: Vec<SystemTransfer>,
    /// This is a lower bound for explicitly decoded System Program Transfer instructions.
    /// It is NEVER a proof of total spending or of execution effects.
    pub declared_system_transfer_lamports: String,
    pub resource_config: Option<V1Resources>,
    pub limitations: Vec<String>,
}

struct Reader<'a> { bytes: &'a [u8], cursor: usize }
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, cursor: 0 } }
    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self.cursor.checked_add(len).ok_or("size overflow")?;
        let slice = self.bytes.get(self.cursor..end).ok_or("truncated transaction")?;
        self.cursor = end;
        Ok(slice)
    }
    fn u8(&mut self) -> Result<u8, String> { Ok(self.take(1)?[0]) }
    fn u16(&mut self) -> Result<u16, String> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().map_err(|_|"invalid u16")?))
    }
    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_|"invalid u32")?))
    }
    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_|"invalid u64")?))
    }
    fn compact_u16(&mut self) -> Result<usize, String> {
        let a = self.u8()?;
        let mut value = (a & 0x7f) as usize;
        if a & 0x80 != 0 {
            let b = self.u8()?;
            value |= ((b & 0x7f) as usize) << 7;
            if b & 0x80 != 0 {
                let c = self.u8()?;
                if c & 0x80 != 0 || c > 3 { return Err("compact-u16 overflow".into()); }
                value |= (c as usize) << 14;
                if value < 16_384 { return Err("non-canonical compact-u16".into()); }
            } else if value < 128 {
                return Err("non-canonical compact-u16".into());
            }
        }
        Ok(value)
    }
}

#[derive(Debug)]
struct Instruction { program: usize, accounts: Vec<usize>, data: Vec<u8> }

fn key(data: &[u8], index: usize) -> String {
    bs58::encode(&data[index * 32 .. (index + 1) * 32]).into_string()
}

fn signature_status(
    signatures: &[u8],
    key_bytes: &[u8],
    count: usize,
    message: &[u8],
) -> TransactionSignatureStatus {
    let mut present = 0;
    let mut invalid = false;
    for i in 0..count {
        let bytes: [u8; 64] = signatures[i * 64 .. (i + 1) * 64]
            .try_into().expect("signature count bounded by parser");
        if bytes.iter().all(|b| *b == 0) { continue; } // Unsigned pre-signing placeholder
        present += 1;
        let k: [u8; 32] = key_bytes[i * 32 .. (i + 1) * 32]
            .try_into().expect("signing key count validated");
        match VerifyingKey::from_bytes(&k) {
            Ok(pubkey) if !pubkey.is_weak() => {
                if pubkey.verify_strict(message, &Signature::from_bytes(&bytes)).is_err() {
                    invalid = true;
                }
            }
            _ => invalid = true,
        }
    }
    if invalid { TransactionSignatureStatus::Invalid }
    else if present == 0 { TransactionSignatureStatus::Unsigned }
    else if present == count { TransactionSignatureStatus::Verified }
    else { TransactionSignatureStatus::PartiallySigned }
}

fn parse_v1_config(r: &mut Reader<'_>, config_mask: u32) -> Result<V1Resources, String> {
    if config_mask & !0x1f != 0 { return Err("unsupported v1 config mask bits".into()); }
    if config_mask & 0b11 == 0b01 || config_mask & 0b11 == 0b10 {
        return Err("v1 priority-fee bits must be set together".into());
    }
    // Values occur in config-bit order. Priority fee occupies bits 0 and 1
    // together and is a TOTAL lamport amount, not micro-lamports per CU.
    let priority_fee_lamports = if config_mask & 0b11 == 0b11 { Some(r.u64()?) } else { None };
    let compute_unit_limit = if config_mask & 0b100 != 0 { Some(r.u32()?) } else { None };
    let loaded_accounts_data_size_limit = if config_mask & 0b1000 != 0 { Some(r.u32()?) } else { None };
    let requested_heap_size = if config_mask & 0b10000 != 0 { Some(r.u32()?) } else { None };
    Ok(V1Resources { config_mask, priority_fee_lamports, compute_unit_limit,
        loaded_accounts_data_size_limit, requested_heap_size })
}

pub fn parse_transaction(raw: &[u8]) -> Result<ParsedTransaction, String> {
    if raw.is_empty() || raw.len() > MAX_V1_SIZE {
        return Err("transaction size outside supported bound".into());
    }
    let is_v1 = raw[0] == 0x81;
    if !is_v1 && raw.len() > MAX_LEGACY_V0_SIZE {
        return Err("legacy/v0 packet exceeds 1232 bytes".into());
    }

    let mut r = Reader::new(raw);
    let (wire_format, required, readonly_signed, readonly_unsigned,
         signatures, message_start, key_bytes, instruction_data, lookup_count, unresolved,
         resource_config, max_accounts, message_end) = if is_v1 {
        r.u8()?; // 0x81, explicitly the first byte of the entire transaction
        let required = r.u8()? as usize;
        let signed_ro = r.u8()? as usize;
        let unsigned_ro = r.u8()? as usize;
        let config_mask = r.u32()?;
        r.take(32)?; // recent blockhash
        let n_instructions = r.u8()? as usize;
        if n_instructions > MAX_INSTRUCTIONS { return Err("too many v1 instructions".into()); }
        let n_accounts = r.u8()? as usize;
        if n_accounts > MAX_V1_ACCOUNTS { return Err("too many v1 addresses".into()); }
        let keys = r.take(n_accounts.checked_mul(32).ok_or("account size overflow")?)?.to_vec();
        // Config values follow address list, NOT the config_mask itself.
        let config = parse_v1_config(&mut r, config_mask)?;
        let mut headers = Vec::with_capacity(n_instructions);
        for _ in 0..n_instructions {
            let program = r.u8()? as usize;
            let n = r.u8()? as usize;
            let data_len = r.u16()? as usize;
            headers.push((program,n,data_len));
        }
        let mut instructions = Vec::with_capacity(n_instructions);
        for (program,n,data_len) in headers {
            let accounts = r.take(n)?.iter().map(|b| *b as usize).collect();
            let data = r.take(data_len)?.to_vec();
            instructions.push(Instruction { program, accounts, data });
        }
        let message_end = r.cursor;
        let signatures = r.take(required.checked_mul(64).ok_or("signature overflow")?)?.to_vec();
        if r.cursor != raw.len() { return Err("trailing v1 bytes".into()); }
        ("v1",required,signed_ro,unsigned_ro,signatures,0,keys,instructions,0,0,
            Some(config),MAX_V1_ACCOUNTS,message_end)
    } else {
        let required = r.compact_u16()?;
        if required == 0 || required > 64 { return Err("invalid legacy/v0 signature count".into()); }
        let signatures = r.take(required.checked_mul(64).ok_or("signature overflow")?)?.to_vec();
        let start = r.cursor;
        let format = if r.bytes.get(r.cursor).ok_or("missing message")? & 0x80 != 0 {
            let version = r.u8()? & 0x7f;
            if version != 0 { return Err(format!("unsupported Solana message version {version}")); }
            "v0"
        } else { "legacy" };
        let n_required = r.u8()? as usize;
        let signed_ro = r.u8()? as usize;
        let unsigned_ro = r.u8()? as usize;
        if required != n_required { return Err("signature count != message header".into()); }
        let n_accounts = r.compact_u16()?;
        if n_accounts == 0 || n_accounts > 64 { return Err("invalid static account count".into()); }
        let keys = r.take(n_accounts.checked_mul(32).ok_or("account size overflow")?)?.to_vec();
        r.take(32)?; // blockhash
        let n_instructions = r.compact_u16()?;
        if n_instructions > MAX_INSTRUCTIONS { return Err("too many compiled instructions".into()); }
        let mut instructions = Vec::with_capacity(n_instructions);
        for _ in 0..n_instructions {
            let program = r.u8()? as usize;
            let n = r.compact_u16()?;
            if n > 256 { return Err("instruction account indices too long".into()); }
            let accounts = r.take(n)?.iter().map(|b| *b as usize).collect();
            let data_len = r.compact_u16()?;
            let data = r.take(data_len)?.to_vec();
            instructions.push(Instruction { program, accounts, data });
        }
        let mut tables = 0;
        let mut unresolved = 0usize;
        if format == "v0" {
            tables = r.compact_u16()?;
            if tables > 32 { return Err("too many ALT tables".into()); }
            for _ in 0..tables {
                r.take(32)?;
                let w = r.compact_u16()?;
                if w > 64 { return Err("too many writable ALT entries".into()); }
                r.take(w)?;
                let rd = r.compact_u16()?;
                if rd > 64 { return Err("too many readonly ALT entries".into()); }
                r.take(rd)?;
                unresolved = unresolved.checked_add(w).and_then(|n| n.checked_add(rd))
                    .ok_or("lookup address count overflow")?;
            }
        }
        if r.cursor != raw.len() { return Err("trailing legacy/v0 bytes".into()); }
        (format,required,signed_ro,unsigned_ro,signatures,start,keys,instructions,
            tables,unresolved,None,64,raw.len())
    };

    let key_count = key_bytes.len() / 32;
    let total = key_count.checked_add(unresolved).ok_or("total accounts overflow")?;
    if required == 0 || required > key_count || readonly_signed > required ||
        readonly_unsigned > key_count - required || total > max_accounts {
        return Err("invalid message header/account set".into());
    }

    let mut programs = Vec::with_capacity(instruction_data.len());
    let mut system_transfers = Vec::new();
    let mut declared: u128 = 0;
    let mut unknown_effects = false;
    for (i, ins) in instruction_data.iter().enumerate() {
        if ins.program >= total || ins.accounts.iter().any(|n| *n >= total) {
            return Err("compiled instruction references an out-of-range account".into());
        }
        let program = if ins.program < key_count {
            key(&key_bytes, ins.program)
        } else {
            unknown_effects = true;
            "<unresolved-ALT-program>".into()
        };
        if program == SYSTEM_PROGRAM {
            if ins.data.len() == 12 && u32::from_le_bytes(ins.data[0..4].try_into().expect("12 bytes")) == 2 {
                if ins.accounts.len() < 2 {
                    return Err("System transfer requires two account indices".into());
                }
                let value = u64::from_le_bytes(ins.data[4..12].try_into().expect("12 bytes"));
                declared = declared.checked_add(value as u128).ok_or("native transfer total overflow")?;
                let lookup_key = |index: usize| -> String {
                    if index < key_count { key(&key_bytes, index) }
                    else { "<unresolved-ALT-account>".into() }
                };
                system_transfers.push(SystemTransfer {
                    instruction_index: i, source: lookup_key(ins.accounts[0]),
                    destination: lookup_key(ins.accounts[1]), lamports: value.to_string(),
                });
                if ins.accounts[0] >= key_count || ins.accounts[1] >= key_count {
                    unknown_effects = true;
                }
            } else {
                unknown_effects = true; // may include create-account funding, nonce withdraw, etc.
            }
        } else if program != MEMO_PROGRAM && program != COMPUTE_BUDGET {
            unknown_effects = true; // SPL token/Token-2022/CPI or other program side effects
        }
        programs.push(program);
    }

    let status = signature_status(&signatures, &key_bytes, required, &raw[message_start..message_end]);
    let mut limitations = vec![
        "Structural parsing and local Ed25519 checks do not prove transaction execution or authorize signing".into(),
        "No RPC simulation, onchain state inspection, blockhash validity or CPI analysis".into(),
        "Declared System transfers are top-level instructions only; total spend and network fees are NOT fully verified".into(),
    ];
    if unresolved > 0 { limitations.push("v0 Address Lookup Table account addresses are unresolved".into()); }
    if unknown_effects { limitations.push("Unknown effects: nontrivial system or other program instructions cannot be fully evaluated offline".into()); }
    if status != TransactionSignatureStatus::Verified {
        limitations.push("The transaction is unsigned, partly signed or has invalid signature bytes".into());
    }
    if let Some(config) = &resource_config {
        if config.compute_unit_limit.unwrap_or_default() == 0 ||
           config.loaded_accounts_data_size_limit.unwrap_or_default() == 0 {
            limitations.push("v1 mandatory compute/loaded-account limits are missing or zero: runtime execution will fail".into());
        }
    }

    Ok(ParsedTransaction {
        wire_format: wire_format.into(), transaction_bytes: raw.len(),
        transaction_sha256: sha256_hex(raw),
        message_sha256: sha256_hex(&raw[message_start..message_end]),
        required_signatures: required, signature_count: required,
        transaction_signature_status: status,
        static_account_count: key_count, total_address_count: total,
        instruction_count: instruction_data.len(),
        lookup_table_count: lookup_count, unresolved_lookup_addresses: unresolved,
        program_ids: programs, system_transfers,
        declared_system_transfer_lamports: declared.to_string(),
        resource_config, limitations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn legacy(transfers: &[(u64,u8,u8)], signed: bool) -> Vec<u8> {
        let signing=SigningKey::from_bytes(&[7u8;32]);
        let mut message=vec![1,0,1,3];
        message.extend_from_slice(&signing.verifying_key().to_bytes()); // signer
        message.extend_from_slice(&[2u8;32]); // destination
        message.extend_from_slice(&[0u8;32]); // System Program ID
        message.extend_from_slice(&[3u8;32]); // blockhash
        message.push(transfers.len() as u8);
        for &(lamports,src,dst) in transfers {
            message.extend_from_slice(&[2,2,src,dst,12]); // program, accounts, data len
            message.extend_from_slice(&2u32.to_le_bytes());
            message.extend_from_slice(&lamports.to_le_bytes());
        }
        let mut wire=vec![1];
        let sig=if signed {signing.sign(&message).to_bytes()} else {[0u8;64]};
        wire.extend(sig);wire.extend(message);wire
    }
    fn v1() -> Vec<u8> {
        let signing=SigningKey::from_bytes(&[9u8;32]);
        let mut message=vec![0x81,1,0,1];
        message.extend_from_slice(&0b1111_u32.to_le_bytes()); // priority fee + CU + data
        message.extend_from_slice(&[4u8;32]); // blockhash
        message.push(1); // one instruction
        message.push(3); // three addresses
        message.extend(signing.verifying_key().to_bytes());
        message.extend([8u8;32]); // destination
        message.extend([0u8;32]); // system program
        message.extend(99u64.to_le_bytes()); // absolute priority fee
        message.extend(200_000u32.to_le_bytes());
        message.extend(65_536u32.to_le_bytes());
        message.extend([2,2,12,0]); // header: program 2, 2 accounts, data length 12
        message.extend([0,1]); // payload: account index list
        message.extend(2u32.to_le_bytes()); // system transfer instruction kind
        message.extend(100u64.to_le_bytes());
        let mut wire=message.clone();wire.extend(signing.sign(&message).to_bytes());wire
    }
    #[test] fn legacy_transfer_and_strict_signatures() {
        let p=parse_transaction(&legacy(&[(75,0,1)],true)).unwrap();
        assert_eq!(p.transaction_signature_status,TransactionSignatureStatus::Verified);
        assert_eq!(p.declared_system_transfer_lamports,"75");
        assert_eq!(p.system_transfers.len(),1);
        assert_eq!(p.system_transfers[0].lamports,"75");
        let unsigned=parse_transaction(&legacy(&[(75,0,1)],false)).unwrap();
        assert_eq!(unsigned.transaction_signature_status,TransactionSignatureStatus::Unsigned);
        let mut forged=legacy(&[(75,0,1)],true);
        let last=forged.len()-1;forged[last]^=1;
        assert_eq!(parse_transaction(&forged).unwrap().transaction_signature_status,
            TransactionSignatureStatus::Invalid);
    }
    #[test] fn zero_or_out_of_bounds_inputs_are_rejected() {
        assert!(parse_transaction(&[]).is_err());
        assert!(parse_transaction(&[0x81,0,0]).is_err());
        let mut too_long=legacy(&[],false);too_long.resize(1233,0);
        assert!(parse_transaction(&too_long).is_err());
        let mut trailing=legacy(&[],false);trailing.push(0);
        assert!(parse_transaction(&trailing).is_err());
        let mut invalid_index=legacy(&[(1,0,1)],false);
        // Index 1 in the account list is the destination: replace with out of bounds.
        let n=invalid_index.len();
        invalid_index[n-14]=255;
        assert!(parse_transaction(&invalid_index).is_err());
    }
    #[test] fn v1_message_layout_and_resource_config() {
        let wire=v1();
        let p=parse_transaction(&wire).unwrap();
        assert_eq!(p.wire_format,"v1");
        assert_eq!(p.transaction_signature_status,TransactionSignatureStatus::Verified);
        assert_eq!(p.message_sha256,sha256_hex(&wire[..wire.len()-64]));
        assert_eq!(p.declared_system_transfer_lamports,"100");
        assert_eq!(p.resource_config.unwrap().priority_fee_lamports,Some(99));
        let mut bad=wire.clone();bad[4]=0xff;bad[5]=0xff;
        assert!(parse_transaction(&bad).is_err());
        let mut truncated=wire;truncated.pop();
        assert!(parse_transaction(&truncated).is_err());
    }
    #[test] fn v0_alt_is_not_mistaken_for_resolved_accounts() {
        let mut wire=legacy(&[],false);
        // The version prefix belongs to the MESSAGE, after signatures.
        wire.insert(65,0x80);
        wire.push(1); // ALT count
        wire.extend([11u8;32]); // ALT address
        wire.push(1);wire.push(5); // writable index
        wire.push(0); // readonly count
        let p=parse_transaction(&wire).unwrap();
        assert_eq!(p.wire_format,"v0");
        assert_eq!(p.unresolved_lookup_addresses,1);
    }
    #[test] fn system_transfer_sum_cannot_wrap_u64() {
        let p=parse_transaction(&legacy(&[(u64::MAX,0,1),(1,0,1)],false)).unwrap();
        assert_eq!(p.declared_system_transfer_lamports,"18446744073709551616");
    }

    #[test] fn independently_signed_intent_enforces_known_sol_transfer_lower_bound() {
        use crate::{verify_intent, PaymentIntentPayload, SignedPaymentIntent};
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        let p=parse_transaction(&legacy(&[(75,0,1)],false)).unwrap();
        let signer=SigningKey::from_bytes(&[23u8;32]);
        let trusted_key=bs58::encode(signer.verifying_key().to_bytes()).into_string();
        let signed_intent=|limit: &str| {
            let intent=PaymentIntentPayload {
                schema_version:1,kind:"hguet_payment_intent".into(),
                intent_id:"test-spend-cap".into(),network:"devnet".into(),
                message_sha256:p.message_sha256.clone(),
                not_before_unix:1,expires_at_unix:4102444800,
                allowed_program_ids:vec![SYSTEM_PROGRAM.into()],
                max_spend_lamports:limit.into(),
            };
            let bytes=serde_json::to_vec(&intent).unwrap();
            let mut message=b"HGUET-PAYMENT-INTENT\0".to_vec();
            message.extend(&bytes);
            SignedPaymentIntent {
                payload_b64:STANDARD.encode(bytes),
                signer_pubkey_b58:trusted_key.clone(),
                signature_b58:bs58::encode(signer.sign(&message).to_bytes()).into_string(),
            }
        };
        let too_low=signed_intent("74");
        let err=verify_intent(&too_low,&trusted_key,"devnet",&p,100).unwrap_err();
        assert!(err.contains("exceed"));
        assert!(verify_intent(&signed_intent("75"),&trusted_key,"devnet",&p,100).is_ok());
    }
}
