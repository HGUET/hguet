//! Historical metadata is a single provider's claim, never current state.
use super::{
    checked_result, effects, verify_rpc_genesis, JsonRpcTransport, LookupResolution, RpcError,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hguet_core::{parse_transaction, ParsedTransaction, TransactionSignatureStatus};
use serde::Serialize;
use serde_json::{json, Map, Value};

#[derive(Debug, Serialize)]
pub struct HistoricalEffects {
    pub lamport_deltas: Option<Vec<super::NativeBalanceDelta>>,
    pub token_deltas: Option<Vec<super::TokenBalanceDelta>>,
    pub cpi: super::CpiObservation,
    pub observed_fields: Vec<String>,
    pub missing_fields: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HistoricalEvidence {
    pub slot: u64,
    pub block_time: Option<i64>,
    pub status: &'static str,
    pub reported_fee_lamports: Option<String>,
    pub historical_loaded_addresses: Option<LookupResolution>,
    pub effects: Option<HistoricalEffects>,
    pub effects_status: &'static str,
}

pub struct HistoricalTransaction {
    pub wire: Vec<u8>,
    pub evidence: HistoricalEvidence,
}

pub struct HistoricalLookup {
    pub genesis_hash: String,
    pub transaction: Option<HistoricalTransaction>,
}

/// Validate before contacting the provider. Transaction IDs are first signatures.
pub fn validate_signature(signature: &str) -> Result<Vec<u8>, RpcError> {
    if signature.is_empty() || signature.len() > 88 {
        return Err(RpcError::InvalidResponse);
    }
    let bytes = bs58::decode(signature)
        .into_vec()
        .map_err(|_| RpcError::InvalidResponse)?;
    if bytes.len() != 64 || bytes.iter().all(|b| *b == 0) {
        return Err(RpcError::InvalidResponse);
    }
    Ok(bytes)
}

fn historical_lookup(
    meta: &Map<String, Value>,
    parsed: &ParsedTransaction,
    slot: u64,
) -> Result<Option<LookupResolution>, RpcError> {
    let Some(value) = meta.get("loadedAddresses").filter(|v| !v.is_null()) else {
        return Ok(None);
    };
    let expected_writable: usize = parsed
        .address_table_lookups
        .iter()
        .map(|table| table.writable_indexes.len())
        .sum();
    let expected_readonly: usize = parsed
        .address_table_lookups
        .iter()
        .map(|table| table.readonly_indexes.len())
        .sum();
    let read = |field: &str, expected: usize| -> Result<Vec<String>, RpcError> {
        let items = value
            .get(field)
            .and_then(Value::as_array)
            .ok_or(RpcError::InvalidResponse)?;
        if items.len() != expected || items.len() > 256 {
            return Err(RpcError::InvalidResponse);
        }
        items
            .iter()
            .map(|v| {
                let key = v.as_str().ok_or(RpcError::InvalidResponse)?;
                if key.len() > 44
                    || !bs58::decode(key).into_vec().is_ok_and(|v| v.len() == 32)
                {
                    return Err(RpcError::InvalidResponse);
                }
                Ok(key.to_owned())
            })
            .collect()
    };
    let writable = read("writable", expected_writable)?;
    let readonly = read("readonly", expected_readonly)?;
    if parsed.unresolved_lookup_addresses == 0 {
        return Ok(None);
    }
    Ok(Some(LookupResolution {
        context_slot: slot,
        table_addresses: parsed
            .address_table_lookups
            .iter()
            .map(|table| table.table_address.clone())
            .collect(),
        resolved_writable_accounts: writable,
        resolved_readonly_accounts: readonly,
        limitation: "Provider-reported historical loaded addresses; no present-day table lookup or independent proof".into(),
    }))
}

fn decode(
    result: Value,
    expected_signature: &[u8],
) -> Result<Option<HistoricalTransaction>, RpcError> {
    if result.is_null() {
        return Ok(None);
    }
    let slot = result
        .get("slot")
        .and_then(Value::as_u64)
        .ok_or(RpcError::InvalidResponse)?;
    let block_time = match result.get("blockTime") {
        None | Some(Value::Null) => None,
        Some(v) => Some(v.as_i64().ok_or(RpcError::InvalidResponse)?),
    };
    let encoded = result
        .get("transaction")
        .and_then(Value::as_array)
        .filter(|a| a.len() == 2 && a[1].as_str() == Some("base64"))
        .and_then(|a| a[0].as_str())
        .ok_or(RpcError::InvalidResponse)?;
    if encoded.len() > 5464 {
        return Err(RpcError::TooLarge);
    }
    let wire = STANDARD
        .decode(encoded)
        .map_err(|_| RpcError::InvalidResponse)?;
    let parsed = parse_transaction(&wire).map_err(|_| RpcError::InvalidResponse)?;
    let version = result.get("version").ok_or(RpcError::InvalidResponse)?;
    let version_matches = match parsed.wire_format.as_str() {
        "legacy" => version.as_str() == Some("legacy"),
        "v0" => version.as_u64() == Some(0),
        "v1" => version.as_u64() == Some(1),
        _ => false,
    };
    if !version_matches
        || parsed.transaction_signature_status != TransactionSignatureStatus::Verified
    {
        return Err(RpcError::InvalidResponse);
    }
    // Core already validated canonical signature count and message boundaries.
    let first = if parsed.wire_format == "v1" {
        wire.len()
            .checked_sub(parsed.signature_count * 64)
            .ok_or(RpcError::InvalidResponse)?
    } else {
        1
    };
    if wire.get(first..first + 64) != Some(expected_signature) {
        return Err(RpcError::InvalidResponse);
    }
    let mut evidence = HistoricalEvidence {
        slot,
        block_time,
        status: "METADATA_UNAVAILABLE",
        reported_fee_lamports: None,
        historical_loaded_addresses: None,
        effects: None,
        effects_status: "METADATA_UNAVAILABLE",
    };
    match result.get("meta") {
        None | Some(Value::Null) => {}
        Some(value) => {
            let meta = value.as_object().ok_or(RpcError::InvalidResponse)?;
            let err = meta.get("err").ok_or(RpcError::InvalidResponse)?;
            if !(err.is_null() || err.is_string() || err.is_object()) {
                return Err(RpcError::InvalidResponse);
            }
            evidence.status = if err.is_null() {
                "RPC_REPORTED_SUCCESS"
            } else {
                "RPC_REPORTED_FAILURE"
            };
            evidence.reported_fee_lamports = match meta.get("fee") {
                None | Some(Value::Null) => None,
                Some(v) => Some(v.as_u64().ok_or(RpcError::InvalidResponse)?.to_string()),
            };
            evidence.historical_loaded_addresses = historical_lookup(meta, &parsed, slot)?;
            if parsed.unresolved_lookup_addresses > 0
                && evidence.historical_loaded_addresses.is_none()
            {
                evidence.effects_status = "HISTORICAL_LOOKUPS_UNAVAILABLE";
            } else {
                // Reuse the bounded metadata decoder, not the simulation transport.
                let decoded = effects::inspect_simulation_effects(
                    meta,
                    &parsed,
                    evidence.historical_loaded_addresses.as_ref(),
                )?;
                let rename_fee = |items: Vec<String>| {
                    items
                        .into_iter()
                        .map(|s| {
                            if s == "simulated_fee" {
                                "historical_reported_fee".into()
                            } else {
                                s
                            }
                        })
                        .collect()
                };
                evidence.effects = Some(HistoricalEffects {
                    lamport_deltas: decoded.lamport_deltas,
                    token_deltas: decoded.token_deltas,
                    cpi: decoded.cpi,
                    observed_fields: rename_fee(decoded.observed_fields),
                    missing_fields: rename_fee(decoded.missing_fields),
                });
                evidence.effects_status = "PARTIAL_UNTRUSTED_RPC";
            }
        }
    }
    Ok(Some(HistoricalTransaction { wire, evidence }))
}

/// Exactly two read-only RPC methods: cluster identity and historical transaction.
/// Never simulate, resolve present-day accounts, or return provider error strings.
pub fn fetch<T: JsonRpcTransport>(
    transport: &T,
    endpoint: &str,
    network: &str,
    signature: &str,
) -> Result<HistoricalLookup, RpcError> {
    let expected = validate_signature(signature)?;
    let genesis_hash = verify_rpc_genesis(transport, endpoint, network)?;
    let request = json!({
        "jsonrpc":"2.0","id":2,"method":"getTransaction",
        "params":[signature,{"encoding":"base64","commitment":"finalized",
                             "maxSupportedTransactionVersion":1}]
    });
    let result = checked_result(transport.post_json(endpoint, &request)?, 2)?;
    Ok(HistoricalLookup {
        genesis_hash,
        transaction: decode(result, &expected)?,
    })
}
