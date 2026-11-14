//! Untrusted agent ↔ operator-owned, block-only signer process data boundary.
//!
//! Trust configuration is NOT part of an agent request: no endpoint, pin,
//! policy flags, clock, RPC report, signer approval, wallet path or secret.
//! The operator must provision trust out of band and enforce actual OS process
//! isolation before any future device backend is added. This module has no
//! network or device transport and returns refusals only.
use super::{guarded_sign, refused, SignerRefusal, SignerRequest};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use hguet_core::{unix_now, SignedPaymentIntent};
use serde::Deserialize;

pub const MAX_AGENT_JSON_BYTES: usize = 65536;
pub const MAX_ORIGINAL_TRANSACTION_BYTES: usize = 16384;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UntrustedAgentRequest {
    schema_version: u32,
    kind: String,
    original_transaction_b64: String,
    signed_intent: SignedPaymentIntent,
}

/// A *locally created* context, separated from the untrusted request.
/// This is a software trust separation only; process ownership, filesystem
/// permissions, syscall filtering and device isolation are NOT established.
pub struct OperatorTrust {
    network: String,
    independently_pinned_intent_signer: String,
}
impl OperatorTrust {
    /// The public Ed25519 intent verification key must come from an operator,
    /// never from an agent envelope or RPC. No trust can be inferred from a
    /// well-formed pubkey alone. Caller must verify provisioning out of band.
    pub fn new(network: &str, pinned_signer: &str) -> Result<Self, &'static str> {
        if !matches!(network, "mainnet" | "devnet" | "testnet") {
            return Err("UNSUPPORTED_NETWORK");
        }
        let raw = bs58::decode(pinned_signer)
            .into_vec()
            .map_err(|_| "ISOLATION_CONFIG_INVALID")?;
        if raw.len() != 32 || bs58::encode(&raw).into_string() != pinned_signer {
            return Err("ISOLATION_CONFIG_INVALID");
        }
        Ok(Self {
            network: network.to_owned(),
            independently_pinned_intent_signer: pinned_signer.to_owned(),
        })
    }
    /// A single bounded, strictly shaped request. In particular, an agent
    /// cannot supply or override pin, network, time, approval, RPC result, or
    /// device command through this input. The local clock is read here.
    ///
    /// Even valid request+intent always return the no-sign refusal.
    pub fn inspect_agent_json(&self, input: &[u8]) -> SignerRefusal {
        if input.len() > MAX_AGENT_JSON_BYTES {
            return refused("ISOLATION_PAYLOAD_TOO_LARGE", None, false, None);
        }
        let envelope: UntrustedAgentRequest = match serde_json::from_slice(input) {
            Ok(envelope) => envelope,
            Err(_) => return refused("ISOLATION_REQUEST_INVALID", None, false, None),
        };
        if envelope.schema_version != 1 || envelope.kind != "hguet_signer_preflight" {
            return refused("ISOLATION_REQUEST_INVALID", None, false, None);
        }
        if envelope.original_transaction_b64.len()
            > (MAX_ORIGINAL_TRANSACTION_BYTES.div_ceil(3) * 4 + 4)
        {
            return refused("ISOLATION_PAYLOAD_TOO_LARGE", None, false, None);
        }
        let transaction = match STANDARD.decode(envelope.original_transaction_b64.as_bytes()) {
            Ok(decoded)
                if !decoded.is_empty()
                    && decoded.len() <= MAX_ORIGINAL_TRANSACTION_BYTES
                    && STANDARD.encode(&decoded) == envelope.original_transaction_b64 =>
            {
                decoded
            }
            _ => return refused("ISOLATION_REQUEST_INVALID", None, false, None),
        };
        let now = match unix_now() {
            Ok(now) => now,
            Err(_) => return refused("CLOCK_UNAVAILABLE", None, false, None),
        };
        let request = SignerRequest {
            original_transaction: &transaction,
            signed_intent: Some(&envelope.signed_intent),
            independently_pinned_intent_signer: Some(&self.independently_pinned_intent_signer),
            network: &self.network,
            now_unix: now,
        };
        // Infallible success type. No command, RPC result or third-party
        // approval JSON can change this result or trigger a key operation.
        match guarded_sign(request) {
            Err(refusal) => refusal,
            Ok(never) => match never {},
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use serde_json::{json, Value};
    const PIN: &str = "2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ";
    const RAW: &str =
        include_str!("../../../tests/fixtures/legacy-spl-transfer-checked-authority-signer.base64");
    const INTENT: &str =
        include_str!("../../../tests/fixtures/signed-direct-token-source-cap-equal.json");
    fn operator() -> OperatorTrust {
        OperatorTrust::new("devnet", PIN).unwrap()
    }
    fn payload() -> Value {
        json!({
            "schema_version":1,"kind":"hguet_signer_preflight",
            "original_transaction_b64":RAW.trim(),
            "signed_intent":serde_json::from_str::<Value>(INTENT).unwrap(),
        })
    }
    fn inspect(v: &Value) -> SignerRefusal {
        operator().inspect_agent_json(&serde_json::to_vec(v).unwrap())
    }
    #[test]
    fn valid_signed_intent_remains_blocked_under_independent_operator_pin() {
        let refusal = inspect(&payload());
        assert_eq!(
            refusal.reason_code,
            "SIGNER_SIDE_ENFORCEMENT_NOT_IMPLEMENTED"
        );
        assert!(refusal.independent_intent_signature_verified);
        assert_eq!(refusal.signing_gate, "block");
        assert!(!refusal.signing_permitted);
        assert!(!refusal.signer_backend_invoked);
        assert!(!refusal.signature_created);
        assert!(!refusal.transaction_broadcast);
        let boundary = refusal.signing_boundary.unwrap();
        assert!(boundary.direct_mint_declaration_bound_checked);
        assert!(boundary.direct_source_declaration_bound_checked);
        assert!(!boundary.automated_signing_permitted);
    }
    #[test]
    fn attacker_cannot_include_network_pin_time_allow_or_rpc_in_agent_request() {
        let mut item = payload();
        for (name, value) in [
            ("network", json!("mainnet")),
            ("independently_pinned_intent_signer", json!(PIN)),
            ("now_unix", json!(1)),
            ("allow", json!(true)),
            ("signing_gate", json!("allow")),
            ("rpc_result", json!({"status":"success"})),
            ("device_command", json!("sign_transaction")),
        ] {
            item[name] = value;
            let denied = inspect(&item);
            assert_eq!(
                denied.reason_code, "ISOLATION_REQUEST_INVALID",
                "injected field: {name}"
            );
            assert!(!denied.signing_permitted);
            item.as_object_mut().unwrap().remove(name);
        }
    }
    #[test]
    fn wrong_operator_pin_and_wrong_network_ignore_agent_supplied_intent_key() {
        let wrong = OperatorTrust::new("devnet", "11111111111111111111111111111111").unwrap();
        let data = serde_json::to_vec(&payload()).unwrap();
        let denied = wrong.inspect_agent_json(&data);
        assert_eq!(denied.reason_code, "SIGNED_INTENT_VERIFICATION_FAILED");
        assert!(!denied.independent_intent_signature_verified);
        let wrong_network = OperatorTrust::new("mainnet", PIN).unwrap();
        let denied = wrong_network.inspect_agent_json(&data);
        assert_eq!(denied.reason_code, "SIGNED_INTENT_VERIFICATION_FAILED");
        assert!(!denied.signing_permitted);
        assert!(OperatorTrust::new("mainnet", "not-base58!!").is_err());
    }
    #[test]
    fn message_replacement_breaks_exact_signed_intent() {
        let mut item = payload();
        let mut wire = STANDARD.decode(RAW.trim()).unwrap();
        wire[90] ^= 1;
        item["original_transaction_b64"] = json!(STANDARD.encode(&wire));
        let denial = inspect(&item);
        assert_eq!(denial.reason_code, "SIGNED_INTENT_VERIFICATION_FAILED");
        assert!(!denial.independent_intent_signature_verified);
        assert!(!denial.signing_permitted);
    }
    #[test]
    fn oversized_truncated_noncanonical_and_unknown_input_never_approve() {
        let operator = operator();
        let huge = vec![b' '; MAX_AGENT_JSON_BYTES + 1];
        assert_eq!(
            operator.inspect_agent_json(&huge).reason_code,
            "ISOLATION_PAYLOAD_TOO_LARGE"
        );
        assert_eq!(
            operator.inspect_agent_json(b"{").reason_code,
            "ISOLATION_REQUEST_INVALID"
        );
        let mut v = payload();
        v["original_transaction_b64"] = json!(format!("{}\n", RAW.trim()));
        assert_eq!(inspect(&v).reason_code, "ISOLATION_REQUEST_INVALID");
        let mut v = payload();
        v["schema_version"] = json!(2);
        assert_eq!(inspect(&v).reason_code, "ISOLATION_REQUEST_INVALID");
        let mut v = payload();
        v["kind"] = json!("sign_transaction");
        assert_eq!(inspect(&v).reason_code, "ISOLATION_REQUEST_INVALID");
        let mut v = payload();
        v["original_transaction_b64"] = json!(STANDARD.encode([1u8; 32]));
        assert_eq!(
            inspect(&v).reason_code,
            "MALFORMED_OR_UNSUPPORTED_TRANSACTION"
        );
    }
    #[test]
    fn envelope_tamper_or_extra_signed_intent_field_is_rejected() {
        let mut v = payload();
        v["signed_intent"]["signature_b58"] =
            json!("1111111111111111111111111111111111111111111111111111111111111111");
        assert_eq!(inspect(&v).reason_code, "SIGNED_INTENT_VERIFICATION_FAILED");
        let mut v = payload();
        v["signed_intent"]["approve"] = json!(true);
        assert_eq!(inspect(&v).reason_code, "ISOLATION_REQUEST_INVALID");
    }
}
