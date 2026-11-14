use super::*;
use base64::{engine::general_purpose::STANDARD,Engine as _};

const PIN:&str="2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ";
const WIRE:&str=include_str!("../../../tests/fixtures/legacy-spl-transfer-checked-authority-signer.base64");
const INTENT:&str=include_str!("../../../tests/fixtures/signed-direct-token-source-cap-equal.json");
fn payload()->(Vec<u8>,SignedPaymentIntent){
    (STANDARD.decode(WIRE.trim()).unwrap(),
     serde_json::from_str(INTENT).unwrap())
}
fn request<'a>(raw:&'a [u8],intent:Option<&'a SignedPaymentIntent>,
    pin:Option<&'a str>)->SignerRequest<'a>{
    SignerRequest{
        original_transaction:raw,signed_intent:intent,
        independently_pinned_intent_signer:pin,
        network:"devnet",now_unix:1_700_000_000,
    }
}
#[test]
fn verified_intent_and_both_caps_still_cannot_sign(){
    let (wire,intent)=payload();
    let result=guarded_sign(request(&wire,Some(&intent),Some(PIN)))
        .unwrap_err();
    assert_eq!(result.signing_gate,"block");
    assert!(!result.signing_permitted);
    assert!(!result.signer_backend_invoked);
    assert!(!result.signature_created);
    assert!(!result.transaction_broadcast);
    assert!(result.independent_intent_signature_verified);
    assert_eq!(result.reason_code,"SIGNER_SIDE_ENFORCEMENT_NOT_IMPLEMENTED");
    let boundary=result.signing_boundary.unwrap();
    assert!(boundary.direct_mint_declaration_bound_checked);
    assert!(boundary.direct_source_declaration_bound_checked);
    assert!(!boundary.automated_signing_permitted);
}
#[test]
fn missing_independent_pin_never_uses_key_from_untrusted_envelope(){
    let (wire,intent)=payload();
    let result=inspect_signer_request(request(&wire,Some(&intent),None));
    assert_eq!(result.reason_code,"INDEPENDENT_TRUST_KEY_MISSING");
    assert!(!result.independent_intent_signature_verified);
    assert!(!result.signing_boundary.unwrap().direct_mint_declaration_bound_checked);
}
#[test]
fn wrong_trust_pin_and_tampered_signature_fail_closed(){
    let (wire,mut intent)=payload();
    let wrong_pin="11111111111111111111111111111111";
    let result=inspect_signer_request(request(&wire,Some(&intent),Some(wrong_pin)));
    assert_eq!(result.reason_code,"SIGNED_INTENT_VERIFICATION_FAILED");
    intent.signature_b58="1111111111111111111111111111111111111111111111111111111111111111".into();
    let result=inspect_signer_request(request(&wire,Some(&intent),Some(PIN)));
    assert_eq!(result.reason_code,"SIGNED_INTENT_VERIFICATION_FAILED");
    assert!(!result.signing_permitted);
}
#[test]
fn mutating_original_wire_invalidates_exact_message_intent(){
    let (mut wire,intent)=payload();
    let original=inspect_signer_request(request(&wire,Some(&intent),Some(PIN)));
    assert!(original.independent_intent_signature_verified);
    // Mutate an account key in the original wire without changing framing.
    wire[90]^=1;
    let changed=inspect_signer_request(request(&wire,Some(&intent),Some(PIN)));
    assert_eq!(changed.reason_code,"SIGNED_INTENT_VERIFICATION_FAILED");
    assert!(!changed.independent_intent_signature_verified);
    assert_ne!(changed.original_message_sha256,original.original_message_sha256);
}
#[test]
fn expired_intent_or_wrong_network_never_invokes_signer(){
    let (wire,intent)=payload();
    let mut expired=request(&wire,Some(&intent),Some(PIN));
    expired.now_unix=4_102_444_800;
    assert_eq!(guarded_sign(expired).unwrap_err().reason_code,
        "SIGNED_INTENT_VERIFICATION_FAILED");
    let mut wrong=request(&wire,Some(&intent),Some(PIN));
    wrong.network="mainnet";
    assert_eq!(guarded_sign(wrong).unwrap_err().reason_code,
        "SIGNED_INTENT_VERIFICATION_FAILED");
}
#[test]
fn malformed_wire_or_missing_intent_never_reaches_backend(){
    let (wire,intent)=payload();
    let bad=[255u8;32];
    let malformed=guarded_sign(request(&bad,Some(&intent),Some(PIN))).unwrap_err();
    assert_eq!(malformed.reason_code,"MALFORMED_OR_UNSUPPORTED_TRANSACTION");
    assert!(malformed.original_message_sha256.is_none());
    let absent=guarded_sign(request(&wire,None,Some(PIN))).unwrap_err();
    assert_eq!(absent.reason_code,"SIGNED_INTENT_MISSING");
}
#[test]
fn nonzero_invalid_transaction_signature_is_rejected(){
    let (mut wire,intent)=payload();
    wire[1..65].fill(1);
    let result=inspect_signer_request(request(&wire,Some(&intent),Some(PIN)));
    assert_eq!(result.reason_code,"TRANSACTION_SIGNATURE_INVALID");
    assert!(!result.signing_permitted);
}
#[test]
fn unsigned_is_normal_preflight_but_never_approval(){
    let (wire,intent)=payload();
    let result=inspect_signer_request(request(&wire,Some(&intent),Some(PIN)));
    assert_eq!(result.signing_boundary.as_ref().unwrap()
        .transaction_signature_status,TransactionSignatureStatus::Unsigned);
    assert!(!result.signing_permitted);
}
#[test]
fn forged_agent_json_cannot_enter_preflight_or_override_wire_review(){
    let (wire,intent)=payload();
    let refusal=inspect_signer_request(request(&wire,Some(&intent),Some(PIN)));
    let mut untrusted=serde_json::to_value(&refusal).unwrap();
    untrusted["signing_permitted"]=serde_json::json!(true);
    untrusted["signing_boundary"]["automated_signing_permitted"]=serde_json::json!(true);
    // No authorization-deserialization API exists. Re-check original bytes.
    let checked=inspect_signer_request(request(&wire,Some(&intent),Some(PIN)));
    assert!(!checked.signing_permitted);
    assert!(!checked.signing_boundary.unwrap().automated_signing_permitted);
}
