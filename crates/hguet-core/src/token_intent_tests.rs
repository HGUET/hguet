//! End-to-end synthetic, exact-byte signed PaymentIntent and original wire
//! transactions. No real wallet, RPC or onchain payment is contacted.
use crate::*;
use base64::{engine::general_purpose::STANDARD,Engine as _};
use ed25519_dalek::{SigningKey,Signer};

const LEGACY_TOKEN:&str="TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022:&str="TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
fn key(n:u8)->String{bs58::encode([n;32]).into_string()}
fn checked(tag:u8,amount:u64)->Vec<u8>{
    let mut b=vec![tag];b.extend(amount.to_le_bytes());b.push(6);b
}
fn wire(ops:&[(bool,Vec<u8>,Vec<u8>)])->ParsedTransaction{
    let mut bytes=vec![1u8];
    bytes.extend([0u8;64]);
    bytes.extend([1,0,1,7]); // 1 signer, 7 static keys
    for key in [key(1),key(2),key(3),key(4),key(5),
                LEGACY_TOKEN.into(),TOKEN_2022.into()]{
        bytes.extend(bs58::decode(key).into_vec().unwrap());
    }
    bytes.extend([9u8;32]); // blockhash
    bytes.push(ops.len() as u8);
    for (token_2022,data,accounts) in ops{
        bytes.push(if *token_2022{6}else{5});
        bytes.push(accounts.len() as u8);
        bytes.extend(accounts);
        bytes.push(data.len() as u8);
        bytes.extend(data);
    }
    parse_transaction(&bytes).unwrap()
}
fn payload(parsed:&ParsedTransaction,limits:Option<Vec<TokenSpendLimit>>)->PaymentIntentPayload{
    PaymentIntentPayload{
        schema_version:1,kind:"hguet_payment_intent".into(),
        intent_id:"offline-test".into(),network:"devnet".into(),
        message_sha256:parsed.message_sha256.clone(),
        not_before_unix:100,expires_at_unix:4102444800,
        allowed_program_ids:vec![LEGACY_TOKEN.into(),TOKEN_2022.into()],
        max_spend_lamports:"1000".into(),token_spend_limits:limits,
        token_source_limits:None,
    }
}
fn capped(mint:u8,raw:&str)->TokenSpendLimit{
    TokenSpendLimit{mint:key(mint),max_debit_raw:raw.into()}
}
fn sign(payload:&PaymentIntentPayload)->(SignedPaymentIntent,String){
    let keypair=SigningKey::from_bytes(&[42u8;32]);
    let key=bs58::encode(keypair.verifying_key().to_bytes()).into_string();
    let encoded=serde_json::to_vec(payload).unwrap();
    let mut signed_bytes=b"HGUET-PAYMENT-INTENT\0".to_vec();
    signed_bytes.extend(&encoded);
    let signature=keypair.sign(&signed_bytes);
    (SignedPaymentIntent{
        payload_b64:STANDARD.encode(encoded),
        signer_pubkey_b58:key.clone(),
        signature_b58:bs58::encode(signature.to_bytes()).into_string(),
    },key)
}
fn verified(envelope:&SignedPaymentIntent,key:&str,tx:&ParsedTransaction)
    ->Result<PaymentIntentPayload,String>{
    verify_intent(envelope,key,"devnet",tx,101)
}
#[test]
fn signed_multi_instruction_mint_cap_allows_equal_but_rejects_one_less(){
    let tx=wire(&[
        (false,checked(12,50),vec![1,3,2,4]),
        (false,checked(15,25),vec![1,3,4]),
    ]);
    let (good,key)=sign(&payload(&tx,Some(vec![capped(4,"75")])));
    let returned=verified(&good,&key,&tx).unwrap();
    assert_eq!(returned.token_spend_limits.unwrap()[0].max_debit_raw,"75");
    let (bad,_) =sign(&payload(&tx,Some(vec![capped(4,"74")])));
    let err=verified(&bad,&key,&tx).unwrap_err();
    assert!(err.contains("exceed"),"{err}");
    let (unlisted,_) =sign(&payload(&tx,Some(vec![capped(3,"100")])));
    assert!(verified(&unlisted,&key,&tx).unwrap_err().contains("missing"));
}
#[test]
fn identical_payload_is_signed_including_new_limits_tampering_fails(){
    let tx=wire(&[(false,checked(12,15),vec![1,3,2,4])]);
    let (original,key)=sign(&payload(&tx,Some(vec![capped(4,"15")])));
    assert!(verified(&original,&key,&tx).is_ok());
    let mut tampered=original.clone();
    let mut payload:serde_json::Value=serde_json::from_slice(
        &STANDARD.decode(&original.payload_b64).unwrap()).unwrap();
    payload["token_spend_limits"][0]["max_debit_raw"]="150".into();
    tampered.payload_b64=STANDARD.encode(serde_json::to_vec(&payload).unwrap());
    assert!(verified(&tampered,&key,&tx).unwrap_err().contains("signature"));
}
#[test]
fn old_absent_field_remains_signed_and_accepted_as_sol_only(){
    let tx=wire(&[(false,checked(12,5),vec![1,3,2,4])]);
    let (old,key)=sign(&payload(&tx,None));
    let json=STANDARD.decode(&old.payload_b64).unwrap();
    assert!(!String::from_utf8(json).unwrap().contains("token_spend_limits"));
    let returned=verified(&old,&key,&tx).unwrap();
    assert!(returned.token_spend_limits.is_none());
    // Legacy intent still carries no claim of a token spend bound.
}
#[test]
fn signed_zero_and_duplicate_mint_caps_are_restrictive(){
    let tx=wire(&[(false,checked(12,5),vec![1,3,2,4])]);
    let (blocked,key)=sign(&payload(&tx,Some(vec![capped(4,"0")])));
    assert!(verified(&blocked,&key,&tx).is_err());
    let (duplicate,_) =sign(&payload(&tx,
        Some(vec![capped(4,"5"),capped(4,"500")])));
    assert!(verified(&duplicate,&key,&tx).unwrap_err().contains("duplicate"));
    let (badraw,_) =sign(&payload(&tx,Some(vec![capped(4,"05")])));
    assert!(verified(&badraw,&key,&tx).is_err());
}
#[test]
fn signed_token_caps_reject_unchecked_and_unbounded_authority_wire(){
    for data in [checked(3,10),checked(8,10),checked(13,10),vec![6,0,0],
                 vec![26,9,0],vec![12,1]] {
        let tx=wire(&[(false,data,vec![1,3,2,4])]);
        let (intent,key)=sign(&payload(&tx,Some(vec![capped(4,"100")])));
        assert!(verified(&intent,&key,&tx).is_err(),
            "unsafe direct operation cannot be marked covered by signed cap");
    }
}
#[test]
fn token2022_fee_transfer_amount_is_cap_covered_but_execution_stays_unknown(){
    let mut bytes=vec![26,1];
    bytes.extend(88u64.to_le_bytes());
    bytes.push(6);
    bytes.extend(2u64.to_le_bytes());
    let tx=wire(&[(true,bytes,vec![1,3,2,4])]);
    let (equal,key)=sign(&payload(&tx,Some(vec![capped(4,"88")])));
    assert!(verified(&equal,&key,&tx).is_ok());
    let (less,_) =sign(&payload(&tx,Some(vec![capped(4,"87")])));
    assert!(verified(&less,&key,&tx).is_err());
}


fn source_cap(mint:u8,source:u8,authority:u8,raw:&str)->TokenSourceLimit {
    TokenSourceLimit {
        mint:key(mint),source_token_account:key(source),
        authority:key(authority),max_debit_raw:raw.into(),
    }
}
fn signed_source_payload(
    parsed:&ParsedTransaction,
    mint_caps:Option<Vec<TokenSpendLimit>>,
    source_caps:Vec<TokenSourceLimit>,
)->PaymentIntentPayload{
    let mut p=payload(parsed,mint_caps);
    p.token_source_limits=Some(source_caps);
    p
}
#[test]
fn signed_source_and_mint_caps_limit_each_direct_checked_source(){
    let tx=wire(&[
        (false,checked(12,80),vec![1,3,2,0]),
        (false,checked(12,20),vec![1,3,2,0]),
        (false,checked(12,30),vec![2,3,4,0]),
    ]);
    let p=signed_source_payload(&tx,Some(vec![capped(4,"130")]),vec![
        source_cap(4,2,1,"100"),source_cap(4,3,1,"30"),
    ]);
    let (env,key)=sign(&p);
    assert!(verified(&env,&key,&tx).is_ok());
    let review=review_declared_source_limits(&tx,p.token_source_limits.as_ref().unwrap()).unwrap();
    assert_eq!(review.debits.len(),2);
    assert_eq!(review.debits[0].declared_raw,"100");
    assert_eq!(review.debits[1].declared_raw,"30");
    assert_eq!(review.checked_direct_debit_instructions,3);
    assert!(review.transaction_required_signer_role_checked);
    assert!(!review.transaction_signatures_verified);
    assert!(!review.token_account_owner_verified);
    assert!(!review.total_spending_proven);
    let p=signed_source_payload(&tx,Some(vec![capped(4,"130")]),vec![
        source_cap(4,2,1,"99"),source_cap(4,3,1,"30"),
    ]);
    let (bad,_) =sign(&p);
    assert!(verified(&bad,&key,&tx).unwrap_err().contains("exceed"));
}
#[test]
fn signer_role_and_authority_mismatches_fail_closed(){
    let tx=wire(&[(false,checked(12,10),vec![1,3,2,0])]);
    let (valid,key)=sign(&signed_source_payload(&tx,None,
        vec![source_cap(4,2,1,"10")]));
    assert!(verified(&valid,&key,&tx).is_ok());
    // Signed scope authorizes a different required signer key.
    let (wrong,_) =sign(&signed_source_payload(&tx,None,
        vec![source_cap(4,2,5,"10")]));
    assert!(verified(&wrong,&key,&tx).is_err());
    // Source account is bound to message index 1, not arbitrary owner claims.
    let (wrong_source,_) =sign(&signed_source_payload(&tx,None,
        vec![source_cap(4,3,1,"10")]));
    assert!(verified(&wrong_source,&key,&tx).is_err());
    // Instruction authority key 5 is not among header-required signers.
    let tx=wire(&[(false,checked(12,10),vec![1,3,2,4])]);
    let (env,key)=sign(&signed_source_payload(&tx,None,
        vec![source_cap(4,2,1,"100")]));
    assert!(verified(&env,&key,&tx).is_err());
}
#[test]
fn strict_source_caps_reject_multisig_and_trailing_hook_accounts(){
    let tx=wire(&[(false,checked(12,5),vec![1,3,2,0,4])]);
    let (env,key)=sign(&signed_source_payload(&tx,None,
        vec![source_cap(4,2,1,"100")]));
    assert!(verified(&env,&key,&tx).unwrap_err().contains("multisig"));
    // Token-2022 checked-with-fee also requires exactly four known roles.
    let mut data=vec![26,1];
    data.extend(5u64.to_le_bytes());data.push(6);data.extend(1u64.to_le_bytes());
    let tx=wire(&[(true,data,vec![1,3,2,0,4])]);
    let (env,key)=sign(&signed_source_payload(&tx,None,
        vec![source_cap(4,2,1,"100")]));
    assert!(verified(&env,&key,&tx).is_err());
}
#[test]
fn signed_source_caps_reject_duplicate_sources_missing_and_zero(){
    let tx=wire(&[(false,checked(15,5),vec![1,3,0])]);
    let (env,key)=sign(&signed_source_payload(&tx,None,
        vec![source_cap(4,2,1,"5")]));
    assert!(verified(&env,&key,&tx).is_ok());
    let (zero,_) =sign(&signed_source_payload(&tx,None,
        vec![source_cap(4,2,1,"0")]));
    assert!(verified(&zero,&key,&tx).is_err());
    let (none,_) =sign(&signed_source_payload(&tx,None,vec![]));
    assert!(verified(&none,&key,&tx).is_err());
    let (duplicate,_) =sign(&signed_source_payload(&tx,None,
        vec![source_cap(4,2,1,"5"),source_cap(4,2,1,"10")]));
    assert!(verified(&duplicate,&key,&tx).unwrap_err().contains("duplicate"));
    let (invalid,_) =sign(&signed_source_payload(&tx,None,
        vec![source_cap(4,2,1,"05")]));
    assert!(verified(&invalid,&key,&tx).is_err());
}
#[test]
fn signed_source_role_fields_cannot_be_tampered_after_signature(){
    let tx=wire(&[(false,checked(12,7),vec![1,3,2,0])]);
    let (env,pin)=sign(&signed_source_payload(&tx,None,
        vec![source_cap(4,2,1,"7")]));
    assert!(verified(&env,&pin,&tx).is_ok());
    let mut broken=env.clone();
    let mut json:serde_json::Value=serde_json::from_slice(
        &STANDARD.decode(&env.payload_b64).unwrap()).unwrap();
    json["token_source_limits"][0]["authority"]=key(5).into();
    broken.payload_b64=STANDARD.encode(serde_json::to_vec(&json).unwrap());
    assert!(verified(&broken,&pin,&tx).unwrap_err().contains("signature"));
}
