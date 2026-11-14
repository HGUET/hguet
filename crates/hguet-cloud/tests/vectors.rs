//! Reproduces the server's S7.1 golden vectors (copied unchanged into testing/cloud-value/protocol) with the Rust client
//! implementation: the same outcome and the same error code for every case this crate implements.

use hguet_cloud::{
    build_client_evidence, memo_reference, proto_policy, solana_signature, subjects_sha256_hex,
    Subject,
};
use serde_json::Value;
use std::path::PathBuf;

fn vectors() -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testing/cloud-value/protocol/s7-client-vectors.json");
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    doc["cases"].as_array().unwrap().clone()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn subjects_sha256_matches_every_vector() {
    let mut checked = (0, 0);
    for case in vectors().iter().filter(|c| c["algo"] == "subjects_sha256") {
        let id = case["id"].as_str().unwrap();
        let input = &case["input"];
        let network = input["network"].as_str().unwrap();
        let expect = &case["expect"];
        // Shape errors belong to the JSON layer; the CLI builds subjects from typed data, so they cannot occur there.
        let parsed: Option<Vec<Subject>> = input["subjects"].as_array().and_then(|items| {
            items
                .iter()
                .map(|item| {
                    let object = item.as_object()?;
                    if object.len() != 3 {
                        return None;
                    }
                    Some(Subject {
                        category: object.get("category")?.as_str()?.to_owned(),
                        network: object.get("network")?.as_str()?.to_owned(),
                        subject_id: object.get("subject_id")?.as_str()?.to_owned(),
                    })
                })
                .collect()
        });
        let actual = match parsed {
            None => Err("SUBJECT_MALFORMED"),
            Some(subjects) => subjects_sha256_hex(network, &subjects).map_err(|e| e.code()),
        };
        if expect["ok"].as_bool().unwrap() {
            assert_eq!(
                actual.as_deref(),
                Ok(expect["sha256"].as_str().unwrap()),
                "{id}"
            );
            checked.0 += 1;
        } else {
            let error = expect["error"].as_str().unwrap();
            if error == "SUBJECT_SET_MALFORMED" {
                continue; // top-level JSON shape: not representable with typed input
            }
            assert_eq!(actual, Err(error), "{id}");
            checked.1 += 1;
        }
    }
    assert!(
        checked.0 >= 8 && checked.1 >= 10,
        "too few subject vectors checked: {checked:?}"
    );
}

#[test]
fn memo_and_signature_match_every_vector() {
    let all = vectors();
    let mut n = 0;
    for case in all.iter().filter(|c| c["algo"] == "memo_reference") {
        let expect = &case["expect"];
        let actual = memo_reference(case["input"]["quote_id"].as_str().unwrap());
        if expect["ok"].as_bool().unwrap() {
            assert_eq!(
                actual.unwrap(),
                expect["memo"].as_str().unwrap(),
                "{}",
                case["id"]
            );
        } else {
            assert_eq!(
                actual.unwrap_err().code(),
                expect["error"].as_str().unwrap(),
                "{}",
                case["id"]
            );
        }
        n += 1;
    }
    for case in all.iter().filter(|c| c["algo"] == "solana_signature") {
        let expect = &case["expect"];
        let actual = solana_signature(case["input"]["signature"].as_str().unwrap());
        if expect["ok"].as_bool().unwrap() {
            let raw = actual.unwrap();
            let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, expect["raw_hex"].as_str().unwrap(), "{}", case["id"]);
        } else {
            assert_eq!(
                actual.unwrap_err().code(),
                expect["error"].as_str().unwrap(),
                "{}",
                case["id"]
            );
        }
        n += 1;
    }
    assert!(n >= 16, "too few memo/signature vectors: {n}");
}

#[test]
fn the_evidence_builder_reproduces_every_valid_client_evidence_vector() {
    let mut n = 0;
    for case in vectors()
        .iter()
        .filter(|c| c["algo"] == "client_evidence" && c["expect"]["ok"] == true)
    {
        let bytes = unhex(case["input"]["bytes_hex"].as_str().unwrap());
        if bytes.is_empty() {
            continue; // absent evidence is valid on the wire; the builder always emits the explicit form
        }
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        let strings = |key: &str| -> Vec<String> {
            body[key]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect()
        };
        let rebuilt = build_client_evidence(
            body["local_decision"].as_str().unwrap(),
            &strings("finding_codes"),
            &strings("coverage"),
        )
        .unwrap();
        assert_eq!(rebuilt, bytes, "{}", case["id"]);
        n += 1;
    }
    assert!(n >= 2, "too few valid evidence vectors: {n}");
}

#[test]
fn the_envelope_policy_matches_every_proto_policy_vector() {
    let mut n = 0;
    for case in vectors().iter().filter(|c| c["algo"] == "proto_policy") {
        let bytes = unhex(case["input"]["envelope_hex"].as_str().unwrap());
        let actual = proto_policy::check_envelope(&bytes);
        let expect = &case["expect"];
        if expect["ok"].as_bool().unwrap() {
            assert!(actual.is_ok(), "{}: {actual:?}", case["id"]);
        } else {
            assert_eq!(
                actual.unwrap_err().code(),
                expect["error"].as_str().unwrap(),
                "{}",
                case["id"]
            );
        }
        n += 1;
    }
    assert!(n >= 20, "too few proto_policy vectors: {n}");
}
