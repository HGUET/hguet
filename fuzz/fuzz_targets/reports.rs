#![no_main]
use hguet::{authority, diff, flow, html, programs, report};
use hguet_core::parse_transaction;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parsed = parse_transaction(data);
    let inventory = programs::inspect(data);
    let dossier = report::inspect(data);
    let comparison = diff::compare(data, data);
    if parsed.is_err() {
        assert!(inventory.is_err());
        assert!(dossier.is_err());
        assert!(comparison.is_err());
        return;
    }
    let parsed = parsed.unwrap();
    let inventory = inventory.expect("parsed wire must retain inventory");
    let dossier = dossier.expect("parsed wire must retain combined report");
    let comparison = comparison.expect("parsed wire must retain diff");
    assert_eq!(dossier.message_sha256, parsed.message_sha256);
    assert_eq!(inventory.message_sha256, parsed.message_sha256);
    assert_eq!(dossier.wire.message_sha256, dossier.authority.message_sha256);
    assert_eq!(dossier.signing_authorization, "NOT_AUTHORIZED");
    assert!(!dossier.execution_proven);
    assert!(dossier.wire.observed_net_changes.is_none());
    assert_eq!(dossier.wire.execution_status, "NOT_PERFORMED");
    assert!(!dossier.authority.authorization_proven);
    assert_eq!(comparison.relation, "IDENTICAL_TRANSACTION_BYTES");
    assert!(!comparison.semantic_equivalence_proven);
    assert!(comparison.instruction_changes.is_empty());
    assert_eq!(comparison.signing_authorization, "NOT_AUTHORIZED");
    assert_eq!(serde_json::to_value(&dossier.wire).unwrap(),
               serde_json::to_value(flow::inspect(data).unwrap()).unwrap());
    assert_eq!(serde_json::to_value(&dossier.authority).unwrap(),
               serde_json::to_value(authority::inspect(data).unwrap()).unwrap());
    let json = serde_json::to_value(&dossier).unwrap();
    for row in &dossier.authority.changes {
        assert!(json["authority"].pointer(&row.evidence_ref).is_some());
    }
    for row in &dossier.wire.flows {
        assert!(json["wire"].pointer(&row.evidence_ref).is_some());
    }
    let document = html::render(&dossier).unwrap();
    assert!(document.starts_with("<!doctype html>"));
    assert!(document.contains("NOT_AUTHORIZED"));
    assert!(!document.contains("<script"));
    assert!(!document.contains("<iframe"));
});
