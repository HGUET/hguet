#!/usr/bin/env python3
"""Exercise actual read-only signer-preflight CLI JSON. Never touch a wallet."""
import json
import sys
from pathlib import Path
from jsonschema import Draft202012Validator

root = Path(__file__).resolve().parents[1]
signer_schema = json.loads((root/"protocol/v1/signer-refusal.schema.json").read_text())
boundary_schema = json.loads((root/"protocol/v1/signing-boundary.schema.json").read_text())

def verify(path, expected_reason, intent_verified):
    data = json.loads(Path(path).read_text())
    assert list(data) == ["signer_refusal"], data
    report = data["signer_refusal"]
    Draft202012Validator(signer_schema).validate(report)
    assert report["signing_gate"] == "block"
    assert report["signing_permitted"] is False
    assert report["signer_backend_invoked"] is False
    assert report["signature_created"] is False
    assert report["transaction_broadcast"] is False
    assert report["reason_code"] == expected_reason
    assert report["independent_intent_signature_verified"] is intent_verified
    assert report["original_message_sha256"] is not None
    boundary = report["signing_boundary"]
    Draft202012Validator(boundary_schema).validate(boundary)
    assert boundary["signing_gate"] == "block"
    assert boundary["automated_signing_permitted"] is False
    assert boundary["message_sha256"] == report["original_message_sha256"]
    assert boundary["independent_intent_verified_by_caller"] is intent_verified
    return report

accepted_intent = verify(
    sys.argv[1], "SIGNER_SIDE_ENFORCEMENT_NOT_IMPLEMENTED", True)
assert accepted_intent["signing_boundary"]["direct_mint_declaration_bound_checked"]
assert accepted_intent["signing_boundary"]["direct_source_declaration_bound_checked"]
assert "SIGNER_SIDE_ENFORCEMENT_NOT_INTEGRATED" in (
    accepted_intent["signing_boundary"]["block_reasons"])

wrong_pin = verify(
    sys.argv[2], "SIGNED_INTENT_VERIFICATION_FAILED", False)
assert not wrong_pin["signing_boundary"]["direct_mint_declaration_bound_checked"]
assert not wrong_pin["signing_boundary"]["direct_source_declaration_bound_checked"]

# Even a syntactically valid forged response must not turn into an approval.
for name, value in [
    ("signing_gate", "allow"),
    ("signing_permitted", True),
    ("signer_backend_invoked", True),
    ("signature_created", True),
    ("transaction_broadcast", True),
]:
    forged = dict(accepted_intent, **{name:value})
    assert list(Draft202012Validator(signer_schema).iter_errors(forged)), name
print("PASS: real CLI signer-preflight blocks valid and untrusted intents with no wallet calls")
