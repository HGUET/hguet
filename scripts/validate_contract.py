#!/usr/bin/env python3
"""Validate HGUET public draft protocol resources and schema fixtures.
These tests check schema shape. They DO NOT assert functional client/server,
cryptographic security, Solana semantics, or completed conformance scenarios.
"""
import json
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
DIR = ROOT / "protocol" / "v1"

def main():
    schema = json.loads((DIR / "cloud-assessment.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    valid = json.loads((DIR / "fixtures" / "cloud-assessment-example.json").read_text())
    Draft202012Validator(schema).validate(valid)

    def must_fail(payload, desc):
        errors = list(Draft202012Validator(schema).iter_errors(payload))
        if not errors:
            raise AssertionError("schema accepted invalid input: " + desc)

    must_fail({**valid, "kind": "security_verdict"}, "wrong artifact type")
    must_fail({**valid, "message_sha256": "deadbeef"}, "short message digest")
    must_fail({**valid, "surprise": "unknown"}, "unknown top-level field")
    must_fail({**valid, "request_id": "not-a-128-bit-id"}, "noncanonical request")
    must_fail({**valid, "findings": [{"code":"X","severity":"magic","enforcement":"warn","evidence_refs":[]}]}, "invalid risk finding")

    cases = json.loads((DIR / "contract-cases.json").read_text())
    assert cases["status"] == "design_targets_not_executed"
    assert cases["protocol_major"] == 1 and cases["protocol_minor"] == 0
    ids = [c["id"] for c in cases["cases"]]
    assert len(ids) >= 20 and len(set(ids)) == len(ids)
    assert all(c["request"] and c["expected"] for c in cases["cases"])

    proto = (DIR / "hguet.proto").read_text()
    assert 'package hguet.protocol.v1;' in proto
    for name in ("PriceQuoteRequest","PriceQuoteResult","CheckRequest","CheckReceipt","CheckStatus",
                 "CheckResult","SignedPayload","BillingReceipt","EnrollStart","EnrollResult"):
        assert f"message {name} " in proto, f"missing message {name}"

    print(f"PASS: JSON Schema 2020-12, synthetic fixture and {len(ids)} planned conformance cases.")
    print("NOTE: This is a draft contract shape check, NOT completed client/server integration.")

if __name__ == "__main__":
    main()
