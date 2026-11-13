#!/usr/bin/env python3
"""Validate public draft PaymentIntent/SecurityVerdict schemas; no live funds."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

BASE = Path(__file__).resolve().parents[1] / "protocol/v1"

def read(name):
    return json.loads((BASE/name).read_text(encoding="utf-8"))

def check(schema, value):
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)

def main():
    names = ["payment-intent", "signed-payment-intent", "security-verdict"]
    schemas = {n:read(n+".schema.json") for n in names}
    for s in schemas.values(): Draft202012Validator.check_schema(s)
    intent = {
        "schema_version":1,"kind":"hguet_payment_intent",
        "intent_id":"synthetic-only","network":"devnet",
        "message_sha256":"ab"*32,"not_before_unix":1,
        "expires_at_unix":4102444800,"allowed_program_ids":[],
        "max_spend_lamports":"1000"
    }
    check(schemas["payment-intent"],intent)
    invalid = dict(intent, max_spend_lamports="0")
    assert list(Draft202012Validator(schemas["payment-intent"]).iter_errors(invalid))
    verdict = {
        "schema_version":1,"kind":"security_verdict","decision":"UNKNOWN",
        "network":"devnet","message_sha256":"ab"*32,
        "transaction_sha256":"cd"*32,"intent_status":"signature_verified",
        "simulation_status":"not_performed","coverage":["wire_structure"],
        "findings":[],"limitations":["no onchain simulation"]
    }
    check(schemas["security-verdict"],verdict)
    invalid = dict(verdict, decision="ALLOW", simulation_status="not_performed", extra="unexpected")
    assert list(Draft202012Validator(schemas["security-verdict"]).iter_errors(invalid))
    # Schema permits future ALLOW, but current CLI NEVER emits it.
    print("PASS: 3 unpublished schemas and negative structural checks; cryptographic verification tested in Rust.")

if __name__=="__main__": main()
