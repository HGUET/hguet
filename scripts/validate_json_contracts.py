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
    # An optional signed v1 field; old SOL-only intent bytes remain valid.
    synthetic_mint = "4" * 32  # syntactically Base58; Rust checks decoded 32-byte length
    capped = dict(intent, token_spend_limits=[
        {"mint":synthetic_mint,"max_debit_raw":"1000"},
        {"mint":"5" * 32,"max_debit_raw":"0"},
    ])
    check(schemas["payment-intent"],capped)
    for bad_limits in [
        [{"mint":synthetic_mint,"max_debit_raw":"01"}],
        [{"mint":synthetic_mint,"max_debit_raw":"-1"}],
        [{"mint":synthetic_mint,"max_debit_raw":"100","extra":"unknown"}],
        [{"mint":"invalid!","max_debit_raw":"1"}],
        [{"mint":synthetic_mint,"max_debit_raw":"1"}] * 2,
        [{"mint":str(i) * 32,"max_debit_raw":"1"} for i in range(1,18)],
    ]:
        invalid = dict(intent, token_spend_limits=bad_limits)
        assert list(Draft202012Validator(schemas["payment-intent"]).iter_errors(invalid)), bad_limits
    # Signed source-account scopes are independent from mint-wide caps.
    source = {
        "mint": synthetic_mint,
        "source_token_account": "6" * 32,
        "authority": "7" * 32,
        "max_debit_raw": "90",
    }
    source_intent = dict(intent, token_source_limits=[source])
    check(schemas["payment-intent"], source_intent)
    check(schemas["payment-intent"], dict(intent, token_source_limits=[]))
    for invalid_cap in [
        dict(source, max_debit_raw="00"),
        dict(source, max_debit_raw="-1"),
        dict(source, max_debit_raw="184467440737095516160"),
        dict(source, source_token_account="invalid!"),
        dict(source, authority="invalid!"),
        dict(source, extra="unexpected"),
    ]:
        invalid = dict(intent, token_source_limits=[invalid_cap])
        assert list(Draft202012Validator(schemas["payment-intent"]).iter_errors(invalid)), invalid_cap
    too_many = [dict(source, source_token_account=str(i % 8 + 1) * 32)
                for i in range(33)]
    assert list(Draft202012Validator(schemas["payment-intent"]).iter_errors(
        dict(intent, token_source_limits=too_many)))
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
