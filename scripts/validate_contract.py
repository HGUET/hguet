#!/usr/bin/env python3
"""HGUET public v0.2 protocol static schema checks (not live payment tests)."""
from copy import deepcopy
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1] / "protocol" / "v1"


def load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def validate(kind, fixture):
    schema = load(f"{kind}.schema.json")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(fixture)
    return schema


def must_reject(schema, obj, reason):
    if not list(Draft202012Validator(schema, format_checker=FormatChecker()).iter_errors(obj)):
        raise AssertionError(f"Invalid {reason} unexpectedly passed")


def integer_ceil(a, b):
    assert a >= 0 and b > 0
    return (a + b - 1) // b


def check_quote_semantics(q):
    assert q["asset"] == "SOL"
    assert q["environment"] == ("production" if q["network"] == "mainnet" else "sandbox")
    assert q["lamports_due"] == str(integer_ceil(
        int(q["usd_price_micros"]) * 1_000_000_000,
        int(q["sol_usd_price_micros"])))
    assert int(q["lamports_due"]) > 0
    assert int(q["sol_usd_price_micros"]) > 0


def main():
    cloud = validate("cloud-assessment", load("fixtures/cloud-assessment-example.json"))
    quote = load("fixtures/payment-quote-example.json")
    quote_schema = validate("payment-quote", quote)
    receipt = load("fixtures/payment-receipt-example.json")
    receipt_schema = validate("payment-receipt", receipt)
    check_quote_semantics(quote)
    assert quote["quote_id"] == receipt["quote_id"]
    assert quote["network"] == receipt["network"]
    assert quote["environment"] == receipt["environment"]
    assert quote["genesis_hash"] == receipt["genesis_hash"]
    assert quote["lamports_due"] == receipt["lamports_paid"]
    assert quote["receiver"] == receipt["receiver"]

    invalid = deepcopy(quote); invalid["asset"] = "USDC"
    must_reject(quote_schema, invalid, "USDC payment")
    invalid = deepcopy(quote); invalid["message_sha256"] = "bad"
    must_reject(quote_schema, invalid, "invalid hash")
    invalid = deepcopy(quote); invalid["random"] = "injected"
    must_reject(quote_schema, invalid, "unexpected field")
    invalid = deepcopy(quote); invalid["oracle_published_at"] = "not-a-date"
    must_reject(quote_schema, invalid, "invalid timestamp")
    invalid = deepcopy(receipt); invalid["settled_commitment"] = "processed"
    must_reject(receipt_schema, invalid, "unfinalized payment")
    invalid = deepcopy(receipt); invalid["lamports_paid"] = "-1"
    must_reject(receipt_schema, invalid, "negative lamports")
    invalid = load("fixtures/cloud-assessment-example.json"); invalid["kind"] = "security_verdict"
    must_reject(cloud, invalid, "composite instead of cloud assessment")

    cases = load("contract-cases.json")
    assert cases["status"] == "design_targets_not_executed"
    assert cases["protocol_major"] == 1 and cases["protocol_minor"] == 0
    assert cases["design_version"] == "0.2-SOL-pay-per-check"
    ids = [c["id"] for c in cases["cases"]]
    assert len(ids) >= 25 and len(set(ids)) == len(ids)

    proto = (ROOT / "hguet.proto").read_text(encoding="utf-8")
    assert 'package hguet.protocol.v1;' in proto
    required = ["ClientHello", "PriceQuoteRequest", "PriceQuoteResult", "PaidCheckRequest",
                "PaidCheckStatus", "CheckReceipt", "CheckResult", "SignedPayload"]
    for name in required:
        assert f"message {name} " in proto, f"missing message {name}"
    for deprecated in ["EnrollStart", "CreditBalance", "TopUpQuote", "CheckRequest"]:
        assert f"message {deprecated} " not in proto, f"legacy prepaid flow remains: {deprecated}"
    print(f"PASS: 3 draft JSON Schemas, synthetic SOL quote/receipt and {len(ids)} planned cases.")
    print("NOTE: schema/fixture checks only; no running server, funded payment or PQ TLS interop.")


if __name__ == "__main__":
    main()
