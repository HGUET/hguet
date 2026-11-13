#!/usr/bin/env python3
"""HGUET unreleased public protocol: static schema checks only, not live payments."""
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


def tier_for_metrics(policy, metrics, capabilities):
    """Highest-required published tier by all bounded metrics and capabilities."""
    limits_map = {
        "transaction_bytes": "max_transaction_bytes",
        "top_level_instructions": "max_top_level_instructions",
        "resolved_accounts": "max_resolved_accounts",
        "lookup_tables": "max_lookup_tables",
        "distinct_programs": "max_distinct_programs",
        "risk_subjects": "max_risk_subjects",
    }
    for tier in policy["tiers"]:
        lim = tier["limits"]
        if all(metrics[k] <= lim[v] for k, v in limits_map.items()) and set(capabilities).issubset(set(tier["allowed_capabilities"])):
            return tier
    raise ValueError("Unsupported quote dimensions; refuse before payment")

def price_reference_accepted(source_observed_seconds_ago, compared_divergence_bps, policy):
    cfg = policy["oracle"]
    if source_observed_seconds_ago < 0 or source_observed_seconds_ago > cfg["source_max_age_seconds"]:
        return False
    if compared_divergence_bps is not None and (compared_divergence_bps < 0 or compared_divergence_bps > cfg["max_tolerated_independent_divergence_bps"]):
        return False
    return True


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
    policy = load("pricing-policy.draft.json")
    assert policy["status"] == "prelaunch_draft_not_published_rates"
    assert policy["pricing_policy_version"] == quote["pricing_policy_version"]
    assert policy["oracle"]["pair"] == "SOL/USD" and policy["payment_asset"] == "SOL"
    assert policy["oracle"]["max_tolerated_independent_divergence_bps"] == 500
    assert not policy["oracle"]["fetch_oracle_for_each_request"]
    tier = tier_for_metrics(policy, quote["complexity"], quote["requested_capabilities"])
    assert tier["id"] == quote["pricing_tier"]
    assert int(quote["usd_price_micros"]) == tier["usd_price_micros"]
    assert int(quote["lamports_due"]) <= int(quote["max_lamports_requested"])
    for age in [0, 14400, 43200, 86399, 86400]:
        assert price_reference_accepted(age, 500, policy)
    for age, divergence in [(86401,0), (90000,None), (0,501), (-1,None)]:
        assert not price_reference_accepted(age, divergence, policy)
    assert tier_for_metrics(policy, dict(quote["complexity"], transaction_bytes=513),
                            quote["requested_capabilities"])["id"] == "standard"
    assert tier_for_metrics(policy, dict(quote["complexity"], top_level_instructions=13),
                            quote["requested_capabilities"])["id"] == "complex"
    assert tier_for_metrics(policy, dict(quote["complexity"], risk_subjects=13),
                            quote["requested_capabilities"])["id"] == "extended"
    assert tier_for_metrics(policy, quote["complexity"], ["independent_rpc_simulation"])["id"] == "extended"
    cloud_example = load("fixtures/cloud-assessment-example.json")
    assert cloud_example["quote_id"] == quote["quote_id"]
    assert cloud_example["environment"] == quote["environment"]
    assert cloud_example["network"] == quote["network"]
    assert cloud_example["message_sha256"] == quote["message_sha256"]
    assert cloud_example["intent_sha256"] == quote["intent_sha256"]
    assert cloud_example["subjects_sha256"] == quote["subjects_sha256"]
    assert cloud_example["transaction_sha256"] == quote["transaction_sha256"]
    assert "tenant_scope" not in cloud_example and "request_id" not in cloud_example
    assert quote["transaction_sha256"] is not None
    assert quote["quote_id"] == receipt["quote_id"]
    assert quote["network"] == receipt["network"]
    assert quote["environment"] == receipt["environment"]
    assert quote["genesis_hash"] == receipt["genesis_hash"]
    assert quote["lamports_due"] == receipt["lamports_paid"]
    assert quote["receiver"] == receipt["receiver"]

    invalid = deepcopy(quote); invalid["lamports_due"] = "0"
    must_reject(quote_schema, invalid, "zero lamport invoice")
    invalid = deepcopy(quote); invalid["sol_usd_price_micros"] = "0"
    must_reject(quote_schema, invalid, "zero reference price")
    invalid = deepcopy(receipt); invalid["lamports_paid"] = "0"
    must_reject(receipt_schema, invalid, "zero payment")
    invalid = deepcopy(cloud_example); invalid.pop("quote_id")
    must_reject(cloud, invalid, "cloud assessment unbound from quote")
    invalid = deepcopy(cloud_example); invalid["tenant_scope"] = "legacy_tenant"
    must_reject(cloud, invalid, "stale tenant based schema")
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
    assert cases["design_status"] == "unreleased-draft-sol-pay-per-check"
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
    print(f"PASS: 3 JSON Schemas, draft pricing tier/cap/24h ±5% tests, SOL quote/receipt and {len(ids)} planned cases.")
    print("NOTE: schema/fixture checks only; no running server, funded payment or PQ TLS interop.")


if __name__ == "__main__":
    main()
