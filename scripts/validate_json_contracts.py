#!/usr/bin/env python3
"""Validate draft signed-intent, verdict and BLOCK-only CLI schemas; no funds."""
import json
from pathlib import Path
from jsonschema import Draft202012Validator, FormatChecker

BASE = Path(__file__).resolve().parents[1] / "protocol/v1"

def read(name):
    return json.loads((BASE/name).read_text(encoding="utf-8"))

def check(schema, value):
    Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)

def main():
    names = ["payment-intent", "signed-payment-intent", "security-verdict",
             "signing-boundary", "signer-refusal"]
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
    # The signer boundary is CLI-only and irrevocably BLOCK in this version,
    # even if a separately signed intent or successful simulation exists.
    boundary = {
        "version":1,"message_sha256":"ab"*32,
        "transaction_signature_status":"verified",
        "independent_intent_verified_by_caller":True,
        "native_sol_direct_transfer_declared_raw":"500",
        "direct_token_program_present":True,
        "direct_mint_declaration_bound_checked":True,
        "direct_source_declaration_bound_checked":True,
        "original_wire_program_allowlist_checked":True,
        "rpc_advisory_aggregate_available":True,
        "rpc_advisory_cap_anomalies":False,
        "original_wire_lookup_identity_unresolved":False,
        "unsupported_program_execution_surface":False,
        "direct_token_semantics_incomplete":False,
        "signer_side_enforcement_integrated":False,
        "execution_bank_authenticated":False,
        "total_native_sol_spending_proven":False,
        "total_gross_token_spending_proven":False,
        "automated_signing_permitted":False,
        "signing_gate":"block",
        "block_reasons":[
            "SIGNER_SIDE_ENFORCEMENT_NOT_INTEGRATED",
            "EXECUTION_BANK_NOT_AUTHENTICATED",
            "TOTAL_NATIVE_SOL_SPEND_NOT_PROVEN",
            "TOTAL_GROSS_TOKEN_SPEND_NOT_PROVEN",
        ],
        "limitation":"No signer or authenticated execution bank is integrated."
    }
    check(schemas["signing-boundary"],boundary)
    for field,unsound in [
        ("signing_gate","allow"),
        ("automated_signing_permitted",True),
        ("signer_side_enforcement_integrated",True),
        ("execution_bank_authenticated",True),
        ("total_native_sol_spending_proven",True),
        ("total_gross_token_spending_proven",True),
    ]:
        forged=dict(boundary,**{field:unsound})
        assert list(Draft202012Validator(schemas["signing-boundary"]).iter_errors(forged)),field
    forged=dict(boundary,block_reasons=["RPC_EFFECT_COVERAGE_UNAVAILABLE"])
    assert list(Draft202012Validator(schemas["signing-boundary"]).iter_errors(forged))
    forged=dict(boundary,extra="unexpected")
    assert list(Draft202012Validator(schemas["signing-boundary"]).iter_errors(forged))
    # An independently verified intent is still only an input to a permanent
    # signer refusal. The public report may not claim hardware key usage.
    refusal = {
        "version":1,
        "signing_gate":"block",
        "signing_permitted":False,
        "signer_backend_invoked":False,
        "signature_created":False,
        "transaction_broadcast":False,
        "original_transaction_sha256":"cd"*32,
        "original_message_sha256":"ab"*32,
        "independent_intent_signature_verified":True,
        "reason_code":"SIGNER_SIDE_ENFORCEMENT_NOT_IMPLEMENTED",
        "signing_boundary":boundary,
        "limitation":"No wallet signing or broadcast exists."
    }
    check(schemas["signer-refusal"],refusal)
    check(schemas["signing-boundary"],refusal["signing_boundary"])
    for field in [
        "signing_permitted","signer_backend_invoked",
        "signature_created","transaction_broadcast"
    ]:
        forged=dict(refusal,**{field:True})
        assert list(Draft202012Validator(schemas["signer-refusal"]).iter_errors(forged))
    # SecurityVerdict schema permits future ALLOW, but current CLI NEVER emits it.
    print("PASS: 5 draft schemas; no signer approval, hardware invocation or transaction broadcast.")

if __name__=="__main__": main()
