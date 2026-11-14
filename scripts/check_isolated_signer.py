#!/usr/bin/env python3
"""End-to-end, offline, process-level BLOCK-only signer admission checks."""
import json
import subprocess
import sys
from pathlib import Path
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "protocol/v1/signer-refusal.schema.json").read_text())
BOUNDARY = json.loads((ROOT / "protocol/v1/signing-boundary.schema.json").read_text())
PIN = "2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ"
RAW = (ROOT / "tests/fixtures/legacy-spl-transfer-checked-authority-signer.base64").read_text().strip()
INTENT = json.loads((ROOT / "tests/fixtures/signed-direct-token-source-cap-equal.json").read_text())
BIN = sys.argv[1]

def invoke(payload, pin=PIN, network="devnet", extra_args=()):
    args = [BIN, "--network", network, "--trusted-key", pin, *extra_args]
    raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    out = subprocess.run(args, input=raw, capture_output=True, check=False, timeout=12)
    return out

def refusal(out, code, signed=None):
    assert out.returncode == 20, (out.returncode, out.stderr, out.stdout[:300])
    result = json.loads(out.stdout)
    assert list(result) == ["signer_refusal"], result
    row = result["signer_refusal"]
    Draft202012Validator(SCHEMA).validate(row)
    if row["signing_boundary"] is not None:
        Draft202012Validator(BOUNDARY).validate(row["signing_boundary"])
    assert row["reason_code"] == code, row
    if signed is not None:
        assert row["independent_intent_signature_verified"] is signed
    assert row["signing_gate"] == "block"
    for key in ("signing_permitted", "signature_created", "signer_backend_invoked", "transaction_broadcast"):
        assert row[key] is False
    # Raw source and envelope must not be echoed to any normal output.
    assert RAW not in out.stdout.decode()
    assert INTENT["signature_b58"] not in out.stdout.decode()
    return row

normal = {
    "schema_version": 1,
    "kind": "hguet_signer_preflight",
    "original_transaction_b64": RAW,
    "signed_intent": INTENT,
}
r = refusal(invoke(normal), "SIGNER_SIDE_ENFORCEMENT_NOT_IMPLEMENTED", True)
assert r["signing_boundary"]["direct_mint_declaration_bound_checked"]
assert r["signing_boundary"]["direct_source_declaration_bound_checked"]
assert r["signing_boundary"]["automated_signing_permitted"] is False
refusal(invoke(normal, pin="11111111111111111111111111111111"),
        "SIGNED_INTENT_VERIFICATION_FAILED", False)
refusal(invoke(normal, network="mainnet"),
        "SIGNED_INTENT_VERIFICATION_FAILED", False)

for field, payload in (
    ("network", "mainnet"), ("now_unix", 1),
    ("independently_pinned_intent_signer", PIN),
    ("rpc_result", {"status": "rpc_succeeded"}),
    ("allow", True),
    ("signing_gate", "allow"),
    ("device_command", "sign_transaction"),
):
    hostile = dict(normal, **{field:payload})
    refusal(invoke(hostile), "ISOLATION_REQUEST_INVALID", False)

refusal(invoke(b"{"), "ISOLATION_REQUEST_INVALID", False)
refusal(invoke(b" " * 65537), "ISOLATION_PAYLOAD_TOO_LARGE", False)
malformed = dict(normal, original_transaction_b64=RAW+"\n")
refusal(invoke(malformed), "ISOLATION_REQUEST_INVALID", False)
malformed = dict(normal, schema_version=2)
refusal(invoke(malformed), "ISOLATION_REQUEST_INVALID", False)
malformed = dict(normal, kind="sign_transaction")
refusal(invoke(malformed), "ISOLATION_REQUEST_INVALID", False)
malformed = dict(normal, signed_intent={**INTENT, "approve":True})
refusal(invoke(malformed), "ISOLATION_REQUEST_INVALID", False)

for extra in [("--rpc-url", "https://example.invalid"), ("--allow",), ("--trusted-key", PIN)]:
    out = invoke(normal, extra_args=extra)
    assert out.returncode == 40, (out.returncode, out.stderr)
    assert b"signer_refusal" not in out.stdout
assert invoke(normal, pin="invalid!").returncode == 40
print("PASS: separate BLOCK-only signer process rejects agent trust/clock/RPC injection, wrong pin, malformed requests and signing attempts")
