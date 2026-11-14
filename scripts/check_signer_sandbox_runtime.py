#!/usr/bin/env python3
"""Exercise actual Bubblewrap+seccomp on Linux when kernel permits it.

If the runner blocks user/mount namespaces, prove the HGUET launcher fails
closed with exit 40 and no output. Never make a network call or touch a key.
"""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
BIN=(ROOT/"target/debug/hguet-signer-isolate").resolve()
LAUNCHER=ROOT/"scripts/run_signer_sandbox.py"
PUBLIC_PIN="2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ"
WIRE=(ROOT/"tests/fixtures/legacy-spl-transfer-checked-authority-signer.base64").read_text().strip()
ENVELOPE=json.loads((ROOT/"tests/fixtures/signed-direct-token-source-cap-equal.json").read_text())
INPUT=json.dumps({
    "schema_version":1,"kind":"hguet_signer_preflight",
    "original_transaction_b64":WIRE,"signed_intent":ENVELOPE,
}).encode()
HASH=hashlib.sha256(BIN.read_bytes()).hexdigest()
ARGS=[sys.executable,str(LAUNCHER),
    "--binary",str(BIN),"--binary-sha256",HASH,
    "--network","devnet","--trusted-key",PUBLIC_PIN]

def run(command,input=b""):
    return subprocess.run(command,input=input,capture_output=True,
                          timeout=20,check=False)

if not Path("/usr/bin/bwrap").exists():
    result=run(ARGS,INPUT)
    assert result.returncode==40
    assert not result.stdout
    assert b"HGUET_SANDBOX_BLOCKED" in result.stderr
    print("SKIP: Bubblewrap not installed; mandatory fail-closed launcher verified")
    sys.exit(0)

# The probe must require namespaces, no capability fallback, and never grant
# the sandboxed process host network or home access.
probe=[
    "/usr/bin/bwrap","--unshare-all","--unshare-user",
    "--disable-userns","--assert-userns-disabled",
    "--cap-drop","ALL",
    "--clearenv",
    "--ro-bind","/usr","/usr",
    "--ro-bind-try","/lib","/lib",
    "--ro-bind-try","/lib64","/lib64",
    "--ro-bind-try","/bin","/bin",
    "/usr/bin/true",
]
available=run(probe).returncode==0
result=run(ARGS,INPUT)
if not available:
    assert result.returncode==40,(result.returncode,result.stderr[:1000])
    assert not result.stdout
    assert b"HGUET_SANDBOX_BLOCKED" in result.stderr
    print("SKIP: runner denies required kernel namespaces; sandbox launcher fails closed")
    sys.exit(0)

assert result.returncode==20,(result.returncode,result.stderr[:2000])
data=json.loads(result.stdout)
assert list(data)==["signer_refusal"]
refusal=data["signer_refusal"]
assert refusal["signing_gate"]=="block"
assert refusal["reason_code"]=="SIGNER_SIDE_ENFORCEMENT_NOT_IMPLEMENTED"
assert refusal["independent_intent_signature_verified"] is True
assert refusal["signer_backend_invoked"] is False
assert refusal["signature_created"] is False
assert refusal["signing_permitted"] is False
assert refusal["transaction_broadcast"] is False

# The same executable must refuse even when the operator key is wrong.
wrong=list(ARGS)
wrong[-1]="11111111111111111111111111111111"
other=run(wrong,INPUT)
assert other.returncode==20,(other.returncode,other.stderr)
untrusted=json.loads(other.stdout)["signer_refusal"]
assert untrusted["reason_code"]=="SIGNED_INTENT_VERIFICATION_FAILED"
assert untrusted["independent_intent_signature_verified"] is False
assert untrusted["signing_permitted"] is False

# Executable hash is mandatory and is checked before entering bwrap.
bad=list(ARGS)
bad[bad.index("--binary-sha256")+1]="0"*64
rejected=run(bad,INPUT)
assert rejected.returncode==40
assert not rejected.stdout
assert b"hash mismatch" in rejected.stderr

print("PASS: live Bubblewrap namespaces + seccomp, inode-pinned signer, BLOCK-only result and tampered hash rejection")
