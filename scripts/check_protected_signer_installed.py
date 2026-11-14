#!/usr/bin/env python3
"""End-to-end root-provisioned prototype and unprivileged service account test.

CI stages only synthetic BLOCK-only signer bytes and public test key. This
tests protected manifest ownership and atomic replay after a real subprocess,
even when the runner kernel disallows Bubblewrap user namespaces.

The temporary test identity is 'nobody' in an ephemeral runner; production
must create a dedicated signer-only service account and private state dir.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

if len(sys.argv)!=4:
    raise SystemExit("usage: check_protected_signer_installed.py ROOT_LAUNCHER POLICY LEDGER")
launcher,policy_path,ledger_path=map(Path,sys.argv[1:])
ROOT=Path(__file__).resolve().parents[1]
wire=(ROOT/"tests/fixtures/legacy-spl-transfer-checked-authority-signer.base64").read_text().strip()
intent=json.loads((ROOT/"tests/fixtures/signed-direct-token-source-cap-equal.json").read_text())
request=json.dumps({
    "schema_version":1,"kind":"hguet_signer_preflight",
    "original_transaction_b64":wire,"signed_intent":intent,
}).encode()
args=["sudo","-n","-u","nobody","/usr/bin/python3",str(launcher),
      "--policy",str(policy_path)]

assert launcher.is_absolute() and policy_path.is_absolute() and ledger_path.is_absolute()
assert launcher.stat().st_uid==0
assert policy_path.stat().st_uid==0
assert policy_path.stat().st_mode & 0o022==0
assert ledger_path.stat().st_uid!=os.geteuid()
assert ledger_path.stat().st_mode & 0o777==0o700

# As the untrusted GitHub runner identity we should not be able to open the
# journal; it belongs to the separate test service identity.
assert not os.access(ledger_path,os.R_OK)
assert not os.access(ledger_path,os.W_OK)

def run(args,data):
    return subprocess.run(args,input=data,capture_output=True,timeout=30,check=False)

first=run(args,request)
assert first.returncode in (20,40),(first.returncode,first.stderr[:1500])
if first.returncode==20:
    obj=json.loads(first.stdout)["signer_refusal"]
    assert obj["signing_gate"]=="block"
    assert obj["signing_permitted"] is False
    assert obj["signature_created"] is False
    assert obj["transaction_broadcast"] is False
    print("PASS: live sandbox started and produced BLOCK-only refusal")
else:
    assert first.stdout==b""
    assert b"HGUET_PROTECTED_BLOCKED" in first.stderr
    # Do not call this a kernel namespace skip until we have proved the
    # one-use marker was durably allocated before the launcher failed.
    pass

# The reservation must be durable *even if* the sandbox launch failed.
listing=subprocess.run(["sudo","-n","find",str(ledger_path),
                        "-maxdepth","1","-name","*.used","-type","f"],
                       capture_output=True,text=True,check=True).stdout.strip().splitlines()
assert len(listing)==1,(
    "protected launcher refused before durable replay reservation: "+
    first.stderr.decode(errors="replace")[:1200]+"; markers="+str(listing))
marker=Path(listing[0])
marker_mode=subprocess.run(["sudo","-n","stat","-c","%a",str(marker)],
                           check=True,capture_output=True,text=True).stdout.strip()
assert marker_mode=="600",marker_mode
raw_bytes=subprocess.run(["sudo","-n","cat",str(marker)],
                         check=True,capture_output=True).stdout
assert len(raw_bytes)>64
if first.returncode==40:
    assert b"sandbox" in first.stderr.lower() or b"bubblewrap" in first.stderr.lower(),first.stderr[:1000]
    if os.environ.get("HGUET_REQUIRE_LIVE")=="1":
        raise SystemExit("FAIL: live sandbox required (HGUET_REQUIRE_LIVE=1) but runner denied it: "+
                         first.stderr.decode(errors="replace")[:300])
    print("SKIP: runner denied required sandbox; durable replay marker still present -- NOT a pass for live isolation")
# One-use identity comes from the signed intent ID, not JSON whitespace.
second=run(args,json.dumps(json.loads(request),indent=3).encode())
assert second.returncode==40,(second.returncode,second.stderr[:1000])
assert second.stdout==b""
assert b"REPLAY_BLOCKED" in second.stderr,second.stderr[:1000]
again=subprocess.run(["sudo","-n","find",str(ledger_path),
                      "-maxdepth","1","-name","*.used","-type","f"],
                     capture_output=True,text=True,check=True).stdout.strip().splitlines()
assert again==listing

# Caller cannot choose another public key or network on the protected path.
for additional in [
    ["--network","mainnet"],
    ["--trusted-key","11111111111111111111111111111111"],
    ["--binary","/tmp/evil"],
]:
    bad=run(args+additional,request)
    assert bad.returncode==40
    assert bad.stdout==b""

# Running protected launcher as UID 0 is explicitly rejected.
privileged=run(["sudo","-n","/usr/bin/python3",str(launcher),
                "--policy",str(policy_path)],request)
assert privileged.returncode==40
assert b"refusing root execution" in privileged.stderr
assert privileged.stdout==b""

print("PASS: real root-owned policy/source/ELF, other-UID service ledger, replay blocked after sandbox outcome")
