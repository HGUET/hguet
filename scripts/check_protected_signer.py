#!/usr/bin/env python3
"""Purely offline tests for protected operator policy and durable replay journal.

No wallets, RPC, network, private keys or real Linux sandbox needed. The
actual root-owned installed launcher is a separate deployment acceptance test.
"""
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"scripts"))
spec = importlib.util.spec_from_file_location(
    "hguet_protected", ROOT/"scripts/run_signer_protected.py")
protected = importlib.util.module_from_spec(spec)
spec.loader.exec_module(protected)

PIN = "2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ"
RAW = (ROOT/"tests/fixtures/legacy-spl-transfer-checked-authority-signer.base64").read_text().strip()
ENVELOPE = json.loads((ROOT/"tests/fixtures/signed-direct-token-source-cap-equal.json").read_text())
REQUEST = {
    "schema_version":1,"kind":"hguet_signer_preflight",
    "original_transaction_b64":RAW,"signed_intent":ENVELOPE,
}
def json_bytes(data):
    return json.dumps(data, separators=(",", ":")).encode()
def required_policy(binary, digest, ledger):
    return {
        "schema_version":1,"kind":"hguet_protected_signer_policy",
        "binary":str(binary),"binary_sha256":digest,
        "network":"devnet","trusted_key":PIN,
        "replay_directory":str(ledger),
    }
def denied(call, fragment=None):
    try:
        call()
    except protected.sandbox.SandboxError as error:
        if fragment:
            assert fragment in str(error),str(error)
        return
    raise AssertionError("fail-closed protected signer unexpectedly accepted unsafe input")

with tempfile.TemporaryDirectory(prefix="hguet-protected-test-") as temp:
    root=Path(temp)
    binary=root/"hguet-signer-isolate"
    binary.write_bytes(b"offline synthetic no-wallet binary")
    binary.chmod(0o700)
    digest=hashlib.sha256(binary.read_bytes()).hexdigest()
    ledger=root/"replay"
    ledger.mkdir(mode=0o700)
    policy=required_policy(binary,digest,ledger)
    # In test check only replay store correctness. A production launcher must
    # have a ROOT-owned, nonwritable install/manifest; tests cannot fake one.
    with mock.patch.object(protected,"_trusted_file",return_value=json_bytes(policy)), \
         mock.patch.object(protected,"_verify_protected_binary_install"):
        assert protected.load_operator_policy("/etc/hguet/signer-policy.json")==policy
        for name,bad in [
            ("binary_sha256","0"*64),
            ("network","unknown"),
            ("replay_directory","relative/path"),
            ("schema_version",2),
        ]:
            altered=dict(policy,**{name:bad})
            with mock.patch.object(protected,"_trusted_file",return_value=json_bytes(altered)), \
                 mock.patch.object(protected,"_verify_protected_binary_install"):
                denied(lambda: protected.load_operator_policy("/etc/hguet/signer-policy.json"))
        for k in ["allow","rpc_url","trusted_time","wallet_key","policy_overrides"]:
            altered=dict(policy,**{k:True})
            with mock.patch.object(protected,"_trusted_file",return_value=json_bytes(altered)), \
                 mock.patch.object(protected,"_verify_protected_binary_install"):
                denied(lambda: protected.load_operator_policy("/etc/hguet/signer-policy.json"),
                       "unexpected/missing")
        duplicate=json_bytes(policy)[:-1]+b',"network":"mainnet"}'
        with mock.patch.object(protected,"_trusted_file",return_value=duplicate), \
             mock.patch.object(protected,"_verify_protected_binary_install"):
            denied(lambda: protected.load_operator_policy("/etc/hguet/signer-policy.json"),
                   "duplicate JSON key")

    # Root-owned ELF ancestry must be enforced independently of its SHA-256.
    # This temporary fixture belongs to the runner user, not to root.
    if os.geteuid()!=0:
        with mock.patch.object(protected,"_secure_ancestors"):
            denied(lambda: protected._verify_protected_binary_install(str(binary)),
                   "root-owned")
    with mock.patch.object(protected.os,"geteuid",return_value=0):
        denied(lambda: protected.run(["--policy","/etc/hguet/signer-policy.json"],
                                   stdin=io.BytesIO(json_bytes(REQUEST))),
               "refusing root execution")

    correct_identity=protected._parse_replay_identity(json_bytes(REQUEST),policy)
    assert len(correct_identity)==64
    # Changes in JSON formatting do not yield a new one-use identifier.
    pretty=json.dumps(REQUEST,indent=2).encode()
    assert protected._parse_replay_identity(pretty,policy)==correct_identity
    # Changing only transaction bytes does not reset signed intent_id replay.
    altered=dict(REQUEST,original_transaction_b64=base64.b64encode(b"different").decode())
    assert protected._parse_replay_identity(json_bytes(altered),policy)==correct_identity
    # Changing the *signed* intent-id would make a new identifier, but would
    # also invalidate Ed25519; Rust preflight will refuse it.
    signed_payload=json.loads(base64.b64decode(ENVELOPE["payload_b64"]))
    signed_payload["intent_id"]+="--invalid-signature"
    different=json.loads(json.dumps(REQUEST))
    different["signed_intent"]["payload_b64"]=base64.b64encode(
        json_bytes(signed_payload)).decode()
    assert protected._parse_replay_identity(json_bytes(different),policy)!=correct_identity

    for field,value in [
        ("trusted_key", PIN),("network","mainnet"),("allow",True),
        ("rpc_result",{"status":"success"}),("device_command","sign"),
        ("now_unix",1),
    ]:
        denied(lambda field=field,value=value: protected._parse_replay_identity(
            json_bytes(dict(REQUEST,**{field:value})),policy))
    bad=json_bytes(REQUEST).replace(
        b'"schema_version":1,',b'"schema_version":1,"schema_version":1,',1)
    denied(lambda: protected._parse_replay_identity(bad,policy),"duplicate JSON key")
    denied(lambda: protected._parse_replay_identity(b" "*(65536+1),policy),"too large")
    denied(lambda: protected._parse_replay_identity(b"{",policy),"invalid replay")
    altered=json.loads(json.dumps(REQUEST))
    altered["signed_intent"]["signer_pubkey_b58"]="11111111111111111111111111111111"
    denied(lambda: protected._parse_replay_identity(json_bytes(altered),policy),"conflicts")
    altered=json.loads(json.dumps(REQUEST))
    altered["original_transaction_b64"]=RAW+"\n"
    denied(lambda: protected._parse_replay_identity(json_bytes(altered),policy))

    # Verify actual atomic O_EXCL journal semantics under simultaneous calls.
    # /tmp's parent is agent-writable, so only the ancestry rule is mocked;
    # this cannot claim an installed protected service is validated.
    with mock.patch.object(protected,"_secure_ancestors"):
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures=[pool.submit(protected.reserve_once,str(ledger),correct_identity)
                     for _ in range(8)]
            results=[]
            for task in futures:
                try:
                    results.append(("ok",task.result()))
                except protected.sandbox.SandboxError as e:
                    results.append(("blocked",str(e)))
        assert sum(x[0]=="ok" for x in results)==1,results
        assert sum(x[0]=="blocked" for x in results)==7,results
        marker=ledger/(correct_identity+".used")
        assert marker.exists()
        assert marker.stat().st_mode & 0o777 == 0o600
        assert correct_identity in marker.read_text()
        denied(lambda: protected.reserve_once(str(ledger),correct_identity),
               "REPLAY_BLOCKED")
        # Different intent can reserve independently but no marker can be
        # removed/released as a result of a sandbox failure.
        different_id=protected._parse_replay_identity(json_bytes(different),policy)
        assert protected.reserve_once(str(ledger),different_id).endswith(".used")
        denied(lambda: protected.reserve_once(str(ledger),different_id),"REPLAY_BLOCKED")
        assert len(list(ledger.glob("*.used")))==2

    # Test the orchestration with an actual ledger and a mocked BLOCK-only
    # OS launch. No request can trigger subprocess on the second attempt.
    second_dir=root/"other-ledger"
    second_dir.mkdir(mode=0o700)
    separate_policy=dict(policy,replay_directory=str(second_dir))
    blocked_output=json_bytes({"signer_refusal":{
        "signing_gate":"block","signing_permitted":False,
        "signer_backend_invoked":False,"signature_created":False,
        "transaction_broadcast":False,
        "signing_boundary":{"signing_gate":"block","automated_signing_permitted":False},
    }})
    seen=[]
    def fake_spawn(argv,**kwargs):
        assert argv[0]==sys.executable
        assert argv[1].endswith("/run_signer_sandbox.py")
        assert "--trusted-key" in argv and argv[-1]==PIN
        assert "--binary-sha256" in argv
        assert kwargs["input"]==json_bytes(REQUEST)
        seen.append(argv)
        return SimpleNamespace(stdout=blocked_output,returncode=20)
    class FakeStdin:
        def __init__(self,data):
            self.buffer=io.BytesIO(data)
    class FakeStdout:
        def __init__(self):
            self.buffer=io.BytesIO()
    with mock.patch.object(protected,"_verify_launcher_install"), \
         mock.patch.object(protected.sandbox,"verify_root_owned_bwrap"), \
         mock.patch.object(protected,"load_operator_policy",return_value=separate_policy), \
         mock.patch.object(protected,"_secure_ancestors"), \
         mock.patch.object(protected.subprocess,"run",side_effect=fake_spawn), \
         mock.patch.object(protected.sys,"stdin",FakeStdin(json_bytes(REQUEST))), \
         mock.patch.object(protected.sys,"stdout",FakeStdout()) as output:
        assert protected.run(["--policy","/etc/hguet/signer-policy.json"])==20
        assert json.loads(output.buffer.getvalue())["signer_refusal"]["signing_gate"]=="block"
    assert len(seen)==1
    with mock.patch.object(protected,"_verify_launcher_install"), \
         mock.patch.object(protected.sandbox,"verify_root_owned_bwrap"), \
         mock.patch.object(protected,"load_operator_policy",return_value=separate_policy), \
         mock.patch.object(protected,"_secure_ancestors"), \
         mock.patch.object(protected.subprocess,"run",side_effect=AssertionError("replay reached sandbox")), \
         mock.patch.object(protected.sys,"stdin",FakeStdin(pretty)):
        denied(lambda: protected.run(["--policy","/etc/hguet/signer-policy.json"]),
               "REPLAY_BLOCKED")
    assert len(seen)==1

    # A runtime failure after reservation can NEVER free the one-use slot.
    fail_dir=root/"fail-ledger"
    fail_dir.mkdir(mode=0o700)
    fail_policy=dict(policy,replay_directory=str(fail_dir))
    with mock.patch.object(protected,"_verify_launcher_install"), \
         mock.patch.object(protected.sandbox,"verify_root_owned_bwrap"), \
         mock.patch.object(protected,"load_operator_policy",return_value=fail_policy), \
         mock.patch.object(protected,"_secure_ancestors"), \
         mock.patch.object(protected.subprocess,"run",
                           side_effect=OSError("sandbox unavailable")), \
         mock.patch.object(protected.sys,"stdin",FakeStdin(json_bytes(REQUEST))):
        denied(lambda: protected.run(["--policy","/etc/hguet/signer-policy.json"]),
               "replay marker retained")
    assert (fail_dir/(correct_identity+".used")).exists()


    # Storage durability failures are terminal. A partially created marker is
    # deliberately never deleted, even when fsync reports an I/O error.
    for fsync_failure in ("marker", "directory"):
        broken_dir = root/("io-failure-" + fsync_failure)
        broken_dir.mkdir(mode=0o700)
        broken_policy = dict(policy, replay_directory=str(broken_dir))
        calls = [0]
        real_fsync = os.fsync

        def failing_fsync(fd):
            calls[0] += 1
            if (fsync_failure == "marker" and calls[0] == 1) or (
                fsync_failure == "directory" and calls[0] == 2
            ):
                raise OSError("simulated durable storage failure")
            return real_fsync(fd)

        with mock.patch.object(protected, "_verify_launcher_install"), \
             mock.patch.object(protected.sandbox, "verify_root_owned_bwrap"), \
             mock.patch.object(protected, "load_operator_policy", return_value=broken_policy), \
             mock.patch.object(protected, "_secure_ancestors"), \
             mock.patch.object(protected.os, "fsync", side_effect=failing_fsync), \
             mock.patch.object(protected.subprocess, "run",
                               side_effect=AssertionError("signer launched after fsync failure")), \
             mock.patch.object(protected.sys, "stdin", FakeStdin(json_bytes(REQUEST))):
            denied(lambda: protected.run(["--policy", "/etc/hguet/signer-policy.json"]),
                   "REPLAY_STORAGE_UNAVAILABLE")
        assert calls[0] == (1 if fsync_failure == "marker" else 2)
        assert (broken_dir/(correct_identity+".used")).exists()
        with mock.patch.object(protected, "_secure_ancestors"):
            denied(lambda: protected.reserve_once(str(broken_dir), correct_identity),
                   "REPLAY_BLOCKED")

print("PASS: operator policy rejects overrides, durable single-use intent replay is atomic, failures never release journal slot")
