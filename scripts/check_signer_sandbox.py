#!/usr/bin/env python3
"""Host-independent tests of HGUET's Linux Bubblewrap launcher invariants.

No real device, network or signer key. Where user namespaces are unavailable,
we separately assert no process can be started without all mandatory policy.
"""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
from types import SimpleNamespace
from unittest import mock

BASE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "hguet_signer_sandbox", BASE/"run_signer_sandbox.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

for machine, arch in [("x86_64",0xC000003E),("aarch64",0xC00000B7)]:
    ins = module.seccomp_instructions(machine)
    assert ins[0] == (module.BPF_LD_W_ABS,0,0,4)
    assert ins[1] == (module.BPF_JEQ_K,1,0,arch)
    assert ins[2] == (module.BPF_RET_K,0,0,module.SECCOMP_RET_KILL_PROCESS)
    assert ins[-1] == (module.BPF_RET_K,0,0,module.SECCOMP_RET_ALLOW)
    assert len(module.seccomp_bytes(machine))==len(ins)*8
    pairs = {
        ins[j][3] for j in range(len(ins)-1) if
        ins[j][0]==module.BPF_JEQ_K and
        ins[j+1]==(module.BPF_RET_K,0,0,module.SECCOMP_RET_ERRNO|1)
    }
    assert {41,42,49,101,165,321,435}.issubset(pairs) if machine=="x86_64" else \
        {198,203,200,117,40,280,435}.issubset(pairs)
try:
    module.seccomp_instructions("i386")
except module.SandboxError:
    pass
else:
    raise AssertionError("unsupported kernel ABI cannot silently degrade")

cmd=module.make_bwrap_command(17,19,"devnet",
    "2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ")
for mandatory in (
    "--unshare-all","--unshare-user","--disable-userns","--assert-userns-disabled",
    "--new-session","--die-with-parent","--clearenv",
    "--seccomp","--ro-bind-fd","--cap-drop",
):
    assert cmd.count(mandatory)==1,mandatory
assert cmd[cmd.index("--seccomp")+1]=="19"
assert cmd[cmd.index("--ro-bind-fd")+1:cmd.index("--ro-bind-fd")+3] == [
    "17","/app/hguet-signer-isolate"]
assert cmd[cmd.index("--cap-drop")+1]=="ALL"
assert "--share-net" not in cmd
assert "--bind" not in cmd
assert "--dev-bind" not in cmd
assert "/home" not in cmd and "/etc" not in cmd
assert cmd[cmd.index("--setenv")+1]=="LANG"
assert cmd[-4:] == [
    "--network","devnet","--trusted-key",
    "2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ"]

refusal={
    "signer_refusal":{
        "signing_gate":"block","signing_permitted":False,
        "signer_backend_invoked":False,"signature_created":False,
        "transaction_broadcast":False,
        "signing_boundary":{"signing_gate":"block",
            "automated_signing_permitted":False},
    }
}
wire = json.dumps(refusal).encode()
assert module.checked_refusal(wire,20)==wire
for bad in [
    dict(refusal, signer_refusal=dict(refusal["signer_refusal"],
         signing_permitted=True)),
    dict(refusal, signer_refusal=dict(refusal["signer_refusal"],
         signer_backend_invoked=True)),
    dict(refusal, signer_refusal=dict(refusal["signer_refusal"],
         signing_boundary=dict(refusal["signer_refusal"]["signing_boundary"],
             automated_signing_permitted=True))),
]:
    try:
        module.checked_refusal(json.dumps(bad).encode(),20)
    except module.SandboxError:
        pass
    else:
        raise AssertionError("forged sandbox approval accepted")
for result in [0,1,40,139]:
    try:
        module.checked_refusal(wire,result)
    except module.SandboxError:
        pass
    else:
        raise AssertionError("sandbox setup or crash accepted as signer refusal")

with tempfile.TemporaryDirectory(prefix="hguet-sandbox-test-") as tmp:
    executable=Path(tmp)/"hguet-signer-isolate"
    original=b"synthetic executable bytes (not real binary)"
    executable.write_bytes(original)
    executable.chmod(0o700)
    pin=hashlib.sha256(original).hexdigest()
    fd=module.open_pinned_executable(str(executable),pin)
    # Move or replace original path after verification; open FD is still
    # bound to the verified original inode, eliminating path re-open races.
    moved=Path(tmp)/"original-inode"
    executable.rename(moved)
    executable.write_bytes(b"substituted untrusted executable")
    executable.chmod(0o700)
    assert os.read(fd,len(original))==original
    os.close(fd)
    try:
        module.open_pinned_executable(str(executable),pin)
    except module.SandboxError:
        pass
    else:
        raise AssertionError("replaced executable accepted")
    executable.unlink()
    executable.symlink_to(moved)
    try:
        module.open_pinned_executable(str(executable),pin)
    except module.SandboxError:
        pass
    else:
        raise AssertionError("symlink swap accepted")
    executable.unlink()
    moved.rename(executable)
    executable.chmod(0o777)
    try:
        module.open_pinned_executable(str(executable),pin)
    except module.SandboxError:
        pass
    else:
        raise AssertionError("world-writable signer accepted")
    executable.chmod(0o700)

    # Simulation of the launcher passes verified FDs, never invokes a raw
    # binary directly or silently drops bwrap/seccomp if process fails.
    fake_out=io.BytesIO()
    class FakeStdout:
        buffer=fake_out
    class FakeStdin:
        buffer=io.BytesIO(b'{"untrusted":"agent"}')
    def fake_spawn(argv, **kwargs):
        assert argv[0]==module.BWRAP_PATH
        assert argv[-5]==module.SANDBOX_EXEC
        assert kwargs["close_fds"] is True
        assert kwargs["pass_fds"] and len(kwargs["pass_fds"])==2
        for fd in kwargs["pass_fds"]:
            os.fstat(fd)
        assert kwargs["env"]=={}
        assert kwargs["input"]==b'{"untrusted":"agent"}'
        return SimpleNamespace(stdout=wire,returncode=20)
    with mock.patch.object(module,"verify_root_owned_bwrap"), \
         mock.patch.object(module.subprocess,"run",side_effect=fake_spawn), \
         mock.patch.object(module.sys,"stdin",FakeStdin()), \
         mock.patch.object(module.sys,"stdout",FakeStdout()):
        status=module.run([
            "--binary",str(executable),"--binary-sha256",pin,
            "--network","devnet","--trusted-key",
            "2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ",
        ])
    assert status==20 and json.loads(fake_out.getvalue())==refusal

    with mock.patch.object(module,"verify_root_owned_bwrap",
                           side_effect=module.SandboxError("bubblewrap unavailable")), \
         mock.patch.object(module.subprocess,"run",
                           side_effect=AssertionError("unsafe fallback invoked")):
        try:
            module.run([
                "--binary",str(executable),"--binary-sha256",pin,
                "--network","devnet","--trusted-key",
                "2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ",
            ])
        except module.SandboxError:
            pass
        else:
            raise AssertionError("missing bwrap must be fail-closed")

print("PASS: pinned FD, mandatory namespaces+seccomp, no unsafe fallback, forged approval rejection")
