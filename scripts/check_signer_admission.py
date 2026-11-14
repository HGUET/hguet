#!/usr/bin/env python3
"""Offline peer-credential admission checks: never launch before authentication."""
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import sys
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_signer_admission as admission

PIN = "2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ"
CFG = {
    "schema_version": 1,
    "kind": "hguet_signer_admission",
    "socket_path": "/run/hguet-signer/admission.sock",
    "allowed_client_uid": 12345,
    "protected_policy": "/etc/hguet/signer-policy.json",
}
BLOCK = json.dumps({"signer_refusal": {
    "signing_gate": "block",
    "signing_permitted": False,
    "signer_backend_invoked": False,
    "signature_created": False,
    "transaction_broadcast": False,
}}).encode()


def denied(action, message=None):
    try:
        action()
    except admission.protected.sandbox.SandboxError as exc:
        if message:
            assert message in str(exc), str(exc)
    else:
        raise AssertionError("unsafe request was admitted")


with mock.patch.object(admission.protected, "_trusted_file",
                       return_value=json.dumps(CFG).encode()), \
     mock.patch.object(admission.protected, "load_operator_policy"), \
     mock.patch.object(admission.os, "geteuid", return_value=999):
    assert admission.load_admission("/etc/hguet/admission.json") == CFG
    for name, value in [
        ("allowed_client_uid", 999), ("allowed_client_uid", True),
        ("allowed_client_uid", 0), ("socket_path", "relative"),
        ("protected_policy", "relative"),
        ("schema_version", 2),
    ]:
        bad = dict(CFG, **{name: value})
        with mock.patch.object(admission.protected, "_trusted_file",
                               return_value=json.dumps(bad).encode()):
            denied(lambda: admission.load_admission("/etc/hguet/admission.json"))
    duplicate = json.dumps(CFG)[:-1] + ',"allowed_client_uid":12346}'
    with mock.patch.object(admission.protected, "_trusted_file",
                           return_value=duplicate.encode()):
        denied(lambda: admission.load_admission("/etc/hguet/admission.json"),
               "duplicate JSON")

left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    if hasattr(socket, "SO_PEERCRED"):
        pid, uid, gid = admission.peer_identity(left)
        assert pid > 0 and uid == os.geteuid() and gid == os.getegid()
    requests = []
    def fake_launch(command, **kwargs):
        requests.append((command, kwargs))
        return SimpleNamespace(returncode=20, stdout=BLOCK)

    # An unknown UID cannot even read the request, much less touch the journal.
    with mock.patch.object(admission, "peer_identity", return_value=(1, 99999, 1)), \
         mock.patch.object(admission, "read_request",
                           side_effect=AssertionError("payload read before auth")):
        denied(lambda: admission.admit_one(left, CFG, launch=fake_launch),
               "unauthorized")
    assert requests == []

    right.sendall(b'{"test":1}')
    right.shutdown(socket.SHUT_WR)
    with mock.patch.object(admission, "peer_identity",
                           return_value=(1, CFG["allowed_client_uid"], 1)):
        assert admission.admit_one(left, CFG, launch=fake_launch) == BLOCK
    assert len(requests) == 1
    command, kwargs = requests[0]
    assert "--policy" in command and command[-1] == CFG["protected_policy"]
    assert kwargs["input"] == b'{"test":1}'
    assert kwargs["close_fds"] is True
finally:
    left.close()
    right.close()

# Oversized requests must not reach the launcher; no unbounded accumulation.
a, b = socket.socketpair()
try:
    b.sendall(b"x" * (admission.MAX_REQUEST + 1))
    b.shutdown(socket.SHUT_WR)
    denied(lambda: admission.read_request(a), "64 KiB")
finally:
    a.close()
    b.close()

# Slow-drip peers: the 5 s budget is TOTAL, not per recv(). A peer sending one
# byte per interval must hit the overall deadline instead of stalling forever.
a, b = socket.socketpair()
try:
    b.sendall(b"x")  # never EOF, never more data
    with mock.patch.object(admission, "REQUEST_DEADLINE_SECONDS", 0.3):
        started = admission.time.monotonic()
        denied(lambda: admission.read_request(a), "deadline")
        assert admission.time.monotonic() - started < 3
finally:
    a.close()
    b.close()

# A malicious or faulty child response cannot pass as a BLOCK refusal.
a, b = socket.socketpair()
try:
    with mock.patch.object(admission, "peer_identity",
                           return_value=(1, CFG["allowed_client_uid"], 1)), \
         mock.patch.object(admission, "read_request", return_value=b"{}"):
        denied(lambda: admission.admit_one(
            a, CFG, launch=lambda *args, **kwargs:
            SimpleNamespace(returncode=0, stdout=BLOCK)), "expected refusal")
finally:
    a.close()
    b.close()

print("PASS: kernel peer admission blocks unauthorized UID before payload and journal, bounds input, rejects false success")
