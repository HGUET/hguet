#!/usr/bin/env python3
"""Offline checks for the split gateway/backend identity architecture."""
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
import run_signer_backend as backend

SandboxError = backend.sandbox.SandboxError
ADMISSION = {
    "schema_version": 1, "kind": "hguet_signer_admission",
    "socket_path": "/run/hguet/admission.sock", "allowed_client_uid": 12345,
    "protected_policy": "/etc/hguet/policy.json",
    "backend_socket": "/run/hguet-backend/backend.sock", "backend_uid": 777,
}
BACKEND = {
    "schema_version": 1, "kind": "hguet_signer_backend",
    "socket_path": "/run/hguet-backend/backend.sock", "allowed_gateway_uid": 888,
    "protected_policy": "/etc/hguet/policy.json",
}


def refuses(action, needle=None):
    try:
        action()
    except SandboxError as exc:
        assert needle is None or needle in str(exc), str(exc)
    else:
        raise AssertionError("unsafe configuration/request was accepted")


def load(cfg, loader, patch_module):
    with mock.patch.object(patch_module.protected, "_trusted_file", return_value=json.dumps(cfg).encode()), \
         mock.patch.object(patch_module.protected, "load_operator_policy"), \
         mock.patch.object(patch_module.os, "geteuid", return_value=999):
        return loader("/etc/hguet/x.json")


assert load(ADMISSION, admission.load_admission, admission) == ADMISSION
only_one = {k: v for k, v in ADMISSION.items() if k != "backend_uid"}
refuses(lambda: load(only_one, admission.load_admission, admission))
for field, value in (("backend_uid", 999), ("backend_uid", 12345), ("backend_uid", 0),
                     ("backend_uid", True), ("backend_socket", "relative"),
                     ("backend_socket", "/run/" + "x" * 120)):
    refuses(lambda: load(dict(ADMISSION, **{field: value}), admission.load_admission, admission))

assert load(BACKEND, backend.load_backend, backend) == BACKEND
for field, value in (("allowed_gateway_uid", 999), ("allowed_gateway_uid", 0), ("allowed_gateway_uid", True),
                     ("socket_path", "relative"), ("schema_version", 2), ("kind", "other")):
    refuses(lambda: load(dict(BACKEND, **{field: value}), backend.load_backend, backend))
refuses(lambda: load(dict(BACKEND, extra=1), backend.load_backend, backend))

# Backend authenticates the peer BEFORE reading a byte or reserving anything.
a, b = socket.socketpair()
try:
    process = mock.Mock(side_effect=AssertionError("journal touched by unauthorized peer"))
    with mock.patch.object(backend.admission, "peer_identity", return_value=(1, 4242, 1)), \
         mock.patch.object(backend.admission, "read_request", side_effect=AssertionError("payload read before auth")), \
         mock.patch.object(backend.protected, "process_request", process):
        refuses(lambda: backend.serve_one(a, BACKEND, {}), "unauthorized backend peer")
    process.assert_not_called()
    with mock.patch.object(backend.admission, "peer_identity", return_value=(1, BACKEND["allowed_gateway_uid"], 1)), \
         mock.patch.object(backend.admission, "read_request", return_value=b"{}"), \
         mock.patch.object(backend.protected, "process_request", return_value=b"ok") as process:
        assert backend.serve_one(a, BACKEND, {"p": 1}) == b"ok"
        process.assert_called_once_with({"p": 1}, b"{}")
finally:
    a.close()
    b.close()

# Gateway pins the backend's kernel UID and never trusts an impostor socket.
fake = mock.MagicMock()
with mock.patch.object(admission.socket, "socket", return_value=fake), \
     mock.patch.object(admission, "peer_identity", return_value=(1, 31337, 1)):
    refuses(lambda: admission.relay_to_backend(b"{}", ADMISSION), "pinned signer UID")
    fake.sendall.assert_not_called()

# A backend reply is re-validated; a forged approval cannot pass.
forged = json.dumps({"signer_refusal": {"signing_gate": "allow", "signing_permitted": True}}).encode()
refuses(lambda: admission.protected.sandbox.checked_refusal(forged, 20))
reply = mock.MagicMock()
reply.recv.side_effect = [b"x" * 70000]
with mock.patch.object(admission.socket, "socket", return_value=reply), \
     mock.patch.object(admission, "peer_identity", return_value=(1, ADMISSION["backend_uid"], 1)):
    refuses(lambda: admission.relay_to_backend(b"{}", ADMISSION), "too large")
dead = mock.MagicMock()
dead.connect.side_effect = FileNotFoundError()
with mock.patch.object(admission.socket, "socket", return_value=dead):
    refuses(lambda: admission.relay_to_backend(b"{}", ADMISSION), "unavailable")

# In split mode the gateway never launches the journal-reserving launcher itself.
conn = mock.MagicMock()
launch = mock.Mock(side_effect=AssertionError("gateway ran the protected launcher directly"))
with mock.patch.object(admission, "peer_identity", return_value=(1, ADMISSION["allowed_client_uid"], 1)), \
     mock.patch.object(admission, "read_request", return_value=b"{}"), \
     mock.patch.object(admission, "relay_to_backend", return_value=b"not a refusal"):
    refuses(lambda: admission.admit_one(conn, ADMISSION, launch=launch), "malformed")
launch.assert_not_called()

print("PASS: split gateway/backend config validation, peer pinning in both directions, no direct launcher in gateway")
