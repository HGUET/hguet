#!/usr/bin/env python3
"""Local AF_UNIX admission gate (serves until SIGTERM; --once for one request) for the BLOCK-only protected signer.

Linux-only prototype. The gate runs under the dedicated signer-service UID,
authenticates the connecting process with kernel SO_PEERCRED BEFORE invoking
the replay-reserving protected launcher. It never signs or broadcasts.
The agent must not share the service UID or control service-owned paths.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
import subprocess
import sys
import time

import run_signer_protected as protected

MAX_REQUEST = protected.AGENT_LIMIT
# Total wall-clock budget for receiving one request (defeats slow-drip peers).
REQUEST_DEADLINE_SECONDS = 5.0
SEND_TIMEOUT_SECONDS = 5.0
ADMISSION_FIELDS = frozenset({
    "schema_version", "kind", "socket_path", "allowed_client_uid",
    "protected_policy",
})
# Optional split-identity mode: relay to a signer backend that owns the replay
# journal under a DIFFERENT UID. Both fields must be present together.
BACKEND_FIELDS = frozenset({"backend_socket", "backend_uid"})
BACKEND_DEADLINE_SECONDS = 25.0


def load_admission(path):
    data = protected._trusted_file(path)
    try:
        cfg = protected._json_strict(data)
    except (ValueError, UnicodeDecodeError, TypeError) as exc:
        raise protected.sandbox.SandboxError("invalid admission policy JSON") from exc
    if type(cfg) is not dict or not (set(cfg) == ADMISSION_FIELDS
            or set(cfg) == ADMISSION_FIELDS | BACKEND_FIELDS):
        raise protected.sandbox.SandboxError("invalid admission policy fields")
    if cfg["schema_version"] != 1 or cfg["kind"] != "hguet_signer_admission":
        raise protected.sandbox.SandboxError("unsupported admission policy")
    if type(cfg["allowed_client_uid"]) is not int or cfg["allowed_client_uid"] <= 0:
        raise protected.sandbox.SandboxError("invalid allowed client UID")
    if cfg["allowed_client_uid"] == os.geteuid():
        raise protected.sandbox.SandboxError("client and signer service must have distinct UIDs")
    for key in ("socket_path", "protected_policy"):
        if type(cfg[key]) is not str or not os.path.isabs(cfg[key]):
            raise protected.sandbox.SandboxError("admission paths must be absolute")
    if Path(cfg["socket_path"]).name in ("", ".", ".."):
        raise protected.sandbox.SandboxError("invalid socket filename")
    if len(os.fsencode(cfg["socket_path"])) >= 104:
        raise protected.sandbox.SandboxError("Unix socket path too long")
    if "backend_socket" in cfg:
        if type(cfg["backend_uid"]) is not int or cfg["backend_uid"] <= 0:
            raise protected.sandbox.SandboxError("invalid backend UID")
        if cfg["backend_uid"] in (os.geteuid(), cfg["allowed_client_uid"]):
            raise protected.sandbox.SandboxError("backend UID must differ from gateway and client UIDs")
        if type(cfg["backend_socket"]) is not str or not os.path.isabs(cfg["backend_socket"]) \
           or len(os.fsencode(cfg["backend_socket"])) >= 104:
            raise protected.sandbox.SandboxError("invalid backend socket path")
    # Validate root-controlled signing policy before exposing the socket.
    protected.load_operator_policy(cfg["protected_policy"])
    return cfg


def verify_socket_parent(path):
    parent = os.path.dirname(path)
    protected._secure_ancestors(os.path.dirname(parent), {0})
    st = os.lstat(parent)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o007 or st.st_mode & 0o020:
        raise protected.sandbox.SandboxError("socket directory must be service-owned, non-world-accessible and non-group-writable")
    # A pre-existing pathname is a configuration error; never unlink it.
    if os.path.lexists(path):
        raise protected.sandbox.SandboxError("admission socket path already exists")


def peer_identity(connection):
    if not hasattr(socket, "SO_PEERCRED"):
        raise protected.sandbox.SandboxError("SO_PEERCRED unavailable")
    raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    if len(raw) != 12:
        raise protected.sandbox.SandboxError("invalid kernel peer credentials")
    pid, uid, gid = struct.unpack("3i", raw)
    if pid <= 0 or uid < 0 or gid < 0:
        raise protected.sandbox.SandboxError("invalid kernel peer identity")
    return pid, uid, gid


def read_request(connection):
    deadline = time.monotonic() + REQUEST_DEADLINE_SECONDS
    chunks = []
    size = 0
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise protected.sandbox.SandboxError("admission request deadline exceeded")
        connection.settimeout(remaining)
        try:
            block = connection.recv(min(8192, MAX_REQUEST + 1 - size))
        except socket.timeout as exc:
            raise protected.sandbox.SandboxError("admission request deadline exceeded") from exc
        if not block:
            break
        chunks.append(block)
        size += len(block)
        if size > MAX_REQUEST:
            raise protected.sandbox.SandboxError("admission request exceeds 64 KiB")
    if not size:
        raise protected.sandbox.SandboxError("empty admission request")
    return b"".join(chunks)


def relay_to_backend(request, cfg):
    """Forward to the journal-owning backend; pin ITS kernel-reported UID."""
    deadline = time.monotonic() + BACKEND_DEADLINE_SECONDS
    link = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        link.settimeout(5)
        link.connect(cfg["backend_socket"])
        _, uid, _ = peer_identity(link)
        if uid != cfg["backend_uid"]:
            raise protected.sandbox.SandboxError("backend socket is not owned by the pinned signer UID")
        link.settimeout(5)
        link.sendall(request)
        link.shutdown(socket.SHUT_WR)
        chunks, size = [], 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise protected.sandbox.SandboxError("signer backend deadline exceeded")
            link.settimeout(remaining)
            block = link.recv(8192)
            if not block:
                break
            chunks.append(block)
            size += len(block)
            if size > protected.sandbox.MAX_OUTPUT_BYTES:
                raise protected.sandbox.SandboxError("signer backend reply too large")
        return b"".join(chunks)
    except socket.timeout as exc:
        raise protected.sandbox.SandboxError("signer backend timed out") from exc
    except OSError as exc:
        raise protected.sandbox.SandboxError("signer backend unavailable") from exc
    finally:
        link.close()


def admit_one(connection, cfg, *, launch=subprocess.run):
    # No agent payload is read and no replay marker can be created before this.
    _, uid, _ = peer_identity(connection)
    if uid != cfg["allowed_client_uid"]:
        raise protected.sandbox.SandboxError("unauthorized peer UID")
    request = read_request(connection)
    if "backend_socket" in cfg:
        return protected.sandbox.checked_refusal(relay_to_backend(request, cfg), 20)
    command = [
        "/usr/bin/python3", "-E", "-s",
        str(Path(protected.__file__).absolute()),
        "--policy", cfg["protected_policy"],
    ]
    try:
        result = launch(command, input=request, capture_output=True, check=False,
                        close_fds=True, timeout=25, env={"LANG": "C"})
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise protected.sandbox.SandboxError("protected subprocess failed") from exc
    output = protected.sandbox.checked_refusal(result.stdout, result.returncode)
    return output


def run(argv=None):
    if sys.platform != "linux" or os.geteuid() == 0:
        raise protected.sandbox.SandboxError("admission requires Linux and non-root service UID")
    parser = protected.sandbox.Exit40Parser(description="one-shot kernel-credential admission for BLOCK-only signer")
    parser.add_argument("--admission", required=True)
    parser.add_argument("--once", action="store_true",
                        help="serve one connection then exit; default serves until SIGTERM")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    protected._verify_launcher_install()
    admission_source = Path(__file__).absolute()
    protected._secure_ancestors(str(admission_source.parent), {0})
    fd = os.open(admission_source, os.O_RDONLY | protected.NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise protected.sandbox.SandboxError("admission code must be root-owned and protected")
    finally:
        os.close(fd)
    cfg = load_admission(args.admission)
    path = cfg["socket_path"]
    verify_socket_parent(path)
    previous = os.umask(0o117)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    bound_inode = None
    try:
        server.bind(path)
        bound = os.lstat(path)
        bound_inode = (bound.st_dev, bound.st_ino)
        os.chmod(path, 0o660)
        server.listen(8)
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
        status = 0
        while True:
            if args.once:
                server.settimeout(15)
            with server.accept()[0] as connection:
                connection.settimeout(SEND_TIMEOUT_SECONDS)
                try:
                    output = admit_one(connection, cfg)
                    connection.sendall(output + (b"" if output.endswith(b"\n") else b"\n"))
                    status = 20
                except (protected.sandbox.SandboxError, OSError) as exc:
                    # Never forward child stderr or claim the attempt was approved.
                    try:
                        connection.sendall(b"HGUET_ADMISSION_BLOCKED\n")
                    except OSError:
                        pass
                    print("HGUET_ADMISSION_BLOCKED: admission refused: " + str(exc), file=sys.stderr)
                    status = 40
            if args.once:
                # One-shot mode: a refused peer ends the run (used by tests).
                return status
    finally:
        server.close()
        os.umask(previous)
        # Only unlink the exact socket inode THIS process bound. A failed bind
        # (pre-existing path) or a substituted path is never removed.
        if bound_inode is not None:
            try:
                st = os.lstat(path)
                if stat.S_ISSOCK(st.st_mode) and (st.st_dev, st.st_ino) == bound_inode:
                    os.unlink(path)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    try:
        sys.exit(run())
    except (protected.sandbox.SandboxError, OSError) as exc:
        print("HGUET_ADMISSION_BLOCKED: " + str(exc), file=sys.stderr)
        sys.exit(40)
