#!/usr/bin/env python3
"""One-request local AF_UNIX admission gate for the BLOCK-only protected signer.

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
import socket
import stat
import struct
import subprocess
import sys

import run_signer_protected as protected

MAX_REQUEST = protected.AGENT_LIMIT
ADMISSION_FIELDS = frozenset({
    "schema_version", "kind", "socket_path", "allowed_client_uid",
    "protected_policy",
})


def load_admission(path):
    data = protected._trusted_file(path)
    try:
        cfg = protected._json_strict(data)
    except (ValueError, UnicodeDecodeError, TypeError) as exc:
        raise protected.sandbox.SandboxError("invalid admission policy JSON") from exc
    if type(cfg) is not dict or set(cfg) != ADMISSION_FIELDS:
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
    connection.settimeout(5)
    chunks = []
    size = 0
    while True:
        block = connection.recv(min(8192, MAX_REQUEST + 1 - size))
        if not block:
            break
        chunks.append(block)
        size += len(block)
        if size > MAX_REQUEST:
            raise protected.sandbox.SandboxError("admission request exceeds 64 KiB")
    if not size:
        raise protected.sandbox.SandboxError("empty admission request")
    return b"".join(chunks)


def admit_one(connection, cfg, *, launch=subprocess.run):
    # No agent payload is read and no replay marker can be created before this.
    _, uid, _ = peer_identity(connection)
    if uid != cfg["allowed_client_uid"]:
        raise protected.sandbox.SandboxError("unauthorized peer UID")
    request = read_request(connection)
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
    try:
        server.bind(path)
        os.chmod(path, 0o660)
        server.listen(1)
        server.settimeout(15)
        with server.accept()[0] as connection:
            try:
                output = admit_one(connection, cfg)
                connection.sendall(output + (b"" if output.endswith(b"\n") else b"\n"))
                return 20
            except (protected.sandbox.SandboxError, OSError) as exc:
                # Never forward child stderr or claim the attempt was approved.
                try:
                    connection.sendall(b"HGUET_ADMISSION_BLOCKED\n")
                except OSError:
                    pass
                raise protected.sandbox.SandboxError("admission refused: " + str(exc)) from exc
    finally:
        server.close()
        os.umask(previous)
        # Only clean up the socket we own, not a substituted path.
        try:
            st = os.lstat(path)
            if stat.S_ISSOCK(st.st_mode) and st.st_uid == os.geteuid():
                os.unlink(path)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    try:
        sys.exit(run())
    except (protected.sandbox.SandboxError, OSError) as exc:
        print("HGUET_ADMISSION_BLOCKED: " + str(exc), file=sys.stderr)
        sys.exit(40)
