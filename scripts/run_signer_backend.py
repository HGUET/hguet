#!/usr/bin/env python3
"""Signer backend: the ONLY process that owns the replay journal (BLOCK-only).

Split-identity deployment of the admission architecture:

  client UID --> gateway UID (admission allow-list, SO_PEERCRED)
                     |  Unix socket, SO_PEERCRED pinned both directions
                     v
                 signer-backend UID (journal owner) --> Bubblewrap --> BLOCK

The gateway account can no longer run the protected launcher itself: the replay
directory belongs to the backend UID (mode 0700), so a compromised or abused
gateway cannot reserve intents or skip admission through a direct launcher run.
Callers that are not the pinned gateway UID are refused before any payload byte
is read. It never signs, holds a key, or broadcasts. It is NOT user
authentication: the gateway UID is still trusted to apply the client allow-list.
"""
from __future__ import annotations

import os
from pathlib import Path
import signal
import socket
import stat
import sys

import run_signer_admission as admission
import run_signer_protected as protected

sandbox = protected.sandbox
BACKEND_FIELDS = frozenset({
    "schema_version", "kind", "socket_path", "allowed_gateway_uid", "protected_policy",
})
BLOCKED_REPLY = b"HGUET_BACKEND_BLOCKED\n"


def load_backend(path):
    data = protected._trusted_file(path)
    try:
        cfg = protected._json_strict(data)
    except (ValueError, UnicodeDecodeError, TypeError) as exc:
        raise sandbox.SandboxError("invalid backend policy JSON") from exc
    if type(cfg) is not dict or set(cfg) != BACKEND_FIELDS:
        raise sandbox.SandboxError("invalid backend policy fields")
    if cfg["schema_version"] != 1 or cfg["kind"] != "hguet_signer_backend":
        raise sandbox.SandboxError("unsupported backend policy")
    uid = cfg["allowed_gateway_uid"]
    if type(uid) is not int or uid <= 0:
        raise sandbox.SandboxError("invalid allowed gateway UID")
    if uid == os.geteuid():
        raise sandbox.SandboxError("gateway and signer backend must have distinct UIDs")
    for key in ("socket_path", "protected_policy"):
        if type(cfg[key]) is not str or not os.path.isabs(cfg[key]):
            raise sandbox.SandboxError("backend paths must be absolute")
    if Path(cfg["socket_path"]).name in ("", ".", ".."):
        raise sandbox.SandboxError("invalid socket filename")
    if len(os.fsencode(cfg["socket_path"])) >= 104:
        raise sandbox.SandboxError("Unix socket path too long")
    protected.load_operator_policy(cfg["protected_policy"])
    return cfg


def serve_one(connection, cfg, policy):
    """Authenticate the peer FIRST; only then read bytes or touch the journal."""
    _, uid, _ = admission.peer_identity(connection)
    if uid != cfg["allowed_gateway_uid"]:
        raise sandbox.SandboxError("unauthorized backend peer UID")
    request = admission.read_request(connection)
    return protected.process_request(policy, request)


def _verify_self():
    path = Path(__file__).absolute()
    protected._secure_ancestors(str(path.parent), {0})
    fd = os.open(path, os.O_RDONLY | protected.NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise sandbox.SandboxError("backend code must be root-owned and protected")
    finally:
        os.close(fd)


def run(argv=None):
    if sys.platform != "linux" or os.geteuid() == 0:
        raise sandbox.SandboxError("backend requires Linux and a non-root signer UID")
    parser = sandbox.Exit40Parser(description="BLOCK-only signer backend (journal owner)")
    parser.add_argument("--backend", required=True)
    parser.add_argument("--once", action="store_true", help="serve one connection and exit")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    protected._verify_launcher_install()
    sandbox.verify_root_owned_bwrap()
    _verify_self()
    cfg = load_backend(args.backend)
    policy = protected.load_operator_policy(cfg["protected_policy"])
    path = cfg["socket_path"]
    admission.verify_socket_parent(path)
    # Let `finally` remove our socket on service stop (systemctl stop / kill).
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    previous = os.umask(0o117)
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    bound_inode = None
    try:
        server.bind(path)
        bound = os.lstat(path)
        bound_inode = (bound.st_dev, bound.st_ino)
        os.chmod(path, 0o660)
        server.listen(4)
        status = 0
        while True:
            if args.once:
                server.settimeout(15)
            connection = server.accept()[0]
            with connection:
                connection.settimeout(admission.SEND_TIMEOUT_SECONDS)
                try:
                    output = serve_one(connection, cfg, policy)
                    connection.sendall(output + (b"" if output.endswith(b"\n") else b"\n"))
                    status = 20
                except (sandbox.SandboxError, OSError) as exc:
                    try:
                        connection.sendall(BLOCKED_REPLY)
                    except OSError:
                        pass
                    print("HGUET_BACKEND_REFUSED: " + str(exc), file=sys.stderr)
                    status = 40
            if args.once:
                return status
    finally:
        server.close()
        os.umask(previous)
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
    except (sandbox.SandboxError, OSError) as exc:
        print("HGUET_BACKEND_BLOCKED: " + str(exc), file=sys.stderr)
        sys.exit(40)
