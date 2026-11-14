#!/usr/bin/env python3
"""Operator-provisioned, one-use, BLOCK-only Linux signer launcher.

Mandatory root-owned policy AND root-owned Python launcher tree, separate
service-owned durable replay directory, then the existing Bubblewrap sandbox.
No device/signature API. No agent-supplied network/pin/digest/ledger override.

This is an offline development security prototype, not customer key custody.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

import run_signer_sandbox as sandbox

POLICY_LIMIT = 4096
AGENT_LIMIT = sandbox.MAX_AGENT_BYTES
NOFOLLOW = os.O_NOFOLLOW | os.O_CLOEXEC
POLICY_FIELDS = frozenset({
    "schema_version", "kind", "binary", "binary_sha256", "network",
    "trusted_key", "replay_directory",
})
INTENT_FIELDS = frozenset({
    "schema_version", "kind", "intent_id", "network", "message_sha256",
    "not_before_unix", "expires_at_unix", "allowed_program_ids",
    "max_spend_lamports", "token_spend_limits", "token_source_limits",
})


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise sandbox.SandboxError("duplicate JSON key refused")
        result[key] = value
    return result


def _json_strict(data):
    return json.loads(data, object_pairs_hook=_reject_duplicates,
                      parse_constant=lambda _: (_ for _ in ()).throw(
                          sandbox.SandboxError("nonfinite JSON value refused")))


def _secure_ancestors(path, owners):
    """Prevent writable ancestor replacement of a trusted policy/script dir."""
    if not os.path.isabs(path):
        raise sandbox.SandboxError("trusted path must be absolute")
    current = Path(path)
    for directory in [current, *current.parents]:
        if directory == Path("/"):
            continue
        info = os.lstat(directory)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners or info.st_mode & 0o022:
            raise sandbox.SandboxError(
                "untrusted or writable ancestor of protected path: "+
                str(directory)+" (uid="+str(info.st_uid)+
                ", mode="+oct(stat.S_IMODE(info.st_mode))+")")


def _trusted_file(path):
    if not os.path.isabs(path):
        raise sandbox.SandboxError("operator policy path must be absolute")
    _secure_ancestors(os.path.dirname(path), {0})
    fd = os.open(path, os.O_RDONLY | NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise sandbox.SandboxError("protected policy/code must be root-owned and immutable to agents")
        value = os.read(fd, POLICY_LIMIT + 1)
        if len(value) > POLICY_LIMIT:
            raise sandbox.SandboxError("trusted policy exceeds fixed size")
        return value
    finally:
        os.close(fd)


def _verify_launcher_install():
    # A writable Python module could simply remove all checks. Require both
    # the launcher and the Bubblewrap implementation and all parent dirs to
    # be installed by an administrator, not agent-writable source checkout.
    here = Path(__file__).absolute()
    other = here.with_name("run_signer_sandbox.py")
    if here.is_symlink() or other.is_symlink():
        raise sandbox.SandboxError("protected launcher cannot be a symlink")
    for item in (str(here), str(other)):
        _secure_ancestors(os.path.dirname(item), {0})
        fd = os.open(item, os.O_RDONLY | NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise sandbox.SandboxError("protected launcher source must be root-owned and immutable to agents")
        finally:
            os.close(fd)


def _verify_protected_binary_install(binary):
    # FD pinning stops pathname swaps but NOT in-place writes to the same
    # inode. Root ownership and protected ancestor directories are mandatory
    # for the protected service so its unprivileged UID cannot write the ELF.
    _secure_ancestors(os.path.dirname(binary), {0})
    fd = os.open(binary, os.O_RDONLY | NOFOLLOW)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or \
           st.st_mode & 0o022 or not st.st_mode & 0o111:
            raise sandbox.SandboxError(
                "protected executable must be root-owned, executable and immutable to signer service")
    finally:
        os.close(fd)


def load_operator_policy(path):
    data = _trusted_file(path)
    try:
        cfg = _json_strict(data)
    except (UnicodeDecodeError, ValueError, TypeError) as error:
        raise sandbox.SandboxError("invalid protected operator JSON") from error
    if type(cfg) is not dict or set(cfg) != POLICY_FIELDS:
        raise sandbox.SandboxError("operator policy has unexpected/missing fields")
    if cfg["schema_version"] != 1 or cfg["kind"] != "hguet_protected_signer_policy":
        raise sandbox.SandboxError("unknown operator policy version")
    if any(type(cfg[key]) is not str for key in
           ("binary", "binary_sha256", "network", "trusted_key", "replay_directory")):
        raise sandbox.SandboxError("operator policy strings expected")
    if cfg["network"] not in ("mainnet", "devnet", "testnet"):
        raise sandbox.SandboxError("untrusted operator network")
    if not cfg["binary"].startswith("/") or not cfg["replay_directory"].startswith("/"):
        raise sandbox.SandboxError("absolute operator paths are mandatory")
    # The executable's inode must be administrator-owned as well as hashed.
    # Otherwise its *contents* could change while the verified FD is open.
    _verify_protected_binary_install(cfg["binary"])
    fd = sandbox.open_pinned_executable(cfg["binary"], cfg["binary_sha256"])
    os.close(fd)
    sandbox.make_bwrap_command(7, 8, cfg["network"], cfg["trusted_key"])
    return cfg


def _parse_replay_identity(request, policy):
    if len(request) > AGENT_LIMIT:
        raise sandbox.SandboxError("agent request too large")
    try:
        agent = _json_strict(request)
        if type(agent) is not dict or set(agent) != {
            "schema_version", "kind", "original_transaction_b64", "signed_intent"
        } or agent["schema_version"] != 1 or agent["kind"] != "hguet_signer_preflight":
            raise ValueError("invalid agent request shape")
        envelope = agent["signed_intent"]
        if type(envelope) is not dict or set(envelope) != {
            "payload_b64", "signer_pubkey_b58", "signature_b58"
        }:
            raise ValueError("invalid envelope shape")
        if any(type(v) is not str for v in envelope.values()) or \
           type(agent["original_transaction_b64"]) is not str:
            raise ValueError("invalid envelope input")
        if len(agent["original_transaction_b64"]) > (16384+2)//3*4+4:
            raise ValueError("raw transaction too large")
        original_data = base64.b64decode(agent["original_transaction_b64"], validate=True)
        if not original_data or len(original_data) > 16384 or \
           base64.b64encode(original_data).decode() != agent["original_transaction_b64"]:
            raise ValueError("noncanonical original transaction")
        if len(envelope["payload_b64"]) > (16384+2)//3*4+4:
            raise ValueError("signed payload too large")
        signed_data = base64.b64decode(envelope["payload_b64"], validate=True)
        if len(signed_data) > 16384 or base64.b64encode(signed_data).decode() != \
           envelope["payload_b64"]:
            raise ValueError("noncanonical signed payload")
        intent = _json_strict(signed_data)
        required = {
            "schema_version", "kind", "intent_id", "network", "message_sha256",
            "not_before_unix", "expires_at_unix", "allowed_program_ids",
            "max_spend_lamports",
        }
        if type(intent) is not dict or not INTENT_FIELDS.issuperset(intent) or \
           not required.issubset(intent) or \
           intent.get("schema_version") != 1 or intent.get("kind") != "hguet_payment_intent":
            raise ValueError("invalid intent structure")
        intent_id = intent.get("intent_id")
        if type(intent_id) is not str or not (1 <= len(intent_id.encode("utf-8")) <= 128):
            raise ValueError("invalid intent identifier")
        if intent.get("network") != policy["network"] or \
           envelope["signer_pubkey_b58"] != policy["trusted_key"]:
            raise sandbox.SandboxError("agent intent conflicts with operator trust")
        # This is a reservation identifier, not an assertion that the signature
        # is valid. The sandboxed Ed25519 verifier still independently checks it.
        data = ["hguet-protected-intent-id-v1", policy["network"],
                policy["trusted_key"], intent_id]
        canonical = json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode()
        return hashlib.sha256(canonical).hexdigest()
    except (UnicodeDecodeError, ValueError, TypeError, KeyError, binascii.Error) as error:
        raise sandbox.SandboxError("invalid replay identity or request") from error


def _open_replay_directory(directory):
    # The launcher is intended to run under a separate dedicated unprivileged
    # service account. The state belongs to that service, NOT to the agent.
    if not os.path.isabs(directory):
        raise sandbox.SandboxError("replay directory is not absolute")
    _secure_ancestors(os.path.dirname(directory), {0, os.geteuid()})
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or \
           info.st_mode & 0o077:
            raise sandbox.SandboxError("replay ledger must belong exclusively to signer service account")
        return fd
    except BaseException:
        os.close(fd)
        raise


def reserve_once(directory, identifier):
    """Atomic O_EXCL + file and directory fsync. Never unlock/delete on failure.

    A crash or a failed sandbox launch consumes this intent, deliberately
    fail-closed. An invalid/copyable signed envelope can cause pre-consumption
    DoS; a production service must authenticate callers independently.
    """
    if len(identifier) != 64 or any(c not in "0123456789abcdef" for c in identifier):
        raise sandbox.SandboxError("invalid canonical replay identifier")
    directory_fd = _open_replay_directory(directory)
    try:
        name = identifier + ".used"
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW,
                         0o600, dir_fd=directory_fd)
        except FileExistsError as error:
            raise sandbox.SandboxError("REPLAY_BLOCKED: intent identifier already reserved") from error
        except OSError as error:
            raise sandbox.SandboxError("REPLAY_STORAGE_UNAVAILABLE: cannot reserve") from error
        try:
            payload = (identifier + "\nreserved-before-sandbox-no-retry\n").encode()
            while payload:
                count = os.write(fd, payload)
                if count <= 0:
                    raise sandbox.SandboxError("REPLAY_STORAGE_UNAVAILABLE: short journal write")
                payload = payload[count:]
            os.fsync(fd)
        except BaseException as error:
            # Do NOT remove a partially written marker after an IO failure.
            raise sandbox.SandboxError("REPLAY_STORAGE_UNAVAILABLE: journal write failed") from error
        finally:
            os.close(fd)
        try:
            os.fsync(directory_fd)
        except OSError as error:
            raise sandbox.SandboxError("REPLAY_STORAGE_UNAVAILABLE: cannot persist directory") from error
        return name
    finally:
        os.close(directory_fd)


def run(argv=None, stdin=None):
    if os.geteuid() == 0:
        raise sandbox.SandboxError(
            "refusing root execution; install a dedicated unprivileged signer service identity")
    parser = sandbox.Exit40Parser(description="protected BLOCK-only HGUET signer")
    parser.add_argument("--policy", required=True, help="root-owned operator policy JSON")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    _verify_launcher_install()
    sandbox.verify_root_owned_bwrap()
    policy = load_operator_policy(args.policy)
    # Read before journal; do not accept truncated input. File and replay
    # access are done by this service, never by sandboxed agent content.
    raw = (sys.stdin.buffer if stdin is None else stdin).read(AGENT_LIMIT+1)
    identity = _parse_replay_identity(raw, policy)
    reserve_once(policy["replay_directory"], identity)

    # Use only root-owned installed launcher source and policy-bound options.
    # Launch with a bounded subprocess; it NEVER signs or grants approval.
    command = [
        sys.executable,
        str(Path(__file__).absolute().with_name("run_signer_sandbox.py")),
        "--binary", policy["binary"],
        "--binary-sha256", policy["binary_sha256"],
        "--network", policy["network"],
        "--trusted-key", policy["trusted_key"],
    ]
    try:
        result = subprocess.run(command, input=raw, capture_output=True, timeout=18,
                                check=False, env={"LANG":"C"}, close_fds=True)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise sandbox.SandboxError("protected sandbox launch failed; replay marker retained") from error
    output = sandbox.checked_refusal(result.stdout, result.returncode)
    # No signed reply or permission token; just a refusal and an OS exit 20.
    sys.stdout.buffer.write(output + (b"" if output.endswith(b"\n") else b"\n"))
    return 20


if __name__ == "__main__":
    try:
        sys.exit(run())
    except (sandbox.SandboxError, OSError) as error:
        print("HGUET_PROTECTED_BLOCKED: " + str(error), file=sys.stderr)
        sys.exit(40)
