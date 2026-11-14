#!/usr/bin/env python3
"""Linux-only, fail-closed Bubblewrap launcher for HGUET's BLOCK-only signer.

The executable's exact verified inode is mounted by FD. Agent JSON is only
passed on stdin. Nothing falls back to a normal unsandboxed process.

This is defense-in-depth for an unsigned/no-key preflight, not secure key
custody, authenticated operator provisioning, or actual transaction approval.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import subprocess
import sys

MAX_AGENT_BYTES = 65536
MAX_OUTPUT_BYTES = 65536
BWRAP_PATH = "/usr/bin/bwrap"
SANDBOX_EXEC = "/app/hguet-signer-isolate"

# Linux audit arch and syscall IDs; only audited little-endian 64-bit ABIs.
# This is a denylist defense-in-depth, NOT a comprehensive syscall allowlist.
ARCH = {
    "x86_64": (0xC000003E, (
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55,
        56, 57, 58, 101, 155, 161, 165, 166, 169, 175, 176, 246,
        248, 249, 250, 272, 298, 304, 308, 310, 311, 313, 320, 321,
        323, 425, 426, 427, 428, 429, 430, 431, 432, 435, 442,
    )),
    "aarch64": (0xC00000B7, (
        39, 40, 104, 105, 106, 117, 198, 199, 200, 201, 202, 203,
        204, 205, 206, 207, 208, 209, 210, 211, 212, 217, 218,
        219, 220, 241, 265, 270, 271, 273, 280, 282, 294, 425,
        426, 427, 428, 429, 430, 431, 432, 435, 442,
    )),
}
# Linux classic-BPF constants
BPF_LD_W_ABS, BPF_JEQ_K, BPF_JSET_K, BPF_RET_K = 0x20, 0x15, 0x45, 0x06
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
X32_SYSCALL_BIT = 0x40000000


class SandboxError(Exception):
    pass


class Exit40Parser(argparse.ArgumentParser):
    def error(self, message):
        raise SandboxError("invalid operator launcher arguments: " + message)


def parse_args(argv):
    parser = Exit40Parser(description="Linux Bubblewrap, mandatory fail-closed signer sandbox")
    parser.add_argument("--binary", required=True, help="absolute trusted signer executable path")
    parser.add_argument("--binary-sha256", required=True, help="operator-pinned executable SHA-256")
    parser.add_argument("--network", required=True, choices=("mainnet", "devnet", "testnet"))
    parser.add_argument("--trusted-key", required=True, help="independently provisioned public intent key")
    return parser.parse_args(argv)


def seccomp_instructions(machine=None):
    """Architecture checked, x32 blocked, privileged and network syscalls denied."""
    if sys.platform != "linux" or sys.byteorder != "little":
        raise SandboxError("unsupported Linux sandbox platform")
    machine = platform.machine() if machine is None else machine
    if machine not in ARCH:
        raise SandboxError("unsupported syscall architecture; no unsafe fallback")
    audit_arch, denied = ARCH[machine]
    result = [
        (BPF_LD_W_ABS, 0, 0, 4),  # seccomp_data.arch
        (BPF_JEQ_K, 1, 0, audit_arch),
        (BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        (BPF_LD_W_ABS, 0, 0, 0),  # seccomp_data.nr
    ]
    if machine == "x86_64":
        result.extend((
            (BPF_JSET_K, 0, 1, X32_SYSCALL_BIT),
            (BPF_RET_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        ))
    for number in sorted(set(denied)):
        result.append((BPF_JEQ_K, 0, 1, number))
        result.append((BPF_RET_K, 0, 0, SECCOMP_RET_ERRNO | errno.EPERM))
    result.append((BPF_RET_K, 0, 0, SECCOMP_RET_ALLOW))
    assert len(result) < 4096
    return result


def seccomp_bytes(machine=None):
    return b"".join(struct.pack("<HBBI", *instruction)
                    for instruction in seccomp_instructions(machine))


def verify_root_owned_bwrap():
    try:
        st = os.stat(BWRAP_PATH)
    except OSError as ex:
        raise SandboxError("Bubblewrap not installed; refused to launch without OS sandbox") from ex
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise SandboxError("Bubblewrap binary is not trusted root-owned immutable-to-users")
    if not os.access(BWRAP_PATH, os.X_OK):
        raise SandboxError("Bubblewrap is not executable")


# --disable-userns / --assert-userns-disabled (no nested user namespaces inside the
# sandbox) first appeared in Bubblewrap 0.8.0. Older versions (Ubuntu 22.04 ships
# 0.6.1) cannot enforce that restriction, and the sandbox is never weakened to fit
# them: the launcher refuses to run instead.
MIN_BWRAP = (0, 8, 0)


def bwrap_version_supported(version_text):
    """True only for 'bubblewrap X.Y[.Z]' with X.Y.Z >= MIN_BWRAP."""
    match = re.fullmatch(r"\s*bubblewrap\s+(\d+)\.(\d+)(?:\.(\d+))?\s*", version_text or "")
    if not match:
        return False
    found = tuple(int(part or 0) for part in match.groups())
    return found >= MIN_BWRAP


def verify_bwrap_version():
    try:
        result = subprocess.run([BWRAP_PATH, "--version"], capture_output=True, text=True,
                                timeout=5, check=False, env={})
    except (OSError, subprocess.TimeoutExpired) as ex:
        raise SandboxError("cannot determine Bubblewrap version; refused to launch") from ex
    if result.returncode != 0 or not bwrap_version_supported(result.stdout):
        raise SandboxError(
            "unsupported Bubblewrap (need >= %d.%d.%d for --disable-userns, found %r); "
            "no weaker sandbox is used" % (MIN_BWRAP + (result.stdout.strip()[:40],)))


def open_pinned_executable(binary, digest):
    if not Path(binary).is_absolute() or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SandboxError("signer path must be absolute and executable hash operator-pinned")
    if Path(binary).name != "hguet-signer-isolate":
        raise SandboxError("unsupported signer executable filename")
    try:
        fd = os.open(binary, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError as ex:
        raise SandboxError("cannot open operator-pinned signer executable") from ex
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o022 or not st.st_mode & 0o111:
            raise SandboxError("signer must be executable regular file, not group/world writable")
        # Check file identity, then mount the SAME open inode via --ro-bind-fd
        # rather than re-opening a user-controlled pathname after verification.
        checksum = hashlib.sha256()
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            checksum.update(block)
        if not hmac.compare_digest(checksum.hexdigest(), digest):
            raise SandboxError("signer executable hash mismatch; launch blocked")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def make_bwrap_command(executable_fd, seccomp_fd, network, trusted_key):
    if network not in ("mainnet", "devnet", "testnet"):
        raise SandboxError("unsupported operator network")
    if not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", trusted_key):
        raise SandboxError("operator public key must be canonical Base58 syntax")
    # Nothing inside a host home, /etc, /run/user or agent working directory is
    # mounted. Read-only host runtime libraries are exposed for the dynamic
    # linker; the executable itself is pinned by opened FD.
    return [
        BWRAP_PATH,
        "--unshare-all",          # network, pid, ipc, mount, uts, cgroup (user is only "-try" here)
        "--unshare-user",         # MANDATORY: --disable-userns needs a hard user ns (bwrap >= 0.8)
        "--disable-userns",       # no nested user namespace escape
        "--assert-userns-disabled",
        "--cap-drop", "ALL",
        "--new-session", "--die-with-parent",
        "--clearenv",
        "--setenv", "LANG", "C",
        "--setenv", "PATH", "/nonexistent",
        "--setenv", "HOME", "/nonexistent",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind-try", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        "--ro-bind-try", "/bin", "/bin",
        "--ro-bind-try", "/sbin", "/sbin",
        "--dir", "/app",
        "--ro-bind-fd", str(executable_fd), SANDBOX_EXEC,
        "--dir", "/dev",          # no host device nodes
        "--dir", "/tmp",          # empty, ephemeral, not host /tmp
        "--proc", "/proc",        # only processes in new pid namespace
        "--chdir", "/",
        "--seccomp", str(seccomp_fd),
        SANDBOX_EXEC,
        "--network", network,
        "--trusted-key", trusted_key,
    ]


def checked_refusal(stdout, returncode):
    """Never pass a child claim of approval through as an accepted refusal."""
    if returncode != 20 or len(stdout) > MAX_OUTPUT_BYTES:
        raise SandboxError("sandbox or signer did not return an expected refusal")
    try:
        obj = json.loads(stdout)
        row = obj["signer_refusal"]
    except (ValueError, TypeError, KeyError) as ex:
        raise SandboxError("sandbox signer response malformed") from ex
    if (type(obj) is not dict or set(obj) != {"signer_refusal"}
        or type(row) is not dict
        or row.get("signing_gate") != "block"
        or any(row.get(name) is not False for name in (
            "signing_permitted", "signer_backend_invoked",
            "signature_created", "transaction_broadcast"))):
        raise SandboxError("sandbox signer response is not unconditionally BLOCK")
    boundary = row.get("signing_boundary")
    if boundary is not None and (
        type(boundary) is not dict or boundary.get("signing_gate") != "block"
        or boundary.get("automated_signing_permitted") is not False
    ):
        raise SandboxError("nested signer boundary attempted to claim authorization")
    return stdout


def run(argv=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    verify_root_owned_bwrap()
    verify_bwrap_version()
    exec_fd = open_pinned_executable(args.binary, args.binary_sha256)
    try:
        seccomp = seccomp_bytes()
        if not hasattr(os, "memfd_create"):
            raise SandboxError("memfd required for mandatory seccomp policy")
        filter_fd = os.memfd_create("hguet-signer-seccomp", os.MFD_CLOEXEC)
        try:
            os.write(filter_fd, seccomp)
            os.lseek(filter_fd, 0, os.SEEK_SET)
            cmd = make_bwrap_command(
                exec_fd, filter_fd, args.network, args.trusted_key)
            # Stdin is the only untrusted data channel; do not read files or
            # follow agent-provided paths. Capture stdout until validation.
            data = sys.stdin.buffer.read(MAX_AGENT_BYTES + 1)
            if len(data) > MAX_AGENT_BYTES:
                raise SandboxError("agent stdin exceeds mandatory 64 KiB limit")
            try:
                result = subprocess.run(
                    cmd, input=data, capture_output=True,
                    close_fds=True, pass_fds=(exec_fd, filter_fd),
                    timeout=12, check=False, env={},
                )
            except (OSError, subprocess.TimeoutExpired) as ex:
                raise SandboxError("sandbox setup/launch failed; no unsandboxed fallback") from ex
            output = checked_refusal(result.stdout, result.returncode)
            sys.stdout.buffer.write(output + (b"" if output.endswith(b"\n") else b"\n"))
            return 20
        finally:
            os.close(filter_fd)
    finally:
        os.close(exec_fd)


if __name__ == "__main__":
    try:
        sys.exit(run())
    except SandboxError as error:
        print("HGUET_SANDBOX_BLOCKED: " + str(error), file=sys.stderr)
        sys.exit(40)
