#!/usr/bin/env python3
"""Prove HGUET_REQUIRE_LIVE=1 turns SKIP into FAIL (and only then).

Forces the live tests into their SKIP paths without weakening any real check:
  * multi-UID test: run without root (dropped with setpriv when we are root)
  * sandbox runtime test: run inside a Bubblewrap with --disable-userns, so the
    nested namespace probe genuinely fails
Expected: without the variable the scripts print SKIP and exit 0; with
HGUET_REQUIRE_LIVE=1 they print FAIL and exit 1. If a skip path cannot be forced
on this host, that part is reported SKIP (never PASS) and the script exits 0
unless HGUET_REQUIRE_LIVE=1 is set for THIS script as well.
"""
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
results = []


def run(cmd, live):
    env = {k: v for k, v in os.environ.items() if k != "HGUET_REQUIRE_LIVE"}
    if live:
        env["HGUET_REQUIRE_LIVE"] = "1"
    return subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=120)


def unprivileged(cmd):
    if os.geteuid() == 0:
        if not shutil.which("setpriv"):
            return None
        return ["setpriv", "--reuid", "65534", "--regid", "65534", "--clear-groups", *cmd]
    return cmd


def check(name, command_factory, skip_marker):
    command = command_factory()
    if command is None:
        results.append((name, "SKIP", "cannot force skip path on this host"))
        return
    relaxed, strict = run(command, False), run(command, True)
    if skip_marker not in relaxed.stdout:
        results.append((name, "SKIP", "skip path not reached (host can run it live): "
                        + (relaxed.stdout + relaxed.stderr).strip()[-120:]))
        return
    ok = (relaxed.returncode == 0 and "NOT a pass" in relaxed.stdout
          and strict.returncode == 1 and "FAIL: required live" in strict.stdout)
    results.append((name, "PASS" if ok else "FAIL",
                    "relaxed rc=%s strict rc=%s %s" % (relaxed.returncode, strict.returncode, strict.stdout.strip()[:120])))


check("multi-UID test without root",
      lambda: unprivileged([PY, str(ROOT / "scripts/check_signer_admission_users.py")]),
      "SKIP:")


def sandbox_without_userns():
    if not Path("/usr/bin/bwrap").exists():
        return None
    return ["/usr/bin/bwrap", "--unshare-user", "--disable-userns", "--ro-bind", "/", "/",
            "--dev", "/dev", "--tmpfs", "/tmp", PY, str(ROOT / "scripts/check_signer_sandbox_runtime.py")]


check("sandbox runtime test with user namespaces unavailable", sandbox_without_userns, "SKIP:")

failed = False
for name, status, detail in results:
    print("%s: %s -- %s" % (status, name, detail))
    failed = failed or status == "FAIL"
    if status == "SKIP" and os.environ.get("HGUET_REQUIRE_LIVE") == "1":
        failed = True
if failed:
    sys.exit(1)
if all(status == "PASS" for _, status, _ in results):
    print("PASS: HGUET_REQUIRE_LIVE=1 makes skipped live security tests fail")
