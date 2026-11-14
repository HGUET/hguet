#!/usr/bin/env python3
"""On a host whose Bubblewrap is older than 0.8.0 the launcher must REFUSE, not degrade.

Run on Ubuntu 22.04 (bubblewrap 0.6.1) in CI. If a supported Bubblewrap is installed this
check is not applicable and says so (exit 0, printed as N/A, never as PASS of the property).
Expected on an unsupported host: exit 40, no stdout, an 'unsupported Bubblewrap' message,
and no attempt to start the signer without --disable-userns.
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import run_signer_sandbox as sandbox  # noqa: E402

BIN = ROOT / "target/debug/hguet-signer-isolate"
PIN = "2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ"

if not Path(sandbox.BWRAP_PATH).exists():
    print("N/A: bubblewrap not installed (the launcher's missing-bwrap refusal is covered elsewhere)")
    sys.exit(0)
version = subprocess.run([sandbox.BWRAP_PATH, "--version"], capture_output=True, text=True).stdout.strip()
if sandbox.bwrap_version_supported(version):
    print("N/A: supported Bubblewrap (%s) installed; the unsupported-version refusal is not exercised here" % version)
    sys.exit(0)
if not BIN.exists():
    print("FAIL: signer binary not built: %s" % BIN)
    sys.exit(1)

wire = (ROOT / "tests/fixtures/legacy-spl-transfer-checked-authority-signer.base64").read_text().strip()
envelope = json.loads((ROOT / "tests/fixtures/signed-direct-token-source-cap-equal.json").read_text())
request = json.dumps({"schema_version": 1, "kind": "hguet_signer_preflight",
                      "original_transaction_b64": wire, "signed_intent": envelope}).encode()
command = [sys.executable, str(ROOT / "scripts/run_signer_sandbox.py"), "--binary", str(BIN), "--binary-sha256",
           hashlib.sha256(BIN.read_bytes()).hexdigest(), "--network", "devnet", "--trusted-key", PIN]
result = subprocess.run(command, input=request, capture_output=True, timeout=30)
ok = (result.returncode == 40 and not result.stdout
      and re.search(rb"unsupported Bubblewrap", result.stderr) is not None
      and b"no weaker sandbox" in result.stderr)
if not ok:
    print("FAIL: unsupported Bubblewrap %r did not fail closed: rc=%s stdout=%r stderr=%r"
          % (version, result.returncode, result.stdout[:100], result.stderr[:300]))
    sys.exit(1)
print("PASS: %s is below the required 0.8.0; launcher refused (exit 40, no output, no weaker sandbox)" % version)
