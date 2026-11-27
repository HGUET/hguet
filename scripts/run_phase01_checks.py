"""Run source-attributed Phase 1 checks and preserve every result, including failures."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--hguet", required=True, type=Path)
    args = parser.parse_args()
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    binary = args.hguet.resolve()
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    commands = [
        ("format", ["cargo", "+1.100.0", "fmt", "--all", "--", "--check"]),
        ("workspace-build", ["cargo", "+1.100.0", "build", "--locked", "--workspace"]),
        ("clippy", ["cargo", "+1.100.0", "clippy", "--locked", "--workspace", "--all-targets", "--", "-D", "warnings"]),
        ("tests", ["cargo", "+1.100.0", "test", "--locked", "--workspace"]),
        ("contract", [sys.executable, "scripts/validate_contract.py"]),
        ("json-contract", [sys.executable, "scripts/validate_json_contracts.py"]),
        ("catalogue", [sys.executable, "scripts/validate_rule_catalogue.py"]),
        ("scenario-drift", [sys.executable, "testing/tools/build_scenarios.py", "--check"]),
        ("framework", [sys.executable, "-m", "unittest", "discover", "-s", "testing/tests", "-v"]),
        ("benchmark", [sys.executable, "testing/runner/run_benchmark.py", "--hguet", str(binary),
                       "--suite", "all", "--out", str(evidence / "benchmark")]),
        ("demo-json", ["sudo", "unshare", "--net", "--", str(binary), "demo", "--json"]),
        ("demo-text", ["sudo", "unshare", "--net", "--", str(binary), "demo"]),
    ]
    report = {"source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
              "binary_sha256_before": digest, "checks": [],
              "pq": "NOT_RUN_BY_THIS_JOB: use the OpenSSL-capable PQ interoperability workflow"}
    target = evidence / "checks.json"

    def persist():
        target.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")

    persist()
    for name, command in commands:
        start = time.monotonic()
        with (evidence / (name + ".log")).open("wb") as log:
            try:
                status = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                        timeout=600, check=False).returncode
            except (OSError, subprocess.TimeoutExpired) as exc:
                log.write(str(exc).encode("utf-8"))
                status = 124
        report["checks"].append({"name": name, "command": command, "exit_code": status,
                                 "elapsed_seconds": round(time.monotonic() - start, 3)})
        persist()
        print(f"{name}: exit {status}", flush=True)
    report["binary_sha256_after"] = hashlib.sha256(binary.read_bytes()).hexdigest()
    report["acceptance"] = "PASS" if (all(x["exit_code"] == 0 for x in report["checks"])
                                      and report["binary_sha256_after"] == digest) else "FAIL"
    persist()
    return 0 if report["acceptance"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
