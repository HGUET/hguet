"""Explicit, bounded read-only public Devnet smoke. No wallet or secrets."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import urllib.request
from urllib.error import HTTPError, URLError

from solders.message import to_bytes_versioned
from solders.transaction import VersionedTransaction

ROOT = Path(__file__).resolve().parents[2]
ENDPOINT = "https://api.devnet.solana.com"
FIXTURE = ROOT / "testing/history/solana-docs-devnet-legacy.json"
MAX_RESPONSE = 1_048_576


def rpc(method, params):
    # Fixed endpoint and read-only method allowlist. No credentials or arbitrary URLs.
    if method not in {"getGenesisHash", "getTransaction"}:
        raise ValueError("read-only methods only")
    request = urllib.request.Request(
        ENDPOINT,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                         "params": params}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        if response.geturl() != ENDPOINT and response.geturl() != ENDPOINT + "/":
            raise ValueError("unexpected RPC redirect")
        raw = response.read(MAX_RESPONSE + 1)
    if len(raw) > MAX_RESPONSE:
        raise ValueError("RPC response too large")
    obj = json.loads(raw)
    if obj.get("id") != 1 or "result" not in obj or "error" in obj:
        raise ValueError("RPC rejected request")
    return obj["result"]


def main():
    if not __debug__:
        raise SystemExit("assertions required")
    p = argparse.ArgumentParser()
    p.add_argument("--hguet", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    fixture = json.loads(FIXTURE.read_text())
    signature = fixture["signature"]
    record = {"source": fixture["source"], "signature": signature,
              "network": "devnet", "endpoint": ENDPOINT,
              "commitment": "finalized", "acceptance": "INCOMPLETE",
              "independent_ledger_proof": False}

    def save():
        (args.out / "result.json").write_text(json.dumps(record, indent=2))

    save()
    try:
        genesis = rpc("getGenesisHash", [])
        record["provider_genesis"] = genesis
        result = rpc("getTransaction", [signature, {"encoding": "base64",
                      "commitment": "finalized", "maxSupportedTransactionVersion": 1}])
        if result is None:
            record["acceptance"] = "UNAVAILABLE"
            record["reason"] = "provider returned null at finalized commitment"
            save()
            raise SystemExit(2)
        (args.out / "provider.json").write_text(json.dumps(result, indent=2))
    except (HTTPError, URLError, TimeoutError, ValueError) as error:
        record["acceptance"] = "UNAVAILABLE"
        record["reason"] = type(error).__name__
        if isinstance(error, HTTPError):
            record["http_status"] = error.code
        save()
        raise SystemExit(2)

    try:
        raw = base64.b64decode(result["transaction"][0], validate=True)
        tx = VersionedTransaction.from_bytes(raw)
        assert bytes(tx) == raw and str(tx.signatures[0]) == signature
        assert all(tx.verify_with_results())
        assert hashlib.sha256(raw).hexdigest() == fixture["wire_sha256"]
        assert hashlib.sha256(to_bytes_versioned(tx.message)).hexdigest() == fixture["message_sha256"]
        assert result["slot"] == fixture["result"]["slot"]
        assert result["version"] == fixture["result"]["version"]
        for field in ("err", "fee", "preBalances", "postBalances"):
            assert result["meta"][field] == fixture["result"]["meta"][field], field
        record["sdk_and_published_example"] = "PASS"
        process = subprocess.run([str(args.hguet.resolve()), "audit", signature,
                                 "--network", "devnet", "--rpc-url", ENDPOINT],
                                 capture_output=True, timeout=60)
        record["cli_exit_code"] = process.returncode
        report = json.loads(process.stdout)
        (args.out / "audit.json").write_text(json.dumps(report, indent=2))
        if process.returncode == 30 and report.get("status") in {
            "NOT_FOUND_AT_REQUESTED_COMMITMENT", "RPC_UNAVAILABLE"
        }:
            # Do not silently hide invalid responses or genesis mismatches.
            if report.get("rpc_error") not in {"RPC_RESPONSE_INVALID", "RPC_GENESIS_MISMATCH"}:
                record["acceptance"] = "UNAVAILABLE"
                record["reason"] = report.get("rpc_error") or report["status"]
                save()
                raise SystemExit(2)
        assert process.returncode == 0, report.get("rpc_error")
        assert report["status"] == "FOUND_SIGNATURE_VERIFIED"
        assert report["verified_genesis_hash"] == genesis
        assert report["signatures_verified"] and not report["execution_proven"]
        assert report["signing_authorization"] == "NOT_AUTHORIZED"
        assert report["wire"]["message_sha256"] == fixture["message_sha256"]
        assert report["historical"]["slot"] == result["slot"]
        assert report["historical"]["reported_fee_lamports"] == str(result["meta"]["fee"])
        actual = {r["account_index"]: int(r["delta_lamports"])
                  for r in report["historical"]["effects"]["lamport_deltas"]}
        expected = {i: post - pre for i, (pre, post) in enumerate(zip(
            result["meta"]["preBalances"], result["meta"]["postBalances"])) if post != pre}
        assert actual == expected
        record["acceptance"] = "PASS"
        save()
    except Exception as error:
        record["acceptance"] = "FAIL"
        record["reason"] = type(error).__name__
        save()
        raise
    print("PASS: public Devnet transaction; SDK signature, published fixture and HGUET audit agree")


if __name__ == "__main__":
    main()
