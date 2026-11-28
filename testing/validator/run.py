"""Execute disposable transactions on a real single-node validator, loopback only."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import urllib.request

from solders.address_lookup_table_account import AddressLookupTableAccount
from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import Message, MessageV0, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.system_program import (
    create_lookup_table, extend_lookup_table, transfer, TransferParams,
)
from solders.transaction import VersionedTransaction

ENDPOINT = "http://127.0.0.1:8899"
MAX_RESPONSE = 1_048_576
METHODS = {"getHealth", "getGenesisHash", "getVersion", "getLatestBlockhash",
           "getSignatureStatuses", "getTransaction", "getBalance", "getSlot",
           "requestAirdrop", "sendTransaction"}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("RPC redirect prohibited")


OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())


def rpc(method, params=None):
    assert method in METHODS
    request = urllib.request.Request(
        ENDPOINT,
        data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                         "params": params or []}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with OPENER.open(request, timeout=5) as response:
        raw = response.read(MAX_RESPONSE + 1)
    assert len(raw) <= MAX_RESPONSE
    payload = json.loads(raw)
    assert payload["id"] == 1 and "error" not in payload, payload.get("error")
    return payload["result"]


def wait(fn, seconds=100):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = fn()
        if result is not None:
            return result
        time.sleep(0.5)
    raise TimeoutError("validator condition not reached")


def finalized(signature):
    def check():
        status = rpc("getSignatureStatuses", [[signature], {"searchTransactionHistory": True}])["value"][0]
        if status and status["confirmationStatus"] == "finalized":
            return status
        return None
    return wait(check)


def balance(key):
    return rpc("getBalance", [str(key), {"commitment": "finalized"}])["value"]


def blockhash():
    return Hash.from_string(rpc("getLatestBlockhash", [{"commitment": "confirmed"}])["value"]["blockhash"])


def submit(tx, expected_error=None):
    raw = bytes(tx)
    signature = str(tx.signatures[0])
    result = rpc("sendTransaction", [base64.b64encode(raw).decode(), {
        "encoding": "base64", "skipPreflight": True, "maxRetries": 0}])
    assert result == signature
    status = finalized(signature)
    assert status["err"] == expected_error, status
    return signature


def history(signature):
    return wait(lambda: rpc("getTransaction", [signature, {"encoding": "base64",
                "commitment": "finalized", "maxSupportedTransactionVersion": 0}]))


def main():
    if not __debug__:
        raise SystemExit("assertions required")
    p = argparse.ArgumentParser()
    p.add_argument("--validator", type=Path, required=True)
    p.add_argument("--hguet", type=Path, required=True)
    p.add_argument("--replay", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    out = args.out.resolve()
    rows = []
    record = {"mandatory_count": 3, "passed_count": 0, "cases": rows,
              "acceptance": "INCOMPLETE", "network": "isolated_local_validator",
              "public_network_access": False}

    def save():
        (out / "result.json").write_text(json.dumps(record, indent=2))

    save()
    # This script is only run in a fresh Linux network namespace with loopback up.
    # Refuse even a caller's ordinary host namespace with non-loopback interfaces.
    assert sorted(os.listdir("/sys/class/net")) == ["lo"], "isolated loopback namespace required"
    home = out / "temporary-home"
    home.mkdir()
    with (out / "validator.log").open("wb") as log:
        proc = subprocess.Popen([str(args.validator.resolve()), "--reset", "--ledger",
            str(home / "ledger"), "--bind-address", "127.0.0.1", "--rpc-port", "8899"],
            stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
            env={**os.environ, "HOME": str(home)})
        try:
            def ready():
                if proc.poll() is not None:
                    raise RuntimeError(f"validator exited: {proc.returncode}")
                try:
                    return True if rpc("getHealth") == "ok" else None
                except (OSError, ValueError, AssertionError):
                    return None
            wait(ready, 120)
            record["genesis"] = rpc("getGenesisHash")
            record["version"] = rpc("getVersion")
            save()
            payer, receiver = Keypair(), Keypair()
            for key, amount in ((payer.pubkey(), 1_000_000_000), (receiver.pubkey(), 1_000_000)):
                sig = rpc("requestAirdrop", [str(key), amount])
                assert finalized(sig)["err"] is None

            def move(amount):
                return transfer(TransferParams(from_pubkey=payer.pubkey(),
                    to_pubkey=receiver.pubkey(), lamports=amount))

            def legacy(instructions):
                msg = Message.new_with_blockhash(instructions, payer.pubkey(), blockhash())
                return VersionedTransaction(msg, [payer])

            def run_case(name, tx, declared, expected_delta, error=None, lookup=False):
                raw = bytes(tx)
                before = balance(receiver.pubkey())
                cli = subprocess.run([str(args.hguet.resolve()), "report", "-", "--offline"],
                    input=raw, capture_output=True, timeout=20)
                assert cli.returncode == 0, cli.stderr
                report = json.loads(cli.stdout)
                assert report["signing_authorization"] == "NOT_AUTHORIZED"
                assert not report["execution_proven"]
                assert report["wire"]["asset_totals"][0]["declared_debit_raw"] == str(declared)
                signature = submit(tx, error)
                assert balance(receiver.pubkey()) - before == expected_delta
                response = history(signature)
                (out / f"{name}-provider.json").write_text(json.dumps(response, indent=2))
                assert response["meta"]["err"] == error
                decoded = base64.b64decode(response["transaction"][0], validate=True)
                assert decoded == raw
                sdk = VersionedTransaction.from_bytes(decoded)
                assert all(sdk.verify_with_results())
                result = subprocess.run([str(args.replay.resolve()), signature],
                    input=json.dumps(response).encode(), capture_output=True, timeout=20)
                assert result.returncode == 0, result.stderr
                replay = json.loads(result.stdout)
                (out / f"{name}-replay.json").write_text(json.dumps(replay, indent=2))
                assert replay["wire_sha256"] == hashlib.sha256(raw).hexdigest()
                assert replay["report"] == report
                assert report["message_sha256"] == hashlib.sha256(to_bytes_versioned(tx.message)).hexdigest()
                assert not replay["source_authentication_performed"] and not replay["execution_proven"]
                assert replay["signing_authorization"] == "NOT_AUTHORIZED"
                hist = replay["historical"]
                assert hist["status"] == ("RPC_REPORTED_SUCCESS" if error is None else "RPC_REPORTED_FAILURE")
                assert hist["reported_fee_lamports"] == str(response["meta"]["fee"])
                expected_rows = {i: (str(a), str(b), str(b-a))
                    for i, (a,b) in enumerate(zip(response["meta"]["preBalances"],
                    response["meta"]["postBalances"])) if a != b}
                observed = {r["account_index"]: (r["before_lamports"], r["after_lamports"],
                    r["delta_lamports"]) for r in hist["effects"]["lamport_deltas"]}
                assert expected_rows == observed
                if lookup:
                    assert report["wire"]["flows"][0]["to"]["address"] is None
                    assert hist["historical_loaded_addresses"]["resolved_writable_accounts"] == [str(receiver.pubkey())]
                rows.append({"case":name, "comparison":"PASS", "signature":signature,
                             "wire_sha256":replay["wire_sha256"],
                             "actual_recipient_delta":expected_delta,
                             "fee_lamports":hist["reported_fee_lamports"],
                             "error":error})
                record["passed_count"] = len(rows)
                save()

            run_case("legacy_transfer", legacy([move(500)]), 500, 500)
            run_case("legacy_rollback", legacy([move(500), move(2_000_000_000)]),
                     2_000_000_500, 0, {"InstructionError": [1, {"Custom": 1}]})
            slot = rpc("getSlot", [{"commitment": "finalized"}])
            create, table = create_lookup_table(dict(authority_address=payer.pubkey(),
                payer_address=payer.pubkey(), recent_slot=slot))
            submit(legacy([create]))
            extend = extend_lookup_table(dict(lookup_table_address=table,
                authority_address=payer.pubkey(), payer_address=payer.pubkey(),
                new_addresses=[receiver.pubkey()]))
            submit(legacy([extend]))
            # Finalization already advances the slot beyond extension.
            msg = MessageV0.try_compile(payer.pubkey(), [move(501)],
                [AddressLookupTableAccount(table, [receiver.pubkey()])], blockhash())
            assert len(msg.address_table_lookups) == 1
            run_case("v0_lookup_transfer", VersionedTransaction(msg, [payer]),
                     501, 501, lookup=True)
            record["acceptance"] = "PASS"
            save()
        except BaseException as error:
            record["acceptance"] = "FAIL"
            record["error"] = repr(error)
            save()
            raise
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
    print("PASS: 3 real isolated validator comparisons")


if __name__ == "__main__":
    main()
