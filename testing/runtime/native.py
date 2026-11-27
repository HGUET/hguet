"""Execute SDK-built transfers in LiteSVM and compare actual state with HGUET."""
import argparse
import base64
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import subprocess
import tempfile

from solders.keypair import Keypair
from solders.litesvm import LiteSVM
from solders.message import Message
from solders.system_program import transfer, TransferParams
from solders.transaction import Transaction
from solders.transaction_metadata import FailedTransactionMetadata
from spl_cases import run_case as token_case
from transfer_fee import run_case as fee_case


def run_case(binary, amounts):
    svm = LiteSVM()
    payer, recipient = Keypair(), Keypair()
    funding = svm.airdrop(payer.pubkey(), 10_000_000)
    assert not isinstance(funding, FailedTransactionMetadata)
    svm.airdrop(recipient.pubkey(), 1_000_000)
    instructions = [transfer(TransferParams(
        from_pubkey=payer.pubkey(), to_pubkey=recipient.pubkey(), lamports=amount))
        for amount in amounts]
    message = Message.new_with_blockhash(instructions, payer.pubkey(), svm.latest_blockhash())
    tx = Transaction([payer], message, svm.latest_blockhash())
    wire = bytes(tx)
    before = svm.get_balance(recipient.pubkey())
    result = svm.send_transaction(tx)
    assert not isinstance(result, FailedTransactionMetadata), str(result)
    delta = svm.get_balance(recipient.pubkey()) - before
    assert delta == sum(amounts)
    with tempfile.TemporaryDirectory(prefix="hguet-runtime-") as directory:
        root = Path(directory)
        fixture, policy = root / "transaction.base64", root / "policy.toml"
        fixture.write_text(base64.b64encode(wire).decode())
        policy.write_text('version=1\nnetwork="devnet"\nmax_declared_system_transfer_lamports="500"\n')
        process = subprocess.run([binary, "check", str(fixture), "--encoding", "base64",
                                  "--network", "devnet", "--policy", str(policy), "--report-v2"],
                                 capture_output=True, text=True, timeout=20)
        report = json.loads(process.stdout)
    effects = report["effects"]
    assert [int(effect["amount_raw"]) for effect in effects] == amounts
    assert all(effect["source"] == "original_wire" for effect in effects)
    assert report["evidence"]["inspection"]["message_sha256"] == hashlib.sha256(bytes(message)).hexdigest()
    expected = "VIOLATION" if delta > 500 else "MATCH"
    assert report["policy_compliance"] == expected
    assert report["signing_authorization"] == "NOT_AUTHORIZED"
    assert process.returncode == (20 if delta > 500 else 30)
    return {"case": "native_repeated_over_cap" if len(amounts) > 1 else "native_match",
            "amounts": amounts, "actual_recipient_delta": delta,
            "wire_sha256": hashlib.sha256(wire).hexdigest(),
            "policy_compliance": expected, "runtime_execution": "PASS"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hguet", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    binary = str(Path(args.hguet).resolve())
    result = {"schema_version": 1, "python": platform.python_version(),
              "solders": importlib.metadata.version("solders"),
              "cases": [run_case(binary, [500]), run_case(binary, [300, 201]),
                        *[token_case(binary, operation) for operation in
                          ("transfer_checked", "approve", "set_authority")],
                        fee_case(binary), fee_case(binary, 1)],
              "limitations": ["Legacy SDK transactions only.",
                              "v1 runtime compatibility remains NOT VERIFIED."]}
    Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
