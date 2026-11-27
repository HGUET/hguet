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
from formats import run_cases as format_cases
from lookup import run_case as lookup_case


def run_case(binary, amounts, insufficient=False):
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
    assert isinstance(result, FailedTransactionMetadata) == insufficient, str(result)
    delta = svm.get_balance(recipient.pubkey()) - before
    assert delta == (0 if insufficient else sum(amounts))
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
    expected = "VIOLATION" if sum(amounts) > 500 else "MATCH"
    assert report["policy_compliance"] == expected
    assert report["signing_authorization"] == "NOT_AUTHORIZED"
    assert process.returncode == (20 if sum(amounts) > 500 else 30)
    return {"case": "native_insufficient_balance" if insufficient else
            ("native_repeated_over_cap" if len(amounts) > 1 else "native_match"),
            "amounts": amounts, "actual_recipient_delta": delta,
            "wire_sha256": hashlib.sha256(wire).hexdigest(),
            "policy_compliance": expected, "runtime_outcome": "REJECTED" if insufficient else "EXECUTED",
            "comparison":"PASS"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hguet", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    binary = str(Path(args.hguet).resolve())
    from acceptance import run_suite, expected_cases
    from functools import partial

    jobs = [
        (("native_match",), partial(run_case, binary, [500])),
        (("native_repeated_over_cap",), partial(run_case, binary, [300, 201])),
        *[((op,), partial(token_case, binary, op))
          for op in ("transfer_checked", "approve", "set_authority")],
        (("token2022_transfer_fee",), partial(fee_case, binary)),
        (("token2022_wrong_fee",), partial(fee_case, binary, 1)),
        (("transfer_checked_wrong_authority",), partial(token_case, binary, "transfer_checked", True)),
        (("native_insufficient_balance",), partial(run_case, binary, [20_000_000], True)),
        (("v0_sdk_transfer", "v1_sdk_transfer", "v1_inline_resources"), partial(format_cases, binary)),
        (("v0_alt_native_transfer",), partial(lookup_case, binary)),
    ]
    metadata = {"schema_version": 1, "python": platform.python_version(),
                "solders": importlib.metadata.version("solders"),
                "binary_sha256": hashlib.sha256(Path(binary).read_bytes()).hexdigest(),
                "limitations": ["ALT runtime comparison keeps offline addresses unresolved.",
                                "v1 comparisons cover native transfers with default and inline resource configurations.",
                                "These local runtime results establish no live cluster support."]}
    return run_suite(jobs, expected_cases, Path(args.out), metadata)


if __name__ == "__main__":
    raise SystemExit(main())
