"""Independent SDK parsing and actual legacy/v0 runtime comparison."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from solders.keypair import Keypair
from solders.litesvm import LiteSVM
from solders.message import MessageV0, MessageV1, TransactionConfig, to_bytes_versioned
from solders.system_program import transfer, TransferParams
from solders.transaction import VersionedTransaction
from solders.transaction_metadata import FailedTransactionMetadata


def run_v0(binary):
    svm = LiteSVM()
    payer, receiver = Keypair(), Keypair()
    svm.airdrop(payer.pubkey(), 10_000_000)
    svm.airdrop(receiver.pubkey(), 1_000_000)
    ix = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=receiver.pubkey(), lamports=500))
    message = MessageV0.try_compile(payer.pubkey(), [ix], [], svm.latest_blockhash())
    tx = VersionedTransaction(message, [payer])
    wire = bytes(tx)
    assert bytes(VersionedTransaction.from_bytes(wire)) == wire
    before = svm.get_balance(receiver.pubkey())
    result = svm.send_transaction(tx)
    assert not isinstance(result, FailedTransactionMetadata), str(result)
    assert svm.get_balance(receiver.pubkey()) - before == 500
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "v0"
        path.write_bytes(wire)
        process = subprocess.run([binary, "inspect", str(path), "--offline", "--report-v2"],
                                 capture_output=True, text=True, timeout=20)
        assert process.returncode == 0
        report = json.loads(process.stdout)
    assert report["evidence"]["inspection"]["wire_format"] == "v0"
    assert report["evidence"]["inspection"]["message_sha256"] == hashlib.sha256(to_bytes_versioned(message)).hexdigest()
    assert report["effects"][0]["amount_raw"] == "500"
    return {"case": "v0_sdk_transfer", "runtime_execution": "PASS",
            "comparison": "PASS", "actual_recipient_delta": 500,
            "message_hash_comparison": "PASS"}


def run_v1(binary, inline_resources=False):
    svm = LiteSVM()
    payer, receiver = Keypair(), Keypair()
    for key, amount in [(payer.pubkey(), 10_000_000), (receiver.pubkey(), 1_000_000)]:
        assert not isinstance(svm.airdrop(key, amount), FailedTransactionMetadata)
    ix = transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=receiver.pubkey(), lamports=500))
    fixture = Path(__file__).resolve().parents[2] / "tests/fixtures/v1-system-transfer.base64"
    v1 = base64.b64decode(fixture.read_text())
    decoded = VersionedTransaction.from_bytes(v1)
    assert decoded.version() == 1 and bytes(decoded) == v1
    case = "v1_inline_resources" if inline_resources else "v1_sdk_transfer"
    config = TransactionConfig(priority_fee=1000, compute_unit_limit=200000,
                               loaded_accounts_data_size_limit=65536, heap_size=32768) if inline_resources else None
    message = MessageV1.try_compile(payer.pubkey(), [ix], svm.latest_blockhash(), config)
    tx = VersionedTransaction(message, [payer])
    wire = bytes(tx)
    assert bytes(VersionedTransaction.from_bytes(wire)) == wire
    before = svm.get_balance(receiver.pubkey())
    outcome = svm.send_transaction(tx)
    if isinstance(outcome, FailedTransactionMetadata):
        return {"case": case, "sdk_roundtrip": "PASS", "runtime_outcome": "REJECTED",
                "runtime_error": str(outcome), "comparison": "FAIL"}
    delta = svm.get_balance(receiver.pubkey()) - before
    assert delta == 500
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "v1"
        path.write_bytes(wire)
        process = subprocess.run([binary, "inspect", str(path), "--offline", "--report-v2"],
                                 capture_output=True, text=True, timeout=20)
        assert process.returncode == 0, process.stderr
        report = json.loads(process.stdout)
    assert report["evidence"]["inspection"]["wire_format"] == "v1"
    assert report["evidence"]["inspection"]["message_sha256"] == hashlib.sha256(to_bytes_versioned(message)).hexdigest()
    assert report["effects"][0]["amount_raw"] == "500"
    return {"case": case, "sdk_roundtrip": "PASS", "runtime_outcome": "EXECUTED",
            "actual_recipient_delta": delta, "comparison": "PASS"}


def run_cases(binary):
    return [run_v0(binary), run_v1(binary), run_v1(binary, True)]
