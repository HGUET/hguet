"""Execute an SDK v0 lookup transaction while keeping offline ALT coverage unknown."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from solders.account import Account
from solders.address_lookup_table_account import AddressLookupTableAccount, ID
from solders.keypair import Keypair
from solders.litesvm import LiteSVM
from solders.message import MessageV0, to_bytes_versioned
from solders.system_program import transfer, TransferParams
from solders.transaction import VersionedTransaction
from solders.transaction_metadata import FailedTransactionMetadata


def run_case(binary):
    svm = LiteSVM()
    svm.warp_to_slot(100)
    receiver, table = (Keypair().pubkey() for _ in range(2))
    signer = Keypair()
    payer = signer.pubkey()
    svm.airdrop(payer, 10_000_000)
    svm.airdrop(receiver, 1_000_000)
    # Canonical lookup-table state header, one address, active at slot 100.
    header = ((1).to_bytes(4, "little") + (2**64-1).to_bytes(8, "little")
              + (1).to_bytes(8, "little") + bytes([0, 0]) + bytes(34))
    assert len(header) == 56
    svm.set_account(table, Account(10_000_000, header + bytes(receiver), ID))
    lookup = AddressLookupTableAccount(table, [receiver])
    ix = transfer(TransferParams(from_pubkey=payer, to_pubkey=receiver, lamports=500))
    message = MessageV0.try_compile(payer, [ix], [lookup], svm.latest_blockhash())
    assert len(message.address_table_lookups) == 1
    tx = VersionedTransaction(message, [signer])
    before = svm.get_balance(receiver)
    result = svm.send_transaction(tx)
    assert not isinstance(result, FailedTransactionMetadata), str(result)
    assert svm.get_balance(receiver) - before == 500
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "lookup.tx"
        path.write_bytes(bytes(tx))
        process = subprocess.run([binary, "check", str(path), "--offline", "--network",
                                  "devnet", "--report-v2"], capture_output=True, text=True, timeout=20)
        assert process.returncode == 30
        report = json.loads(process.stdout)
    inspection = report["evidence"]["inspection"]
    assert inspection["message_sha256"] == hashlib.sha256(to_bytes_versioned(message)).hexdigest()
    assert inspection["unresolved_lookup_addresses"] == 1
    assert report["effects"][0]["kind"] == "native_transfer"
    assert report["effects"][0]["amount_raw"] == "500"
    assert report["effects"][0]["destination_account"] is None
    assert report["evidence"]["verdict"]["decision"] == "UNKNOWN"
    assert report["signing_authorization"] == "NOT_AUTHORIZED"
    return {"case":"v0_alt_native_transfer", "runtime_outcome":"EXECUTED",
            "actual_recipient_delta":500, "offline_destination":"UNKNOWN",
            "unresolved_lookup_addresses":1, "comparison":"PASS"}
