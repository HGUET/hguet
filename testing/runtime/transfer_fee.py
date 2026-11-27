"""Token-2022 fee initialization and transfers executed by LiteSVM."""
import base64
import json
from pathlib import Path
import subprocess
import tempfile

from solders.account import Account
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.litesvm import LiteSVM
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.transaction_metadata import FailedTransactionMetadata
from runtime_errors import assert_instruction_error

TOKEN_2022 = Pubkey.from_string("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")


def run_case(binary, expected_fee=2):
    svm = LiteSVM()
    owner = Keypair()
    mint, source, destination = (Keypair().pubkey() for _ in range(3))
    svm.airdrop(owner.pubkey(), 10_000_000)
    writable = lambda address: AccountMeta(address, False, True)
    def instruction(data, accounts):
        return Instruction(TOKEN_2022, data, accounts)
    def execute(instructions):
        message = Message.new_with_blockhash(instructions, owner.pubkey(), svm.latest_blockhash())
        transaction = Transaction([owner], message, svm.latest_blockhash())
        return transaction, svm.send_transaction(transaction)
    # Base account padding + account type + TransferFeeConfig TLV (108 bytes).
    svm.set_account(mint, Account(10_000_000, bytes(278), TOKEN_2022))
    config = bytes([26, 0, 0, 0]) + (100).to_bytes(2, "little") + (100).to_bytes(8, "little")
    _, result = execute([
        instruction(config, [writable(mint)]),
        instruction(bytes([20, 6]) + bytes(owner.pubkey()) + bytes([0]), [writable(mint)]),
    ])
    assert not isinstance(result, FailedTransactionMetadata), str(result)
    for address in (source, destination):
        # Base token account + account type + TransferFeeAmount TLV (8 bytes).
        svm.set_account(address, Account(10_000_000, bytes(178), TOKEN_2022))
        _, result = execute([instruction(bytes([18]) + bytes(owner.pubkey()),
                                        [writable(address), AccountMeta(mint, False, False)])])
        assert not isinstance(result, FailedTransactionMetadata), str(result)
    auth = AccountMeta(owner.pubkey(), True, False)
    _, result = execute([instruction(bytes([7]) + (1000).to_bytes(8, "little"),
                                    [writable(mint), writable(source), auth])])
    assert not isinstance(result, FailedTransactionMetadata), str(result)
    before_source, before_destination = svm.get_account(source).data, svm.get_account(destination).data
    transfer = bytes([26, 1]) + (123).to_bytes(8, "little") + bytes([6]) + expected_fee.to_bytes(8, "little")
    tx, result = execute([instruction(transfer, [
        writable(source), AccountMeta(mint, False, False), writable(destination), auth])])
    after_source, after_destination = svm.get_account(source).data, svm.get_account(destination).data
    rejected = expected_fee != 2
    assert isinstance(result, FailedTransactionMetadata) == rejected, str(result)
    rejection = assert_instruction_error(result, 0, 32) if rejected else None
    if rejected:
        assert (before_source, before_destination) == (after_source, after_destination)
    else:
        assert int.from_bytes(after_source[64:72], "little") == 877
        assert int.from_bytes(after_destination[64:72], "little") == 121
        assert int.from_bytes(after_destination[170:178], "little") == 2
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "tx.base64"
        path.write_text(base64.b64encode(bytes(tx)).decode())
        output = subprocess.run([binary, "inspect", str(path), "--offline", "--encoding",
                                 "base64", "--report-v2"], capture_output=True, text=True, timeout=20)
        assert output.returncode == 0
        effect = json.loads(output.stdout)["effects"][0]
    assert effect["kind"] == "checked_token_transfer" and effect["amount_raw"] == "123"
    assert effect["expected_fee_raw"] == str(expected_fee)
    inventory = subprocess.run([binary, "programs", "-", "--offline"],
                               input=bytes(tx), capture_output=True, timeout=20)
    assert inventory.returncode == 0, inventory.stderr
    program = json.loads(inventory.stdout)
    declaration = program["instructions"][0]["declaration"]
    assert declaration["kind"] == "token2022_extension"
    assert declaration["operation"] == "transfer_checked_with_fee" and declaration["layout_checked"]
    assert declaration["source_account"] == str(source) and declaration["destination_account"] == str(destination)
    assert declaration["mint"] == str(mint) and declaration["declared_amount_raw"] == "123"
    assert declaration["expected_fee_raw"] == str(expected_fee) and declaration["decimals"] == 6
    assert program["signing_authorization"] == "NOT_AUTHORIZED"
    return {"program_inventory": "PASS", "case": "token2022_wrong_fee" if rejected else "token2022_transfer_fee",
            "runtime_outcome": "REJECTED" if rejected else "EXECUTED",
            "runtime_error": rejection, "wire_amount": 123, "expected_fee": expected_fee,
            "source_debit": 0 if rejected else 123, "destination_credit": 0 if rejected else 121,
            "withheld_fee": 0 if rejected else 2, "runtime_validation": "PASS", "comparison": "PASS",
            "hguet_effect_coverage": "WIRE_DECLARATION_ONLY"}
