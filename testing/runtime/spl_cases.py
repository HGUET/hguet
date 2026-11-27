"""Independent SDK transaction construction and actual SPL Token execution."""
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
from solders.token.state import Mint, TokenAccount, TokenAccountState
from solders.transaction import Transaction
from solders.transaction_metadata import FailedTransactionMetadata
from runtime_errors import assert_instruction_error

TOKEN = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")


def run_case(binary, operation, wrong_authority=False):
    svm = LiteSVM()
    owner, delegate = Keypair(), Keypair()
    mint, source, destination = (Keypair().pubkey() for _ in range(3))
    assert not isinstance(svm.airdrop(owner.pubkey(), 10_000_000), FailedTransactionMetadata)
    if wrong_authority:
        assert not isinstance(svm.airdrop(delegate.pubkey(), 1_000_000), FailedTransactionMetadata)
    svm.set_account(mint, Account(10_000_000, bytes(Mint(owner.pubkey(), 1000, 6, True)), TOKEN))
    for address, amount in [(source, 1000), (destination, 0)]:
        state = TokenAccount(mint, owner.pubkey(), amount, None,
                             TokenAccountState.Initialized, None, 0)
        svm.set_account(address, Account(10_000_000, bytes(state), TOKEN))
    auth = AccountMeta(delegate.pubkey() if wrong_authority else owner.pubkey(), True, False)
    writable = lambda address: AccountMeta(address, False, True)
    if operation == "transfer_checked":
        data = bytes([12]) + (123).to_bytes(8, "little") + bytes([6])
        accounts = [writable(source), AccountMeta(mint, False, False), writable(destination), auth]
    elif operation == "approve":
        data = bytes([4]) + (123).to_bytes(8, "little")
        accounts = [writable(source), AccountMeta(delegate.pubkey(), False, False), auth]
    else:
        data = bytes([6, 2, 1]) + bytes(delegate.pubkey())
        accounts = [writable(source), auth]
    instruction = Instruction(TOKEN, data, accounts)
    message = Message.new_with_blockhash([instruction], owner.pubkey(), svm.latest_blockhash())
    tx = Transaction([owner, delegate] if wrong_authority else [owner], message, svm.latest_blockhash())
    before = svm.get_account(source).data
    result = svm.send_transaction(tx)
    assert isinstance(result, FailedTransactionMetadata) == wrong_authority, str(result)
    rejection = assert_instruction_error(result, 0, 4) if wrong_authority else None
    state = TokenAccount.from_bytes(svm.get_account(source).data)
    if wrong_authority:
        assert svm.get_account(source).data == before
        assert TokenAccount.from_bytes(svm.get_account(destination).data).amount == 0
    elif operation == "transfer_checked":
        assert state.amount == 877
        assert TokenAccount.from_bytes(svm.get_account(destination).data).amount == 123
    elif operation == "approve":
        assert state.delegate == delegate.pubkey() and state.delegated_amount == 123
    else:
        assert state.owner == delegate.pubkey()
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "tx.base64"
        path.write_text(base64.b64encode(bytes(tx)).decode())
        process = subprocess.run([binary, "inspect", str(path), "--offline", "--encoding",
                                  "base64", "--report-v2"], capture_output=True, text=True, timeout=20)
        assert process.returncode == 0, process.stderr
        report = json.loads(process.stdout)
    effect = report["effects"][0]
    expected = {"transfer_checked": "checked_token_transfer", "approve": "delegate_approval",
                "set_authority": "authority_change"}[operation]
    assert effect["kind"] == expected
    if operation == "approve":
        assert effect["delegate"] == str(delegate.pubkey()) and effect["amount_raw"] == "123"
    elif operation == "set_authority":
        assert effect["new_authority"] == str(delegate.pubkey())
    else:
        assert effect["amount_raw"] == "123"
    return {"case": operation + ("_wrong_authority" if wrong_authority else ""),
            "runtime_outcome": "REJECTED" if wrong_authority else "EXECUTED",
            "runtime_error": rejection, "comparison":"PASS", "hguet_effect": expected,
            "source_amount_after": state.amount}
