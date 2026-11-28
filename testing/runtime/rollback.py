"""Actual local runtime rollback comparisons, not simulation claims."""
import argparse
import json
from pathlib import Path
import subprocess

from solders.keypair import Keypair
from solders.litesvm import LiteSVM
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import transfer, TransferParams
from solders.transaction import Transaction
from solders.transaction_metadata import FailedTransactionMetadata
from solders.account import Account
from solders.instruction import Instruction, AccountMeta
from solders.token.state import Mint, TokenAccount, TokenAccountState
from runtime_errors import assert_instruction_error

TOKEN = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")


def main():
    if not __debug__:
        raise SystemExit("assertions required")
    p = argparse.ArgumentParser()
    p.add_argument("--hguet", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    binary = args.hguet.resolve()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    cases = []

    def save(status):
        args.out.write_text(json.dumps({"mandatory_count":2, "passed_count":len(cases),
            "acceptance":status,"cases":cases}, indent=2))

    def inspect(svm, payer, instructions):
        msg = Message.new_with_blockhash(instructions, payer.pubkey(), svm.latest_blockhash())
        tx = Transaction([payer], msg, svm.latest_blockhash())
        result = subprocess.run([str(binary),"report","-","--offline"],input=bytes(tx),
                                capture_output=True,timeout=20)
        assert result.returncode == 0, result.stderr
        report = json.loads(result.stdout)
        assert report["signing_authorization"] == "NOT_AUTHORIZED"
        assert not report["execution_proven"]
        assert report["wire"]["observed_net_changes"] is None
        return tx, report

    save("INCOMPLETE")
    svm = LiteSVM()
    payer = Keypair()
    receiver = Pubkey.new_unique()
    assert not isinstance(svm.airdrop(payer.pubkey(), 10_000_000), FailedTransactionMetadata)
    assert not isinstance(svm.airdrop(receiver, 1_000_000), FailedTransactionMetadata)
    before = svm.get_balance(receiver)
    tx, report = inspect(svm,payer,[transfer(TransferParams(
        from_pubkey=payer.pubkey(),to_pubkey=receiver,lamports=n)) for n in (500,20_000_000)])
    assert report["wire"]["asset_totals"][0]["declared_debit_raw"] == "20000500"
    outcome = svm.send_transaction(tx)
    assert isinstance(outcome, FailedTransactionMetadata), outcome
    rejection = assert_instruction_error(outcome, 1, 1)
    assert svm.get_balance(receiver) == before
    cases.append({"case":"late_native_failure_rolls_back_first_transfer","comparison":"PASS",
                  "declared_debit_raw":"20000500","actual_recipient_delta":0,
                  "runtime_error":str(outcome.err()), "rejection":rejection})
    save("INCOMPLETE")

    svm = LiteSVM()
    payer = Keypair()
    assert not isinstance(svm.airdrop(payer.pubkey(),10_000_000),FailedTransactionMetadata)
    mint, source, dest, delegate = (Pubkey.new_unique() for _ in range(4))
    svm.set_account(mint,Account(10_000_000,bytes(Mint(payer.pubkey(),1000,6,True)),TOKEN))
    for address, amount in ((source,1000),(dest,0)):
        state=TokenAccount(mint,payer.pubkey(),amount,None,TokenAccountState.Initialized,None,0)
        svm.set_account(address,Account(10_000_000,bytes(state),TOKEN))
    w=lambda key: AccountMeta(key,False,True)
    r=lambda key: AccountMeta(key,False,False)
    auth=AccountMeta(payer.pubkey(),True,False)
    approve=Instruction(TOKEN,b"\x04"+(99).to_bytes(8,"little"),[w(source),r(delegate),auth])
    overspend=Instruction(TOKEN,b"\x0c"+(1001).to_bytes(8,"little")+b"\x06",
                          [w(source),r(mint),w(dest),auth])
    before=[bytes(svm.get_account(a).data) for a in (source,dest,mint)]
    tx,report=inspect(svm,payer,[approve,overspend])
    assert report["authority"]["changes"][0]["declared_delegate_limit_raw"] == "99"
    assert report["wire"]["asset_totals"][0]["declared_debit_raw"] == "1001"
    outcome=svm.send_transaction(tx)
    assert isinstance(outcome,FailedTransactionMetadata),outcome
    rejection = assert_instruction_error(outcome, 1, 1)
    assert [bytes(svm.get_account(a).data) for a in (source,dest,mint)] == before
    assert TokenAccount.from_bytes(svm.get_account(source).data).delegate is None
    cases.append({"case":"late_token_failure_rolls_back_delegate_approval","comparison":"PASS",
                  "declared_delegate_limit_raw":"99","actual_delegate":None,
                  "runtime_error":str(outcome.err()), "rejection":rejection})
    save("PASS")
    print("PASS: 2 actual LiteSVM rollback comparisons")


if __name__=="__main__":
    main()
