"""Independent SDK/runtime checks for the original-wire asset-flow view."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from solders.account import Account
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.litesvm import LiteSVM
from solders.message import Message, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.system_program import transfer, TransferParams
from solders.token.state import Mint, TokenAccount, TokenAccountState
from solders.transaction import Transaction
from solders.transaction_metadata import FailedTransactionMetadata

ROOT = Path(__file__).resolve().parents[2]
TOKEN = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
TOKEN2022 = Pubkey.from_string("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")


def main():
    if not __debug__:
        raise SystemExit("assertions required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--hguet", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    binary = args.hguet.resolve()
    registry = Registry().with_resource(
        "urn:hguet:programs:v1",
        Resource.from_contents(json.loads(
            (ROOT / "protocol/programs/v1/report.schema.json").read_text())))
    validator = Draft202012Validator(json.loads(
        (ROOT / "protocol/flow/v1/report.schema.json").read_text()), registry=registry)
    cases = []
    args.out.parent.mkdir(parents=True, exist_ok=True)

    def record(name, executed=False):
        cases.append({"case": name, "comparison": "PASS",
                      "runtime": "EXECUTED" if executed else "NOT_RUN"})
        args.out.write_text(json.dumps({"cases": cases, "acceptance": "INCOMPLETE"}, indent=2))

    def make_tx(svm, payer, instructions):
        message = Message.new_with_blockhash(instructions, payer.pubkey(), svm.latest_blockhash())
        return Transaction([payer], message, svm.latest_blockhash()), message

    def inspect(tx, message):
        p = subprocess.run([str(binary), "flow", "-", "--offline"], input=bytes(tx),
                           capture_output=True, timeout=20)
        assert p.returncode == 0, p.stderr
        r = json.loads(p.stdout)
        validator.validate(r)
        assert r["message_sha256"] == hashlib.sha256(to_bytes_versioned(message)).hexdigest()
        assert r["execution_status"] == "NOT_PERFORMED"
        assert r["signing_authorization"] == "NOT_AUTHORIZED"
        assert r["observed_net_changes"] is None and r["actual_network_fee_lamports"] is None
        for edge in r["flows"]:
            assert edge["evidence_ref"] == "/program_report/instructions/" + str(edge["instruction_index"])
            assert r["program_report"]["instructions"][edge["instruction_index"]]["instruction_index"] == edge["instruction_index"]
        return r

    svm = LiteSVM()
    payer = Keypair()
    receiver = Pubkey.new_unique()
    assert not isinstance(svm.airdrop(payer.pubkey(), 10_000_000), FailedTransactionMetadata)
    assert not isinstance(svm.airdrop(receiver, 1_000_000), FailedTransactionMetadata)
    tx, msg = make_tx(svm, payer, [
        transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=receiver, lamports=n))
        for n in (300, 201)])
    report = inspect(tx, msg)
    assert [e["amount_raw"] for e in report["flows"]] == ["300", "201"]
    assert report["asset_totals"][0]["declared_debit_raw"] == "501"
    before = svm.get_balance(receiver)
    result = svm.send_transaction(tx)
    assert not isinstance(result, FailedTransactionMetadata), str(result)
    assert svm.get_balance(receiver) - before == 501
    record("repeated_sol_declarations", True)

    svm = LiteSVM()
    payer = Keypair()
    mint, source, dest = (Pubkey.new_unique() for _ in range(3))
    assert not isinstance(svm.airdrop(payer.pubkey(), 10_000_000), FailedTransactionMetadata)
    svm.set_account(mint, Account(10_000_000, bytes(Mint(payer.pubkey(), 1000, 6, True)), TOKEN))
    for address, amount in [(source, 1000), (dest, 0)]:
        state = TokenAccount(mint, payer.pubkey(), amount, None, TokenAccountState.Initialized, None, 0)
        svm.set_account(address, Account(10_000_000, bytes(state), TOKEN))
    w = lambda key: AccountMeta(key, False, True)
    auth = AccountMeta(payer.pubkey(), True, False)
    checked = lambda amount, decimals: Instruction(TOKEN, b"\x0c" + amount.to_bytes(8, "little") + bytes([decimals]),
        [w(source), AccountMeta(mint, False, False), w(dest), auth])
    tx, msg = make_tx(svm, payer, [
        checked(123, 6),
        Instruction(TOKEN, b"\x07" + (20).to_bytes(8, "little"), [w(mint), w(dest), auth]),
        Instruction(TOKEN, b"\x08" + (7).to_bytes(8, "little"), [w(source), w(mint), auth]),
    ])
    report = inspect(tx, msg)
    total = report["asset_totals"][0]
    assert (total["declared_transfer_raw"], total["declared_mint_raw"],
            total["declared_burn_raw"], total["declared_debit_raw"]) == ("123", "20", "7", "130")
    assert report["flows"][1]["from"] is None and report["flows"][2]["to"] is None
    outcome = svm.send_transaction(tx)
    assert not isinstance(outcome, FailedTransactionMetadata), str(outcome)
    assert TokenAccount.from_bytes(svm.get_account(source).data).amount == 870
    assert TokenAccount.from_bytes(svm.get_account(dest).data).amount == 143
    assert Mint.from_bytes(svm.get_account(mint).data).supply == 1013
    record("token_transfer_mint_burn", True)

    tx, msg = make_tx(svm, payer, [
        checked(1, 6), checked(2, 9),
        Instruction(TOKEN, b"\x03" + (3).to_bytes(8, "little"), [w(source), w(dest), auth]),
        Instruction(TOKEN, b"\x04" + (99).to_bytes(8, "little"), [w(source), w(dest), auth]),
        Instruction(Pubkey.new_unique(), b"\x00", []),
    ])
    report = inspect(tx, msg)
    assert len(report["flows"]) == 3 and report["unknown_asset_instruction_indices"] == [2]
    assert report["unquantified_instruction_indices"] == [3, 4]
    total = report["asset_totals"][0]
    assert total["declared_debit_raw"] == "3" and total["conflicting_declared_decimals"]
    assert total["declared_decimals"] == [6, 9]
    record("unknown_mint_and_decimals_conflict")

    fee_data = b"\x1a\x01" + (123).to_bytes(8, "little") + b"\x06" + (2).to_bytes(8, "little")
    tx, msg = make_tx(svm, payer, [
        checked(10, 6),
        Instruction(TOKEN2022, fee_data, [w(source), AccountMeta(mint, False, False), w(dest), auth]),
    ])
    report = inspect(tx, msg)
    assert len(report["asset_totals"]) == 2
    fee_total = next(t for t in report["asset_totals"] if t["asset"]["token_program"] == str(TOKEN2022))
    assert fee_total["declared_debit_raw"] == "123"
    assert fee_total["declared_expected_fee_raw"] == "2"
    assert fee_total["expected_fee_instruction_count"] == 1
    record("fee_not_double_counted_and_programs_separate")

    p = subprocess.run([str(binary), "flow", "-", "--offline"], input=b"\xff", capture_output=True, timeout=20)
    assert p.returncode == 40
    validator.validate(json.loads(p.stdout))
    p = subprocess.run([str(binary), "flow", "-"], input=bytes(tx), capture_output=True, timeout=20)
    assert p.returncode == 40
    validator.validate(json.loads(p.stdout))
    record("versioned_errors_and_explicit_offline")

    args.out.write_text(json.dumps({"cases": cases, "mandatory_count": 5,
                                    "passed_count": len(cases), "acceptance": "PASS"}, indent=2))
    print("PASS: 5 asset flow SDK/CLI comparisons; 2 executed in LiteSVM")


if __name__ == "__main__":
    main()
