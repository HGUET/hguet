"""SDK-constructed authority declarations, with separate real runtime state checks."""
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
    registry = Registry().with_resource("urn:hguet:programs:v1", Resource.from_contents(
        json.loads((ROOT / "protocol/programs/v1/report.schema.json").read_text())))
    schema = json.loads((ROOT / "protocol/authority/v1/report.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, registry=registry)
    cases = []
    args.out.parent.mkdir(parents=True, exist_ok=True)

    def record(name, executed=False):
        cases.append({"case": name, "comparison": "PASS",
                      "runtime": "EXECUTED" if executed else "NOT_RUN"})
        args.out.write_text(json.dumps({"cases": cases, "acceptance": "INCOMPLETE"}, indent=2))

    svm = LiteSVM()
    payer = Keypair()
    delegate, mint, source, empty, proposed, hook = (Pubkey.new_unique() for _ in range(6))
    assert not isinstance(svm.airdrop(payer.pubkey(), 10_000_000), FailedTransactionMetadata)
    # Construct canonical SPL Mint state including freeze authority.
    mint_state = (bytes(Mint(payer.pubkey(), 1000, 6, True))[:46]
                  + (1).to_bytes(4, "little") + bytes(payer.pubkey()))
    assert len(mint_state) == 82
    svm.set_account(mint, Account(10_000_000, mint_state, TOKEN))
    for account, amount in [(source, 1000), (empty, 0)]:
        state = TokenAccount(mint, payer.pubkey(), amount, None,
                             TokenAccountState.Initialized, None, 0)
        svm.set_account(account, Account(10_000_000, bytes(state), TOKEN))

    w = lambda key: AccountMeta(key, False, True)
    r = lambda key: AccountMeta(key, False, False)
    auth = AccountMeta(payer.pubkey(), True, False)

    def token(data, accounts):
        return Instruction(TOKEN, data, accounts)

    def inspect(instructions, execute=False):
        msg = Message.new_with_blockhash(instructions, payer.pubkey(), svm.latest_blockhash())
        tx = Transaction([payer], msg, svm.latest_blockhash())
        p = subprocess.run([str(binary), "authority", "-", "--offline"],
                           input=bytes(tx), capture_output=True, timeout=20)
        assert p.returncode == 0, p.stderr
        report = json.loads(p.stdout)
        validator.validate(report)
        assert report["message_sha256"] == hashlib.sha256(to_bytes_versioned(msg)).hexdigest()
        assert not report["execution_proven"] and not report["authorization_proven"]
        for event in report["changes"]:
            index = event["instruction_index"]
            assert event["evidence_ref"] == f"/program_report/instructions/{index}"
            assert report["program_report"]["instructions"][index]["instruction_index"] == index
        if execute:
            outcome = svm.send_transaction(tx)
            assert not isinstance(outcome, FailedTransactionMetadata), str(outcome)
        return report

    report = inspect([token(b"\x04" + (200).to_bytes(8, "little"), [w(source), r(delegate), auth])], True)
    assert report["changes"][0]["declared_delegate_limit_raw"] == "200"
    assert TokenAccount.from_bytes(svm.get_account(source).data).delegate == delegate
    report = inspect([token(b"\x05", [w(source), auth])], True)
    assert report["changes"][0]["action"] == "revoke_delegate"
    state = TokenAccount.from_bytes(svm.get_account(source).data)
    assert state.delegate is None and state.delegated_amount == 0 and state.amount == 1000
    record("runtime_delegate_revoke", True)

    for opcode, action, expected in [(10, "freeze", TokenAccountState.Frozen),
                                      (11, "thaw", TokenAccountState.Initialized)]:
        report = inspect([token(bytes([opcode]), [w(source), r(mint), auth])], True)
        assert report["changes"][0]["action"] == action
        assert report["changes"][0]["control_scope"] == "token_account_state"
        state = TokenAccount.from_bytes(svm.get_account(source).data)
        assert state.state == expected and state.amount == 1000
    record("runtime_freeze_thaw", True)

    report = inspect([token(b"\x06\x00\x00", [w(mint), auth])], True)
    event = report["changes"][0]
    assert event["control_scope"] == "mint_authority"
    assert event["action"] == "request_authority_removal" and event["proposed_authority"] is None
    assert Mint.from_bytes(svm.get_account(mint).data).mint_authority is None
    record("runtime_mint_authority_removal", True)

    report = inspect([token(b"\x09", [w(empty), w(payer.pubkey()), auth])], True)
    assert report["changes"][0]["recipient"] == str(payer.pubkey())
    assert report["changes"][0]["action"] == "close_account"
    account = svm.get_account(empty)
    assert account is None or account.lamports == 0
    record("runtime_close_empty_token_account", True)

    report = inspect([
        token(b"\x06\x01\x01" + bytes(proposed), [w(mint), auth]),
        token(b"\x06\xff\x01" + bytes(proposed), [w(mint), auth]),
        token(b"\x06\x01\x01", [w(mint), auth]),
        Instruction(TOKEN2022, b"\x23" + bytes(delegate), [w(mint)]),
        Instruction(TOKEN2022, b"\x24\x01" + bytes(hook), [w(mint), auth]),
        Instruction(TOKEN2022, b"\x1b\x00", [w(mint)]),
    ])
    events = report["changes"]
    assert [e["instruction_index"] for e in events] == [0, 1, 3, 4]
    assert events[0]["control_scope"] == "freeze_authority"
    assert events[1]["control_scope"] == "unclassified_authority_type"
    assert events[1]["authority_type_raw"] == 255
    assert events[2]["control_scope"] == "mint_permanent_delegate"
    assert events[2]["proposed_authority"] == str(delegate)
    assert events[3]["control_scope"] == "mint_transfer_hook"
    assert events[3]["proposed_hook_program"] == str(hook)
    assert report["unclassified_instruction_indices"] == [1, 2, 5]
    record("sdk_control_scope_and_unknowns")

    report = inspect([
        token(b"\x04" + (200).to_bytes(8, "little"), [w(source), r(delegate), auth]),
        token(b"\x04" + (10).to_bytes(8, "little"), [w(source), r(proposed), auth]),
        token(b"\x05", [w(source), auth]),
    ])
    assert [e["declared_delegate_limit_raw"] for e in report["changes"]] == ["200", "10", None]
    assert [e["action"] for e in report["changes"]] == ["set_delegate", "set_delegate", "revoke_delegate"]
    record("ordered_approvals_not_summed")

    for options in (["--offline"], []):
        p = subprocess.run([str(binary), "authority", "-", *options],
                           input=b"\xff", capture_output=True, timeout=20)
        assert p.returncode == 40
        validator.validate(json.loads(p.stdout))
    record("versioned_errors")

    args.out.write_text(json.dumps({"cases": cases, "mandatory_count": 7,
                                    "passed_count": len(cases), "acceptance": "PASS"}, indent=2))
    print("PASS: 7 authority SDK/CLI comparisons; 4 cases executed in LiteSVM")


if __name__ == "__main__":
    main()
