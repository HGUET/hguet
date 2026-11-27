"""Independent SDK fixtures for the additive offline program inventory."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from jsonschema import Draft202012Validator
from solders.compute_budget import set_compute_unit_limit, set_compute_unit_price
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.litesvm import LiteSVM
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.transaction_metadata import FailedTransactionMetadata

ROOT = Path(__file__).resolve().parents[2]
MEMO = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
COMPUTE = Pubkey.from_string("ComputeBudget111111111111111111111111111111")
ATA = Pubkey.from_string("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
TOKEN = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
SYSTEM = Pubkey.default()
TOKEN_2022 = Pubkey.from_string("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")


def main():
    if not __debug__:
        raise SystemExit("assertions required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--hguet", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    binary = args.hguet.resolve()
    schema = Draft202012Validator(json.loads(
        (ROOT / "protocol/programs/v1/report.schema.json").read_text()))
    cases = []

    def inspect(instructions, execute=False):
        svm = LiteSVM()
        payer = Keypair()
        assert not isinstance(svm.airdrop(payer.pubkey(), 10_000_000), FailedTransactionMetadata)
        message = Message.new_with_blockhash(instructions(payer.pubkey()), payer.pubkey(),
                                             svm.latest_blockhash())
        tx = Transaction([payer], message, svm.latest_blockhash())
        wire = bytes(tx)
        process = subprocess.run([str(binary), "programs", "-", "--offline"],
                                 input=wire, capture_output=True, timeout=20)
        assert process.returncode == 0, process.stderr
        report = json.loads(process.stdout)
        schema.validate(report)
        assert report["message_sha256"] == hashlib.sha256(bytes(message)).hexdigest()
        assert report["signing_authorization"] == "NOT_AUTHORIZED"
        if execute:
            result = svm.send_transaction(tx)
            assert not isinstance(result, FailedTransactionMetadata), str(result)
        return report

    def record(name, runtime=False):
        cases.append({"case": name, "comparison": "PASS",
                      "runtime": "EXECUTED" if runtime else "NOT_RUN"})
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps({"cases": cases, "acceptance": "INCOMPLETE"}, indent=2))

    report = inspect(lambda _: [set_compute_unit_limit(200000), set_compute_unit_price(5)], True)
    declarations = [i["declaration"] for i in report["instructions"]]
    assert [i["value_raw"] for i in declarations] == ["200000", "5"]
    assert [i["operation"] for i in declarations] == [
        "set_compute_unit_limit", "set_compute_unit_price"]
    assert all(not i["message_v1"] for i in declarations)
    record("sdk_compute_budget", True)

    secret = b"synthetic memo fixture"
    report = inspect(lambda _: [Instruction(MEMO, secret, [])], True)
    assert report["instructions"][0]["declaration"] == {
        "kind": "memo", "byte_length": len(secret), "valid_utf8": True}
    assert secret.decode() not in json.dumps(report)
    record("sdk_memo_payload_omitted", True)

    report = inspect(lambda _: [Instruction(MEMO, b"\xff", []),
                                Instruction(COMPUTE, b"\x02\x01", []),
                                Instruction(Pubkey.new_unique(), b"\x00", [])])
    assert [i["layout_status"] for i in report["instructions"]] == [
        "INVALID_UTF8", "UNSUPPORTED_LAYOUT", "UNSUPPORTED_LAYOUT"]
    assert report["instructions"][2]["family"] == "unknown_program"
    record("invalid_and_opaque_layouts")

    wallet, mint = Pubkey.new_unique(), Pubkey.new_unique()
    ata, _ = Pubkey.find_program_address([bytes(wallet), bytes(TOKEN), bytes(mint)], ATA)

    def ata_instructions(payer):
        accounts = [AccountMeta(payer, True, True), AccountMeta(ata, False, True),
                    AccountMeta(wallet, False, False), AccountMeta(mint, False, False),
                    AccountMeta(SYSTEM, False, False), AccountMeta(TOKEN, False, False)]
        bad = accounts[:-1] + [AccountMeta(MEMO, False, False)]
        return [Instruction(ATA, b"\x01", accounts), Instruction(ATA, b"\x01", bad)]

    report = inspect(ata_instructions)
    a, b = report["instructions"]
    assert a["declaration"]["operation"] == "create_idempotent"
    assert a["declaration"]["static_program_roles_match"] is True
    assert b["declaration"]["static_program_roles_match"] is False
    assert a["accounts"][1]["address"] == str(ata)
    assert a["accounts"][2]["address"] == str(wallet)
    assert a["accounts"][0]["required_signer"] is True
    record("sdk_ata_declared_roles")

    def token_instructions(payer):
        source, mint, destination, delegate = (Pubkey.new_unique() for _ in range(4))
        auth = AccountMeta(payer, True, False)
        w = lambda key: AccountMeta(key, False, True)
        r = lambda key: AccountMeta(key, False, False)
        return [
            Instruction(TOKEN, b"\x03" + (99).to_bytes(8, "little") + b"\xff",
                        [w(source), w(destination), auth]),
            Instruction(TOKEN, b"\x07" + (123).to_bytes(8, "little"),
                        [w(mint), w(destination), auth]),
            Instruction(TOKEN, b"\x08" + (17).to_bytes(8, "little"),
                        [w(source), w(mint), auth]),
            Instruction(TOKEN, b"\x05", [w(source), auth]),
            Instruction(TOKEN, b"\x06\x03\x00", [w(source), auth]),
            Instruction(TOKEN, b"\x09", [w(source), w(destination), auth]),
            Instruction(TOKEN, b"\x0a", [w(source), r(mint), auth]),
            Instruction(TOKEN, b"\x0b", [w(source), r(mint), auth]),
            Instruction(TOKEN, b"\x11", [w(source)]),
            Instruction(TOKEN, b"\x0c\x01", [w(source), r(mint), w(destination), auth]),
            Instruction(TOKEN_2022, b"\x23" + bytes(delegate), [w(mint)]),
            Instruction(TOKEN_2022, b"\x24\x01" + bytes(delegate), [w(mint), auth]),
            Instruction(TOKEN_2022, b"\x1b\x00", [w(mint)]),
        ]

    report = inspect(token_instructions)
    rows = report["instructions"]
    assert [row["declaration"]["operation"] for row in rows[:9]] == [
        "transfer", "mint_to", "burn", "revoke", "set_authority", "close_account",
        "freeze_account", "thaw_account", "sync_native"]
    assert rows[0]["declaration"]["amount_raw"] == "99"
    assert rows[1]["declaration"]["amount_raw"] == "123"
    assert rows[2]["declaration"]["amount_raw"] == "17"
    assert rows[4]["declaration"]["authority_type"] == 3
    assert rows[4]["declaration"]["new_authority"] is None
    assert rows[9]["layout_status"] == "UNSUPPORTED_LAYOUT"
    assert rows[10]["declaration"]["operation"] == "initialize_permanent_delegate"
    assert rows[10]["declaration"]["new_authority"] is not None
    assert rows[11]["declaration"]["operation"] == "update_transfer_hook"
    assert rows[11]["declaration"]["hook_program_id"] is not None
    assert rows[12]["layout_status"] == "PREFIX_ONLY"
    assert rows[12]["declaration"]["mint"] is None
    record("sdk_token_instruction_inventory")

    process = subprocess.run([str(binary), "programs", "-", "--offline"],
                             input=b"\xff", capture_output=True, timeout=20)
    assert process.returncode == 40
    schema.validate(json.loads(process.stdout))
    record("versioned_input_error")

    args.out.write_text(json.dumps({"cases": cases, "acceptance": "PASS",
                                    "mandatory_count": 6, "passed_count": len(cases)}, indent=2))
    print("PASS: 6 independent SDK/CLI comparisons; 2 executed in LiteSVM")


if __name__ == "__main__":
    main()
