"""Network-isolated SDK/CLI tests for semantic transaction comparison."""
import argparse
import json
from pathlib import Path
import subprocess
import tempfile

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message, MessageV0
from solders.address_lookup_table_account import AddressLookupTableAccount
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction, VersionedTransaction

TOKEN = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
MEMO = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")


def main():
    if not __debug__:
        raise SystemExit("assertions required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--hguet", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    binary = args.hguet.resolve()
    cases = []
    args.out.parent.mkdir(parents=True, exist_ok=True)

    def record(name):
        cases.append({"case": name, "comparison": "PASS"})
        args.out.write_text(json.dumps({"cases": cases, "acceptance": "INCOMPLETE"}, indent=2))

    payer, other = Keypair(), Keypair()
    receiver, source, delegate = (Pubkey.new_unique() for _ in range(3))
    block = Hash.new_unique()

    def tx(instructions, signer=payer, recent=block):
        message = Message.new_with_blockhash(instructions, signer.pubkey(), recent)
        return bytes(Transaction([signer], message, recent))

    def sol(n):
        return transfer(TransferParams(from_pubkey=payer.pubkey(), to_pubkey=receiver, lamports=n))

    def compare(a, b):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "before"
            path.write_bytes(a)
            p = subprocess.run([str(binary), "diff", str(path), "-", "--offline"],
                               input=b, capture_output=True, timeout=20)
        assert p.returncode == 0, p.stderr
        report = json.loads(p.stdout)
        assert report["signing_authorization"] == "NOT_AUTHORIZED"
        assert not report["semantic_equivalence_proven"]
        for change in report["instruction_changes"]:
            for side in ("before", "after"):
                index = change[side + "_index"]
                if index is not None:
                    assert change[side + "_ref"] == f"/{side}/instructions/{index}"
                    assert report[side]["instructions"][index]
                else:
                    assert change[side + "_ref"] is None
        return report

    original = tx([sol(100)])
    report = compare(original, original)
    assert report["relation"] == "IDENTICAL_TRANSACTION_BYTES" and not report["instruction_changes"]
    unsigned = bytearray(original)
    unsigned[1:65] = bytes(64)
    report = compare(original, bytes(unsigned))
    assert report["relation"] == "IDENTICAL_MESSAGE_BYTES"
    assert report["before"]["signature_status"] != report["after"]["signature_status"]
    record("byte_and_signature_identity")

    report = compare(original, tx([sol(1000)]))
    assert report["relation"] == "MESSAGE_CHANGED"
    assert "asset_movement" in report["instruction_changes"][0]["changed_fields"]
    assert report["before"]["instructions"][0]["asset_movement"]["amount_raw"] == "100"
    assert report["after"]["instructions"][0]["asset_movement"]["amount_raw"] == "1000"
    record("economic_amount_change")

    approval = Instruction(TOKEN, b"\x04" + (99).to_bytes(8, "little"),
                           [AccountMeta(source, False, True), AccountMeta(delegate, False, False),
                            AccountMeta(payer.pubkey(), True, False)])
    report = compare(original, tx([sol(100), approval]))
    assert report["instruction_changes"][-1]["status"] == "ADDED_AT_POSITION"
    assert report["after"]["instructions"][1]["authority_change"]["action"] == "set_delegate"
    record("added_authority_change")

    report = compare(tx([sol(100), sol(200), sol(100)]), tx([sol(100), sol(100), sol(200)]))
    assert report["instruction_multiset_equal"] and not report["ordered_instruction_fingerprints_equal"]
    report = compare(tx([sol(100), sol(100)]), original)
    assert not report["instruction_multiset_equal"]
    record("order_and_duplicate_multiplicity")

    report = compare(tx([Instruction(MEMO, b"memo1", [])]), tx([Instruction(MEMO, b"memo2", [])]))
    assert report["instruction_changes"][0]["changed_fields"] == ["instruction_data"]
    assert "memo1" not in json.dumps(report) and "memo2" not in json.dumps(report)
    opaque = Pubkey.new_unique()
    report = compare(tx([Instruction(opaque, b"x", [])]), tx([Instruction(opaque, b"y", [])]))
    assert report["before"]["coverage_gap_indices"] == [0]
    assert report["instruction_changes"][0]["changed_fields"] == ["instruction_data"]
    record("opaque_and_memo_payload_hashes")

    report = compare(original, tx([sol(100)], recent=Hash.new_unique()))
    assert report["message_fields_changed"] == ["recent_blockhash"]
    report = compare(tx([]), tx([], signer=other))
    assert "fee_payer" in report["message_fields_changed"] and "required_signers" in report["message_fields_changed"]
    p = Pubkey.new_unique()
    report = compare(tx([Instruction(opaque, b"x", [AccountMeta(p, False, False)])]),
                     tx([Instruction(opaque, b"x", [AccountMeta(p, False, True)])]))
    assert "accounts_or_privileges" in report["instruction_changes"][0]["changed_fields"]
    record("message_context_and_privileges")

    def lookup_tx(table):
        msg = MessageV0.try_compile(payer.pubkey(), [sol(100)],
                                   [AddressLookupTableAccount(table, [receiver])], block)
        return bytes(VersionedTransaction(msg, [payer]))

    report = compare(lookup_tx(Pubkey.new_unique()), lookup_tx(Pubkey.new_unique()))
    assert report["before"]["coverage_gap_indices"] == [0]
    assert report["before"]["instructions"][0]["identity"]["accounts"][1]["address"] is None
    assert "accounts_or_privileges" in report["instruction_changes"][0]["changed_fields"]
    record("unresolved_lookup_identity")

    p = subprocess.run([str(binary), "diff", "-", "-", "--offline"], input=original,
                       capture_output=True, timeout=20)
    assert p.returncode == 40 and json.loads(p.stdout)["kind"] == "hguet_diff_error"
    record("bounded_input_errors")
    args.out.write_text(json.dumps({"cases": cases, "mandatory_count": 8,
                                    "passed_count": len(cases), "acceptance": "PASS"}, indent=2))
    print("PASS: 8 offline semantic diff SDK/CLI comparisons")


if __name__ == "__main__":
    main()
