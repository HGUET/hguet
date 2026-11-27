"""Network-isolated SDK/CLI tests for semantic transaction comparison."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from jsonschema import Draft202012Validator
from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message, MessageV0, MessageV1, TransactionConfig, to_bytes_versioned
from solders.address_lookup_table_account import AddressLookupTableAccount
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction, VersionedTransaction

TOKEN = Pubkey.from_string("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
MEMO = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
ROOT = Path(__file__).resolve().parents[2]


def main():
    if not __debug__:
        raise SystemExit("assertions required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--hguet", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    binary = args.hguet.resolve()
    schema = json.loads((ROOT / "protocol/diff/v1/report.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
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
        validator.validate(report)
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
    assert "address_table_lookups" in report["message_fields_changed"]
    record("unresolved_lookup_identity")

    default = MessageV1.try_compile(payer.pubkey(), [sol(100)], block, None)
    configured = MessageV1.try_compile(payer.pubkey(), [sol(100)], block,
        TransactionConfig(priority_fee=1000, compute_unit_limit=200000,
                          loaded_accounts_data_size_limit=65536, heap_size=32768))
    report = compare(bytes(VersionedTransaction(default, [payer])),
                     bytes(VersionedTransaction(configured, [payer])))
    assert report["before"]["message_sha256"] == hashlib.sha256(to_bytes_versioned(default)).hexdigest()
    assert report["after"]["message_sha256"] == hashlib.sha256(to_bytes_versioned(configured)).hexdigest()
    assert report["message_fields_changed"] == ["resource_config"]
    assert report["after"]["resource_config"]["priority_fee_lamports"] == 1000
    assert report["before"]["recent_blockhash_sha256"] == hashlib.sha256(bytes(block)).hexdigest()
    assert report["ordered_instruction_fingerprints_equal"]
    record("v1_inline_resource_change")

    p = subprocess.run([str(binary), "diff", "-", "-", "--offline"], input=original,
                       capture_output=True, timeout=20)
    assert p.returncode == 40 and json.loads(p.stdout)["kind"] == "hguet_diff_error"
    validator.validate(json.loads(p.stdout))
    record("bounded_input_errors")

    audit_schema = json.loads((ROOT / "protocol/audit/v1/report.schema.json").read_text())
    Draft202012Validator.check_schema(audit_schema)
    audit_validator = Draft202012Validator(audit_schema)
    from solders.signature import Signature
    signature = str(Signature.from_bytes(original[1:65]))
    for inputs in (["invalid", "--network", "devnet", "--rpc-url", "https://rpc.example"],
                   [signature], [signature, "--network", "devnet"],
                   [signature, "--network", "devnet", "--rpc-url", "http://rpc.example"]):
        p = subprocess.run([str(binary), "audit", *inputs], capture_output=True, timeout=20)
        assert p.returncode == 40, p.stderr
        audit_validator.validate(json.loads(p.stdout))
    record("historical_audit_invalid_configuration")
    args.out.write_text(json.dumps({"cases": cases, "mandatory_count": 10,
                                    "passed_count": len(cases), "acceptance": "PASS"}, indent=2))
    print("PASS: 9 offline semantic diff SDK/CLI comparisons and 1 audit configuration group")


if __name__ == "__main__":
    main()
