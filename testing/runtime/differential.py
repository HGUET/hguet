"""Deterministic independent SDK differential corpus; no network or live keys."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from solders.hash import Hash
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.message import Message, MessageV0, MessageV1, TransactionConfig, to_bytes_versioned
from solders.pubkey import Pubkey
from solders.system_program import transfer, TransferParams
from solders.transaction import VersionedTransaction
from solders.address_lookup_table_account import AddressLookupTableAccount

SEED = b"hguet-phase2-differential-v1"


def digest(label):
    return hashlib.sha256(SEED + label.encode()).digest()


def pub(label):
    return Pubkey.from_bytes(digest(label))


def main():
    if not __debug__:
        raise SystemExit("assertions required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--hguet", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    binary = args.hguet.resolve()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    cases = []
    expected = 0

    def save(status):
        args.out.write_text(json.dumps({
            "corpus_version": 1, "seed": SEED.decode(), "acceptance": status,
            "mandatory_count": expected, "passed_count": sum(c["comparison"] == "PASS" for c in cases),
            "cases": cases,
        }, indent=2))

    def run(name, wire, check):
        row = {"case": name, "wire_sha256": hashlib.sha256(wire).hexdigest(),
               "wire_hex": wire.hex(), "comparison": "FAIL"}
        try:
            row.update(check())
            row["comparison"] = "PASS"
        except Exception as exc:
            row["error"] = repr(exc)
        cases.append(row)
        save("INCOMPLETE")

    def invoke(*args, data):
        p = subprocess.run([str(binary), *args], input=data, capture_output=True, timeout=20)
        return p.returncode, json.loads(p.stdout)

    payer = Keypair.from_seed(digest("payer"))
    second = Keypair.from_seed(digest("second"))
    receiver, opaque, readonly = (pub(n) for n in ("receiver", "opaque", "readonly"))
    block = Hash.from_bytes(digest("block"))
    move = lambda amount: transfer(TransferParams(from_pubkey=payer.pubkey(),
                                                   to_pubkey=receiver, lamports=amount))
    extra = Instruction(opaque, b"opaque\x00\xff", [
        AccountMeta(second.pubkey(), True, False), AccountMeta(readonly, False, False)])
    fixtures = []
    for version in ("legacy", "v0", "v1"):
        for i, amount in enumerate((0, 1, 500, 2**64 - 1)):
            for multi in (False, True):
                instructions = [move(amount), move(1)]
                if multi:
                    instructions.append(extra)
                if version == "legacy":
                    msg = Message.new_with_blockhash(instructions, payer.pubkey(), block)
                elif version == "v0":
                    msg = MessageV0.try_compile(payer.pubkey(), instructions,
                                                [AddressLookupTableAccount(pub("table"), [receiver, readonly])], block)
                else:
                    msg = MessageV1.try_compile(payer.pubkey(), instructions, block, None)
                signers = [payer, second] if multi else [payer]
                fixtures.append((f"{version}-{i}-multi{int(multi)}", msg, signers, amount))
    for mask in range(16):
        config = TransactionConfig(**{k: v for bit, (k, v) in enumerate((
            ("priority_fee", 1000), ("compute_unit_limit", 200000),
            ("loaded_accounts_data_size_limit", 65536), ("heap_size", 32768)
        )) if mask & (1 << bit)})
        msg = MessageV1.try_compile(payer.pubkey(), [move(2), move(1)], block, config)
        fixtures.append((f"v1-config-{mask:02x}", msg, [payer], 2))
    expected = len(fixtures) * 3
    save("INCOMPLETE")
    for name, msg, signers, amount in fixtures:
        tx = VersionedTransaction(msg, signers)
        raw = bytes(tx)
        def positive():
            assert bytes(VersionedTransaction.from_bytes(raw)) == raw
            code, report = invoke("report", "-", "--offline", data=raw)
            assert code == 0, report
            assert report["signing_authorization"] == "NOT_AUTHORIZED"
            assert report["message_sha256"] == hashlib.sha256(to_bytes_versioned(msg)).hexdigest()
            assert report["wire"]["asset_totals"][0]["declared_debit_raw"] == str(amount + 1)
            assert report["wire"]["observed_net_changes"] is None
            assert not report["execution_proven"]
            assert report["authority"]["changes"] == []
            with tempfile.TemporaryDirectory() as directory:
                p = Path(directory) / "original.bin"
                p.write_bytes(raw)
                code, diff = invoke("diff", str(p), "-", "--offline", data=raw)
            assert code == 0, diff
            snap = diff["before"]
            assert snap["transaction_sha256"] == hashlib.sha256(raw).hexdigest()
            assert snap["recent_blockhash_sha256"] == hashlib.sha256(bytes(block)).hexdigest()
            assert snap["signature_status"] == "verified"
            assert snap["required_signers"] == [str(k) for k in msg.account_keys[:msg.header.num_required_signatures]]
            assert diff["relation"] == "IDENTICAL_TRANSACTION_BYTES" and not diff["instruction_changes"]
            assert not diff["semantic_equivalence_proven"]
            accounts = snap["message_accounts"]
            for i, key in enumerate(msg.account_keys):
                signer = i < msg.header.num_required_signatures
                writable = (i < msg.header.num_required_signatures - msg.header.num_readonly_signed_accounts
                            if signer else i < len(msg.account_keys) - msg.header.num_readonly_unsigned_accounts)
                assert accounts[i]["address"] == str(key)
                assert accounts[i]["required_signer"] == signer and accounts[i]["writable"] == writable
            for i, ix in enumerate(msg.instructions):
                row = snap["instructions"][i]
                assert row["compiled_program_index"] == ix.program_id_index
                assert row["compiled_account_indices"] == list(ix.accounts)
                assert row["identity"]["data_sha256"] == hashlib.sha256(bytes(ix.data)).hexdigest()
            return {"kind":"SDK_VALID", "message_sha256":report["message_sha256"]}
        run(name, raw, positive)
        for label, bad in (("truncated", raw[:-1]), ("trailing", raw + b"\x00")):
            def negative():
                code, report = invoke("report", "-", "--offline", data=bad)
                assert code == 40, (code, report)
                assert report["kind"] == "hguet_report_error"
                assert report["signing_authorization"] == "NOT_AUTHORIZED"
                return {"kind":"STRUCTURALLY_INVALID", "exit_code":code}
            run(name + "-" + label, bad, negative)
    passed = len(cases) == expected and all(c["comparison"] == "PASS" for c in cases)
    save("PASS" if passed else "FAIL")
    if not passed:
        raise SystemExit("differential corpus failed; inspect recorded wire and errors")
    print(f"PASS: {expected} deterministic SDK differential cases (40 valid, 80 malformed)")


if __name__ == "__main__":
    main()
