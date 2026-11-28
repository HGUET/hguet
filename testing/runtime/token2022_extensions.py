"""Actual local Token-2022 state comparisons. Disposable test keys, no network."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from solders.account import Account
from solders.instruction import AccountMeta, Instruction
from solders.keypair import Keypair
from solders.litesvm import LiteSVM
from solders.message import Message
from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.transaction_metadata import FailedTransactionMetadata
from runtime_errors import assert_instruction_error

TOKEN = Pubkey.from_string("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")


def w(key):
    return AccountMeta(key, False, True)


def r(key):
    return AccountMeta(key, False, False)


def auth(key):
    return AccountMeta(key, True, False)


def ix(data, *accounts):
    return Instruction(TOKEN, data, list(accounts))


def u64(n):
    return n.to_bytes(8, "little")


def extension(data, tag, length):
    # Extended mint/account layout: base, padding if necessary, type, TLV.
    offset = 166
    while offset + 4 <= len(data):
        kind = int.from_bytes(data[offset:offset+2], "little")
        size = int.from_bytes(data[offset+2:offset+4], "little")
        assert offset + 4 + size <= len(data)
        if kind == tag:
            assert size == length
            return bytes(data[offset+4:offset+4+size])
        offset += 4 + size
    raise AssertionError(f"extension {tag} missing")


class Runtime:
    def __init__(self, binary):
        self.binary = binary
        self.svm = LiteSVM()
        self.owner = Keypair()
        self.other = Keypair()
        for signer in (self.owner, self.other):
            assert not isinstance(self.svm.airdrop(signer.pubkey(), 100_000_000),
                                  FailedTransactionMetadata)
        self.mint = Pubkey.new_unique()

    def data(self, key):
        return bytes(self.svm.get_account(key).data)

    def send(self, instructions, signer=None, expected_error=None):
        signers = [self.owner] if signer is None else [self.owner, signer]
        message = Message.new_with_blockhash(instructions, self.owner.pubkey(),
                                             self.svm.latest_blockhash())
        tx = Transaction(signers, message, self.svm.latest_blockhash())
        output = subprocess.run([self.binary, "report", "-", "--offline"],
                                input=bytes(tx), capture_output=True, timeout=20)
        assert output.returncode == 0, output.stderr
        report = json.loads(output.stdout)
        assert report["signing_authorization"] == "NOT_AUTHORIZED"
        assert not report["execution_proven"]
        assert report["wire"]["observed_net_changes"] is None
        result = self.svm.send_transaction(tx)
        if expected_error is None:
            assert not isinstance(result, FailedTransactionMetadata), str(result)
            rejection = None
        else:
            assert isinstance(result, FailedTransactionMetadata), str(result)
            rejection = assert_instruction_error(result, 0, expected_error)
        return report, {"wire_sha256": hashlib.sha256(bytes(tx)).hexdigest(),
                        "runtime_error": rejection}

    def initialize_mint(self, length, extension_ix):
        self.svm.set_account(self.mint, Account(10_000_000, bytes(length), TOKEN))
        report, evidence = self.send([
            extension_ix,
            ix(bytes([20, 6]) + bytes(self.owner.pubkey()) + bytes([0]), w(self.mint)),
        ])
        return report, evidence

    def token_account(self, length, immutable=False):
        address = Pubkey.new_unique()
        self.svm.set_account(address, Account(10_000_000, bytes(length), TOKEN))
        instructions = [ix(bytes([22]), w(address))] if immutable else []
        instructions.append(ix(bytes([18]) + bytes(self.owner.pubkey()),
                               w(address), r(self.mint)))
        self.send(instructions)
        return address

    def mint_to(self, destination, amount):
        self.send([ix(bytes([7]) + u64(amount), w(self.mint), w(destination),
                      auth(self.owner.pubkey()))])

    def amount(self, address):
        return int.from_bytes(self.data(address)[64:72], "little")

    def checked(self, source, destination, amount, signer):
        return ix(bytes([12]) + u64(amount) + bytes([6]), w(source),
                  r(self.mint), w(destination), auth(signer.pubkey()))


def permanent_delegate(binary):
    rt = Runtime(binary)
    delegate = rt.other
    report, init = rt.initialize_mint(202, ix(bytes([35]) + bytes(delegate.pubkey()), w(rt.mint)))
    change = report["authority"]["changes"][0]
    assert change["control_scope"] == "mint_permanent_delegate"
    assert change["proposed_authority"] == str(delegate.pubkey())
    assert extension(rt.data(rt.mint), 12, 32) == bytes(delegate.pubkey())
    src, dst = rt.token_account(165), rt.token_account(165)
    rt.mint_to(src, 1000)
    # No account-level approval. The separate permanent delegate signs the local test.
    assert rt.data(src)[72:76] == bytes(4)
    report, move = rt.send([rt.checked(src, dst, 123, delegate)], signer=delegate)
    assert (rt.amount(src), rt.amount(dst)) == (877, 123)
    assert report["wire"]["asset_totals"][0]["declared_debit_raw"] == "123"
    assert report["wire"]["program_report"]["instructions"][0]["declaration"]["authority"] == str(delegate.pubkey())
    return {"init": init, "transfer": move, "source_after": 877,
            "destination_after": 123, "account_delegate_present": False}


def transfer_hook_config(binary):
    rt = Runtime(binary)
    hook = Pubkey.new_unique()
    replacement = Pubkey.new_unique()
    report, init = rt.initialize_mint(
        234, ix(bytes([36, 0]) + bytes(rt.owner.pubkey()) + bytes(hook), w(rt.mint)))
    change = report["authority"]["changes"][0]
    assert change["control_scope"] == "mint_transfer_hook"
    assert change["proposed_hook_program"] == str(hook)
    assert extension(rt.data(rt.mint), 14, 64) == bytes(rt.owner.pubkey()) + bytes(hook)
    before = rt.data(rt.mint)
    _, denied = rt.send([ix(bytes([36, 1]) + bytes(replacement), w(rt.mint),
                            auth(rt.other.pubkey()))], signer=rt.other, expected_error=4)
    assert rt.data(rt.mint) == before
    report, update = rt.send([ix(bytes([36, 1]) + bytes(replacement), w(rt.mint),
                                 auth(rt.owner.pubkey()))])
    assert report["authority"]["changes"][0]["proposed_hook_program"] == str(replacement)
    assert extension(rt.data(rt.mint), 14, 64)[32:] == bytes(replacement)
    report, remove = rt.send([ix(bytes([36, 1]) + bytes(32), w(rt.mint),
                                 auth(rt.owner.pubkey()))])
    assert report["authority"]["changes"][0]["proposed_hook_program"] is None
    assert extension(rt.data(rt.mint), 14, 64)[32:] == bytes(32)
    return {"init": init, "unauthorized": denied, "update": update,
            "remove": remove, "hook_cpi_executed": False}


def fee_lifecycle(binary):
    rt = Runtime(binary)
    config = (bytes([26, 0, 1]) + bytes(rt.owner.pubkey()) + bytes([1])
              + bytes(rt.other.pubkey()) + (100).to_bytes(2, "little") + u64(100))
    _, init = rt.initialize_mint(278, ix(config, w(rt.mint)))
    state = extension(rt.data(rt.mint), 1, 108)
    assert state[:32] == bytes(rt.owner.pubkey()) and state[32:64] == bytes(rt.other.pubkey())
    src, dst = rt.token_account(178), rt.token_account(178)
    rt.mint_to(src, 1000)
    data = bytes([26, 1]) + u64(123) + bytes([6]) + u64(2)
    _, transfer = rt.send([ix(data, w(src), r(rt.mint), w(dst), auth(rt.owner.pubkey()))])
    assert (rt.amount(src), rt.amount(dst)) == (877, 121)
    assert extension(rt.data(dst), 2, 8) == u64(2)
    _, harvest = rt.send([ix(bytes([26, 4]), w(rt.mint), w(dst))])
    assert extension(rt.data(dst), 2, 8) == u64(0)
    assert extension(rt.data(rt.mint), 1, 108)[64:72] == u64(2)
    before = (rt.data(rt.mint), rt.data(dst))
    _, denied = rt.send([ix(bytes([26, 2]), w(rt.mint), w(dst),
                            auth(rt.owner.pubkey()))], expected_error=4)
    assert (rt.data(rt.mint), rt.data(dst)) == before
    report, withdraw = rt.send([ix(bytes([26, 2]), w(rt.mint), w(dst),
                                     auth(rt.other.pubkey()))], signer=rt.other)
    assert rt.amount(dst) == 123 and extension(rt.data(rt.mint), 1, 108)[64:72] == u64(0)
    # No amount is encoded in the withdrawal instruction; offline coverage must stay partial.
    assert report["wire"]["unquantified_instruction_indices"] == [0]
    assert report["wire"]["flows"] == []
    data = bytes([26, 5]) + (250).to_bytes(2, "little") + u64(99)
    before = rt.data(rt.mint)
    _, denied_config = rt.send([ix(data, w(rt.mint), auth(rt.other.pubkey()))],
                               signer=rt.other, expected_error=4)
    assert rt.data(rt.mint) == before
    report, update = rt.send([ix(data, w(rt.mint), auth(rt.owner.pubkey()))])
    declaration = report["wire"]["program_report"]["instructions"][0]["declaration"]
    assert declaration["fee_basis_points"] == 250 and declaration["maximum_fee_raw"] == "99"
    assert report["authority"]["changes"][0]["control_scope"] == "mint_transfer_fee_config"
    state = extension(rt.data(rt.mint), 1, 108)
    assert state[98:106] == u64(99) and state[106:108] == (250).to_bytes(2, "little")
    return {"init": init, "transfer": transfer, "harvest": harvest, "denied_withdraw": denied,
            "withdraw": withdraw, "denied_config": denied_config, "update": update,
            "withdrawn_raw": 2, "future_fee_bps": 250,
            "future_fee_maximum_raw": 99, "active_fee_not_inferred": True}


def nontransferable(binary):
    rt = Runtime(binary)
    report, init = rt.initialize_mint(170, ix(bytes([32]), w(rt.mint)))
    assert report["wire"]["program_report"]["instructions"][0]["layout_status"] == "PREFIX_ONLY"
    assert extension(rt.data(rt.mint), 9, 0) == b""
    src, dst = rt.token_account(174, immutable=True), rt.token_account(174, immutable=True)
    rt.mint_to(src, 1000)
    before = (rt.data(src), rt.data(dst))
    report, denied = rt.send([rt.checked(src, dst, 1, rt.owner)], expected_error=37)
    assert (rt.data(src), rt.data(dst)) == before
    assert report["wire"]["asset_totals"][0]["declared_debit_raw"] == "1"
    return {"init": init, "denied": denied, "source_after": 1000, "destination_after": 0}


def main():
    if not __debug__:
        raise SystemExit("assertions required")
    p = argparse.ArgumentParser()
    p.add_argument("--hguet", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    functions = [permanent_delegate, transfer_hook_config, fee_lifecycle, nontransferable]
    rows = []

    def save(status):
        args.out.write_text(json.dumps({"mandatory_count": len(functions),
            "passed_count": sum(r["comparison"] == "PASS" for r in rows),
            "acceptance": status, "cases": rows}, indent=2))

    save("INCOMPLETE")
    for function in functions:
        row = {"case": function.__name__, "comparison": "FAIL"}
        try:
            row["evidence"] = function(str(args.hguet.resolve()))
            row["comparison"] = "PASS"
        except Exception as error:
            row["error"] = repr(error)
        rows.append(row)
        save("INCOMPLETE")
    passed = len(rows) == len(functions) and all(r["comparison"] == "PASS" for r in rows)
    save("PASS" if passed else "FAIL")
    if not passed:
        raise SystemExit("Token-2022 runtime comparison failed; inspect case evidence")
    print("PASS: 4 Token-2022 runtime groups")


if __name__ == "__main__":
    main()
