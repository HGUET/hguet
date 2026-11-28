"""SDK-created ALT lifecycle transactions executed in isolated LiteSVM."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

from solders.address_lookup_table_account import AddressLookupTableAccount, ID
from solders.compute_budget import set_compute_unit_limit
from solders.hash import Hash
from solders.keypair import Keypair
from solders.litesvm import LiteSVM
from solders.message import Message, MessageV0
from solders.pubkey import Pubkey
from solders.system_program import (
    create_lookup_table, extend_lookup_table, freeze_lookup_table,
    deactivate_lookup_table, close_lookup_table, transfer, TransferParams,
)
from solders.transaction import Transaction, VersionedTransaction
from solders.transaction_metadata import FailedTransactionMetadata
from solders.transaction_status import InstructionErrorFieldless, TransactionErrorInstructionError

ACTIVE = 2**64 - 1


class Runtime:
    def __init__(self, binary):
        self.binary = binary
        self.svm = LiteSVM()
        self.owner, self.other = Keypair(), Keypair()
        self.recipient = Pubkey.new_unique()
        self.counter = 0
        for address in (self.owner.pubkey(), self.other.pubkey(), self.recipient):
            assert not isinstance(self.svm.airdrop(address, 100_000_000),
                                  FailedTransactionMetadata)
        self.slot(100, [99, 98])

    def slot(self, current, history):
        # Deliberately controlled sysvars, not a wall-clock or validator cooldown claim.
        self.svm.warp_to_slot(current)
        self.svm.set_slot_hashes([(s, Hash.new_unique()) for s in history])
        assert self.svm.get_clock().slot == current

    def snapshot(self, table):
        account = self.svm.get_account(table)
        assert account is not None and account.owner == ID
        data = bytes(account.data)
        assert len(data) >= 56 and (len(data)-56) % 32 == 0
        assert int.from_bytes(data[:4], "little") == 1
        assert data[21] in (0, 1)
        return {
            "lamports": account.lamports,
            "deactivation_slot": int.from_bytes(data[4:12], "little"),
            "last_extended_slot": int.from_bytes(data[12:20], "little"),
            "start_index": data[20],
            "authority": str(Pubkey.from_bytes(data[22:54])) if data[21] else None,
            "addresses": [str(Pubkey.from_bytes(data[i:i+32])) for i in range(56, len(data), 32)],
            "data_sha256": hashlib.sha256(data).hexdigest(),
        }

    def inspect(self, tx):
        wire = bytes(tx)
        p = subprocess.run([self.binary, "report", "-", "--offline"],
                           input=wire, capture_output=True, timeout=20)
        assert p.returncode == 0, p.stderr
        report = json.loads(p.stdout)
        assert report["signing_authorization"] == "NOT_AUTHORIZED"
        assert not report["execution_proven"]
        assert report["wire"]["observed_net_changes"] is None
        return report, hashlib.sha256(wire).hexdigest()

    def mutate(self, instruction, table, operation, action, signer=None, error=None):
        # Distinct Compute Budget declaration avoids replay of an identical signed tx.
        self.counter += 1
        instructions = [set_compute_unit_limit(200000+self.counter), instruction]
        block = self.svm.latest_blockhash()
        message = Message.new_with_blockhash(instructions, self.owner.pubkey(), block)
        signers = [self.owner] if signer is None else [self.owner, signer]
        tx = Transaction(signers, message, block)
        report, digest = self.inspect(tx)
        row = report["wire"]["program_report"]["instructions"][1]
        assert row["layout_status"] == "DECODED_DECLARATION"
        assert row["declaration"]["operation"] == operation
        assert row["accounts"][0]["address"] == str(table)
        changes = report["authority"]["changes"]
        assert len(changes) == 1 and changes[0]["action"] == action
        assert changes[0]["target"] == str(table)
        assert changes[0]["control_scope"] == "lookup_table"
        assert report["wire"]["flows"] == []
        assert report["wire"]["unquantified_instruction_indices"] == [1]
        outcome = self.svm.send_transaction(tx)
        if error is None:
            assert not isinstance(outcome, FailedTransactionMetadata), str(outcome)
        else:
            assert isinstance(outcome, FailedTransactionMetadata), str(outcome)
            failure = outcome.err()
            assert isinstance(failure, TransactionErrorInstructionError), repr(failure)
            assert failure.index == 1 and failure.err == error, repr(failure)
        return {"operation": operation, "wire_sha256": digest,
                "runtime": "EXECUTED" if error is None else "REJECTED",
                "runtime_error": None if error is None else str(error),
                "declaration": row["declaration"], "authority_change": changes[0]}

    def create(self):
        instruction, table = create_lookup_table(dict(
            authority_address=self.owner.pubkey(), payer_address=self.owner.pubkey(),
            recent_slot=99))
        evidence = self.mutate(instruction, table, "create_lookup_table", "initialize")
        assert evidence["declaration"]["recent_slot_raw"] == "99"
        state = self.snapshot(table)
        assert state["authority"] == str(self.owner.pubkey())
        assert state["deactivation_slot"] == ACTIVE and state["addresses"] == []
        assert state["lamports"] > 0
        return table, evidence

    def params(self, table, authority=None):
        return dict(lookup_table_address=table,
                    authority_address=authority or self.owner.pubkey())

    def extend(self, table, addresses, signer=None, error=None):
        authority = signer.pubkey() if signer else self.owner.pubkey()
        instruction = extend_lookup_table(dict(**self.params(table, authority),
            payer_address=self.owner.pubkey(), new_addresses=addresses))
        evidence = self.mutate(instruction, table, "extend_lookup_table", "extend",
                               signer=signer, error=error)
        assert evidence["declaration"]["new_addresses"] == [str(a) for a in addresses]
        return evidence

    def lookup_transfer(self, table, addresses, amount):
        self.counter += 1
        block = self.svm.latest_blockhash()
        instructions = [set_compute_unit_limit(200000+self.counter),
            transfer(TransferParams(from_pubkey=self.owner.pubkey(),
                                    to_pubkey=self.recipient, lamports=amount))]
        message = MessageV0.try_compile(self.owner.pubkey(), instructions,
            [AddressLookupTableAccount(table, addresses)], block)
        assert len(message.address_table_lookups) == 1
        tx = VersionedTransaction(message, [self.owner])
        report, digest = self.inspect(tx)
        edge = report["wire"]["flows"][0]
        assert edge["amount_raw"] == str(amount) and edge["to"]["address"] is None
        assert report["wire"]["unresolved_endpoint_instruction_indices"] == [1]
        before = self.svm.get_balance(self.recipient)
        outcome = self.svm.send_transaction(tx)
        assert not isinstance(outcome, FailedTransactionMetadata), str(outcome)
        assert self.svm.get_balance(self.recipient) - before == amount
        return {"wire_sha256": digest, "actual_recipient_delta": amount,
                "offline_destination": "UNRESOLVED"}


def freeze_branch(binary):
    rt = Runtime(binary)
    table, created = rt.create()
    addresses = [rt.recipient, Pubkey.new_unique()]
    extended = rt.extend(table, addresses)
    state = rt.snapshot(table)
    assert state["addresses"] == [str(a) for a in addresses]
    assert state["last_extended_slot"] == 100 and state["start_index"] == 0
    denied = rt.extend(table, [Pubkey.new_unique()], signer=rt.other,
                       error=InstructionErrorFieldless.IncorrectAuthority)
    assert rt.snapshot(table) == state
    rt.slot(101, [100, 99])
    used = rt.lookup_transfer(table, addresses, 500)
    frozen = rt.mutate(freeze_lookup_table(rt.params(table)), table,
                       "freeze_lookup_table", "freeze")
    state = rt.snapshot(table)
    assert state["authority"] is None and state["deactivation_slot"] == ACTIVE
    denied_extend = rt.extend(table, [Pubkey.new_unique()],
                              error=InstructionErrorFieldless.Immutable)
    denied_deactivate = rt.mutate(deactivate_lookup_table(rt.params(table)), table,
        "deactivate_lookup_table", "deactivate", error=InstructionErrorFieldless.Immutable)
    denied_close = rt.mutate(close_lookup_table(dict(**rt.params(table),
        recipient_address=rt.recipient)), table, "close_lookup_table", "close_account",
        error=InstructionErrorFieldless.Immutable)
    assert rt.snapshot(table) == state
    used_after_freeze = rt.lookup_transfer(table, addresses, 501)
    return {"created": created, "extended": extended, "wrong_authority": denied,
            "used": used, "frozen": frozen, "frozen_state": state,
            "denied_extend": denied_extend, "denied_deactivate": denied_deactivate,
            "denied_close": denied_close, "used_after_freeze": used_after_freeze}


def close_branch(binary):
    rt = Runtime(binary)
    table, created = rt.create()
    addresses = [rt.recipient]
    extended = rt.extend(table, addresses)
    rt.slot(101, [100, 99])
    close = close_lookup_table(dict(**rt.params(table), recipient_address=rt.recipient))
    state = rt.snapshot(table)
    denied_active = rt.mutate(close, table, "close_lookup_table", "close_account",
                              error=InstructionErrorFieldless.InvalidArgument)
    assert rt.snapshot(table) == state
    deactivated = rt.mutate(deactivate_lookup_table(rt.params(table)), table,
                            "deactivate_lookup_table", "deactivate")
    state = rt.snapshot(table)
    assert state["deactivation_slot"] == 101
    denied_current = rt.mutate(close, table, "close_lookup_table", "close_account",
                               error=InstructionErrorFieldless.InvalidArgument)
    assert rt.snapshot(table) == state
    rt.slot(102, [101, 100, 99])
    denied_recent = rt.mutate(close, table, "close_lookup_table", "close_account",
                              error=InstructionErrorFieldless.InvalidArgument)
    assert rt.snapshot(table) == state
    used = rt.lookup_transfer(table, addresses, 500)
    # Simulate the deactivation slot aging out of the 512-entry recent history.
    rt.slot(615, list(range(614, 102, -1)))
    before = rt.svm.get_balance(rt.recipient)
    closed = rt.mutate(close, table, "close_lookup_table", "close_account")
    account = rt.svm.get_account(table)
    assert account is None or (account.lamports == 0 and not account.data)
    assert rt.svm.get_balance(rt.recipient) - before == state["lamports"]
    assert closed["authority_change"]["recipient"] == str(rt.recipient)
    return {"created": created, "extended": extended, "denied_active": denied_active,
            "deactivated": deactivated, "deactivated_state": state,
            "denied_current_slot": denied_current, "denied_recent_slot": denied_recent,
            "used_during_cooldown": used, "closed": closed,
            "recipient_credit_lamports": state["lamports"], "slot_history_controlled": True}


def main():
    if not __debug__:
        raise SystemExit("assertions required")
    p = argparse.ArgumentParser()
    p.add_argument("--hguet", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    cases = []
    def save(status):
        args.out.write_text(json.dumps({"mandatory_count": 2, "passed_count":
            sum(c["comparison"] == "PASS" for c in cases), "cases": cases,
            "acceptance": status}, indent=2))
    save("INCOMPLETE")
    for function in (freeze_branch, close_branch):
        row = {"case": function.__name__, "comparison": "FAIL"}
        try:
            row["evidence"] = function(str(args.hguet.resolve()))
            row["comparison"] = "PASS"
        except Exception as error:
            row["error"] = repr(error)
        cases.append(row)
        save("INCOMPLETE")
    passed = len(cases) == 2 and all(c["comparison"] == "PASS" for c in cases)
    save("PASS" if passed else "FAIL")
    if not passed:
        raise SystemExit("ALT lifecycle comparison failed; inspect recorded errors")
    print("PASS: 2 actual ALT lifecycle groups (freeze and deactivation/close)")


if __name__ == "__main__":
    main()
