#!/usr/bin/env python3
"""Deterministically generate the committed benchmark scenarios (testing/scenarios/*.json).

GROUND TRUTH IS AUTHORED HERE FROM THE THREAT SEMANTICS, NOT FROM HGUET OUTPUT.
Each scenario states, before any tool is run: the label (GOOD/BAD/UNKNOWN), which
decisions are acceptable, which finding families a correct tool must raise, and
why. HGUET is never invoked by this script. `--check` fails if the committed
files differ from what this generator produces (no silent hand edits).
"""
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "lib"))
import crypto_tx as ct  # noqa: E402

OUT = HERE.parent / "scenarios"
FORMAT = "hguet-bench-scenario/1"
ISSUER = "issuer:trusted"
TRUSTED = ct.signer_pubkey(ISSUER)
PAYER_LABEL = "signer:payer"
PAYER = ct.signer_pubkey(PAYER_LABEL)
ALICE, BOB, EVE = ct.plain_pubkey("dest:alice"), ct.plain_pubkey("dest:bob"), ct.plain_pubkey("dest:eve-attacker")
MINT_A, MINT_B, MINT_EVIL = ct.plain_pubkey("mint:A"), ct.plain_pubkey("mint:B"), ct.plain_pubkey("mint:evil")
SRC_A, DST_A = ct.plain_pubkey("tokacct:payer:A"), ct.plain_pubkey("tokacct:merchant:A")
SRC_B, DST_B = ct.plain_pubkey("tokacct:payer:B"), ct.plain_pubkey("tokacct:merchant:B")
SRC_OTHER = ct.plain_pubkey("tokacct:victim-other")
NONSIGNER = ct.plain_pubkey("auth:never-signs")
T, T22 = ct.TOKEN, ct.TOKEN_2022
SYS, CB, MEMO = ct.SYSTEM, ct.COMPUTE_BUDGET, ct.MEMO

# Family names group finding codes by security meaning (a correct tool may use any member).
F_INTENT = ["INTENT_REJECTED"]
F_TOKEN_INTENT = ["INTENT_REJECTED", "SIGNED_INTENT_TOKEN_CAP_INVALID"]
F_SOURCE_INTENT = ["INTENT_REJECTED", "SIGNED_INTENT_SOURCE_SCOPE_INVALID"]
FORBIDDEN_FOR_GOOD = [
    "INTENT_REJECTED", "SIGNED_INTENT_TOKEN_CAP_INVALID", "SIGNED_INTENT_SOURCE_SCOPE_INVALID",
    "POLICY_SOL_TRANSFER_CAP", "POLICY_BLOCKED_SOL_RECIPIENT", "POLICY_BLOCKED_PROGRAM",
    "POLICY_UNAPPROVED_PROGRAM", "POLICY_UNAPPROVED_SOL_RECIPIENT", "POLICY_WRONG_NETWORK",
    "INVALID_TRANSACTION_SIGNATURE", "MALFORMED_TRANSACTION", "BAD_INPUT", "BAD_SIGNED_INTENT",
]
PROVEN_INTENT = [{"path": "verdict.coverage", "contains": "independently_pinned_intent_signature"}]
SCENARIOS = []


def tx_b64(instructions, signers=(), mode="unsigned", v0=None, blockhash="bh1"):
    raw, message = ct.build_transaction(instructions, PAYER, signers, v0, blockhash, mode)
    return raw, message


def add(sid, cls, title, category, rationale, raw, message, *, network="devnet", intent=None,
        trusted=TRUSTED, policy=None, rpc=None, smoke=False, build=None, extra_expect=None,
        evidence="offline_sufficient", acceptable=None, required=None, forbidden=None, proven=None,
        tx_encoding="base64"):
    import base64
    acceptable = acceptable or {"GOOD": ["ALLOW", "UNKNOWN"], "BAD": ["DENY"], "UNKNOWN": ["UNKNOWN"]}[cls]
    scenario = {
        "format": FORMAT, "id": sid, "class": cls, "title": title, "category": category,
        "smoke": smoke, "rationale": rationale,
        "build_spec": build or {},
        "input": {
            "network": network,
            "transaction": {"encoding": tx_encoding, "data": base64.b64encode(raw).decode()},
            "message_sha256_independent": __import__("hashlib").sha256(message).hexdigest() if message else None,
            "intent": intent, "trusted_key": trusted, "policy_toml": policy, "rpc": rpc or {"mode": "none"},
        },
        "truth": {
            "label": cls, "acceptable_decisions": acceptable, "evidence_level": evidence,
            "authored_independently_of_tool": True,
        },
        "expect": {
            "findings_required": required or [],
            "findings_forbidden": forbidden if forbidden is not None else (FORBIDDEN_FOR_GOOD if cls == "GOOD" else []),
            "proven": proven or [],
        },
    }
    if extra_expect:
        scenario["expect"].update(extra_expect)
    SCENARIOS.append(scenario)


def intent_for(message, tamper=False, **kw):
    return ct.sign_intent(ct.intent_payload(message, **kw), ISSUER, tamper=tamper)


def pay(dst, lamports):
    return ct.ix_system_transfer(PAYER, dst, lamports)


def policy(**fields):
    lines = ["version = 1", 'network = "%s"' % fields.pop("network", "devnet")]
    for key, value in fields.items():
        if isinstance(value, list):
            lines.append("%s = [%s]" % (key, ", ".join('"%s"' % v for v in value)))
        else:
            lines.append('%s = "%s"' % (key, value))
    return "\n".join(lines) + "\n"


# =============================================================== GOOD (20)
def good():
    def sol(sid, title, why, instrs, *, signers=(), mode="unsigned", cap="5000", progs=(SYS,), smoke=False,
            network="devnet", v0=None, policy_toml=None, category="sol_transfer", proven=None):
        raw, msg = tx_b64(instrs, signers, mode, v0)
        add(sid, "GOOD", title, category, why, raw, msg, network=network,
            intent=intent_for(msg, network=network, max_spend=cap, allowed_programs=list(progs),
                              intent_id="bench-" + sid),
            policy=policy_toml, smoke=smoke, proven=(proven if proven is not None else PROVEN_INTENT),
            build={"cap": cap})

    sol("G-001", "Plain SOL payment below the signed cap",
        "1000 lamports to the approved payee, signed cap 5000: exactly what the issuer authorised.",
        [pay(ALICE, 1000)], smoke=True)
    sol("G-002", "SOL payment exactly at the signed cap",
        "Boundary: amount == cap is within authority (cap is an upper bound, inclusive).",
        [pay(ALICE, 5000)])
    sol("G-003", "Two SOL payments whose sum is below the cap",
        "1200 + 1800 = 3000 <= 5000; summed declared spend stays inside the cap.",
        [pay(ALICE, 1200), pay(BOB, 1800)])
    sol("G-004", "SOL payment with compute-budget instruction",
        "ComputeBudget carries no value transfer and is on the issuer allowlist.",
        [ct.ix_compute_budget_limit(200000), pay(ALICE, 900)], progs=(SYS, CB))
    sol("G-005", "SOL payment with a memo",
        "Memo program adds a reference string; no value movement; allowlisted.",
        [ct.Instruction(MEMO, [(PAYER, True, False)], b"invoice-4711"), pay(ALICE, 900)], progs=(SYS, MEMO))
    sol("G-006", "Fully signed SOL payment",
        "Transaction carries a valid Ed25519 signature from the fee payer; payment within cap.",
        [pay(ALICE, 2500)], signers=(PAYER_LABEL,), mode="valid",
        proven=PROVEN_INTENT + [{"path": "inspection.transaction_signature_status", "equals": "verified"}])
    sol("G-007", "Mainnet SOL payment with mainnet-bound intent",
        "Intent network equals the checked network; value inside cap.", [pay(BOB, 700)], network="mainnet")
    sol("G-008", "Testnet SOL payment with testnet-bound intent",
        "Intent network equals the checked network; value inside cap.", [pay(BOB, 700)], network="testnet")
    raw, msg = tx_b64([pay(ALICE, 1500)], v0=[])
    add("G-009", "GOOD", "v0 transaction without lookup tables", "sol_transfer",
        "A v0 message that uses only static keys is fully resolvable offline; 1500 <= 5000.",
        raw, msg, intent=intent_for(msg, max_spend="5000", intent_id="bench-G-009"), proven=PROVEN_INTENT)

    def tok(sid, title, why, instrs, *, caps=None, sources=None, progs=(SYS, T), cap_sol="1000", smoke=False,
            proven=None, category="token_transfer", signers=(), mode="unsigned"):
        raw, msg = tx_b64(instrs, signers, mode)
        add(sid, "GOOD", title, category, why, raw, msg,
            intent=intent_for(msg, allowed_programs=list(progs), max_spend=cap_sol, token_caps=caps,
                              source_caps=sources, intent_id="bench-" + sid),
            smoke=smoke, proven=proven if proven is not None else PROVEN_INTENT)

    tok("G-010", "SPL transfer exactly at the signed mint cap",
        "TransferChecked 1000 of mint A, signed per-mint cap 1000 (inclusive upper bound).",
        [ct.ix_token_transfer_checked(T, SRC_A, MINT_A, DST_A, PAYER, 1000)], caps=[(MINT_A, "1000")], smoke=True)
    tok("G-011", "SPL transfer below the signed mint cap",
        "500 <= 1000 signed cap.", [ct.ix_token_transfer_checked(T, SRC_A, MINT_A, DST_A, PAYER, 500)],
        caps=[(MINT_A, "1000")])
    tok("G-012", "Two SPL transfers summing exactly to the cap",
        "400 + 600 = 1000 equals cap; aggregation per mint must not false-positive.",
        [ct.ix_token_transfer_checked(T, SRC_A, MINT_A, DST_A, PAYER, 400),
         ct.ix_token_transfer_checked(T, SRC_A, MINT_A, DST_A, PAYER, 600)], caps=[(MINT_A, "1000")])
    tok("G-013", "Token-2022 checked transfer below the signed cap",
        "Token-2022 program with a plain TransferChecked of 300 under cap 1000.",
        [ct.ix_token_transfer_checked(T22, SRC_A, MINT_A, DST_A, PAYER, 300)], caps=[(MINT_A, "1000")],
        progs=(SYS, T22))
    tok("G-014", "Checked token burn below the signed cap",
        "BurnChecked of 200 under cap 1000: a declared debit inside the authorised bound.",
        [ct.ix_token_burn_checked(T, SRC_A, MINT_A, PAYER, 200)], caps=[(MINT_A, "1000")], category="token_burn")
    src = [(MINT_A, SRC_A, PAYER, "1000")]
    tok("G-015", "Source-scoped SPL transfer below the signed source cap",
        "Debit from the exact authorised source account by the exact authority (a required signer).",
        [ct.ix_token_transfer_checked(T, SRC_A, MINT_A, DST_A, PAYER, 700)], sources=src, smoke=True,
        proven=PROVEN_INTENT + [{"path": "signed_token_source_review.transaction_required_signer_role_checked",
                                 "equals": True}])
    tok("G-016", "Source-scoped SPL transfer exactly at the source cap",
        "Boundary on the source-scoped cap.",
        [ct.ix_token_transfer_checked(T, SRC_A, MINT_A, DST_A, PAYER, 1000)], sources=src,
        proven=PROVEN_INTENT + [{"path": "signed_token_source_review.transaction_required_signer_role_checked",
                                 "equals": True}])
    tok("G-017", "Transfers of two approved mints, each under its cap",
        "Independent caps per mint; neither is exceeded.",
        [ct.ix_token_transfer_checked(T, SRC_A, MINT_A, DST_A, PAYER, 100),
         ct.ix_token_transfer_checked(T, SRC_B, MINT_B, DST_B, PAYER, 900)],
        caps=[(MINT_A, "500"), (MINT_B, "900")])
    # Policy-governed good cases (restrictive local policy; the transfer satisfies every rule).
    raw, msg = tx_b64([pay(ALICE, 400)])
    add("G-018", "GOOD", "SOL payment satisfying a restrictive local policy", "policy",
        "Policy cap 499, allowed recipient Alice, allowed program System; transfer 400 to Alice.",
        raw, msg, intent=intent_for(msg, max_spend="5000", intent_id="bench-G-018"),
        policy=policy(max_declared_system_transfer_lamports="499", allowed_sol_recipients=[ALICE],
                      allowed_program_ids=[SYS]), proven=PROVEN_INTENT + [
            {"path": "verdict.coverage", "contains": "local_restrictive_policy"}], smoke=True)
    raw, msg = tx_b64([pay(ALICE, 499)])
    add("G-019", "GOOD", "SOL payment exactly at the policy cap with unrelated deny lists", "policy",
        "499 equals the policy cap; the deny lists name other keys, so nothing applies.",
        raw, msg, intent=intent_for(msg, max_spend="5000", intent_id="bench-G-019"),
        policy=policy(max_declared_system_transfer_lamports="499", denied_sol_recipients=[EVE],
                      denied_program_ids=[ct.DRAINER_PROGRAM]), proven=PROVEN_INTENT)
    raw, msg = tx_b64([ct.ix_compute_budget_limit(300000),
                       ct.Instruction(MEMO, [(PAYER, True, False)], b"order-77"), pay(BOB, 1500)],
                      (PAYER_LABEL,), "valid")
    add("G-020", "GOOD", "Realistic signed payment: compute budget, memo and transfer", "sol_transfer",
        "All programs allowlisted, value inside cap, valid signature.", raw, msg,
        intent=intent_for(msg, max_spend="5000", allowed_programs=[SYS, CB, MEMO], intent_id="bench-G-020"),
        proven=PROVEN_INTENT + [{"path": "inspection.transaction_signature_status", "equals": "verified"}])


# ================================================================ BAD (25)
def bad():
    def sol(sid, title, why, instrs, *, req, cap="5000", progs=(SYS,), smoke=False, category="intent",
            nb=1, exp=4102444800, network="devnet", check_network=None, tamper=False, issuer=ISSUER,
            hash_from=None, signers=(), mode="unsigned"):
        raw, msg = tx_b64(instrs, signers, mode)
        bound = msg if hash_from is None else hash_from
        payload = ct.intent_payload(bound, network=network, max_spend=cap, allowed_programs=list(progs),
                                    not_before=nb, expires=exp, intent_id="bench-" + sid)
        add(sid, "BAD", title, category, why, raw, msg, network=check_network or network,
            intent=ct.sign_intent(payload, issuer, tamper=tamper), smoke=smoke,
            required=[req], build={"cap": cap})

    sol("B-001", "SOL transfer above the signed spend cap",
        "6000 lamports requested, issuer authorised at most 5000: spend-limit violation.",
        [pay(ALICE, 6000)], req=F_INTENT, smoke=True)
    sol("B-002", "Instruction to a program outside the signed allowlist",
        "Extra call to an unreviewed custom program; the issuer allowed only System.",
        [pay(ALICE, 1000), ct.ix_custom(ct.CUSTOM_PROGRAM, [(PAYER, True, True)])], req=F_INTENT)
    other_raw, other_msg = tx_b64([pay(ALICE, 1000)])
    sol("B-003", "Transaction swapped after intent approval",
        "Intent was issued for a 1000-lamport payment to Alice; the presented transaction drains 4900 to Eve.",
        [pay(EVE, 4900)], req=F_INTENT, smoke=True, hash_from=other_msg, category="intent_binding")
    sol("B-004", "Expired intent", "Authorisation window closed long ago (expires 1970-01-01T00:16:40Z).",
        [pay(ALICE, 1000)], req=F_INTENT, nb=1, exp=1000, category="intent_time")
    sol("B-005", "Intent not yet valid", "not_before is in the year 2100; authority does not exist yet.",
        [pay(ALICE, 1000)], req=F_INTENT, nb=4102444000, exp=4102444800, category="intent_time")
    sol("B-006", "Intent signed by an untrusted key",
        "The pinned issuer key differs from the key that signed the intent (attacker-supplied authority).",
        [pay(ALICE, 1000)], req=F_INTENT, issuer="issuer:attacker", category="intent_trust")
    sol("B-007", "Intent payload altered after signing",
        "The spend cap was edited post-signature; Ed25519 verification must fail.",
        [pay(ALICE, 1000)], req=F_INTENT, tamper=True, category="intent_integrity")
    sol("B-008", "Devnet intent replayed on mainnet",
        "Intent is bound to devnet; presenting it for a mainnet check is cross-network replay.",
        [pay(ALICE, 1000)], req=F_INTENT, network="devnet", check_network="mainnet", category="intent_binding")

    def tokbad(sid, title, why, instrs, *, req, caps=None, sources=None, progs=(SYS, T), smoke=False,
               category="token_cap", cap_sol="1000"):
        raw, msg = tx_b64(instrs)
        add(sid, "BAD", title, category, why, raw, msg,
            intent=intent_for(msg, allowed_programs=list(progs), max_spend=cap_sol, token_caps=caps,
                              source_caps=sources, intent_id="bench-" + sid),
            required=[req], smoke=smoke)

    tc = [(MINT_A, "1000")]
    tokbad("B-009", "Token transfer above the signed per-mint cap",
           "1500 of mint A against a signed cap of 1000.",
           [ct.ix_token_transfer_checked(T, SRC_A, MINT_A, DST_A, PAYER, 1500)], req=F_TOKEN_INTENT, caps=tc,
           smoke=True)
    tokbad("B-010", "Token transfer of a mint the issuer never approved",
           "Mint EVIL is absent from the signed token_spend_limits.",
           [ct.ix_token_transfer_checked(T, SRC_A, MINT_EVIL, DST_A, PAYER, 1)], req=F_TOKEN_INTENT, caps=tc,
           category="token_mint")
    tokbad("B-011", "Split token transfers exceeding the cap in aggregate",
           "600 + 600 = 1200 > 1000: each instruction alone looks small.",
           [ct.ix_token_transfer_checked(T, SRC_A, MINT_A, DST_A, PAYER, 600),
            ct.ix_token_transfer_checked(T, SRC_A, MINT_A, DST_A, PAYER, 600)], req=F_TOKEN_INTENT, caps=tc)
    tokbad("B-012", "Unchecked token Transfer under mint caps",
           "Opcode 3 carries no mint/decimals; its mint cannot be bound to the signed cap.",
           [ct.ix_token_transfer_unchecked(T, SRC_A, DST_A, PAYER, 10)], req=F_TOKEN_INTENT, caps=tc,
           category="token_unbounded")
    tokbad("B-013", "Token Approve (delegate) hidden among permitted transfers",
           "Approve grants a third party spending authority; it is outside any payment cap.",
           [ct.ix_token_transfer_checked(T, SRC_A, MINT_A, DST_A, PAYER, 10),
            ct.ix_token_approve(T, SRC_A, EVE, PAYER, 18446744073709551615)], req=F_TOKEN_INTENT, caps=tc,
           category="token_authority")
    sol_only = dict(progs=(SYS, T), cap_sol="1000")
    tokbad("B-014", "SetAuthority transferring token-account ownership to an attacker",
           "A payment intent never authorises handing account ownership to Eve (ownership theft).",
           [ct.ix_token_set_authority(T, SRC_A, PAYER, EVE)],
           req=["WIRE_TOKEN_DIRECT_AUTHORITY_RISK", "INTENT_REJECTED", "SIGNED_INTENT_TOKEN_CAP_INVALID"],
           category="token_authority", **sol_only)
    tokbad("B-015", "CloseAccount sweeping the account to an attacker address",
           "CloseAccount moves the rent and closes the account to Eve; not a payment.",
           [ct.ix_token_close_account(T, SRC_A, EVE, PAYER)],
           req=["WIRE_TOKEN_DIRECT_AUTHORITY_RISK", "INTENT_REJECTED", "SIGNED_INTENT_TOKEN_CAP_INVALID"],
           category="token_authority", **sol_only)
    srcs = [(MINT_A, SRC_A, PAYER, "1000")]
    tokbad("B-016", "Debit from a source account the issuer never scoped",
           "Signed source scope covers SRC_A only; the transaction drains another account.",
           [ct.ix_token_transfer_checked(T, SRC_OTHER, MINT_A, DST_A, PAYER, 5)], req=F_SOURCE_INTENT,
           sources=srcs, category="token_source")
    tokbad("B-017", "Debit authority differs from the signed authority",
           "Source scope names the payer as authority; the instruction uses a different signer.",
           [ct.Instruction(T, [(SRC_A, False, True), (MINT_A, False, False), (DST_A, False, True),
                               (ct.signer_pubkey("signer:other"), True, False)],
                           bytes([12]) + (5).to_bytes(8, "little") + bytes([6]))],
           req=F_SOURCE_INTENT, sources=srcs, category="token_source")
    tokbad("B-018", "Debit authority is not a required transaction signer",
           "The scoped authority is an account that is not a signer of the transaction (and not the fee payer): the debit cannot be authorised.",
           [ct.Instruction(T, [(SRC_A, False, True), (MINT_A, False, False), (DST_A, False, True),
                               (NONSIGNER, False, False)],
                           bytes([12]) + (5).to_bytes(8, "little") + bytes([6]))],
           req=F_SOURCE_INTENT, sources=[(MINT_A, SRC_A, NONSIGNER, "1000")], category="token_source")

    def pol(sid, title, why, instrs, *, req, toml, smoke=False, category="policy"):
        raw, msg = tx_b64(instrs)
        add(sid, "BAD", title, category, why, raw, msg, intent=None, trusted=None, policy=toml,
            required=[req], smoke=smoke)

    pol("B-019", "SOL transfer above the local policy cap", "500 lamports against a hard cap of 499.",
        [pay(ALICE, 500)], req=["POLICY_SOL_TRANSFER_CAP"], smoke=True,
        toml=policy(max_declared_system_transfer_lamports="499"))
    pol("B-020", "Transfer to a denylisted recipient", "Eve is on the operator denylist.",
        [pay(EVE, 10)], req=["POLICY_BLOCKED_SOL_RECIPIENT"], toml=policy(denied_sol_recipients=[EVE]))
    pol("B-021", "Call to a denylisted program", "A known drainer program id is on the operator denylist.",
        [pay(ALICE, 10), ct.ix_custom(ct.DRAINER_PROGRAM, [(PAYER, True, True)])],
        req=["POLICY_BLOCKED_PROGRAM"], toml=policy(denied_program_ids=[ct.DRAINER_PROGRAM]))
    pol("B-022", "Program outside the operator allowlist", "Only System is allowed; a custom program is invoked.",
        [pay(ALICE, 10), ct.ix_custom(ct.CUSTOM_PROGRAM, [(PAYER, True, True)])],
        req=["POLICY_UNAPPROVED_PROGRAM"], toml=policy(allowed_program_ids=[SYS]))
    pol("B-023", "Recipient outside the operator allowlist", "Only Alice may be paid; Bob is not approved.",
        [pay(BOB, 10)], req=["POLICY_UNAPPROVED_SOL_RECIPIENT"], toml=policy(allowed_sol_recipients=[ALICE]))
    raw, msg = tx_b64([pay(ALICE, 1000)], (PAYER_LABEL,), "invalid")
    add("B-024", "BAD", "Transaction with a forged signature", "transaction_integrity",
        "Signature bytes are non-zero but do not verify for the fee payer: a forged or corrupted transaction.",
        raw, msg, intent=intent_for(msg, max_spend="5000", intent_id="bench-B-024"),
        required=[["INVALID_TRANSACTION_SIGNATURE"]], smoke=True)
    raw, msg = tx_b64([pay(ALICE, 1000)])
    cut = raw[:len(raw) - 20]
    add("B-025", "BAD", "Truncated transaction bytes", "transaction_integrity",
        "Wire bytes are cut mid-instruction; no valid Solana transaction can be decoded from them.",
        cut, None, intent=None, trusted=None, required=[["MALFORMED_TRANSACTION"]], smoke=True)


# ============================================================= UNKNOWN (15)
def unknown():
    def unk(sid, title, why, instrs, *, req, intent=True, trusted=TRUSTED, progs=(SYS,), cap="5000", v0=None,
            policy_toml=None, rpc=None, smoke=False, evidence="insufficient", category="evidence_gap",
            caps=None, sources=None, signers=(), mode="unsigned", forbidden=None):
        raw, msg = tx_b64(instrs, signers, mode, v0)
        add(sid, "UNKNOWN", title, category, why, raw, msg,
            intent=intent_for(msg, max_spend=cap, allowed_programs=list(progs), token_caps=caps,
                              source_caps=sources, intent_id="bench-" + sid) if intent else None,
            trusted=trusted, policy=policy_toml, rpc=rpc, required=[req] if req else [], smoke=smoke,
            evidence=evidence, forbidden=forbidden if forbidden is not None else [])

    unk("U-001", "Payment with no authorisation evidence",
        "No intent and no pinned issuer key: nothing independent states what is allowed.",
        [pay(ALICE, 1000)], req=["INTENT_UNVERIFIED"], intent=False, trusted=None, smoke=True)
    unk("U-002", "Intent present but issuer key not pinned",
        "An intent file exists, but without an independently pinned key it carries no authority.",
        [pay(ALICE, 1000)], req=["INTENT_UNVERIFIED"], trusted=None)
    raw, msg = tx_b64([ct.Instruction(SYS, [(PAYER, True, True), ("alt:0", False, True)],
                                      (2).to_bytes(4, "little") + (1000).to_bytes(8, "little"))],
                      v0=[("tbl1", [0], [])])
    add("U-003", "UNKNOWN", "v0 transfer whose destination lives in an unresolved lookup table", "alt",
        "The payee address is only an index into an Address Lookup Table that offline mode cannot resolve.",
        raw, msg, intent=None, trusted=None, required=[["WIRE_TOKEN_DIRECT_ALT_UNRESOLVED"]],
        evidence="insufficient", forbidden=[], smoke=False)
    add("U-004", "UNKNOWN", "v0 transfer with unresolved lookup table AND a valid intent", "alt",
        "The issuer authorised something, but who is paid is unresolved: neither safe nor provably bad. "
        "A tool that answers DENY here claims knowledge it does not have (UNKNOWN != DENY).",
        raw, msg, intent=intent_for(msg, max_spend="5000", intent_id="bench-U-004"), required=[],
        evidence="insufficient", forbidden=[], smoke=True)
    unk("U-005", "Call to an unreviewed custom program, no authorisation",
        "Effects of an arbitrary program cannot be evaluated offline and nothing authorises it.",
        [ct.ix_custom(ct.CUSTOM_PROGRAM, [(PAYER, True, True)])], req=["INTENT_UNVERIFIED"], intent=False,
        trusted=None)
    unk("U-006", "Token-2022 instruction with opaque extension semantics",
        "Opcode 255 is not a decodable core instruction; its effect on balances is undetermined.",
        [ct.Instruction(T22, [(SRC_A, False, True), (PAYER, True, False)], bytes([255, 1, 2, 3]))],
        req=["WIRE_TOKEN_DIRECT_OPAQUE"], progs=(SYS, T22), evidence="requires_rpc")
    raw, msg = tx_b64([pay(ALICE, 1000)])
    unsupported = raw[:1 + 64] + b"\x82" + raw[1 + 64 + 1:]
    add("U-007", "UNKNOWN", "Transaction with an unsupported message version", "format",
        "Version byte 0x82 does not exist; the tool cannot interpret the transaction at all.",
        unsupported, None, intent=None, trusted=None, required=[["UNSUPPORTED_FORMAT"]], evidence="insufficient")
    unk("U-008", "SOL-only intent but the transaction moves tokens",
        "The intent caps lamports only; token debits are neither authorised nor limited.",
        [ct.ix_token_transfer_checked(T, SRC_A, MINT_A, DST_A, PAYER, 10)],
        req=["SIGNED_INTENT_TOKEN_CAP_UNSPECIFIED"], progs=(SYS, T), smoke=False, evidence="insufficient")
    raw, msg = tx_b64([ct.Instruction("alt:0", [(PAYER, True, True)], b"")], v0=[("tbl2", [], [0])])
    add("U-009", "UNKNOWN", "Allowlist policy with a program resolved only through a lookup table", "alt",
        "The program identity itself is behind an unresolved lookup; an allowlist cannot be evaluated.",
        raw, msg, intent=None, trusted=None, policy=policy(allowed_program_ids=[SYS]),
        required=[["POLICY_UNRESOLVED_PROGRAM", "WIRE_TOKEN_DIRECT_ALT_UNRESOLVED"]], evidence="insufficient")
    rpc_cases = [
        ("U-010", "closed_port", "RPC endpoint refuses connections",
         "The user asked for simulation but the RPC provider is unreachable: no simulation evidence exists."),
        ("U-011", "non_tls_garbage", "RPC endpoint answers with non-TLS bytes",
         "A server that does not speak TLS must not be believed; there is no verified simulation."),
        ("U-012", "hangup", "RPC endpoint closes the connection immediately",
         "Abrupt close gives no response; simulation is unavailable, not clean."),
    ]
    for sid, behavior, title, why in rpc_cases:
        unk(sid, title, why, [pay(ALICE, 1000)], req=["RPC_SIMULATION_FAILED", "NO_SIMULATION", "RPC_TRANSPORT_FAILURE"],
            rpc={"mode": "mock", "behavior": behavior}, smoke=(sid == "U-010"), evidence="requires_rpc",
            category="rpc_failure", progs=(SYS,))
    unk("U-013", "Token debit with an extra multisig-style account under source caps",
        "A legitimate multisig authority adds accounts; HGUET cannot validate it offline - unknown, not malicious.",
        [ct.Instruction(T, [(SRC_A, False, True), (MINT_A, False, False), (DST_A, False, True), (PAYER, True, False),
                            (ct.signer_pubkey("signer:cosigner"), True, False)],
                        bytes([12]) + (5).to_bytes(8, "little") + bytes([6]))],
        req=[], sources=[(MINT_A, SRC_A, PAYER, "1000")], progs=(SYS, T), evidence="insufficient")
    unk("U-014", "Token-2022 fee-bearing transfer within the declared cap",
        "TransferCheckedWithFee: gross debit is amount + fee; the fee depends on mint state only RPC can read.",
        [ct.Instruction(T22, [(SRC_A, False, True), (MINT_A, False, False), (DST_A, False, True), (PAYER, True, False)],
                        bytes([26, 1]) + (900).to_bytes(8, "little") + bytes([6]) + (50).to_bytes(8, "little"))],
        req=[], caps=[(MINT_A, "1000")], progs=(SYS, T22), evidence="requires_rpc")
    unk("U-015", "System account creation funds an undeclared amount",
        "createAccount moves lamports that are not a plain top-level transfer; total spend is unprovable offline.",
        [ct.Instruction(SYS, [(PAYER, True, True), (ct.signer_pubkey("signer:newacct"), True, True)],
                        (0).to_bytes(4, "little") + (2_000_000).to_bytes(8, "little") + (165).to_bytes(8, "little")
                        + ct.b58decode(T))],
        req=[], cap="5000", signers=(), evidence="insufficient")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if committed scenarios differ")
    args = parser.parse_args()
    good(); bad(); unknown()
    assert len(SCENARIOS) == 60 and [s["class"] for s in SCENARIOS].count("GOOD") == 20 \
        and [s["class"] for s in SCENARIOS].count("BAD") == 25 \
        and [s["class"] for s in SCENARIOS].count("UNKNOWN") == 15, "scenario mix must be 20/25/15"
    ids = [s["id"] for s in SCENARIOS]
    assert len(set(ids)) == 60
    OUT.mkdir(exist_ok=True)
    drift = []
    for scenario in SCENARIOS:
        text = json.dumps(scenario, indent=2, sort_keys=True) + "\n"
        path = OUT / (scenario["id"] + ".json")
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                drift.append(scenario["id"])
        else:
            path.write_text(text, encoding="utf-8", newline="\n")
    if args.check:
        extra = sorted(p.stem for p in OUT.glob("*.json") if p.stem not in ids)
        if drift or extra:
            print("FAIL: scenario files differ from the generator: %s %s" % (drift, extra))
            return 1
        print("PASS: 60 committed scenarios match the generator")
    else:
        print("wrote %d scenarios to %s" % (len(SCENARIOS), OUT))
    return 0


if __name__ == "__main__":
    sys.exit(main())
