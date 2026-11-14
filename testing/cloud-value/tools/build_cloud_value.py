#!/usr/bin/env python3
"""Generate Cloud Value Benchmark v1: 100 scenarios whose decisive facts are NOT in the transaction.

Layout written (all committed, `--check` forbids drift):
  inputs/CV-###.json    what the analysed component may see (tx, intent, policy, cloud request)
  truth/CV-###.json     HIDDEN ground truth + labelling provenance (never passed to any component)
  evidence/EV-####.json independent evidence fixtures: provenance, time, network, confidence, tier
  labeling/review_packet.json  blind-review packet for the most critical cases

10 threat categories x 10 scenario kinds. Evidence tiers are kept apart:
  historical_class  a documented, publicly known attack CLASS; the instance here is synthetic
                    (instance_verified=false: no on-chain history can be fetched offline)
  lab_simulation    a deterministic model run whose inputs and method are recorded
  hypothetical      a plausible risk with no observed occurrence (never a basis for accusation)
No network, no keys with value, no real payments.
"""
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT.parent / "lib"))
import crypto_tx as ct  # noqa: E402

NOW = "2026-11-01T00:00:00Z"
FORMAT_IN, FORMAT_TRUTH, FORMAT_EV = "hguet-cv-input/1", "hguet-cv-truth/1", "hguet-cv-evidence/1"
ISSUER = "issuer:trusted"
TRUSTED = ct.signer_pubkey(ISSUER)
PAYER_LABEL = "signer:payer"
PAYER = ct.signer_pubkey(PAYER_LABEL)
SYS, T, T22 = ct.SYSTEM, ct.TOKEN, ct.TOKEN_2022
ALICE = ct.plain_pubkey("dest:alice")
GENESIS = {"devnet": "bench-genesis-devnet", "testnet": "bench-genesis-testnet", "mainnet": "bench-genesis-mainnet"}

KINDS = ["tp_historical", "tp_lab", "local_covers", "fp_stale_retracted", "fp_wrong_network", "fp_hypothetical",
         "benign_corroboration", "no_evidence", "conflict", "tamper"]
TAMPERS = ["bad_signature", "wrong_binding", "unsupported_safe_claim", "expired_assessment", "wrong_network_assessment"]
CATEGORIES = [
    # id, name, subject type, claim code, adverse enforcement
    ("C01", "malicious_program", "program", "PROGRAM_KNOWN_DRAINER", "hard_deny"),
    ("C02", "drainer_recipient", "account", "RECIPIENT_KNOWN_DRAINER", "hard_deny"),
    ("C03", "address_poisoning", "account", "RECIPIENT_ADDRESS_POISONING", "hard_deny"),
    ("C04", "fake_mint", "mint", "MINT_IMPERSONATION", "hard_deny"),
    ("C05", "transfer_hook_honeypot", "mint", "MINT_TRANSFER_HOOK_MALICIOUS", "hard_deny"),
    ("C06", "confiscatory_transfer_fee", "mint", "MINT_CONFISCATORY_TRANSFER_FEE", "hard_deny"),
    ("C07", "permanent_delegate_mint", "mint", "MINT_PERMANENT_DELEGATE_ABUSE", "hard_deny"),
    ("C08", "freeze_authority_risk", "mint", "MINT_FREEZE_AUTHORITY_RISK", "warn"),
    ("C09", "alt_resolves_to_drainer", "alt_table", "ALT_ENTRY_RESOLVES_TO_DRAINER", "hard_deny"),
    ("C10", "cpi_hidden_drain", "program", "PROGRAM_CPI_DRAINS_FUNDS", "hard_deny"),
]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def acct(label):
    return ct.plain_pubkey("cv:" + label)


# ------------------------------------------------------------------ evidence
class Evidence:
    def __init__(self):
        self.records = []

    def add(self, subject, network, code, polarity, tier, *, confidence, observed, valid_until, source,
            method, reference, reproducible=False, retracts=None, extra=None):
        record = {
            "format": FORMAT_EV, "evidence_id": "EV-%04d" % (len(self.records) + 1),
            "subject": {"type": subject[0], "id": subject[1]}, "network": network,
            "claim": {"code": code, "polarity": polarity},
            "observed_at": observed, "valid_until": valid_until, "confidence": confidence,
            "provenance": {"tier": tier, "source": source, "method": method, "reference": reference,
                           "instance_verified": False, "reproducible": reproducible,
                           "note": "synthetic instance; the class/method is the documented part"},
        }
        if retracts:
            record["retracts"] = retracts
        if extra:
            record["extra"] = extra
        self.records.append(record)
        return record["evidence_id"]


# ------------------------------------------------------------ transaction forms
def category_tx(cat, tag):
    """Return (instructions, allowed_programs, caps, v0, subjects, primary_subject)."""
    cid = cat[0]
    pay = ct.ix_system_transfer
    if cid == "C01":
        prog = acct("program:" + tag)
        return ([pay(PAYER, ALICE, 1000), ct.ix_custom(prog, [(PAYER, True, True)])], [SYS, prog], None, None,
                [("program", prog)], ("program", prog))
    if cid == "C10":
        prog = acct("cpi-program:" + tag)
        return ([ct.ix_custom(prog, [(PAYER, True, True), (acct("vault:" + tag), False, True)])], [prog], None, None,
                [("program", prog)], ("program", prog))
    if cid in ("C02", "C03"):
        recipient = acct("recipient:" + tag)
        return [pay(PAYER, recipient, 1000)], [SYS], None, None, [("account", recipient)], ("account", recipient)
    if cid == "C09":
        table = ct.plain_pubkey("alt-table:" + tag)
        instr = ct.Instruction(SYS, [(PAYER, True, True), ("alt:0", False, True)],
                               (2).to_bytes(4, "little") + (1000).to_bytes(8, "little"))
        return [instr], [SYS], None, [(tag, [0], [])], [("alt_table", table)], ("alt_table", table)
    # mint categories
    program = T22 if cid in ("C05", "C06", "C07") else T
    mint = acct("mint:" + tag)
    src, dst = acct("src:" + tag), acct("dst:" + tag)
    return ([ct.ix_token_transfer_checked(program, src, mint, dst, PAYER, 500)], [SYS, program], [(mint, "1000")],
            None, [("mint", mint)], ("mint", mint))


def describe(instrs):
    """Human-readable, label-free description of the instructions (for blind reviewers)."""
    out = []
    for ins in instrs:
        data = ins.data
        accounts = [a[0] for a in ins.accounts]
        if ins.program == SYS and len(data) == 12 and data[:4] == (2).to_bytes(4, "little"):
            out.append("System transfer of %d lamports from the fee payer to %s" % (
                int.from_bytes(data[4:], "little"), accounts[1] if accounts[1] != "alt:0" else "an address in lookup table alt:0"))
        elif ins.program in (T, T22) and data[:1] == bytes([12]):
            out.append("%s TransferChecked of %d raw units of mint %s (destination token account %s)" % (
                "Token-2022" if ins.program == T22 else "SPL Token", int.from_bytes(data[1:9], "little"), accounts[1], accounts[2]))
        else:
            out.append("Call to program %s with %d accounts, %d data bytes" % (ins.program, len(accounts), len(data)))
    return out


def review_case(sid, inputs, instrs, evidence_records):
    subjects = {(x["type"], x["id"]) for x in inputs["cloud_request"]["subjects"]}
    related = [dict(r) for r in evidence_records if (r["subject"]["type"], r["subject"]["id"]) in subjects]
    return {
        "format": "hguet-cv-blind-review-case/1", "id": sid,
        "what_you_may_use": "only this file; do NOT open truth/, scenario titles, generator code or reports",
        "network": inputs["network"], "reference_time": inputs["clock"],
        "transaction": {"instructions": describe(instrs), "signed_intent_present": True,
                        "intent_covers": "the instructions above are within the signed spend/program limits"},
        "subjects_to_assess": inputs["cloud_request"]["subjects"],
        "available_independent_evidence": related,
        "note_on_evidence": ("Evidence instances are synthetic fixtures of documented attack classes; judge whether, "
                             "given ONLY the evidence fields (network, validity window, retraction, tier, confidence), "
                             "the transaction should be treated as BAD, GOOD or UNKNOWN."),
        "questions": {"verdict": "BAD | GOOD | UNKNOWN", "confidence_0_to_1": None,
                      "decisive_evidence_ids": [], "reasoning": ""},
    }


def build_scenario(cat_index, kind_index, evidence):
    cat = CATEGORIES[cat_index]
    cid, cname, stype, code, enforcement = cat
    kind = KINDS[kind_index]
    sid = "CV-%03d" % (cat_index * 10 + kind_index + 1)
    tag = "%s-%s" % (cid, kind)
    network = ["devnet", "devnet", "testnet", "devnet", "devnet"][kind_index % 5] if kind != "fp_wrong_network" else "devnet"
    other = "mainnet"
    instrs, allowed, caps, v0, subjects, primary = category_tx(cat, tag)
    if kind == "local_covers":
        instrs = instrs + [ct.ix_system_transfer(PAYER, ALICE, 9000)]  # exceeds the 5000 cap -> local DENY
    raw, message = ct.build_transaction(instrs, PAYER, (), v0, "bh-" + tag, "unsigned")
    payload = ct.intent_payload(message, network=network, intent_id="cv-" + sid, allowed_programs=allowed,
                                max_spend="5000", token_caps=caps)
    intent = ct.sign_intent(payload, ISSUER)
    subject_ids = [{"type": t, "id": i} for t, i in subjects]
    request = {
        "format": "cv-request-view/1", "network": network, "data_scope": "metadata_only", "profile": "strict",
        "message_sha256": sha(message), "transaction_sha256": sha(raw),
        "intent_sha256": sha(json.dumps(intent, sort_keys=True).encode()), "subjects": subject_ids,
    }
    adverse_sev = "critical" if enforcement == "hard_deny" else "high"
    ev = {"observed": "2026-10-10T00:00:00Z", "until": "2027-04-01T00:00:00Z"}
    decisive, tier, discards, tamper = [], None, [], None
    acceptable_final = ["DENY"] if enforcement == "hard_deny" else ["WARN", "DENY"]
    label, local_expected, requires_cloud, threat = "UNKNOWN", "UNKNOWN", True, False
    rationale = ""
    historical = ("historical_class", "documented public attack class: " + cname.replace("_", " "),
                  "synthetic instance of a publicly documented class; no on-chain instance verified")
    lab = ("lab_simulation", "deterministic benchmark model run (%s)" % cname, "model inputs recorded in the fixture")

    def adverse(tier_info, conf, *, net=None, observed=None, until=None, repro=False, extra=None):
        return evidence.add(primary, net or network, code, "adverse", tier_info[0], confidence=conf,
                            observed=observed or ev["observed"], valid_until=until or ev["until"], source=tier_info[1],
                            method=tier_info[2], reference="class:" + cname, reproducible=repro, extra=extra)

    if kind == "tp_historical":
        decisive.append(adverse(historical, 0.95))
        label, threat, tier = "BAD", True, "historical_class"
        rationale = "The subject is a member of a documented %s pattern; only external knowledge shows it." % cname
    elif kind == "tp_lab":
        decisive.append(adverse(lab, 0.9, repro=True, extra={"lab_input_sha256": sha(tag.encode())}))
        label, threat, tier = "BAD", True, "lab_simulation"
        rationale = "A recorded deterministic simulation shows the harmful behaviour (%s)." % cname
    elif kind == "local_covers":
        decisive.append(adverse(historical, 0.9))
        label, threat, tier, local_expected, requires_cloud = "BAD", True, "historical_class", "DENY", False
        rationale = ("Already visibly over the signed spend cap, so local analysis denies on its own; the external "
                     "evidence is corroborating and must not be counted as an additional detection.")
    elif kind == "fp_stale_retracted":
        old = adverse(historical, 0.95, observed="2026-07-01T00:00:00Z", until="2026-09-01T00:00:00Z")
        decisive.append(evidence.add(primary, network, code, "retraction", "historical_class", confidence=0.9,
                                     observed="2026-08-15T00:00:00Z", valid_until="2027-08-15T00:00:00Z",
                                     source=historical[1], method="review concluded the earlier flag was wrong",
                                     reference="retraction-of:" + old, retracts=old))
        label, tier = "GOOD", "historical_class"
        discards = ["superseded", "expired"]
        rationale = "The only adverse record expired and was retracted as erroneous; accusing the subject is a false accusation."
    elif kind == "fp_wrong_network":
        adverse(historical, 0.95, net=other)
        label, tier = "UNKNOWN", None
        discards = ["wrong_network"]
        rationale = "Adverse evidence concerns the same-looking subject on %s; nothing applies to %s: UNKNOWN, not DENY." % (other, network)
    elif kind == "fp_hypothetical":
        decisive.append(evidence.add(primary, network, code, "adverse", "hypothetical", confidence=0.4,
                                    observed=ev["observed"], valid_until=ev["until"], source="threat-model note",
                                    method="no observed occurrence", reference="hypothesis:" + cname))
        label, tier = "UNKNOWN", "hypothetical"
        discards = ["hypothetical_tier_cannot_accuse"]
        rationale = "Only a hypothetical risk exists; no occurrence was observed, so neither accusation nor clearance is supported."
    elif kind == "benign_corroboration":
        decisive.append(evidence.add(primary, network, cname.upper() + "_REPUTABLE", "benign", "historical_class",
                                     confidence=0.9, observed=ev["observed"], valid_until=ev["until"],
                                     source=historical[1], method="long-standing public record without incident",
                                     reference="class:" + cname))
        label, tier, threat = "GOOD", "historical_class", False
        rationale = "Independent benign record; Cloud may add coverage but can never create ALLOW or prove safety."
    elif kind == "no_evidence":
        label = "UNKNOWN"
        rationale = "Neither the transaction nor any independent source says anything about the subject."
    elif kind == "conflict":
        decisive.append(adverse(historical, 0.9, observed="2026-10-01T00:00:00Z"))
        decisive.append(evidence.add(primary, network, cname.upper() + "_REPUTABLE", "benign", "lab_simulation",
                                     confidence=0.85, observed="2026-10-15T00:00:00Z", valid_until=ev["until"],
                                     source=lab[1], method=lab[2], reference="class:" + cname, reproducible=True))
        label, tier = "UNKNOWN", "historical_class"
        acceptable_final = ["UNKNOWN", "WARN"]
        rationale = "Two valid, independent records disagree and neither supersedes the other: unresolved."
    else:  # tamper
        decisive.append(adverse(historical, 0.95))
        tamper = TAMPERS[cat_index % len(TAMPERS)]
        label, threat, tier = "BAD", True, "historical_class"
        acceptable_final = ["UNKNOWN", "DENY", "WARN"] if tamper == "unsupported_safe_claim" else ["UNKNOWN"]
        discards = [tamper]
        rationale = ("The subject really is bad, but the Cloud answer is %s; a verifier must discard it and the final "
                     "answer stays at the local UNKNOWN (no credit for a tampered finding)." % tamper)
    if kind in ("fp_stale_retracted", "benign_corroboration", "fp_wrong_network", "no_evidence", "fp_hypothetical",
                "conflict"):
        acceptable_final = {"fp_stale_retracted": ["UNKNOWN"], "benign_corroboration": ["UNKNOWN"],
                            "fp_wrong_network": ["UNKNOWN"], "no_evidence": ["UNKNOWN"],
                            "fp_hypothetical": ["UNKNOWN"], "conflict": ["UNKNOWN", "WARN"]}[kind]
    critical = kind in ("tp_historical", "tp_lab", "fp_stale_retracted")
    canary = "CVCANARY-" + sha(("canary:" + sid).encode())[:16]
    inputs = {
        "format": FORMAT_IN, "id": sid, "network": network, "clock": NOW,
        "transaction": {"encoding": "base64", "data": base64.b64encode(raw).decode()},
        "intent": intent, "trusted_key": TRUSTED, "policy_toml": None, "rpc": {"mode": "none"},
        "cloud_request": request,
        "cloud_harness": {"tamper": tamper},
    }
    truth = {
        "format": FORMAT_TRUTH, "id": sid, "canary": canary, "category": cname, "category_id": cid, "kind": kind,
        "label": label, "threat_present": threat, "local_expected": local_expected,
        "acceptable_final": acceptable_final, "decisive_evidence": decisive, "decisive_tier": tier,
        "requires_cloud_evidence": requires_cloud, "expected_verifier_discards": discards, "tamper": tamper,
        "adverse_enforcement": enforcement if threat else None, "rationale": rationale,
        "labeling": {"authored_by": "generator:build_cloud_value.py v1 (single author)",
                     "critical": critical,
                     "independent_review": {"status": "pending_human_review" if critical else "rule_cross_check_only",
                                            "reviewers": []}},
    }
    truth["_review_case"] = review_case(sid, inputs, instrs, evidence.records) if critical else None
    return inputs, truth


def build_all():
    evidence = Evidence()
    scenarios = []
    for c in range(10):
        for k in range(10):
            scenarios.append(build_scenario(c, k, evidence))
    return scenarios, evidence.records


def write_json(path, value, check, drift):
    text = json.dumps(value, indent=2, sort_keys=True) + "\n"
    if check:
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            drift.append(str(path.relative_to(ROOT)))
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    scenarios, records = build_all()
    assert len(scenarios) == 100 and len({i["id"] for i, _ in scenarios}) == 100
    drift = []
    expected = set()
    cases = []
    for inputs, truth in scenarios:
        case = truth.pop("_review_case")
        if case:
            cases.append(case)
        for folder, value in (("inputs", inputs), ("truth", truth)):
            path = ROOT / folder / (inputs["id"] + ".json")
            expected.add(path)
            write_json(path, value, args.check, drift)
    for record in records:
        path = ROOT / "evidence" / (record["evidence_id"] + ".json")
        expected.add(path)
        write_json(path, record, args.check, drift)
    # blind-review packet: one self-contained, label-free file per critical case
    for case in cases:
        path = ROOT / "labeling" / "blind_review" / (case["id"] + ".json")
        expected.add(path)
        write_json(path, case, args.check, drift)
    index = ROOT / "labeling" / "review_packet.json"
    expected.add(index)
    write_json(index, {"format": "hguet-cv-review-packet/1", "cases": sorted(c["id"] for c in cases),
                       "instructions": "labeling/blind_review/README.md",
                       "status": "PENDING: no reviewer has responded yet"}, args.check, drift)
    if args.check:
        for folder in ("inputs", "truth", "evidence", "labeling/blind_review"):
            for path in (ROOT / folder).glob("*.json"):
                if path not in expected:
                    drift.append("extra:" + str(path.relative_to(ROOT)))
        if drift:
            print("FAIL: committed Cloud Value files differ from the generator: %s" % drift[:10])
            return 1
        print("PASS: 100 scenarios, %d evidence records, review packet match the generator" % len(records))
    else:
        print("wrote 100 scenarios, %d evidence records, %d blind-review cases" % (len(records), len(cases)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
