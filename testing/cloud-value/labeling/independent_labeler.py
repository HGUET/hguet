"""Independent re-labelling of the Cloud Value scenarios from INPUTS + EVIDENCE only.

This is a second, separately written derivation of the labels. It does not import the
generator and never opens `truth/` until the final comparison. Agreement shows the truth files
are consistent with the evidence under the written labelling rules (RULES.md); it does NOT replace
a human blind review, and it cannot catch a shared misconception about what is dangerous.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

CV = Path(__file__).resolve().parents[1]


def _t(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def load(directory, pattern):
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted((CV / directory).glob(pattern))]


def derive_label(inputs, evidence):
    request = inputs["cloud_request"]
    now = _t(inputs["clock"])
    subjects = {(s["type"], s["id"]) for s in request["subjects"]}
    about = [e for e in evidence if (e["subject"]["type"], e["subject"]["id"]) in subjects]
    retracted = {e["retracts"] for e in about if e.get("retracts")}
    live = [e for e in about
            if e["network"] == request["network"] and _t(e["observed_at"]) <= now <= _t(e["valid_until"])
            and e["evidence_id"] not in retracted and e["claim"]["polarity"] in ("adverse", "benign")]

    def strong(e):
        p = e["provenance"]
        return (p["tier"] == "historical_class" and e["confidence"] >= 0.8) or \
               (p["tier"] == "lab_simulation" and p.get("reproducible") and e["confidence"] >= 0.8)

    adverse = [e for e in live if e["claim"]["polarity"] == "adverse" and strong(e)]
    benign = [e for e in live if e["claim"]["polarity"] == "benign" and strong(e)]
    if adverse and benign:
        return "UNKNOWN", "conflicting valid evidence"
    if adverse:
        return "BAD", "valid strong adverse evidence"
    if benign:
        return "GOOD", "valid strong benign evidence"
    if retracted and any(e["network"] == request["network"] and e["claim"]["polarity"] == "retraction" for e in about):
        return "GOOD", "only adverse record was retracted"
    return "UNKNOWN", "no valid strong evidence"


def run():
    inputs = {i["id"]: i for i in load("inputs", "CV-*.json")}
    evidence = load("evidence", "EV-*.json")
    derived = {sid: derive_label(i, evidence) for sid, i in inputs.items()}
    truth = {t["id"]: t for t in load("truth", "CV-*.json")}
    rows, mismatches = [], []
    for sid in sorted(truth):
        label, why = derived[sid]
        agree = label == truth[sid]["label"]
        rows.append({"id": sid, "kind": truth[sid]["kind"], "truth": truth[sid]["label"], "derived": label,
                     "agree": agree, "reason": why})
        if not agree:
            mismatches.append(rows[-1])
    by_kind = {}
    for row in rows:
        k = by_kind.setdefault(row["kind"], {"agree": 0, "total": 0})
        k["total"] += 1
        k["agree"] += row["agree"]
    tiers = {}
    for e in evidence:
        tiers[e["provenance"]["tier"]] = tiers.get(e["provenance"]["tier"], 0) + 1
    critical = [t for t in truth.values() if t["labeling"]["critical"]]
    return {
        "method": "independent rule-based derivation from inputs+evidence (labeling/independent_labeler.py)",
        "agreement": {"agree": sum(r["agree"] for r in rows), "total": len(rows)},
        "by_kind": by_kind, "mismatches": mismatches,
        "evidence_tiers": tiers,
        "all_evidence_instances_unverified_on_chain": all(not e["provenance"]["instance_verified"] for e in evidence),
        "critical_cases": len(critical),
        "critical_with_human_review": sum(bool(t["labeling"]["independent_review"]["reviewers"]) for t in critical),
        "human_review_status": "PENDING: no independent human reviewer has labelled the critical cases yet "
                               "(labeling/review_packet.json is ready for a blind review)",
        "limits": ["rule-based agreement shares the authors' notion of 'dangerous'",
                   "single author for scenarios, evidence and truth",
                   "no historical on-chain instance is verified: tiers describe documented classes, not incidents"],
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2))
