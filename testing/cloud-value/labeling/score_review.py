#!/usr/bin/env python3
"""Score blind-review responses against the hidden truth (run by the benchmark owner, never by reviewers).

  labeling/responses/<reviewer_id>/CV-###.json   a reviewer's copy of labeling/blind_review/CV-###.json
                                                 with `questions.verdict` (BAD|GOOD|UNKNOWN), confidence,
                                                 decisive_evidence_ids and reasoning filled in

Reports per-reviewer agreement with `truth/`, pairwise Cohen's kappa between reviewers, and every
disagreement. It NEVER edits `truth/`: a disagreement must be resolved in writing by a human, and only
then recorded. The labels count as independently verified only when at least two reviewers answered ALL
critical cases; with none, the status stays PENDING.
"""
import json
import sys
from itertools import combinations
from pathlib import Path

CV = Path(__file__).resolve().parents[1]
LABELS = ("BAD", "GOOD", "UNKNOWN")


def kappa(a, b):
    n = len(a)
    if not n:
        return None
    observed = sum(x == y for x, y in zip(a, b)) / n
    expected = sum((a.count(l) / n) * (b.count(l) / n) for l in LABELS)
    return None if expected == 1 else round((observed - expected) / (1 - expected), 4)


def main():
    truth = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in (CV / "truth").glob("CV-*.json")}
    critical = sorted(t for t, v in truth.items() if v["labeling"]["critical"])
    responses = {}
    root = CV / "labeling" / "responses"
    for reviewer in sorted(p for p in root.glob("*") if p.is_dir()) if root.exists() else []:
        answers = {}
        for path in sorted(reviewer.glob("CV-*.json")):
            verdict = json.loads(path.read_text(encoding="utf-8")).get("questions", {}).get("verdict")
            if verdict in LABELS and path.stem in truth:
                answers[path.stem] = verdict
        responses[reviewer.name] = answers
    report = {"critical_cases": len(critical), "reviewers": {}, "pairwise_kappa": {}, "disagreements": []}
    for name, answers in responses.items():
        agree = sum(answers.get(c) == truth[c]["label"] for c in critical if c in answers)
        report["reviewers"][name] = {"answered": len([c for c in critical if c in answers]), "agree_with_truth": agree}
        for case in critical:
            if case in answers and answers[case] != truth[case]["label"]:
                report["disagreements"].append({"case": case, "reviewer": name, "reviewer_verdict": answers[case],
                                                "truth": truth[case]["label"]})
    for (a, answers_a), (b, answers_b) in combinations(responses.items(), 2):
        shared = [c for c in critical if c in answers_a and c in answers_b]
        report["pairwise_kappa"]["%s~%s" % (a, b)] = {"cases": len(shared),
                                                       "kappa": kappa([answers_a[c] for c in shared], [answers_b[c] for c in shared])}
    complete = [n for n, a in responses.items() if all(c in a for c in critical)]
    report["status"] = ("INDEPENDENTLY_REVIEWED (resolve every listed disagreement in writing before recording)"
                        if len(complete) >= 2 else
                        "PENDING: %d reviewer(s) have answered all %d critical cases; at least 2 are required" % (len(complete), len(critical)))
    out = CV / "labeling" / "review_results.json"
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(report["status"])
    for name, r in report["reviewers"].items():
        print("  %s: %d/%d agree with truth" % (name, r["agree_with_truth"], r["answered"]))
    print("  disagreements:", len(report["disagreements"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
