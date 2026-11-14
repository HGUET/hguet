# Label quality report - Cloud Value Benchmark v1

Snapshot of facts at generation time. `report.json -> labeling_quality` recomputes the numbers on every run.

## What exists

| Item | Count |
|------|-------|
| scenarios (10 categories x 10 kinds) | 100 |
| evidence fixtures | 110 (historical_class 80, lab_simulation 20, hypothetical 10) |
| evidence instances verified on-chain | **0** (`instance_verified=false` everywhere; classes are documented, instances synthetic) |
| ground-truth files | 100, kept apart from `inputs/`; canary + key leak guard in runner and tests |
| critical cases (additional-TP + false-accusation traps) | 30 |
| critical cases reviewed by an independent human | **0** (packet ready: `review_packet.json`) |

## Checks performed

1. **Independent rule-based re-derivation** (`independent_labeler.py`, separate code, reads inputs + evidence only):
   **100/100** labels agree with `truth/`. It also detects disagreement: removing the decisive evidence of a
   BAD scenario flips the derived label to UNKNOWN (unit-tested).
2. **Leak guard**: no truth key, label or canary appears in `inputs/` or `evidence/` (runner aborts; unit test).
3. **Generator drift check**: committed files equal the generator output (`--check`, run in CI).
4. **Verifier gap found by the benchmark, fixed in rules not labels**: the first run showed a naive server's
   accusation on *conflicting* valid evidence reached DENY under the strict verifier (10/60 false accusations,
   all in `conflict`). Rule R11 (cap hard_deny at warn while strong benign evidence stands) was added; labels
   were not touched.

## What this does NOT establish

* **No independent human review has happened.** The 100/100 agreement shares the author's notion of
  "dangerous" and cannot reveal a common misconception.
* Scenario, evidence and truth were authored by one generator. Evidence is written to the labelling rules, so
  the agreement partly measures that the fixtures say what the rules expect.
* The `historical_class` tier is a documented *class*, not a verified incident; nothing here is a claim that an
  event occurred. `lab_simulation` is a benchmark-internal model run, not an external lab.
* Debatable labels, flagged for the reviewer: `fp_wrong_network` is UNKNOWN (no applicable evidence) rather
  than GOOD; C08 accepts WARN or DENY because freeze authority is a risk, not a proven theft; `fp_stale_retracted`
  is GOOD on the strength of a retraction record alone.
* `coverage_gained` has structural ceilings: hypothetical evidence cannot count and the reference server does
  not surface retractions, so 40/60 is not a defect rate.

## Required before the labels are called independently verified

Blind relabel of `review_packet.json` by at least two reviewers who have not seen `truth/`; record verdicts in
`truth/*.json -> labeling.independent_review.reviewers`; resolve disagreements in writing; only then does
`cost_per_independently_reviewed_useful_finding` become non-null.
