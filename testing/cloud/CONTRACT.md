# Cloud Benchmark - contract for the next stage

Status: **interface and rules fixed, no real Cloud measured.** Nothing here sends data anywhere.
The CLI has no Cloud client, so "Local + Cloud" can only be *modelled* today. The contract exists
so the real server, when it appears, is measured by the same machinery and cannot be confused
with the model.

## 1. Three result sources, never merged

| `source_kind` | What it is | Available now | May be used to claim |
|---------------|------------|---------------|----------------------|
| `reference_mock` | deterministic stand-in with named *profiles* | yes | how the documented composition rules behave. **Nothing about a real service** |
| `real_server` | a live HGUET Cloud implementation reached through an explicit opt-in | **no** (no client, no verifier, no network phase) | measured Cloud behaviour, once it exists |
| `independent_proof` | reviewed reference execution / proof, independent of HGUET *and* of the mock | **no** (no proofs authored) | ground truth about what a scenario really does |

Rules:

1. Every `CloudResult` carries `source_kind` (`hguet-cloud-eval-result/1`). A result without it is invalid.
2. Reports contain **one table per source kind**. No combined, averaged or "best of" figure is allowed.
3. A mock profile derived from ground truth (`oracle_upper_bound`) is labelled an **upper bound** and is
   never quoted as an expected or achieved improvement.
4. A mock result can never be used to satisfy a `real_server` or `independent_proof` acceptance criterion.
5. Cloud data can only **raise severity** or be discarded. It must never create `ALLOW`, never override a
   local hard `DENY`, and an assessment that is unsigned, expired, or bound to another message hash is
   discarded (see `mocks/cloud_mock.py::combine`, derived from `interoperability.md`).

## 2. Evaluator interface (`testing/cloud/evaluator.py`)

```python
class CloudSource:
    kind: "reference_mock" | "real_server" | "independent_proof"
    def profiles(self) -> list[str]
    def assess(self, scenario: dict, local_row: dict, profile: str) -> CloudResult

CloudResult = {format, source_kind, source_id, profile, available, reason, assessment|null, notes[]}
```

* `ReferenceMock` profiles: `silent`, `oracle_upper_bound`, `always_benign`, `always_adverse`, `stale`,
  `mismatched_binding` - chosen to probe the *rules* (does benign Cloud ever produce ALLOW? does an
  always-adverse Cloud amplify false blocks? are stale/mismatched assessments discarded?).
* `RealServer`: performs **no network I/O** in this phase and returns `available=false` with a reason.
  Activating it needs (a) a signed `CloudAssessment` verifier in the CLI, (b) an explicit opt-in flag and
  endpoint, (c) a data-handling review, because a transaction would leave the machine.
* `IndependentProof`: reads `testing/cloud/proofs/<scenario>.json` with `established_by`, a
  `message_sha256` binding and an `adverse` flag; a proof without provenance or with the wrong hash is rejected.

## 3. Comparison on identical scenarios (`testing/cloud/compare.py`)

For the same scenario set the report gives, side by side but **separately labelled**:

| Column | Source | Status today |
|--------|--------|--------------|
| `local_offline` | real `hguet --offline` | measured |
| `local_rpc` | real `hguet --rpc-url` | measured only for transport failure (UNKNOWN); successful simulation cannot be driven through the CLI without weakening TLS, so it is `not_measurable_through_cli` and covered by Rust unit tests |
| `local_cloud.reference_mock.<profile>` | local result + mock Cloud + composition rules | **model** |
| `local_cloud.real_server` | - | unavailable |
| `local_cloud.independent_proof` | - | unavailable |

Per column: confusion matrix and the same headline ratios as the main benchmark, plus three
Cloud-attribution counters that make harm visible: `ALLOW_created_by_cloud` (must be 0, exit status 1
otherwise), `good_scenarios_blocked_only_because_of_cloud`, `bad_scenarios_denied_only_because_of_cloud`.

## 4. What the first comparison shows (83 scenarios, model only)

Local offline already denies 36/36 BAD scenarios, so a Cloud has **no headroom to show benefit** on the
current set: even the `oracle_upper_bound` profile adds +0. The `always_adverse` profile shows the risk
side: +23 GOOD scenarios blocked purely because a (hostile or wrong) Cloud said so; `always_benign`,
`stale` and `mismatched_binding` change nothing, as the rules require; ALLOW is never created.

## 5. Acceptance criteria for the real-server stage

1. `RealServer` returns verified, signed, hash-bound `CloudAssessment`s; unsigned/expired/mismatched ones
   are discarded and counted.
2. A **Cloud-requiring scenario set** exists (`evidence_level: requires_cloud`): cases whose ground truth
   cannot be derived from the transaction bytes (known-malicious program or recipient, token reputation,
   freshly drained destination). Without it Cloud value cannot be measured. Each needs an
   `independent_proof` file.
3. Results from `real_server` and `independent_proof` are reported in their own tables, with the
   scenarios that lack a proof listed explicitly rather than counted as passes.
4. A hostile-Cloud test (`always_adverse`, `always_benign`, truncated and replayed assessments) passes with
   `ALLOW_created_by_cloud == 0` and no local hard DENY overridden.
5. Latency, availability and failure behaviour of the real server are reported separately from decision
   quality; an unreachable Cloud must degrade to the local decision, never to ALLOW.
6. Privacy: the benchmark states which transaction fields were sent; default is nothing.

## 6. Not decided

Cloud-required profile semantics for ALLOW, the signed-assessment key distribution, who authors and
reviews independent proofs, and how Cloud findings map onto severity thresholds. These need owners before
`real_server` is implemented.
