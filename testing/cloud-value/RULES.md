# Cloud Value Benchmark v1 - rules

BLOCK-only. No real payments, no secrets, metadata-only requests, synthetic data. Real server:
**unavailable unless explicitly enabled**; reference-mock numbers are a **model**.

## 1. What is measured

100 scenarios = 10 threat categories x 10 kinds. In every scenario the decisive fact is **not in the
transaction bytes** (program/recipient/mint reputation, token-mint state, ALT resolution, CPI behaviour),
so local analysis can at best answer UNKNOWN. A Cloud adds value only by supplying *independently
confirmed* evidence; it can also do harm by false accusation, over-claiming, or being believed when it
should not be.

| Category | Subject | Local sees |
|----------|---------|-----------|
| C01 malicious program | program id | an unreviewed custom program |
| C02 drainer recipient | account | an ordinary transfer |
| C03 address poisoning | account | an ordinary transfer |
| C04 fake mint | mint | a capped checked transfer |
| C05 transfer-hook honeypot | Token-2022 mint | a capped checked transfer |
| C06 confiscatory fee | Token-2022 mint | a capped checked transfer |
| C07 permanent delegate | Token-2022 mint | a capped checked transfer |
| C08 freeze-authority risk | mint | a capped checked transfer (adverse = WARN, not DENY) |
| C09 ALT resolves to drainer | lookup table | an unresolved lookup |
| C10 CPI hidden drain | program id | a call to a custom program |

| Kind | Truth | Correct final answer |
|------|-------|----------------------|
| `tp_historical` / `tp_lab` | BAD | DENY (WARN or DENY for C08) - an *additional* true positive |
| `local_covers` | BAD | DENY already from local analysis (over-cap): Cloud must add nothing |
| `fp_stale_retracted` | GOOD | UNKNOWN - the only adverse record expired and was retracted |
| `fp_wrong_network` | UNKNOWN | UNKNOWN - evidence is about another network |
| `fp_hypothetical` | UNKNOWN | UNKNOWN - a hypothetical risk is never grounds for accusation |
| `benign_corroboration` | GOOD | UNKNOWN - Cloud may add coverage, never ALLOW |
| `no_evidence` | UNKNOWN | UNKNOWN |
| `conflict` | UNKNOWN | UNKNOWN or WARN - valid evidence disagrees |
| `tamper` | BAD | UNKNOWN - the answer is forged/misbound/expired/dishonest and must be discarded |

## 2. Separation of ground truth from inputs

* `inputs/` is the only thing a component receives (transaction, intent, policy, metadata-only Cloud request,
  and a harness switch that tampers with the *answer*). `truth/` is opened only by the scorer.
* Each truth file has a unique canary string. The runner aborts if a canary or a ground-truth key appears in
  anything component-visible; a unit test asserts the same.
* The reference server takes `(request, evidence directory)` only. The **evidence** directory is the Cloud's
  knowledge base and carries no labels.

## 3. Evidence fixtures (`evidence/`)

Fields: `subject`, `network`, `claim{code,polarity}`, `observed_at`, `valid_until`, `confidence`,
`provenance{tier, source, method, reference, instance_verified, reproducible}`, optional `retracts`.
Tiers are never mixed in reporting or in the acceptance rules:

* `historical_class` - a *documented* public attack class. **The instance is synthetic**
  (`instance_verified=false`); no on-chain history can be fetched offline and none is claimed.
* `lab_simulation` - a recorded deterministic model run (`reproducible=true`).
* `hypothetical` - a plausible risk with no observed occurrence; capped at *inform*, never accuses.

## 4. Acceptance rules for a signed CloudAssessment (`verify/assessment_rules.py`)

Whole-assessment discards: envelope shape, signature algorithm known, algorithm verifiable
(`ml-dsa-87` is recognised but unsupported here), key pinned, signature valid, schema conformant
(`protocol/v1/cloud-assessment.schema.json`), binding (message, transaction, subjects), network + genesis,
validity window. Per finding (strict mode): cited evidence listed in `sources` with a matching digest;
eligible record (subject in request, same network, inside window, not retracted/superseded, polarity and
code agree); enforcement capped by provenance (hard_deny needs historical or reproducible lab evidence with
confidence >= 0.8; hypothetical = inform); hard_deny capped at warn while strong benign evidence for the
same subject stands (R11). `safety:*` claims are information only, counted as unsupported without eligible
benign evidence, and **never** produce ALLOW. A local DENY is never lowered.

`trusting` mode skips the per-finding checks (signature/binding/time still apply). It exists to expose the harm
of believing a server blindly, and is reported next to `strict`.

## 5. Metrics (every ratio printed as numerator/denominator)

| Metric | Definition |
|--------|-----------|
| additional true positive | BAD (non-tamper) where local is not acceptable and the verified final answer is, over BAD scenarios with room |
| additional false positive / false accusation rate | non-BAD where the final answer is more severe than local and not acceptable per truth, over non-BAD |
| accusation attempts blocked by verifier | non-BAD where the server claimed deny/warn and the verifier prevented any escalation |
| correct evidence attribution | accepted accusations whose cited evidence includes all decisive evidence, over accepted accusations |
| unsupported safety claims emitted / believed | claims without eligible benign evidence; believed = acted on by the verifier mode |
| unknown handling correct | UNKNOWN-truth scenarios whose final answer is acceptable |
| coverage gained from verified evidence | scenarios needing Cloud evidence where verified decisive evidence was accepted |
| tampered assessments wrongly trusted | tamper scenarios whose outcome changed (or became ALLOW) |
| availability / latency | answered/applicable; mean and p95 server+verify time (model values for the mock) |
| cost per useful finding | nominal units / additional TP with correct attribution. `..._truth_confirmed`: confirmed by the independent truth files; `..._independently_reviewed`: confirmed by a human reviewer - **n/a, no reviews exist** |

## 6. Label quality (`labeling/`)

* Authoring is single-source (generator).
* `independent_labeler.py` re-derives every label from inputs + evidence only. Agreement is reported.
  It checks consistency with the written rules; it does **not** replace a human review.
* 30 critical cases (additional-TP scenarios and false-accusation traps) are packaged in
  `labeling/review_packet.json` for a **blind** human relabel. Status: **pending**, 0 reviewers.
