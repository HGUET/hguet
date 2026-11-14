# HGUET Security Benchmark (foundation)

Executable framework that measures how well the **real `hguet` binary** detects dangerous
transactions, how often it blocks legitimate ones, how it treats missing evidence, and that
signing stays blocked. BLOCK-only: no keys, no wallet, no broadcast, synthetic data only.

```bash
cargo build -p hguet
python testing/tools/build_scenarios.py --check        # committed scenarios == generator output
python -m unittest discover -s testing/tests            # framework self-tests
python testing/runner/run_benchmark.py --hguet target/debug/hguet                 # all 60
python testing/runner/run_benchmark.py --hguet target/debug/hguet --subset smoke  # 13, used in CI
# open testing/reports/latest/report.html   (report.json has every scenario, finding and command)
```

## Layout

| Path | Purpose |
|------|---------|
| `scenarios/*.json` | 60 versioned scenarios (`hguet-bench-scenario/1`, schema in `schema/`). 20 GOOD, 25 BAD, 15 UNKNOWN |
| `tools/build_scenarios.py` | deterministic generator; **never runs HGUET**; `--check` forbids hand edits |
| `lib/crypto_tx.py` | dependency-free Solana wire builder + RFC 8032 Ed25519 + Base58, written from the public specs |
| `runner/run_benchmark.py` | runs `hguet check` (and `signer-preflight`), scores, writes JSON + HTML |
| `mocks/rpc_mock.py`, `mocks/cloud_mock.py` | deterministic mocks (see limits) |
| `known_defects.json` | documented HGUET defects; matching failures are `XFAIL`, never hidden |
| `tests/` | self-tests of the framework (RFC vectors, metrics, invariants, mocks) |

## Ground truth is independent

Each scenario's label, acceptable decisions, required finding families and rationale are
authored from threat semantics (what the signed intent/policy forbids) **before** any run. The
generator imports no HGUET code. The transaction builder is cross-checked: the runner compares
the tool's parsed `message_sha256` with the builder's own digest and fails the scenario as
`scenario_builder_error` on disagreement. Triage after the first run changed *scenario
construction errors* only (see `TRIAGE.md`), never a label to fit the tool.

## What is scored (kept separate on purpose)

1. **Decision**: confusion matrix truth x {ALLOW, WARN, DENY, UNKNOWN, ERROR}. UNKNOWN and DENY are
   never merged. Per-class precision/recall/F1 treat GOOD<->ALLOW, BAD<->DENY, UNKNOWN<->UNKNOWN.
   Ratios are always printed as numerator/denominator; 0/0 is `n/a`.
2. **Threat detection** (BAD): decision DENY *and* the required finding family present.
   A BAD scenario answered UNKNOWN is a *miss that was blocked anyway*
   (`bad_not_denied_but_blocked_only`) - BLOCK-only is not detection.
3. **Proven-safe properties**: positive proofs HGUET must show (pinned intent signature verified,
   signer roles checked, valid transaction signature, policy coverage) and the global invariant
   that no run claims total spending was proven.
4. **Uncertainty** (UNKNOWN): must stay UNKNOWN with the expected reason; DENY is
   `unknown_overclaimed_as_deny`, ALLOW is unsafe.
5. **Final signing block**: exit code non-zero, `signing_gate=block`, `automated_signing_permitted=false`,
   `signer-preflight` refusal with no signature/broadcast. A violation outranks every other failure.

## Mocks and their limits

* **Mock RPC** is transport-level only. HGUET accepts only HTTPS endpoints validated against public
  roots, so a mock cannot impersonate a provider without weakening TLS - which the benchmark will not do.
  It serves refused/plaintext/hang-up endpoints to prove fail-closed behaviour. Successful-simulation
  enrichment is covered by the Rust unit tests (`JsonRpcTransport` injection), **not** by this benchmark.
* **Mock Cloud** checks the documented composition rules on a mock; the CLI has no Cloud client. Its
  results are labelled "MOCK CLOUD / REFERENCE MODEL" in the report and say nothing about a real server.

## Exit status and CI

Non-zero on any `FAIL`, `XPASS` (stale defect entry), runner error or failed Cloud rule. `XFAIL`
scenarios are counted and printed. CI runs the 13-scenario smoke set on every push
(`rust-ci.yml`); `benchmark-full.yml` runs all 60 weekly, on demand and when `crates/**` or
`testing/**` change, and uploads the HTML/JSON report.

## Known limits

Offline scenarios only; ALLOW is structurally unreachable in the offline prototype (GOOD scores as
UNKNOWN at best and `good_left_unknown` reports it); 60 scenarios give wide error bars; ground truth
is single-author and not independently reviewed.
