# HGUET Security Benchmark (foundation)

Executable framework that measures how well the **real `hguet` binary** detects dangerous
transactions, how often it blocks legitimate ones, how it treats missing evidence, and that
signing stays blocked. BLOCK-only: no keys, no wallet, no broadcast, synthetic data only.

```bash
cargo build -p hguet
python -m pip install -r testing/requirements.txt
python testing/tools/build_scenarios.py --check        # committed scenarios == generator output
python -m unittest discover -s testing/tests            # framework self-tests
python testing/runner/run_benchmark.py --hguet target/debug/hguet                 # the 60 main scenarios
python testing/runner/run_benchmark.py --hguet target/debug/hguet --suite all     # 60 main + 64 regression/coverage
python testing/runner/run_benchmark.py --hguet target/debug/hguet --subset smoke  # 13, used in CI
# open testing/reports/latest/report.html   (report.json has every scenario, finding and command)
```

## Layout

| Path | Purpose |
|------|---------|
| `scenarios/*.json` | 60 versioned scenarios (`hguet-bench-scenario/1`, schema in `schema/`). 20 GOOD, 25 BAD, 15 UNKNOWN |
| `scenarios-regression/*.json` | 64 further scenarios: paired regression cases for fixed defects and the coverage extension (v1 wire format, binary/Base58 input, mainnet/testnet, malformed wire structure, partial signatures) |
| `tools/build_scenarios.py` | deterministic generator; **never runs HGUET**; `--check` forbids hand edits |
| `lib/crypto_tx.py` | dependency-free Solana wire builder (legacy, v0, v1) + RFC 8032 Ed25519 + Base58, written from the public specs |
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

6. **Public contract**: every verdict the tool prints is validated against the published
   `protocol/v1/security-verdict.schema.json` (`public_schema_violation`), and the process exit code must match
   the decision (`exit_code_contract_violation`). The validator uses `jsonschema` Draft 2020-12, including `oneOf` hash constraints
   and JSON boolean/number distinctions. Install `testing/requirements.txt` before running.

## Tests beside the scenario benchmark

Scenarios are hand-picked inputs. Three Rust test groups state properties for *any* input and run in
`cargo test --workspace`:

| Where | What it asserts |
|-------|-----------------|
| `crates/hguet-core/src/property_tests.rs` | 70,000 random and mutated byte strings never panic and every accepted transaction is self-consistent; a declared amount never shrinks when an instruction is padded; the SOL total equals the sum of the movements built; a signed mint or source cap is accepted exactly when the debits fit; no single-bit change to an intent, its signature or the bound message verifies; cap and validity-window boundaries are exact |
| `crates/hguet-cli/src/pipeline_tests.rs` | the real `check` pipeline with an injected RPC transport: successful and failed simulation, wrong cluster, lookup-table resolution with a signed intent, hard DENY decided before the provider is contacted, a provider that claims approval, all three input encodings |
| `crates/hguet-rpc/tests/hostile_provider.rs` | 6,000 mutated provider answers cannot crash the client or produce a permission field; 20,000 arbitrary token instructions are each either recognized or opaque and the signing boundary always blocks |

All generators are fixed-seed, so a failure is reproducible from its case number. They are not
coverage-guided fuzzers: they find shallow structural faults, not deep ones.

`.github/workflows/mutation-testing.yml` (manual) runs `cargo-mutants` on `hguet-core` and `hguet-policy`
to list code changes the tests do not notice. Failures propagate to the job status and reports
are uploaded even on failure; missing reports fail the upload. It has not completed a run yet.

## Mocks and their limits

* **Mock RPC** is transport-level only. HGUET accepts only HTTPS endpoints validated against public
  roots, so a mock cannot impersonate a provider without weakening TLS - which the benchmark will not do.
  It serves refused/plaintext/hang-up endpoints to prove fail-closed behaviour. Successful simulation is
  covered in Rust instead: `pipeline_tests.rs` runs the whole `check` command against an injected transport,
  and `hostile_provider.rs` mutates the provider's answers. No test contacts a real Solana RPC node.
* **Mock Cloud** checks the documented composition rules on a mock; the CLI has no Cloud client. Its
  results are labelled "MOCK CLOUD / REFERENCE MODEL" in the report and say nothing about a real server.

## Exit status and CI

Non-zero on any `FAIL`, `XPASS` (stale defect entry), runner error or failed Cloud rule. `XFAIL`
scenarios are counted and printed. CI runs the 13-scenario smoke set on every push
(`rust-ci.yml`); `benchmark-full.yml` runs all 60 weekly, on demand and when `crates/**` or
`testing/**` change, and uploads the HTML/JSON report.

## Known limits

* ALLOW is structurally unreachable (GOOD scores as UNKNOWN at best; `good_left_unknown` reports it).
* 124 scenarios still give wide error bars, and every one was written by the same author as the tool's
  fixes. Ground truth is not independently reviewed; one label (U-015) has already been found wrong.
* The v1 builder could not be cross-checked against a validator. Agreement between builder and parser
  proves they match each other, not the network.
* No scenario and no test exercises a real RPC node, real CPI effects, Token-2022 hooks or fees charged
  on-chain; those appear only as "unknown" or as injected responses.
* Whether the on-chain programs ignore trailing instruction bytes (the reason padded instructions are
  decoded) was not confirmed against a validator.
