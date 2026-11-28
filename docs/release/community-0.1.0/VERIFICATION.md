# Source-attributed verification — 2026-11-28

**Measured development snapshot, not release acceptance.** Source [`d716d606a71291f6d65e007d281bbffc513a2784`](https://github.com/HGUET/hguet/commit/d716d606a71291f6d65e007d281bbffc513a2784). The complete runtime workflow is red because formatting fails; no claim that all CI is green.

| Evidence | Result | Source artifact entry |
| --- | --- | --- |
| Locked build | PASS | build.log |
| Strict Clippy | PASS | clippy.log |
| Workspace tests | 315 passed, 0 failed, 6 ignored | tests.log |
| Mandatory LiteSVM runtime | 13/13 PASS | result.json |
| Program SDK/CLI | 10/10 PASS | programs-preview.json |
| Flow SDK/CLI | 8/8 PASS | flow-preview.json |
| Authority SDK/CLI | 7/7 PASS | authority-preview.json |
| Diff/Audit SDK/CLI | 10/10 PASS (9 diff, 1 audit configuration group) | diff-preview.json |
| HTML SDK/CLI | 7/7 PASS | html-preview.json |
| Lab SDK/CLI | 7/7 PASS | lab-preview.json |
| Contract/schema/catalogue/scenario-drift/framework checks | PASS (see logs for platform-specific skips) | acceptance record and logs |
| Synthetic benchmark | 227 PASS, 0 FAIL/XFAIL/XPASS | benchmark/report.json |
| Offline policy demo JSON/text | PASS | acceptance logs |
| Rust formatting | FAIL, two formatting diffs in lab.rs | format.log |
| PQ interoperability | SUCCESS (separate workflow) | PQ workflow link below |

The 62 runtime and SDK/CLI groups above (13 mandatory runtime + 49 additional groups) are not 62 independent executed chain transactions: some groups are structural, schema, error, reproducibility or mock-provider checks. Additional groups include selected actual LiteSVM execution. Do not add them to the scenario benchmark as an attack detection metric.

## Reproduce and inspect

- [Runtime & full acceptance workflow](https://github.com/HGUET/hguet/actions/runs/46086487261) — conclusion failure due to formatting.
- [Runtime evidence artifact](https://github.com/HGUET/hguet/actions/runs/46086487261/artifacts/15239177591) — downloaded and verified: **498/498** listed file SHA-256 values matched. source.txt and benchmark metadata name the exact source above.
- [PQ workflow](https://github.com/HGUET/hguet/actions/runs/46086487268) — success. The separate PQ artifact was not re-downloaded for this checkpoint.
- Earlier [full green runtime](https://github.com/HGUET/hguet/actions/runs/46086362411) and [PQ](https://github.com/HGUET/hguet/actions/runs/46086362409) on `28554a4b35df4da5000ba981b0b27c0155707d42`, before the lab changes.

Downloaded runtime ZIP SHA-256: `954b1e57800bb8c56c17900b8d767766bb231ce69bfe52fbb819a825c7b04fd4`.
Tested CLI binary SHA-256: `b58029ee35c12757e123fd23492a18028f6ad2cba998ce682b51728628f81316`.
Benchmark scenario SHA-256: `446af2311a601cb73c0013a1385de187ad044e79d730979ff5f18930708a9549`.

Environment: hosted Ubuntu 24.04 x86_64, Rust 1.100.0, Python 3.12.16, Solders 0.29.0. Network-isolated SDK/CLI harnesses run after dependency installation. GitHub artifacts are retention-limited and may require authentication; checksums are not publisher authentication.

```sh
cargo build --locked -p hguet
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python -m pip install -r testing/runtime/requirements.txt -r testing/requirements.txt
python scripts/run_phase01_checks.py --evidence /tmp/hguet-acceptance --hguet target/debug/hguet
```

See [runtime harness](../../../testing/runtime/README.md) for the individual scripts and isolated environment; the hosted workflow is the authoritative full command sequence.

## What the benchmark means

| Project-authored label | Observed decision | Count |
| --- | --- | ---: |
| BAD | DENY | 119 |
| UNKNOWN | UNKNOWN | 77 |
| GOOD | UNKNOWN | 31 |

All 227 expected outcomes passed. GOOD remains UNKNOWN because the engine does not grant signing permission; this is neither approval performance nor a real-world detection rate. Synthetic fixtures are not representative traffic and their labels are not independently reviewed. The separate mock Cloud track is a reference model, not server effectiveness evidence.

## Generated documents

The verified ZIP contains five actual engine HTML reports under html-reports/ and the six-case lab's 12 JSON/HTML files plus manifest under security-demo-lab/. The lab suite checks SDK unsigned wire roundtrip, independent CLI report parity, local anchors, passive markup, deterministic output, manifest hashes and no overwrite.

Earlier Chromium content-rendering checks on five reports used viewport widths 1280 and 390 CSS pixels; no page-level horizontal overflow, broken link target, external HTTP request or page error was observed. Content was loaded in isolated pages rather than direct local-file navigation. No full accessibility/browser certification is claimed.

## Remaining work

Formatting needs correction and a new exact-source full acceptance run. Phase 2 broader coverage and all whole-release gates remain open: public historical fixtures, more System/Token-2022/authority and ALT mutation execution, validator and fuzz differential corpus, stronger semantics/intent policies, independent benchmark review and third-party adapter, x402/integration work, packaging/provenance and release readiness. No live public historical audit sample was verified here. No product release or independent audit.

[Roadmap](ROADMAP.md) · [Coverage](COVERAGE_MATRIX.md) · [Gates](RELEASE_GATES.md).

## Extended validation checkpoint

Exact source [29486e4](https://github.com/HGUET/hguet/commit/29486e4dcb95b9c40d2d139c667e7f066d771a6f): [full Runtime CI SUCCESS](https://github.com/HGUET/hguet/actions/runs/46088566612), including formatting and strict Clippy. The additional 120/120 differential cases and 2/2 actual rollback comparisons passed. Downloaded [artifact 15239768083](https://github.com/HGUET/hguet/actions/runs/46088566612/artifacts/15239768083) has 502/502 manifest entries matching; ZIP SHA-256 `c20a52be8c9466905297fe51a8c9bd443ed3e9208fc52bd3e4ea27d2e5c8ba1a`. Both source.txt lines identify the exact source. Rollbacks failed at instruction 1 with custom code 1 and left recipient/delegate state unchanged. PQ succeeded at fb834f0, before the Python-only differential/rollback changes; no new PQ run claimed for 29486e4. Earlier formatting failure above is superseded by this scoped green checkpoint. Public historical validation is a new separate work item.
