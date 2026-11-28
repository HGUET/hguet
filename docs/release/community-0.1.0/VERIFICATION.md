# Source-attributed verification — 2026-11-28

**Historical measured snapshot, not release acceptance.** The later full green 29486e4 checkpoint is recorded below. Source [`d716d606a71291f6d65e007d281bbffc513a2784`](https://github.com/HGUET/hguet/commit/d716d606a71291f6d65e007d281bbffc513a2784). The complete runtime workflow is red because formatting fails; no claim that all CI is green.

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

## First public historical smoke — failed fixture comparison

At d2bfa24, [Runtime](https://github.com/HGUET/hguet/actions/runs/46089236388) and [PQ](https://github.com/HGUET/hguet/actions/runs/46089236392) succeeded, including the offline published-fixture regression. The separate [public smoke](https://github.com/HGUET/hguet/actions/runs/46089236362) failed at preBalances before running the live CLI audit. [Artifact 15240132856](https://github.com/HGUET/hguet/actions/runs/46089236362/artifacts/15240132856): all five listed file hashes matched. The provider returned the expected signed wire, slot and version; the checked-in JSON rounded initial/final balances 13086426097436981 and 13086425097431981 to integers ending in 980, through JavaScript Number serialization above 2^53. The delta was unaffected but absolute values differed. Corrected literal decimals; no provider metadata was silently accepted as a passing result. Retry pending. Public endpoint access was demonstrated, but the live HGUET audit itself was not reached. No independent ledger proof.

## First successful live historical audit

Exact source 90e4a36bf91a0b15161c59014fa5f9bd1954429a; [public Devnet smoke SUCCESS](https://github.com/HGUET/hguet/actions/runs/46089512195). [Artifact 15240158130](https://github.com/HGUET/hguet/actions/runs/46089512195/artifacts/15240158130), 6/6 SHA-256 manifest entries verified; archive SHA-256 `02fff4db2a32ec54f266c2bee0d3a6c57c62b67dfa44b08867ff63b7172c059b`. source.txt matches the exact source. The raw provider response and HGUET audit are preserved. SDK and published metadata match; CLI exit 0, FOUND_SIGNATURE_VERIFIED, signatures_verified=true, execution_proven=false, signing_authorization=NOT_AUTHORIZED. Exact sender balances 13086426097436981 and 13086425097431981; fee 5000; deltas -1000005000 and 1000000000. Earlier failed fixture precision comparison remains recorded above. One public legacy/Devnet case, one provider; no independent ledger proof. New Token-2022 runtime suite is pending.

## Full green Token-2022 and public audit checkpoint

Exact source 9eef59dbbd0b34afcda0e69afcd907d1fef9689b: [Runtime SUCCESS](https://github.com/HGUET/hguet/actions/runs/46089660808), [PQ SUCCESS](https://github.com/HGUET/hguet/actions/runs/46089660871), [Public Devnet SUCCESS](https://github.com/HGUET/hguet/actions/runs/46089660814). Downloaded [runtime artifact 15239679776](https://github.com/HGUET/hguet/actions/runs/46089660808/artifacts/15239679776); all 504 SHA-256 manifest entries verified, source.txt identifies exact source, ZIP SHA-256 `d81091be7a794bc9027cd48628aedbc9d65386837c44443459662f52975db14b`. token2022-extensions.json records 4/4 PASS: permanent delegate transfer, transfer-hook configuration changes (not hook CPI), fee collection/harvest/withdrawal and future fee configuration, nontransferable rejection. These are local actual runtime groups, not comprehensive extension semantics. The public historical smoke is one legacy/Devnet example, not independent ledger proof. New ALT lifecycle groups on b840fb9 are pending; no claim of pass.

## ALT lifecycle checkpoint

Exact source e265036de6d0c6950c05fa4f25d4d0dc1cf9411e: [full Runtime SUCCESS](https://github.com/HGUET/hguet/actions/runs/46090077710). Earlier code source b840fb9 also passed (46090021895). Downloaded [artifact 15240568397](https://github.com/HGUET/hguet/actions/runs/46090077710/artifacts/15240568397): 506/506 file SHA-256 values matched; ZIP SHA-256 `613424c0ebbaa6d355d753522048cb5aed25a481b5099dfa236f6a854243ab44`. Both source.txt lines match exact source. alt-lifecycle.json records 2/2 actual LiteSVM groups PASS, including frozen table mutation rejection and controlled slot-history expiry followed by close with 1503360 lamports refunded to recipient. This is controlled local sysvar evidence, not a validator wall-clock cooldown check. PQ and public historical smoke last succeeded on 9eef59d. Separate coverage-guided ASan fuzz targets added subsequently at 36b3bcb; first execution pending.
