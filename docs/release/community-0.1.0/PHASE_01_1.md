# Phase 1.1 — Foundation hardening and acceptance record

**Status: ACCEPTED for Phase 1.1 at source `19c24255c41749c90b9c6d9bd8c02158bd97d640`.** This is a source-attributed progress record, not a release or independent security audit.

Audit baseline: `2de07aff3e220856337dd73cd7f0b6e68abe2fab`.

## Implemented corrections

- Mandatory LiteSVM case inventory, incremental evidence and fail-closed exit status. Missing, duplicate, incomplete or unexpected results cannot pass. All 13 comparisons run separately. Optimized Python with disabled assertions is refused.
- Expected runtime rejection checks verify exact instruction index and custom code (System 1; SPL OwnerMismatch 4; Token-2022 FeeMismatch 32) and retain account-state assertions.
- Rust toolchain installation uses isolated homes. Evidence lives outside checkout, survives setup/build failures, and includes a per-file SHA-256 manifest.
- V2 reuses one parsed representation, records local policy compliance from typed evaluation, and preserves v1. Argument errors for explicit v2 JSON inspect/check emit the v2 envelope. Effects are omitted if inspection evidence is absent. Selected policy/signature findings point to existing wire evidence.
- Three previously open defensive RPC findings now have paired tests calling real typed guard functions and the production finding mapping. This is stage-level regression coverage, not proof that malformed RPC data can reach the stage through all upstream validators.
- Hosted local acceptance workflow records formatting, build, strict Clippy, workspace tests, contract and catalogue checks, framework, benchmark, and network-isolated demos. Separate PQ workflow retains no-skip requirements and publishes evidence.

## Actual hosted evidence

| Snapshot | Evidence | Result |
| --- | --- | --- |
| fadecc2 | [Run 46018226570](https://github.com/HGUET/hguet/actions/runs/46018226570), [artifact 15208065426](https://github.com/HGUET/hguet/actions/runs/46018226570/artifacts/15208065426) | Runtime 13/13, benchmark 227/227, Rust 285 pass / 6 ignored; strict Clippy failed |
| 32e4e79 | [Run 46018518956](https://github.com/HGUET/hguet/actions/runs/46018518956), [artifact 15207685955](https://github.com/HGUET/hguet/actions/runs/46018518956/artifacts/15207685955) | Runtime 13/13, benchmark 227/227, Rust 289 pass; catalogue 125 records, zero uncatalogued codes and zero open targeted references; fmt and Clippy failed |

The first artifact was downloaded and all 468 manifest entries verified; archive SHA-256 `19fe6ac4092c38a3b0fe6dc4c4f3775a70c0de9e2c1eaaa48ff31165526defec`. The second downloaded archive SHA-256 is `824b79656ff1da4fe64f5870839a79bc592645d4134c67a2fcafd20e7e0e2536`. These are separate snapshots, not evidence for later commits.

The toolchain installation conflict and checkout evidence loss were diagnosed through actual hosted logs and corrected. Five acceptance unit tests independently passed on exact repository blob copies (653808d657d98434024bb75b3948979588c301ec, f0edb1e15fdcead9754db6c1c55e42559bc66a56).

Clippy's needless reborrow was fixed in c61f4eb. Formatting changes in the following checkpoint apply the actual hosted rustfmt diff. The new PQ workflow is enabled in 8c37e91. These corrections require final successful reruns; do not mark PASS on the strength of the older reports.

## Open acceptance items

- Independent ground-truth review and broader runtime/validator coverage remain release-level work, not claimed by this checkpoint.
- V2 still uses v1 evidence as its compatibility envelope; richer typed provenance and full RPC effect modeling remain later-phase work. Cloud feature isolation remains deferred.
- No product release/tag, signing permission or live-fund execution is authorized.

See [release gates](RELEASE_GATES.md), [baseline](BASELINE.md), and [coverage matrix](COVERAGE_MATRIX.md).

## Final acceptance — 2026-11-27

Both hosted workflows succeeded on exact source `19c24255c41749c90b9c6d9bd8c02158bd97d640`. Downloaded archives independently checked for source attribution and every listed SHA-256 entry.

| Evidence | Actual result |
| --- | --- |
| [Local acceptance run](https://github.com/HGUET/hguet/actions/runs/46018962197) / [artifact](https://github.com/HGUET/hguet/actions/runs/46018962197/artifacts/15208280536) | All 12 commands exit 0; 289 Rust tests passed, 6 ignored; benchmark 227/227, LiteSVM 13/13, 5 acceptance unit tests; Python framework 106 passed, 3 skipped |
| [PQ run](https://github.com/HGUET/hguet/actions/runs/46018962231) / [artifact](https://github.com/HGUET/hguet/actions/runs/46018962231/artifacts/15207077012) | 109 Python tests passed with no skips; 6 explicitly selected Rust PQ tests passed |

Runtime archive SHA-256: `e3ea79a27285f678966f64d773c823e10676207259b10e8e489d609919708888` (468 manifest entries, no mismatches). PQ archive SHA-256: `224b36cc6beeadd1183966b5af7b12831169484cfb42f15adb27327ac9c1d421` (5 entries, no mismatches). CLI SHA-256 `07307903f7dbd30aed5ba32132cb79dd1146d6ca19b3cce6a7c9288790b50763` matches runtime, benchmark and before/after acceptance records. Ubuntu hosted runner, Python 3.12.16, Solders 0.29.0. No claims of independent security audit or live cluster compatibility. Phase 2 may begin; release gates remain open.
