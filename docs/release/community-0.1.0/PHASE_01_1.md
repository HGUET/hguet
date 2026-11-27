# Phase 1.1 — Foundation hardening and acceptance record

**Status: OPEN pending a fresh complete hosted verification.** This is a source-attributed progress record, not a release or independent security audit.

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

- Fresh successful hosted local acceptance and PQ runs on the final source; inspect artifact results and manifests, including ignored/skipped denominators.
- Independent ground-truth review and broader runtime/validator coverage remain release-level work, not claimed by this checkpoint.
- V2 still uses v1 evidence as its compatibility envelope; richer typed provenance and full RPC effect modeling remain later-phase work. Cloud feature isolation remains deferred.
- No product release/tag, signing permission or live-fund execution is authorized.

See [release gates](RELEASE_GATES.md), [baseline](BASELINE.md), and [coverage matrix](COVERAGE_MATRIX.md).
