# Community Edition coverage matrix

**Developer preview.** Implemented means code exists, not complete assurance. Evidence is scoped to the exact source in [VERIFICATION.md](VERIFICATION.md); whole-release gates remain open.

| Capability | Current implementation and scoped evidence | Open acceptance work |
| --- | --- | --- |
| Legacy/v0/v1 parse | SDK hashes and selected actual LiteSVM executions, v1 inline resources | Broad differential/fuzz/validator and live-cluster coverage |
| Ed25519 / exact message | Local signature checks, exact message digest, signed historical fixtures | Broader independent vectors |
| PaymentIntent v1 | Independently pinned issuer and exact-message binding, limited declared constraints | Semantic recipient/purpose/asset mandate and signer integration |
| Local policy | Restrictive SOL/program/recipient scope, v2 scoped results | Richer token/authority policy and independent threat review |
| Program intelligence | 10 SDK/CLI groups; selected runtime cases and explicit coverage gaps | Broader System, Token-2022 extensions, Stake/Loader/DEX scope |
| Asset flow | 8 SDK/CLI groups, raw u128 totals, fee separation, unknown mint/ALT, RPC link tests | Program-aware balance identities, full CPI/net/state reconciliation, rent/withheld/fees |
| Authority | 7 SDK/CLI groups, selected actual delegate/revoke/freeze/mint/close tests | Additional Token-2022, System/Stake/Loader/ALT state and CPI |
| Semantic diff | 9 SDK groups, exact bytes and order, privileges, v1, opaque and ALT fingerprints | Rich alignment, more differential context tests; no equivalence claim |
| Historical audit | 7 Rust synthetic signed-fixture tests, explicit RPC and historical metadata only, CLI error group | Public finalized historical corpus, adversarial independent providers; no ledger proof |
| RPC simulation | Existing single-provider advisory transport, snapshots, correlation | Real validator, broader adversarial and non-atomic evidence verification |
| Combined report / HTML | 7 SDK/CLI groups, 5 generated reports, passive markup, local anchor and JSON parity; limited Chromium content checks | Broader browser/accessibility, DOT, terminal/report polish |
| Demo Lab | 7 SDK/CLI groups, 6 deterministic unsigned cases, 12 hashed JSON/HTML files | Additional corpus and runtime tests; existing lab does not execute fixtures |
| Signing boundary | BLOCK-only; no signing or broadcast | Preserve invariants, independent audit |
| Engine / v2 | Reusable library, default v1 compatibility, explicit report v2 | Released integration surface and compatibility review |
| x402 exact SVM | Planned | Official pinned SDK examples and semantic checks |
| Rust / TS / MCP | Internal Rust library exists; no released integration packages | Public example builds and optional read-only MCP |
| Benchmark | 227/227 expected synthetic scenarios, 13 mandatory actual local runtime comparisons plus additional groups | Reviewed ground truth, external adapter and representative validation |
| Cloud / MPP | Experimental / deferred | Not release dependencies |

## Evidence checkpoints

Phase 1.1 accepted on [19c24255](PHASE_01_1.md). Initial Phase 2 runtime/SDK slices have been progressively verified; exact source and links are retained in [PHASE_02.md](PHASE_02.md). Latest measured source d716d60: 315 workspace tests passed, 6 ignored; 62 runtime and SDK/CLI groups passed, including structural and negative tests; 227 synthetic benchmark expected outcomes passed. Separate PQ workflow passed. Full runtime workflow remains red on formatting. No entire release gate or complete instruction family is certified by these counts.

[Limitations](../../../LIMITATIONS.md) · [Supported programs](../../../SUPPORTED-PROGRAMS.md) · [Release gates](RELEASE_GATES.md).
