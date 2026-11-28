# Community Edition release gates

**Targets, not measured passes.** Mark PASS only with exact commit, command, actual output/artifact and platform. FAIL or NOT RUN remains visible. Unsupported capabilities must be excluded from claims and handled explicitly.

| Gate | Mandatory evidence |
| --- | --- |
| G01 free independence | Build/run local engine with Cloud unavailable; no registration, telemetry, wallet key or unexpected outbound calls |
| G02 compatibility | Existing v1 schema, signing refusal and exit contract regression tests; documented v2 migration |
| G03 parser correctness | Independent SDK fixtures, differential tests and bounded fuzzing; zero unexplained differences in advertised scope |
| G04 runtime correctness | Actual LiteSVM and validator execution vs independently generated fixtures; no mock substitution |
| G05 security | Zero signing/broadcast authorization, critical missed violations and false hard DENY in required reviewed cases; explicit UNKNOWN coverage |
| G06 effects | Distinct wire/CPI/net/state evidence, fees/authority/gaps, conflict and overflow tests |
| G07 CLI | Clean-machine quick start, offline demo, bounded stdin, stable JSON/text/HTML reports, audit/diff; safe escaping |
| G08 policies / intent | Independent trust anchor, exact message binding, semantic recipient/asset/cap restrictions, negative tests |
| G09 x402 | Official version-pinned exact SVM fixture; legitimate scope and extra-effect violation; no real funds |
| G10 integrations | Rust and TS examples actually run; MCP optional and not advertised unless verified |
| G11 benchmark | Public reproducible report, denominators, hashes, skips/failures, independent review status; third-party adapter |
| G12 packaging | Clean locked builds and smoke tests per advertised target, checksums, verified publisher signature/attestation, SBOM and provenance |
| G13 documentation | Current vs target clearly separated, limitations and security reporting route; no unverified claims |

Platform claims require actual testing per published target. Do not create fictitious signatures/notarization or present checksums as publisher authentication. No production-grade or independently audited claim without independent evidence. Release owner decides whether to narrow advertised scope; agents may not silently waive gates. External review is sought; absence must be disclosed. Cloud availability is not a gate.

## Phase 1 evidence checkpoint, 2026-11-27

These are partial release-gate observations, scoped to the recorded local tests.

| Gate | Observed evidence and remaining work |
| --- | --- |
| G01 | Demo executes identically with Linux networking isolated; broader clean-install gate open |
| G02 | V1 golden cases, full synthetic benchmark and public contract validators pass |
| G03 | SDK legacy/v0/v1 comparisons added; comprehensive differential/fuzz coverage open |
| G04 | Thirteen LiteSVM cases pass; validator corpus remains later-phase work |
| G05–G06 | Refusal preserved in measured cases; per-rule fixture catalogue and finer coverage remain open |
| G07 | Bounded stdin, explicit text, doctor and real demo implemented; HTML/audit/diff remain open |
| G08–G10 | Existing intent/policy preserved; semantic mandate, x402 and integrations remain open |
| G11 | 227/227 local benchmark cases pass; independent review and adapter remain open |
| G12 | No release package or publisher provenance produced |
| G13 | Baseline records measured results and runtime limits; full release documentation remains open |

See BASELINE.md for commands, source attribution, evidence locations and hashes.

## Phase 1.1 checkpoint

Intermediate hosted runs measured 13/13 mandatory LiteSVM comparisons and 227/227 synthetic benchmark cases; the same runs also reported strict formatting/lint failures. See [PHASE_01_1.md](PHASE_01_1.md) for links and later corrective commits. Do not waive G02/G03/G04/G05 on older results. No release gate is marked complete by this checkpoint.

Phase 1.1 final hosted acceptance succeeded at `19c24255c41749c90b9c6d9bd8c02158bd97d640`; see [verified evidence](PHASE_01_1.md#final-acceptance--2026-11-27). These results do not close whole-release gates or certify later source revisions.

## Phase 2 evidence checkpoint — 2026-11-28

[Verification record](VERIFICATION.md) identifies source d716d60, 315 workspace tests passed (6 ignored), 13 mandatory LiteSVM comparisons, 49 additional SDK/CLI groups, 227 synthetic scenario passes, strict Clippy and separate PQ success. Full runtime workflow FAILS on two formatting differences. This is partial evidence, not release acceptance.

| Gate | New evidence and remaining work |
| --- | --- |
| G01/G02 | Network-isolated reports and lab, standalone contract parity; existing v1/v2 regressions passed. Broader clean installation and platform compatibility remain open. |
| G03/G04 | Selected SDK legacy/v0/v1 and actual LiteSVM cases; broader differential corpus, validator, live public historical and fuzzing remain open. |
| G05/G06 | Wire flow, authority, diff, RPC links and historical metadata separation, refusal preserved; semantic/state and independent threat review coverage incomplete. |
| G07 | HTML, audit, diff and demo lab now implemented, scoped tests pass. DOT, browser/accessibility, portability and live historical checks remain open. |
| G08/G09/G10 | Semantic mandates, x402 and external integrations not yet accepted. |
| G11 | 227/227 expected synthetic outcomes; independent review and third-party adapter remain open. |
| G12 | No public release package or publisher attestation. |
| G13 | Current README, command/contract index, coverage and limitations updated; full release documentation acceptance pending. |

No entire gate is waived by this checkpoint.
