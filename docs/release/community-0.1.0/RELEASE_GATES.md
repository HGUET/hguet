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
