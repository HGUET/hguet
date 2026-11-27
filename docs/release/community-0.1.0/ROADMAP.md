# HGUET Community Edition 0.1.0 — authoritative release roadmap

Direction adopted 2026-11-27. **Target, not a release announcement.** The product is a free local-first MIT-licensed security toolkit for Solana transactions and autonomous agents. Cloud is independent and non-blocking. Existing architecture documents remain component design references; this roadmap governs delivery priority. Existing implemented v1 contracts and security invariants take precedence over proposed interfaces.

## Release promise

A developer should install a verified binary, run an offline synthetic demo in under a minute, inspect and compare transactions, check independently supplied policies and signed intent, obtain evidence-rich human/JSON/HTML reports, analyze historical transactions with explicit source limits, and integrate the engine into another project. No keys, custody, registration, mandatory Cloud or automatic signing.

| Phase | Deliverable | Exit condition |
| --- | --- | --- |
| 1 — Foundation | Baseline, reusable engine, scoped report v2, initial effect/rule model, offline demo, first runtime harness | [PHASE_01.md](PHASE_01.md) acceptance |
| 2 — Transaction intelligence | Program and asset/authority intelligence, semantic diff, historical audit, standalone reports, runtime validation | [PHASE_02.md](PHASE_02.md): verified vertical slices, no unexplained differences in claimed scope |
| 3 — Runtime validation | LiteSVM, local validator, optional Devnet with disposable keys, public historical corpus, fuzzing | Actual execution comparisons, documented gaps |
| 4 — CLI and reports | Polish inspect/check/simulate/audit/diff/explain/doctor/demo, portable CLI and reports (initial diff/audit/HTML moved to Phase 2) | Golden and end-to-end tests, no hidden network, portable UX |
| 5 — Intent and policy | Semantic mandate (recipient/asset/cap/fee payer/expiry), trusted issuer boundary, token policies, templates | Adversarial positive/negative runtime cases |
| 6 — Payments | x402 V2 exact SVM verification with official SDK fixture, destination ownership and extra effects | Reproducible valid/violating examples; no facilitator, signing or real funds |
| 7 — Integration | Rust library, typed TypeScript CLI wrapper, optional read-only MCP preview | External example builds; operator trust outside agent input |
| 8 — Community benchmark | Independent corpus, adapter contract, reproducible scorecard, contribution process | External adapter and reviewed ground truth; transparent skips |
| 9 — Release engineering | Verified artifacts, supply-chain evidence, installation docs and release notes | All [release gates](RELEASE_GATES.md) for advertised scope |

Milestones: alpha.1 (foundation), beta.1 (validated engine and reports), rc.1 (integration, benchmark and artifact candidates), 0.1.0 (public Community Edition). These are not existing tags. Evidence controls release.

## Architecture and security decisions

- Extract orchestration from CLI into a reusable typed library; choose modules or crates only as justified.
- Separate transaction validity, scoped policy compliance, per-check coverage, simulation status, evidence, and signing authorization. Preserve v1 output/exit behavior with explicit version selection or migration. No general ALLOW.
- Unified effects retain original instruction indices, account roles, asset/program identity, raw integer amounts, provenance and uncertainty. Never sum duplicate observations into claimed gross spend.
- Separate trusted configuration from untrusted agent requests. Valid exact-message hash or signed intent does not guarantee informed authorization or complete execution effects.
- Local deterministic checks, token semantics, RPC analysis, audit, SDK, x402 verification and benchmark remain free. Provider costs may apply to user-selected RPC.
- Cloud contracts, PQ transport, experimental signer remain preserved but not Community Edition release dependencies. No signer-side authorization or production wallet integration.
- MPP, autonomous signer, wallet, GUI, other blockchains, broader DeFi support and commercial Cloud expansion are deferred unless explicitly reprioritized.

[Baseline](BASELINE.md) · [Coverage matrix](COVERAGE_MATRIX.md) · [Release gates](RELEASE_GATES.md) · [Phase 1](PHASE_01.md).

Phase 1.1 accepted at the measured snapshot in [PHASE_01_1.md](PHASE_01_1.md). Phase 2 sequencing supersedes the earlier allocation of first diff, historical audit and HTML report implementations to Phase 4; release gates are unchanged.
