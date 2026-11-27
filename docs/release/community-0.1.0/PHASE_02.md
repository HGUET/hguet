# Phase 2 — Transaction Intelligence

**Status: development; not a public release.** Prerequisite: Phase 1.1 accepted on its measured source. All capabilities below are free and local-first, with explicit RPC only for operations requiring it. Existing v1/v2 semantics, signing refusal and regression tests remain binding.

## Work packages

| Slice | Deliverable | Acceptance |
| --- | --- | --- |
| 2.0 Program intelligence | Typed original-wire program/instruction catalogue; core System, SPL, Token-2022, Compute Budget, ATA, Memo, ALT; unknowns explicit; optional Stake/loader/one DeFi integration after core validation | Exact program ID and layout; SDK vectors, malformed and ALT cases; execution comparison for every advertised runtime behavior |
| 2.1 Asset flow | Separate wire/CPI/net/state views, raw integer amounts per asset, account identity and role, fees/rent/withheld, conflict markers | No double counting, unknown not zero, evidence pointers, runtime state comparison |
| 2.2 Authority intelligence | Declared account owner/delegate/authority mutations, revocations and future-control exposure; observed state separate | Positive and negative tests; no inferred ownership or permission |
| 2.3 Semantic diff | Offline before/after comparing ordered instructions, roles, amounts, programs, hashes and resource config | Added/removed/reordered instructions, duplicates, opaque and unresolved addresses; no false equivalence |
| 2.4 Historical audit | Explicit HTTPS RPC getTransaction by signature; verify returned identity, cluster and supported encoding; historical vs current state separate | Bounded transport, malformed/adversarial replies; read-only public fixtures; no replay/broadcast |
| 2.5 Reports | Terminal and self-contained HTML/DOT with asset and authority evidence; synthetic demo lab | Escaping, no external script/CDN, correct unknowns and evidence; offline tests |
| 2.6 Validation | SDK differential corpus, LiteSVM and validator tests, adversarial benchmark | Actual measured results, explicit denominators and gaps, full compatibility checks |

## Initial slice 2.0

Provide an additive offline program-intelligence API and CLI, separate from existing report v1/v2 contracts. Report one row per original instruction, exact program identity or unresolved lookup index, declaration name, layout status, declared parameters and account roles where supported. No program-name allowlisting or safety inference. Distinguish recognized data shape from runtime acceptance. Never infer effective fees from a Compute Budget instruction, especially v1 inline resources. Do not reproduce memo content into terminal output; report byte length and UTF-8 validity. ATA declarations do not establish PDA correctness, ownership or rent amount. Start with Compute Budget, Memo, System movement reuse, and ATA create variants. All remaining cases stay explicitly unsupported until separately validated.

No mandatory Cloud, signing, wallet keys, real funds, hidden network or release publication. Use independently constructed SDK fixtures; test invalid lengths, unknown opcodes, unresolved ALT, v1 configurations and misleading account roles. Preserve exact existing JSON and exit semantics. Record actual hosted results for each increment; do not mark Phase 2.0 complete until required coverage is implemented and validated.

Later slices require their own technical specification and acceptance record. Phase 3 remains broader validator/devnet/history/fuzz verification; Phase 4 remains CLI polish and portable delivery.
