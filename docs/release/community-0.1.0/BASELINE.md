# Documentation baseline — 2026-11-27

Source snapshot: `b34924ee6e665dacf2253cecad0e200dc764fce5`. This is not a tested build record.

- MIT license; core, policy, RPC, signer, CLI and Cloud components.
- Existing CLI supports inspect/check, signer-preflight, policy validate, config show and experimental loopback Cloud commands; primary stdin is not supported.
- Legacy/v0/v1 parser, signed v1 PaymentIntent, restrictive local policy, optional RPC evidence, partial token semantics and BLOCK-only signer boundary.
- Tree contains 60 main and 167 regression JSON scenarios (total 227); a file count, not a pass count. Generator and runner must establish executable counts.
- No verified current-commit build, runtime result or full test result was obtained during this documentation-only migration.
- Gaps: independent runtime differential checks, semantic mandates, rich CLI/reporting, historical audit, x402, SDK integrations, external benchmark review and release artifacts.

Phase 1 must refresh with exact HEAD, toolchain/dependency versions, commands, exit status, counts, artifact hashes and observed failures/skips. Preserve previous evidence with commit/date attribution.
