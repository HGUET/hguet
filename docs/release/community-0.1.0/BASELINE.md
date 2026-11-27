# Documentation baseline — 2026-11-27

Source snapshot: `b34924ee6e665dacf2253cecad0e200dc764fce5`. This is not a tested build record.

- MIT license; core, policy, RPC, signer, CLI and Cloud components.
- Existing CLI supports inspect/check, signer-preflight, policy validate, config show and experimental loopback Cloud commands; primary stdin is not supported.
- Legacy/v0/v1 parser, signed v1 PaymentIntent, restrictive local policy, optional RPC evidence, partial token semantics and BLOCK-only signer boundary.
- Tree contains 60 main and 167 regression JSON scenarios (total 227); a file count, not a pass count. Generator and runner must establish executable counts.
- No verified current-commit build, runtime result or full test result was obtained during this documentation-only migration.
- Gaps: independent runtime differential checks, semantic mandates, rich CLI/reporting, historical audit, x402, SDK integrations, external benchmark review and release artifacts.

Phase 1 must refresh with exact HEAD, toolchain/dependency versions, commands, exit status, counts, artifact hashes and observed failures/skips. Preserve previous evidence with commit/date attribution.


## Measured Phase 1 baseline, 2026-11-27

Commit 320c7a1c6bf76881822c1bd389064fb02042edfa, initially clean main,
Windows x86_64 MSVC, rustc 1.100.0 (0ef1bc386), LLVM 23.1.5.

Executed successfully with exit 0:
- cargo build --locked --workspace
- cargo fmt --all -- --check
- cargo clippy --locked --workspace --all-targets -- -D warnings
- cargo test --locked --workspace
- python scripts/validate_contract.py
- python scripts/validate_json_contracts.py
- python testing/tools/build_scenarios.py --check
- python testing/runner/run_benchmark.py --hguet target/debug/hguet.exe --suite all --out target/phase01-evidence/benchmark

Benchmark measured 227 PASS, zero FAIL/XFAIL/XPASS. BAD denied 119/119,
UNKNOWN preserved 77/77, GOOD left UNKNOWN 31/31. Signing-boundary field
was present and blocked in 210/227 scenarios. This denominator must not be
reported as a 227-case signing-boundary check. Cloud scoring uses mocks.

Local raw output is under target/phase01-evidence. These generated files
are excluded by Git. The report JSON records the executable digest.
Framework self-tests initially stalled without output under the restricted
launcher and were interrupted. A verbose rerun is being evaluated separately.
Real Solana SDK/LiteSVM runtime validation is NOT RUN at this milestone.
Phase 1 acceptance remains OPEN.
