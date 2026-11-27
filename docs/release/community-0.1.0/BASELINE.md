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
launcher and were interrupted. The verbose rerun outside the restricted launcher completed in 63.034 seconds: 101 tests, 15 skipped because the Windows environment lacked the OpenSSL CLI. These mock framework tests do not establish runtime correctness.
Real Solana SDK/LiteSVM runtime validation is NOT RUN at this milestone.
Phase 1 acceptance remains OPEN.

### Engine extraction verification

Analysis orchestration now lives in the existing hguet package's library
target, with AnalysisInput, TrustedConfig, Operation and analyze. The caller
supplies an RPC transport and a clock closure. The CLI owns bounded input
loading and output. Input loading errors are retained until the original
policy/intent evaluation point to preserve v1 precedence.

All 47 pre-existing package tests pass after the move. Five persisted golden
cases compare baseline JSON and exit codes, including file, policy and intent
errors. A sixth one-time comparison covered an existing restrictive policy.
The complete benchmark passed 227/227 after extraction, with zero FAIL,
XFAIL or XPASS. Output is target/phase01-evidence/engine-benchmark.
Contract validators and strict workspace Clippy passed.
Cloud remains compiled as before; optional feature isolation is deferred
until its dependency and platform implications are tested.


### WSL framework verification, 2026-11-27

At commit 21c70a0 the complete Python framework ran in Ubuntu 26.04 WSL,
Python 3.14.4, OpenSSL 3.5.5, using the installed Linux jsonschema and
PyYAML packages. Command:
python3 -u -m unittest discover -s testing/tests -v

Result: 101 tests in 66.056 seconds, OK, zero skips. All 15 tests skipped
in the Windows run executed. Output:
target/phase01-evidence/framework-wsl-native.log.
Python emitted ResourceWarning messages for unclosed SSL sockets in the
test framework. These warnings remain to be addressed. This run tests
framework/TLS behavior; actual Solana runtime verification remains NOT RUN.
An initial WSL attempt incorrectly reused Windows PYTHONPATH dependencies
and was interrupted; it is excluded from the acceptance result.
