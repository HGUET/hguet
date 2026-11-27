# Documentation baseline â€” 2026-11-27

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

## Consolidated verification, 2026-11-27

Source parent 41d45d1f54446157908a654a89a7915ac1c5ac1c plus the text output
change committed with this evidence. Ubuntu 26.04 WSL, Rust 1.100.0,
Python 3.14.4, OpenSSL 3.5.5 and Solders 0.29.0.

Commands completed successfully:

```sh
cargo build --locked --workspace
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
python3 scripts/validate_contract.py
python3 scripts/validate_json_contracts.py
python3 testing/tools/build_scenarios.py --check
python3 testing/runner/run_benchmark.py --hguet HGUET_BINARY --suite all --out target/phase01-final/benchmark
python3 testing/runtime/native.py --hguet HGUET_BINARY --out target/phase01-final/runtime.json
```

The workspace run recorded 265 passed, zero failed, six explicitly ignored
PQ tests. The subsequently added text/stdin compatibility test passed in a
separate package run. Benchmark: 227 PASS, zero FAIL/XFAIL/XPASS; BAD 119/119,
UNKNOWN 77/77, GOOD left UNKNOWN 31/31. Thirteen real runtime cases completed.
All three demo reports validate against report v2. Demo output was identical
inside an isolated Linux network namespace with no external network.
The six ignored PQ checks were selected separately with
`cargo test --locked -p hguet-cloud --all-targets -- --ignored`; all six passed.

WSL jsonschema initially lacked RFC3339 format validation. Adding the Linux
rfc3339-validator 0.1.4 dependency restored rejection of invalid timestamps;
both contract validators then passed without schema changes.

Local evidence is target/phase01-final. SHA-256 hashes:

- benchmark/report.json e66d09a95bcafd338d12f8695e43f68e4016be823c8a78bd9af0acbb2ed4484f
- runtime.json 6dbf5c6a829f7901fd02a9bca01bee561764ae825c32e8fe07307fb882d84bf8
- demo.json e9408de11790fe8ec74b84604fabcd153fd682cd29820147801e3b6c8312c4c8

Phase 1 remains open for detailed per-rule positive/negative catalogue,
finer per-check coverage and a durable published evidence package. Original-wire
effects are typed; CPI/net/state observations retain v1 evidence separation.
Cloud feature isolation was evaluated and deferred to preserve compatibility.


## Source-attributed evidence archive

Tested commit aa198e545d86461d0d2c1fd6763581b65c3df8d2.
Archive target/phase01-catalogue-evidence.zip contains 459 files and a
manifest with per-file SHA-256 hashes. All entries were read back and their
hashes verified. Archive SHA-256:
cb13ebee332fc131eb3774b76dc5e3a421dc143649cc4b9a1b8f91637548ce33.

Workspace: 268 passed, zero failed, six ignored PQ checks. Those six passed
in the separately selected PQ run. Benchmark: 227 PASS, zero FAIL/XFAIL/XPASS.
Runtime: thirteen cases. Demo executed in an isolated network namespace.
The archive includes raw command logs, environment, benchmark inputs/results,
runtime output and demo output. It does not itself provide publisher
authentication or independent review.

All eight local-policy codes now have catalogue entries and test references.
Other finding families still require individual catalogue review.
Phase 1 acceptance remains open for that work and complete evidence/coverage
review. The archive is a local artifact, without a public release or tag.

## WSL regression refresh — 2026-11-27

Source: base commit 3faa940 plus the cross-program CPI regression and
catalogue/docs changes in the accompanying commit. This run is independent
of the older aa198e5 evidence archive and does not refresh its benchmark
or runtime claims.

Ubuntu-26.04 WSL: `cargo test --locked --workspace` passed 280 tests,
zero failures, six ignored. `cargo test --locked -p hguet-cloud --all-targets
-- --ignored` separately passed all six PQ tests.
`cargo clippy --locked -p hguet --all-targets -- -D warnings` and
`cargo fmt --all -- --check` passed. Rule catalogue reference validation
passed for 111 entries with zero detected uncatalogued engine codes;
five targeted regression gaps remain open.

Local logs: target/phase01-current/workspace-tests-wsl.txt,
pq-tests-wsl.txt and clippy-wsl.txt. Tested source SHA-256:

- crates/hguet-cli/src/pipeline_tests.rs: 2835650f9ba9346a480604c89012af796d6c0a9b3b4f9cc1ad1f9a8927211063
- protocol/v2/rules.json: bc5dcfd7a58a5045220e84d72432ca980ad7fea76142dd6ed29ac8a6baa9e298

## Catalogue CI and portability refresh — 2026-11-27

Base ba9f735 plus the catalogue CI/portability changes in the accompanying
commit. The validator and seven mutation/portability tests passed on Windows.
WSL Ubuntu-26.04: catalogue validation passed for 125 rules with five explicit
targeted regression gaps; all workflow YAML parsed successfully.
`PYTHONPATH="$PWD/target/runtime-deps" python3 -m unittest discover -s
testing/tests -v` ran 108 tests in 490.489 seconds: OK, zero skips.
OpenSSL-dependent TLS tests ran; ResourceWarning messages for unclosed test
SSL sockets remain visible in the log. The run covers the Python framework,
not a new execution of the 227-case HGUET benchmark.

Normalized 1073 fixture references to repository-portable forward slashes.
CI now invokes the catalogue validator and its regressions. Local full log:
target/phase01-current/framework-tests-wsl.txt. SHA-256:
52314ac98a60c7aad3e63dec091419f4aa1728214aa2d90b3bdd2eec2d84ba0b

## Verified-review reuse — 2026-11-27

Base da28a8b plus the review-reuse changes in the accompanying commit.
CLI consumes the exact bounded mint/source reviews produced during intent
verification. Existing public verifier return types remain available through
compatibility wrappers. Two redundant second-check errors are historical
catalogue entries; three RPC defensive finding regression gaps remain open.
No signed constraint or failure precedence is waived.

`cargo test --locked -p hguet -p hguet-core`: 118 passed, zero failed.
CLI/core Clippy with warnings denied and workspace formatting passed.
Eight catalogue validator regressions passed, including rejecting retirement
of a still-emitted code.
WSL locked CLI build and full benchmark: 227 PASS, zero FAIL/XFAIL/XPASS.
This is a current local regression measurement, not independent review or
a refresh of the older archived evidence package.

Report: target/phase01-current/review-reuse-benchmark/report.json. SHA-256:
41db0958140ff5b2c4b7151713f6dbe28a38c3098c93dcd78ddaa93343933656

Tested Rust source SHA-256 (LF-normalized):

- crates/hguet-core/src/lib.rs: 849266f8bc4afc2eb90b45a5c62711d93ce9c30307b3bdb15a852fc66942acb2
- crates/hguet-cli/src/lib.rs: 2fa074f122b1cc37ead9d888b495c49ba503e340352d35ced4f1d4465e61dc64

## Runtime CI preparation — 2026-11-27

Base c682442 plus the runtime CI/output changes in the accompanying commit.
All thirteen LiteSVM comparisons ran successfully in WSL Ubuntu-26.04,
Solders 0.29.0, inside `unshare --user --map-root-user --net`.
Each case now records comparison=PASS after its assertions. Existing detailed
fee/runtime fields are retained. Workflow YAML validation passed.
The new Ubuntu-24.04/Python-3.12 hosted job has not been run here; its status
is NOT RUN until actual hosted results are available. The job installs pinned
dependencies, builds locked CLI, isolates runtime networking and uploads
source/environment/binary-hash/results/log artifacts. Bash pipefail prevents
tee from masking a harness failure. No release or hosted run was triggered.

Local result: target/phase01-current/runtime-network-isolated.json. SHA-256:
4a8ddd5f8d51203891436f442debd952e97e3d28e4b718708376f3be35d18277
