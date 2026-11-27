# Phase 1 — Community Edition foundation

## Mission and boundaries

Implement a working, independently useful local security analysis foundation, not a documentation-only or Cloud expansion task. Work incrementally from current main. Preserve MIT, all existing tests, v1 contracts and BLOCK-only signing. No keys in released analysis code, signing/broadcast, real funds, mandatory Cloud, hidden network, speculative mass refactoring or automatic publication. Existing CI may be used; do not weaken gates. Disposable keys only in isolated test harnesses.

## 1. Baseline and compatibility

Record exact HEAD, clean/dirty status, toolchain, locked dependencies and platform. Build workspace; run fmt, clippy, locked tests, public contract validators, benchmark generator check, harness tests, all existing scenarios. Discover runner commands from repository; capture stdout/stderr, exit status, pass/fail/skip/XFAIL, counts and artifacts. Report unavailable platform/PQ/live checks separately. Update BASELINE and COVERAGE_MATRIX with evidence. Do not remove tests or change ground truth to match output.

## 2. Extract reusable analysis API

Locate orchestration in hguet-cli/src/main.rs. Move into a small typed engine module or justified crate; leave CLI as adapter. Separate untrusted transaction/intent bytes from independently configured network, issuer public key, policy and permitted RPC. Inject transport and time source; offline default, no implicit RPC/Cloud. Preserve existing v1 JSON field meanings, exit codes, hard DENY precedence and signer refusal. Add golden regression tests comparing old/new CLI output. Evaluate Cloud feature isolation without breaking sandbox protocol.

## 3. Report v2 and evidence

Add separate versioned schema and opt-in CLI selector; do not mutate v1. Report structural validity and signature status separately, scoped policy compliance (MATCH/VIOLATION/UNKNOWN/NOT_CONFIGURED), per-check coverage (COMPLETE only for named scope, PARTIAL/UNSUPPORTED), simulation status, findings, provenance and signing_authorization=NOT_AUTHORIZED. No general ALLOW. Unknown evidence never becomes zero or safe. Retain verified intent scope, RPC slot/source and non-atomic limitations. Test mixed violation+coverage cases.

## 4. Initial effects and rule catalogue

Reuse current decoding/correlation; typed effects for native transfer, checked token transfer/burn, delegate, authority change, account closure and unknown. Stable identifiers map existing codes without breaking v1. Each finding documents scope, severity, evidence references, limitations and positive/negative fixtures. Preserve raw integer quantities; separate original-wire declaration, CPI observation and net delta. No ownership or gross spending claims from unavailable data. Defer broad program coverage and graph visualization.

## 5. CLI demo and bounded input

Add bounded stdin for inspect/check, one JSON object on stdout and diagnostics on stderr for JSON mode, preserve old flags and error/exit behavior. Add explicit human-readable format, help, version metadata and doctor (offline by default; no secret/URL logging). Add hguet demo using versioned synthetic fixtures: one scoped match without authorization, one extra transfer exceeding cap, one unknown/opaque case. Show expected versus observed effects and evidence; no hardcoded fake findings. Run demo from clean build, network disabled, no wallet credentials.

## 6. Initial real runtime harness

Pin compatible Solana SDK and LiteSVM versions; record v1 support independently. Generate transactions independently of HGUET parser; compare actual pre/post state and execution outcome with claimed effects. Minimum cases: native SOL transfer, SPL TransferChecked, delegate approval, authority change, Token-2022 transfer fee, repeated debits exceeding cap. Include legitimate and violation variants; isolated disposable keypairs only. Distinguish runtime rejection, missing evidence and HGUET violation. If runtime unavailable, report NOT RUN and blocker; no mock substitution. Full local validator/Devnet corpus in Phase 3.

## 7. Acceptance and handoff

Phase 1 is complete only when existing contract/regression tests are preserved and actual results recorded; reusable API and v2 schema are tested; initial effects and rule mapping work; real offline demo and stdin function; initial runtime cases execute with actual evidence; no security invariant regresses. Run locked workspace tests and full benchmark on final code, plus contract validation. Update documentation statuses only for observed capabilities.

Return exact baseline/final commit, changed files, commands/results, benchmark denominators, actual demo output, runtime tool versions and evidence, unresolved limitations, gate status, and suggested Phase 2 scope. Do not tag or announce 0.1.0.
