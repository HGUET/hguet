# Benchmark triage log

First full run of the 60 scenarios against `hguet` (debug build, commit `390a889`): **41 PASS / 19 FAIL**.
Every failure was classified as a framework/scenario error or an HGUET defect. Labels were never
changed to match the tool; what changed is listed here so the result is not circular.

## Corrections to the benchmark itself (15 of the 19 first-run failures were runner/scenario errors; 4 are HGUET defects)

| Symptom | Cause | Fix |
|---------|-------|-----|
| 11 scenarios `ERROR` (rc 40, usage text) | `hguet check` requires an `--intent` argument even when none exists (repository CI passes a nonexistent path for the same reason); the runner omitted it | runner passes a path to a nonexistent `absent-intent.json` |
| B-018 expected DENY, got UNKNOWN | **scenario bug**: the scoped authority was the fee payer, hence a required signer; the case was not actually "authority is not a signer" | authority is now an account that never signs (label unchanged: BAD) |
| U-009 (hidden behind the usage error, then) got DENY | **scenario bug**: the custom program was a static key, so the allowlist was legitimately violated; the intent ("program only behind an unresolved lookup") was not built | builder gained `alt:N` program references; the program now lives in the lookup table (label unchanged: UNKNOWN) |
| U-010..U-012 UNKNOWN but "wrong reason" | **vocabulary gap**: HGUET reports `RPC_TRANSPORT_FAILURE`, which was missing from the "RPC unavailable" finding family | family extended; semantics unchanged (decision UNKNOWN was already correct) |
| (preventive) | builder vs parser trust | runner compares the tool's `message_sha256` with the builder's; mismatch -> `scenario_builder_error` (0 occurrences after fixes) |

## HGUET defects found (current: 56 PASS, 4 XFAIL, 0 FAIL)

| ID | Scenarios | Finding | Severity | Notes |
|----|-----------|---------|----------|-------|
| HG-BENCH-001 | B-014, B-015 | Token-account ownership transfer (`SetAuthority`) and `CloseAccount` sweep to an attacker under a payment intent return **UNKNOWN**, not DENY. The threat *is* surfaced (`WIRE_TOKEN_DIRECT_AUTHORITY_RISK`, high). | medium | Signing is blocked regardless (BLOCK-only). Making this a hard DENY tightens policy; needs a product decision, so it is documented, not changed. |
| HG-BENCH-002 | U-004, U-013 | Conditions HGUET *cannot verify* (unresolved ALT with a valid intent; multisig-style extra accounts under source caps) are returned as **DENY via `INTENT_REJECTED`**. `verdict-schema.md` reserves DENY for definitive violations and lists unresolved ALT as a coverage gap (UNKNOWN). | medium | Conflates UNKNOWN with DENY. Fail-closed is defensible for a signer, but the verdict then overstates knowledge. Loosening DENY->UNKNOWN is a security-semantics change and was not made here. |

Observations that are not failing scenarios:

* `ALLOW` is unreachable offline (`signing_boundary` blocks reasons, no code path emits it): all 20 GOOD
  scenarios resolve to UNKNOWN. False-block rate is 0/20 but **0/20 are positively cleared**.
* `check --offline` demands `--intent` even for policy-only checks (usability).
* Out of reach of a CLI-level benchmark: successful RPC simulation (HTTPS-only, WebPKI roots; mocking it
  would require weakening TLS verification) and any Cloud behaviour (not implemented in the CLI).

## Current metrics (numerator/denominator)

```
False blocks on GOOD                     0/20
GOOD resolved to ALLOW                   0/20   (structurally unreachable offline)
GOOD left UNKNOWN                        20/20
BAD denied                               23/25  (all 23 with the required finding family)
BAD answered UNKNOWN (blocked only)       2/25  (B-014, B-015)
BAD allowed (unsafe)                      0/25
UNKNOWN kept UNKNOWN with reason         13/15
UNKNOWN overclaimed as DENY               2/15  (U-004, U-013)
Signing blocked invariants               60/60
CLI errors                                0/60
Mock Cloud reference rules                6/6   (model only; not evidence about a real server)
```
