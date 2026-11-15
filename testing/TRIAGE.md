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

---

## Resolution of HG-BENCH-001 and HG-BENCH-002

Baseline `42e631b`: 56 PASS / 4 XFAIL. After the semantic fix: **60 original scenarios 60/60 acceptable
(56 PASS + 4 former XFAIL now XPASS, registry cleared), 0 FAIL**. The original scenarios and their labels were
not edited. Resulting figures on the 60: BAD denied 25/25, BAD merely blocked 0/25, UNKNOWN kept UNKNOWN 15/15,
UNKNOWN overclaimed as DENY 0/15, false blocks on GOOD 0/20, signing-block invariants 60/60.

| Defect | Scenarios | Fix | Result |
|--------|-----------|-----|--------|
| HG-BENCH-001 | B-014, B-015 | `intent_scope::review_account_control` judges `SetAuthority`/`CloseAccount` against the verified intent: third-party target that does not sign -> DENY with `INTENT_SCOPE_*` + evidence refs; signer target / revoke -> UNKNOWN with a structured reason | DENY |
| HG-BENCH-002 | U-004, U-013 | `ReviewFailure`/`IntentFailure` split violation from coverage gap; coverage -> UNKNOWN `INTENT_COVERAGE_INCOMPLETE` + `coverage_gaps`; proven static violations still win over an unresolved ALT or multisig | UNKNOWN |

Regression suite `scenarios-regression/` (23 paired cases) was written to discriminate: against the **old**
binary (`42e631b`) it yields **6 PASS / 17 FAIL** (including 3 false blocks of legitimate Revoke/SyncNative/close-to-self,
and 5 UNKNOWN overclaimed as DENY); against the fixed binary **23/23 PASS**. Rust: 5 new unit tests in
`intent_scope.rs`; 197 workspace tests pass.

### Behaviour changes that loosen DENY (explicit, reviewed)

* Under signed token caps, **administrative** token instructions (Revoke, SyncNative, Initialize*) and
  **unsupported/opaque** opcodes now give UNKNOWN instead of DENY: nothing proves a violation. Known money- or
  control-moving operations that no cap can authorise (Transfer, Approve, MintTo, Burn, Freeze/Thaw) still DENY.
* An unresolved ALT or multisig-style extra accounts alone no longer produce `INTENT_REJECTED`.
* The legacy `verify_intent`/`review_declared_*` API keeps its fail-closed behaviour for every non-debit
  instruction; only the new `*_detailed` functions (used by the CLI) distinguish gaps.
* Signing is unchanged: every path still ends in BLOCK; `signing_blocked` is 83/83.

### Ground-truth review (nothing was edited silently)

No scenario label was shown to be wrong by the fix. One **labelling question** is recorded, not changed:
B-012 (unchecked token `Transfer` under signed mint caps) is labelled BAD/DENY because the cap model only
admits checked forms; a stricter reading could call it UNKNOWN (mint unbound). HGUET keeps DENY; the
label stands until the owner decides the intended contract for unchecked debits.

### Still open (not defects of these two items)

* ALLOW is unreachable offline; `good_left_unknown` stays 20/20 (+3 in regression).
* Approve/delegate to a third party under a **SOL-only** intent is still UNKNOWN (only SetAuthority and
  CloseAccount were in scope here); under token caps it is DENY (B-111).

---

## Code-review findings outside the original benchmark (encoding and instruction-form evasions)

A manual code review, not the benchmark, found that a declared amount could leave every cap without
any scenario failing:

| Finding | Why no scenario caught it | Fix | New regression cases |
|---------|---------------------------|-----|----------------------|
| One trailing byte on a System `Transfer`, `TransferChecked`, `BurnChecked`, `TransferCheckedWithFee` or `SetAuthority` made the instruction unrecognised (decoders required exact lengths): DENY became UNKNOWN, the SOL total read 0 and recipient lists were skipped | every scenario was built by `crypto_tx.py` with canonical encodings only | decoders read the prefix and treat lengths as minimums | B-113, B-114, B-115, B-119, G-105 |
| `CreateAccount`, `CreateAccountWithSeed`, `WithdrawNonceAccount` and `TransferWithSeed` name an explicit lamport amount but were not counted | U-015 labelled an over-cap `CreateAccount` UNKNOWN | all five forms are counted in `declared_system_transfer_lamports` and `system_transfers` (new `kind` field) | B-116, B-117, B-118, B-120, U-111 |

### Ground-truth correction (explicit, not silent)

**U-015 was mislabelled.** It funded a new account with 2,000,000 lamports under a signed cap of 5000
and was labelled UNKNOWN with the rationale "total spend is unprovable offline". The amount is explicit
in the instruction data, so that transaction is a proven overage, the same class as B-001. The scenario
keeps its id, label and instruction; its signed cap is now 5,000,000 so the declared amount is inside
the cap and UNKNOWN is the correct answer. The over-cap case is preserved as regression B-116. The main
suite stays 20/25/15.

Not re-run against the pre-fix binary: only the padded SOL transfer and padded `TransferChecked` cases
were reproduced by hand before the fix (both UNKNOWN then, DENY now).

Also changed: a message that lists the same account key twice is rejected as malformed; a signed
`max_spend_lamports` with a leading `+` is rejected; `check` no longer requires `--intent`; with
`--rpc-url`, an unresolved lookup table no longer stops `check` before the RPC is consulted (the intent
is then advisory only and no limit is reported as enforced).

Current: 60 main + 36 regression = **96/96 PASS**, BAD denied 45/45, false blocks 0/25,
UNKNOWN overclaimed as DENY 0/26.
