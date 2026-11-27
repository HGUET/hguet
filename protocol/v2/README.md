# Analysis Report v2

Use `--report-v2` with `inspect` or `check`. Default output remains JSON v1.
Exit codes are preserved. The schema is `analysis-report.schema.json`.

Structural validity covers successful original-wire parsing. Signature status
is reported separately. Policy compliance describes configured local
restrictions on original-wire declarations. MATCH means those restrictions
were evaluated without violations or unresolved policy findings.
It provides no execution or total-spending guarantee.

Inherited v1 coverage entries conservatively remain PARTIAL. Explicit
checks distinguish original-wire structural validation, supplied Ed25519
signatures and whole-transaction execution effects. COMPLETE applies only
to the named structure/signature check. Unsigned or partial signatures remain
PARTIAL; unavailable checks and full execution effects remain UNSUPPORTED.
Findings retain v1 codes,
stable `HGUET.<code>` identifiers and JSON-pointer evidence references.
RPC source and slot fields remain in embedded v1 evidence.
Signing authorization is always NOT_AUTHORIZED.

The effects array uses the existing original-wire decoders for native transfers,
checked token transfers and burns, approvals, authority changes and account
closures. Unknown instructions retain their index and explicit limitations.
Raw amounts are decimal strings. Authority/delegate roles describe declarations.
RPC CPI and net-balance observations remain separately attributed in evidence.
They are never added to the original-wire effect amounts.

Finding scopes identify policy declarations, wire instructions, signature checks
or advisory RPC observations where the existing code provides that distinction.
Detailed per-rule catalogues and runtime validation remain open Phase 1 work.

rules.json now contains 125 rules spanning local policy, intent trust,
signature/wire checks, direct tokens, RPC CPI, Token-2022 extension
observations, later mint/token-account snapshots, aggregate spending,
source authority, CPI source coverage and effect correlation. Its status is
engine_emission_inventory_with_regression_gaps. Other codes retain stable identifiers
and conservative generic scopes pending individual catalogue review.

RPC catalogue entries name provider observations as their evidence and
preserve non-atomic account-state limitations. Family-level reporting tests
are distinguished from individually reviewed rule assertions.

Run `python scripts/validate_rule_catalogue.py` to check unique identities,
source definitions and referenced regression tests and benchmark fixtures.
The report tests also compare catalogue scopes with the emitted scopes.
Fixture references identify existing synthetic cases. Their presence does
not imply independent ground-truth review.


The validator also inventories emitted engine finding codes missing individual
catalogue entries. The current checkpoint reports zero uncatalogued engine emission codes and
3 entries with targeted regression references still open. Family-level
references also require individual assertion review. It prints these as OPEN;
a successful reference check does not mean complete catalogue coverage.
Aggregate and correlation entries preserve the distinction between original
wire, provider-reported CPI, net changes and later snapshots. A repeated
observation across views never becomes an additional claimed debit.

Signed-cap pipeline regressions use existing signed token/source fixtures.
Equal caps retain partial coverage, a one-unit mint or source overage is
rejected before RPC, and omission of both cap fields emits the explicit
unspecified-token-cap finding. The later TOKEN_CAP_INVALID and
SOURCE_SCOPE_INVALID branches repeat verification already performed during
intent acceptance; their targeted reachability remains open. No guard was
weakened to force those paths.

RPC pipeline regressions distinguish an absent token post-balance from a
zero token loss. The fake provider supplies explicit missing-account results
for optional state reads. A CPI program outside the signed allowlist emits
an advisory finding; the allowed program variant does not. Neither changes
the UNKNOWN result or signing refusal.

Additional signed-source and CPI-source read regressions inject both transport
failure and malformed response payloads. They assert that the actual read
was attempted, the specific unavailable finding is emitted, UNKNOWN and
signing refusal persist, and previously verified signed source scope remains
verified and explicitly partial.

The original-wire token decoder bound has a paired pipeline regression. A
structurally accepted Token instruction with 600 data bytes exceeds the
bounded semantic decoder and emits WIRE_TOKEN_DIRECT_DECODER_UNAVAILABLE.
A normal checked transfer does not. The oversized case remains UNKNOWN and
never authorizes signing. Fixture token-oversized-instruction.base64 was
generated with Solders 0.29.0 Message.new_with_blockhash and
Transaction.new_unsigned: payer bytes [7; 32], Token program, one writable
signer payer account, data [255; 600], and the default blockhash. It contains
no private key or live transaction.

Reachability checks for aggregate failures now have paired CLI regressions.
Duplicate static account keys are rejected as MALFORMED_TRANSACTION (exit 40)
before the RPC transport is called. A provider changing the mint identity of
one token account between pre/post balances is rejected as RPC_RESPONSE_INVALID
(exit 30) before aggregate analysis. Distinct wire accounts and stable mint
identities do produce an aggregate object, while signing remains blocked.
These tests exercise earlier guards; they do not cover or close the later
RPC_AGGREGATE_TOKEN_ANALYSIS_INVALID finding. That targeted regression remains
open. The checks intentionally use the existing parser and RPC validation.

### Remaining defensive finding reachability

The following is a source review plus selected regressions, not a formal
unreachability proof or a waiver of the five targeted regression gaps.

| Finding | Earlier constraint / current evidence | Remaining work |
| --- | --- | --- |
| SIGNED_INTENT_TOKEN_CAP_INVALID | `verify_intent_detailed` invokes the same deterministic token-limit review on the same parsed wire and signed limits before populating `verified_intent`; coverage failures also leave that path. Existing equal/over-cap pipeline tests exercise acceptance and early rejection. | Prove the invariant across all review return paths or find a counterexample; the later error branch has not been exercised. |
| SIGNED_INTENT_SOURCE_SCOPE_INVALID | The same source-limit review runs during independent intent verification before its CLI recomputation. Existing source-cap overage tests reject before RPC. | Review all source-review failure/coverage paths; no direct emission fixture yet. |
| RPC_SOURCE_AUTHORITY_EVIDENCE_INVALID | Snapshot constructors validate slot floors, sizes, state/address binding and unique accounts; the supplemental signed-source read excludes already observed addresses. | Check constructor/correlator invariants, including cross-program signed sources and state decoding; no direct emission fixture yet. |
| RPC_CPI_SOURCE_CORRELATION_INVALID | CPI decoding bounds and assigns parent/inner indices; snapshot constructors validate slots/state and exclude existing addresses. The 512/513 pipeline test confirms the shared item boundary. | Review all source-claim operations and snapshot combinations; no direct emission fixture yet. |
| RPC_AGGREGATE_TOKEN_ANALYSIS_INVALID | Wire parsing rejects duplicate keys and more than 64 instructions; CPI parsing rejects duplicate parent groups and more than 512 items; token snapshots reject conflicting mint/owner identity. Guard regressions cover duplicate keys and changed mint identity. | Review aggregate-only checks against every upstream constructor; no direct emission fixture yet. |

`cpi_item_limit_is_enforced_before_source_correlation_and_aggregation` uses
512 compiled checked-transfer CPI declarations with one source and one mint.
It asserts 512 correlation entries and an advisory CPI view of 512 raw units,
without claiming executed spending. At 513 items RPC_RESPONSE_INVALID is
emitted, the CPI account read is not attempted and no aggregate is returned.
Both cases remain UNKNOWN and signing is blocked. No decoder, trust or
correlation guard was relaxed to construct these tests.

The cross-program CPI regression pairs two same-program declarations with
a SPL Token / Token-2022 pair naming the same source. Same-program claims
perform one supplementary read and retain missing-account observations.
Conflicting program identities emit RPC_CPI_SOURCE_READ_UNAVAILABLE before
request id 7 is sent. Both claims retain unobserved authority and no owner;
the two raw units remain only an advisory CPI declaration view, with gross
spending unproven and signing blocked. This exercises the missing-address
constructor guard, not RPC_CPI_SOURCE_CORRELATION_INVALID.

### RPC observation coverage

Four named checks distinguish provider CPI declarations, native account net
changes, token account net changes and later non-atomic account state.
Available observations remain PARTIAL; unavailable views are UNSUPPORTED.
A recorded empty list is an available observation, with explicit limitations;
it never establishes zero spending or complete execution. Incomplete token
balance pairs remain partial evidence. Each later snapshot retains its own
source and slot in embedded evidence. No RPC observation receives COMPLETE.
These entries are additive to v2 coverage; the v1 evidence and exit contract
are preserved.

Catalogue discovery also covers dynamically forwarded RpcError codes and
account-control scope findings from hguet-core. Missing emitted-code entries
now fail validation. Signing-boundary reason strings remain a separate
contract. The fourteen additional entries document their actual scope and
limits; RPC typed-error injection verifies code forwarding and refusal,
without claiming to reproduce every underlying transport failure cause.

The Rust CI workflow runs the catalogue validator and its mutation regressions.
Tests reject missing dynamic/direct codes, duplicate rules, broken test
references, unrecorded regression gaps and source paths outside the repository.
Catalogue fixture references use forward slashes for both Linux and Windows;
portable-path checks prevent Windows-generated separators breaking Linux CI.
The five declared targeted regression gaps remain visible in successful output.

### Reusing verified intent reviews

The additive Rust API `verify_intent_with_reviews` returns the verified payload
and the exact mint/source declaration reviews performed during verification.
`verify_intent` and `verify_intent_detailed` keep their existing return types.
CLI reporting consumes those reviews instead of recomputing them. Failure
precedence, signed constraint checks and v1 finding text are preserved.
SIGNED_INTENT_TOKEN_CAP_INVALID and SIGNED_INTENT_SOURCE_SCOPE_INVALID are
historical, no longer emitted: both previously described failure of a second
identical deterministic check after the first had succeeded. They remain in
the catalogue with RETIRED_REDUNDANT_CHECK and historical_not_emitted lifecycle.
Tests compare retained reviews with the bounded check results and confirm
mint/source overages still reject during verification. Three RPC defensive
finding regression gaps remain open. The earlier reachability table describes
the pre-refactor investigation; it does not override these lifecycle statuses.
