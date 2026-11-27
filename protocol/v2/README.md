# Analysis Report v2

Use `--report-v2` with `inspect` or `check`. Default output remains JSON v1.
Exit codes are preserved. The schema is `analysis-report.schema.json`.

Structural validity covers successful original-wire parsing. Signature status
is reported separately. Policy compliance describes configured local
restrictions on original-wire declarations. MATCH means those restrictions
were evaluated without violations or unresolved policy findings.
It provides no execution or total-spending guarantee.

Inherited v1 coverage entries conservatively remain PARTIAL. Three explicit
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

rules.json now contains 111 rules spanning local policy, intent trust,
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
5 entries with targeted regression references still open. Family-level
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
