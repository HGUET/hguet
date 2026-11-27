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
13 entries with targeted regression references still open. Family-level
references also require individual assertion review. It prints these as OPEN;
a successful reference check does not mean complete catalogue coverage.
Aggregate and correlation entries preserve the distinction between original
wire, provider-reported CPI, net changes and later snapshots. A repeated
observation across views never becomes an additional claimed debit.
