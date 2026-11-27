# Analysis Report v2

Use `--report-v2` with `inspect` or `check`. Default output remains JSON v1.
Exit codes are preserved. The schema is `analysis-report.schema.json`.

Structural validity covers successful original-wire parsing. Signature status
is reported separately. Policy compliance describes configured local
restrictions on original-wire declarations. MATCH means those restrictions
were evaluated without violations or unresolved policy findings.
It provides no execution or total-spending guarantee.

Coverage entries conservatively remain PARTIAL. Findings retain v1 codes,
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
