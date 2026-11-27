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

Typed effects and detailed per-rule scope catalogues remain open Phase 1 work.
