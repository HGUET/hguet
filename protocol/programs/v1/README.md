# Program intelligence v1 — developer preview

Separate additive report, not a change to the existing analysis report v1/v2.
Run `hguet programs FILE --offline [--encoding binary|base64|base58] [--json]`.
Bounded stdin (-) is accepted. No RPC, policy verdict, signing or broadcasting.
Exit 0 means the inventory was produced, not that instructions execute safely.
Exit 40 emits a versioned hguet_program_error JSON object.

One row per original compiled top-level instruction. Static program IDs and
account indices are taken from the wire; lookup addresses remain null.
Layout status DECODED_DECLARATION means only supported shape/fields, not
runtime acceptance. Unsupported or unresolved data remains explicit.
Compute Budget accepts exact tags 1–4 with canonical widths; no effective
fee calculation. For v1, inline resource_config is separate from instruction
declarations. Memo content is intentionally omitted (only UTF-8 validity
and byte length). ATA create/create-idempotent accepts only six-account
layouts, records declared roles and static System/Token program match;
does not validate PDA, rent, actual account ownership or privileges.
System native movement reuses existing core parsing, including movement
subtypes; no total spending inference. SPL Token/Token-2022/ALT identities
are recognized, but the new inventory does not yet decode their instructions.
Existing report v1/v2 behavior is unchanged.

References:
- https://solana.com/docs/core/fees/compute-budget
- https://github.com/solana-program/memo
- https://github.com/solana-foundation/solana-go/blob/main/programs/associated-token-account/Create.go

Initial unit tests cover exact compute declarations and malformed lengths,
plus the existing System fixture. Independent SDK/runtime checks are required
before Phase 2.0 acceptance. No claim of live compatibility or a release.

The separate [JSON Schema](report.schema.json) covers both success and error envelopes. The independent SDK test script `testing/runtime/programs_preview.py` checks five cases, including actual LiteSVM execution of Compute Budget and Memo, ATA declared roles, unknown/malformed layouts and invalid transaction input. It runs in a network-isolated hosted workflow. ATA runtime execution is not claimed by this slice.
