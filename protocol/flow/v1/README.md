# Asset Flow v1 — developer preview

Run `hguet flow FILE --offline [--encoding binary|base64|base58] [--json]`.
Bounded stdin (-) accepted. Exit 0 means the inventory was produced, not that
the transaction is safe; exit 40 gives a versioned hguet_flow_error. No network,
Cloud, keys, signing or broadcasting. Existing analysis v1/v2 unchanged.

The original-wire view emits one edge per decoded quantity declaration. Account
endpoints retain original message indices and nullable static addresses.
Mint/burn use a null supply-side endpoint; no invented account. Totals group
only SOL or a declared exact token program/mint pair. Unchecked transfers
retain individual edges but are excluded from grouped totals. Amounts and
totals are decimal strings, aggregated with u128. Different declared decimals
for the same mint/program produce a conflict marker; no display conversion.

Debit is the sum of decoded transfer, funding, nonce withdrawal and burn
declarations, not wallet-specific gross spending. Mint does not count as a
debit. Repeated and self transfers are not netted. Expected transfer fees are
part of the transfer amount, separately annotated, never added to debit.
Expected fee total only includes instructions with a declared fee and is not
actual network or token fee. Zero category subtotal means no decoded quantity
in that category. Unquantified instructions, unknown assets and unresolved
endpoints have separate index lists. No inference of total execution effects,
rent, hooks, actual fees or net changes.

The embedded program report is the evidence source; each edge's JSON Pointer
resolves to its instruction. The schema references the existing program
schema by logical identifier urn:hguet:programs:v1. Register the local
`protocol/programs/v1/report.schema.json` under that identifier before
validating (no network resolution). See `testing/runtime/flow_preview.py`.

This is only the first offline slice of Phase 2.1. Existing RPC analysis remains
separate. CPI/net/state correlation, richer authority reports and historical
execution analysis are pending. No public release or independent audit claimed.
