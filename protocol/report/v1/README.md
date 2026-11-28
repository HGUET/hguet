# Combined Transaction Intelligence v1

Run `hguet report FILE --offline [--encoding binary|base64|base58] [--json|--html]`.
A single original-wire program inventory supplies the standalone flow and
authority views. The nested copies retain existing report contracts; do not
count repeated inventory as independent evidence. Both message digests must
match the root. No RPC, simulation, actual execution or authorization proof.
JSON is default; optional HTML combines asset movements, authority changes,
program inventory and expandable evidence. Exit 0 means the report was
produced, not that signing is approved. Exit 40 is hguet_report_error.

Register local flow, authority and program schemas at their documented URNs
before validating this [schema](report.schema.json). The SDK suite verifies
nested contracts and equality with the independent commands.

## Verified development snapshot

The combined report's nested JSON parity, schema and HTML projection passed in the seven-group HTML SDK/CLI suite. Both views derive from one program decode and do not establish execution or authorization. See [source-attributed verification](../../../docs/release/community-0.1.0/VERIFICATION.md) for d716d60, where full runtime CI remained red on formatting. No complete release or independent security assurance is claimed.
