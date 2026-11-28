# RPC Asset Flow v1 — developer preview

Run `hguet flow-rpc FILE --rpc-url HTTPS_URL --network mainnet|devnet|testnet [--encoding binary|base64|base58] [--json]`.

This command explicitly discloses original transaction bytes to a user-selected HTTPS RPC.
No default endpoint or network. Genesis is verified first. The existing bounded
simulation pipeline uses sigVerify=false and replaceRecentBlockhash=true and may
request lookup, mint and token account state from the same provider. No signing,
broadcasting, Cloud or keys. Use the independent offline `flow` command for privacy.

The new report retains the complete offline wire report and embeds typed
SimulationEvidence. The original message hash is a local binding to the bytes,
not proof that the provider executed those bytes unchanged. The RPC view contains
CPI claims, optional net balance rows, simulated fee, later non-atomic snapshots
and the existing evidence graph. Null metadata is not zero. Failed simulation
observations are not successful execution. Provider failure preserves wire data
with RPC_UNAVAILABLE and a bounded error code. No actual execution is proven.

Endpoint links match wire account index and static address, and for tokens the
declared mint. Token balance rows do not retain program identity; do not infer
a program match. NO_DELTA_ROW and METADATA_ABSENT are distinct. A native delta
row may be absent because unchanged accounts were omitted. No missing amount is
manufactured. CPI links are reported parent instruction relationships for
recognized token instructions and classified extensions; opaque CPI counts
remain in the embedded evidence. Links reference evidence via JSON Pointers.
Several wire edges can point to the same observation. Never add link quantities
or combine wire totals with CPI/net rows. No attribution, reconciliation,
authorization, safe-signing or full spend bound is implied.

Exit 0: provider reports simulation success, not a security verdict.
Exit 30: provider failed simulation or RPC evidence unavailable.
Exit 40: malformed input or configuration, versioned hguet_rpc_flow_error.
Existing analysis and offline flow contracts unchanged.

Tests use an injected transport and real bounded response decoder; no live RPC
or real funds. Actual execution remains validated only in separate local runtime
fixtures. The full Phase 2.1 acceptance is not claimed.

The [JSON schema](report.schema.json) validates the envelope, links, refusal invariants and required RPC evidence fields. Embedded RPC details retain the existing typed evidence shape, not an exhaustive independent schema. Register the local flow and program schemas under their documented URN identifiers. The network-isolated CLI suite validates invalid configuration error envelopes; Rust injected-transport tests check successful/failed report fields, evidence pointers, repeated edges sharing one net row, incomplete token pairs and CPI links. Provider error truncation preserves UTF-8 boundaries. Scoped hosted functional verification is recorded below; whole-phase acceptance remains open.

## Verified development snapshot

The Rust injected-transport tests and the network-isolated CLI configuration checks passed. Live RPC and full program-aware semantic reconciliation remain unverified. See [source-attributed verification](../../../docs/release/community-0.1.0/VERIFICATION.md) for d716d60, where full runtime CI remained red on formatting. No complete release or independent security assurance is claimed.
