# Semantic Transaction Diff v1 — developer preview

Run `hguet diff BEFORE AFTER --offline [--encoding binary|base64|base58] [--json]`.
Both inputs use the selected encoding; at most one can be stdin (-). Each input
is bounded. Exit 0 means the comparison was produced, not equivalence or
approval. Exit 40 is hguet_diff_error. No RPC, Cloud, signing or broadcasting.

The relation is IDENTICAL_TRANSACTION_BYTES, IDENTICAL_MESSAGE_BYTES or
MESSAGE_CHANGED, using SHA-256 from the validated original wire. The report
compares fee payer, ordered required signer identities, message account order and
declared signer/writable flags, recent blockhash digest, wire version and inline
resources. Signature status and count are retained separately in each snapshot.
Instruction identities include program, ordered account identities/privileges
and SHA-256 of exact raw instruction bytes (including unknown or memo data).
ALT identity is a table/index/writable reference, not a resolved address.
Fingerprints hash serialized identities, not arbitrary JSON supplied by a caller.
An equal multiset retains duplicate multiplicity; it is not order equality.

Position changes compare decoded declarations and asset/control summaries as
well as the original identity. Insertions/removals can shift positions; no
edit-distance alignment or move identification is claimed. JSON Pointers
reference snapshot instruction rows. Embedded summaries have standalone
report pointers removed. Hashes of low-entropy memo payloads are not privacy
guarantees. A changed message invalidates an exact-message intent binding;
the command does not verify an intent. Identical bytes are never proof of
safety, ownership, effective runtime privileges, state or authorization.
Signing is always NOT_AUTHORIZED. Existing report contracts unchanged.

This is the initial Phase 2.3 slice, not a release. SDK fixtures and full
hosted regression checks are required for acceptance.

The [JSON schema](report.schema.json) validates the diff envelope, snapshots, identity and pointer shapes, and refusal invariants. The nested decoder summaries are intentionally open objects, not exhaustive independent contracts. The SDK suite also checks v1 inline resource changes, exact message and blockhash digests, and lookup references. Compiled indices and the entire lookup declaration list are preserved separately from normalized fingerprints; a remaining unexplained byte change is explicitly classified as unclassified_message_bytes. Measured hosted results are recorded below; broader acceptance remains open.

## Verified development snapshot

All nine Diff SDK/CLI groups passed, including v1 inline resources, opaque data, repeated/reordered instructions and unresolved ALT references. Position alignment and equivalence remain unproved. See [source-attributed verification](../../../docs/release/community-0.1.0/VERIFICATION.md) for d716d60, where full runtime CI remained red on formatting. No complete release or independent security assurance is claimed.
