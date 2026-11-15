# HGUET CLI → private Server: public contract change notice

**Status:** historical request recorded during development; public `HGUET/hguet` owns the wire contract and private `HGUET/server` consumes an exact pin. The current state is tracked in [server compatibility](../architecture/server-compatibility.md). This notice does **not** authorize any production infrastructure changes.

The CLI now has a **read-only, explicit opt-in** `hguet-rpc` module, including network-genesis verification, v0 address lookup table account validation and Solana `simulateTransaction` evidence.

## Compatibility impact

The public [`protocol/v1/security-verdict.schema.json`](../../protocol/v1/security-verdict.schema.json) has a **backward-compatible enum extension** to `simulation_status`:

- `not_performed` — no RPC request made (existing value)
- `rpc_succeeded` — a selected Solana RPC returned a simulation with `err=null`, advisory only
- `rpc_failed` — selected RPC returned a simulation with non-null `err`
- `rpc_unavailable` — HTTPS/genesis/RPC/error/response mismatch; not a security verdict

All four **still yield `SecurityVerdict.decision=UNKNOWN`** unless a stronger independent local hard DENY exists. Server has no authority to sign or override the final CLI verdict.

The optional `rpc_analysis` object is **local CLI output** wrapping `SecurityVerdict`; it is not a new Protobuf Cloud message and must **not** be mistaken for a trusted server `CloudAssessment`. Address lookup keys are evidence from a user-chosen, single Solana RPC at a context slot; neither network consensus nor guaranteed future execution.

**Current public JSON schema Git blob SHA (at notice creation):**
`53df73d2ea67a3a0f5d8cab61f28571eb716f374`.

## Requested action by private Server

1. Read this notice and the public schema **only**; leave public CLI implementation untouched.
2. Compare the private `docs/architecture/public-contract.lock.json` against the reviewed public revision. **At the time of this historic notice**, the private pin was `0606d5f2549a7a55a0fce24d6ebdf65bb713e598`; **as of 2026-11-15** it is `b60c4d5e403946070b3f189dec3bf56ad18efd56`. Do not use this older instruction as the current lock status.
3. When appropriate, **update the private pin and workflow together** to the exact tested public commit, including changed schema blob SHA, and run protocol compatibility CI. Do not silently loosen unrelated price/receipt schemas or invent new wire messages.
4. Continue the independently assigned private Rust backend and Devnet/Sandbox work; no real Mainnet SOL, no public 443 without security gates.

Do not describe public HEAD changes as verified against the server's pinned contract until corresponding reviewed blobs and tests agree. Public green CI alone does not demonstrate paid-client/server interoperability. The CLI Cloud function remains disabled.
