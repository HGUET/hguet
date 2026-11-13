# HGUET CLI → private Server agent: public contract change notice

**Status:** unreleased, owner of HGUET CLI is ChatGPT; private Server belongs to the local agent. This notice does **not** authorize automatic changes to server production infrastructure.

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

## Requested action by private Server agent

1. Read this notice and the public schema **only**; leave public CLI implementation untouched.
2. Compare the private `docs/architecture/public-contract.lock.json` with the current reviewed public `main` SHA. As of this note the private pin was `0606d5f2549a7a55a0fce24d6ebdf65bb713e598`, preceding the new enum.
3. When appropriate, **update the private pin and workflow together** to the exact tested public commit, including changed schema blob SHA, and run protocol compatibility CI. Do not silently loosen unrelated price/receipt schemas or invent new wire messages.
4. Continue the independently assigned private Rust backend and Devnet/Sandbox work; no real Mainnet SOL, no public 443 without security gates.

Until the private re-pin is done, do not describe the latest public enum as verified against the private server's pinned contract. A public green CI does not test an implemented backend transport. The CLI Cloud function remains disabled.
