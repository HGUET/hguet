# First Rust implementation slice — unreleased

This is a **working offline wire-format prototype**, not a security-ready Solana policy agent and **not** a released version.

Run:
```sh
cargo test --workspace
cargo run -p hguet -- --help
cargo run -p hguet -- inspect transaction.bin --offline --json
cargo run -p hguet -- inspect tests/fixtures/v1-system-transfer.base64 --encoding base64 --offline --json
cargo run -p hguet -- check transaction.bin --network devnet --mode local \
  --intent signed-intent.json --trusted-key PINNED_PUBKEY --json
```

The `inspect` command now parses **legacy, v0 and v1** Solana wire structures using format-specific layouts. The v1 decoder reads its explicit resource config (including the **total** priority fee in lamports), fixed-width instruction headers and trailing signature array. It verifies any **nonzero Ed25519 transaction signatures** against the exact wire message, while accepting zero-filled unsigned placeholders in pre-signature workflows. v0 Address Lookup Table addresses remain **unresolved** until trusted RPC resolution is implemented. The decoder identifies top-level native **System Program Transfer** instructions and their integer lamports as a *lower bound* only. It cannot infer CPI, token movements, non-transfer System operations or the full amount of funds at risk. No RPC simulation, blockhash validity, wallet signing or Cloud calls are implemented.

`check` verifies **Ed25519 signed payment intent** using a separately configured trusted public key. Signed message = ASCII `HGUET-PAYMENT-INTENT`, one zero byte, and the exact UTF-8 JSON bytes contained inside the Base64 `payload_b64`; it is intentionally NOT reserialized before checking the signature. This prevents JSON formatting ambiguity. After strict signature verification, the payload must bind the parsed **Solana message SHA-256**, network and validity window.

**Important:** Signed `max_spend_lamports` is now checked against the **sum of decoded top-level native SOL Transfer instructions**; exceeding that lower bound causes `DENY`. This is not a proof that total spending is within the limit because CPI and other program effects remain unknown. A valid signed intent still yields **UNKNOWN**, never ALLOW. Nonzero invalid Ed25519 signatures cause `DENY` in `check`; missing signatures may be legitimate before signing and remain informational. A malformed transaction or invalid intent is rejected, and the customer-controlled signer retains enforcement responsibility.

`SecurityVerdict` is returned as `{"inspection":..., "verdict":...}`; the JSON Schema validates **the nested `verdict` object**. CLI exit code `30` means UNKNOWN for `check`, `20` DENY, `40` malformed input; successful informational `inspect` returns `0` but does not imply security approval.

Canonical public contracts:
- [PaymentIntent](../../protocol/v1/payment-intent.schema.json)
- [Signed intent envelope](../../protocol/v1/signed-payment-intent.schema.json)
- [Final SecurityVerdict](../../protocol/v1/security-verdict.schema.json)
- [Cloud and SOL quote contracts](../../protocol/v1/README.md)

## Restrictive offline local policies

A separate Rust crate `hguet-policy` implements **restrictive-only** local rules. A policy can forbid programs and direct SOL recipients, constrain the selected Solana network, and cap the sum of **top-level native System transfers**. It **never** authorizes spending or promotes `UNKNOWN` to `ALLOW`. Untested program-internal transfers, CPI, token effects, Solana network fees and v0 ALT addresses remain outside this limited evidence.

Example test policy:

```toml
version = 1
network = "devnet"
max_declared_system_transfer_lamports = "499"

# List Base58 Solana 32-byte public keys, not token labels.
denied_program_ids = []
denied_sol_recipients = []
# Optional positive allowlists: allowed_program_ids = ["..."]
# Optional positive allowlists: allowed_sol_recipients = ["..."]
```

```sh
cargo run -p hguet -- policy validate tests/fixtures/policy-devnet-deny.toml --json
cargo run -p hguet -- check TRANSACTION.bin --mode local --network devnet \
  --intent signed-intent.json --trusted-key PINNED_INTENT_SIGNER \
  --policy /path/to/trusted-user-policy.toml --json
```

The policy file and trusted intent authority must come from **independent user-controlled configuration**, never an AI agent's self-reported permission. A malicious agent could bypass the CLI entirely; the customer's actual wallet/signer still must enforce security decisions. An invalid policy is rejected before use. A matching/empty restrictive policy is **not** evidence of safe execution.

## Opt-in Solana JSON-RPC simulation (implemented first slice)

The public CLI includes `hguet-rpc`, a **read-only** JSON-RPC client. No RPC connection is made by `inspect --offline`, `policy validate`, `config show`, or `check` without `--rpc-url`. There is **no** HGUET Cloud connection in this mode.

```sh
cargo run -p hguet -- check TRANSACTION.bin \
  --mode local --network devnet \
  --intent signed-intent.json --trusted-key PINNED_AUTHORITY \
  --policy /trusted/local-policy.toml \
  --rpc-url https://api.devnet.solana.com --json
```

The selected **external Solana RPC provider will receive the entire serialized transaction**. The operator chooses this explicitly; use a provider acceptable for the transaction's privacy. Do not paste a private RPC URL containing an API token into logs or tickets.

Before simulating, the client validates the HTTPS URL (no embedded credentials, fragments or non-HTTPS schemes), parses the transaction locally, calls `getGenesisHash`, and rejects a mismatch against the known Mainnet/Devnet/Testnet genesis. It then requests `simulateTransaction` with:

```json
{
  "encoding": "base64",
  "commitment": "confirmed",
  "sigVerify": false,
  "replaceRecentBlockhash": true,
  "innerInstructions": true
}
```

**Why `sigVerify=false`?** Simulation with `replaceRecentBlockhash=true` conflicts with signature verification in the RPC API. The local Solana Engine separately verifies nonzero original Ed25519 transaction signatures. Replacement means a successful simulation does **not** certify future execution of the original signed transaction. Public API method: https://solana.com/docs/rpc/http/simulatetransaction.

JSON output includes optional `rpc_analysis`: verified genesis, context slot, simulated message SHA-256, `rpc_succeeded` or `rpc_failed`, compute units and bounded counts of returned logs/inner-instruction groups. Private logs themselves are **not** printed. On RPC error or mismatched network, `simulation_status=rpc_unavailable` plus an explicit reason code is returned in the **UNKNOWN** verdict. Any successful simulation remains `UNKNOWN`, not `ALLOW`; known independent local hard DENY still wins **before** contacting RPC.

The transport sets a response size limit (1 MiB), request size limit, short network timeouts, and **no redirects**. Unit tests inject a mock JSON-RPC transport and cover wrong genesis, malformed responses, conflicting status, success, simulation error, no accidental RPC before offline validation, and mutually compatible blockhash/signature options. Tests do **not** claim live Devnet simulation succeeded.

Still outstanding: **v0 Address Lookup Table resolution**, account-state/balance delta inspection, complete CPI and Token-2022 analysis, RPC multi-provider cross-checks and trusted policy enforcement at the external signer. Until those exist, remote simulation alone cannot justify `ALLOW`.

## Planned default Cloud server (configured, not active)

The CLI has a compile-time **default future Cloud endpoint** `vps-d0669a91.vps.ovh.net:443` (authenticated TLS 1.3 + Protobuf/TCP, **NOT SSH**). View this setting without making any network request:

```sh
cargo run -p hguet -- config show --json
```

The result explicitly reports `cloud.available=false`. `--mode cloud` is still refused: no actual Cloud transport, TLS trust validation, paid check or SOL transfer is implemented. The SSH operator user `debian@` must never be copied into this public endpoint; no private keys, server certs or payment receiver secrets are in this repository. The hostname alone is not proof of server identity.

No customer seed keys, real SOL invoice address or active Cloud endpoint is used.
