# First Rust implementation slice — unreleased

This is a **working offline wire-format prototype**, not a security-ready Solana policy agent and **not** a released version.

Run:
```sh
cargo test --workspace
cargo run -p hguet -- --help
cargo run -p hguet -- inspect transaction.bin --offline --json
cargo run -p hguet -- check transaction.bin --network devnet --mode local \
  --intent signed-intent.json --trusted-key PINNED_PUBKEY --json
```

The `inspect` command parses **legacy and v0** Solana wire structure with strict size/index/bound checks. Address Lookup Table addresses are **not resolved**. `v1` wire transactions have a different layout and are explicitly **UNSUPPORTED** (UNKNOWN). No wallet signing, remote simulation, transaction-signature verification, token effects or Cloud calls are implemented.

`check` verifies **Ed25519 signed payment intent** using a separately configured trusted public key. Signed message = ASCII `HGUET-PAYMENT-INTENT`, one zero byte, and the exact UTF-8 JSON bytes contained inside the Base64 `payload_b64`; it is intentionally NOT reserialized before checking the signature. This prevents JSON formatting ambiguity. After strict signature verification, the payload must bind the parsed **Solana message SHA-256**, network and validity window.

**Important:** The prototype does not compute actual transfer lamports, simulate transaction effects, or apply the signed `max_spend_lamports` to decoded instruction effects. Therefore even a valid signed intent yields **UNKNOWN**, never ALLOW. A malformed transaction or invalid intent yields **DENY** (or CLI input error) and cannot authorize spending. The caller's signer still owns enforcement.

`SecurityVerdict` is returned as `{"inspection":..., "verdict":...}`; the JSON Schema validates **the nested `verdict` object**. CLI exit code `30` means UNKNOWN for `check`, `20` DENY, `40` malformed input; successful informational `inspect` returns `0` but does not imply security approval.

Canonical public contracts:
- [PaymentIntent](../../protocol/v1/payment-intent.schema.json)
- [Signed intent envelope](../../protocol/v1/signed-payment-intent.schema.json)
- [Final SecurityVerdict](../../protocol/v1/security-verdict.schema.json)
- [Cloud and SOL quote contracts](../../protocol/v1/README.md)

## Planned default Cloud server (configured, not active)

The CLI has a compile-time **default future Cloud endpoint** `vps-d0669a91.vps.ovh.net:443` (authenticated TLS 1.3 + Protobuf/TCP, **NOT SSH**). View this setting without making any network request:

```sh
cargo run -p hguet -- config show --json
```

The result explicitly reports `cloud.available=false`. `--mode cloud` is still refused: no actual Cloud transport, TLS trust validation, paid check or SOL transfer is implemented. The SSH operator user `debian@` must never be copied into this public endpoint; no private keys, server certs or payment receiver secrets are in this repository. The hostname alone is not proof of server identity.

No customer seed keys, real SOL invoice address or active Cloud endpoint is used.
