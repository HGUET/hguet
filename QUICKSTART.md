# Quick start — current source, pre-alpha

Use the repository's pinned Rust toolchain and Cargo.lock. No wallet or Cloud account is needed.

```sh
cargo build --locked -p hguet
cargo run --locked -p hguet -- --help
cargo run --locked -p hguet -- inspect tests/fixtures/legacy-noop.base64 --encoding base64 --offline --json
cargo run --locked -p hguet -- inspect tests/fixtures/v1-system-transfer.base64 --encoding base64 --offline --json
cargo run --locked -p hguet -- policy validate tests/fixtures/policy-devnet-deny.toml --json
cargo run --locked -p hguet -- check tests/fixtures/legacy-noop.base64 --encoding base64 --mode local --network devnet --policy tests/fixtures/policy-devnet-deny.toml --json
```

Use a bounded file (stdin is not yet supported for inspect/check). Use binary, base64 or base58 explicitly. The network label is caller-supplied offline; it does not prove cluster state. Independently control policy paths and pinned issuer keys.

Optional RPC (only with authorized input; discloses bytes to the chosen provider):

```sh
cargo run --locked -p hguet -- check TX.bin --mode local --network devnet --intent SIGNED.json --trusted-key PINNED_KEY --rpc-url https://api.devnet.solana.com --json
```

Replace placeholders with independently obtained input. RPC simulation uses a replacement blockhash and disables provider signature verification; local signature checks are separate. A successful simulation is not execution proof. Transaction verdicts may return 20 (DENY) or 30 (UNKNOWN). Help and policy syntax validation have their own status codes and do not imply signing permission.

Current limitations: JSON output, no primary stdin input, no public released binaries, no autonomous signing, no finalized audit, no released x402 verifier. See [roadmap](docs/release/community-0.1.0/ROADMAP.md), [implementation](docs/implementation/README.md), [limitations](LIMITATIONS.md).
