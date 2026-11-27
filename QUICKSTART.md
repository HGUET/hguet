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

Use a bounded file or stdin (-) for inspect/check (16,384 encoded bytes maximum). Use binary, base64 or base58 explicitly. The network label is caller-supplied offline; it does not prove cluster state. Independently control policy paths and pinned issuer keys.

Optional RPC (only with authorized input; discloses bytes to the chosen provider):

```sh
cargo run --locked -p hguet -- check TX.bin --mode local --network devnet --intent SIGNED.json --trusted-key PINNED_KEY --rpc-url https://api.devnet.solana.com --json
```

Replace placeholders with independently obtained input. RPC simulation uses a replacement blockhash and disables provider signature verification; local signature checks are separate. A successful simulation is not execution proof. Transaction verdicts may return 20 (DENY) or 30 (UNKNOWN). Help and policy syntax validation have their own status codes and do not imply signing permission.

Current limitations: JSON v1 default, optional report v2 and text output, no public released binaries, no autonomous signing, no finalized audit, no released x402 verifier. See [roadmap](docs/release/community-0.1.0/ROADMAP.md), [implementation](docs/implementation/README.md), [limitations](LIMITATIONS.md).

## Current developer preview

```sh
cargo run --locked -p hguet -- demo
cargo run --locked -p hguet -- doctor --json
cargo run --locked -p hguet -- inspect tests/fixtures/v1-system-transfer.base64 --encoding base64 --offline --report-v2
cat tests/fixtures/v1-system-transfer.base64 | cargo run --locked -p hguet -- inspect - --offline --encoding base64 --text
```

The demo uses actual synthetic analysis, not a signing grant. Use [Phase 1.1 acceptance](docs/release/community-0.1.0/PHASE_01_1.md) for verification status.

## Program Intelligence preview (Phase 2.0)

```sh
cargo run --locked -p hguet -- programs tests/fixtures/v1-system-transfer.base64 --encoding base64 --offline
```

Separate offline declaration inventory; no verdict or signing permission. See [contract](protocol/programs/v1/README.md).

## Asset Flow preview (Phase 2.1)

```sh
cargo run --locked -p hguet -- flow tests/fixtures/v1-system-transfer.base64 --encoding base64 --offline
```

This offline preview groups raw, declared quantities by SOL or exact token program and mint. It reports supply changes separately and leaves actual fees and net changes unknown. See [flow contract](protocol/flow/v1/README.md).

## Explicit RPC asset-flow correlation (developer preview)

```sh
hguet flow-rpc transaction.bin --network devnet --rpc-url https://YOUR_RPC
```

This sends the original transaction bytes to the explicitly selected provider for simulation, with signature verification disabled and recent blockhash replacement enabled. It can also request lookup, mint and token-account state from that provider. It does not broadcast. Use the offline flow command if you do not want to disclose transaction bytes. See [RPC flow contract](protocol/flow-rpc/v1/README.md).
