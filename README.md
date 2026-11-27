<div align="center">

# HGUET

**The open-source security toolkit for Solana transactions and autonomous agents.**

*Security should happen before the signature.*

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](Cargo.toml) [![Status](https://img.shields.io/badge/status-pre--alpha-orange.svg)](#status)

[Website](https://hguet.fr) · [Quick start](QUICKSTART.md) · [Roadmap](docs/release/community-0.1.0/ROADMAP.md) · [Security](SECURITY.md)

</div>

> **Pre-alpha — not yet a released or independently audited security product.** Never use HGUET output as permission to sign or as proof that live funds are safe. The current signing boundary is BLOCK-only.

## Why HGUET?

A transaction can simulate successfully and still violate the user's intent. HGUET examines original Solana transaction bytes, independent restrictions, and optional RPC evidence to explain what is known, what is inconsistent, and what cannot be proven before a customer-controlled signature.

HGUET is built for developers, wallet teams, security researchers and AI-agent payment integrators. The free MIT-licensed toolkit is the primary product: no account, custody, mandatory cloud, license server or hidden telemetry. RPC is opt-in and discloses transaction data to the chosen provider.

## Current implementation

| Capability | Current scope |
| --- | --- |
| Offline transaction inspection | Legacy/v0/v1 wire parser; binary, Base64, Base58; hashes and signature status; v1 runtime compatibility not independently established |
| Signed PaymentIntent | Ed25519 against independently pinned public key, exact message hash, network label, validity window, program and direct debit constraints |
| Local policy | Restrictive SOL cap, program and SOL recipient rules; not total spending enforcement |
| RPC analysis | Explicit HTTPS endpoint, genesis check, ALT and simulation observations; not proof of final execution |
| SPL Token / Token-2022 | Bounded direct/CPI decoding, mint and token-account snapshots, separate debit and net-delta views; partial coverage |
| Effect correlation | Provenance-aware graph and gaps; no guaranteed attribution or total gross spending |
| Signer preflight | Local and isolated experimental refusal boundary; no signing, broadcast or authorization |
| Cloud | Optional loopback Devnet protocol experiments; public paid service unavailable |
| Testing | Open synthetic benchmark, property tests, adversarial RPC tests and CI; real runtime validation remains a release gate |

See [implementation](docs/implementation/README.md), [limitations](LIMITATIONS.md) and [coverage matrix](docs/release/community-0.1.0/COVERAGE_MATRIX.md).

## Quick start — build from source

```sh
cargo build --locked -p hguet
cargo run --locked -p hguet -- --help
cargo run --locked -p hguet -- inspect tests/fixtures/legacy-noop.base64 --encoding base64 --offline --json
cargo run --locked -p hguet -- policy validate tests/fixtures/policy-devnet-deny.toml --json
```

Fixtures are synthetic and use placeholder signatures. Inspection/check decisions can be nonzero (including UNKNOWN); exit code 0 from help or policy syntax validation is not transaction approval. See [Quick start](QUICKSTART.md).

## Community Edition 0.1.0

Phase 1.1 is accepted at the verified source snapshot; Phase 2 development has begun. See the [acceptance record](docs/release/community-0.1.0/PHASE_01_1.md) for source-attributed hosted evidence and remaining gates. No product release or complete security assurance is claimed.

Run `hguet demo` for three synthetic offline cases through the actual engine.
Use `hguet demo --json` for the versioned reports and evidence. The demo
contains an expected 500-lamport declaration, an additional transfer exceeding
the configured cap, and an opaque program requiring UNKNOWN. Every case
refuses signing. No endpoint or credentials are needed.

For transaction reports, use `--text` for terminal output or `--report-v2`
for the new JSON schema. Default JSON v1 and exit codes remain compatible.
`inspect` and `check` also accept `-` for bounded stdin (16384 encoded bytes).
`--text` and `--json` are mutually exclusive. `hguet doctor --json` reports
offline environment capabilities.

Our first public release prioritizes a reusable security engine, scoped findings and coverage, real Solana runtime validation, terminal/JSON/HTML reports, audit and diff, semantic policies, x402 exact SVM verification, Rust and TypeScript integration and an open benchmark.

These are **targets**, not installed commands. No general ALLOW or automatic signing is planned for 0.1.0. MPP and expanded Cloud are deferred.

[Roadmap](docs/release/community-0.1.0/ROADMAP.md) · [Release gates](docs/release/community-0.1.0/RELEASE_GATES.md) · [Phase 1 task](docs/release/community-0.1.0/PHASE_01.md)

## Architecture and contribution

- [Public architecture](docs/architecture/README.md) and [v1 contracts](protocol/v1/README.md).
- [Security benchmark](testing/README.md).
- [Previous detailed status and Cloud usage](docs/implementation/previous-readme.md), retained as a historical snapshot.
- [Contributing](CONTRIBUTING.md) and [security reporting](SECURITY.md).

We welcome independent runtime fixtures, ground-truth review, security analysis and integration examples. Never publish private keys or confidential transactions.

## Status

No public Community Edition release is claimed here. The first release is gated by actual evidence, not the roadmap. Licensed under [MIT](LICENSE).

[Support development](docs/support.md) · [HGUET organization](https://github.com/HGUET) · [hguet.fr](https://hguet.fr)
