<div align="center">

# HGUET

### Secure the intent. Verify the transaction.

**Open-source security checks for AI-agent payments on Solana.**

[![Project stage](https://img.shields.io/badge/stage-early%20development-7C3AED?style=flat-square)](#project-status)
[![Platform](https://img.shields.io/badge/network-Solana-14F195?style=flat-square)](#what-were-building)
[![Language](https://img.shields.io/badge/stack-Rust-00C2B8?style=flat-square)](#architecture)
[![Cloud](https://img.shields.io/badge/cloud-optional-B967FF?style=flat-square)](#two-modes)

[**Website**](https://hguet.fr) · [**Architecture**](#architecture) · [**Roadmap**](#roadmap) · [**Security principles**](#security-principles)

</div>

---

> [!IMPORTANT]
> **Project status — early development.** HGUET is being designed and built. The functionality and commands described below are **planned**, not a released or audited security product. Do not rely on this repository to protect live funds yet.

## Why HGUET?

A Solana transaction can simulate successfully and still be **the wrong payment**.

Autonomous agents need a practical way to verify **what will happen**, **whether the intended payment matches the transaction**, and **which risks or unknowns remain** — *before anyone signs or broadcasts*.

**HGUET is designed to make those checks a normal part of an agent's workflow.**

## What we're building

| Free local security checks | Optional HGUET Intelligence Cloud |
| --- | --- |
| Decode Solana transactions and instructions | Fresh threat and incident signals |
| RPC simulation and balance-change inspection | Multi-source network health and correlation |
| Trusted payment-intent validation | Reputation and change monitoring for programs |
| Local policy and spending checks | Cross-session agent payment behavior |
| x402 / MPP payment safety checks | Enriched, signed security reports |
| Stable JSON verdicts for automation | Paid, usage-based intelligence |

The CLI will remain useful **without a HGUET account**. Local checks use the user's configured Solana RPC. Cloud intelligence is opt-in.

## The intended workflow

```text
AI Agent / Solana payment tool
            |
            v
      HGUET CLI (Rust)
            |
      +-----+------+
      |            |
      v            v
 Local checks   Optional HGUET Cloud
      |            |
      +-----+------+
            |
            v
    ALLOW / WARN / DENY / UNKNOWN
            |
            v
  Customer-controlled signing
```

### Proposed CLI interface

```bash
# Planned interface — not yet implemented
hguet check transaction.bin --intent payment-intent.json --json
hguet check transaction.bin --cloud --json
hguet doctor
```

HGUET is **not a wallet**. It does not take custody of assets, request private keys, sign transactions, or broadcast payments.

## Security principles

- **No false guarantees:** a successful simulation is a snapshot, not proof that final execution will be safe.
- **Trust the instruction boundary:** payment intent must come from a trusted source, not solely from untrusted agent-generated text.
- **Make uncertainty visible:** missing data or stale RPC state should not silently become `ALLOW`.
- **Keep control with the customer:** checks are advisory unless the customer's signer enforces them.
- **Security through review:** the free CLI, check semantics, and verdict format are designed to be inspectable.
- **Private by default:** no wallet secret keys, and no hidden cloud requests in local mode.

## Architecture

Two repositories, one product:

| Repository | Visibility | Responsibility |
| --- | --- | --- |
| **[HGUET/hguet](https://github.com/HGUET/hguet)** | Public | Rust CLI, local checks, public protocol, tests, integrations |
| **HGUET/server** | Private | Threat intelligence, network monitoring, accounts, billing, advanced risk analysis |

The planned commercial transport is authenticated post-quantum-capable TLS 1.3, built from maintained cryptographic libraries, **not a custom cipher or VPN**. Exact algorithms and mutual authentication must pass implementation and interoperability tests before any security claims.

### Unified CLI ↔ Cloud contract

**[Interoperability contract](docs/architecture/interoperability.md)** · [Public draft Protobuf wire schema](protocol/v1/hguet.proto) · [Signed CloudAssessment JSON schema](protocol/v1/cloud-assessment.schema.json) · [Conformance cases](protocol/v1/contract-cases.json)

**Trust boundary:** Cloud signs only its own assessment and billing receipt; the CLI independently verifies them and composes the final SecurityVerdict. Server-side intelligence cannot override a local hard DENY. Public protocol files are a **draft**, not released endpoints.

## Current Cloud direction — unreleased design

> **Release status:** No HGUET releases have been published. Documentation describes the current design proposal; numbers in `protocol/v1` are internal wire-schema identifiers, not product versions.

**No registration, no balances, no USDC.** HGUET's optional Cloud is designed as **one security check paid directly in native SOL**, quoted in USD using a cached current-day SOL/USD reference (approximately ±5% tolerance in the market reference, **exact lamports in the signed invoice**). A Basic metadata check has a **proposed** USD reference price of $0.001; more instructions, accounts, sources and computational depth increase the pre-agreed quoted price. Pricing is a draft, not a live offer.

- [Complexity-based pricing policy](docs/architecture/pricing-policy.md)
- [Anonymous SOL payment flow](docs/architecture/payment-per-request.md)
- [Public accountless protocol draft](protocol/v1/README.md)

### CLI architecture — design documents

The full Rust CLI specification is published in **[docs/architecture/README.md](docs/architecture/README.md)**. All components below are planned; the codebase is still pre-alpha.

| Document | What it specifies |
| --- | --- |
| [Rust implementation blueprint](docs/architecture/implementation-blueprint.md) | Crate boundaries, typed interfaces, pipeline and build plan |
| [CLI commands & configuration](docs/architecture/cli-interface.md) | Command syntax, output, registration, SOL-only payment, local state |
| [Solana engine](docs/architecture/solana-engine.md) | Legacy/v0/v1, ALT, CPI, simulation, RPC evidence and failures |
| [Security & threat model](docs/architecture/security.md) | Trusted intent, limits, bypass threats, risk and privacy |
| [Verdict schema](docs/architecture/verdict-schema.md) | JSON contract and ALLOW/WARN/DENY/UNKNOWN decision rules |
| [Cloud transport](docs/architecture/cloud-protocol.md) | PQ TLS, binary protocol, accounts and idempotent billing |
| [Testing and roadmap](docs/architecture/testing-roadmap.md) | Security test matrix, milestones and release criteria |
| [Architecture decisions](docs/architecture/decisions.md) | Chosen and deferred scope |
| [Technical references](docs/architecture/references.md) | Official Solana, payment protocol and cryptography references |

## Roadmap

- [ ] Transaction decoding, Solana simulation, canonical JSON verdict
- [ ] Trusted payment-intent verification and local policies
- [ ] x402 / MPP checks, automation and agent integrations
- [ ] Open adversarial test suite and reproducible benchmark
- [ ] Optional private intelligence-cloud connection
- [ ] Security review, release signing, and documented limitations

## Support HGUET development

HGUET's local security CLI is planned to remain free and open source. If you'd like to support its development, you can send a **voluntary SOL donation** to the Solana address below.

```text
39iqkHNMqncEPp3p52zKwUHnYzk2MJbcaHyY4Hhg2fWC
```

**Network:** Solana mainnet · **Asset:** native SOL · [View address on Solscan](https://solscan.io/account/39iqkHNMqncEPp3p52zKwUHnYzk2MJbcaHyY4Hhg2fWC)

> Donations are voluntary, do not purchase HGUET Cloud credits or services, and are **not** the HGUET Cloud billing/commercial SOL payment address. Check the complete address and network before sending. HGUET never asks you to share wallet private keys.

## Project status

**Pre-alpha.** We're establishing the architecture, threat model, tests and integration boundaries. There is no published stable binary or production SLA.

We welcome thoughtful technical feedback, reproducible test cases, and discussion of Solana agent-payment failure modes. Please do **not** publish live credentials, exploitable secrets or private customer transactions in public issues.

---

<div align="center">

**HGUET** · Built for an agent-driven Solana ecosystem

[Website](https://hguet.fr) · [GitHub Organization](https://github.com/HGUET)

*Security should happen before the signature.*

</div>
