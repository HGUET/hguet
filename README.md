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

### Detailed CLI architecture — design v0.1

The full Rust CLI specification is published in **[docs/architecture/README.md](docs/architecture/README.md)**. All components below are planned; the codebase is still pre-alpha.

| Document | What it specifies |
| --- | --- |
| [Rust implementation blueprint](docs/architecture/implementation-blueprint.md) | Crate boundaries, typed interfaces, pipeline and build plan |
| [CLI commands & configuration](docs/architecture/cli-interface.md) | Command syntax, output, registration, USDC credit, local state |
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

## Project status

**Pre-alpha.** We're establishing the architecture, threat model, tests and integration boundaries. There is no published stable binary or production SLA.

We welcome thoughtful technical feedback, reproducible test cases, and discussion of Solana agent-payment failure modes. Please do **not** publish live credentials, exploitable secrets or private customer transactions in public issues.

---

<div align="center">

**HGUET** · Built for an agent-driven Solana ecosystem

[Website](https://hguet.fr) · [GitHub Organization](https://github.com/HGUET)

*Security should happen before the signature.*

</div>
