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

## Implementation status — first Rust code (unreleased)

**Working today:** a Rust workspace with `hguet-core` and `hguet` CLI, strict offline **legacy/v0/v1 wire-format** decoding, bounded inputs, SHA-256 message/transaction hashes, local verification of provided **Ed25519 transaction signatures**, detection of top-level native **SOL System transfers**, and independently trusted **Ed25519 PaymentIntent** verification including a lower-bound spend-cap check. The prototype emits explicit UNKNOWN/DENY SecurityVerdicts and has Rust unit / end-to-end JSON smoke tests.

**Local restrictive policy now works:** the `hguet-policy` Rust crate and `hguet policy validate TRUSTED.toml` enforce optional user-controlled network/program/SOL-recipient restrictions and direct native transfer cap violations. This can return **DENY**, never ALLOW. More in the [implementation guide](docs/implementation/README.md).

**Signed per-mint caps (optional, unreleased):** `PaymentIntent` v1 now supports `token_spend_limits` (mint + canonical raw `u64` maximum) in its **exact-byte signed payload**. The offline verifier conservatively rejects exceeded/uncovered direct `TransferChecked`, `BurnChecked` and Token-2022 `TransferCheckedWithFee` debits and fails closed on unknown direct token instructions. It returns a structured direct-debit review; CPI and net balance comparisons remain advisory high-risk warnings. **No transaction-wide token spend guarantee or ALLOW exists**, and Cloud checks are still paid in native SOL only. See [implementation](docs/implementation/README.md).

**Source-bound token caps (optional, unreleased):** An exact-byte signed `PaymentIntent` can now also include `token_source_limits` per mint, source token account, required transaction signer authority and raw `u64` maximum. The offline CLI rejects unmatched source/authority, missing required-signer roles, unsupported multisig/extra-account forms and direct overages. Unsigned *pre-signing* messages can still be checked; the report separately marks whether the transaction signatures were cryptographically verified. Required-signer *placement* is not proof of current token-account ownership or total executed spending; successful direct-scope checks remain `UNKNOWN`. [Details](docs/implementation/README.md).

**Account authority observations (advisory):** the optional signed `token_source_limits` review can now be compared with **later** SPL Token or Token-2022 account state from the selected RPC. The CLI distinguishes observed owner vs delegate, delegated allowance, frozen accounts, mint/program mismatches and missing source-account evidence in `signed_source_authority_evidence`. **Neither a matching account authority nor a matching delegate proves execution-time permission, total spending or safety.** A separate bounded RPC request can now read up to 32 **used sources covered by an independently verified signed intent** when they were absent from simulation token-balance metadata. Every extra read has its own non-atomic slot; unavailable accounts stay unobserved, and CPI-only accounts are not automatically fetched. See [implementation](docs/implementation/README.md).

**CPI Source Coverage (optional, advisory):** the RPC engine can now read up to 32 previously unobserved source token accounts referenced by its decoded SPL Token/Token-2022 CPI instructions, with a **single extra bounded RPC batch** only after successful opt-in simulation. It reuses prior balance-derived and independently signed-source account snapshots without fetching duplicates. The CLI reports `cpi_source_account_snapshot` and `cpi_source_coverage`, including each source's RPC evidence origin, slot, mint/program discrepancies and any missing or opaque CPI coverage. The selected RPC's instructions and later account state are **not proof of onchain execution, ownership, gross spending or permission**. No `ALLOW` is emitted.

**Aggregate token spend evidence (advisory, unreleased):** HGUET now compares three **separate** views per mint and source token account: original-wire checked debit declarations, RPC-reported checked CPI debit declarations and negative net token-account deltas. Within each view, repeated operations are summed using bounded integers and compared with independently verified signed mint/source caps. The three views are **never added to a single claimed gross spend**, because the same event can be represented more than once. The `aggregate_token_spending` JSON and separate risk findings flag possible cap overages and missing/unchecked/opaque activity. No execution proof, independent authorization, total gross spend guarantee, or `ALLOW` exists.

**Verified Spending Boundaries (block-only, unreleased):** A new `signing_boundary` CLI report separates independently verified signed **direct-wire declaration limits** from unresolved ALT, arbitrary program effects, CPI, account state, fees and execution uncertainties. It **always blocks automatic signing**: `signing_gate="block"`, `automated_signing_permitted=false` and `signer_side_enforcement_integrated=false`. Even a verified PaymentIntent, valid transaction signature and successful RPC simulation do not prove total SOL/token spending or authorize `ALLOW`. No wallet signing or transaction broadcast is implemented. See [implementation](docs/implementation/README.md).

**Local signer preflight (BLOCK-only, no device integration):** The isolated `hguet-signer` workspace crate and `hguet signer-preflight FILE --offline --network devnet --intent INTENT.json --trusted-key PINNED_PUBLIC_KEY --encoding base64 --json` command re-parse the original transaction and verify the exact signed PaymentIntent. They **always refuse** to invoke a signer, create a signature, approve spending or broadcast a transaction—even if the intent and direct token caps are valid. There are no private keys or wallet SDKs: this is a testable refusal boundary, not an implemented spending enforcer. [Implementation details](docs/implementation/README.md).

**Trusted Signer Isolation (BLOCK-only, separate process):** A new hguet-signer-isolate binary accepts a tightly bounded, strict **agent JSON request on stdin** containing only original transaction bytes and a signed PaymentIntent. The intended network and pinned public trust key are **operator process configuration**, not agent-supplied fields. The earlier public signing backend trait was removed. Injected allow/RPC/time/key/device-command fields are rejected and **no transaction is ever signed or broadcast**. CI exercises the real separate process with synthetic signed intents and adversarial input. This does **not** yet provide an OS sandbox, protected launch or exclusive wallet access: see [threat model](docs/architecture/trusted-signer-isolation.md).

**Linux signer sandbox (operator opt-in, BLOCK-only):** A fail-closed launcher at `scripts/run_signer_sandbox.py` confines the separate no-key `hguet-signer-isolate` binary using mandatory Bubblewrap network/mount/PID/user isolation, read-only runtime files, dropped capabilities, an architecture-checked seccomp syscall filter and a separately pinned SHA-256 executable inode. It **never runs unconfined on failure** (exit 40), and only returns a blocked signer refusal after a successful sandbox launch (exit 20). The direct binary remains development-accessible without OS confinement but still cannot sign; no hardware wallet or total spending enforcement exists. Current CI verifies the policy and refusal behavior; if user namespaces are prohibited, live sandbox execution is explicitly skipped. [Linux sandbox details](docs/architecture/linux-signer-sandbox.md).

**Read-only Solana RPC Engine (opt-in):** `hguet-rpc` supports explicit user-selected HTTPS RPC, cluster validation through `getGenesisHash`, v0 address lookup checking, and bounded `simulateTransaction` reports. It now extracts **exact native SOL and token balance deltas where both snapshots exist**, validates CPI program identities and reports evidence gaps. It preserves and checks original top-level compiled instructions and **decodes direct SPL Token / Token-2022 operations from wire bytes** (offline for static keys, RPC-ALT-dependent where needed), with separate warnings for direct movements, account-control operations, unchecked transfers and opaque extensions. It also performs **limited compiled-byte decoding** of token CPI movement and authority operations, and identifies Token-2022 Transfer Fee, Transfer Hook, Permanent Delegate and confidential-extension instruction families as **opaque advisory effects**, with exact byte-level field parsing for a small supported subset. When a successful simulation exposes candidate token mints, it also performs one optional, bounded **same-provider Token-2022 mint TLV read**, reporting fee schedules, active hooks, permanent delegates and unknown extensions with **non-atomic slot provenance**. The engine also reads a bounded set of SPL Token and Token-2022 **holding accounts** after successful opt-in simulation, identifying frozen state, delegation, withheld fees, Memo Transfer, CPI Guard, confidentiality and unknown TLV payloads while separately comparing reported account mint/authority against simulation metadata. Both mint and token-account RPC snapshots are **non-atomic advisory evidence**. It now emits a **bounded deterministic Effect Correlation Graph** in `rpc_analysis.effect_graph`, preserving separately sourced wire declarations, simulated balance deltas, CPI claims and later non-atomic mint/token-account state links. Graph alerts highlight unprovable CPI-to-net attribution and conflicting account identities, but **no graph edge proves exact gross spending, final execution or authorization**. Missing/partial data is not filled with zeros. All single-provider evidence remains advisory: even successful simulation returns `UNKNOWN`, never `ALLOW`. When an independently verified signed PaymentIntent is available, the CLI also flags RPC-observed CPI programs outside its allowlist and fee-payer net outflow above the signed SOL cap as **advisory high-risk findings** (not authoritative spend enforcement). Offline CLI and HGUET Cloud do **not** automatically contact Solana RPC. [Implementation and privacy details](docs/implementation/README.md).

**Future server address:** `vps-d0669a91.vps.ovh.net:443` is currently the hardcoded default for *future* opt-in Cloud use. `hguet config show --json` displays it offline. Cloud transport remains disabled until authenticated TLS and the signed-protocol workflow are implemented.

**Not working yet:** independently verified multi-provider/atomic Solana state, guaranteed complete account/balance snapshots, authenticated full mint/account extension state, **semantic** CPI and Token-2022 effects, **full** spending-cap enforcement (including program-internal transfers and network fees), finalized transaction audit, Cloud networking, SOL settlement or signed Cloud assessments. Optional RPC balance/CPI fields are treated as incomplete provider-supplied observations, not proof of safe execution. **Do not rely on this prototype to approve live funds.** It never emits ALLOW.

```sh
cargo test --workspace
cargo run -p hguet -- inspect tests/fixtures/legacy-noop.base64 --encoding base64 --offline --json
cargo run -p hguet -- inspect tests/fixtures/v1-system-transfer.base64 --encoding base64 --offline --json
cargo run -p hguet -- policy validate tests/fixtures/policy-devnet-deny.toml --json
# Explicitly opt-in to external RPC only with a trusted intent and acceptable privacy:
# cargo run -p hguet -- check TX.bin --mode local --network devnet --intent SIGNED.json --trusted-key PINNED_KEY --rpc-url https://api.devnet.solana.com --json
```

The synthetic sample deliberately contains placeholder signatures and is **not a valid authorized payment**. See the [implementation README](docs/implementation/README.md) and [actual Rust CI](https://github.com/HGUET/hguet/actions/workflows/rust-ci.yml). No HGUET product release has been published.

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
| Local policy and spending checks | Optional authorized session analysis (future; not available anonymously) |
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
| **HGUET/server** | Private | Threat intelligence, network monitoring, SOL payment verification and advanced risk analysis |

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
| [CLI commands & configuration](docs/architecture/cli-interface.md) | Command syntax, output, anonymous SOL payment, local state |
| [Solana engine](docs/architecture/solana-engine.md) | Legacy/v0/v1, ALT, CPI, simulation, RPC evidence and failures |
| [Security & threat model](docs/architecture/security.md) | Trusted intent, limits, bypass threats, risk and privacy |
| [Verdict schema](docs/architecture/verdict-schema.md) | JSON contract and ALLOW/WARN/DENY/UNKNOWN decision rules |
| [Cloud transport](docs/architecture/cloud-protocol.md) | PQ TLS, signed quotes, one-shot SOL claims and risk responses |
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
