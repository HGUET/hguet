# HGUET CLI — Architecture specification

**Version:** 0.1-draft · **Date:** 2026-11-13 · **Status:** design only / not implemented  
**Repository:** `HGUET/hguet` (public, Apache-2.0)  
**Commercial counterpart:** `HGUET/server` (private, proprietary)

> This is the authoritative **proposed architecture** for the open-source CLI. No command, cryptographic guarantee, security detection, production deployment, or audit described below is claimed to exist yet. Implementations must pass the acceptance criteria before the project can be called production-ready.

## 1. Product mandate

HGUET is a Rust CLI that examines **prospective Solana transactions before customer-controlled signing**. It aims to answer four questions:

1. **Execution:** What might this transaction do under the observed network state?
2. **Intent:** Does that action match an independently trusted payment authorization?
3. **Policy:** Is it consistent with configured controls on assets, recipients, programs and budgets?
4. **Evidence:** What was checked, what was not checked, and what does that imply for the verdict?

It returns a machine-readable `ALLOW`, `WARN`, `DENY` or `UNKNOWN` result, not a magic “safe” bit. The free CLI remains useful on its own. Optional commercial HGUET Cloud adds continuously maintained threat and network intelligence.

**Non-goals:** wallet creation, custody, transaction signing, broadcasting, onchain firewall, autonomous money movement, token issuance, creating a cryptographic algorithm, unverified “AI guarantees”, replacing Solana RPC or acting as an official Solana service.

## 2. Trust boundaries and component diagram

```text
      User / approved business workflow
               | (independently authorized intent)
               v
   +--------------------------------------+
   | HGUET CLI process                    |
   |                                      |
   | CLI Parser / Config / Profiles       |
   |     |                                |
   | Input guard + tx decoder             |
   |     |                                |
   | Intent verifier + Policy Engine      |
   |     |                                |
   | Solana RPC adapter / Simulator       |
   |     |                                |
   | Effects Analyzer + Rule Engine       |
   |     |                                |
   | Verdict Aggregator + JSON Renderer   |
   |     |                                |
   |       +--> optional Cloud Client ----+--- PQ-capable TLS 1.3 ---> HGUET Cloud
   +--------------------------------------+                          (private)
               |                                     |
               +--> optional Solana RPC             +--> intelligence
               |                                     +--> monitoring
               v                                     +--> billing
    ALLOW / WARN / DENY / UNKNOWN
               |
               v
      Customer-owned signer / agent integration
```

**Mandatory boundary:** HGUET does not take possession of signing keys. A CLI verdict is advisory until an independently protected signer *requires* and validates a matching verdict. An agent able to bypass that signer can also bypass HGUET.

**Network boundary:** `local` means **no requests to HGUET Cloud**, not “no network use”: Solana simulation requires the selected user-controlled RPC endpoint. A separate `inspect --offline` path must perform decoding without RPC.

## 3. One executable, maintainable Rust workspace

Logical crates (library decomposition, **not** separate daemons or paid modules):

```text
HGUET/hguet/
├── Cargo.toml                  # proposed workspace manifest
├── Cargo.lock                  # commit for reproducible CLI builds
├── crates/
│   ├── hguet-cli/              # binary, clap commands, UX, exit codes
│   ├── hguet-core/             # pipeline and typed security context
│   ├── hguet-solana/           # wire decoder, RPC, ALT, simulation
│   ├── hguet-intent/           # trusted authorization canonicalization
│   ├── hguet-policy/           # deterministic policies, budget engine
│   ├── hguet-analyzer/         # effects, CPI, permissions, heuristics
│   ├── hguet-verdict/          # schema, evidence, deterministic aggregation
│   ├── hguet-protocol/         # PUBLIC cloud wire protocol and versioning
│   ├── hguet-transport/        # authenticated PQ TLS client, enrollment
│   └── hguet-storage/          # config, OS key storage, optional local SQLite
├── integrations/              # sample signer/agent/CI integrations
├── tests/                     # golden, threat and integration fixtures
├── docs/
│   └── architecture/          # these specifications
└── .github/workflows/         # build, lint, test, release and advisories
```

Start implementation as **one Rust binary plus small library crates**; split only when dependency and security boundaries justify it. The directory tree above is a target layout, not evidence that code exists.

### Responsibilities, dependencies and data flow

| Crate | Inputs → outputs | Security properties |
| --- | --- | --- |
| `hguet-cli` | CLI/stdin/config → requests and output | no implicit cloud, stable automation exit codes |
| `hguet-core` | validated inputs → execution plan | no security logic hidden in presentation |
| `hguet-solana` | raw tx + network → decoded effects and simulation | version-aware, all accounts resolved, slot/freshness recorded |
| `hguet-intent` | signed/trusted authorization → verified intent | agent-generated claims not trusted |
| `hguet-policy` | intent + effects + local policy → findings | deterministic, deny overrides, bounded state |
| `hguet-analyzer` | instructions, balances, CPI → findings | distinguish known, unknown and unresolved semantics |
| `hguet-verdict` | evidence + findings → canonical report | provenance and completeness surfaced |
| `hguet-protocol` | typed client/cloud messages → bytes | publicly inspectable, versioned, size bounded |
| `hguet-transport` | device identity + cloud endpoint → protected session | reject weak negotiated groups and unauthenticated peers |
| `hguet-storage` | config, key references, local usage reservations | least privilege, atomic writes, secret redaction |

No crate depends on a private server implementation. The private server may depend on published protocol/schema code from this public repository.

## 4. Security pipeline (deterministic first)

```text
1. Parse parameters, select profile and required coverage
2. Read bounded input; check accepted format and transaction version
3. Compute the exact original message/transaction fingerprint
4. Bind to configured Solana network (genesis verification)
5. Resolve address tables (v0), signer/fee payer roles and instructions
6. Load trusted intent and local policy; validate trust provenance
7. Simulate against eligible RPC state; capture slot and timestamp
8. Decode direct + inner effects, asset deltas and authority changes
9. Apply deterministic policy and intent rules
10. If opted in: request Cloud enrichment for the same fingerprint
11. Aggregate evidence, severity, uncertainty and coverage
12. Render verdict; exit with stable code; never sign or broadcast
```

A timeout, unsupported format, unresolved address table, ambiguous token semantics or missing **mandatory** evidence yields `UNKNOWN` (or `DENY` when a provable hard violation exists). A successful RPC simulation is a prerequisite for the relevant checks, **not proof of safety**.

### Decisions

- **`ALLOW`**: the mandatory checks for the selected policy/profile passed at a recorded network state. Advisory, not a guarantee.
- **`WARN`**: required evidence exists, but nonfatal risk needs conscious review.
- **`DENY`**: a definitive mandatory policy violation or unambiguous forbidden behavior was found.
- **`UNKNOWN`**: a required check could not be completed or a relevant behavior was not understood.

Aggregation precedence: definitive hard deny wins; otherwise missing mandatory evidence → unknown; otherwise warnings → warn; otherwise allow. A strict caller treats every state other than ALLOW as fail-closed.

## 5. Modes and scope

| Mode | Identity | RPC | Cloud | Goal |
| --- | --- | --- | --- | --- |
| `inspect --offline` | none | none | none | decode bytes only, no execution/safety claim |
| `check --mode local` | none | client's RPC | never | useful free baseline with trustworthy scope |
| `check --mode cloud` | client credentials | client's RPC + cloud sources | yes | baseline + enriched paid intelligence |
| `doctor` | none unless cloud tests requested | optional | optional | connectivity, version, crypto compatibility |
| `account / topup / usage` | enrolled device identity | no requirement | yes | manage subscription-free usage entirely in CLI |

`cloud` is explicit; environment defaults may not silently switch free checks to paid requests. Local mode must be usable without a HGUET account or HGUET Cloud availability.

## 6. Data contracts, system design references

Read these companion specifications:

1. [CLI surface & configuration](cli-interface.md) — exact proposed commands, inputs, config, exit codes and secret handling.
2. [Solana transaction engine](solana-engine.md) — versions, RPC, simulation, account resolution and unsafe cases.
3. [Intent & policy security model](security.md) — attacker model, authorization, spending, TOCTOU, privacy.
4. [Verdict schema](verdict-schema.md) — stable JSON structure, precedence, evidence and examples.
5. [Cloud protocol & PQ transport](cloud-protocol.md) — versioning, transport, enrollment and usage billing.
6. [Testing, roadmap & release gates](testing-roadmap.md) — repeatable criteria and CI.
7. [Architectural decisions](decisions.md) — accepted vs deferred choices.
8. [Primary technical references](references.md) — external specs and compatibility checklist.

## 7. Project-wide invariants

1. Never request seed phrases, wallet private keys or signatures from a hot wallet.
2. Never sign, send or settle a customer's transaction.
3. Never claim a simulation is equivalent to executed mainnet finality.
4. Never label unsupported or incompletely understood operations as `ALLOW` in strict profiles.
5. Never use agent-provided “intent” as independent authority without a trusted verification path.
6. Never silently call Cloud in local mode or silently downgrade PQ transport.
7. Never log complete user transactions, confidential intents, keys, API credentials or private payment data by default.
8. Never use proprietary server-only code as a hidden dependency for free mode.
9. Never conflate “recommendation” with “enforcement”; the external signer controls enforcement.
10. Test every supported transaction format, protocol version and network independently before advertising support.

## 8. Ownership and evolution

The public repository owns CLI commands, protocol schemas, wire versioning, free checks and public fixtures. Private `HGUET/server` owns threat feeds, correlations, metering, account service and operations. Shared compatibility is maintained by versioned, publicly specified contracts; both products must pass cross-repository integration tests before deployment.

**Planned product, not shipped code.** Feature gates and release notes must mark implemented coverage precisely.