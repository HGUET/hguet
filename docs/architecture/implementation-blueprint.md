# HGUET CLI — Rust implementation blueprint

**Status:** proposed interfaces. This document is **not compilable code** and does not claim these crates currently exist.

## 1. Dependency direction

```text
hguet-cli
    |
    v
hguet-core
    |
    +-- hguet-solana           (RPC abstraction + normalized tx)
    +-- hguet-intent           (trusted intent verification)
    +-- hguet-policy           (pure deterministic evaluation)
    +-- hguet-analyzer         (effects/CPI/authority findings)
    +-- hguet-verdict          (schema and provenance)
    +-- hguet-storage          (config/state)
    |
    +-- OPTIONAL CloudEnricher interface
          |
          +-- hguet-transport + hguet-protocol
```

**No reverse dependencies.** `hguet-verdict` must not import Solana network clients; `hguet-policy` must not perform RPC, filesystem, logging, date/time reads or Cloud calls. HGUET's core coordinates adapters through interfaces; transport and storage are replaceable.

## 2. Typed domain model (illustrative Rust)

```rust
// Pseudocode design. Imports/derive attributes omitted intentionally.

enum Decision { Allow, Warn, Deny, Unknown }

enum Mode { OfflineInspect, LocalCheck, CloudCheck }

enum TxVersion { Legacy, V0, V1, Unsupported(u8) }

struct NetworkBinding {
    chain_id: String,
    observed_genesis_hash: Option<String>,
    genesis_verified: bool,
}

struct TxArtifact {
    original_wire: Vec<u8>,    // bounded, ephemeral
    original_wire_hash: [u8; 32],
    original_message_hash: [u8; 32],
    version: TxVersion,
    network: NetworkBinding,
}

struct VerifiedIntent {
    id: String,
    canonical_hash: [u8; 32],
    provenance: IntentProvenance,
    issuer_key_id: Option<String>,
    expires_at: Option<SystemTime>,
    constraints: IntentConstraints,
}

struct ObservedState {
    context_slot: u64,
    commitment: Commitment,
    observed_at: SystemTime,
    rpc_endpoint_id: String,
    used_replacement_blockhash: bool,
}

struct Finding {
    code: FindingCode,
    severity: Severity,
    enforcement: Enforcement,
    evidence: Vec<EvidenceRef>,
}

struct Coverage {
    mandatory: Vec<CheckId>,
    passed: Vec<CheckId>,
    failed: Vec<CheckId>,
    unknown: Vec<CheckId>,
}

struct CheckContext {
    artifact: TxArtifact,
    verified_intent: Option<VerifiedIntent>,
    policy: Policy,
    snapshot: Option<ObservedState>,
    mode: Mode,
}
```

Use integer base units for all onchain asset quantities; never floating-point token calculations. Favor strongly typed IDs and checked arithmetic instead of ambiguous strings in production code.

## 3. Pure and effectful interfaces

```rust
// Interface sketch, not guaranteed compiling signatures.
trait TransactionDecoder {
    fn decode(&self, bytes: &[u8]) -> Result<DecodedTransaction, DecodeError>;
}

trait IntentVerifier {
    fn verify(&self, raw: &[u8], anchors: &TrustAnchors)
        -> Result<VerifiedIntent, IntentError>;
}

trait PolicyEvaluator {
    fn evaluate(&self, ctx: &PolicyContext, effects: &[Effect])
        -> PolicyEvaluation;
}

trait EffectsAnalyzer {
    fn analyze(&self, decoded: &DecodedTransaction,
               simulated: &SimulationEvidence)
        -> EffectsAnalysis;
}

// Async I/O abstraction in real code, no runtime hardcoded into policy crate.
trait RpcProvider {
    async fn genesis_hash(&self) -> Result<GenesisHash, RpcError>;
    async fn resolve_alt(&self, key: &Pubkey) -> Result<AltSnapshot, RpcError>;
    async fn simulate(&self, request: SimulationRequest)
        -> Result<SimulationEvidence, RpcError>;
}

trait CloudEnricher {
    async fn enrich(&self, request: CloudCheckRequest)
        -> Result<CloudCheckResponse, CloudError>;
}

trait VerdictAggregator {
    fn finalize(&self, ctx: &CheckContext, findings: Vec<Finding>,
                coverage: Coverage) -> SecurityVerdict;
}
```

Use an **opaque data source interface** for tests: deterministic fake RPC, fixed clock, fixed Cloud response, fixed trust anchors. Do not put network calls inside unit tests for pure evaluation.

## 4. Async orchestration and cancellation

The future `CheckEngine::run(input, options) -> Result<SecurityVerdict, CheckError>` should:

1. Parse bounded bytes and load a read-only config snapshot.
2. Validate the configured network and independently verify intent.
3. Resolve v0 ALT accounts, capturing account context.
4. Simulate with explicit compatibility flags; record observed slot and status.
5. Normalize account + token + CPI effects and evaluate hard policy.
6. Optionally call Cloud **only** when opted in and required by resolved mode.
7. Reconcile local findings, Cloud evidence and coverage through pure aggregation.
8. Emit one structured object; map verdict to CLI exit status.

Every network request must have a deadline, cancellation path and size cap. Bound concurrency, enforce retry budgets with jitter and verify idempotency before retrying billable Cloud calls. Avoid file I/O and blocking cryptographic work on async reactor threads when measurable overhead is significant; use tested async-safe primitives or controlled blocking pools.

### Deterministic snapshots

All “current time” decisions should take a supplied clock snapshot so tests are repeatable. Solana-related invariants depend on a recorded RPC slot and commitment, not system wall-clock alone. Cache entries must be scoped to (genesis/network, relevant account, slot or freshness criteria), and never silently turn a stale snapshot into an ALLOW.

## 5. Crate/API design by unit

| Crate | Public API to design first | Test technique |
| --- | --- | --- |
| `hguet-cli` | `Command`, `OutputFormat`, `ExitStatus` | golden help/output, stdin/TTY |
| `hguet-core` | `CheckRequest`, `CheckEngine` | fake adapters and fixed clock |
| `hguet-solana` | `DecodedTransaction`, `SimulationEvidence`, `NormalizedInstruction` | cross-version fixtures/differential |
| `hguet-intent` | `TrustedIntent`, `TrustAnchors`, `IntentProvenance` | signature and replay vectors |
| `hguet-policy` | `Rule`, `PolicyProfile`, `PolicyEvaluation` | table-based deterministic tests |
| `hguet-analyzer` | `Effect`, `AuthorityChange`, `UnknownEffect` | CPI/Token-2022 fixtures |
| `hguet-verdict` | `SecurityVerdict`, `Finding`, `Coverage` | JSON schema + canonical tests |
| `hguet-protocol` | `ClientEnvelope`, `ServerEnvelope`, `ProtocolVersion` | wire version & fuzz |
| `hguet-transport` | `AuthenticatedCloudSession` + one-use paid claim | real server-authenticated PQ TLS interop + negative tests |
| `hguet-storage` | `ConfigSnapshot`, `CredentialRef`, `LocalBudgetLedger` | permissions & transaction races |

## 6. Dependency candidates (not pinned choices yet)

- **CLI & UX:** `clap` for command grammar; `serde`/`serde_json` for typed output.
- **Async & logging:** `tokio`, `tracing` and `tracing-subscriber` with sensitive-data redaction.
- **Errors:** `thiserror` for typed failures; separate error mapping from public verdict findings.
- **Solana:** maintained official modular Solana crates for transactions, messages, signatures and RPC; verify compatibility with **v1** before pinning. Do not bind architecture to obsolete crate names or parse formats by assumption.
- **Crypto:** maintained `openssl` bindings with pinned provider/version for HGUET Cloud PQ TLS; use reference crypto for intent verification, never implement lattice or AEAD algorithms manually.
- **Wire:** `prost`/Protobuf as initial candidate, publicly versioned and fuzz-tested.
- **OS integration:** platform-known directories, OS keyring APIs, `rusqlite` for *optional* local state.
- **Security tooling:** `cargo-audit` or equivalent, `cargo-deny`, secret scanning, cargo-fuzz, lockfile review.

Crates are **candidates**; verify licenses, maintenance, vulnerabilities, binary portability, cross-compilation and MSRV before adoption.

## 7. Feature flags and isolation

Prefer explicit Cargo features such as:

```text
default = ["local"]
local      = core + RPC-based free checks
cloud      = transport + protocol + quote/claim verification
platform-secure-storage = OS-protected one-use claim secrets
dev-fixtures = local mocks, never published as production auth bypass
```

CLI runtime still uses explicit `--mode`; having Cloud compiled in **must not** mean sending data to HGUET servers. A build with `cloud` disabled must remain fully functional for local checks.

No hidden remote code/plugin downloads, no mutation of customer wallets, no arbitrary scripting in policy files.

## 8. Observability and privacy

- Internal typed events: `decode_started`, `rpc_context_observed`, `simulation_finished`, `policy_violation`, `cloud_enrichment`, `report_rendered`.
- Redact raw transactions, intent bodies, wallet secrets, quote claim secrets, RPC URL tokens and customer email addresses from logs by default.
- Never put secrets in panic output, metrics tags or support bundles.
- HGUET Cloud telemetry is **opt-in** for the user, not a free-CLI dependency.
- Log performance without exposing sensitive resources; use sample fixture IDs in CI.

## 9. Upgrade/compatibility path

Keep public verdict JSON stable through a documented major/minor schema; Protobuf wire has independent versioning and explicit capability negotiation. New unsupported versions must be rejected or UNKNOWN rather than downgrading the parser.

Track Solana support by **format and instruction family**, not “supports all transactions” marketing. Maintain a version compatibility matrix linking pinned dependency versions, devnet/mainnet features, Token-2022 extensions, and known unsupported programs.

## 10. First implementation ticket set

1. Cargo workspace, pinned toolchain, CI lint/tests (no network or product claims).
2. Types + JSON schema for `SecurityVerdict`, golden examples and exit-status tests.
3. Offline parser + fixture harness: malformed/legacy/v0/v1.
4. RPC abstraction + fake provider + genesis/hash/slot handling.
5. One safe, correctly decoded SPL transfer with simulated balance delta and strict intent.
6. Trust anchor and signed intent verification; reject agent-provided unverified authorization.
7. Expand to CPI, authority changes, Token-2022, x402/MPP.
8. Cloud protocol and transport interop tests **only after free CLI is robust**.

## 11. Implementation completion checklist

Before any feature is marked done: unit/integration/fuzz cases, negative security cases, public CLI help, JSON fixture, performance measurement, docs change, no secrets/implicit network connections and targeted compatibility test. “Compiled” is not sufficient evidence of secure operation.

See [overview](README.md), [CLI](cli-interface.md), [Solana](solana-engine.md), [security](security.md), [testing](testing-roadmap.md).