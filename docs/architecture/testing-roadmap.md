# HGUET CLI — Testing, milestones and release gates

**Status:** targets for implementation; none of these checks are claimed to have passed.

## 1. Development sequence (each milestone independently demonstrable)

| Milestone | Scope | Acceptance criteria |
| --- | --- | --- |
| M0 | Workspace/bootstrap | `cargo fmt --check`, `clippy -D warnings`, build and unit test all pass |
| M1 | Offline inspector | legacy/v0/v1 parser as supported; no network; malformed inputs safe |
| M2 | Solana RPC simulator | successful/failing simulation fixtures; network/genesis, slot, coverage |
| M3 | Intent & policy | independently trusted signature; hard deny; unknown on untrusted intent |
| M4 | SecurityVerdict | stable JSON schema, proof fields, exit codes, CI integration |
| M5 | Agent/x402/MPP adapters | realistic checkout/challenge fixtures, no signing, signer-bound checks |
| M6 | Local release | cross-platform binaries, supply-chain policy, published limitations |
| M7 | Cloud client prototype | real PQ TLS interop, enrollment, signed receipts and fail closed |
| M8 | Paid account CLI | top-up invoice, account, credit ledger and retry-safe billing |
| M9 | External trial | benchmarks against existing tools, false positive/negative analysis, audit |

Do not start private Cloud before a useful and well-tested **free M1–M4** milestone exists.

## 2. Test matrix

### Parsing and input safety

- Valid legacy, v0 (ALT), and v1 (inline addresses, new resource fields) fixtures; signature metadata correct.
- Reject unsupported versions, unknown critical fields, invalid compact-u16, oversized bytes, invalid account indices, corrupted lookups, malformed token instructions, invalid b58/b64.
- Fuzz wire, intent JSON, policy TOML, CLI stdin and cloud protobuf decoding; enforce memory/time limits.
- Differential tests against an independent maintained Solana reference parser.
- No keypair/secret parsing code compiled into CLI.

### Solana behavior

- Native SOL transfer, SPL Token, Token-2022, associated token accounts, CPI effects and unsupported extension handling.
- Account ownership/mint/decimals mismatch; wrong fee payer; hidden authority change; malicious delegate.
- `simulateTransaction` success vs instruction error; expired blockhash; sigVerify/replaceRecentBlockhash incompatibility.
- Wrong genesis hash, stale context, ALT lookup failure, RPC mismatch, network timeout, partial logs and reorg.
- Tests for mainnet/devnet binding, version format size, and exact message fingerprint; compare deterministic snapshots.
- In strict mode, unknown program semantics or missing required simulation must never return ALLOW.

### Payment-intent and policy behavior

- Independently signed correct intent ALLOW candidate.
- Agent-generated unverified intent UNKNOWN; incorrect signature DENY/UNKNOWN per configured policy.
- Changed amount, recipient, asset mint, token program, program IDs, purpose/resource scope and expired intent DENY.
- Duplicate intent and transaction replay, concurrent local budget reservations, counter rollback.
- Untrusted x402/MPP challenge with wrong CAIP-2 network, wrong amount, malicious payTo, stale nonce and fake receipt.
- MPP metered cumulative voucher exceeding authorized ceiling and replay attempts.

### Cloud and protocol

- End-to-end PQ TLS 1.3 with SecP384r1MLKEM1024 + supported ML-DSA-87 certificate/identity scheme + AES-256-GCM.
- Force legacy TLS version, classical-only group, mismatched cert, expired client cert, missing pinned root, revoked device: must fail.
- Cipher/group negotiation assertions; timeouts, partial reads, malformed frames, oversized protobuf messages, half-close/reconnect.
- Version skew between public client and private server, signed report verification, key rotation and replay tests.
- Billing: concurrent check requests, retry after timeout, duplicate request IDs, multiple devices, top-up invoice double-credit prevention, fees only under terms.
- Explicit local mode produces **zero HGUET Cloud network connections**.

### Adversarial scenarios / must-have benchmark

Start with at least **200 reproducible case variants** across categories (goal, not existing dataset):

1. Recipient substitution
2. Token mint/decimals substitution
3. Payment amount inflation
4. Duplicate billing and fragmented purchases
5. Unintended delegate or token authority changes
6. CPI and upgraded program side effects
7. Token-2022 extension bypass attempts
8. Expired/replaced blockhash and stale RPC
9. x402 V2 payment-request manipulation
10. MPP payment challenge, voucher and session manipulation
11. Unsupported v1/v0 message parsing
12. Incorrect or forged security report / intent approval

For each case, record expected verdict and **why** it is expected, including when correct decision is UNKNOWN.

## 3. Required quality metrics (targets, not measurements)

- No known hard-deny test fixture may be reported ALLOW.
- No unsupported/opaque mandatory effect may be reported ALLOW in strict mode.
- Deterministic verdict for fixed input + fixed snapshot + fixed policy.
- Stable JSON response contract, schema compatibility and CLI exit code mapping.
- Zero uncontrolled Cloud requests in local tests.
- Bounded memory, CPU, log size and transaction decode time under adversarial input.
- Report p50/p95 local evaluation latency separately from RPC network wait.
- Record reproducible false-positive and false-negative statistics with denominators and confidence notes; do not invent accuracy percentages.
- Cross-platform cryptographic interoperability matrix must be green before announcing “PQ-secure Cloud”.

## 4. CI pipeline (planned)

```text
main/pull_request
  |
  +-- rustfmt / clippy / cargo test
  +-- dependency vulnerability and license checks
  +-- no-secrets scanning
  +-- schema / sample JSON validation
  +-- deterministic transaction fixture tests
  +-- parser fuzz smoke test
  +-- cross-platform build matrix
  +-- doc links and Markdown lint
  +-- optional nightly performance benchmarks
  +-- optional Cloud integration tests against ephemeral test server
```

Testing against Devnet is valuable but **not a substitute** for reproducible mocked historical traces and adversarial fixtures. Live RPC tests should not make all PRs flaky; run scheduled smoke tests separately.

## 5. Supply chain and release

- Pin source dependency revisions after compatibility review, commit CLI Cargo.lock.
- Use reproducible/reviewable builds, least-privileged GitHub Actions, SBOM, signed release artifacts, checksums and documented verification.
- Release without embedded private server credentials; no silent auto-execution of downloaded scripts.
- Cryptographic provider versions, PQ algorithms, server trust anchors, compatibility requirements and revocation update story in release notes.
- Publish a threat model, supported transaction version matrix, unsupported program types and limitations.
- Independent security review and responsible disclosure pathway before business users are asked to trust production mainnet checks.

## 6. Delivery ownership

- **Public repository:** free CLI, protocol schema, public fixtures, open integrations and docs.
- **Private server repository:** intelligence ingestion, proprietary correlation, Cloud billing, enforcement of Cloud quotas and server operations.
- **Website:** project status and links only, never unsupported “already available” statements.

## 7. Release gates

### Alpha

M1–M4 complete; devnet/manual examples; explicit experimental warnings. Safe default strict mode and documented UNKNOWN behavior.

### Beta

x402/MPP fixtures, realistic Solana program adapters, reproducible developer integrations, transparent benchmark, incident handling process. Security review started.

### Production readiness

Independent audit scope addressed; baseline adversarial tests passed; stable schema, signed binary provenance, tested multi-platform PQ Cloud, real user pilot results, SLOs, monitoring and safe incident response.

These are **gates**, not time estimates or commitments.

See [overview](README.md), [Cloud](cloud-protocol.md), [Solana engine](solana-engine.md), [threat model](security.md).