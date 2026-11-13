# HGUET CLI — Architecture decisions (unreleased)

**Status:** current design decisions, **no product release**. Superseded proposals must not be implemented alongside current architecture.

| ADR | Current choice | Engineering consequence |
| --- | --- | --- |
| CLI-001 | Open-source Rust CLI; independent free local mode | no HGUET account or Cloud dependency for local analysis |
| CLI-002 | Assembly of final `SecurityVerdict` in public CLI | Cloud signs only its own `CloudAssessment` |
| CLI-003 | Trusted PaymentIntent from independently configured authority | agent-provided intent alone cannot justify ALLOW |
| CLI-004 | Optional Cloud = **one SOL payment per one security check** | no user registration, credit balance, top-up or USDC |
| CLI-005 | External customer wallet signs separate service payment | HGUET never receives customer private keys or signs protected payment |
| CLI-006 | USD reference tariff, **cached SOL/USD**, exact signed lamports | 24h price age ceiling, ~5% reference divergence tolerance, no postpay surcharge |
| CLI-007 | Deterministic complexity tiers and source-limited scope | price based on work, not amount at risk or verdict |
| CLI-008 | Three Solana clusters, isolated production/sandbox | Mainnet real SOL, Devnet/Testnet valueless test SOL |
| CLI-009 | Server-authenticated hybrid PQ-capable TLS 1.3 | exact group/identity interoperability required before claims, no mandatory client mTLS |
| CLI-010 | Versioned public Protobuf and signed JSON contracts | private server pins exact public commit, does not fork contract |
| CLI-011 | One-use random claim secret + onchain finalized settlement | private report retrieval without reusable user identity |
| CLI-012 | No automatic Cloud escalation | opt-in disclosure and external payment signer approval |
| CLI-013 | No custody, no protected-transaction signing/broadcast | customer wallet/signer must enforce advisory result |
| CLI-014 | No `ALLOW` for missing mandatory evidence | hard local DENY > mandatory UNKNOWN > WARN > ALLOW |

## Superseded proposals

- Device registration, account login, client mTLS, membership, prepaid USDC and service credits.
- Separate web billing cabinet or subscription.
- A server-signed *final composite* SecurityVerdict.
- Pricing proportional to the protected transaction's monetary value.
- A per-request high-frequency SOL/USDC oracle lookup.

## Deferred engineering choices

- A reviewed wallet adapter that can prepare System transfer + quote Memo as an unsigned external-wallet operation.
- Optional persistent pseudonymous signer-bound history (not anonymous global tracking); no enforceable global spending caps without a controlled signer.
- Onchain escrow, account-abstraction enforcement and batch billing.
- Commercially licensed threat feeds and network partnerships; never imply access without contract.
- Pin and test exact TLS provider, native library versions, report signature and key rotation.
- Exact published price, minimum viable SOL invoice, refunds and fee economics after Devnet proof.

## Change control

The [public protocol](../../protocol/v1/README.md) and [shared interoperability specification](interoperability.md) define current consumer behavior. A protocol change requires a matching fixture/CI update and explicit re-pin in `HGUET/server`. Protocol-number `v1` is **not** the HGUET product version. No product version until first real release.
