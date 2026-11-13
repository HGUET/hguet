# HGUET public protocol v1 — accountless SOL pay-per-check (DRAFT)

**Design status:** Unreleased draft, not a running API. **No HGUET product releases exist yet.** The `protocol/v1` folder denotes a proposed wire-schema major version, **not** an HGUET v1.0 product release. · Updated 2026-11-13.

This directory is the **canonical public contract** shared by `HGUET/hguet` (Rust CLI) and private `HGUET/server`. The server consumes an exact pinned commit and must not fork these public message definitions.

## Files

- [hguet.proto](hguet.proto) — TLS-framed Protobuf: `PriceQuoteRequest`, `PriceQuoteResult`, `PaidCheckRequest`, `PaidCheckStatus`, pending `CheckReceipt`, terminal `CheckResult`.
- [payment-quote.schema.json](payment-quote.schema.json) — JCS-canonical signed SOL/USD quote; **USD tariff is a price reference, not a token transfer**.
- [payment-receipt.schema.json](payment-receipt.schema.json) — separately signed receipt for **one native SOL payment, one Cloud check**.
- [cloud-assessment.schema.json](cloud-assessment.schema.json) — source-attributed, separately signed Cloud risk assessment bound by quote ID (not by an obsolete tenant/account). The CLI composes the **final** SecurityVerdict.
- [contract-cases.json](contract-cases.json) — 30 **planned** interoperability scenarios, not completed integration tests.
- [fixtures/payment-quote-example.json](fixtures/payment-quote-example.json), [fixtures/payment-receipt-example.json](fixtures/payment-receipt-example.json), [fixtures/cloud-assessment-example.json](fixtures/cloud-assessment-example.json) — synthetic only, never production treasury or current market data.
- [Authoritative payment spec](../../docs/architecture/payment-per-request.md) and [CLI/server compatibility](../../docs/architecture/interoperability.md).

## Protected transaction's optional signed token caps

A separately signed `PaymentIntent` for the **transaction being inspected** may now include optional `token_spend_limits` entries (`mint` Base58 address, `max_debit_raw` canonical unsigned u64). This is **not** a quote currency, HGUET payment method or Cloud invoice. It bounds recognized **direct checked token debit declarations** in the original wire only. The current Rust verifier rejects uncovered direct token operations, exceeded caps and duplicate/invalid entries but cannot authorize total execution spending through CPI, custom programs or token extensions. All such unknown outcomes stay `UNKNOWN`. The omitted field preserves signed SOL-only intent compatibility; the private server must pin this exact public contract before assuming any new field semantics.



```text
CLI local check (free)
  → server-authenticated PQ TLS (no registration, no device mTLS required)
  → PriceQuoteRequest (message/intent/subjects, scope, max lamports)
  ← signed PriceQuoteResult (USD tariff, fresh SOL/USD, integer lamports, receiver, expiry)
  → external wallet signs native SOL System transfer + memo quote ID
  → PaidCheckRequest (signature, private claim secret, bound check parameters)
  ← CheckReceipt (pending) OR CheckResult (terminal signed CloudAssessment + PaymentReceipt)
  → CLI verifies both, merges with local checks, returns final SecurityVerdict
```

`PaidCheckStatus` lets the holder of the private quote claim secret retrieve an existing result after a disconnection **without paying again**. A claim is not a user account or a credit balance. The claim secret is not published onchain; its SHA-256 commitment is bound into signed quote. The server must not disclose one person's result to a third party who simply observes the onchain transfer signature.

## Pricing and cluster policy

- **All invoices are native SOL**, expressed in integer **lamports**; never USDC, SPL mints, fiat card payments or internal credit balances in current draft.
- Product tariff uses **integer USD microdollars** converted to lamports using a **cached current-day SOL/USD reference** (last source update ≤24 hours). Refresh in the background daily, preferably every 4–12 hours; do not fetch oracle data on every request. Approximate ±5% deviation relative to credible independent observations is tolerable; >5% conflict requires repricing source review or pausing new quotes. The signed invoice **always requires exact lamports**, not ±5% underpayment.
- **[Complexity-based pricing tiers](../../docs/architecture/pricing-policy.md)**: Basic $0.001 / Standard $0.003 / Complex $0.006 / Extended from $0.010 are **illustrative unapproved launch targets**. Quote binds policy version, highest-required tier, bounded complexity metrics, requested features, risk subjects and client fee cap.
- Conversion: `lamports = ceil(usd_price_micros * 1_000_000_000 / sol_usd_price_micros)` using checked integer arithmetic.
- Signed quote freezes the lamports amount until expiry; user max price cap is binding, no silent repricing.
- Mainnet: real SOL and production receiver. Devnet/Testnet: **test** SOL and sandbox receiver. All quotes and receipts bind environment + network **and genesis hash**, never interchangeable.
- Donation wallet is **not** the receiver for service payments.

## Authentication, signing and transport

- TLS 1.3 with the selected verified hybrid `SecP384r1MLKEM1024` group and ML-DSA-87 server identity profile. These are **testable design requirements**, not proof of live PQ service.
- No user registration or long-lived client certificate: one quote is authorized by its private claim secret and **verified onchain settlement**.
- Framing: `uint32 big-endian length` (≤1 MiB), followed by one Protobuf `Envelope` with major=1/minor=0 draft.
- Signed quote uses `HGUET-SOL-QUOTE/v1`; signed PaymentReceipt uses `HGUET-SOL-PAYMENT-RECEIPT/v1`; CloudAssessment uses `HGUET-CLOUD-ASSESSMENT/v1`. Each has independent canonical JCS body, detached signature and authenticated key.
- A signed Cloud assessment **does not sign or replace** the final CLI SecurityVerdict.
- Replay, wrong cluster, wrong receiver, changed message, expired quote or wrong claim secret fail closed; network delays remain pending and can be recovered.

**No released protocol version exists yet.** The private server must pin this exact public draft while in development and run cross-repository fixtures before production.
## Contract corrections from joint audit

- `PriceQuoteRequest` can include **raw transaction bytes with explicit consent** before payment, only to validate a bounded complexity tier and wire/message digest. It must never silently send raw data or run expensive unquoted network analysis.
- `PaymentQuote`, `CloudAssessment`, and `PaymentReceipt` bind the **same one-use `quote_id`**, message digest, network/genesis, environment and optional original wire digest. The server cannot authenticate a previous tenant in this accountless design.
- `verified_from_raw_transaction` is accepted only when the server actually decoded a consented raw transaction; a client-provided boolean is not evidence.
- Signed payment amounts and USD/SOL price numerators must be **strictly positive integers**; a 0-lamport receipt cannot be a completed paid check.
