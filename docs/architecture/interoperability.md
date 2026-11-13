# HGUET CLI ↔ Server — Unified interoperability contract

**Status: Unreleased architecture draft. No HGUET product releases exist.** The proposed `protocol/v1` directory is a wire-format draft, not a v1.0 product release. Private `HGUET/server` consumes a pinned commit of this public contract.

## Responsibility

| Public HGUET CLI | Private HGUET Server |
| --- | --- |
| Parse and simulate supported Solana transactions with user-selected RPC | Monitor current network/program risk sources |
| Verify independently trusted payment intent and local policy | Provide bounded intelligence and correlations |
| Produce final `SecurityVerdict` (`ALLOW/WARN/DENY/UNKNOWN`) | Sign `CloudAssessment` and separate `PaymentReceipt` |
| Request a priced Cloud assessment only when explicitly selected | Quote in USD and accept one native SOL payment for one check |
| Preserve user-controlled wallet/signing authority | Never sign or broadcast customer's protected transaction |

No account, login, device enrollment, prepaid balance, subscription or USDC is required for the current proposed Cloud design. The customer uses a separate external wallet to pay SOL for one selected check; the donation address is not a payment receiver.

## Public protocol and three signed artifacts

1. [`protocol/v1/hguet.proto`](../../protocol/v1/hguet.proto): proposed TCP/TLS-framed Protobuf messages for price quote, paid check, pending status and result.
2. [Payment Quote](../../protocol/v1/payment-quote.schema.json): signed USD tariff, current-day **SOL/USD** reference, complexity tier, exact **lamports**, network/genesis, commercial receiver, expiry, claim commitment, chosen capabilities and price cap. Signature domain `HGUET-SOL-QUOTE/v1`.
3. [CloudAssessment](../../protocol/v1/cloud-assessment.schema.json): signed sources, risk facts, coverage and transaction/intent hash binding. Signature domain `HGUET-CLOUD-ASSESSMENT/v1`. Does **not** sign the final CLI decision.
4. [PaymentReceipt](../../protocol/v1/payment-receipt.schema.json): signed proof binding one finalized SOL settlement event to one check, domain `HGUET-SOL-PAYMENT-RECEIPT/v1`.
5. [SecurityVerdict](verdict-schema.md): composed **by the CLI**, not server-signed. Known local hard DENY cannot be overridden by Cloud; missing mandatory evidence yields UNKNOWN.

Use canonical JCS JSON under independent signature domains with authenticated key rotation. Signatures establish issuer and data integrity, not accuracy of a risk prediction.

## End-to-end workflow (unreleased)

```text
CLI: free local check → independently trusted intent/policy
   → server-authenticated PQ-capable TLS connection
   → PriceQuoteRequest (exact check inputs, complexity, max lamports)
   ← signed PriceQuoteResult (USD micros, cached SOL/USD, fixed lamports)
Customer external wallet signs native SOL System transfer + quote Memo
   → PaidCheckRequest (quote ID, private one-check claim, paid tx signature)
   ← CheckReceipt (pending) or CheckResult (signed CloudAssessment + PaymentReceipt)
CLI: verify bindings and signed artifacts, merge with local results
   → FINAL SecurityVerdict; customer signer controls actual authorization
```

A paid transfer and offchain computation are **not atomic**. If service is unavailable after settlement, the one-check claim is recoverable using `PaidCheckStatus`; do not require a second payment without retry/refund resolution.

## Pricing rules

- Proposed tier targets: Basic **$0.001**, Standard $0.003, Complex $0.006, Extended from $0.010. **Not released commercial rates.**
- Price depends on bounded work and explicit analysis depth: transaction bytes, instructions, accounts, number of risk subjects, optional data sources and additional RPC/simulation. Not the amount being transferred or whether the result is DENY.
- A trusted cached SOL/USD reference updated at least once daily (source timestamp ≤24h) is sufficient for micro-invoices; approximate **5% market-reference tolerance** is acceptable when independently checked. The user must pay the **exact** signed lamports, with no 5% underpayment or post-payment surcharge.
- Metadata-only scope cannot prove transaction size or simulate hidden instructions: quote only for the bounded supplied scope. Raw bytes require disclosure/consent; unquoted extra work cannot be billed.

## Security and clusters

- Mainnet: real native SOL, production receiver and independent secrets/state.
- Devnet/Testnet: valueless test SOL, sandbox receivers, isolated claims/results. Always verify `getGenesisHash` and quote environment binding.
- Signed quote binds a **SHA-256 commitment** of a randomly generated **256-bit private claim**. The public Solana payment signature **does not** authorize report retrieval.
- TLS 1.3 with required tested `SecP384r1MLKEM1024` and ML-DSA-87 server identity; no mandatory client mTLS. Real cryptographic interop is **not yet proven**.
- No custom cryptography, implicit Cloud fallback, server access to customer wallet private keys, or inference that a hash-only Cloud check independently decoded the transaction.
- The protocol is publicly documented; server authorization cannot be based on secret binary or “official CLI only”.

## Authority, compatibility and release status

The canonical wire/schema source is the **public** [protocol draft](../../protocol/v1/README.md), together with the [payment specification](payment-per-request.md) and [pricing policy](pricing-policy.md). The private server pins the exact commit and runs the same [planned scenarios](../../protocol/v1/contract-cases.json).

**No product version has been assigned or released.** Numeric schema identifiers are internal placeholders; any first product version is set only by an actual release. Public schema checks are **not** successful Rust client/server payment or PQ TLS integration tests.
