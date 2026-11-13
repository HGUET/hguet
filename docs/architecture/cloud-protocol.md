# HGUET CLI — Cloud transport and paid-check protocol

**Status:** unreleased architecture draft; **no deployed backend or real PQ interoperability is claimed**.

> Canonical protocol: [Protobuf](../../protocol/v1/hguet.proto), [signed price quote](../../protocol/v1/payment-quote.schema.json), [signed CloudAssessment](../../protocol/v1/cloud-assessment.schema.json), [signed payment receipt](../../protocol/v1/payment-receipt.schema.json), [price rules](pricing-policy.md). This document replaces all earlier account/enrollment/USDC/credit flows.

## 1. Separation of responsibilities

The public Rust CLI runs independently for free and owns the final `SecurityVerdict`. The proprietary Rust server supplies optional risk intelligence and one-off native SOL payment verification. There is **no Cloud user registration, login, device certificate, prepaid service credit, stored user balance, USDC mint or subscription** in the current design.

```text
HGUET CLI: local inspect / trusted intent / policy / user's Solana RPC
    |
    | opt-in only: server-authenticated PQ TLS 1.3
    v
PriceQuoteRequest (cluster/genesis, hashes, bounded subjects and metrics,
                  claim commitment, data consent, maximum lamports)
    |
    v
HGUET Server: cached daily SOL/USD + deterministic tier -> signed PriceQuote
    |
    v
Customer-controlled external wallet signs native SOL transfer + quote Memo
    |
    v
PaidCheckRequest (quote ID + claim secret + payment signature + same scope)
    |
    v
Server verifies FINALIZED transfer -> bounded risk intelligence analysis
    |
    v
CheckResult (signed CloudAssessment + separate signed PaymentReceipt)
    |
    v
CLI verifies signatures/binding/coverage -> FINAL SecurityVerdict
```

If a paid request is pending or the connection fails, `PaidCheckStatus(quote_id, claim_secret)` retrieves the *same* claim/result without another payment. A pending `CheckReceipt` is **never** an ALLOW/DENY verdict.

## 2. TLS security profile

- Standard **TLS 1.3** over TCP, not custom encryption, a VPN, or public HTTP/REST paid API.
- Required tested hybrid group **SecP384r1MLKEM1024** (RFC 10024) with **AES-256-GCM** TLS record protection under `TLS_AES_256_GCM_SHA384`.
- Selected **ML-DSA-87** server authentication with verified certificate path and pinned trust roots/signing keys. Prove end-to-end interoperability on each target OS/TLS provider before advertising PQ support.
- No mandatory client mTLS: paid access is authorized by **a one-shot private claim secret and verified onchain funds**, not a reusable device identity.
- Disable 0-RTT for state-changing messages; fail closed on classical-only/downgraded groups, bad pins/identity, unsupported protocol major or missing required algorithms.
- Initial server trust is shipped through signed releases and authenticated pin/CA rotation; do not rely on first-contact TOFU.
- HGUET service must not claim that TLS transport encryption hides the payment/transaction content from HGUET itself after it is decrypted.

## 3. Binary wire framing

Use `4-byte unsigned big-endian frame length` plus exactly one **Protobuf Envelope**, maximum **1 MiB**, smaller per-field limits. The proposed `protocol_major=1` is a *wire-schema number*, not product version or published release. Unknown critical types or incompatible major versions produce explicit protocol errors, never silent fallback.

Client may be any compatible implementation with valid one-shot payment; a public wire protocol cannot cryptographically ensure the peer is the “official HGUET binary”. Rate limits and paid claim validation enforce service access.

## 4. Quote creation and cost control

Server calculates a one-check price **before payment**, based on requested intelligence capabilities, bounded metrics and [published draft complexity tiers](pricing-policy.md). Tariff is denominated in integer USD microdollars, converted to **exact integer lamports** using an authenticated cached SOL/USD observation updated at least daily and no older than 24 hours. Approximate market-reference divergence up to **5%** can be tolerated, but the customer must pay the **exact lamports** in the signed quote.

Quote binds: `quote_id`, `environment`, network + verified genesis, message/intent digest, optional original transaction-wire hash, source-subject digest, requested capabilities, raw-data disclosure scope, pricing policy version/tier, metrics, USD price, source FX timestamp, receiver, one-time Memo, expiry, client maximum fee and claim-secret SHA-256 commitment.

**Pre-quote privacy:** `PriceQuoteRequest.raw_transaction` may contain bytes ONLY if `raw_transaction_consent=true`. This lets the server decode **bounded data locally** to verify transaction format and complexity *before quoting*. A metadata-only request must not claim hidden CPI/effects were verified or that raw data was received. `verified_from_raw_transaction` is **never trusted from a client-supplied boolean**: server sets this flag in the signed quote only after real validation. If raw data was required but not disclosed, the service must offer metadata-only scope or refuse a deep quote, not invent data.

## 5. One-shot payment and results

The customer uses their **own wallet** to create the native SOL System Program transfer of the exact lamports to the configured **commercial** receiver with a unique quote Memo in the same Solana transaction. HGUET does not sign/broadcast customer-protected transfers or accept secret seeds. The public donation wallet is NEVER the paid-service receiver.

Server verifies finalized execution evidence against the **expected cluster/genesis**, quote Memo, receiver, positive exact lamports, instruction index and event uniqueness. A public transaction signature is not authority to obtain someone else's Cloud result; `PaidCheckRequest` and `PaidCheckStatus` must prove possession of the private 256-bit quote claim secret.

Persistent state tracks the one quote, finalized payment, bounded check execution and separate assessment/payment receipt. If infrastructure fails after payment, retain retry/recovery rights or a documented refund path, not a new obligatory payment. Once a signed quote is issued, no post-payment complexity surcharge or market repricing is allowed.

### Signed report domains

- `HGUET-SOL-QUOTE/v1\0<canonical_body>`: commercial price and scope.
- `HGUET-CLOUD-ASSESSMENT/v1\0<canonical_body>`: Cloud risk findings, coverage and evidence, **bound to the same quote ID**, network/genesis, message/intent/subjects and disclosure scope.
- `HGUET-SOL-PAYMENT-RECEIPT/v1\0<canonical_body>`: one finalized native SOL settlement event and check.

Sign independently with reviewed, authenticated keys over canonical JSON (RFC 8785 JCS candidate). The CLI checks signatures itself; a boolean flag claiming signature validity is not evidence. Server **does not sign the final CLI-composed SecurityVerdict**; local hard policy DENY remains authoritative.

## 6. Network environments

| Network | Payment | Cloud role |
| --- | --- | --- |
| Mainnet | real SOL | production only |
| Devnet | test SOL | sandbox only |
| Testnet | test SOL | sandbox only |

Separate receivers, signing roots, state/claims and security defaults. Verify RPC `getGenesisHash`; never use a test-network transfer to authorize production. Testnet may be unstable and reset.

## 7. Privacy and risk limits

The metadata-only service can check declared program IDs and subjects but not infer transaction effects from a hash. A customer who opts into sending a raw transaction must be told if HGUET will forward it to third-party RPC providers. Local free mode sends no data to HGUET Cloud. No persistent client account or reusable identity exists to guarantee cross-session spending enforcement; such protection requires separately authenticated policy/signer integration.

Treat unknown Token-2022 extension, CPI effect, RPC failure, stale mandatory source or unsupported transaction format as **UNKNOWN** under strict mandatory coverage. Server Cloud risk may inform WARN/DENY according to explicit policy but **cannot override** a known local DENY.

## 8. Testing / production blockers

- Protobuf schema compilation; JSON Schema/fixtures; cross-repo content pinning.
- Real PQ TLS handshake, group/certificate/cipher verification and downgrade tests across supported platforms.
- Exact USD-to-lamports integer math, 24h FX age/5% reference policy, deterministic complexity-tier limits.
- Quote signature/fee cap, raw-prequote consent, checked input hashes, zero-lamport rejection.
- Finalized SOL settlement, Memo matching, wrong receiver, one-event/one-claim uniqueness, timeout/retry/refund.
- Quote ID/message/network/subject binding through both signed CloudAssessment and separate PaymentReceipt.
- Privacy, anonymous quote DDoS controls, credential/claim secrecy and signer enforcement.
- End-to-end Rust client/server tests and real Solana Devnet tests **before** any paid production launch.

This document specifies the desired system; it **does not claim** those tests have been run. See [public interoperability](interoperability.md), [security](security.md), [CLI commands](cli-interface.md).
