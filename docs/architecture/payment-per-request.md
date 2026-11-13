# HGUET Cloud — SOL pay-per-request and automatic USD quotation

**Status:** Unreleased architecture draft, **not implemented**. Updated 2026-11-13.  
**Current design authority:** this public document supersedes earlier CLI/server discussions of registered accounts, prepaid credits and USDC top-ups. The private server must follow the same rules.

## Decision

- **One Cloud check = one native SOL payment.** No registration, no HGUET account, no subscriptions and no stored service balance.
- **Price is defined in USD** (integer microdollars for precision); the server automatically quotes the precise **SOL amount** from a current-day cached SOL/USD reference. **No USDC token is used** on any cluster.
- The customer/agent's **external wallet** signs and sends the service payment; HGUET neither requests wallet secrets nor signs/broadcasts the protected payment.
- The free CLI's local checks remain free. Only explicitly opted-in Cloud intelligence has a charge. **No fee proportional to the value of the protected transaction**.
- Mainnet bills real SOL; Devnet and Testnet use **valueless test SOL** and independently isolated sandbox service. Same payment code path, different economics.

## 1. Two-stage paid request (payment cannot be atomically coupled to remote compute)

```text
AI agent / operator -> public HGUET CLI
   -> free local inspection, trusted intent and policy
   -> choose --network devnet|testnet|mainnet and --mode cloud
   -> generate random quote/request ID + 256-bit private claim secret
   -> query HGUET Cloud over authenticated PQ TLS 1.3

HGUET Server -> signed PriceQuote:
   USD service price (fixed price tier)
   current-day cached SOL/USD reference, source ID and observation timestamp
   exact integer lamports, network + genesis, receiver,
   expiration, unique quote ID and private claim-secret commitment
   message + intent digests, requested features, data disclosure

CLI -> display SOL invoice and USD reference price
   -> customer's separate wallet signs and sends native SOL
   -> System Program transfer + quote reference in the SAME transaction

CLI -> PaidCheckRequest:
   original quote ID + exactly bound check parameters,
   payment transaction signature + claim secret
Server -> verifies independent onchain settlement + uniqueness
   -> performs risk enrichment; signs CloudAssessment
   -> signs a distinct PaymentReceipt (not a balance or credit)
CLI -> verifies both, merges findings with local mandatory checks
   -> FINAL client-composed SecurityVerdict
```

**A single request submission can carry a payment proof, but cannot generate confirmed onchain funds by itself.** First obtain the price quote, then the user pays onchain, then submit the payment reference. A lost connection is recoverable using `PaidCheckStatus(quote_id, claim_secret)`; this capability is bound to one paid check, **not a reusable user account**.

## 2. Price oracle and exact lamports (no stablecoin dependency)

Use an independently authenticated, explicitly configured **SOL/USD** market-data feed; e.g., an official Pyth SOL/USD feed, not a random token symbol or client-supplied URL. Evaluate freshness from the feed's actual **price-update timestamp** (not just API response time), confidence/quality and publisher availability. A second independent observation can detect extreme divergence; do not pretend two mirrors of the same feed are independent.

**Current-day pricing policy:** use a trusted **cached SOL/USD reference** whose actual price-update timestamp is no older than **24 hours**, refreshed at least once daily (preferably every 4–12 hours, out of request path). An approximate deviation up to **5%** against a credible independent market observation is acceptable for these micro-payments; above 5%, suspend quoting and refresh/reconcile. This is a *tolerance*, not a guaranteed oracle accuracy claim. No mandatory live feed lookup per Cloud request. Reject stale, missing, nonpositive or implausible rates. **Never apply ±5% tolerance to the exact lamports due on a signed invoice.** See [competitive complexity-based pricing](pricing-policy.md).

Use checked integer/fixed-point arithmetic:

```text
usd_price_micros  = tariff price in USD * 1,000,000  (integer)
sol_usd_micros    = verified USD per 1 SOL * 1,000,000
lamports_due      = ceil(usd_price_micros * 1_000_000_000 / sol_usd_micros)
```

Use `u128` or arbitrary-precision checked integer intermediates, no `f64` in financial computation. Reject 0 lamports, overflow, very small amounts below the separately approved minimum viable invoice, or price above the caller's **maximum allowed lamports**. Service fees and Solana transaction fees are distinct and displayed separately where possible.

Example only: tariff **$0.01/check**, market SOL/USD **$100**, invoice **100,000 lamports = 0.0001 SOL**. These values are mathematical illustrations, not today's exchange rate or published HGUET pricing.

**Quote validity:** e.g. 90-second TTL; signed quote freezes the lamport amount until expiry. A new price observation does **not** retroactively alter an issued invoice. Expired quotes require requoting before payment; late/ambiguous payments go to claim/refund handling rather than silently lost or credited to another request. No guarantee that finality completes before expiry; distinguish **payment submitted before expiry** versus **finality attained later**, and define a bounded grace/reconciliation policy using onchain block time/slot.

A cached direct SOL/USD feed makes **USDC unnecessary even as an oracle reference**. `SOL/USDC` is merely one potential market pair, with an additional USDC peg assumption; prefer `SOL/USD` to keep the design independent of the token entirely.

### Complexity-based fee — quote before payment

The initial suggested tariff is **$0.001 basic**, **$0.003 standard**, **$0.006 complex**, and **from $0.010 extended**, subject to operating cost and genuine competitor checks. Tier reflects supported work and request volume (bytes, instructions, resolved accounts, risk subjects, supported program effects and explicit extra RPC/deep lookups), **not transaction value or risk severity**. Price is signed **before** payment and cannot increase after transfer. Metadata-only requests cannot secretly trigger full simulation; unsigned client-declared complexity metrics are not evidence of actual execution. See [pricing-policy.md](pricing-policy.md).

## 3. Three networks, distinct deployments and receiver addresses

| Solana network | Payment | Cloud environment | Isolation |
| --- | --- | --- | --- |
| Mainnet | real native SOL | production | production treasury, keys and DB |
| Devnet | valueless test SOL | sandbox | test receiver, keys and DB |
| Testnet | valueless test SOL | sandbox | test receiver, keys and DB |

Verify `getGenesisHash`; signer network and receiver must match quote. Sandbox uses real-world reference SOL/USD solely to test **the same conversion code**, not because test SOL has a market price. Clearly mark `SANDBOX — NO REAL MONEY`.

Production/sandbox quote signing keys, receiver addresses, claim records and environment identifiers must not be interchangeable. An address used publicly for HGUET donations (`39iqkHNMqncEPp3p52zKwUHnYzk2MJbcaHyY4Hhg2fWC`) is **NOT** a commercial receiver.

## 4. Invoice and payment matching

Signed quote includes a unique unpredictable 128-bit quote ID, request/intent digests, price/lamports, receiver, chain identity, expires-at, claim-secret SHA-256 commitment and configured SOL/USD price-reference provenance and pricing tier/metrics digest. Use separate domain `HGUET-SOL-QUOTE/v1` and a maintained cryptographic signature; JSON canonicalization follows public schema. The server verifies its own signed quote from durable storage, not untrusted client arguments.

**MVP payment format:** native SOL `SystemProgram.transfer` to the server-configured receiver **plus a Memo containing the quote ID** in the same atomic onchain transaction. The CLI can prepare a transaction for an external wallet but **cannot sign with the customer's key**. Not every wallet supports attaching a memo: document a compatible wallet adapter or separately approved unique-invoice-receiver alternative before production.

Server checks finalized `getTransaction` evidence on **correct genesis**, System Program transfer destination, positive exact transfer lamports, successful transaction, memo matching the signed quote, occurrence counts and unique transaction signature + instruction index. Reject extra conflicting transfers or ambiguous duplicated memos. Do not merely check account balance, tx signature supplied by user, public token labels, or memo without actual funds transfer. Same onchain event can settle **only one** quote/check.

A quote claim secret is **not** sent to Solana; the payer keeps it locally (file access limited). Server stores only its hash/commitment, and requests prove possession through authenticated TLS. A public chain observer cannot redeem the visible transaction signature without the claim secret. The quote and claim secret are tied to **one** analysis and have bounded lifetime.

## 5. Recovery, payment fairness and idempotency

Database records still exist, but they are **per-payment claims and durable results**, **not accounts, users or balances**:

```text
QUOTE_ISSUED -> PAYMENT_OBSERVED -> PAYMENT_FINALIZED
 -> CHECK_RUNNING -> CHECK_COMPLETE -> RECEIPT_ISSUED
                          |
                          +-> FAILURE_RETRYABLE -> CHECK_RUNNING
                          +-> FAILURE_REFUND_REQUIRED -> REFUNDED
```

- Idempotency key: `(environment, genesis, quote_id, payment_signature, instruction_index)`, with unique constraints and canonical request binding.
- Same settled payment + same claim + same check -> return same result with **no second charge**.
- Same payment reused for a different check/claim -> reject, no new paid service.
- RPC delay/reorg -> pending; don't claim it is finalized until verification succeeds.
- Provider outage **after payment** -> preserve an authenticated, resumable one-check claim, do not force second payment. If service cannot be delivered within contractual limit, initiate refund or approved recovery; refunds are signed by a separately controlled HGUET treasury workflow and reconciled onchain.
- In a truly accountless design, client must securely retain the local claim secret/receipt. Lost claim credentials require a narrowly scoped support/recovery procedure; do not promise frictionless recovery without identity.

**Threat model:** quote spam, oracle manipulation/staleness, payer front-running, memo reuse, wrong cluster, wrong receiver, replay, fork/reorg, stolen claim secret, duplicated billing and payer refund abuse.

## 6. Transport and identity

TLS remains **server-authenticated** with the required tested hybrid PQ profile and authenticated report signatures. **Do not require a long-lived client certificate, account enrollment or login** for public paid checks. The temporary claim secret is the authorization for **one** quote/result; paid service is gated by validated funds, signed quote and rate limits. No secret in binary, URL, log or chain memo.

Strict traffic admission rules must protect anonymous quotes, PQ handshake CPU and expensive RPC/database work. Limit quotes by coarse transport/IP controls with privacy-safe operational telemetry, price quote TTL and outstanding claim caps. Never claim “only our official binary can call the server”; the wire protocol is public.

## 7. Planned CLI command contract

```sh
hguet check tx.bin --intent approved-intent.json --network mainnet --mode local --json
hguet check tx.bin --intent approved-intent.json --network mainnet --mode cloud --max-fee-lamports 200000 --json
hguet check tx.bin --intent approved-intent.json --network devnet --mode cloud --max-fee-lamports 200000 --json
hguet check tx.bin --intent approved-intent.json --network testnet --mode cloud --max-fee-lamports 200000 --json
hguet payment status QUOTE_ID --claim-file ./claim.hguet --json
```

Automated agents should support an **external signer/wallet integration** and explicit maximum fee, rather than interactive prompts. HGUET never automatically signs a user's wallet transaction. API should allow the workflow to supply an existing payment signature after external wallet transfer. Local CLI remains useful without Cloud or price-oracle access.

## 8. Public compatibility boundary

- The public `protocol/v1/hguet.proto` must expose **anonymous quote + paid check + payment status**, not mandatory `AccountGet / EnrollStart / CreditBalance / TopUp` for current draft.
- Signed quote schema is distinct from signed CloudAssessment and signed PaymentReceipt. **Server does not sign final CLI SecurityVerdict.**
- Private server pins the exact public commit; implements environment isolation and onchain payment verifier, not a global credit ledger.
- This is a breaking **draft** rework before any released stable protocol. Do not claim production v1 backward compatibility.
- Run shared negative tests for stale/incorrect oracle price, expired quote, double spending, claim theft, wrong genesis, Testnet→Mainnet conversion, malicious memo and RPC-finality failure.

## 9. References

- [Pyth price feed semantics](https://docs.pyth.network/pro/payload-reference) — price update timestamp vs carried-forward price
- [Pyth best practices](https://docs.pyth.network/pro/best-practices) — stale/confidence checks
- [Solana transaction RPC](https://solana.com/docs/rpc/http/gettransaction)
- [Solana native transfer documentation](https://solana.com/docs/payments/how-payments-work)
- [HGUET shared interoperability design](interoperability.md)

**A signed quote is an authenticated price offer, not an escrow, a guarantee of eventual execution, or an onchain atomic swap.**
