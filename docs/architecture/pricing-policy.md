# HGUET — Competitive complexity-based SOL pricing

**Status:** Proposed pre-release tariff policy, **not a published binding offer** (2026-11-13).  
**Authority:** this public document describes what the CLI is allowed to quote and what the private server must calculate. See [accountless payment architecture](payment-per-request.md).

## Product decision

- **Free local CLI, paid Cloud only.** Pay for optional Cloud intelligence, not for the value of a protected transfer.
- **One check, one onchain native SOL payment**; no registration, USDC, prepaid wallet, subscriptions or service-credit ledger.
- **USD is the unit of account**, not a token. Server converts the quoted USD fee into exact **integer lamports**, using a trusted current-day **SOL/USD reference**.
- **Base tariff should be lower than comparable paid security APIs** when operating cost permits. Do not claim universally cheapest: some vendors have free quotas and published tiers may not be directly comparable.
- Quote is final **before** the user broadcasts SOL. Never dynamically add a surcharge after payment due to unexpected CPI, RPC cost or risk outcome.

## 1. Launch tariff proposal (USD reference, not SOL/USDC)

| Quote tier | Draft USD price | Included paid Cloud scope | Typical eligibility |
| --- | ---: | --- | --- |
| `basic` | **$0.0010** | cached network and subject reputation signals; no additional RPC simulation | ≤512 tx bytes, ≤4 top-level instructions, ≤16 resolved accounts, ≤2 lookup subjects |
| `standard` | $0.0030 | extra program/subject history and moderate correlation | ≤1,232 bytes, ≤12 instructions, ≤32 accounts, ≤6 lookup subjects |
| `complex` | $0.0060 | deeper correlation over additional programs and risk signals | ≤4,096 bytes, ≤24 instructions, ≤64 accounts, ≤12 lookup subjects |
| `extended` | **from $0.0100**, signed exact quote | explicitly requested extra source calls / independent simulation / bounded high-complexity jobs | above thresholds, supported additional programs or expensive features |

**Draft reference only**, subject to an actual competitor/product coverage comparison and unit-economics testing. The prices above are not live HGUET offers. Source comparison (observed 2026-11-13): [Utilia listing](https://www.x402-list.com/services/utilia-solana-preflight) showed $0.002–$0.008 per route but was marked **offline**, so not a verified active competing price. [GoPlus Security API](https://www.gopluslabs.io/en/security-api) lists a free tier plus paid monthly usage packages, with usage measured in **CU**, not uniform dollar-per-request. HGUET cannot assert that it undercuts GoPlus's free tier or compare CU to requests without usage weights.

**At low prices, onchain SOL transfer network fees and the RPC/feed costs can be material relative to the fee.** Measure gross contribution per tier and minimum viable invoice; adjust future published tariffs with advance notice, never mutate existing signed quotes.

## 2. What increases complexity — not transaction value

Use **observable work inputs**, not arbitrary reputational bias or the amount of SOL the agent intends to transfer:

1. **Transaction size / volume:** canonical wire bytes, supported transaction format, total static+resolved account count.
2. **Instruction fan-out:** top-level instruction count, unique program IDs and address lookup table resolution.
3. **Risk subjects:** number of distinct network+program+mint+recipient subjects the Cloud must query.
4. **Analysis depth:** supported Token-2022 extension effects, authority changes, program-upgrade history and requested cross-source correlation.
5. **Expensive optional work:** independent server-side RPC simulation or extra feed lookups, selected **explicitly before quote**.
6. **Batch size (future):** one quote for several transactions requires a new *atomic billed-batch* protocol and must not silently be inferred from current single-check message.

**Not charged by:** transfer amount, wallet balance, being flagged suspicious, a DENY outcome, a low confidence risk score, or random solver timing. Higher risk **alone** does not change price. The cost reflects chosen coverage and predictable work, not how much value HGUET claims to save.

### Deterministic tier selection

Compute the **highest tier demanded** by any supported bounded factor, never averaging large or opaque work down to basic. The thresholds above apply to declared/verified transaction metrics and the requested Cloud scope:

- Basic requires all Basic limits and only basic cached signals.
- Standard requires all Standard limits and no independent server simulation.
- Complex requires all Complex limits and documented supported adapters; if requested effects cannot be understood, return explicit UNKNOWN rather than pretending paid deeper analysis succeeded.
- Extended is required if any complexity limit exceeded **or** an expensive capability requested; publish exact price and maximum coverage with a **hard caller cap**. Unsupported workload can be **refused at quote time** instead of charged.

**Metadata-only privacy:** When the server receives only hashes/subject metadata, it cannot independently verify wire size, instruction count or simulate hidden CPI. It must price only the **explicitly requested and submitted subject/feature scope** plus bounded declared metrics, and clearly restrict coverage. Deep transaction analysis requires customer consent to submit necessary raw bytes *before* quoting or an independently verified compact proof scheme implemented later. Do not rely on an agent's unverified small-number claim to guarantee execution cost.

If the actual paid request has more complexity than the signed quote supports: **never auto-charge more**. Either complete within the pre-agreed bound with honest limited coverage, or return a documented retry/refund path. Do not turn a post-payment tier mismatch into silent revenue.

## 3. Current-day price reference: ±5% is acceptable

HGUET does **not** need second-by-second exchange quotes for micro-payments.

- Fetch a trusted **SOL/USD** reference (not SOL/USDC) and cache it with the **actual observation/publish timestamp**, source ID and quality flags.
- Refresh at least **once per UTC day**; preferably refresh every 4–12 hours in the background. The quote path reads cache and performs **no mandatory live oracle fetch on every check**.
- Accept a reference no older than **24 hours** (configured threshold) and not future-dated; if no acceptable current-day reference exists, suspend issuing new payable quotes until updated.
- **±5% is a tolerated approximate market-price deviation**, *not* an assertion that an unverified price is correct. When a credible independent comparison is available, if the deviation exceeds 5%, mark price uncertain and update from verified data or stop quoting. An unavailable independent comparison must not be represented as a verified ±5% guarantee.
- Discard zero/negative/non-finite, malformed, unauthenticated, obviously wrong, or strongly disputed readings. A 24-hour-old observation is *fresh enough for this commercial policy*, not for security assessment of onchain state.
- On the quotation, expose rate, feed observed timestamp, age and the fact that it is a daily reference. Quote **exact lamports** is then cryptographically signed for a short validity window (e.g., 90 seconds). The permitted 5% exchange-rate approximation does not permit **short-paying the signed invoice by 5%**.

### Correct fixed-point conversion

```text
usd_price_micros = (USD reference tariff) × 1_000_000, integer
sol_usd_micros   = (USD per SOL reference) × 1_000_000, integer
lamports_due     = ceil(usd_price_micros × 1_000_000_000 / sol_usd_micros)
```

Use checked integer or fixed-decimal arithmetic. Do not use IEEE `f64` or divide first and lose precision. Sign the integer inputs and **rounded-up integer output**. USD tariff, SOL/USD reference and onchain network fee are displayed separately. Devnet/Testnet use the **same reference conversion** to exercise logic but are paid in valueless test SOL and isolated sandbox receivers.

## 4. How CLI and server agree on complexity/price

Before payment:

```text
CLI: parse bytes, determine declared stats + risk subjects locally
 → choose network, data scope, desired capabilities and explicit max fee
 → PriceQuoteRequest includes those features and commitment to EXACT check
Server: bound, validate and price requested work deterministically
 → choose tier, tariff version, USD micros, cached SOL/USD rate
 → compute lamports, return signed PriceQuoteResult
CLI: verify tier + metrics hash + amount + network + expiry
 → human/agent-controlled wallet signs native SOL transfer
 → PaidCheckRequest must match quoted scope, tier and input hashes
```

- Quote must bind **pricing_policy_version**, **tier**, **complexity metrics**, **subjects digest**, **requested capabilities**, and all existing transaction/claim/network fields.
- CLI refuses quote above `--max-fee-lamports`; in automated mode, the external signer must enforce that limit too.
- Server checks quoted scope matches the actual work; downgrade/omission yields no false “complete” coverage.
- No secret tenant, reusable account, prepaid balance, membership, per-wallet reputation pricing or cookie/HTTP API.
- A quote must not be abused as an open-ended denial-of-service way to force expensive RPC calls before payment; provide a cheap price-only path, strict request size/quota, and rate-limit.

## 5. Tests and business gates

- Fresh 4/12/23-hour SOL/USD cache values accepted per configured age; 25-hour reference rejected, no quote.
- Two independent credible rates differ >5% → defer quote/refetch; ≤5% → choose approved canonical source and document tolerance.
- One USD reference tariff converted deterministically to integer lamports with checked ceiling.
- Signed quote fixed even if cached market rate changes by 5% before settlement.
- Basic, standard, complex, extended boundary tests: exact thresholds and ±1 byte/instruction/subject transitions.
- Metadata-only quote never claims independent transaction decoding/extra RPC simulation.
- Complex request disguised as Basic cannot force unquoted high-cost Cloud work or a surprise charge.
- No price surcharge based on DENY or transaction transfer amount.
- After paying once, outage gives retryable result or refund claim rather than charging again.
- Negative real-world margin at Basic triggers **pricing-policy review before launch**, not an unannounced retrospective charge.
- Confirm competitive positioning against *active, directly comparable* paid APIs with live quotes (free plans must be disclosed).

See [payment flow](payment-per-request.md), [public protocol](../../protocol/v1/README.md), and [cross-repository contract](interoperability.md).
