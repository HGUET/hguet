# HGUET CLI — Commands, configuration and accountless Cloud UX

**Status:** v0.2 design, **not implemented**. This replaces the old `register/login/topup/balance/usage` design. See [SOL payment specification](payment-per-request.md).

## Supported command grammar (proposed)

```text
hguet --version | --help
hguet inspect [TRANSACTION|-] --offline [--encoding binary|base64|base58] [--json]
hguet check [TRANSACTION|-] --intent PATH [--policy PATH]
            --network mainnet|devnet|testnet
            --mode local|cloud
            [--profile strict|review|explore] [--rpc URL]
            [--max-fee-lamports INTEGER] [--json]
            [--payment-signature BASE58] [--claim-file PATH]
hguet payment status QUOTE_ID --claim-file PATH [--json]
hguet policy validate FILE
hguet intent verify FILE [--trusted-key PUBLIC_KEY]
hguet doctor [--rpc] [--cloud] [--json]
hguet config show|set|unset|path
hguet completions bash|zsh|fish|powershell
```

**There are no commands for HGUET registration, login, credits, balance or prepaid top-ups.** Paid Cloud requires only an ephemeral quote claim and an onchain payment. The CLI itself never accepts or generates the user's wallet private key.

## Local mode (free)

```sh
hguet inspect tx.bin --offline --json
hguet check tx.bin --intent approved-intent.json --network devnet --mode local --json
```

- `inspect --offline` does **no network access**.
- `check --mode local` uses the **user-configured Solana RPC** (network access to that RPC but **none** to HGUET Cloud).
- Verify RPC genesis, transaction version (legacy/v0/v1 where supported), address lookup and mandatory source coverage. Invalid or opaque execution cannot silently yield ALLOW.
- Local mode works even when Cloud, SOL/USD price feeds or public faucets are unavailable.

## Cloud mode: no signers in HGUET

```sh
hguet check tx.bin --intent approved-intent.json --network mainnet \
  --mode cloud --max-fee-lamports 200000 --json
```

Proposed interactive path:
1. Perform free local evaluation. If a known local hard DENY is present, default to **not charging** for needless Cloud enrichment; deliberate override for additional investigation requires explicit consent.
2. Generate `quote_id` context and a 256-bit private `claim_secret` stored locally with restrictive file permissions; send its SHA-256 commitment and exact request bindings.
3. Receive and verify **server-signed PriceQuote** with a fresh SOL/USD market price, the **USD service tariff**, exact integer lamports, correct network/genesis, **separate commercial receiver**, memo reference, quote expiration, requested scope and maximum fee.
4. Display `<network> / REAL SOL` for Mainnet or `<network> / TEST SOL` for Devnet/Testnet. Show both USD reference and fixed SOL invoice. **No auto-signing**. The caller uses an external wallet; CLI may export the unsigned transfer+memo for compatible wallet integration.
5. After the customer wallet broadcasts the payment, supply its Solana signature and private claim to HGUET Server. Server independently verifies finalized transfer and that one quote/payment has not previously been spent on a different check.
6. Verify **signed CloudAssessment** and **separately signed PaymentReceipt**. Merge Cloud evidence with mandatory local checks; CLI composes final `ALLOW / WARN / DENY / UNKNOWN`.
7. On timeout or disconnect, use `hguet payment status QUOTE_ID --claim-file PATH`. No second charge. If paid service remains unavailable, refer claim to retry/refund workflow.

Automated agents must be explicitly connected to a **customer-controlled external signer** with per-check fee cap and consent. HGUET cannot bypass wallet authorization or privately hold seed phrases.

## Network configuration

`--network mainnet|devnet|testnet` binds the **analyzed transaction** and SOL payment; the paid check's cluster and quote's cluster must match. Verify `getGenesisHash` for all RPC sources. Environment mapping is fixed:

| Network | Cloud account / balance | Payment and receiver |
| --- | --- | --- |
| Mainnet | **none** | real SOL → production treasury |
| Devnet | **none** | test SOL → sandbox receiver |
| Testnet | **none** | test SOL → sandbox receiver |

The `--max-fee-lamports` cap is a caller-side upper bound, **not a tariff**. Accepting a higher quote silently is forbidden. No Cloud mode default in a local-only command.

## CLI inputs and outputs

- `TRANSACTION` may be a bounded binary file or stdin `-`. Base64/Base58 must be explicitly declared or robustly validated. Initial input caps must track tested Solana legacy/v0/v1 format limits.
- Intent must originate from an independently configured trusted authority; an agent-supplied `intent.json` alone is not proof.
- `--json` emits **one complete JSON object on stdout**, diagnostic text on stderr. No prompts when stdin is non-TTY; pending payment state should have its own machine-readable status with invoice/claim identifiers but no secrets in shared logs.
- Report includes exact message/intent hashes, network/genesis, simulation context, supported coverage, findings, cloud status and explicit limitations.
- Known decision exit codes remain: `0 ALLOW`, `10 WARN`, `20 DENY`, `30 UNKNOWN`, `40 bad input`, `50 infrastructure`, `60 paid Cloud/payment failure`. A pending unpaid quote is NOT a completed verdict.
- Never print `claim_secret`, wallet secrets, raw private intents or full SOL payment proof in unredacted shared diagnostics.

## Configuration and secret storage

Non-secret settings: approved RPC endpoints, default `mode=local`, default network, strict profile, output format, market quote cap and privacy preferences. The ephemeral claim secret belongs in **a single-claim local file or OS-protected store**, never HGUET account credentials. Use atomic restrictive file writes, no world-readable claims, and clear retention/erase/recovery instructions.

## Important limitations

- Paying SOL does not atomically guarantee an offchain result. A finalized transfer creates a recoverable one-check claim; it may require retry or approved refund on server outage.
- Test SOL has no real-world cash value even though test invoices use an actual SOL/USD conversion for engineering parity.
- Native SOL payments here use **HGUET's own Protobuf payment-proof protocol**, not the SPL-oriented Solana x402 exact scheme.
- A Cloud signature authenticates the server's assessment, **not the final CLI-composed verdict** and not guaranteed network safety.

## References

[Payment architecture](payment-per-request.md) · [Public Protobuf](../../protocol/v1/README.md) · [Solana analysis](solana-engine.md) · [Final verdict](verdict-schema.md) · [Threat model](security.md).