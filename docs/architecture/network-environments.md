# Solana clusters and SOL-first Cloud billing

**Status:** v0.1 proposed design; no payment processor or three-cluster server is implemented. Updated 2026-11-13.

## Decision: one cluster-aware security engine, separated billing environments

HGUET analyzes prospective transactions on all three public Solana networks:

| CLI network | Standard RPC (development only) | Product environment | Settlement asset |
| --- | --- | --- | --- |
| `mainnet` | `https://api.mainnet.solana.com` | `production` | **real native SOL** |
| `devnet` | `https://api.devnet.solana.com` | `sandbox` | **test native SOL** |
| `testnet` | `https://api.testnet.solana.com` | `sandbox` | **test native SOL** |

Devnet is primarily for application integration and Testnet is primarily for validator/network testing; the latter may be intermittent. Both have test SOL available through airdrops and may reset. Production applications require a production RPC, not the public rate-limited example.

All supported networks must be differentiated by **verified genesis hash**, not only display name, RPC hostname, account address or signature. The CLI may also inspect a local validator by explicit opt-in, but that is offline/local developer mode, not shared Cloud billing.

## Native SOL first, USDC optional later

For the initial implementation, paid Cloud **top-ups use native SOL**, not SPL tokens. This reduces deployment and reconciliation complexity across all three networks. No token mint or associated token account is required for an ordinary native SOL transfer. Future USDC acceptance must be added behind explicit asset support, network-specific verified mint IDs and dedicated tests; never accept a token merely because its symbol says USDC.

The free CLI has **no fee** for local analysis. Charging is **not a commission on the protected payment amount**. Only explicitly requested **Cloud intelligence** consumes prepaid HGUET service credits.

Onchain SOL amounts use **integer lamports** (1 SOL = 1,000,000,000 lamports), never floating-point money. HGUET service credits are separate integer accounting units. The server publishes a signed price schedule and signed top-up invoice. For the simplest MVP, set price schedules in integer service credits with fixed SOL top-up packages; SOL exchange-rate exposure is a known business trade-off. If fiat-pegged prices are introduced later, conversion must use an authenticated bounded-time quote with disclosed rate and expiry.

## Top-up and check lifecycle

```text
hguet topup 0.1 --asset SOL --network devnet
   -> CLI obtains server-signed invoice (cluster/genesis, asset=SOL,
      exact lamports, treasury destination, invoice reference, expiry,
      sandbox/production environment and service credit units)
   -> user signs ordinary SOL payment using their own wallet
   -> server verifies actual transfer on the invoice's EXACT cluster
   -> only corresponding environment's credit ledger is incremented ONCE

hguet check transaction.bin --network devnet --mode cloud
   -> CLI verifies local intent/policy and obtains signed Cloud price quote
   -> server reserves and captures SANDBOX credits only
   -> CLI verifies CloudAssessment and composes final SecurityVerdict
```

No HGUET component ever requests the customer's wallet private key, signs their payment, or broadcasts their protected payment transaction. External wallet transfer to pay **HGUET's service** is distinct from the transaction being security-checked.

## Absolute environment isolation

1. `production` has real SOL invoices and real paid credits; `sandbox` uses valueless test SOL and **test credits only**.
2. Production and sandbox must have separate signing roots/certificates, treasury receiver configuration, invoices, credit journals, rate limits and settlement watchers. Prefer separate databases and deployment credentials. A tenant may have separate sandbox and production accounts but **never a fungible balance**.
3. No Devnet/Testnet transfer can fund production, even with the same wallet pubkey, invoice reference or transaction signature.
4. Every invoice, settlement, ledger entry, Cloud check and signed receipt is bound to `environment + network/genesis + tenant + request ID`.
5. A changed RPC endpoint must pass `getGenesisHash` validation or the payment is rejected before credit.
6. Test credits are resettable, non-withdrawable and have no real monetary value. Devnet/Testnet airdrop abuse must be controlled with quota and demo limits; airdrops are not free unlimited compute.
7. A sandbox Cloud result is labeled `TEST`, even if it analyzes a hypothetical valid transaction. It must not be misrepresented as a production security guarantee.

## Invoice verification

Native SOL invoice fields: invoice ID, issue/expiry time, environment, network ID, genesis hash, `asset=SOL`, **integer lamports**, verified receiver and an invoice-binding reference. The server must inspect the finalized transfer (destination, positive lamports received, source/wallet constraints when specified, finalized commitment and reference matching) and apply a unique settlement event key. A memo alone is not payment proof; a bare customer-supplied signature is not settlement proof.

Ambiguous matching must go to review, not silently credit another account. An ordinary transfer into the donation wallet is **never** a service top-up. The publicly listed donation address `39iqkHNMqncEPp3p52zKwUHnYzk2MJbcaHyY4Hhg2fWC` is for gifts only and is NOT the mainnet treasury address; server operators must configure separate receivers per cluster/environment.

## CLI surface (planned, not implemented)

```sh
hguet inspect tx.bin --offline --json
hguet check tx.bin --intent intent.json --network mainnet --mode local --json
hguet check tx.bin --intent intent.json --network devnet --mode cloud --json
hguet check tx.bin --intent intent.json --network testnet --mode cloud --json

hguet topup 0.1 --asset SOL --network mainnet
hguet topup 2 --asset SOL --network devnet
hguet topup 2 --asset SOL --network testnet
hguet balance --network devnet --json
hguet usage --network testnet --json
```

For a paid invoice, network selection must be explicit and reconfirmed; no silent fallback to Mainnet. Display `MAINNET / REAL SOL` or `DEVNET / TEST SOL` or `TESTNET / TEST SOL` prominently.

## Acceptance cases

- Each supported RPC identifies its expected network/genesis; wrong endpoint fails closed.
- Native SOL invoice is matched by exact integer lamports, cluster/genesis, receiver and invoice reference, with finalized evidence.
- Devnet/Testnet top-ups result **only in sandbox credits**, never production balance.
- Production and sandbox reject each other's device credentials, signed invoices, request IDs and paid receipts.
- Idempotent duplicate settlement or check retry credits/charges **once**.
- Reorg/rollback, expired invoice, wrong receiver, uncertain transfer and unsolicited donation remain uncredited.
- RPC/public faucet outage doesn't break free offline inspection; Cloud returns clearly degraded status.
- No token accounts/mints are assumed for native SOL. Future USDC requires separate verified token handling.
- No charge based on security-checked transaction size; fees are for optional Cloud checks only.

## References

- [Solana clusters](https://solana.com/docs/references/clusters)
- [Solana faucets](https://solana.com/developers/cookbook/development/airdrops-and-faucets)
- [Solana lamports](https://solana.com/docs/core/accounts/account-structure)
- [Public CLI/server interoperability](interoperability.md)
- [Public draft Protobuf protocol](../../protocol/v1/hguet.proto)

**All payment parameters and commands in this document are examples, not live prices or deployed service addresses.**
