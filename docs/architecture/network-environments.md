# HGUET — Solana network environments

**Status:** Unreleased design draft. The [anonymous SOL payment contract](payment-per-request.md) and [pricing rules](pricing-policy.md) supersede any historical top-up/credit proposals.

## Supported clusters

| Transaction cluster | Example development RPC | Cloud mode | Service payment |
| --- | --- | --- | --- |
| Mainnet | `https://api.mainnet.solana.com` | production | **real native SOL**, paid per check |
| Devnet | `https://api.devnet.solana.com` | sandbox | **valueless test SOL**, paid per test check |
| Testnet | `https://api.testnet.solana.com` | sandbox | **valueless test SOL**, paid per test check |

User-provided RPC endpoints are supported but MUST be checked against expected **genesis hash**. Public example RPC services have usage restrictions and are not production infrastructure. Testnet is primarily for validator/network experiments, can reset and may have intermittent availability.

A local validator can be supported for explicit local tests but has **no shared Cloud payment mode** in the current draft.

## No reusable account credit

There is **no `topup`, `balance`, account or USDC** in the proposed Cloud architecture. Each Cloud security request receives a **server-signed one-use price quote** in USD, converted using a cached daily SOL/USD reference into **exact native lamports**. An external wallet then transfers SOL to a configured commercial receiver with a unique quote Memo. That one verified payment authorizes **one** check bound to message/intent hashes and a private claim.

Mainnet settlement uses real SOL. Devnet/Testnet settlement exercises the same verification code using test SOL without any monetary value or production access. Sandbox/production receiver addresses, claim stores, cryptographic signing roots and risk/usage data are isolated.

## Accounting and payment boundaries

- The [HGUET donation address](https://solscan.io/account/39iqkHNMqncEPp3p52zKwUHnYzk2MJbcaHyY4Hhg2fWC) is **not** a commercial treasury.
- Solana network fees are separate from the fee for HGUET Cloud analysis.
- Every quote binds **cluster name, verified genesis, environment, exact lamports, scope, claim commitment and expiry**.
- Payment is counted only after independently verified finalized transfer + matching Memo to receiver.
- The same onchain settlement cannot authorize two reports, and a Devnet/Testnet transfer can never purchase a Mainnet check.
- An RPC outage or Testnet reset must never affect the free local CLI or charge a second time for an already paid claim.

## Examples (planned commands)

```sh
hguet inspect tx.bin --offline --json
hguet check tx.bin --intent intent.json --mode local --network mainnet --json
hguet check tx.bin --intent intent.json --mode cloud --network devnet --max-fee-lamports 200000 --json
hguet check tx.bin --intent intent.json --mode cloud --network testnet --max-fee-lamports 200000 --json
hguet payment status QUOTE_ID --claim-file ./claim.hguet --json
```

**No binary or paid server has been released yet.** See [shared interoperability](interoperability.md), [protocol](../../protocol/v1/README.md), [security model](security.md).