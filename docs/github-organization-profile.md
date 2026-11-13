<div align="center">

# HGUET

### Security before the signature.

**Open-source security tools and real-time threat intelligence for AI-agent payments on Solana.**

[**hguet.fr**](https://hguet.fr) · [**Open-source CLI**](https://github.com/HGUET/hguet)

</div>

---

### We protect the moment before an AI agent pays.

An agent can execute a valid transaction that is still *wrong*: wrong recipient, wrong token, wrong amount, unexpected permissions, or a risky protocol.

**HGUET** is building an independent, Rust-based pre-transaction security layer that combines:

- **Transaction X-Ray:** decode and simulate the payment before signing.
- **Intent Verification:** compare the actual transaction with the authorized payment.
- **Local Policies:** free, inspectable checks for agent integrations.
- **Network Intelligence:** optional commercial enrichment with live Solana risk signals.
- **Verifiable Verdicts:** transparent `ALLOW / WARN / DENY / UNKNOWN` results.

### Our repositories

| Repository | What it is |
| --- | --- |
| **[hguet](https://github.com/HGUET/hguet)** | Free, open-source Rust CLI and security checks |
| **server** *(private)* | Proprietary, optional threat-intelligence SaaS |

**We never ask for wallet private keys, custody customer funds, or execute transactions on behalf of the customer.**

> **Status:** Early-stage development. No released, audited security product is being claimed.

### Support development

Voluntary Solana mainnet **SOL** donations help support HGUET's open-source development:

`39iqkHNMqncEPp3p52zKwUHnYzk2MJbcaHyY4Hhg2fWC`

This is **not** a Cloud billing or service-credit payment address.

---

<div align="center">

**Free to verify locally. Pay only for deeper intelligence.**

[Explore HGUET](https://github.com/HGUET/hguet) · [Website](https://hguet.fr)

</div>
