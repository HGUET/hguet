# HGUET CLI — Primary technical references and fact-check notes

**Checked:** 2026-11-13. These are external specifications and docs; link targets may evolve. Design choices remain HGUET proposals until implemented and tested.

## Solana

- [Solana: simulateTransaction RPC](https://solana.com/docs/rpc/http/simulatetransaction) — encoded transaction, commitment, `sigVerify`, `replaceRecentBlockhash`, `innerInstructions`, `minContextSlot`, account return and simulation error. **Unsigned can be simulated**, but this does not authenticate an agent's intent.
- [Solana: Versioned Transactions](https://solana.com/docs/core/transactions/versioned-transactions) — legacy, v0, and v1 formats. The contemporary docs describe a **v1 format with 4,096-byte maximum and no address lookup tables**. Confirm implementation crate support rather than assuming v0 is the latest.
- [Solana: Transaction Introspection](https://solana.com/docs/core/transactions/transaction-introspection) — address resolution, loaded v0 ALT addresses and decoding nested CPI effects; example JS introspection approach, not necessarily a Rust API.

## Machine-to-machine payment models

- [Solana: x402 V2](https://solana.com/docs/payments/agentic-payments/x402) — `PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, `PAYMENT-RESPONSE`; CAIP-2 Solana network IDs, mint+base units+payTo, selected scheme and restrictions.
- [x402 specification V2](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md) — protocol fields, authority of resource requirement and scheme binding.
- [Solana: MPP](https://solana.com/docs/payments/agentic-payments/mpp) — payment challenge and credential, one-off charges vs metered sessions and cumulative vouchers. Current specs are Internet-Drafts.
- [Solana: Agentic payments overview](https://solana.com/docs/payments/agentic-payments) — comparison of MPP and x402; MPP is **not** MCP.

## PQ/TLS and intent/report integrity

- [IETF RFC 10024](https://www.rfc-editor.org/rfc/rfc10024.html) — TLS 1.3 hybrid groups including **SecP384r1MLKEM1024**.
- [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM.
- [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) — ML-DSA; ML-DSA-87 signature algorithm.
- [OpenSSL](https://docs.openssl.org/) — provider/API support must be checked for real TLS1.3 hybrid KEM and ML-DSA certificates with the pinned version.
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) — JSON Canonicalization Scheme (candidate for trusted intent/report signature payload).

## Implementation verification checklist

Before coding, verify from current official docs and tests:

1. Solana SDK crate and Rust compiler support **legacy, v0, v1** formats and Token-2022 semantics actually claimed by release.
2. In the chosen RPC client, sigVerify and replaceRecentBlockhash are used in compatible modes; the request reliably preserves original message identity.
3. Address lookup and CPI introspection produce fully resolved addresses and structured effects (no indexed-account guessing).
4. OpenSSL/crypto provider version negotiates **the exact required PQ hybrid group**; independently validate ML-DSA-87 server **and client** authentication across supported platforms.
5. No optional network-intelligence source (STRIDE, SIRN, Watchtower, commercial feeds) is described as formally integrated until approved and operational.
6. The service never claims official Solana Foundation affiliation, guaranteed transaction safety or compliance accreditation.

## Product status

This folder contains **design specifications** only. It is deliberately explicit about unsupported behavior, threat-model assumptions and the gap between real-world execution and hypothetical simulation.