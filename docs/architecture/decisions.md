# HGUET CLI — Architecture decisions (ADRs)

**Status: approved design direction, implementation pending.** These decisions summarize the user-selected product model and deliberately reject unnecessary infrastructure.

| ID | Decision | Rationale | Consequence |
| --- | --- | --- | --- |
| ADR-001 | One free, open-source Rust CLI | useful distribution, auditability, integrations | Apache-2.0; no required Cloud subscription |
| ADR-002 | Closed-source, paid Cloud in `HGUET/server` | differentiated continuously maintained intelligence | public versioned client protocol; private analytics |
| ADR-003 | No wallet or custody functionality | reduce risk, complexity and regulatory exposure | never sign/broadcast or request wallet keys |
| ADR-004 | CLI-first registration, payment and usage | no web cabinet | Cloud account commands available in CLI |
| ADR-005 | Local simulation via user's RPC | avoid free-mode dependency on our infrastructure | local ≠ offline; disclose RPC data exposure |
| ADR-006 | Check intent + transaction effects, not only RPC success | meaningful value for autonomous payments | trusted intent provenance is mandatory for strict decisions |
| ADR-007 | Native Rust executable with JSON output | convenient for agents and CI | documented exit codes, deterministic schema |
| ADR-008 | PQ-capable TLS 1.3, no custom cipher, no VPN | robust transport without reinventing cryptography | prove negotiated KEM and mTLS in interop tests |
| ADR-009 | Commercial API reachable by authenticated CLI clients | users do not call HTTP API directly | cannot prove peer is “official binary”; device credentials authorize calls |
| ADR-010 | No proprietary protocol-only “security by obscurity” | open CLI must be inspectable | public versioned schema and code |
| ADR-011 | Security rules are deterministic first | auditable and reproducible | ML-assisted heuristics, if any, remain advisory |
| ADR-012 | Hard boundaries before powerful capabilities | eliminate silent bypass claims | client signer must enforce the verdict externally |

## Deferred

- Onchain smart-account enforcement and Solana smart contracts: **not in scope** for the first HGUET product.
- Wallet signing and settlement services: **not planned**.
- Global irrevocable budgets from a standalone local CLI: **cannot be guaranteed**.
- Dynamic AI interpretation of payment intent as an authority: **not accepted**.
- Running a universal Solana threat monitor locally: **not required**; optional Cloud enhancement.
- Storing private analytics, paid threat feeds or commercial backend in this public repository: **rejected**.

## Open engineering decisions

- Exact maintained modular Solana crates and a tested minimum supported Rust version.
- Native TLS library, OpenSSL provider and platform packaging matrix for PQ mTLS.
- Cloud protobuf message versioning and deprecation window after interoperability tests.
- Independent security review scope, adversarial benchmark and pricing model.
- Final license/third-party dependency notices; current repository LICENSE must remain authoritative.

## Change control

Any change that weakens the above trust guarantees requires a dedicated architecture review, threat-model update, tests and a user-approved change to product scope. No silently added custody, mandatory Cloud mode or proprietary CLI logic.

For rationale and dependencies, see [README](README.md), [security](security.md), [cloud protocol](cloud-protocol.md).