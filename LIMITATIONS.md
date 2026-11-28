# Current limitations — developer preview

HGUET is an unreleased, non-custodial security and transaction intelligence toolkit. The following limits apply even when a test suite passes.

| Boundary | What is not established |
| --- | --- |
| Authorization | No result permits signing or broadcasting. DENY is a supported violation; UNKNOWN and scoped MATCH are not approval. HGUET cannot enforce a wallet's behavior by itself. |
| Wire parsing | Selected legacy/v0/v1 cases are SDK- and LiteSVM-validated, not comprehensive live-cluster compatibility. |
| Program semantics | Supported layouts are instruction-specific. Opaque programs, many Token-2022 extensions, broader System/Stake/Loader/DEX semantics, multisig and hooks remain incomplete. |
| Asset flow | Gross declarations are not net loss, wallet-specific spend or actual execution; fees, rent, supply, CPI and withheld amounts are not globally reconciled. Unknown values never mean zero. |
| Authority | Declared owner/delegate changes do not prove current permissions, effective control, irreversibility or final state. Approvals are not additive. |
| Semantic diff | Position-based comparison and normalized fingerprints, not edit alignment or semantic equivalence; unresolved ALT identity is not a resolved address. |
| RPC simulation | Single-provider advisory claims; replacement blockhash, sigVerify=false and later non-atomic snapshots. No finality or execution proof. Transaction bytes are disclosed to the provider. |
| Historical audit | Requests finalized metadata and verifies returned signatures; no independent ledger inclusion or consensus proof. Historical loaded addresses are provider claims; no full historical state reconstruction. One public legacy/Devnet case has passed end-to-end; broader mainnet/v0/v1/token/CPI and independent-provider cases remain unverified. |
| Signed intent and policy | Exact message binding and limited direct restrictions do not establish a general recipient/purpose authorization or total spending bound. Independently pinned issuer and policy are essential. |
| Reports and lab | Passive HTML and synthetic examples are available; not authenticated reports or a comprehensive accessibility/browser audit. No DOT export. Reports may contain sensitive transaction details. |
| Verification | Tests are scoped to their fixtures and exact source snapshot. Project-authored synthetic benchmark is not an independent audit or a traffic sample; broader validator, fuzz and external review are open. |
| Integration/release | No released SDK, x402/MPP verifier, production signer, public binary release or verified supply-chain package yet. Cloud experiments are not a public paid service. |

See [current evidence](docs/release/community-0.1.0/VERIFICATION.md), [supported programs](SUPPORTED-PROGRAMS.md), [coverage matrix](docs/release/community-0.1.0/COVERAGE_MATRIX.md) and [release gates](docs/release/community-0.1.0/RELEASE_GATES.md).
