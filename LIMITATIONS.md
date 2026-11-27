# Current limitations — pre-alpha

- The CLI is not a wallet or signer; automatic signing permission is structurally false. DENY means a supported violation; UNKNOWN is not permission. A syntax-valid policy or valid signature is not proof of safety.
- Legacy/v0/v1 parser behavior needs differential verification against supported Solana SDK/runtime versions; a parser accepting v1 does not prove live cluster support.
- Original-wire direct SOL and checked-token declarations are not total spending. CPI, fees, rent, opaque programs, multisig, lookup resolution, token extensions and account-state effects may remain unresolved.
- Signed PaymentIntent v1 binds exact bytes and trusted issuer but is not a semantic purchase authorization; it lacks a general recipient/purpose grant and does not establish signer-side enforcement.
- RPC is opt-in; its simulation and later state reads are advisory, non-atomic and may be incomplete or wrong. Replacement blockhash and disabled provider signature verification limit what simulation establishes.
- No finalized transaction forensic audit, full historical state reconstruction, x402/MPP verifier, released SDK or production signer is claimed.
- Existing benchmark is primarily synthetic and authored within the project; mock/transport tests are not runtime validation or an independent audit.
- Cloud loopback experiments are not a public paid service. The free release is independent.
- No release platform, binary, publisher signature, SBOM or external review is claimed until actual evidence is published.

[Implementation](docs/implementation/README.md) · [Coverage matrix](docs/release/community-0.1.0/COVERAGE_MATRIX.md) · [Release gates](docs/release/community-0.1.0/RELEASE_GATES.md).

Phase 1.1 adds bounded stdin, report v2 and a reusable engine. Hosted results apply only to their source snapshots; see the [acceptance record](docs/release/community-0.1.0/PHASE_01_1.md). A scoped MATCH never proves safety, actual execution or total spending. No final release readiness is claimed.
