# Security policy

HGUET is pre-alpha and has no supported production release. The security model is non-custodial and BLOCK-only. No result authorizes signing or guarantees execution, safety or total spending.

## Reporting vulnerabilities

Use GitHub private vulnerability reporting if enabled. If unavailable, open a public issue requesting a private channel without including exploit details, credentials or sensitive transaction data. No response SLA is promised. Never disclose private keys, live claim secrets or customer transactions.

Include exact commit, platform, synthetic reproduction, expected/actual behavior, affected trust boundary and evidence. Do not test with real funds or against unauthorized third-party infrastructure.

## Trust boundaries

- Independently control issuer trust anchors, operator policies, network and permitted RPC endpoints; agent input is untrusted.
- RPC results are advisory, potentially incomplete, non-atomic or malicious.
- Cloud is opt-in and cannot override local hard DENY.
- No local report is an authorization grant. No wallet signing or broadcasting is implemented in the public engine.
- Explicitly report malformed input, unsupported effects and unavailable evidence.

[Threat model](docs/architecture/security.md) · [Limitations](LIMITATIONS.md) · [Release gates](docs/release/community-0.1.0/RELEASE_GATES.md).

## Reports and historical evidence

The HTML renderer escapes dynamic values and emits passive standalone documents with a restrictive CSP, but reports may include confidential transaction data and are not authenticated artifacts. Never expose private RPC endpoints or customer transaction bytes through public issue attachments. Explicit simulation sends original bytes to the chosen provider. Historical audit sends a public identifier, verifies returned signatures locally and treats historical metadata as untrusted; no independent ledger proof. Demo Lab fixtures are synthetic and unsigned; never broadcast. See [HTML contract](protocol/html/README.md), [CLI reference](docs/CLI.md), and [current verification](docs/release/community-0.1.0/VERIFICATION.md).
