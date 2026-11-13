# HGUET CLI — Cloud protocol, post-quantum transport and billing

**Status:** proposed wire contract and security requirements; **no production TLS interoperability is claimed**.

The **public** repository owns the client, wire schema and compatibility fixtures. The **private** `HGUET/server` repository owns the backend, aggregation, accounts, threat feeds, pricing and operations.

## 1. Network model

```text
HGUET CLI (Rust)
  |
  | TLS 1.3 / mutual authentication after enrollment
  | REQUIRED hybrid SecP384r1MLKEM1024 key exchange
  | REQUIRED verified PQ-capable identity policy
  v
HGUET private TCP service (Rust)
  |
  +-- Enrollment and device identity
  +-- Account, usage quotas and prepaid balance
  +-- Simulation/context endpoint and Cloud risk engine
  +-- Program upgrades / threat-source provenance
  +-- Verifiable report signing and idempotency
```

The CLI has one **documented** Cloud endpoint, e.g., `hguet.fr:443` (subject to DNS and host deployment decisions). There is no public REST/GraphQL/HTTP API for commercial checks. The **client still uses ordinary HTTPS RPC** to communicate with a user-selected Solana provider in local mode; the “no HTTP API” decision applies to the HGUET **commercial server**.

Any third-party client able to reproduce a public wire protocol and authenticate with valid credentials may send requests. **Do not claim to cryptographically enforce “official CLI binary only”**. Authorization is by client identity and server policy, not binary name.

## 2. Cryptographic profile

Requirements selected for HGUET:

| Purpose | Required profile / caveat |
| --- | --- |
| Protected channel | standard TLS **1.3 only**, not custom encrypted sockets |
| Hybrid key agreement | **SecP384r1MLKEM1024** as defined in RFC 10024; require negotiated group |
| Authentication | **ML-DSA-87**, using certificates/handshake supported by a tested provider; mTLS for enrolled devices |
| Record protection | **AES-256-GCM** via TLS cipher suite with HKDF/key schedule implemented by TLS |
| Hashing | SHA3-512 is available for app-layer report fingerprints; TLS hash/KDF is determined by negotiated TLS cipher suite, not arbitrarily substituted |
| Library | maintained OpenSSL 3.5+ bindings are initial candidate; pin exact tested versions |
| Security policy | reject fallback to classical-only KEM, TLS <1.3, unverified identities or missing required PQ signature support |

RFC 10024 standardizes the hybrid group. Actual **ML-DSA-87 client certificate/handshake support** and cross-platform linkage must be proven with integration tests before the feature can ship. A tested library version, provider configuration, cert chain formats, and key-rotation runbook must be documented.

**Bootstrap challenge:** initial registration has no client cert yet. Embed an independently authenticated/pinned server root or public key distribution trust path in a signed CLI release. Register over already authenticated PQ TLS; create a locally held device identity (secure OS key storage) and request a short-lived enrollment challenge. Only then provision a client certificate for mTLS. Do not use unauthenticated trust-on-first-use against an arbitrary endpoint.

**Do not** invent your own cryptographic primitives or swap a failed PQ handshake for classical TLS. Fail closed with an actionable error. Disable TLS early data/0-RTT for state-changing requests, enforce session replay checks, device revocation and credential expiration.

## 3. Application protocol

The HGUET application protocol is **publicly documented**, although the server is private:

- TCP + authenticated TLS 1.3, using library framing and record protection.
- Over TLS: length-prefixed binary frames, **4-byte unsigned network-order length**, followed by a versioned Protobuf message (example choice: `prost` codegen).
- Configured frame upper bound, initially **1 MiB**; larger inputs are rejected before allocation. Individual fields (transaction bytes, evidence, string lengths, arrays) have tighter limits.
- One request may carry a stable 128-bit request ID and idempotency token; responses echo ID.
- Messages include protocol major/minor, message type, tenant/device identity, timestamp, deadline, and signed/verified report when applicable.
- Protocol major mismatch → explicit incompatibility, **not** silent alternate transport.
- No arbitrary server-issued commands, shell execution or plugin downloads in client transport.

Proposed versioned messages:

```text
ClientHello   / ServerHello            # protocol features / capabilities (inside TLS)
EnrollStart   / EnrollChallenge / EnrollProof / EnrollResult
AccountGet    / AccountResult
TopUpQuote    / TopUpInvoice / TopUpStatus
CreditBalance / UsageQuery / UsageResult
CheckRequest  / CheckReceipt
CheckStatus   / CheckResult
DeviceList    / DeviceRevoke
Error         / RateLimited / UpgradeRequired
```

Message schemas should be committed as `protocol/v1/hguet.proto` in **this public repository** before an implementation. Server implementations will pin a tagged protocol crate version. The listed protocol names are design targets, not implemented endpoints.

## 4. Server risk check request

Minimum Cloud request envelope:

```json
{
  "protocol_version": 1,
  "request_id": "random-collision-resistant-id",
  "device_id": "registered-device-id",
  "mode": "cloud",
  "network_id": "solana-mainnet",
  "transaction_message_sha256": "<hex>",
  "trusted_intent_sha256": "<hex>",
  "client_local_verdict": "<sanitized local assessment>",
  "requested_capabilities": ["network_health", "program_risk", "behavioral_intelligence"],
  "privacy": {
    "raw_transaction_included": false,
    "minimum_required_metadata": true
  }
}
```

This JSON only **illustrates the logical fields**; the transport uses binary messages. Cloud must not falsely claim to simulate a raw transaction unless the client explicitly provides sufficient transaction bytes. If a paid check needs raw bytes, prompt/profile must disclose the submission and compute a new request with an explicit consent flag.

Cloud replies must be bound to the same **message hash, intent hash, network and scope** as the local request. Aggregation must reject mismatched or late responses. Threat signals include evidence source, data age, confidence and revocation/correction metadata.

## 5. Identity and account life cycle (CLI only)

```text
hguet register
    -> initial PQ TLS + pinned server authentication
    -> account creation / ownership verification (CLI challenge)
    -> local device key creation
    -> certificate enrollment
hguet login
    -> confirm active device identity / challenge, no browser session
hguet device list
hguet device revoke ID
hguet logout
    -> remove local auth session and optionally revoke token
```

Account owner email or other contact verification can use a **one-time code entered in CLI**; avoid harvesting personal data beyond what billing/abuse control requires.

- Credentials are device-scoped, rotatable and revocable.
- Root trust key rotation uses a signed trust-transition and explicit expiry.
- TLS client certificate does not alone decide charge limits, allowed tenants or API permissions; server checks each request.
- Encrypt locally cached credentials with OS facilities. No shared secret baked into public GitHub binaries.
- Redact cloud user IDs, access IDs, top-up invoices and network secrets from logs as appropriate.

## 6. USDC top-up & usage billing

Preferred early flow: **prepaid, pay-per-completed-Cloud-check**, no annual subscription required.

```text
hguet topup 10 --asset USDC
 -> Cloud issues signed quote/invoice: exact base units,
    official mint, destination, network, expiry and one-time reference
 -> CLI displays invoice text/QR
 -> Customer uses their OWN wallet to sign/send USDC
 -> Cloud verifies confirmation and invoice ownership
 -> Account receives credits once
hguet balance
hguet check ... --mode cloud
 -> server verifies authorization + sufficient credit
 -> reserves or atomically consumes charge for request_id
 -> computes decision and returns receipt
 -> same request retried: same receipt, no duplicate charge
```

HGUET is receiving **payment for its own security service**, not holding a customer's payment funds to forward to merchants. Confirm legal, tax and consumer/commercial terms before launch.

Rules:

- Prices and free limits are server-published and cryptographically authenticated; client never computes final charge.
- Charge a completed analysis whether its result is ALLOW, WARN or DENY, if that was agreed in the quote.
- Auth failures, malformed input rejected pre-analysis and genuine server-side failures must not be charged.
- A service `UNKNOWN` due to incomplete but valid checks is priced only when agreed transparently; provider outage should be credited/refunded.
- Idempotent handling of retries, timeouts and duplicate transaction **checks**: key by account + request ID + canonical payload hash; reject same ID for a changed payload.
- Credits never depend on an unauthenticated Solana RPC response alone; top-up deposit and finality policy must be verified authoritatively.
- Client must display current balance and per-request price before submission where interactive; automation requires predefined pricing/budget ceiling.
- Billing audit and refunds remain in the private backend.

## 7. Combining local and Cloud intelligence

1. Always run local deterministic checks first.
2. If a known hard DENY exists, Cloud may add context but **cannot overrule** it.
3. If Cloud is required by profile and unavailable, result is UNKNOWN.
4. If Cloud optional and unavailable, return clearly marked **local-only coverage**; do not claim it contains live network intelligence.
5. Cloud risk signals may cause WARN or DENY **only according to explicit, inspectable policy**, with source/age and customer preference.
6. The final report includes local and Cloud evidence plus signed receipt when Cloud completed.

### Privacy notes

Transport TLS protects the link in transit, **not data from the HGUET service after decryption**. If Cloud analysis receives customer transaction bytes, server can inspect them. Be explicit about retention and provider sharing. HGUET server may query third-party RPC/threat feeds: make external data flows auditable.

## 8. Protocol failure matrix

| Event | Behavior |
| --- | --- |
| PQ KEM or ML-DSA unsupported | refuse Cloud, explain compatibility; local mode available |
| Server cert/pin mismatch | hard TLS error, no fallback |
| Client key revoked | unauthorized; no Cloud check |
| Expired quote | request fresh quote, never quietly pay |
| Duplicate request ID with same body | return same receipt/result |
| Duplicate request ID with altered body | conflict, reject |
| Payment credit insufficient | Cloud auth/payment error, local unchanged |
| Mid-check disconnect | query status by request ID, no repeated charge |
| Cloud stale feeds | label evidence stale; UNKNOWN if required |
| Schema major mismatch | explicit upgrade required |

## 9. Operational guarantees to test

- Successful **real** TLS handshake with configured group and signature algorithms on Linux, Windows and macOS test images.
- Packet inspection shows no plaintext check/intent data on wire.
- Negotiated group/cipher/certificate chain logged as non-secret diagnostic metadata.
- Tampered cert, expired key, downgraded group, client without key or replay → rejection.
- Multi-node idempotency stress test yields exactly one charge per paid request.
- Subscription-less free local checks function while Cloud is disconnected.

References: [architecture](README.md), [security](security.md), [verdict](verdict-schema.md), [sources](references.md).