# HGUET ↔ HGUET Server — Unified interoperability contract (draft earlier draft)

**Canonical source:** this PUBLIC repository (`HGUET/hguet`).  
**Consumer:** private `HGUET/server`, which must pin this repository's tagged contract.  
**Status:** design-only, **unreleased**. No compatibility promise until an explicitly tagged alpha.

This document resolves cross-repository ambiguity. For externally visible behavior it takes precedence over older architecture prose. Proprietary algorithms, feed data, tenant internals, keys and SQL remain private.

## 1. Roles and scope

| Concern | Free CLI | Private Cloud | External signer |
| --- | --- | --- | --- |
| Parse legacy/v0/v1 transaction | required when supported | only if explicitly given raw bytes | supplies exact signed message |
| Local RPC simulation | client-selected RPC | optional **independent** RPC with disclosure | may require recheck before sign |
| Trusted authorization | verifies independently configured issuer | may verify independently provided proof; a hash is insufficient | **enforces** approved policy |
| Local hard policy | authoritative for CLI decision | must **never** override | checks returned decision and message binding |
| Threat intelligence | no paid feed | source-attributed signals and monitoring | advisory for signer policy |
| Account, invoice, credits | UX commands only | account state, onchain deposit verification, ledger | customer external wallet pays topup |
| Final JSON verdict | **composed by CLI** | server **does not sign final composite** | optional caller-side verification |
| Server-signed assessment | verifies, displays, merges | **signs only CloudAssessment** and billing receipt | may verify assessment independently |

**No wallet custody, no customer payment signing or broadcasting.** HGUET receiving USDC for its **own service** is not customer-funds custody. Local mode never contacts HGUET Cloud, although it may call the customer's configured Solana RPC. `inspect --offline` has no network.

## 2. Exact request and response lifecycle

```text
AI agent / approved workflow
   ├── transaction bytes (untrusted)
   └── independently trusted PaymentIntent + local Policy
           |
           v
      HGUET CLI
      decode / verify intent / local RPC / local findings
           |
           +── mode=local: finalize SecurityVerdict, print JSON
           |
           +── mode=cloud: authenticated PQ TLS session
                    |
                    +── PriceQuoteRequest → authenticated PriceQuoteResult
                    +── CheckRequest(accepted_quote, idempotency, hashes, features,
                    |                disclosure, local evidence, price cap)
                    v
              HGUET SERVER
              identity + quota + price + durable reservation
              snapshot + correlated risk + optional server RPC
                    |
                    +── signed CloudAssessment + BillingReceipt
                    v
      HGUET CLI verifies server key, hashes, request, TTL, profile
      merges only permitted findings + local mandatory coverage
           |
           v
      FINAL SecurityVerdict (CLI, not itself server-signed)
           |
      customer-controlled signer, if integrated
```

Do not conflate a hash-only Cloud enrichment with independent transaction simulation or independently authenticated intent. The server may report `not_assessed` for any unavailable capability.

## 3. The two distinct report types

### 3.1 SecurityVerdict — local final report

The public CLI's `--json` output uses the schema and precedence in [verdict-schema.md](verdict-schema.md).

- `decision: ALLOW|WARN|DENY|UNKNOWN` is the **final CLI result**.
- Includes original transaction/message hashes, trusted intent evidence, declared network/genesis, mandatory coverage, local and optional Cloud findings.
- A successful simulation alone cannot produce ALLOW.
- If a Cloud response has bad signature/hash/tenant/scope/expiry: **discard it**, add `CLOUD_EVIDENCE_INVALID`; if Cloud mandatory → UNKNOWN; if optional → retain local verdict with `cloud.status=invalid`, never claim Cloud coverage.
- Final JSON is not “cryptographically signed by HGUET Server” merely because one embedded CloudAssessment was signed.

### 3.2 CloudAssessment — server-authenticated enrichment

The server signs a **canonical assessment payload**, with data sufficient for third-party verification:

```json
{
  "schema_version": 1,
  "kind": "cloud_assessment",
  "tenant_scope": "<opaque bound tenant identity>",
  "request_id": "<128-bit ID in canonical encoding>",
  "network": "solana-mainnet",
  "genesis_hash": "<verified genesis or explicit unknown>",
  "message_sha256": "<lowercase 64-hex>",
  "intent_sha256": "<lowercase 64-hex or explicit null>",
  "requested_profile": "strict",
  "capabilities_performed": ["program_risk", "network_health"],
  "capabilities_unavailable": [],
  "risk_snapshot_id": "<opaque>",
  "ruleset_version": "<version>",
  "evidence_digest": "<lowercase 64-hex evidence manifest digest>",
  "sources": [{"source_id": "example", "kind": "solana_rpc", "observed_at": "<UTC RFC3339>", "evidence_sha256": "<lowercase 64-hex>"}],
  "findings": [],
  "coverage": {"required": [], "passed": [], "unknown": []},
  "issued_at": "<UTC RFC3339>",
  "expires_at": "<UTC RFC3339>"
}
```

- Serialize this body using a **chosen canonical encoding**. Proposed target: RFC 8785 JCS JSON with a strict fixed schema, rejected duplicate keys/unknown critical fields, bounded size.
- Sign `ASCII("HGUET-CLOUD-ASSESSMENT/v1") || 0x00 || canonical_body_bytes` with the tested ML-DSA-87 report key. Key ID and signature are carried **outside** the canonical body. This signature binds claims and inputs; it cannot prove their accuracy.
- The signed payload covers source IDs/timestamps and a digest of a retained evidence manifest; source provenance is not proof of source accuracy.
- Server identity and report key are separately verified via authenticated distribution/rotation. Client recomputes hashes, checks time window and account/request binding **before** reporting `signature_verified=true`.
- Signed billing receipt is separate from signed risk assessment (a completed check and its charge are independently auditable).
- Never copy a server-supplied verdict into local final `decision` without local coverage/aggregation.

**Report state vs billing state:** an authenticated CloudAssessment may have a “partial/unknown coverage” status yet still be a completed (possibly billable under agreed terms) analysis. A transient infrastructure fault is **not** a completed billable check.

## 4. Transport and versioning

Network transport `TCP + TLS 1.3`, no commercial REST API and **no custom VPN or encryption**.

| Requirement | Canonical design |
| --- | --- |
| Hybrid key exchange | `SecP384r1MLKEM1024` (RFC 10024), verified exact negotiated group |
| Identity | ML-DSA-87 certificate signatures where full mTLS interoperability verified |
| TLS cipher | `TLS_AES_256_GCM_SHA384` (AES-256-GCM; TLS native HKDF-SHA384) |
| Bootstrap | server-authenticated PQ TLS; no client certificate **yet**; pinned trust roots |
| Subsequent sessions | mutual TLS + tenant/device authorization + revocation |
| In-TLS frames | 4-byte big-endian unsigned size + one Protobuf message; ≤1 MiB |
| Protocol negotiation | major/minor versions; unknown major or critical field fails closed |
| Replay | 0-RTT off, enrollment nonce one use, idempotent paid messages |

All protocol definitions live in public repository (future/initial draft `protocol/v1/hguet.proto`). Server consumes a pinned **tagged** public schema; no private divergent fork. Current file is **draft** until an explicitly published protocol tag; fields may change before first release.

A third party who reproduces the public protocol and possesses valid device credentials **may** connect. Only official CLI binaries cannot be cryptographically enforced by “secret protocol”; billing and authorization enforce access.

## 5. Input binding and privacy

A `CheckRequest` must contain enough to uniquely bind:

- `tenant` derived from server-side authenticated device session, never trusted from a client field;
- 128-bit unpredictable `request_id`, scoped to tenant, used for idempotency;
- `network/genesis`, `message_sha256`, `wire_sha256` when wire is known, and `intent_sha256` (or explicitly none);
- `profile` and explicit list of requested capabilities;
- data-privacy flags, redacted local evidence and/or raw transaction when **explicitly** opted in;
- accepted signed price quote ID/schedule and maximum permitted credit fee. First request a quote for network, profile, capability set and disclosure scope; reject expired/mismatched quotes and any amount above caller's configured ceiling.

**Hash only:** the server can look up known program/destination signals only if those **subjects** are explicitly supplied; a bare message hash cannot reveal recipient, token or authority. It may **not** claim independent simulation, decode or intent verification without corresponding bytes/proof.

Raw bytes: allowed only with CLI user's explicit disclosure or previously configured consent. Any forwarding to third-party RPC must be separately described. A `cloud` session is *not* hidden in a `local` command.

## 6. Identity, top-up and billing contract

- `hguet register` and `login`: no web cabinet. Initial server-only authenticated PQ TLS enrollment; afterwards device mTLS; optional email one-time code entered in CLI.
- `hguet topup 10 --asset USDC` returns an authenticated **invoice** with official network/mint/token program, exact base units, reference/deposit mapping, expiry and HGUET treasury receiver. The customer pays with a **separate customer-controlled wallet**; HGUET CLI never signs that payment.
- Server verifies incoming finalized transfer, applies exactly one journal credit for unique settlement event, and exposes `balance` and `topup status`.
- `CheckRequest` quotes and reserves credits; same (tenant, request_id, request_body_hash) can complete/return status **once**. Reusing ID with new body → conflict.
- One charge for an accepted **completed service assessment** under disclosed price/terms. Hard DENY and WARN **can** be billed. Infrastructure fault and unfulfilled mandated service **must not** be charged.
- If analysis ends UNKNOWN due to genuine supported-but-inconclusive evidence, charge only if explicit prior tariff covers that status; never charge an upstream outage as a successful check.
- Server signs a `BillingReceipt` separately; client `CheckStatus` gets the same result and receipt after a disconnect. Receipt must match the assessment request and final charged amount.

**No subscription/web checkout required for earlier draft.** Topup amount and per-check price must not be implied fixed; tariff is server-authoritative, authenticated, and subject to client price ceiling.

## 7. Final verdict merge and exit status

**Aggregation rule shared by CLI and server:** known hard DENY > missing **mandatory** evidence UNKNOWN > WARN > ALLOW. Server supplies findings/coverage, never overrides a known local hard DENY.

| Outcome | CLI JSON `decision` | CLI process exit |
| --- | --- | --- |
| All required checks passed | ALLOW | `0` |
| Nonfatal risk needs review | WARN | `10` |
| Proven mandatory rule violated | DENY | `20` |
| Mandatory evidence absent/unsupported/inconsistent | UNKNOWN | `30` |
| Invalid input/config | not a completed security verdict | `40` |
| Infrastructure/transport failure | fail / UNKNOWN as applicable | `50` |
| Cloud authorization/credit error | fail / UNKNOWN as applicable | `60` |

When Cloud is **mandatory** and unavailable/unauthorized/credit-exhausted, integration **must block**, with no local ALLOW. When Cloud is **optional** and unavailable, CLI may return a clearly identified **local-only** result, not a Cloud-enhanced ALLOW. A separately handled `infra` error should not accidentally be treated as a final `DENY` threat finding.

Cloud `CheckReceipt` = *accepted/in progress* only. Cloud `CheckResult` = *terminal assessment + billing receipt* or a typed terminal failure; do not render an accepted receipt as a completed security verdict.

## 8. Version matrix and acceptance

| Consumer | Producer | Requirement |
| --- | --- | --- |
| Public CLI local report | Public `hguet-verdict` crate | `schema_version=1` and golden JSON |
| CLI Cloud client | Private server gateway | identical `protocol_major=1` draft frame/schema |
| Server CloudAssessment | CLI verifier | same key trust roots, message/intent/network/profile/request binding |
| Server USDC invoice | CLI account UI | authenticated mint/network/reference/expiry/price |
| Server BillingReceipt | CLI usage/balance | same request ID, price schedule and charge state |
| CLI strict signer integration | External signer | exact transaction/message hash and verdict freshness |

Before release, perform **both** independent build suites and a cross-repository integration test with negative cases: wrong chain, wrong tenant, stale signature, mismatched transaction, duplicate requests, billing races, partial Cloud coverage and TLS downgrade.

### Authority order for disputes

1. The actual protocol schema and conformance fixtures from **public HGUET/hguet** when tagged and tested.
2. This shared compatibility contract and public SecurityVerdict spec.
3. Private implementation docs and internal state machines.
4. Illustrative CLI output examples / marketing.

If two documents disagree, do **not silently implement either**: open a compatibility issue and update both before deployment.

## 9. Open items (not misleading promises)

- The protobuf envelope, signed CloudAssessment JSON schema and golden fixtures must be implemented and validated.
- Final enrollment proof and device certificate compatibility profile to be selected/tested with OpenSSL provider.
- Solana transaction format v1 is live: support must be version-aware and tested.
- Final unit economics, customer price ceiling, minimum top-up and legal terms need business decision.
- STRIDE and SIRN data availability must be separately verified; **no assumed partnership**.

**References:** [public Cloud design](cloud-protocol.md), [final verdict format](verdict-schema.md), [CLI interface](cli-interface.md), [security model](security.md).