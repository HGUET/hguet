# HGUET CLI ↔ Server — compatibility snapshot (2026-11-15)

> **Community Edition direction (2026-11-27):** This is a dated compatibility snapshot. Preserve pinned revisions and test evidence; do not infer deployment or update wire contracts to match product marketing. See the [release roadmap](../../docs/release/community-0.1.0/ROADMAP.md).

**Status: unreleased draft, not a full end-to-end certification.** This page tracks the public/privately pinned contract and separates implemented primitives from enabled network behavior. Public `protocol/v1` is authoritative. A protocol major of 1 is **not** a product release.

## Source of truth and exact revision

- **Canonical definitions:** [public protocol/v1](../../protocol/v1/README.md), [hguet.proto](../../protocol/v1/hguet.proto) and the public JCS JSON schemas. Do not maintain a parallel private wire protocol.
- **Server contract pin:** [HGUET/server public-contract.lock.json](https://github.com/HGUET/server/blob/main/docs/architecture/public-contract.lock.json), public commit `18736c0c09a5adba3b7b798addcaa76b2051bf57`.
- **Public `main` checked:** `da50606f6f0e3ebdc9c9c2da7cf18e598809d2e3` (snapshot; newer commits may follow).
- **Blob comparison:** **12/14** locked paths still have identical Git blobs at that public HEAD. In particular, `hguet.proto`, signed `payment-quote`, `cloud-assessment`, `payment-receipt` schemas, draft pricing policy, cases and example fixtures match.
- **Drift requiring review before repin:** `protocol/v1/payment-intent.schema.json` (locked `c80d17757ec6b63dccac91bd5c760b336d159c5c`, public HEAD `3a0c3ddb8e5e46a61ed6b29ecf67fef7f0b378f0`), and `scripts/validate_json_contracts.py` (locked `2a7641a555fdb1b8da68e1d3c93f2c2f06f70969`, public HEAD `8d54cbfe3262ab4f23c7c51780c45a6fef24b6b4`). **Semantic review:** the current PaymentIntent schema adds optional `token_spend_limits` and `token_source_limits` (signed local user intent, not Cloud payment currency); older SOL-only intent stays syntactically valid. The validator expands tests for those optional fields and BLOCK-only signer/report schemas. There is **no change to the pinned Cloud Protobuf or quote/assessment/receipt blobs**. This is not evidence of a Cloud wire break, but exact-byte signed intent semantics and pin/update CI still require executable tests before re-pin.
- The private pin remains deliberately unchanged. A newer public source tree and a server pinned to an earlier commit can both be correct, but **must never be described as fully synchronized**.

## Subsequent local verdict-schema drift (2026-11-15)

The testing extension adds `signature_verified_scope_incomplete` to the public
`SecurityVerdict.intent_status` enum to describe an independently verified intent whose
instruction scope cannot be fully checked. The CLI already emitted this value. It does
not authorize signing or imply complete spending enforcement. Older strict validators
reject the new value, so consumers need an explicit schema update; this is not a claim
of compatibility with the private server's pinned schema. The snapshot and blob counts
above refer to their stated historical commit, not this working tree. Cloud Protobuf,
quote, assessment and receipt definitions are unchanged by this extension.

## Current implementation versus intended public protocol

| Contract | Public CLI / protocol | Private server on `main` | Cross-repo status |
| --- | --- | --- | --- |
| `ClientHello` / `ServerHello` | Protobuf v1 framing defined; CLI Cloud remains disabled | Loopback PQ TLS/Protobuf responder | No live CLI ↔ server E2E demonstrated |
| `PriceQuoteRequest` / signed `PriceQuoteResult` | Draft wire + JSON/JCS schema | Request semantic validator and quote/signing/storage primitives; **network issuer disabled** | Not integrated |
| `PaidCheckRequest` | Quote-bound claim + payment signature | **Opt-in read-only replay** of a preexisting completed history result only, with pinned ML-DSA-87 quote verifier and PostgreSQL preflight; new network payment admission disabled | Not a paid submission E2E |
| `PaidCheckStatus` / `CheckResult` | Claim holder retrieves existing result without paying twice | Loopback claim-authorized completed result retrieval; otherwise generic `UNAVAILABLE` | Cross-platform client interop not yet demonstrated |
| `CheckReceipt` | Pending/accepted, not an authorization verdict | No gateway emission yet | Planned |
| Quote / assessment / receipt signatures | Separate authenticated ML-DSA-87/JCS domains | Signed primitives and storage/worker tests | Production key/trust distribution unverified |
| Native SOL payment | Exact lamports + Memo, correct genesis, finalized, one quote → one check | Operator-only two-RPC finalized verification and atomic PostgreSQL work queue | No full live paid Devnet E2E demonstrated |
| Result ownership | Random private 256-bit claim, SHA-256 quote commitment | Claim-authorized read-only retrieval; never wallet signature alone | Negative/synthetic tests only, not production audit |
| Final `SecurityVerdict` | Composed by CLI; local hard DENY cannot be overridden | Server returns evidence, **not** final verdict | Boundary agreed |
| User account / USDC / subscription / device mTLS | Not in one-shot Cloud design | Not part of current paid service | Agreed absence |

**Transport target:** TLS 1.3, `SecP384r1MLKEM1024`, `TLS_AES_256_GCM_SHA384`, ML-DSA-87 server identity, four-byte big-endian Protobuf frame (≤1 MiB). Private OpenSSL/loopback tests do not establish supported public-client OS interoperability or production trust bootstrapping.

**Environment:** sandbox Devnet only in implemented operator/gateway paths; `127.0.0.1:8443` only. No public 443, Mainnet payment or released Cloud service is enabled by these changes.

## Rules for further synchronization

1. Review changes to the two drifted public files for signer/validator semantics. **Never** silently overwrite or re-pin public-contract.lock.json to latest `main`.
2. Compare schema Git blobs, run public fixture/schema checks, private pinned-contract CI, Rust tests, PostgreSQL migration/concurrency tests and strict TLS tests; record actual results rather than assuming GitHub commits imply passing CI.
3. Demonstrate real public Rust CLI ↔ loopback server interoperability (including protocol errors, signature domains and claim recovery) before enabling new paid admission.
4. Complete signed quote issuance, two-origin Devnet settlement, one-shot historical worker, durable `CheckResult` and crash/retry E2E, then independent security review. Only after that consider public deployment.
5. Preserve existing signed bytes and Protobuf field numbers; introduce incompatible changes only by explicit contract revision and synchronized client/server changes.

For the intended lifecycle see [interoperability](interoperability.md) and [Cloud protocol](cloud-protocol.md). For current private implementation see [server implementation notes](https://github.com/HGUET/server/blob/main/docs/implementation/README.md).
