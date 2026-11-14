# Interoperability with the public HGUET protocol

Authority: `protocol/v1/hguet.proto`, `payment-quote.schema.json`, `cloud-assessment.schema.json`,
`payment-receipt.schema.json`, `docs/architecture/cloud-protocol.md`. **No second protocol exists in this
benchmark.** Anything below that the public files leave open is listed under "Questions for the protocol
owners" and is *not* decided here.

## 1. What the previous adapter got wrong (reconciliation)

The earlier `server/real_server.py` was written before the proto was compared with it. Against the public
files it was a parallel protocol:

| Previous assumption | Public protocol | Resolution |
|---------------------|-----------------|-----------|
| `POST /v1/assessments` over HTTP(S) | TLS 1.3, 4-byte big-endian length, one Protobuf `Envelope` (<= 1 MiB) | adapter deleted; `server/protocol_client.py` speaks the real transport |
| own request document (`hguet-cloud-request/1`) | `PriceQuoteRequest` / `PaidCheckRequest` | benchmark keeps only an internal *view* (`cv-request-view/1`) and maps it to the proto messages |
| answer `{assessment, signature{alg,key_id,sig_b58}}` | `SignedPayload{canonical_payload, signature, key_id, signing_algorithm}` | verifier takes exactly `SignedPayload` |
| domain `HGUET-CLOUD-ASSESSMENT\0` | `HGUET-CLOUD-ASSESSMENT/v1\0`, `HGUET-SOL-QUOTE/v1\0`, `HGUET-SOL-PAYMENT-RECEIPT/v1\0` | `verify/common.py: DOMAINS` |
| Ed25519 stand-in as *the* scheme | ML-DSA-87 | ML-DSA-87 via OpenSSL >= 3.5; Ed25519 only as a labelled `TEST-ONLY-ED25519` fallback, refused for the real server |
| one call returns an assessment | quote -> external SOL payment -> paid check with claim secret -> signed assessment **and** signed receipt | adapter implements both phases, never pays, never skips a check |
| subject types program/account/mint/alt_table | `Subject.category`: program, mint, destination, merchant | account->destination; `alt_table` has no category and is **not sent** (C09 marked not-applicable for the real server) |

A unit test fails if `real_server.py`, `/v1/assessments` or `urllib.request` reappear in `server/`.

## 2. Flow implemented (`server/protocol_client.py`)

```text
ClientHello -> ServerHello
PriceQuoteRequest(network, genesis_hash, message/intent/transaction hashes, profile, capabilities,
                  DATA_SCOPE_METADATA_ONLY, claim_secret_sha256, maximum_lamports, subjects,
                  subjects_sha256, complexity)
  <- PriceQuoteResult(signed_quote)         verified: signature, schema, network/genesis/environment,
                                            message + subjects + claim commitment, lamports <= cap, expiry
[ operator pays on DEVNET with their own wallet; the benchmark never holds keys or pays ]
PaidCheckRequest(quote_id, claim_secret, payment signature, same bound parameters)
  <- CheckReceipt(pending)  -> PaidCheckStatus(quote_id, claim_secret) (bounded polling, no second payment)
  <- CheckResult(signed_cloud_assessment, signed_payment_receipt)
                                            verified: both signatures, quote_id binding, assessment <-> receipt
                                            hash binding, lamports/receiver, then the full assessment rules
```

`ProtocolError` codes become machine-readable failure reasons; an unverified or failed exchange yields **no**
answer, and `combine()` leaves the local verdict untouched.

## 3. Verification (independent of the server)

* **Signature**: `ML-DSA-87` through OpenSSL >= 3.5, checked against the NIST ACVP FIPS 204 known-answer
  vectors (`verify/vectors/mldsa87_acvp_sigver.json`, 15 cases, 12 must be rejected; provenance and source hash
  recorded). Without such a backend ML-DSA signatures are *unverifiable* and discarded (`unsupported_signature_alg`).
* **Issuer key**: pinned in a trust store (`verify/trust/`), checked for algorithm, validity window, purpose,
  environment, and `test_only`. There is **no** `real_issuers.json`: until HGUET provisions a pinned issuer key
  through an authenticated release, the real server cannot be authenticated.
* **Payload**: must be canonical JCS (RFC 8785) byte-for-byte; duplicate keys and floats rejected; schema-valid.
* **Identity/hash/time**: network, genesis, environment (mainnet = production, devnet/testnet = sandbox),
  message/transaction/intent/subjects hashes, quote_id, data scope, validity window.
* **Provenance**: every cited evidence record's digest is recomputed from an independent registry; findings are
  capped by tier, confidence, network, validity and retraction (rules F1-F4 in `verify/assessment_rules.py`).

## 4. Why the real server is still `unavailable`

1. **PQ TLS group cannot be enforced.** The protocol requires hybrid `SecP384r1MLKEM1024` and fail-closed on
   anything else. Python's `ssl` can neither select nor read back the negotiated group, so the requirement
   cannot be checked. The adapter reports this instead of connecting with weaker guarantees. TLS 1.3, certificate
   verification, hostname checking and CA pinning are always on and cannot be switched off.
2. **No pinned issuer key** (section 3).
3. **Payments are external.** Each scenario needs its own finalized devnet payment; none is made automatically.
4. A harness that speaks the public protocol (`testserver/`) exercises the adapter in tests only. Its results are
   `conformance`, never reported as `real_server`.

## 5. Devnet-only procedure (synthetic data, test SOL, no commercial payment)

1. Operator obtains a devnet endpoint, its CA bundle and the issuer public key through an authenticated channel;
   adds the key to `verify/trust/real_issuers.json` (`environments: ["sandbox"]`, `test_only: false`).
2. Run with `--enable-real-server --real-server-host H --real-server-ca CA.pem`: the adapter obtains and
   verifies a signed quote per scenario and records `awaiting_external_payment` events (lamports, receiver, memo).
3. The operator pays each quote with their own devnet wallet (test SOL) and writes
   `{message_sha256: {payment_signature, claim_secret_hex}}` to a payments file. The claim secrets are bearer
   secrets generated locally per quote.
4. Re-run with `--payments-file`: verified assessments flow into the `real_server` column. Mainnet quotes are never
   requested by this benchmark; a `production` environment answer for a devnet request is discarded.

## 6. Questions for the protocol owners (not decided here)

1. `Subject.category` has no value for a lookup table (`alt_table`); how should ALT-based risk be requested?
2. `subjects_sha256` and `evidence_digest` canonicalisation: the benchmark ADOPTED the HGUET/server S7.1 proposal
   (`docs/architecture/canonical-contract-s7.md`, 176 vectors): subjects are `{category, network, subject_id}` sorted
   byte-wise; `evidence_digest` is SHA-256 of the union manifest of the cited records. The proposal is still not
   confirmed by the public protocol owner as a wire contract; the server cross-check
   (`scripts/crosscheck_public.py`) reports 0 disagreements.
3. Definition of `sources[].evidence_sha256` and `evidence_digest` (benchmark: sha256(JCS(record)) and
   sha256(JCS(sorted digests))).
4. Redaction format of `ClientEvidence.canonical_local_evidence_json` (benchmark sends `{}`).
5. How a client proves the negotiated TLS group, and how the first issuer key is distributed.
6. Whether the quote Memo and `payment_signature` format are fixed (the receipt schema needs >= 64 characters).
