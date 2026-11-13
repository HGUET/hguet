# HGUET protocol v1 — PUBLIC DRAFT

**Unreleased draft (2026-11-13).** This is the **single proposed source of truth** for the wire format between the open-source CLI and private HGUET Server. Protobuf definitions here are **not evidence of a working endpoint**.

## Files

- [hguet.proto](hguet.proto): framed Protobuf messages for registration, devices, invoices, prepaid balance, cloud checks and status.
- [cloud-assessment.schema.json](cloud-assessment.schema.json): canonical JSON data signed by HGUET Server for **CloudAssessment only**, including risk-source provenance and evidence manifest digest.
- [contract-cases.json](contract-cases.json): cross-repo conformance test scenarios (requirements, not completed test results).
- [Unified interoperability contract](../../docs/architecture/interoperability.md): normative roles, signing, precedence and billing policy.

## Encoding and transport

```text
TCP -> TLS 1.3 with required tested PQ profile
    -> uint32 BE length (max 1 MiB) -> Protobuf Envelope
    -> Envelope protocol_major=1, protocol_minor=0
    -> Envelope.request_id = exactly 16 unpredictable bytes
```

Do not carry tenant authorization in user-supplied fields. Identity comes from the verified mTLS device session. Initial enrollment uses already authenticated server-only TLS before issuing a device certificate.

The `signed_cloud_assessment` field is a detached-signature wrapper around JCS-canonical `cloud-assessment.schema.json` JSON; report domain separator is `HGUET-CLOUD-ASSESSMENT/v1` plus a zero byte and signed bytes. `signed_receipt` is a **distinct** signed record with a separately defined domain separator `HGUET-BILLING-RECEIPT/v1`. Invoice `server_invoice_signature` uses `HGUET-INVOICE/v1`. Never reuse one domain separator across kinds.

Solana wire bytes may be sent only under `DataScope.DATA_SCOPE_RAW_TRANSACTION` with `raw_transaction_consent=true`; a metadata-only request cannot assert full independent simulation.

A `PriceQuoteRequest` asks for an authenticated price for the intended capabilities, network, profile and data-sharing scope. `PriceQuoteResult` carries quote ID, schedule, signed maximum price and expiry. The client validates the `HGUET-PRICE-QUOTE/v1` signature and its own cap **before** sending `CheckRequest.accepted_quote_id`. Invalid or expired quotes fail closed.

`maximum_charge_units` is a nonnegative decimal string in authenticated tariff units. No floating-point monetary calculations. Client can set 0 to forbid a charge; server rejects rather than raises the ceiling.

## Security requirements before implementation

- Strict parser/schema validation: field lengths, enums, unknown critical fields, per-field bounds and rejecting malformed JCS payloads.
- Reject unknown protocol major; explicit minor/capability negotiation.
- Reject encrypted connection when negotiated group, certificate or signature policy fails.
- Sign and verify assessment **independently** of final CLI JSON verdict.
- Server returns terminal `CheckResult` only on terminal assessment. `CheckReceipt` indicates pending/accepted, not risk decision.
- Idempotency `tenant + request ID + canonical request hash`, same result/charge on retries.
- Authenticated session context binds server-signed report to tenant, network, request, message and intent hashes.
- Verified server receipt proves issuer and data binding, not absolute safety.

## Interoperability upgrade rule

This protocol is draft and can change until a **public tagged release**. Thereafter any incompatible wire change requires a new protocol major. Private `HGUET/server` pins the published version, runs the same test fixtures and never forks this file.