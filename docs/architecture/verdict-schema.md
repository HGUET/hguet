# HGUET CLI — Public SecurityVerdict contract

**Design only.** Proposed JSON schema `schema_version=1`; version control will stabilize it before implementation. A JSON output is an **evidence-bearing advisory opinion**, never a transaction authorization on its own.

## Relationship to CloudAssessment

**[Unified interoperability contract](interoperability.md)** distinguishes two independently verified artifacts:

1. **SecurityVerdict (this document)** — final JSON produced by the **CLI** after combining mandatory local checks with any optional Cloud facts. This *composite JSON is not server-signed*.
2. **CloudAssessment** — signed, server-issued *enrichment* with network/program/behavior findings, whose canonical schema lives in [protocol/v1/cloud-assessment.schema.json](../../protocol/v1/cloud-assessment.schema.json). PaymentReceipt has its own signature and domain-separated signed body.

A valid Cloud signature authenticates only the CloudAssessment, not a guarantee that the overall payment is safe. Local hard DENY remains DENY. Invalid/expired/mismatched Cloud evidence is discarded, and Cloud-required profiles return UNKNOWN.

## 1. Decision semantics

| Status | Meaning | Default signer behavior |
| --- | --- | --- |
| `ALLOW` | all mandatory checks for **declared profile/coverage** passed at observed state | may continue only under independently enforced signer policy |
| `WARN` | nonfatal risk remains and user review is necessary | block automation, request review |
| `DENY` | definitive hard policy violation or known disallowed action | reject |
| `UNKNOWN` | needed evidence absent, stale, inconsistent or unsupported | block strict automation |

Priority: hard `DENY` > missing mandatory coverage `UNKNOWN` > `WARN` > `ALLOW`. Never “average” safety into a numerical score that hides an unknown instruction.

## 2. Example response

This payload is **illustrative** and NOT a real HGUET check; the displayed build label is not a released product version:

```json
{
  "schema_version": 1,
  "tool": {
    "name": "hguet",
    "version": "unreleased-draft",
    "mode": "local",
    "profile": "strict"
  },
  "decision": "DENY",
  "action": "DO_NOT_SIGN",
  "network": {
    "id": "solana-mainnet",
    "genesis_verified": true,
    "genesis_hash": "<observed full genesis hash>"
  },
  "transaction": {
    "wire_format": "v0",
    "transaction_sha256": "<hex>",
    "message_sha256": "<hex>",
    "wire_bytes": 451,
    "original_message_unchanged": true
  },
  "intent": {
    "intent_id": "approved-task-0001",
    "intent_sha256": "<hex>",
    "provenance": "verified_trusted_issuer",
    "issued_by": "operator-approved-key-1",
    "expires_at": "2026-11-13T16:00:00Z"
  },
  "simulation": {
    "attempted": true,
    "success": true,
    "commitment": "confirmed",
    "context_slot": 300000000,
    "rpc_endpoint_id": "user-rpc-1",
    "used_replacement_blockhash": false,
    "observed_at": "2026-11-13T15:00:00Z"
  },
  "effects": [
    {
      "kind": "spl_token_transfer",
      "mint": "<verified mint>",
      "token_program": "<program id>",
      "destination_owner": "<verified owner>",
      "amount_base_units": "25000000",
      "source": "instruction:0"
    }
  ],
  "findings": [
    {
      "code": "RECIPIENT_MISMATCH",
      "severity": "critical",
      "enforcement": "hard_deny",
      "summary": "Recipient differs from the independently approved intent",
      "evidence_refs": ["instruction:0", "intent:approved-task-0001"]
    }
  ],
  "coverage": {
    "mandatory_checks": ["tx_decode", "intent", "simulation", "effects"],
    "passed": ["tx_decode", "simulation"],
    "failed": ["intent"],
    "unknown": [],
    "complete_for_profile": false
  },
  "provenance": {
    "sources": ["user-rpc-1", "trusted-local-intent"],
    "cloud_assessment_signature": null
  },
  "limits": [
    "Simulation is a snapshot; network state may change before execution",
    "A CLI verdict is advisory unless the customer-controlled signer enforces it"
  ]
}
```

**Important:** `coverage.complete_for_profile=false` can accompany definitive `DENY` because a known hard violation already blocks the payment. For ALLOW, it MUST be true and all mandatory checks must pass.

The placeholder network/genesis and slot values above must be replaced with observed facts at runtime; they are not hardcoded Solana state.

## 2a. DENY versus missing coverage (implemented in the CLI)

`DENY` is reserved for a **proven** violation. When the CLI cannot establish the facts it returns
`UNKNOWN` with `INTENT_COVERAGE_INCOMPLETE` (never `INTENT_REJECTED`) and, next to `verdict`, a
`coverage_gaps` array with a machine-readable reason. Reasons in use: `ALT_UNRESOLVED`,
`MULTISIG_OR_EXTRA_ACCOUNTS`, `ACCOUNT_MANAGEMENT_NOT_COVERED`, `UNSUPPORTED_TOKEN_INSTRUCTION`,
`ACCOUNT_CONTROL_SIGNER_BINDING_UNPROVEN`, `ACCOUNT_REFERENCE_UNRESOLVED`,
`INSTRUCTION_BYTES_UNAVAILABLE`. A violation that is visible in statically resolved data still wins
over a gap (an unresolved lookup table cannot hide an over-cap transfer or a forbidden program).

Account-control instructions are judged against the verified intent (`intent_scope_review`, a
sibling object so the `verdict` schema is unchanged; each entry has `code`, `kind`
(`violation`|`coverage_gap`), `gap_reason` and `evidence_refs`):

| Instruction | Condition | Result |
|-------------|-----------|--------|
| `SetAuthority` | new authority is neither the current authority nor a transaction signer | DENY `INTENT_SCOPE_AUTHORITY_TRANSFER` (+ `INTENT_REJECTED`) |
| `SetAuthority` | target is a signer / current authority | UNKNOWN `TOKEN_AUTHORITY_CHANGE_UNPROVEN` |
| `SetAuthority` | authority removed (None) | UNKNOWN `TOKEN_AUTHORITY_REVOKE_IRREVERSIBLE` |
| `CloseAccount` | destination does not sign the transaction | DENY `INTENT_SCOPE_CLOSE_DESTINATION` (+ `INTENT_REJECTED`) |
| `CloseAccount` | destination signs the transaction | UNKNOWN `TOKEN_CLOSE_DESTINATION_UNPROVEN` |

Rationale: a PaymentIntent v1 has no field that can grant a change of account control, so a
transfer of control (or of the balance, including wrapped SOL) to a non-signing third party is outside
every intent by construction. Without a verified intent there is no scope: UNKNOWN. Revoke, SyncNative
and Initialize* are administrative: UNKNOWN under token caps, not DENY. Unchecked Transfer, Approve,
MintTo, Burn, Freeze/Thaw remain DENY under signed caps because the caps can never bound them.

## 3. Required fields and type choices

- `schema_version` integer; never silently interpret a newer unknown major schema.
- `decision` enum, `action` enum. Risk scores may be added as **informational** only, not decision authority.
- SHA-256 digests are lower-case fixed-length hex and domain separated where used for authorization; distinguish **wire** and **message** identities.
- Currency is represented as **integer base units encoded as decimal strings** (no float rounding). Mint/program/network identify the asset.
- Evidence references are stable within a report and link to parsed instructions, simulated state, local intent or Cloud feed.
- `simulation.success` can be null when not run. `attempted=false` must not be encoded as `success=true`.
- `context_slot` is an observed slot, not an execution guarantee.
- `intent.provenance` enum: `verified_trusted_issuer`, `operator_configured_unverified`, `agent_supplied_untrusted`, `missing`.
- `coverage.unknown[]` includes identifiers for unsupported instruction/extension, unresolved ALT, RPC freshness, unsupported transaction version.
- `limits[]` always includes material advisory limitations; do not suppress in “quiet” JSON output.
- Tool errors must be machine-readable with sanitized codes; secrets and raw account credentials never appear.
- Optional `cloud_report_signature` includes algorithm, key ID, signature, report hash, issued/expiry and verified key provenance.

## 4. Free vs Cloud compatibility

Both modes return the **same base schema**.

Cloud may append only documented extension objects:

```json
{
  "cloud": {
    "status": "completed",
    "sources": [
      {"kind": "network_health", "source": "example", "freshness_seconds": 12}
    ],
    "billing": {
      "request_id": "<idempotent id>",
      "charge_status": "charged_once"
    }
  }
}
```

No raw proprietary feed, private claim secret or customer transaction content should leak by default. A customer must see the **reason and provenance** for a Cloud finding, not only a proprietary opaque number.

## 5. Signature design

For signed **CloudAssessment** reports (not the final CLI SecurityVerdict):

1. Define exact canonical byte encoding (e.g., canonical JSON/JCS or protobuf canonical subset with explicit rules).
2. Exclude the signature field from the signed body.
3. Domain-separate `HGUET-CLOUD-ASSESSMENT/v1` and include original message hash, intent hash, network, profile, signed Cloud findings/coverage, source provenance, evidence digest, issued-at and expiry. The final CLI decision and separate billing receipt are **not** included in this signature.
4. Sign with a server-held, rotated key; prefer ML-DSA-87 for the post-quantum profile once end-to-end implementation is verified.
5. Publish server verification keys and rotation records through an authenticated pinned-key chain.
6. Client verifies signature and freshness before indicating `report_signature_verified=true`.

A signed CloudAssessment authenticates the assessment's issuer and content, **not a proof that a payment is safe**. The final CLI SecurityVerdict is composed separately.

## 6. JSON output and tests

`--json` emits one object on stdout, not random diagnostics. Keep report deterministic under a fixed mocked network snapshot. Validate with public JSON Schema, golden vectors and negative tests. Older readers must reject unknown **major** schema versions and unknown critical enum states.

See [CLI](cli-interface.md), [security](security.md), [testing](testing-roadmap.md).