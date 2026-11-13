# HGUET CLI — Solana decoding and simulation engine

**Status:** engineering design, not a shipped parser. Official references: [references](references.md).

## 1. Engine responsibilities

The engine receives **transaction bytes**, network configuration and a policy-defined freshness requirement and produces:

1. An unambiguous description of the transaction (version, signers, payer, programs, accounts, instructions).
2. Resolved account addresses (including v0 Address Lookup Tables).
3. Simulation evidence (slot, errors, logs, compute, inner instructions, returned accounts, and optional post-balances).
4. Interpreted **net effects**: SOL/token movements, token-program variants, approvals, authority and ownership changes, and unknown effects.
5. Explicit unknown/unsupported markers. It **must not** invent or infer normality from opaque program payloads.

Engine pipeline:

```text
Wire input ──> versioned parser ──> account resolution ──> instruction IR
                                         |
              RPC genesis + slot check ──┤
                                         v
                                simulation adapter
                                         |
                       +-----------------+------------------+
                       |                                    |
                  direct effects                        CPI effects
                       |                                    |
                       +-----------------+------------------+
                                         |
                                  Effect Graph
                                         |
                                policy + verdict
```

The “Effect Graph” is an **in-memory structure**, not a graph database. Every edge has source instruction/CPI path, affected account/mint/owner, amount or authority delta, evidence reference and confidence classification.

## 2. Solana formats and canonical identity

Current official Solana docs describe **legacy**, **v0**, and **v1** transaction formats; v1 has different size and account/resource-limit semantics. The implementation must be version-aware.

- Legacy and v0: respect the documented 1,232-byte wire limit; v0 may use Address Lookup Tables (ALTs).
- v1: official docs describe a 4,096-byte wire limit and in-message resource limits; validate exact feature/activation and tested SDK compatibility before release.
- Unknown versions: `UNKNOWN/UNSUPPORTED_TX_VERSION` in policy check, never parsed as a familiar layout.
- Strict canonical fingerprint: cryptographic hash (SHA-256) of the original wire bytes **plus explicit version and network binding**, with separate hash of the transaction *message* actually intended for signing.
- **Signature differences matter:** signed and unsigned representations of the same message may have different transaction hashes. The signing binding must use the message bytes, signer roles and pinned authorization, not just a friendly transaction ID.

All indexed accounts must resolve to concrete addresses. Missing lookup table, RPC inconsistency or invalid account index → `UNKNOWN`. Resolving only static message keys in a v0 transaction is a security bug.

## 3. RPC adapter

Use a configured provider and robust JSON-RPC parser. Minimum methods:

| Method | Why |
| --- | --- |
| `getGenesisHash` | verify intended cluster; prevent mainnet/devnet confusion |
| `getSlot` / `getBlockHeight` | capture source head, freshness and local confidence |
| `getLatestBlockhash` | optional blockhash validity diagnostics |
| `getAddressLookupTable` or compatible account fetch | resolve v0 loaded addresses |
| `getAccountInfo` / `getMultipleAccounts` | token metadata, program and account owner context |
| `simulateTransaction` | obtain execution results without broadcasting |

Use allowlisted or explicit user-set endpoints; do not accept arbitrary URLs from untrusted payment intent (prevents SSRF). HTTPS and certificate validation are required for remote RPC. URLs with embedded credentials must be redacted.

Simulation request should ordinarily specify:

```json
{
  "encoding": "base64",
  "commitment": "confirmed",
  "sigVerify": false,
  "replaceRecentBlockhash": false,
  "innerInstructions": true,
  "minContextSlot": 123456
}
```

**Important constraints:**

- Unsigned transactions can be simulated with `sigVerify: false` when blockhash is valid. This **does not** prove a real signer authorized anything.
- `sigVerify: true` verifies provided signatures and is **incompatible** with `replaceRecentBlockhash: true`. Never send an internally contradictory combination.
- `replaceRecentBlockhash: true` can be useful for **diagnostic** execution when a blockhash expired, but changes simulation context and invalidates “exact bytes checked” claims. Report prominently and do not issue strict `ALLOW` for the original transaction based solely on that modified simulation.
- `minContextSlot` is a minimum acceptable context slot, **not** an instruction to execute historically at a specific slot.
- A successful simulation from one RPC is **not consensus**, finality, definitive ordering or proof of future transaction effects.
- Query balance/account deltas carefully; token transfers can affect source, destination, fees, rent and authority. An opaque instruction may cause side effects outside known decoders.

## 4. Instruction coverage and token safety

Implement in audited increments with golden fixtures:

1. **System Program:** native SOL transfer, account create/assign/allocate, fee-payer changes.
2. **SPL Token:** transfers (including checked), delegate approval/revoke, mint, burn, authority changes and close-account semantics.
3. **Token-2022:** supported extensions with feature-specific tests (transfer fees, transfer hooks, confidential transfers, metadata pointers and relevant authority changes). Unsupported extension behavior yields explicit unknowns.
4. **Associated Token Accounts:** creation and destination mint/owner validation, including fees and rent effects.
5. **Compute/priority fees:** version-appropriate accounting; unknown resource behavior not ignored.
6. **Program deployment and upgrades:** upgrade authority, ownership/loader changes, executable flags and unexpected writable accounts.
7. **Cross-program invocations:** decode returned inner instructions, correlate to outer calls, and preserve unresolved call paths.
8. **DeFi/DEX calls:** never infer a safe swap from top-level program name alone; require a supported program adapter or a demonstrably complete state/effect analysis.

For **every** debit or authority change, include the actual effected account, owner when known, mint and base units, plus source evidence. `transferChecked` mint/decimals help validation but are not substitutes for verified mint metadata. Do not treat displayed decimal amounts as authoritative integer amounts.

## 5. What Transaction X-Ray must display

```text
Network:           solana-mainnet (genesis validated)
Format:            v0
Message fingerprint: SHA256:...
Signers / payer:   ...
Programs:          resolved IDs + trust status
Intended operation: USDC payment to merchant X
SOL out:           0.000... SOL (fees; estimated)
Token out:         25_000_000 base units of USDC
Token in:          ...
Authority changes: none observed in supported interpreters
Opaque calls:      1 (analysis incomplete)
Simulation context: slot=... commitment=confirmed RPC=...
Verdict:           UNKNOWN (unresolved call)
```

This text is illustrative. **Never** show “safe” solely because authority changes were not observed; say “not observed within supported analysis”.

## 6. Network health and provider trust

Free mode: use the client's configured RPC and display provider identity, slot, commitment and lag diagnostics. Multiple RPC endpoints may be configured, with bounded sampling; disagreeing state should lower confidence or trigger UNKNOWN.

Cloud mode: optional multi-source incident and network feeds. A program upgrade or authority rotation is a **risk signal**, not automatic evidence of compromise. Threat feeds require source, freshness, confidence, corrections and retractions.

No single feed or incident status badge can independently justify “SAFE”. If server signals are stale or Cloud unavailable and required by policy, result is UNKNOWN or lower coverage.

## 7. Signature/TOCTOU boundary

Checking happens at time `T1`; an external signer may sign at `T2`, and the network executes at `T3`. State can change between all three.

A strict signer integration must:

- Bind verdict to exact message bytes, network and intent hash.
- Verify maximum verdict age and relevant blockhash lifetime.
- Reject a changed message, recipient, token amount, instruction set or fee payer.
- Require re-check after rebuilding/resigning a transaction or after expiry.
- Know that even exact-message binding cannot guarantee identical state at execution.

The CLI itself **does not** enforce signing; the customer controls signer integration.

## 8. Explicit failure cases

| Situation | Result when required |
| --- | --- |
| Wrong genesis hash / network | DENY or hard configuration error |
| Unsupported transaction version | UNKNOWN |
| Lookup tables unresolved | UNKNOWN |
| Expired blockhash / diagnostic rehash only | UNKNOWN |
| RPC simulation timeout or stale slot | UNKNOWN |
| Simulation program error | DENY as not executable under observed state, with failure reason |
| Opaque program might move money | UNKNOWN in strict mode |
| Direct forbidden recipient or exceeded hard policy | DENY |
| Program upgraded very recently | WARN or UNKNOWN by configured risk policy |
| Fully understood, authorized transfer | eligible for ALLOW (not guarantee) |

## 9. Implementation notes

Prefer official maintained Solana modular crates and verified dependencies. Solana crate APIs and transaction versions change quickly; select and pin a known-working compatibility matrix, document MSRV, cargo feature flags and golden fixtures. No hand-written raw parser in production unless an independent differential test against an official/reference implementation is maintained.

Use bounded concurrency, capped RPC logs and account responses; record rpc/version values that explain disagreement. Token symbol “USDC” is UI metadata only: **canonical asset identity = verified mint + network + token program**.

See [security](security.md), [verdict](verdict-schema.md) and [tests](testing-roadmap.md).