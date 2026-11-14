# First Rust implementation slice — unreleased

This is a **working offline wire-format prototype**, not a security-ready Solana policy agent and **not** a released version.

Run:
```sh
cargo test --workspace
cargo run -p hguet -- --help
cargo run -p hguet -- inspect transaction.bin --offline --json
cargo run -p hguet -- inspect tests/fixtures/v1-system-transfer.base64 --encoding base64 --offline --json
cargo run -p hguet -- check transaction.bin --network devnet --mode local \
  --intent signed-intent.json --trusted-key PINNED_PUBKEY --json
```

The `inspect` command now parses **legacy, v0 and v1** Solana wire structures using format-specific layouts. The v1 decoder reads its explicit resource config (including the **total** priority fee in lamports), fixed-width instruction headers and trailing signature array. It verifies any **nonzero Ed25519 transaction signatures** against the exact wire message, while accepting zero-filled unsigned placeholders in pre-signature workflows. v0 Address Lookup Table addresses remain **unresolved** until trusted RPC resolution is implemented. The decoder identifies top-level native **System Program Transfer** instructions and their integer lamports as a *lower bound* only. It cannot infer CPI, token movements, non-transfer System operations or the full amount of funds at risk. No RPC simulation, blockhash validity, wallet signing or Cloud calls are implemented.

`check` verifies **Ed25519 signed payment intent** using a separately configured trusted public key. Signed message = ASCII `HGUET-PAYMENT-INTENT`, one zero byte, and the exact UTF-8 JSON bytes contained inside the Base64 `payload_b64`; it is intentionally NOT reserialized before checking the signature. This prevents JSON formatting ambiguity. After strict signature verification, the payload must bind the parsed **Solana message SHA-256**, network and validity window.

**Important:** Signed `max_spend_lamports` is now checked against the **sum of decoded top-level native SOL Transfer instructions**; exceeding that lower bound causes `DENY`. This is not a proof that total spending is within the limit because CPI and other program effects remain unknown. A valid signed intent still yields **UNKNOWN**, never ALLOW. Nonzero invalid Ed25519 signatures cause `DENY` in `check`; missing signatures may be legitimate before signing and remain informational. A malformed transaction or invalid intent is rejected, and the customer-controlled signer retains enforcement responsibility.

`SecurityVerdict` is returned as `{"inspection":..., "verdict":...}`; the JSON Schema validates **the nested `verdict` object**. CLI exit code `30` means UNKNOWN for `check`, `20` DENY, `40` malformed input; successful informational `inspect` returns `0` but does not imply security approval.

Canonical public contracts:
- [PaymentIntent](../../protocol/v1/payment-intent.schema.json)
- [Signed intent envelope](../../protocol/v1/signed-payment-intent.schema.json)
- [Final SecurityVerdict](../../protocol/v1/security-verdict.schema.json)
- [Cloud and SOL quote contracts](../../protocol/v1/README.md)

## Restrictive offline local policies

A separate Rust crate `hguet-policy` implements **restrictive-only** local rules. A policy can forbid programs and direct SOL recipients, constrain the selected Solana network, and cap the sum of **top-level native System transfers**. It **never** authorizes spending or promotes `UNKNOWN` to `ALLOW`. Untested program-internal transfers, CPI, token effects, Solana network fees and v0 ALT addresses remain outside this limited evidence.

Example test policy:

```toml
version = 1
network = "devnet"
max_declared_system_transfer_lamports = "499"

# List Base58 Solana 32-byte public keys, not token labels.
denied_program_ids = []
denied_sol_recipients = []
# Optional positive allowlists: allowed_program_ids = ["..."]
# Optional positive allowlists: allowed_sol_recipients = ["..."]
```

```sh
cargo run -p hguet -- policy validate tests/fixtures/policy-devnet-deny.toml --json
cargo run -p hguet -- check TRANSACTION.bin --mode local --network devnet \
  --intent signed-intent.json --trusted-key PINNED_INTENT_SIGNER \
  --policy /path/to/trusted-user-policy.toml --json
```

The policy file and trusted intent authority must come from **independent user-controlled configuration**, never an AI agent's self-reported permission. A malicious agent could bypass the CLI entirely; the customer's actual wallet/signer still must enforce security decisions. An invalid policy is rejected before use. A matching/empty restrictive policy is **not** evidence of safe execution.

## Opt-in Solana JSON-RPC simulation (implemented first slice)

The public CLI includes `hguet-rpc`, a **read-only** JSON-RPC client. No RPC connection is made by `inspect --offline`, `policy validate`, `config show`, or `check` without `--rpc-url`. There is **no** HGUET Cloud connection in this mode.

```sh
cargo run -p hguet -- check TRANSACTION.bin \
  --mode local --network devnet \
  --intent signed-intent.json --trusted-key PINNED_AUTHORITY \
  --policy /trusted/local-policy.toml \
  --rpc-url https://api.devnet.solana.com --json
```

The selected **external Solana RPC provider will receive the entire serialized transaction**. The operator chooses this explicitly; use a provider acceptable for the transaction's privacy. Do not paste a private RPC URL containing an API token into logs or tickets.

Before simulating, the client validates the HTTPS URL (no embedded credentials, fragments or non-HTTPS schemes), parses the transaction locally, calls `getGenesisHash`, and rejects a mismatch against the known Mainnet/Devnet/Testnet genesis. It then requests `simulateTransaction` with:

```json
{
  "encoding": "base64",
  "commitment": "confirmed",
  "sigVerify": false,
  "replaceRecentBlockhash": true,
  "innerInstructions": true
}
```

**Why `sigVerify=false`?** Simulation with `replaceRecentBlockhash=true` conflicts with signature verification in the RPC API. The local Solana Engine separately verifies nonzero original Ed25519 transaction signatures. Replacement means a successful simulation does **not** certify future execution of the original signed transaction. Public API method: https://solana.com/docs/rpc/http/simulatetransaction.

JSON output includes optional `rpc_analysis`: verified genesis, context slot, simulated message SHA-256, `rpc_succeeded` or `rpc_failed`, compute units and bounded counts of returned logs/inner-instruction groups. Private logs themselves are **not** printed. On RPC error or mismatched network, `simulation_status=rpc_unavailable` plus an explicit reason code is returned in the **UNKNOWN** verdict. Any successful simulation remains `UNKNOWN`, not `ALLOW`; known independent local hard DENY still wins **before** contacting RPC.

The transport sets a response size limit (1 MiB), request size limit, short network timeouts, and **no redirects**. Unit tests inject a mock JSON-RPC transport and cover wrong genesis, malformed responses, conflicting status, success, simulation error, no accidental RPC before offline validation, and mutually compatible blockhash/signature options. Tests do **not** claim live Devnet simulation succeeded.

**v0 ALT address lookup (implemented as advisory):** for v0 messages referencing lookup tables, the RPC Engine also calls `getMultipleAccounts` after verified genesis and validates the returned account owner (`AddressLookupTab1e1111111111111111111111111`), serialized metadata discriminator, active table status, selected indexes and extension-slot warm-up. It resolves writable keys from all tables before read-only keys, and passes the observed ALT context slot to `simulateTransaction` as `minContextSlot`. Invalid/missing/deactivating tables, wrong owners, malformed data, or backwards-moving simulation slots fail closed to `UNKNOWN`. The `rpc_analysis.lookup_resolution` result is **one-provider, slot-scoped evidence only** and is not a consensus guarantee. Offline output still reports unresolved ALT addresses, because no network state was read.

## Solana balance deltas and CPI coverage (implemented, advisory)

The `hguet-rpc::effects` module now processes the **optional** `simulateTransaction` fields `preBalances`/`postBalances`, `preTokenBalances`/`postTokenBalances`, `innerInstructions`, `fee` and `loadedAddresses`. Every observation is tied to the explicit RPC simulation slot and the **original signed message hash**; for v0, loaded addresses are matched against the separately checked lookup-table resolution.

Results are returned under `rpc_analysis.effect_analysis`:

- `lamport_deltas`: per-account address, before/after and signed change in exact **lamports** (string integers, not floating point).
- `token_deltas`: token-account index/address, mint, decimals, owner when supplied, raw token-unit balances and delta **only when both comparable sides are present**. New/closed or inconsistent account state is **not** silently treated as zero.
- `cpi`: whether internal instructions were recorded, number of groups/instructions, invoked program IDs validated against account indexes, and explicit need for semantic review. `innerInstructions=null` is **missing coverage**, not proof of zero CPI.
- `simulated_fee_lamports`: fee only if the RPC provided a well-formed integer.
- `observed_fields`, `missing_fields` and `warnings`: explicit evidence coverage. `security_coverage` is **always** `partial_untrusted_rpc`.

Malformed or inconsistent arrays, invalid account indices, duplicate token records, wrongly encoded amounts, CPI indices, mismatched `loadedAddresses` and unsupported metadata cause `rpc_unavailable`/`UNKNOWN`, never `ALLOW`. JSON-RPC responses are capped at 1 MiB; nested token/CPI collections have explicit bounds. Raw log text is never copied into the CLI's analysis output.

### Advisory comparison with independently verified PaymentIntent

When `hguet check` has validated a signed PaymentIntent against the separately pinned `--trusted-key`, a successful single-provider RPC simulation can now add two **high-risk advisory findings** without changing the final `UNKNOWN` decision:

- `RPC_CPI_OUTSIDE_SIGNED_INTENT`: a captured inner instruction names a program ID absent from the signed `allowed_program_ids`. This is a prompt to inspect the behavior, not independent proof that the CPI was malicious or that RPC captured every CPI.
- `RPC_FEE_PAYER_NET_OUTFLOW_OVER_CAP`: paired native balance observations show that account index 0 (the fee payer) lost more lamports **net** than the signed `max_spend_lamports`. Network fees contribute to this loss and incoming transfers can mask outgoing spending, so this is not an accurate gross-spend calculation.

The comparison runs only after trusted intent verification and only when `rpc_succeeded`. A missing trusted key, missing relevant RPC fields, or a failed simulation does not fabricate a mismatch. No provider-supplied observation can promote the decision to `ALLOW` or cause a definitive local `DENY`; the external signer must still enforce the authorization independently.

**Limitations:** Not every RPC provider emits all of these optional simulation fields. The simulation may use a replacement blockhash and does not prove the transaction will execute on-chain. A token change observed across two RPC snapshots **is not** complete attribution of all CPI effects, and a successful response alone does not certify authorization, exact eventual debits, consensus state or token-program semantics. Even when every optional field is populated, the local `SecurityVerdict` stays `UNKNOWN`.

Source: [official Solana RPC simulation result and balance/CPI structures](https://solana.com/docs/rpc/json-structures) and [simulateTransaction API](https://solana.com/docs/rpc/http/simulatetransaction).

Still outstanding: independently corroborated/atomic v0 Address Lookup Table **state**, finalized post-execution `getTransaction` audit, complete CPI and Token-2022 semantic decoding, reliable pre-sign fee and **total** debit limits, RPC multi-provider cross-checks and trusted policy enforcement at the external signer. Until those exist, remote simulation alone cannot justify `ALLOW`.


### Compiled SPL Token CPI decoding — bounded advisory subset

The RPC request explicitly sets `innerInstructionsEncoding: "json"` alongside `innerInstructions: true`. This requests compiled instruction `programIdIndex`, indexed `accounts`, and Base58 `data` instead of trusting provider-authored `jsonParsed` summaries. If a provider supplies only parsed instruction fields, HGUET records **opaque** token CPI evidence rather than trusting that parsed semantic claim.

For instructions whose program ID exactly matches the original SPL Token Program or Token-2022, `effect_analysis.cpi` now provides:

- `token_instructions`: bounded observations, each with parent/inner instruction indexes, token program ID, selected operation, role-specific resolved accounts and optional unsigned raw amount/decimals/authority type/new authority. The declared amount is **not** a verified net effect.
- `opaque_token_instruction_count`: token CPI entries whose binary semantics cannot be decoded (including unknown tags, unexpected binary layouts and missing compiled data).
- `token_2022_extension_instruction_count`: opaque Token-2022 CPI entries with extension or future opcode (25 or higher); they may contain hooks, transfer fees, withheld balances or other authority effects and must not be treated as ordinary transfers.
- `missing_compiled_token_data_count`: token CPI entries lacking canonical compiled account indices/data; `jsonParsed` text never substitutes for binary evidence.

The decoder recognizes a limited byte-level subset of common SPL Token instructions: `Transfer`, `TransferChecked`, `Approve`, `ApproveChecked`, `Revoke`, `SetAuthority`, `MintTo`, `MintToChecked`, `Burn`, `BurnChecked`, `CloseAccount`, `FreezeAccount`, `ThawAccount` and `SyncNative`. It does **not** resolve account owners, actual signature authorization, multisig conditions, mint extension state, Token-2022 runtime semantics, hook effects, confidential flows, or verify that reported CPI was executed on-chain.

Only on `rpc_succeeded`, the CLI can emit `RPC_TOKEN_CPI_AUTHORITY_RISK` (approval, authority or account control), `RPC_TOKEN_CPI_MOVEMENT` (declared token movement), and `RPC_TOKEN_CPI_OPAQUE` (unparsed token semantics). They are advisory findings, **not** conclusive `DENY` and never a reason for `ALLOW`. A failed simulation cannot prove completion of any CPI. Unknown, unsupported and absent metadata remain unknown.

References: [Solana simulation CPI encoding](https://solana.com/docs/rpc/http/simulatetransaction), [Solana transaction metadata](https://solana.com/docs/rpc/json-structures), [SPL Token instruction layout](https://docs.rs/spl-token-interface/latest/spl_token_interface/instruction/enum.TokenInstruction.html), [Token-2022 extensions](https://www.solana-program.com/docs/token-2022).

### Token-2022 extension classification — phase 1 (advisory)

The parser additionally labels Token-2022 CPI instruction **prefixes** from binary Base58-encoded `data`, never from untrusted `jsonParsed` strings. The new `effect_analysis.cpi.token_2022_extension_observations` array records the parent/inner CPI index, top-level discriminator and recognized family, plus:

- `layout_checked=false` for an unrecognized/truncated layout or family-only hint; a known prefix alone is **not** proof that its inner instruction is valid.
- `layout_checked=true` only for exactly parsed `TransferCheckedWithFee` (26/1), `SetTransferFee` (26/5), `InitializePermanentDelegate` (35), `InitializeTransferHook` (36/0), and `UpdateTransferHook` (36/1). Extracted fields are **declarations**, not authenticated configuration or proof of execution.
- For Transfer Fee, optional raw amounts, expected fee, basis points and maximum fee; for Permanent Delegate and Transfer Hook, selected key/address roles. The Token-2022 prefix discriminants and subtypes follow the published SPL Token-2022 interface.
- Family-only hints for confidential transfers/fees/mint-burn, CPI guard, pause, non-transferable, account reallocation, pointer/configuration extensions and unknown future opcodes. These remain **opaque**.

Even when some exact fields are parsed, `opaque_token_instruction_count` and `token_2022_extension_instruction_count` still include these extensions: their state-dependent semantics have **not** been validated. In particular, this CPI classifier does not by itself authenticate or execute transfer-hook programs, verify Token-2022 mint configuration, or validate fee formulas against an atomic execution-state snapshot. An extension can exist on a mint **without any extension instruction appearing in simulated CPI**; absence of these observations is never proof of absence of fees/hooks/delegates.

After a successful advisory RPC simulation, the CLI may emit these findings for extension instructions **or for corresponding extension-authority rotations in a Token-2022 `SetAuthority` CPI** (authority types `4`/`5` for transfer fees, `8` for permanent delegate, `10` for transfer hook, and `9`/`11` for confidential authorities):

- `RPC_TOKEN_2022_TRANSFER_FEE`: transfer-fee operations, configuration or authority rotation mentioned in CPI.
- `RPC_TOKEN_2022_TRANSFER_HOOK`: hook initialization/update or hook-authority rotation mentioned in CPI.
- `RPC_TOKEN_2022_PERMANENT_DELEGATE`: initialization or rotation of a mint-wide delegate mentioned in CPI.
- `RPC_TOKEN_2022_CONFIDENTIAL_EFFECTS`: confidential transfer, confidential fee or mint/burn extension CPI families mentioned in CPI.

All findings remain high-risk advisory hints, return `UNKNOWN`, do **not** broadcast or sign, and do not authorize a transaction. To enforce actual payment constraints, future work needs authenticated mint/account data, full extension state validation, transaction-level direct + CPI effects, independent provider comparisons, and customer-controlled signer integration.

Sources: [Token-2022 interface discriminants](https://docs.rs/spl-token-2022-interface/latest/src/spl_token_2022_interface/instruction.rs.html), [Transfer Fee instruction layout](https://docs.rs/spl-token-2022-interface/latest/src/spl_token_2022_interface/extension/transfer_fee/instruction.rs.html), [Transfer Hook instruction layout](https://docs.rs/spl-token-2022-interface/latest/src/spl_token_2022_interface/extension/transfer_hook/instruction.rs.html), [Solana transfer fees](https://solana.com/docs/tokens/extensions/transfer-fees), [Solana permanent delegate](https://solana.com/docs/tokens/extensions/permanent-delegate).

## Opt-in Token-2022 mint TLV snapshot (implemented, advisory)

After a successful opt-in Solana RPC simulation, HGUET may issue **one additional read-only `getMultipleAccounts` request to the same selected RPC** for at most 16 candidate mints. Candidates are derived from reported token balance changes and compiled Token-2022 CPI instructions. No request happens for an offline check, failed simulation, or absent candidates. If there are more than 16 candidates, HGUET refuses to silently truncate the risk set and reports unavailable evidence.

The request uses `encoding=base64`, `commitment=confirmed`, and `minContextSlot=<simulation slot>`. This enforces only a **minimum RPC context slot**, NOT an atomic read of the bank used by `simulateTransaction`. The output includes `rpc_analysis.mint_snapshot.simulation_slot`, `context_slot`, `atomic_with_simulation=false`, and per-address status (`token_2022`, `not_token_2022`, or `missing`). Invalid, stale or conflicting provider responses fail closed to `UNKNOWN`.

For a Token-2022-owned mint the parser checks the base 82-byte mint state, 83-byte zero padding, account type byte at **offset 165**, and TLV entries starting at **offset 166**. It rejects truncated or duplicate extensions, wrong account-only extension types, unsupported sizes and invalid decoded layouts. The bounded TLV list records all recognized type IDs; unknown types remain explicitly opaque.

The current byte-level **mint-state** decoders cover:

- `TransferFeeConfig` (type 1): config/withdraw authorities, withheld raw amount and older/newer fee schedules, including epoch, basis points, maximum fee.
- `PermanentDelegate` (type 12): optional non-zero pubkey for mint-wide delegation.
- `TransferHook` (type 14): optional update authority and hook program pubkey.
- `NonTransferable` (type 9): presence with exactly empty payload.

Other mint extension types, including confidential transfer configuration, default account state, pausable, interest-bearing, pointer and metadata extensions, remain **present-but-not-semantically-validated**. Account-side Token-2022 extensions are inspected separately as **non-atomic RPC evidence**, with only a limited subset of payloads decoded; see the following section.

The CLI now reports advisory `RPC_MINT_TRANSFER_FEE_CONFIG`, `RPC_MINT_TRANSFER_HOOK_ACTIVE`, `RPC_MINT_PERMANENT_DELEGATE_ACTIVE`, `RPC_MINT_CONFIDENTIAL_EXTENSION`, `RPC_MINT_UNKNOWN_EXTENSION`, `RPC_MINT_OPAQUE_EXTENSION_STATE`, `RPC_MINT_STATE_MISSING`, and `RPC_MINT_STATE_NON_ATOMIC` as appropriate. The risk checks do not promote any transaction to `ALLOW`. Even a mint with no detected extension is **not evidence of full transaction safety**, because CPI can move funds through other accounts, mint state can change, and simulated results are provider-supplied.

This is **single-provider snapshot correlation**, not verified on-chain finality or a signer-enforced authorization policy. The next stages require transaction-instruction-to-mint provenance, authenticated and atomic account/mint state, consistency across providers and slots, more complete Token-2022 extension semantics, and signer-controlled enforcement.

Source: [Solana `getMultipleAccounts`](https://solana.com/docs/rpc/http/getmultipleaccounts), [official Token-2022 TLV layout](https://docs.rs/spl-token-2022-interface/latest/src/spl_token_2022_interface/extension/mod.rs.html), [Token-2022 extension IDs](https://docs.rs/spl-token-2022-interface/latest/spl_token_2022_interface/extension/enum.ExtensionType.html).

## SPL Token / Token-2022 token-account state and correlation (implemented, advisory)

After a **successful** opt-in simulation, HGUET may make one further `getMultipleAccounts` request to the *same selected RPC* for up to **16 token holding account addresses** derived from paired token-balance metadata. This is distinct from the previously implemented mint lookup. No extra call occurs without candidate accounts, in offline mode, or after a failed simulation. Excessive candidates or a conflicting account→mint mapping are rejected rather than truncated.

The request uses `encoding=base64`, `commitment=confirmed`, and `minContextSlot=<simulation slot>`. The JSON output includes `rpc_analysis.token_account_snapshot`, with both `simulation_slot` and `context_slot` and explicit `atomic_with_simulation=false`. A minimum slot is **not** a pinned transaction bank; a later account may have changed after simulation. HGUET does not equate its current amount with either the simulated pre- or post-balance, and never treats cross-slot agreement as proof of safe execution.

For **both legacy SPL Token and Token-2022-owned token accounts**, the reader checks the exact 165-byte base layout, COption delegate/native/close-authority tags and initialized/frozen state. Legacy SPL Token accounts must be **exactly 165 bytes**; only Token-2022 accounts can contain `account_type=2` at offset 165 and TLV from 166. It rejects malformed, repeated, truncated and mint-only extensions. It recognizes:

- **Account base:** mint identity, owner authority, raw balance, delegate and delegated raw amount, frozen state, native reserve and close authority.
- **TransferFeeAmount** (type 2): exact `u64` withheld raw tokens on this account, not total paid fees.
- **MemoTransfer** (8), **CpiGuard** (11), **TransferHookAccount** (15): exact one-byte boolean flags, including required inbound memo, CPI restrictions and in-transfer hook flag.
- **ImmutableOwner** (7), **NonTransferableAccount** (13): exact empty-payload presence.
- **ConfidentialTransferAccount** (5), **ConfidentialTransferFeeAmount** (17), **PausableAccount** (27), unknown future types: explicit **opaque** presence, never default-safe.

For each token account, HGUET reports whether the later snapshot's base mint and authority agree with simulation-reported mint/owner, plus whether its mint appeared in the separate Token-2022 mint snapshot. This is **cross-slot correlation**, not an independent proof or a hard local `DENY`. A disagreement generates `RPC_TOKEN_ACCOUNT_MINT_MISMATCH` or `RPC_TOKEN_ACCOUNT_AUTHORITY_MISMATCH`. Missing mint correlation, missing holding accounts, frozen state, active delegate, withheld fees, required memo, CPI Guard, non-transferability, confidential/unknown extensions and non-atomicity are surfaced as distinct advisory CLI findings.

**Scope limit:** the initial token-account read still fetches only accounts in simulated pre/post token-balance metadata. If an **independently verified, signed** `token_source_limits` intent names an actually used source absent from that initial batch, a **separate signed-source-only RPC batch** can now fetch it (up to 32 distinct omitted sources). CPI-only accounts, unsigned/unpinned intent addresses, omitted metadata, token-program hooks, multisig authorization, alternate mint states and final settlement remain unverified. An absent or failed extra read never implies a safe source. A successful snapshot **always retains `UNKNOWN`** for security approval. The wallet/signer must enforce any authorization independently. More account reads are disclosed to the chosen third-party RPC provider; no Cloud endpoint is contacted in local mode.

References: [Solana getMultipleAccounts](https://solana.com/docs/rpc/http/getmultipleaccounts), [official Token Account base struct](https://docs.rs/spl-token-2022-interface/latest/spl_token_2022_interface/state/struct.Account.html), [Token-2022 extension identifiers](https://docs.rs/spl-token-2022-interface/latest/spl_token_2022_interface/extension/enum.ExtensionType.html), [Transfer Fee Account](https://docs.rs/spl-token-2022-interface/latest/spl_token_2022_interface/extension/transfer_fee/struct.TransferFeeAmount.html), [CPI Guard](https://docs.rs/spl-token-2022-interface/latest/spl_token_2022_interface/extension/cpi_guard/struct.CpiGuard.html).

## Effect Correlation Engine — deterministic advisory graph

The opt-in RPC response now includes `rpc_analysis.effect_graph` after strict transaction parsing, simulation metadata checks and any optional mint/token-account lookups. It is a **bounded in-memory evidence index**, not a blockchain graph database, execution trace proof, exact-spend ledger, or policy ALLOW engine.

The graph has namespaced `nodes` (`account`, `mint`, `authority`, `program`, `asset`), `edges` with explicit source/target, relation, amount when genuinely available, optional mint, top-level/CPI instruction indexes, RPC slot and attribution category. Deterministic node order and explicit hard limits (512 nodes / 1,024 edges) prevent unbounded output; the existing bounded RPC parsers also limit source input.

Evidence provenance is **not merged**:
- `original_wire` / `declared_only`: explicitly decoded top-level System transfers and program identities from the original transaction. These are declarations, not executed transfers.
- `rpc_paired_balances` / `rpc_token_balances` with `rpc_observed`: native and token **net** deltas from complete simulated balance pairs; partial token rows remain partial and never assume zeros.
- `rpc_compiled_cpi` / `rpc_observed`: selected token transfers, mint/burn and authority/delegation instructions, retaining parent and inner CPI indexes and their declared raw amounts. Their **causal attribution to net balance differences is unknown**: intermediate movements, Token-2022 fees, hooks, multiple instructions and compensating flows cannot be recovered by matching quantities.
- `rpc_later_mint_account` and `rpc_later_token_account` / `later_non_atomic_state`: mint→hook/delegate and holding→mint/owner/delegate links from separate snapshot calls. Each edge retains the separate context slot. Even matching slots do not prove an atomic transaction-bank snapshot.

The graph also carries `sources` (with slot and explicit non-atomic flags), `evidence_gaps` (e.g. missing paired snapshots, opaque CPI, unresolved lookup addresses, missing state, cross-slot state), and `alerts` (e.g. CPI gross-vs-net attribution unproven, mint/authority disagreement, delegated privileges and hook/fee changes). The invariants `execution_proven=false`, `spend_limit_enforced=false` and `security_coverage="partial_untrusted_rpc"` do not change when all graph edges are populated.

Only on successful simulation, the CLI can add `RPC_EFFECT_GRAPH_CPI_UNATTRIBUTED`, `RPC_EFFECT_GRAPH_IDENTITY_CONFLICT` and `RPC_EFFECT_GRAPH_OPAQUE_CPI` advisory findings. A failed simulation creates **wire-declaration-only** edges; it never fabricates simulated effects. A successful simulation stays `UNKNOWN` rather than `ALLOW`, including if no graph alert appears.

Next steps: independent/atomic state validation, direct **top-level** SPL Token instruction decoding, richer CPI effect coverage, accounting for multiple transfers and fees, cross-provider checks, and signer-side enforcement of a separately pinned payment policy.

## Direct SPL Token / Token-2022 instruction decoding (implemented, advisory)

The original-wire parser in `hguet-core` now preserves every bounded compiled top-level instruction as `inspection.compiled_top_level_instructions`, including its instruction index, indexed program/account roles and Base58-encoded original instruction bytes. This is wire **declaration evidence**, not RPC simulation output, signature authorization or verified execution.

The shared binary decoder in `hguet-rpc/src/direct_token.rs` recognizes common Token Program and Token-2022 **base** opcodes: `Transfer`, `TransferChecked`, `Approve`, `ApproveChecked`, `Revoke`, `SetAuthority`, `MintTo`, `MintToChecked`, `Burn`, `BurnChecked`, `CloseAccount`, `FreezeAccount`, `ThawAccount` and `SyncNative`. Unknown/unsupported opcodes, including state-dependent Token-2022 extensions, remain **opaque** with optional extension-family hints. Unchecked `Transfer` has no mint argument; HGUET never invents its mint or decimals.

The CLI now emits offline wire-declaration warnings `WIRE_TOKEN_DIRECT_MOVEMENT`, `WIRE_TOKEN_DIRECT_UNCHECKED_TRANSFER`, `WIRE_TOKEN_DIRECT_AUTHORITY_RISK` and `WIRE_TOKEN_DIRECT_OPAQUE`. For a legacy SOL-only PaymentIntent without `token_spend_limits`, the CLI emits `SIGNED_INTENT_TOKEN_CAP_UNSPECIFIED` when direct wire instructions declare token movement/approval or contain opaque token bytes. A signed mint-cap extension is now supported as described below; the older SOL-only intent remains valid and does not acquire implied token authorization. They do **not** depend on simulation succeeding, and none alone grants or enforces a spend cap. If lookup accounts are unresolved, the offline check reports `WIRE_TOKEN_DIRECT_ALT_UNRESOLVED` rather than manufacturing program/account roles. When RPC ALT resolution is explicitly opted in, the structured `rpc_analysis.direct_token_analysis` marks resolved program and account identities as dependent on one provider (`program_address_from_lookup`, `account_addresses_from_lookup`). Those IDs must not be silently upgraded to independently verified trust.

The Effect Correlation Graph adds `wire_declared_token_transfer`, `wire_declared_token_mint`, `wire_declared_token_burn`, `wire_declared_token_approval` and authority-control links with `source="original_wire"`, `attribution="declared_only"`, **no RPC slot**, and an original top-level instruction index. They remain separate from `cpi_declared_token_transfer` and `simulated_token_net_delta`. Direct wire declarations still appear in the graph when `simulateTransaction` fails; no CPI/net effect is thereby invented. The graph flags unsupported direct token payloads, unchecked-mint ambiguity and ALT trust dependencies.

Security boundary: decoding original bytes does **not** establish that a token account belongs to the correct mint/program, that a delegate is authorized, that the transaction will execute as simulated, or that its total SOL/token debit is below a signed limit. Transaction-local signature checks, independently verified PaymentIntent, user-controlled policy, RPC effects and any future signer-side controls remain distinct. `ALLOW` is not implemented.

Primary references: [official SPL Token instruction interface](https://github.com/solana-program/token/blob/main/interface/src/instruction.rs), [Solana token transfer guidance](https://solana.com/docs/tokens/basics/transfer-tokens), [Solana v0 ALT semantics](https://solana.com/docs/core/transactions/versioned-transactions).

## Signed per-mint token debit limits (implemented, **direct-wire scope only**)

The existing exact-byte Ed25519-signed `PaymentIntentPayload` v1 can now **optionally** carry `token_spend_limits` without changing its signature domain, major version, or legacy required fields. Omission preserves old SOL-only semantics. Every entry has a canonical Base58 mint address decoding to **32 bytes** and `max_debit_raw`: a canonical unsigned decimal `u64` in the token mint's raw units. **Zero is valid** and forbids direct debit of the mint. At most 16 different mint entries are accepted; duplicate mints, invalid keys, negative/decimal/leading-zero strings, overflow and unrecognized fields are rejected before any RPC request. No decimals or floating-point conversions are involved.

Example of the new **optional signed payload field** (mint addresses below are placeholders, not payment destinations):

```json
"token_spend_limits": [
  {"mint":"<32-byte-mint-address-in-base58>","max_debit_raw":"1000000"}
]
```

When present, the local verifier parses and sums only these top-level **original wire instructions** with an explicitly named mint and exact raw amount: SPL Token / Token-2022 `TransferChecked` and `BurnChecked`, and Token-2022 `TransferCheckedWithFee` (source debit is the declared amount; the stated fee is a recipient-side withholding parameter, not a second source debit). The sum for each mint uses checked `u128` accumulation and is compared to its signed `u64` ceiling. A missing mint, direct declared overage, unresolved ALT, malformed or unsupported direct Token Program instruction—including unchecked `Transfer`, authority/approval instructions and unknown Token-2022 extension opcodes—makes signed-intent validation **fail closed** (`INTENT_REJECTED`/DENY). This is intentionally restrictive: an operation that the decoder cannot bound does not get a free pass.

The CLI returns `signed_token_spend_review` with the per-mint **declared** totals, signed raw limits, number of checked direct debit instructions, `limits_enforced_on_direct_wire_declarations=true`, `total_spending_proven=false`, and coverage text. It also emits `SIGNED_INTENT_TOKEN_CAP_PARTIAL_COVERAGE` and stays `UNKNOWN` even if direct declarations are within the signed caps. Signer privileges, mint/token account state, fees, token authority and **CPI or arbitrary program-induced token transfers** are not proven by the direct-wire validator; the limit is **not** a transaction-wide spending guarantee.

If the user **opts in** to simulation and separately verifies the signed intent, the CLI compares provider-reported checked token CPI debit declarations and Token-2022 `TransferCheckedWithFee` hints, as well as observed negative token-account net deltas, with the same mint caps. It can report `RPC_SIGNED_TOKEN_MINT_OUTSIDE_CAPS`, `RPC_SIGNED_TOKEN_CPI_OVER_CAP`, `RPC_SIGNED_TOKEN_NET_LOSS_OVER_CAP` and `RPC_SIGNED_TOKEN_CAP_INCOMPLETE`. These are warnings only, because one RPC provider's CPI and pre/post balance data do **not** establish exact gross spending, asset ownership, hook effects or final execution. Matching RPC numbers are never used to authorize `ALLOW`, and RPC mismatches alone do not create a hard signed-intent rejection.

The Cloud pay-per-check fee **still uses native SOL only**, independently of the SPL-token limits for the *protected* transaction. The private Cloud server has not been deployed as a token-cap enforcement service.

Reference: [Token-2022 checked fee transfer layout](https://docs.rs/spl-token-2022-interface/latest/src/spl_token_2022_interface/extension/transfer_fee/instruction.rs.html), [Token Program checked transfer format](https://solana.com/docs/tokens/basics/transfer-tokens).

## Signed source-account / signer-role limits (implemented, direct-wire scope)

The independently Ed25519-signed `PaymentIntentPayload` v1 supports a second **optional** field, `token_source_limits`, in addition to the existing optional `token_spend_limits`. Existing exact-byte SOL-only and mint-only signed intents remain valid **without changing version or signature domain**. Every entry contains `mint`, `source_token_account`, `authority` (canonical 32-byte Base58 pubkeys) and `max_debit_raw` (canonical unsigned `u64`), with at most **32 distinct source accounts**. Duplicate sources, even under different mints or authorities, invalid keys, malformed numbers and unsupported source shapes fail verification before RPC.

Signed example **field only**, not a usable payment destination:

```json
"token_source_limits": [{
  "mint": "<canonical-mint-pubkey>",
  "source_token_account": "<canonical-SPL-token-account-pubkey>",
  "authority": "<canonical-transaction-required-signer-pubkey>",
  "max_debit_raw": "500000"
}]
```

When provided, HGUET inspects **every** original-wire Token/Token-2022 instruction and fails closed on anything except the small strict checked-debit subset: direct `TransferChecked`, `BurnChecked`, and `TransferCheckedWithFee`, requiring **exactly** four, three, or four token account-role entries respectively. This intentionally excludes multisig and instructions with extra hook accounts until full authorization semantics are implemented. For each checked debit it binds the mint, **source token account** (instruction role 0), and **authority** (role 3, 2, or 3) to an exact signed scope and sums raw debits in checked `u128` per source. Every authority must be one of the **first `num_required_signatures` static transaction keys**. An absent scope, non-required signer, different authority, duplicate source, excess amount, unresolved ALT or unknown direct token opcode triggers signed-intent rejection and a CLI `DENY` (not a false zero debit).

If both optional fields are present, **both constraints apply**: the sum per mint and the sum for each bound source+authority must each remain within the respective signed maximum. A signed `token_source_limits: []` forbids any direct Token Program debit (rather than granting an implicit wildcard). The CLI reports `signed_token_source_review` with declared raw amounts, exact source/mint/authority, signed source ceiling, `transaction_required_signer_role_checked`, `transaction_signatures_verified`, `token_account_owner_verified=false`, and `total_spending_proven=false`. A verified signed source restriction adds the advisory finding `SIGNED_INTENT_SOURCE_SCOPE_PARTIAL_COVERAGE`; **it never promotes to `ALLOW`**.

With **explicit opt-in RPC simulation** and a separately verified signed source cap, HGUET also compares the provider's selected checked CPI source/mint/authority claims and (when available) a later legacy SPL Token or Token-2022 holding-account snapshot. Advisory findings include `RPC_SIGNED_SOURCE_CPI_OUTSIDE_SCOPE`, `RPC_SIGNED_SOURCE_CPI_OVER_CAP`, `RPC_SIGNED_SOURCE_ACCOUNT_CONFLICT` and `RPC_SIGNED_SOURCE_EVIDENCE_INCOMPLETE`. CPI declarations can be absent, partial or inconsistent; later account state is a **different-slot, single-provider observation**, not authoritative pre-execution proof. These findings do not cause an independently verified hard policy `DENY` and cannot authorize `ALLOW`.

**Account authority reconciliation (implemented, advisory):** The CLI now returns `signed_source_authority_evidence` when a signed source review and successful opt-in RPC simulation are available. For each **actually used signed source**, it compares the original-wire Token / Token-2022 program ID and signed mint to the later observed account program and base mint, then distinguishes `observed_owner`, `observed_delegate`, **`observed_permanent_delegate`** (only when separately observed Token-2022 mint state names the signer), `unmatched` and `unobserved` authority relationships. It checks whether the **later** delegated allowance and token balance cover the declared direct debit and records frozen or restricted/opaque extension state. The report exposes the simulation slot, later account context slot and optional separate **mint context slot**, `atomic_with_simulation=false`, `authorization_proven=false` and `total_spending_proven=false`. Mint-level PermanentDelegate can authorize transfers and burns without appearing as the token-account owner or ordinary delegate, but the mint RPC evidence is also non-atomic. It is a **comparison between independently signed wire claims and untrusted account observations**, not a transfer authorization or wallet-signature approval.

CLI warnings include `RPC_SOURCE_AUTHORITY_NON_ATOMIC`, `RPC_SOURCE_AUTHORITY_UNOBSERVED`, `RPC_SOURCE_AUTHORITY_PROGRAM_CONFLICT`, `RPC_SOURCE_AUTHORITY_MINT_CONFLICT`, `RPC_SOURCE_AUTHORITY_ROLE_UNMATCHED`, `RPC_SOURCE_AUTHORITY_DELEGATE_ALLOWANCE_LOW`, `RPC_SOURCE_AUTHORITY_BALANCE_LOW`, `RPC_SOURCE_AUTHORITY_FROZEN`, and `RPC_SOURCE_AUTHORITY_EXTENSION_UNRESOLVED`. A valid account delegate or mint-level permanent delegate matching the signed instruction authority **does not by itself constitute an owner mismatch**. With no mint-state observation, a Token-2022 signer-role difference is uncertain rather than a confirmed unauthorized transaction. Nevertheless, a later delegate allowance is **not a historical pre-execution allowance**. Token accounts not returned from either the original balance-driven snapshot or the new signed-source-only snapshot remain explicitly `unobserved`, never implicitly matching. All these warnings remain **advisory**; independent local policy and signed-wire violations are the only supported hard-DENY reasons.

**Source Account Evidence Coverage (implemented, advisory):** After a successful **explicit opt-in** simulation, the CLI takes only the actually used source addresses from a **separately verified signed** `token_source_limits` review. The first account request (RPC id 5) still reads at most 16 token-balance-derived accounts. A **second request (id 6) occurs only when at least one signed source is missing from that primary snapshot**, to the same user-selected RPC using `getMultipleAccounts`, `base64`, `confirmed` and `minContextSlot` at least the primary snapshot slot or simulation slot. No duplicate account address is re-read; no extra RPC request is performed when all signed sources are already included, no valid signed source exists, simulation failed or offline mode is active. At most 32 source addresses are fetched in one additional request; conflicting source→mint/program mappings, oversized responses, stale slot, invalid base64 and malformed account data fail closed at the decoder boundary.

The output contains a separate `signed_source_account_snapshot` with its own `simulation_slot`, `context_slot`, `atomic_with_simulation=false`, signed mint and original-wire token program identity, read status (including missing/other-program), and the strictly parsed account state when available. It is *not* merged into the simulation metadata balance snapshot: these are different evidence origins. `signed_source_authority_evidence` now accepts both snapshots, selects **one source observation** per used signed address, records its `context_slot` and optional `missing_signed_source_context_slot`, and compares owner/delegate/allowance, frozen status, mint, token owner program and Token-2022 PermanentDelegate without fabricating an execution bank. A failed supplemental read produces `RPC_SIGNED_SOURCE_ADDITIONAL_READ_UNAVAILABLE` and preserves missing coverage. Account/slot conflicts produce `RPC_SOURCE_AUTHORITY_EVIDENCE_INVALID` rather than authorizing spend. Every successful correlation retains `authorization_proven=false` and `total_spending_proven=false`; all related findings are **advisory**, not hard signed-policy DENY.

**Critical distinction:** The message's signer *role* is not a verified onchain token-account owner/delegate. An unsigned pre-signing transaction can satisfy the *required-signer placement check*, while `transaction_signatures_verified=false`. Even complete Ed25519 transaction signatures prove only who signed the message, **not** that the stated key owns or can spend tokens from the account. Frozen state, permanent delegates, multisig, program authority, mint-account state, CPI/hook flows, fees and total gross spending require separate evidence and enforcement. RPC simulation remains advisory, not authorization.

The optional source scope governs the **protected transaction**, not HGUET Cloud billing. The proposed pay-per-check Cloud payment continues to use native SOL only. No real transfer, wallet secret, server deployment or automatic transaction signing is performed.

References: [Solana message signer ordering](https://solana.com/docs/core/transactions/transaction-structure), [SPL TransferChecked source/mint/owner roles](https://solana.com/docs/tokens/basics/transfer-tokens).

## CPI Source Coverage — bounded, RPC-attributed evidence (implemented, advisory)

After **explicit opt-in** Solana simulation succeeds, the existing RPC CPI decoder records selected SPL Token / Token-2022 **compiled inner instruction** source account roles. The new `crates/hguet-rpc/src/cpi_source_rpc.rs` collects sources from decoded transfers (including unchecked `Transfer`), checked transfers, burns, approvals, revoke/close/freeze/thaw/sync-native operations and **exactly decoded** Token-2022 `TransferCheckedWithFee`. A Token-2022 fee transfer's source address comes from compiled account index 0; its declared mint comes from index 1. Unrecognized, malformed or parsed-only CPI instructions are **not** assigned invented sources or amounts. `SetAuthority` can affect a mint as well as a holding account and is not blindly interpreted as a source token account.

For up to **32 distinct CPI source accounts** not already observed in the simulation token-balance account snapshot or optional verified signed-source-only snapshot, HGUET makes **at most one additional** `getMultipleAccounts` request (JSON-RPC id 7) to the **same user-selected RPC endpoint**. The request uses `base64`, `confirmed` and `minContextSlot` at least as high as the simulation, previous token-account and supplemental signed-source snapshots. There is **no request** when there are no decoded CPI sources, CPI recording is missing, no new addresses remain, no RPC opt-in was given, or simulation failed. Conflicting program identities for the same CPI source, 33 or more missing accounts, stale slots, malformed binary account state, duplicated or unrelated evidence fail closed as unavailable coverage. No provider-issued CPI identity is promoted to signed-wire provenance.

The CLI adds two **separate** objects to its opt-in RPC JSON response:

- `cpi_source_account_snapshot` — standalone later-slot account observations selected from the *single provider's* CPI claims: source address, claimed token program, separately decoded SPL Token/Token-2022 holding-account state or missing/other-program status, `simulation_slot`, `context_slot`, `atomic_with_simulation=false`. This is not merged with earlier balance or signed-source snapshots.
- `cpi_source_coverage` — per-instruction reference to `parent_instruction_index` / `inner_instruction_index`, `source_account`, claimed mint when **explicitly present in the CPI opcode**, declared raw amount, authority, and **observation origin** (`balance_rpc`, `signed_source_rpc`, `cpi_source_rpc`, or `unobserved`) plus that observation's actual later RPC slot. It checks matching token program, mint when declared, owner/delegate, delegate allowance, observed balance and frozen status. Unchecked `Transfer` has no declared mint; a later account mint is observed separately and **never backfilled into the CPI declaration**.

Findings include `RPC_CPI_SOURCE_NON_ATOMIC`, `RPC_CPI_SOURCE_SEMANTICS_INCOMPLETE`, `RPC_CPI_SOURCE_UNOBSERVED`, `RPC_CPI_SOURCE_PROGRAM_MISMATCH`, `RPC_CPI_SOURCE_MINT_MISMATCH`, `RPC_CPI_SOURCE_UNCHECKED_MINT`, `RPC_CPI_SOURCE_AUTHORITY_UNRESOLVED`, `RPC_CPI_SOURCE_DELEGATE_ALLOWANCE_LOW`, `RPC_CPI_SOURCE_BALANCE_LOW`, `RPC_CPI_SOURCE_FROZEN`, `RPC_CPI_SOURCE_READ_UNAVAILABLE` and `RPC_CPI_SOURCE_CORRELATION_INVALID`. They are **advisory RPC findings only**. In particular, CPI source records are not independently signed: a matching balance or delegate in a later slot cannot establish execution-time permission, CPI completeness, total gross source debits or a real spending cap. Even perfectly matched evidence retains `authorization_proven=false`, `total_gross_token_spending_proven=false`, `security_coverage="partial_untrusted_rpc"` and the CLI decision `UNKNOWN`, never `ALLOW`.

## Aggregate Token Spending Analysis — independent evidence views (implemented, advisory)

The read-only RPC adapter now builds `aggregate_token_spending` for a **successful, explicitly opted-in** simulation using `crates/hguet-rpc/src/aggregate_spending.rs`. It groups observations deterministically by **mint** and by **(mint, source token account)** using checked `u128` sums and original raw base-unit amounts. **It never adds the three categories together**, because one economic event can appear as an original wire declaration, one or more provider CPI declarations, and a negative token-account net delta:

1. `wire_checked_debit_raw`: amounts from **original signed-wire instruction arguments** for checked token transfers and burns, plus layout-checked direct Token-2022 `TransferCheckedWithFee` (the source's declared amount, not the withheld recipient fee). Unchecked `Transfer` has no declared mint, so its amount is not assigned to an asset.
2. `rpc_cpi_checked_debit_raw`: independently summed, **selected RPC-provided** compiled checked CPI transfers, burns and exact checked-with-fee extensions. These may reflect events also visible in the top-level wire or account balances. Source and mint identities are only provider CPI claims.
3. `rpc_negative_account_net_raw`: sum of **negative** token-account deltas from complete paired provider pre/post balances. A net loss can hide larger gross outgoing activity offset by incoming tokens; nonnegative and incomplete balance rows are not treated as debit evidence. It may also cover token accounts unrelated to the trusted payer.

Each mint and source view carries the relevant ceiling from a **separately verified, exact-byte signed** `token_spend_limits` or `token_source_limits` PaymentIntent, when the caller supplies one. Every category is compared **individually** to the mint-wide or source-specific signed raw `u64` ceiling. Multiple decoded CPI debits for the same mint/source are summed *within their own category*. Over-cap values or CPI/net activity outside a signed mint/source list raise distinct **advisory** findings; original-wire limit violations remain the responsibility of the independently enforced local signed-intent verifier, not RPC. Both mint and source cap sets may be present; either view may reveal a separate potential issue.

The report does **not** manufacture a single `total_gross_spend`, effective authorization, signed cap enforcement, or executed spend. Instead it reports `wire_cpi_and_net_amounts_never_added=true`, `total_gross_token_spend_proven=false`, `onchain_spend_limit_enforced=false`, `execution_proven=false`, `security_coverage="partial_untrusted_rpc"`. It also preserves direct opaque instruction counts, provider opaque CPI counts, unchecked transfers with un-attributable mint, missing/partial token balance metadata and unresolved CPI source coverage. The separate `wire_rpc_alt_identity_dependent_instructions` counter records original-wire instructions whose program or account IDs depend on **single-provider Address Lookup Table resolution** rather than static signed message keys; the CLI warns with `RPC_AGGREGATE_WIRE_ALT_IDENTITY_UNTRUSTED`. This distinction is retained even when the instruction bytes themselves came from the original wire. A later RPC token-account mint may be displayed elsewhere but is **never substituted for an absent mint in unchecked wire/CPI opcode data**.

Additional CLI findings include `RPC_AGGREGATE_TOKEN_NON_ADDITIVE`, `RPC_AGGREGATE_CPI_MINT_CAP_RISK`, `RPC_AGGREGATE_CPI_SOURCE_CAP_RISK`, `RPC_AGGREGATE_NET_MINT_CAP_RISK`, `RPC_AGGREGATE_NET_SOURCE_CAP_RISK`, `RPC_AGGREGATE_UNLISTED_MINT`, `RPC_AGGREGATE_UNLISTED_SOURCE`, `RPC_AGGREGATE_TOKEN_COVERAGE_INCOMPLETE` and `RPC_AGGREGATE_TOKEN_AUTHORITY_SIDE_EFFECTS`. An unexpected consistency/bounds error yields `RPC_AGGREGATE_TOKEN_ANALYSIS_INVALID`. None of these reports is a signer-side policy verdict or permits `ALLOW`.

The unit tests cover repeated checked CPI debits exceeding caps, two sources exceeding one mint cap while each source is below its own cap, same apparent 70-unit debit in all three categories **without** a false 210-unit total, incomplete and unchecked mint evidence, unlisted accounts and Token-2022 checked-fee transfers. Solana RPC and Cloud are not contacted by these synthetic tests.

## Verified Spending Boundaries — block-only signing contract (implemented, **no signing permission**)

The CLI now returns an additional **`signing_boundary`** object on parsed normal inspection/check paths, computed by `crates/hguet-rpc/src/signing_boundary.rs`. This is a *read-only, conservative readiness assessment for a future customer-controlled signer*, not a signer or authorization service. It has `signing_gate="block"`, `automated_signing_permitted=false`, `signer_side_enforcement_integrated=false`, `execution_bank_authenticated=false`, `total_native_sol_spending_proven=false` and `total_gross_token_spending_proven=false` **unconditionally**, including when a signed PaymentIntent is valid and the provider reports a successful simulation. Existing `SecurityVerdict` remains `UNKNOWN` or `DENY`; the boundary **never** issues `ALLOW`.

Within its permitted scope, the report distinguishes **what is actually checked** from what is still unknown:

- `independent_intent_verified_by_caller`: true only when the CLI has independently pinned and Ed25519-verified the signed exact-message PaymentIntent. The `assess_signing_boundary` library function itself **does not** verify the signature and must never receive an agent-supplied unverified payload.
- `direct_mint_declaration_bound_checked` / `direct_source_declaration_bound_checked`: only true if the existing strict **original-wire** checked SPL Token/Token-2022 debit reviewers revalidate the signed cap lists; these bounds apply to explicit **direct declaration arguments**, not CPI, net effects, fees or actual executed gross spending. A checked mint cap alone does not imply a checked source cap.
- `original_wire_program_allowlist_checked` and `original_wire_lookup_identity_unresolved`: preserve the signed allowed top-level programs and the lack of independently resolved ALT program/account identity. `unsupported_program_execution_surface` flags arbitrary top-level programs even if listed in an intent.
- `direct_token_semantics_incomplete` includes opaque/unknown direct token operations, unresolved/dependent ALT addresses or missing binary decoding. The exact original token program/account indices and base58 data are only declarations.
- `rpc_advisory_aggregate_available` and `rpc_advisory_cap_anomalies`: single-provider RPC adds **risk information only** and never removes a signer blocker. Missing/opaque CPI or incomplete token balance coverage also appears among the block reasons.

`block_reasons` is a deterministic list of machine-readable issues such as `NO_INDEPENDENT_VERIFIED_INTENT`, `DIRECT_TOKEN_MINT_LIMIT_NOT_VERIFIED`, `DIRECT_TOKEN_SOURCE_LIMIT_NOT_VERIFIED`, `ORIGINAL_WIRE_ALT_IDENTITY_UNRESOLVED`, `CUSTOM_OR_UNSUPPORTED_PROGRAM_EFFECTS`, `RPC_CAP_ANOMALIES_ADVISORY`, and the unconditional `SIGNER_SIDE_ENFORCEMENT_NOT_INTEGRATED`, `EXECUTION_BANK_NOT_AUTHENTICATED`, `TOTAL_NATIVE_SOL_SPEND_NOT_PROVEN` and `TOTAL_GROSS_TOKEN_SPEND_NOT_PROVEN`. An unsigned transaction is ordinary *pre-signing* input: missing signatures are not falsely reported as invalid Ed25519 signatures, but also never grant permission. Invalid nonzero transaction signatures remain a separate rejection.

The public `PaymentIntent` v1 schema, domain-separated Ed25519 signatures and Cloud pricing **have not changed**. This is a new CLI wrapper field, not an alteration of the public `SecurityVerdict` contract. No private keys, wallet APIs, signing, broadcast or automatic payment approval are introduced. The remaining work requires a customer-controlled signer with fail-closed verification on the exact bytes and a defensible *execution-time* bound on all relevant SOL/token/fee/CPI effects; the current model cannot provide that proof.

## Local customer signer integration seam (implemented, BLOCK-only, no wallet)

New workspace crate: `crates/hguet-signer` (version 0.0.0, unpublished). It is a **separate local, offline, read-only preflight boundary** for eventual customer-controlled hardware/software signer integration. No private keys, wallet SDKs, hardware-device transport, signature generation or transaction broadcast exist. This is **not** an automated payment product.

- `SignerRequest` requires original wire bytes, the untrusted signed PaymentIntent envelope, a **separately supplied pinned public key**, intended Solana network and a caller-controlled trusted local Unix time. It never accepts an agent-authored verdict, an RPC result or a serialized `SigningBoundary` as an authorization grant.
- `inspect_signer_request` independently parses the original message, decodes supported static direct token operations, and calls `hguet-core::verify_intent` for the exact message hash, network, time bounds and Ed25519 signature against the independently pinned key. Invalid wire, missing independent key, altered message, wrong network, expired intent, and invalid transaction signatures are distinct fail-closed refusal reasons.
- The earlier public `SignerBackend` trait was **removed entirely**. `guarded_sign(request) -> Result<Infallible,SignerRefusal>` has no device/backend argument and no representable success type. Neither the CLI nor another caller can reach a signing backend through this API; no device or wallet backend exists.
- The `SignerRefusal` object has `signing_gate="block"`, `signing_permitted=false`, `signer_backend_invoked=false`, `signature_created=false`, `transaction_broadcast=false` regardless of a verified intent. Its optional nested `signing_boundary` retains the signed declaration and unsolved execution warnings. These results **must not be used as a wallet signing token**.
- All validation is offline. No CLI action creates a signature, submits to Solana, accesses Cloud or logs a secret key. A malicious caller could of course invoke some *other* software's signing API; HGUET currently has **no device isolation or exclusive hardware signer control**, and this module must not be described as proven onchain enforcement.

The actual CLI adapter is:

```sh
cargo run -p hguet -- signer-preflight tests/fixtures/legacy-spl-transfer-checked-authority-signer.base64 \
  --encoding base64 --network devnet --offline \
  --intent tests/fixtures/signed-direct-token-source-cap-equal.json \
  --trusted-key 2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ --json
```

**The command always returns exit code 20 (refusal)** when a transaction and envelope are readable; malformed arguments/files return code 40, never signing. The key shown is a **public, synthetic test-only Ed25519 identity**, not a key to use with real funds. Even with matching source/mint caps, a signed intent verifies **declarations**, not CPI, fees, bank execution, or permission to sign. `--offline` is required and `--rpc-url` is explicitly refused by this command.

The new `protocol/v1/signer-refusal.schema.json` is an **unreleased, CLI-only output schema** that freezes every signer/broadcast capability flag to false. `signing-boundary.schema.json` remains a separate schema for the nested boundary. Synthetic Rust tests and CI run the real CLI twice: one valid, independently pinned envelope and one wrong pinned key; both must refuse, with no signer backend call and no external RPC. Future engineering must separately design exclusive device access, trusted intent acquisition, isolated key handling and an execution-time enforced spending policy; a green local preflight does not deliver those properties.

## Trusted Signer Isolation — operator-configured process and strict agent input (implemented, BLOCK-only)

The new standalone executable **hguet-signer-isolate** has a deliberately narrow, offline **stdin JSON** boundary: the untrusted agent supplies only schema_version=1, kind=hguet_signer_preflight, original_transaction_b64 and signed_intent. The public protocol/v1/signer-agent-request.schema.json declares that shape. Rust additionally rejects unknown nested/top-level fields, noncanonical Base64, JSON larger than 65,536 bytes, transactions larger than 16,384 bytes and unexpected request kinds. Inputs cannot carry an authorization decision, RPC simulation, device command, pin, network or clock.

The **OperatorTrust** object owns the network and independently provisioned public intent verification key, supplied when the process starts rather than by the agent. Its current process uses the OS local clock to validate expiry. It independently parses original transaction bytes and verifies the intent's exact-message Ed25519 signature before always returning a SignerRefusal. The process has no RPC URL, signer backend, wallet SDK or broadcast action, so the agent cannot invoke any of these through this interface. A malformed agent payload yields a schema-constrained BLOCK refusal (exit code 20); invalid operator flags/configuration give exit code 40.

Example of the isolated process invocation (the public key is synthetic; input JSON is sent on stdin):

~~~sh
cargo run -p hguet-signer --bin hguet-signer-isolate -- \
  --network devnet --trusted-key 2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ \
  < /path/to/untrusted-agent-request.json
~~~

CI also builds this executable and invokes scripts/check_isolated_signer.py, which probes a verified signed intent, wrong independent key, forged allow/signing_gate, injected time/network/pin/RPC fields, unexpected device commands, malformed nested JSON and oversized input. Every valid-path outcome **remains refusal** with signature_created=false, signer_backend_invoked=false, transaction_broadcast=false. No source transaction or signed envelope is echoed in output.

**Security boundary, not a production device signer:** The bare Rust process shown above has no OS sandbox. Linux operators may now use [the mandatory Bubblewrap/seccomp launcher](../architecture/linux-signer-sandbox.md) to confine this BLOCK-only binary with separate network/PID/user/mount namespaces, a restricted filesystem, dropped capabilities, a syscall denylist and a verified open executable inode. The launcher **refuses to start** without the required sandbox; it never runs unconfined as a fallback. The process can still be invoked directly without the launcher (but it cannot sign), and no protected OS user/attestation, exclusive device custody, trusted clock, replay ledger, runtime gross-spending bound, trusted display or transaction execution proof exists. A hostile parent who controls operator launch configuration can still replace the pin/cluster or choose another build hash. CI validates the policy and fail-closed behavior; a runner that prohibits namespace creation reports live sandbox execution as *skipped*, not successful. See [Trusted Signer Isolation threat model](../architecture/trusted-signer-isolation.md).

## Linux OS-Level Signer Sandbox (operator opt-in, fail-closed)

Use scripts/run_signer_sandbox.py to start **hguet-signer-isolate** with a mandatory Bubblewrap sandbox. This Linux x86_64/AArch64-only launcher requires a separately pinned binary SHA-256, absolute executable path, intended network and independently pinned public intent verification key. It **never** receives or uses a private key or wallet API.

A successful launch creates isolated network and other namespaces, drops capabilities, exposes only read-only runtime libraries and a file-descriptor-pinned executable, removes host home and device paths, and installs a mandatory architecture-checked seccomp filter restricting network, process spawning, namespace and privileged syscalls. If any required protection is unavailable, the launcher returns **exit code 40, no signer result, no unsafe fallback**. It returns exit **20** only when the OS-sandboxed process itself returns a valid BLOCK-only refusal.

CI checks the BPF policies, bad result rejection, protected inode against file-swap attacks, wrong executable digest, and fail-closed process creation. On CI runners without permitted unprivileged namespaces, it reports that **live namespace execution was skipped**, while still checking the absence of unsafe fallback. This is not a real wallet-signing security boundary; direct Rust process invocation remains possible and also BLOCK-only. See [Linux signer sandbox architecture](../architecture/linux-signer-sandbox.md).

## Protected Signer Launch & Replay Protection (optional Linux path, BLOCK-only)

The new operator-controlled entrypoint, `scripts/run_signer_protected.py`, accepts **only** a `--policy` argument pointing to a protected root-owned JSON configuration. It derives the trusted network, Ed25519 public key pin, executable SHA-256 and persistent replay directory exclusively from that file; the untrusted agent supplies only transaction bytes and a signed intent via stdin. The Python launcher/module sources, policy and path ancestors must be root-owned and not agent-writable. The ledger directory must belong only to the dedicated signer service account (0700). HGUET does not create this service account or protected installation automatically.

Before launching the mandatory Bubblewrap sandbox, the new launcher makes a **single-use reservation** indexed by the signed PaymentIntent's `intent_id`, pinned issuer and network. An atomic `O_EXCL` marker (0600) is written and both marker and directory are `fsync`ed. The reservation remains after all failures, timeouts and invalid signatures; reformatting the same agent JSON or changing transaction bytes cannot reset the reservation. Failed journal creation or a repeat exits with code **40** and never launches the sandbox. The sandboxed Rust signer still independently checks the exact Ed25519 signature and **always refuses** signing.

**Critical limitation:** The host reservation happens *before* the sandbox verifies the Ed25519 signature. Any caller with a known intent identifier may prematurely occupy its slot and cause denial of service, so independent client authentication is required before a future production service could expose this interface. A privileged attacker could roll back/remove filesystem markers. This is **not** a hardware-backed anti-replay counter, protected service deployment or release-ready signer. See [protected launch and replay documentation](../architecture/protected-signer-replay.md).

## Planned default Cloud server (configured, not active)

The CLI has a compile-time **default future Cloud endpoint** `vps-d0669a91.vps.ovh.net:443` (authenticated TLS 1.3 + Protobuf/TCP, **NOT SSH**). View this setting without making any network request:

```sh
cargo run -p hguet -- config show --json
```

The result explicitly reports `cloud.available=false`. `--mode cloud` is still refused: no actual Cloud transport, TLS trust validation, paid check or SOL transfer is implemented. The SSH operator user `debian@` must never be copied into this public endpoint; no private keys, server certs or payment receiver secrets are in this repository. The hostname alone is not proof of server identity.

No customer seed keys, real SOL invoice address or active Cloud endpoint is used.
