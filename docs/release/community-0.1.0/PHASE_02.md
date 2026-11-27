# Phase 2 — Transaction Intelligence

**Status: development; not a public release.** Prerequisite: Phase 1.1 accepted on its measured source. All capabilities below are free and local-first, with explicit RPC only for operations requiring it. Existing v1/v2 semantics, signing refusal and regression tests remain binding.

## Work packages

| Slice | Deliverable | Acceptance |
| --- | --- | --- |
| 2.0 Program intelligence | Typed original-wire program/instruction catalogue; core System, SPL, Token-2022, Compute Budget, ATA, Memo, ALT; unknowns explicit; optional Stake/loader/one DeFi integration after core validation | Exact program ID and layout; SDK vectors, malformed and ALT cases; execution comparison for every advertised runtime behavior |
| 2.1 Asset flow | Separate wire/CPI/net/state views, raw integer amounts per asset, account identity and role, fees/rent/withheld, conflict markers | No double counting, unknown not zero, evidence pointers, runtime state comparison |
| 2.2 Authority intelligence | Declared account owner/delegate/authority mutations, revocations and future-control exposure; observed state separate | Positive and negative tests; no inferred ownership or permission |
| 2.3 Semantic diff | Offline before/after comparing ordered instructions, roles, amounts, programs, hashes and resource config | Added/removed/reordered instructions, duplicates, opaque and unresolved addresses; no false equivalence |
| 2.4 Historical audit | Explicit HTTPS RPC getTransaction by signature; verify returned identity, cluster and supported encoding; historical vs current state separate | Bounded transport, malformed/adversarial replies; read-only public fixtures; no replay/broadcast |
| 2.5 Reports | Terminal and self-contained HTML/DOT with asset and authority evidence; synthetic demo lab | Escaping, no external script/CDN, correct unknowns and evidence; offline tests |
| 2.6 Validation | SDK differential corpus, LiteSVM and validator tests, adversarial benchmark | Actual measured results, explicit denominators and gaps, full compatibility checks |

## Initial slice 2.0

Provide an additive offline program-intelligence API and CLI, separate from existing report v1/v2 contracts. Report one row per original instruction, exact program identity or unresolved lookup index, declaration name, layout status, declared parameters and account roles where supported. No program-name allowlisting or safety inference. Distinguish recognized data shape from runtime acceptance. Never infer effective fees from a Compute Budget instruction, especially v1 inline resources. Do not reproduce memo content into terminal output; report byte length and UTF-8 validity. ATA declarations do not establish PDA correctness, ownership or rent amount. Start with Compute Budget, Memo, System movement reuse, and ATA create variants. All remaining cases stay explicitly unsupported until separately validated.

No mandatory Cloud, signing, wallet keys, real funds, hidden network or release publication. Use independently constructed SDK fixtures; test invalid lengths, unknown opcodes, unresolved ALT, v1 configurations and misleading account roles. Preserve exact existing JSON and exit semantics. Record actual hosted results for each increment; do not mark Phase 2.0 complete until required coverage is implemented and validated.

Later slices require their own technical specification and acceptance record. Phase 3 remains broader validator/devnet/history/fuzz verification; Phase 4 remains CLI polish and portable delivery.

## Phase 2.0 implementation checkpoints

- Source 1b77605: hosted SDK/CLI preview 5/5, runtime 13/13, benchmark 227/227; all local acceptance commands except rustfmt passed. PQ workflow succeeded. [CI](https://github.com/HGUET/hguet/actions/runs/46041092548), [evidence](https://github.com/HGUET/hguet/actions/runs/46041092548/artifacts/15220296339). All 470 manifest entries verified. Formatting corrections applied in the token increment.
- Static SPL/Token-2022 instruction inventory, canonical ALT mutations, native System account roles, extended SDK fixtures and actual ATA runtime tests are implemented in following source revisions. Final hosted results pending; Phase 2.0 remains open. Broad System non-movement and Token-2022 extension layouts, ALT mutation execution and other deferred programs require further work. No existing verdict or signing semantics changed.

## Phase 2.1 initial implementation — offline asset flow

The new independent `hguet flow` command consumes the typed program inventory, emits one original-wire movement edge per decoded instruction, and groups raw quantities by SOL or token program + mint. Unknown mints are never guessed; mint/burn, funding, nonce withdrawals and expected fee declarations remain distinguishable. Self-transfers and repetitions are retained as declarations, not netted. Actual network fees and observed net changes remain null. Embedded program report supplies evidence pointers. Separate JSON schema and SDK/runtime tests gate the increment. Phase 2.0 broader gaps and final acceptance remain tracked independently. CPI/net/state reconciliation and historical audit are not implemented by this slice.

## Phase 2.1 RPC correlation preview

The complete hosted acceptance and PQ workflows succeeded on `fe94ee6ad167c4dbc145a1a15a18fd83e3762032`: [Runtime](https://github.com/HGUET/hguet/actions/runs/46044374991), [PQ](https://github.com/HGUET/hguet/actions/runs/46044374984). This establishes acceptance of that offline increment, not all Phase 2.0/2.1 goals.

New additive `flow-rpc` report reuses the bounded typed simulation pipeline, retains the offline wire inventory unchanged, and links account/mint rows and reported CPI parent instructions with JSON Pointers. RPC failures preserve wire declarations. Native/token net rows, CPI claims, graph and later non-atomic account snapshots stay separate; no joint numeric total or execution proof. Mock transport tests exercise real decoders, not a live network. Full semantic reconciliation, program-aware balance identity, actual historical execution and broader runtime comparisons remain open. New source acceptance pending.

## Phase 2.2 initial authority intelligence

The additive offline `authority` command exposes selected token delegate, authority, freeze/thaw, close-account, Token-2022 hook/permanent-delegate/fee configuration and ALT control declarations. Unsupported and unresolved rows remain explicitly unclassified. No live state or authority proof; no final state calculation. Existing SPL runtime cases now assert the new report against actual delegate and ownership changes. Full Phase 2.2 acceptance pending, including further coverage and runtime tests. Prior RPC flow source f6ccc8e passed all acceptance commands except formatting; targeted formatting corrections applied. The final d335303 verification is not yet complete at this checkpoint.

## Phase 2.3 initial semantic diff

Prior Authority and full acceptance/PQ workflows succeeded on `2ce4274d21871e5f46352476b887636fa7454031`: [Runtime](https://github.com/HGUET/hguet/actions/runs/46046205306), [PQ](https://github.com/HGUET/hguet/actions/runs/46046205313). New offline `diff` command compares exact transaction/message identities, header-declared privileges, fee payer, signer list, recent blockhash, v1 resources, original instruction data fingerprints and per-position asset/control declarations. Duplicate-preserving multiset comparison distinguishes same inventory from same order. No semantic equivalence, execution or signing claim; lookup references remain unresolved. This first slice uses positional differences rather than guessed instruction alignment. Fresh hosted verification pending.

The previous accepted authority artifact [15222477131](https://github.com/HGUET/hguet/actions/runs/46046205306/artifacts/15222477131) was downloaded and all 474 SHA-256 manifest entries verified; 13/13 runtime, 10/10 program, 8/8 flow and 7/7 authority SDK/CLI comparisons passed. New diff schema and nine SDK cases added on later source; pending verification.

## Phase 2.4 historical audit preview

Diff final hosted runtime and PQ passed at `c25d90a5668eaf3fbbe695f3b48a0abc85307c53`: [Runtime](https://github.com/HGUET/hguet/actions/runs/46046884193), [PQ](https://github.com/HGUET/hguet/actions/runs/46046884146). New `audit` command requests genesis and finalized getTransaction with base64 and maxSupportedTransactionVersion=1. The core parser verifies returned signatures and first signature binding. Historical loaded addresses are validated against wire lookup counts but not independently authenticated; no present-day account fetches. A separate historical view contains provider-reported status, fee, balance and CPI metadata; wire flow/authority declarations remain separate. This does not establish ledger inclusion or consensus. New source acceptance pending; no public network sample verified yet.

The historical audit contract and seven signed-fixture integration tests cover the three wire formats, missing metadata, wrong cluster, signature substitution, tampering, failed execution fee, historical ALT and strict request inventory. Existing network-isolated CLI suite validates invalid audit configuration. New CI must pass before this preview is accepted; live historical sample coverage remains open.

## Phase 2.5 standalone report preview

Historical audit source `63b2a1af405cbe4041dcde0bffb0161fdf49b13f` passed locked build, strict Clippy, workspace tests, all runtime/SDK checks and PQ; only rustfmt failed. [Artifact](https://github.com/HGUET/hguet/actions/runs/46050762882/artifacts/15224302571) downloaded and all 476 manifest entries verified. Exact formatting corrections applied. Live public historical samples remain open.

New opt-in HTML output for programs, flow, authority, diff, flow-rpc and audit. Passive standalone documents contain bounded engine report views, declared asset edges, authority tables, before/after differences and separate historical/simulation observations, plus evidence explorer and internal links. Existing JSON and exit semantics unchanged. No scripts, external resources, network, authorization claims or arbitrary HTML input. Rendering tests and hosted validation required. Browser UX, DOT export, demo lab and live RPC cases remain open.

Combined offline report command consumes one program inventory, derives flow and authority views and renders them together. Separate versioned JSON schema and seven HTML SDK/CLI comparisons (five actual generated HTML reports in CI artifact). No live network, signing or positive authorization. Source acceptance and visual browser review remain pending.
