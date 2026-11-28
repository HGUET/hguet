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

## Security Demo Lab — offline preview

At ac9e557 the hosted seven HTML comparisons and all functional checks passed; only formatting failed. All 483 evidence manifest entries verified ([artifact](https://github.com/HGUET/hguet/actions/runs/46061111737/artifacts/15228204259)). Exact reported formatting corrections applied in 28554a4. Local Chromium content rendering of the five generated HTML files at 1280 and 390 CSS pixels found no page-level horizontal overflow, missing internal link target, external HTTP request or page error. Direct file navigation was restricted by the environment, so contents were loaded into offline browser pages; this is not a full accessibility or browser compatibility audit.

New lab command exports six deterministic unsigned examples through actual report/diff engines. JSON/HTML pairs and SHA-256 manifest, no overwrite, independent SDK parse and CLI parity checks. All examples explicitly synthetic and non-executed. Existing demo remains unchanged. Historical live examples, runtime execution of the lab corpus, DOT and broad validation remain open. New hosted results pending.

## Current checkpoint — 2026-11-28

Source d716d606a71291f6d65e007d281bbffc513a2784: all 13 mandatory runtime, 10 program, 8 flow, 7 authority, 10 diff/audit, 7 HTML and 7 lab groups passed; 315 workspace tests passed (6 ignored), 227/227 synthetic benchmark expected outcomes passed, locked build and Clippy passed. PQ workflow succeeded. Full runtime acceptance failed solely on two Rust formatting diffs in lab.rs. Downloaded evidence manifest verified 498/498. See [VERIFICATION.md](VERIFICATION.md) for precise links and scope. Earlier pending test statements above are historical checkpoints.

Initial implementations 2.0–2.5 and the synthetic lab exist and have scoped functional evidence. No entire slice's broader acceptance is declared complete. Phase 2.6 is the immediate next priority: fix formatting, exact-source green acceptance, read-only public historical samples, more real runtime differential comparisons, broader Token-2022/authority and ALT mutation coverage, validator and fuzzing, evidence review. DOT export and richer semantic reconciliation remain open. No release or live-network effectiveness claim.

## Phase 2.6 — first validation increment

Exact hosted formatting corrections applied to lab.rs at fb834f066a4b555a0bbb629670d365db99b74f98. Added a deterministic SDK differential corpus (40 valid messages plus 80 structurally malformed variants) and two actual local rollback comparisons. Mandatory CI steps preserve individual wire hashes, results and runtime errors. No new product commands. Hosted results pending. Public historical corpus, wider extension/ALT runtime, validator and coverage-guided fuzzing remain open.

## Phase 2.6 measured differential/rollback and public history increment

At 29486e4dcb95b9c40d2d139c667e7f066d771a6f, full runtime acceptance succeeded, including 120 differential and 2 actual rollback cases; artifact manifest 502/502 verified. See [VERIFICATION.md](VERIFICATION.md). Added an independently signed published Devnet example, reconstructed from official Solana documentation and verified locally using Ed25519, plus an offline Rust historical test and separately network-enabled bounded public smoke. Published metadata is not a live response. New hosted results pending; no wide public corpus or independent ledger proof claimed.

## Token-2022 extension runtime increment

Four additional mandatory LiteSVM groups compare permanent delegate behavior, hook configuration (not hook execution), fee collection/harvest/withdrawal/configuration and non-transferable rejection. Test-only change, no broad new decoder coverage claimed. Exact expected state and rejection codes must pass before updating measured results. Public historical fixture corrected separately after first public response exposed loss of integer precision in fixture preparation. New CI pending.

Public Devnet smoke passed at 90e4a36; six artifact manifest entries verified. See [VERIFICATION.md](VERIFICATION.md). First live historical legacy audit verified, broader historical corpus remains open. Four new Token-2022 runtime groups are implemented and pending hosted results.

## ALT lifecycle increment

Exact source 9eef59dbbd0b34afcda0e69afcd907d1fef9689b passed [full Runtime](https://github.com/HGUET/hguet/actions/runs/46089660808), [PQ](https://github.com/HGUET/hguet/actions/runs/46089660871) and [public Devnet smoke](https://github.com/HGUET/hguet/actions/runs/46089660814). Four new Token-2022 groups and precise historical absolute balances passed. New ALT lifecycle groups test actual local create/extend/freeze/deactivate/close, exact failures and state/refund, with controlled sysvars. Hosted results pending. No new decoder or full validator compatibility claimed.

## Coverage-guided fuzz smoke

Both ALT lifecycle workflows passed on b840fb9 and e265036 (46090021895 and 46090077710). Added separate developer-only cargo-fuzz workspace and two libFuzzer targets, checked-in seed materialization, 20,000-execution budgets per target and network-isolated ASan runs with preserved corpus/crashes/logs. Actual fuzz results pending. No percentage or whole-release acceptance claimed.
