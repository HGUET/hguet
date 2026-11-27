# Community Edition coverage matrix

Source baseline, not independently verified effectiveness. Update with exact test IDs, code references and evidence.

| Capability | Baseline | Release target |
| --- | --- | --- |
| Legacy/v0/v1 parse | Implemented, validation incomplete | Differential validation; advertise v1 only where runtime supports it |
| Ed25519 signature / exact message | Implemented | Independent vectors and malformed/partial tests |
| PaymentIntent v1 | Implemented, direct-wire scope | Preserve; semantic mandate separately versioned |
| Native SOL policy | Partial direct scope | Fees/recipient/roles distinguished |
| Token policy and recipient checks | Partial signed caps | Mint/source/destination constraints and authority policy |
| CPI and Token-2022 | Partial/advisory | Bounded runtime-tested instruction/effect catalogue |
| ALT | Partial RPC evidence | Slot/owner/lookup validation and uncertainty |
| Effect graph | Implemented advisory | Unified provenance, export and conflict reporting |
| RPC simulation | Implemented advisory | Real validator tests; no execution guarantee |
| Signing boundary | Implemented BLOCK-only | Preserve; no authorization |
| Engine API / report v2 | Planned | Typed public API, v1 compatibility |
| Terminal / stdin / HTML / DOT | Planned | Verified offline UX and escaping |
| Historical audit and diff | Planned | Provenance-aware audit and semantic diff |
| x402 exact SVM | Planned | Official SDK sandbox fixtures |
| Rust / TS integrations | Planned | Tested public examples |
| MCP | Optional preview | Read-only, trusted config, bounded input |
| Benchmark | Synthetic framework exists | Runtime and independently reviewable corpus/adapters |
| Cloud / MPP | Experimental / planned | Not release dependencies |

Runtime milestone measured on 2026-11-27 using Solders 0.29.0 and embedded
LiteSVM in WSL: five actual execution comparisons passed. Native transfer
and repeated debit cap, SPL TransferChecked, approve and set_authority were
checked against resulting account state. See testing/runtime/README.md.
Two additional Token-2022 fee cases executed: correct fee transfers and
incorrect fee runtime rejection. HGUET reports the expected wire fee through
the existing checked extension decoder. Seven runtime cases now pass.
One SDK-generated v1 transfer now executes in the pinned LiteSVM and matches
HGUET message hashing and effects. The existing v1 fixture round-trips through
the SDK. V0 native transfer also passes; ALT runtime comparison remains open.
Wrong token authority and insufficient SOL produce verified runtime rejections.
The harness now records eleven cases. These observations do not establish
complete v1 support or live cluster compatibility.

[Limitations](../../../LIMITATIONS.md) · [Supported programs](../../../SUPPORTED-PROGRAMS.md).
