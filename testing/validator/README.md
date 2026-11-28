# Local Agave validator comparison

Pinned Agave v2.3.13 single-node test-validator binary, with the official
GitHub release asset SHA-256 checked before unpacking. This older release
is intentionally a legacy/v0 comparison baseline, not a v1 compatibility
claim. Dedicated CI downloads dependencies before entering a fresh Linux
network namespace with only loopback enabled. Python refuses non-loopback
interfaces, disables proxies/redirects and uses a fixed local RPC URL.

The test harness (not HGUET) generates disposable test keys, airdrops local
test lamports and submits SDK transactions to that isolated node. It checks
three finalized historical cases: native transfer, atomic rollback after
a late insufficient-funds instruction, and v0 ALT transfer. Original wire,
SDK signatures, actual recipient balance, reported fee and each pre/post
balance row are compared with the HGUET offline report and historical decoder.
No public transaction is submitted and no keys or ledger are archived.

The production CLI only supports HTTPS and named public networks with pinned
genesis. The local validator uses HTTP and a fresh genesis. Rather than
weakening these checks or relabeling localnet as Devnet, a test-only Rust
example replays a bounded captured getTransaction result through the same
historical decoder. It explicitly asserts source authentication and execution
proof are absent. This validates decoding actual validator metadata, not
production HTTPS transport or public cluster finality.

See the [workflow](../../.github/workflows/validator-local.yml) for exact
commands and environment. The initial result is pending. No broader validator,
v1, token/CPI, or real ALT cooldown timing claim.
