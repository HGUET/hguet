# Coverage-guided fuzzing

Separate developer-only workspace; no dependencies added to the shipping CLI.
Uses cargo-fuzz 0.13.2 / libFuzzer with AddressSanitizer, nightly-2026-10-01.
The first smoke is bounded to 20,000 executions per target, max input 4097
bytes, 10-second per-input timeout and 2048 MB RSS limit. These are configured
budgets, not measured execution counts or a coverage percentage.

- wire: repeated parser results, counts, index bounds, deterministic JSON and
  original transaction hash.
- reports: parsed inputs must retain offline inventory/report/self-diff,
  exact shared message identity, refusal-only invariants, evidence pointers,
  independent flow/authority parity and passive HTML.

Seed inputs are materialized from checked-in synthetic fixtures, the published
signed Devnet example, and malformed size boundaries. Never broadcast seeds.
The target is network-free and has no access to wallet keys or funds.
The workflow builds before entering an isolated network namespace and
preserves the evolving corpus, crashes, actual logs, toolchain, exact source,
binary hashes and the separately resolved fuzz lockfile. The production lockfile
is unchanged; the fuzz dependency resolution is recorded per run, not yet
committed as a reproducible lockfile.

On Linux:

```sh
rustup toolchain install nightly-2026-10-01 --profile minimal
cargo +nightly-2026-10-01 install cargo-fuzz --version 0.13.2 --locked
cp Cargo.lock fuzz/Cargo.lock
python fuzz/seeds.py --out fuzz/corpus
cargo +nightly-2026-10-01 fuzz run wire --sanitizer address -- -runs=20000 -max_len=4097 -seed=314159
cargo +nightly-2026-10-01 fuzz run reports --sanitizer address -- -runs=20000 -max_len=4097 -seed=314159
```

Any panic, ASan finding, invariant violation or timeout must be investigated;
preserve the failing input and add a focused regression before claiming a fix.
A smoke pass is not exhaustive fuzz coverage or an independent audit.
Existing deterministic differential tests and cargo-mutants code mutation
testing are distinct techniques. Hosted execution pending.
