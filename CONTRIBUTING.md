# Contributing to HGUET

Read [roadmap](docs/release/community-0.1.0/ROADMAP.md), [Phase 1](docs/release/community-0.1.0/PHASE_01.md) and [coverage](docs/release/community-0.1.0/COVERAGE_MATRIX.md). The free MIT toolkit is the primary product.

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --locked -p hguet
python -m pip install -r testing/requirements.txt
python testing/tools/build_scenarios.py --check
python -m unittest discover -s testing/tests
python testing/runner/run_benchmark.py --hguet target/debug/hguet --suite all
```

On Windows use the appropriate .exe path. Consult [testing documentation](testing/README.md) for additional contract/platform checks. Record actual failures and skips; do not weaken gates.

Prefer scoped changes and independent fixtures, ground truth, real-runtime comparisons, adversarial tests and integration examples. Preserve existing v1 semantics unless a separately versioned change is documented. Retain hard violations when coverage is incomplete. No signing, custody, hidden network, required Cloud or unreviewed safety claims. See [SECURITY.md](SECURITY.md).
