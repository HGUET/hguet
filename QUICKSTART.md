# Quick start

> Developer preview. Build from source; no public 0.1.0 binary release yet. No wallet, account or Cloud required.

## 1. Build

```sh
git clone https://github.com/HGUET/hguet.git
cd hguet
cargo build --locked -p hguet
cargo run --locked -p hguet -- --help
cargo run --locked -p hguet -- doctor --json
```

Rust is pinned by [rust-toolchain.toml](rust-toolchain.toml) (1.100.0); dependencies are locked. The debug executable is `target/debug/hguet` (Windows: `target\debug\hguet.exe`). Subsequent examples assume it is on PATH; alternatively replace `hguet` with `cargo run --locked -p hguet --`.

## 2. Explore the offline lab

```sh
hguet lab all --out hguet-demo-lab
hguet lab authority --html > authority.html
hguet lab diff --json
hguet demo
hguet demo --json
```

Open the HTML files locally. The lab output directory must not exist; verify the 12 file hashes in manifest.json. All fixtures are unsigned synthetic examples; never broadcast. See [Demo Lab](docs/DEMO_LAB.md).

## 3. Decode your own transaction

```sh
hguet report tests/fixtures/v1-system-transfer.base64 --encoding base64 --offline --html > transaction.html
hguet programs transaction.bin --offline
hguet flow transaction.bin --offline
hguet authority transaction.bin --offline
hguet inspect transaction.bin --offline --report-v2
hguet inspect transaction.bin --offline --text
```

Binary is the default input; select `--encoding base64` or `--encoding base58` for text. File and stdin (`-`) are bounded (16,384 encoded bytes); the parser applies separate wire limits. For example:

```sh
cat tests/fixtures/v1-system-transfer.base64 | hguet report - --encoding base64 --offline
```

Use PowerShell `Get-Content -Raw` for Base64 text on Windows; use a binary file rather than a text pipe for raw bytes. Do not mix `--text` and `--json`, or `--html` and `--json`. Analysis `inspect/check` default to v1 JSON, with explicit v2/text; inventory commands use their own JSON contracts and optional HTML. See [CLI reference](docs/CLI.md).

## 4. Compare messages

```sh
hguet diff tests/fixtures/demo-v1/match.base64 tests/fixtures/demo-v1/violation.base64 --encoding base64 --offline --html > diff.html
```

Both inputs use the selected encoding; at most one can be stdin. Comparison reports message/transaction identity and positional differences, not semantic equivalence.

## 5. Restrict a proposed transaction

```sh
hguet policy validate tests/fixtures/demo-v1/policy.toml --json
hguet check tests/fixtures/demo-v1/violation.base64 --encoding base64 --mode local --network devnet --policy tests/fixtures/demo-v1/policy.toml --report-v2
```

The second command is expected to return DENY/20. Its synthetic declared native debit exceeds the configured 500-lamport cap. A policy match is never authorization. For independently issued signed intent:

```sh
hguet check transaction.bin --mode local --network devnet --intent signed-intent.json --trusted-key PINNED_KEY --policy trusted-policy.toml --report-v2
```

Replace placeholders with independently obtained configuration and input. Offline network labels are operator supplied. `signer-preflight` is refusal-only and never signs.

## 6. Opt in to RPC only when appropriate

```sh
hguet flow-rpc transaction.bin --network devnet --rpc-url https://YOUR_RPC --html > simulation.html
hguet check transaction.bin --mode local --network devnet --intent signed-intent.json --trusted-key PINNED_KEY --rpc-url https://YOUR_RPC --report-v2
hguet audit TRANSACTION_SIGNATURE --network mainnet --rpc-url https://YOUR_RPC --html > audit.html
```

Simulation discloses serialized transaction bytes to the explicit provider and uses replacement blockhash and disabled provider signature verification. Local signature checks are separate. Historical audit requests finalized metadata and verifies returned signatures; it submits only the public identifier and does not read current account state. Provider responses are untrusted; live public historical fixtures remain a validation task. Never include a confidential RPC URL in public logs.

## 7. Interpret output and exit status

For the inventory/HTML commands 0 means a report was produced, not that signing is safe; RPC commands may return 30 when data is unavailable or simulation fails. Historical audit returns 0 for a signature-verified transaction even if reported execution failed. Invalid input/configuration returns a JSON error (40) even if HTML was requested. `check` can return 20 (DENY) or 30 (UNKNOWN). Inspect/help/policy syntax success does not imply authorization. See [CLI reference](docs/CLI.md) for precise command-specific behavior.

Share reports only with intended recipients; HTML contains transaction data. Never use HGUET as a signing grant.

[Documentation](docs/README.md) · [Limitations](LIMITATIONS.md) · [Current evidence](docs/release/community-0.1.0/VERIFICATION.md).
