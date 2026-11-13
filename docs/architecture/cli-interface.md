# HGUET CLI — Commands, configuration and UX contract

**Design status:** proposed, not implemented. The examples are **interface specifications**, not runnable commands. See [overview](README.md).

## 1. Command taxonomy

```text
hguet
  --version | --help
  inspect [TRANSACTION|-] [--offline] [--json]
  check [TRANSACTION|-] --intent INTENT.json [--policy POLICY.toml]
       [--mode local|cloud] [--profile strict|review|explore]
       [--rpc URL] [--network mainnet|devnet] [--max-charge UNITS] [--json]
  policy validate FILE
  intent verify FILE [--trusted-key PUBKEY]
  doctor [--rpc] [--cloud] [--json]
  config show|set|unset|path
  register [--email ...]
  login
  account
  pricing [--json]              # authenticated current Cloud quote/schedule
  device list|revoke DEVICE_ID
  topup AMOUNT --asset USDC
  balance
  usage [--since DATE] [--json]
  history [--limit N] [--json]
  logout
  completions bash|zsh|fish|powershell
```

`inspect` is non-enforcing disassembly and metadata extraction. `check` is policy evaluation. Account and top-up commands communicate only with our paid service, never with the Solana RPC by default (except when explicitly verifying an invoice payment).

### Behavior by command

| Command | Reads private files? | Network behavior | Expected output |
| --- | --- | --- | --- |
| `inspect --offline` | only named transaction | none | decoded transaction and unsupported instructions |
| `check --mode local` | tx, intent, policy, trust roots | user-configured Solana RPC | SecurityVerdict |
| `check --mode cloud` | same plus device auth | user RPC + PQ protected Cloud | enriched SecurityVerdict |
| `policy validate` | policy file | none | syntax, semantics, conflict results |
| `intent verify` | intent and trusted anchor | none | signer/trust status and restrictions |
| `doctor` | config and optional device metadata | only requested targets | capability and health report |
| `register/login` | device identity | HGUET Cloud | account/device enrollment status |
| `topup` | device identity | HGUET Cloud | unique payment invoice and expiry |
| `balance/usage/history` | device identity | HGUET Cloud | credit and usage summary |

**Avoid “hguet pay”**: it implies wallet or transfer execution and violates the non-custodial product mandate.

### Price confirmation before charging

Cloud checks first obtain an **authenticated price quote** (network, capabilities, disclosure scope, price schedule, quote ID and expiry). Automated callers configure a maximum **integer credit-unit** charge; the CLI must reject an invoice/check whose verified price exceeds the cap and **never** silently approve a more expensive quote. Interactive CLI can show the price before submitting, without invoking any web cabinet.

### Cloud mode and wallet distinction

`--mode cloud` is canonical. A future `--cloud` shorthand is a convenience alias only; neither may be selected automatically by local-mode defaults. `hguet topup 10 --asset USDC` expresses a **human amount** of 10 USDC. The protocol translates it into a precise integer base-unit quote after mint/network verification; the server never trusts unvalidated float conversions.

All enrollment, invoice display, balance, usage, and status actions happen through CLI. **The actual USDC transfer is signed by the customer's external wallet**, not by HGUET CLI. A Cloud-signed assessment does not make the composite local verdict server-signed.

See the [shared interoperability contract](interoperability.md) and [public protocol draft](../../protocol/v1/README.md).

## 2. First-run examples

Free analysis, no HGUET registration:

```sh
# Offline parsing only; nothing touches HGUET servers or Solana
hguet inspect tx.bin --offline --json

# Live simulation against explicitly configured RPC
hguet config set rpc.default "https://user-selected-solana-rpc.example"
hguet check tx.bin --intent approved-intent.json --profile strict --json

# Integrate from an agent that produces transaction bytes on stdin
cat tx.base64 | hguet check - --encoding base64 \
  --intent approved-intent.json --profile strict --json
```

Optional paid enrichment and account management, entirely through CLI:

```sh
hguet register --email team@example.com
hguet login
hguet doctor --cloud
hguet topup 10 --asset USDC
hguet balance --json
hguet pricing --json
hguet check tx.bin --intent approved-intent.json --mode cloud --json
hguet usage --since 2026-11-01 --json
hguet device list
hguet device revoke DEVICE_ID
```

Account enrollment can include an email challenge entered in the CLI. `topup` returns a payment invoice (recipient, mint, exact base units, network, reference, expiry, instructions); a customer-owned **external** wallet signs the actual USDC payment. The CLI monitors crediting. HGUET receiving payment for its own service is not a wallet custody service for clients. Never ask a user to paste wallet seed phrases.

**No mandatory web cabinet**; if card payments are introduced later, payment provider-hosted authorization is a separate optional integration and must be described honestly.

## 3. Input contract

Transaction sources:

- `TRANSACTION` path (binary wire format by default), or `-` for stdin; never read arbitrary directory trees.
- Optional `--encoding binary|base64|base58`; base64 preferred for RPC.
- Reject overlong input before allocation, malformed compact-u16, invalid signatures array lengths, unresolved address lookups, invalid version or extra trailing garbage.
- Cap untrusted input: **16 KiB encoded text; 4,096 bytes decoded transaction wire** as an initial conservative ceiling (actual per-version bounds enforced separately and updated when official formats change). Configurable limits only downward in strict environments.
- Version support must be explicit (legacy/v0/v1 per current Solana documentation); no unchecked fallback treating unknown version as legacy.
- Input filenames and paths may contain sensitive details; redact in public logs when configured.

**Never** accept private keys as arguments, stdin data, environment variables or configuration values. A CLI may accept the **public key** and the signed *authorization* produced by an independent signer.

## 4. Policy and trusted-intent input

Example `policy.toml` (proposed):

```toml
policy_version = 1
default = "unknown"
allowed_networks = ["solana-mainnet"]
allowed_mints = ["<approved mint address>"]
allowed_programs = ["<approved program id>"]
max_payment_base_units = "10000000"
require_verified_intent = true
deny_unrecognized_instructions = true
block_authority_changes = true

[simulation]
required = true
max_context_age_slots = 80
minimum_commitment = "confirmed"

[cloud]
required = false
```

`max_context_age_slots` and similar values are **risk-policy parameters**, not implied RPC guarantees. The project must test how freshness is actually measured (slot snapshots and observed head lag).

Trusted intent is a separately produced, optionally signed object. In strict mode, an intent supplied by the same untrusted agent without an independently pinned trust root does not authorize a payment. See [security](security.md).

## 5. Configuration and state

Proposed platform locations (use OS-known directories rather than reimplementing them):

| Data | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Non-secret config | `$XDG_CONFIG_HOME/hguet/config.toml` | `%APPDATA%\\HGUET\\config.toml` | `~/Library/Application Support/HGUET/config.toml` |
| Local state/cache | `$XDG_STATE_HOME/hguet/` | `%LOCALAPPDATA%\\HGUET\\` | `~/Library/Application Support/HGUET/` |
| Device secret | OS keyring or permission-restricted encrypted fallback | Windows credential store / DPAPI | macOS Keychain |

Settings precedence: CLI option > trusted per-user config > safe compiled default. Environment overrides must be explicit and documented; environment variables never silently enable Cloud or weaken transport.

Safe example:

```toml
schema_version = 1
network = "solana-mainnet"
default_mode = "local"
default_profile = "strict"
rpc_url = "https://user-selected-solana-rpc.example"

[output]
format = "human"
color = "auto"
redact_sensitive = true

[cloud]
endpoint = "hguet.fr:443"
enabled = false
device_key_reference = "os-keyring:hguet/device"
```

RPC URL credentials (if any) are sensitive and must not appear in logs or crash traces. Protect config path from symlinks/untrusted writers and refuse world-readable secret-bearing fallback files.

## 6. Output contract, automation and exit codes

- `stdout`: **one complete JSON object** per invocation in `--json` mode; no progress bars, ANSI colors or diagnostic chatter.
- `stderr`: human warnings/errors with redacted identifiers; machine callers can request typed `errors[]` in output.
- JSON includes schema version and full coverage/evidence; never return only a score.
- Stable, documented exit codes:

| Exit | Meaning | CI / signer action |
| --- | --- | --- |
| `0` | ALLOW | may proceed only if signer revalidates exact transaction binding |
| `10` | WARN | do not auto-sign; review |
| `20` | DENY | block |
| `30` | UNKNOWN | block in strict integrations |
| `40` | invalid CLI input or configuration | fail |
| `50` | infrastructure/transport failure | fail |
| `60` | Cloud auth, credit or account failure | fail |

A completed check that legitimately concludes `UNKNOWN` returns `30`, whereas an invalid input or network exception not convertible to evidence returns `40/50`; ensure deterministic mapping.

- `--quiet` affects human diagnostics, not schema fields.
- `--timeout` upper bounded; `--no-color` and `NO_COLOR` supported.
- Any prompt/interactive input is prohibited in automation mode (`--json` or non-TTY stdin); CLI fails clearly instead of hanging.

## 7. Behavior, accessibility and safety

- Friendly `--help`, shell completion, accessible terminal output without assuming color vision.
- Deterministic JSON order when signatures/canonical hashes are involved.
- Sane timeouts, bounded parallel RPC requests, cancellation on Ctrl-C.
- No telemetry without explicit permission. No automatic Cloud fallback.
- Clear warning when simulation used a replacement blockhash: result is **not** bound to the exact transaction the signer might sign.
- Outputs identify `not_simulated`, `unresolved` and `unsupported` instead of turning them into “safe”.
- Always print the target network and original transaction fingerprint in human-readable summaries.

## 8. Compatibility & versioning

- CLI command grammar may evolve before `v1.0`, but JSON and cloud schemas receive independent versions.
- Public fixtures test JSON against schemas; no breaking shape changes without version increase.
- Binaries for Linux x86_64 and aarch64, Windows x86_64 and macOS arm64/x86_64 are **targets**, not release commitments.
- Platform PQ TLS support must be verified before adding Cloud to any distribution.

See [verdict schema](verdict-schema.md), [cloud protocol](cloud-protocol.md) and [test plan](testing-roadmap.md).