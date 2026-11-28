# Current CLI reference

Commands below are implemented in the developer-preview source, not a released package. Run `hguet --help` for the binary's exact grammar. All input is untrusted. No command grants signing permission.

| Command | Required arguments / main flags | Network |
| --- | --- | --- |
| inspect | FILE --offline; --encoding, --report-v2, --text, --json | Offline for this invocation |
| check | FILE --mode local --network NETWORK; optional --intent FILE --trusted-key BASE58, --policy FILE, --rpc-url HTTPS_URL, --report-v2, --text | Offline without RPC URL; otherwise explicit simulation |
| signer-preflight | FILE --offline --network NETWORK --intent FILE --trusted-key BASE58 | Offline refusal only |
| policy validate | FILE [--json] | None |
| config show / doctor | [--json] | None |
| programs / flow / authority / report | FILE --offline [--encoding ENCODING] [--json\|--html] | None |
| diff | BEFORE AFTER --offline [--encoding ENCODING] [--json\|--html] | None |
| flow-rpc | FILE --network NETWORK --rpc-url HTTPS_URL [--encoding ENCODING] [--json\|--html] | Explicit provider simulation and optional state reads |
| audit | SIGNATURE --network NETWORK --rpc-url HTTPS_URL [--json\|--html] | Explicit provider historical metadata |
| demo | [--json] | None |
| lab | CASE [--json\|--html], or all --out NEW_DIR | None |
| --help / --version | — | None |

NETWORK is mainnet, devnet or testnet. ENCODING is binary (default), base64 or base58. Transaction file/stdin is limited to 16,384 encoded bytes, with separate decoded-wire limits. Diff permits only one stdin and uses the same encoding for both inputs.

The public source also contains explicitly experimental local Devnet `cloud hello/quote/status/submit` paths. See [historical sandbox documentation](implementation/previous-readme.md) and actual help; these are not part of a public paid service. No standalone `simulate`, `explain`, `intent verify`, MCP or released SDK is claimed.

## Output contracts and status codes

| Family | Output | Exit meaning |
| --- | --- | --- |
| inspect/check | Analysis v1 JSON (default), v2 with --report-v2, text with --text | Informational inspect success 0; check DENY 20, UNKNOWN 30; malformed 40. Never approval. |
| programs/flow/authority/report/diff | Separate v1 JSON, optional --html | 0 report produced; 40 input/configuration error |
| flow-rpc | Separate v1 JSON or HTML | 0 RPC reports simulation success; 30 failed/unavailable; 40 invalid configuration/input |
| audit | Separate v1 JSON or HTML | 0 signature-bound transaction returned (including reported execution failure); 30 not found/unavailable/invalid provider evidence; 40 invalid configuration/input |
| lab | Lab v1 JSON, per-case HTML, or export manifest | 0 report/export produced; 40 invalid case/options or export failure |
| policy validate / help / version / doctor | Command-specific output | 0 means command success, not transaction authorization |

Inventory errors remain JSON even when --html was requested. Valid RPC failure reports may be HTML. Do not mix --html and --json or --text and --json. Read the exit status before opening redirected output as HTML. No output is a signing grant. See [contract index](README.md#machine-readable-contracts).

## Privacy and trust

Offline commands make no RPC calls. Select RPC endpoints explicitly and independently; simulation sends original bytes, audit sends a public identifier. No HGUET Cloud is required. Treat RPC metadata as potentially malicious and later simulation snapshots as non-atomic. Independently pin policy and issuer keys, not agent-supplied values. Keep raw transactions and generated reports private when necessary.

[Quick start](../QUICKSTART.md) · [Security](../SECURITY.md) · [Limitations](../LIMITATIONS.md).
