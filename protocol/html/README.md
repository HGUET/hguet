# Standalone HTML reports — developer preview

The seven inventory commands report, programs, flow, authority, diff, flow-rpc and audit
accept an explicit --html flag. JSON is still the default, with its existing
contract. --json and --html are mutually exclusive. Output is written to stdout;
use redirection to save a file. Exit codes remain unchanged. Configuration and
input errors retain the JSON error envelope (40); valid reports with unavailable
RPC evidence can be HTML (30). Do not interpret exit 0 as approval.

The renderer is a projection of engine-generated reports, not a new verdict.
It displays original-wire asset edges, authority changes, instruction inventory,
positional diff, or historical/advisory balance and CPI views as appropriate.
Amounts stay raw strings. Missing values are labeled and no numeric views are
combined. The evidence explorer retains all report fields, with deterministic
hashed anchors for JSON pointers. Expand parent groups if needed. Nested
limitations are retained in the evidence explorer.

All dynamic content is escaped, controls and bidi overrides are shown visibly,
anchors are generated from hashes, and no scripts, external assets, forms or
remote links are included. A restrictive meta CSP forbids resource loading
except inline CSS. The HTML renderer itself does not make network requests;
RPC commands still use the explicitly selected endpoint before rendering.
The document may contain sensitive transaction/account information and should
be shared only intentionally. Never treat a locally saved HTML file as a
cryptographically authenticated report.

No external dependencies added. No browser automation, DOT export or public
release claim. Independent tests cover injection, local anchors and output
format selection. See the Phase 2 roadmap for acceptance status.

The SDK/CLI suite `testing/runtime/html_preview.py` generates five actual HTML files from synthetic transactions and validates a passive tag allowlist, local anchor resolution, restrictive CSP, unchanged JSON and invalid format/input handling. It runs with the network namespace isolated and saves the HTML files inside the source-attributed CI evidence artifact. Additional Rust tests cover escaped malicious values and HTML rendering of typed historical and simulation fixture reports. A test pass is not equivalent to a browser rendering or accessibility audit.

The combined `report` command renders one offline dossier of flow, authority and program inventory. Both nested views derive from one program decode and preserve their standalone JSON contracts. The test suite verifies their exact equality with separately generated views.
