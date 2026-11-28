# HGUET Security Demo Lab

**Developer preview. All transactions are synthetic and unsigned. Never broadcast.**

```sh
hguet lab all --out hguet-demo-lab
hguet lab authority --html > authority.html
hguet lab diff --json
```

| Case | Expected observation |
| --- | --- |
| payment | 500 declared lamports, no execution claim |
| additional-debit | 501 declared lamports across two instructions |
| authority | proposed 99 raw-unit token delegate limit, no direct debit |
| token2022 | 123 raw-unit declared transfer including expected fee 2 |
| uncertainty | opaque instruction, unquantified effects |
| diff | changed original message, added declaration |

These expectations are tested against actual engine outputs, not substituted
for them. Fixtures contain no private keys, live blockhashes or valid signatures.
The JSON envelope preserves the original Base64 wire and optional before wire
so independent tools can reproduce the report. The HTML shows a synthetic
banner and the actual report. Output is deterministic and offline. No amount
is a verified executed debit or total wallet spending.

The export requires a new directory; existing paths are rejected. It writes
six JSON/HTML pairs and a manifest with each file's SHA-256. A failure may
leave a partial directory; a missing manifest means incomplete export.
Verify hashes before sharing. The manifest is not a signature or authenticity
guarantee. No live historical sample is included in this lab; the separately
opt-in audit command requires an explicit provider.

The network-isolated SDK/CLI suite verifies roundtrip and unsigned status,
reproducibility, actual CLI report parity, local HTML anchors and no overwrite.
The six cases are not a comprehensive security benchmark or runtime test suite.
The existing policy demo, `hguet demo`, remains unchanged.
