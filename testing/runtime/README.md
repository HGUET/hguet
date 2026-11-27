# Initial independent runtime comparisons

Install requirements.txt in an isolated Linux Python environment. Build the
locked HGUET CLI, then run:

```sh
python3 native.py --hguet /absolute/path/to/hguet --out runtime-result.json
```

Solders 0.29.0 supplies the Solana SDK and embedded LiteSVM runtime.
Transactions are constructed and signed by Solders with disposable keypairs
inside this harness. HGUET sees serialized bytes and public policy only.
The harness never contacts an RPC or submits a chain transaction.

Five cases executed successfully in Ubuntu 26.04 WSL with Python 3.14.4:
native transfer, repeated native debits exceeding a local cap, SPL checked
transfer, delegate approval and account-owner authority change. The harness
checks actual balances/delegation/owner state after LiteSVM execution and
compares the corresponding HGUET declarations. Initial token accounts are
explicitly provisioned with SDK state layouts. Token program instructions
execute in the runtime.

Limitations remain legacy transactions, no independent v1 runtime support
claim, and an outstanding Token-2022 transfer fee case. Additional legitimate
and violation variants and runtime rejection cases are required for Phase 1.
These comparisons do not establish total-spending coverage or an audit.

Package documentation https://heavey.dev/solders/tutorials/litesvm.html

The verified Linux Solders wheel SHA-256 was
00524baf575ae5edb2ba43cdb1d80491c59efdc16b48fec96a6f929c0401d0e4.
Local measured output is target/phase01-evidence/runtime-native.json.
