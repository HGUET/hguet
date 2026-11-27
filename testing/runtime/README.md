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

Seven cases executed successfully in Ubuntu 26.04 WSL with Python 3.14.4:
native transfer, repeated native debits exceeding a local cap, SPL checked
transfer, delegate approval and account-owner authority change. The harness
checks actual balances/delegation/owner state after LiteSVM execution and
compares the corresponding HGUET declarations. Initial token accounts are
explicitly provisioned with SDK state layouts. Token program instructions
execute in the runtime.

Token-2022 tests initialize the fee extension and mint through the runtime,
then transfer 123 units at 100 basis points. The source debit is 123,
destination credit 121 and destination withheld fee 2. A second case supplies
an incorrect expected fee of 1 and confirms runtime rejection with unchanged
token account bytes. HGUET reports the declared amount and expected fee in
both cases, independently of runtime success. The instruction layout reference
is https://github.com/solana-program/token-2022/blob/main/interface/src/extension/transfer_fee/instruction.rs.

Limitations remain legacy transactions, no independent v1 runtime support
claim. Additional legitimate
and violation variants and runtime rejection cases are required for Phase 1.
These comparisons do not establish total-spending coverage or an audit.

Package documentation https://heavey.dev/solders/tutorials/litesvm.html

The verified Linux Solders wheel SHA-256 was
00524baf575ae5edb2ba43cdb1d80491c59efdc16b48fec96a6f929c0401d0e4.
Local measured output is target/phase01-evidence/runtime-native.json.
