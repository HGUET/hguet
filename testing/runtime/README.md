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

Thirteen runtime comparisons completed successfully in Ubuntu 26.04 WSL with Python 3.14.4:
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

Additional comparisons cover SDK-built v0 and v1 native transfers. Both
executed and their serialized message hashes matched HGUET. The bundled v1
fixture also round-tripped exactly through the SDK. A transfer with the wrong
token authority and a native transfer with insufficient funds were rejected
with unchanged destination/token state. HGUET retains wire declarations in
rejected runtime cases.

Coverage is limited to the thirteen listed cases, including the v0 ALT and
v1 inline-resource variants described below. Live cluster support is
unverified. Broader program, state and rejection coverage remains future
work. These comparisons do not establish total-spending coverage or an audit.

Package documentation https://heavey.dev/solders/tutorials/litesvm.html

The verified Linux Solders wheel SHA-256 was
00524baf575ae5edb2ba43cdb1d80491c59efdc16b48fec96a6f929c0401d0e4.
Local measured output is target/phase01-evidence/runtime-native.json.


The v0 ALT case executes against an active, SDK-layout lookup account and
confirms an actual recipient increase of 500. Offline HGUET retains the
known declared amount, exposes unresolved addresses and reports UNKNOWN.
V2 account fields remain null where ALT state is required.

The v1 inline-resource case sets a priority fee of 1000, compute limit 200000,
loaded-data limit 65536 and heap size 32768. The SDK-generated message
executes and its serialized hash matches HGUET. Coverage remains limited to
these particular settings and this pinned local runtime.

## Continuous checks

`.github/workflows/runtime-ci.yml` builds the locked CLI on Ubuntu 24.04 and
runs this harness with Python 3.12 and the pinned requirements on pushes to
main and pull requests. Dependency installation precedes execution inside a
separate network namespace (`sudo unshare --net`), which has no external
network access. LiteSVM executes locally; no wallet credentials or live RPC
are needed. The harness compares its thirteen cases and exits on an assertion
failure. CI retains the result JSON, command log, source commit, environment
and CLI SHA-256 even on a failing runtime step. The hash identifies the tested
binary; it is not publisher authentication.

This workflow definition is locally validated; a hosted CI pass must be
observed separately. Local WSL checks use the same harness with an unprivileged
user/network namespace where supported. Platform/runtime claims remain scoped
to actual measured runs.

Every case includes comparison=PASS only after its runtime and HGUET
assertions succeed; existing detailed runtime fields are preserved.
The CI runtime step uses explicit Bash pipefail so tee cannot mask failure.
