# Program and instruction coverage

Coverage means a bounded declaration decoder or a specific verified observation, not a program safety endorsement. All rows remain partial.

| Program family | Current original-wire intelligence | Local runtime evidence (selected cases) |
| --- | --- | --- |
| System | Transfer, transfer with seed, account creation/funding, nonce withdrawal subset | Native transfers, repeated cap, insufficient SOL, SDK v0/v1, v0 ALT transfer |
| SPL Token | Transfer/checked, mint/burn and checked variants, approve/checked, revoke, set authority, close, freeze/thaw, sync native | Checked transfer, mint/burn, approval/revoke, owner change, mint authority removal, freeze/thaw, empty-account close, wrong authority |
| Token-2022 | Selected base instructions; checked fee transfer, set transfer fee, initialize permanent delegate, initialize/update transfer hook | Correct and incorrect expected transfer fee, resulting withheld amounts; other extensions primarily declarations |
| Compute Budget | Selected heap, unit limit/price, loaded data limit declarations; v1 inline resources separately | SDK Compute Budget and v1 inline-resource cases |
| Memo | Byte length and UTF-8 status; payload omitted | Memo local execution |
| Associated Token Account | Six-account create and create-idempotent declarations and static program role check | Actual creation and idempotent repeat; resulting mint/owner/balance |
| ALT | Create/extend/freeze/deactivate/close shapes; bounded addresses; table/index references retained | Actual v0 transfer using an active table; mutation execution not broadly verified |
| Stake / upgradeable loader / DeFi | No broad semantic decoder coverage | Not established |
| Unknown program or unresolved lookup | Explicit gaps; never infer zero or safety | Malformed/opaque/lookup-isolation SDK tests |

## Evidence status

The [Program Intelligence contract](protocol/programs/v1/README.md) describes exact layouts, supported field bounds and missing data. Related [Asset Flow](protocol/flow/v1/README.md) and [Authority](protocol/authority/v1/README.md) views reuse the inventory; [RPC correlation](protocol/flow-rpc/v1/README.md) does not turn provider observations into verified effects.

`DECODED_DECLARATION` means supported wire fields were recognized. `PREFIX_ONLY`, `UNSUPPORTED_LAYOUT`, `UNRESOLVED_ACCOUNTS`, `UNRESOLVED_PROGRAM` and `DECODER_UNAVAILABLE` expose gaps. Memo invalid UTF-8 remains explicit. No program-name allowlisting or blanket support claim.

See [source-attributed verification](docs/release/community-0.1.0/VERIFICATION.md) for actual SDK/LiteSVM results and remaining work. Broader validator execution, extension/state coverage and live-cluster behavior remain open.

## Extended runtime checkpoint

At 9eef59d, four actual Token-2022 extension runtime groups passed: permanent delegate, hook configuration (not hook CPI), fee collection/harvest/withdrawal/future fee configuration, non-transferable rejection. No expansion of static layout coverage is implied. Two new ALT lifecycle groups are implemented and pending CI; until measured, the existing v0 lookup transfer is the confirmed ALT runtime case. See [verification](docs/release/community-0.1.0/VERIFICATION.md).

ALT lifecycle groups passed on e265036: SDK create/extend/freeze/deactivate/close, exact wrong-authority/frozen/cooldown rejection, actual lookup transfers and close refund with controlled slot history. No validator timing or broad live-cluster claim. See [verification](docs/release/community-0.1.0/VERIFICATION.md).
