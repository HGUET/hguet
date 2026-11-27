# Historical Transaction Audit v1 — developer preview

Run `hguet audit SIGNATURE --network mainnet|devnet|testnet --rpc-url HTTPS_URL [--json]`.

Exactly two read-only RPC methods: getGenesisHash and getTransaction (finalized,
base64, maxSupportedTransactionVersion=1). No default provider or network.
The supplied Base58 signature must decode to 64 nonzero-as-a-whole bytes.
Only that public identifier is sent; no local wallet or transaction file.
The response is bounded, decoded by the existing core wire parser and must
match its reported version and first signature. All required signatures must
verify locally. Legacy/v0/v1 wire layouts are supported by the decoder.
No provider error string or endpoint is returned.

The report distinguishes FOUND_SIGNATURE_VERIFIED, NOT_FOUND_AT_REQUESTED_COMMITMENT,
and RPC_UNAVAILABLE. A null result does not prove a transaction never existed.
Historical metadata can be missing. Historical provider claims of success/failure
and fee are separate from wire flow and authority declarations. A failed
transaction can have a fee. The typed balance/CPI decoder is reused; no simulation
request or present-day account reads. Historical loaded addresses are checked
for valid keys and exact writable/readonly counts. If absent for a lookup-dependent
message, effects are unavailable, not zero. Invalid metadata rejects the response.
Slot, block time, fee, balances, CPI and loaded addresses remain provider claims.
No consensus, ledger inclusion, state or authorization proof; no broadcast.
No combined totals across declaration/CPI/net layers.

Exit 0: signature-bound transaction returned, even if its reported execution failed.
Exit 30: not found or unavailable/invalid provider evidence.
Exit 40: malformed input or configuration, hguet_audit_error.
All signing authorization is NOT_AUTHORIZED. No changes to prior contracts.

References:
- https://solana.com/developers/docs/rpc/http/gettransaction
- https://solana.com/developers/docs/rpc/json-structures

This is a developer preview; mock transport tests and real read-only public
historical samples are required before broad compatibility claims.
