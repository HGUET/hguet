# Public historical validation — first fixed case

The fixture solana-docs-devnet-legacy.json reconstructs original signed legacy wire
from the publicly documented example at
https://solana.com/developers/docs/rpc/http/gettransaction (accessed 2026-11-28).
The wire was reconstructed from the public key list, header, blockhash,
compiled instruction and signature. Its Ed25519 signature was independently
verified using Python cryptography before inclusion. The metadata is a projection
of that published example, not a freshly retrieved response or a cryptographic
proof of ledger inclusion. No private keys are present.

The offline Rust historical audit integration test passes this fixed fixture
through the actual bounded historical decoder and mock transport. A separate
public smoke script queries the official Devnet endpoint for the fixed signature
at finalized commitment, checks original bytes and signature using Solders,
and compares the actual HGUET audit against the published metadata and provider
net balances. The script uses only getGenesisHash and getTransaction; the CLI
also uses only those methods. No transaction submission or account reads.

```sh
cargo build --locked -p hguet
python -m pip install -r testing/runtime/requirements.txt
python testing/history/public_smoke.py --hguet target/debug/hguet --out public-history-evidence
```

This network-enabled check is separate from network-isolated acceptance.
The dedicated workflow runs on changes to this directory or manual dispatch.
Public RPC may rate-limit or prune historical data: exit 2 records unavailable
evidence and is not a pass. Assertion failures are failures, not skipped cases.
Outputs contain public transaction metadata, exact source and hashes in CI.
A single provider match is not independent consensus verification. Wider
mainnet/v0/v1/token/CPI historical corpus and second-provider checks are open.
Never broadcast the historical bytes.

## First public smoke result

Run 46089236362 returned a public Devnet transaction with the expected signed bytes, slot and version, but failed at preBalances before invoking the CLI. The checked-in fixture had rounded two balances above 2^53 by one lamport during JavaScript numeric serialization. The raw archived provider response retains exact integers. Corrected the two original decimal literals without parsing through JavaScript Number; the offline and live checks must run again. The original failure and artifact are retained in the verification record. No live audit pass is claimed yet.
