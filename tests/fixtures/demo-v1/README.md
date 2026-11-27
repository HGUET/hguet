# Demo fixture version 1

Synthetic unsigned legacy transactions generated independently with the existing
testing/lib/crypto_tx.py builder. No keypair or credential is bundled.
The payer is account('signer:demo-payer'), destinations are
account('demo-recipient') and account('demo-extra').

- match declares one System transfer of 500 lamports.
- violation declares the same transfer plus one lamport to the extra address.
- opaque calls CUSTOM_PROGRAM with no instruction accounts and data byte 01.

All transactions use build_transaction's default unsigned signature mode.
policy.toml limits declared native transfers to 500 lamports on devnet.
This cap says nothing about opaque-program execution or network fees.
