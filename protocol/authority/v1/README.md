# Authority Intelligence v1 — developer preview

Run `hguet authority FILE --offline [--encoding binary|base64|base58] [--json]`.
Bounded stdin (-) supported. Exit 0 means the inventory was produced, not that
the transaction is authorized. Exit 40 returns hguet_authority_error. No RPC.

One event per selected decoded control declaration. The target, authority,
proposed authority, delegate limit and recipient are wire roles, not verified
account state. Required signer is a message role only. SPL base authority types
0–3 are named; other numeric values remain explicitly unclassified. Null
proposed authority on SetAuthority is a requested removal, not proof it is
allowed. A delegate limit is not a debit and successive approvals are not summed.
Hook configuration, fee configuration and ALT operations are control
declarations, not proof of effective execution. Details including raw fields
remain in the embedded program report. Each event points to its instruction.
Unknown, unresolved, invalid and prefix-only rows remain unclassified.
No full authority inventory, CPI coverage, final-state or safety claim.

Existing analysis, program and flow reports are unchanged. No signing,
broadcasting, account custody, real funds or mandatory Cloud. Runtime checks
for existing SPL approval and account-owner change fixtures compare actual
state to the new declaration report; all other operations require their own
runtime evidence. Phase 2.2 remains open.
