# Program coverage

Coverage is instruction-specific, not a program safety endorsement.

| Program family | Current baseline | 0.1.0 target |
| --- | --- | --- |
| System | Direct native transfer subset | Validated supported instructions, fees/rent distinguished |
| SPL Token | Partial direct/CPI movement and authority decoding | Runtime-validated supported effects, explicit gaps |
| Token-2022 | Partial operations, TLV observations and opaque extensions | Supported fee, hook, delegate and account-state evidence; no blanket completeness |
| Compute Budget, ATA, ALT, Memo | Partial recognition / ALT resolution | Validated core instruction coverage |
| Stake, upgradeable loader | No broad semantic coverage claimed | Optional after mandatory coverage |
| Jupiter / Raydium / Orca and other DeFi | No broad semantic coverage claimed | One bounded integration only if evidence justifies it |
| Arbitrary programs | Opaque/partial effects | Explicit unknowns and evidence; never infer safety from a known ID |

Record exact program IDs, versions, decoded fields, test IDs, evidence and gaps before claiming semantics.
