# Trusted Signer Isolation — threat model and blocked prototype

**Status: implemented input separation and no-sign process, NOT trusted OS/device isolation.** HGUET has no released signer, key material, hardware wallet integration, Solana broadcast capability, spending-permission token or enforced onchain gross-spend limit. Every current path is **BLOCK**.

## Trust domains

| Domain | Origin | Trust / allowed role |
| --- | --- | --- |
| Agent / UI / proposed transaction | AI agent or application process | **Untrusted.** Can provide proposed original-wire bytes and an independently signed PaymentIntent envelope only |
| Selected Solana RPC | Optional provider outside signer process | **Untrusted and non-atomic.** Simulation, account data, CPI, risk badges and balance deltas are observations, never approvals; the isolated process accepts no RPC input |
| Operator launch configuration | Separately configured process owner | **Provisioning assumption**, not remotely attested. Provides intended network and pinned intent signer public key outside agent JSON |
| Local wall clock | OS process | Used for signed-intent expiry; **not** trusted hardware time, susceptible to compromised host |
| HGUET signer process | Rust workspace code | Re-parses raw bytes, verifies pinned Ed25519 intent and returns **refusal only** |
| Actual wallet/device | Future, not present | No backend trait, keys, device channel, signing or broadcasting code exists |

## Current data path

~~~text
UNTRUSTED AGENT                         OPERATOR-LAUNCHED LOCAL PROCESS
  proposed bytes + signed envelope ──> hguet-signer-isolate (stdin, <=64 KiB JSON)
                                        ├─ strict schema_version=1 + kind
                                        ├─ reject unknown fields / oversize / noncanonical Base64
                                        ├─ decode <=16 KiB original transaction
                                        ├─ read operator-selected network + public key
                                        ├─ read current OS clock; no agent-supplied time
                                        ├─ parse original Solana message
                                        ├─ verify exact-message domain-separated signed intent
                                        ├─ audit direct checked token declaration caps
                                        └─ BLOCK + JSON SignerRefusal + exit code 20
                                                 X NO SIGNING BACKEND
                                                 X NO RPC / WALLET / BROADCAST
~~~

The executable is launched with:

~~~sh
cargo run -p hguet-signer --bin hguet-signer-isolate -- --network devnet --trusted-key OPERATOR_PINNED_PUBLIC_KEY
~~~

The JSON request comes on **stdin**. The process accepts no file paths, URLs, RPC, wallet or signing options. A request contains only **schema_version**, **kind=hguet_signer_preflight**, **original_transaction_b64**, and **signed_intent** (payload_b64, signer_pubkey_b58, signature_b58). The new public schema, protocol/v1/signer-agent-request.schema.json, specifies this shape. Rust additionally limits total input to 65,536 bytes, decoded transaction to 16,384 bytes, and checks canonical Base64. Unknown, injected, malformed and oversized requests produce block-only refusal.

The public SignerBackend.sign_transaction trait from the original prototype was **removed**. The only guarded_sign function has no backend argument and has an uninhabited Infallible success type. A malicious caller can always invoke other programs, but HGUET's exposed signer gate cannot perform signing.

## Established properties

- Injected allow, signing_gate, network, now_unix, trusted_key, independently_pinned_intent_signer, rpc_result and device_command fields in the agent JSON are **rejected**, never merged into operator configuration.
- The request cannot alter the public key or cluster chosen when the process starts. An attacker who controls **process startup** can still choose another key or network; current software cannot prevent that.
- The signed intent is independently verified against the transaction message hash, network and current local clock. A match records a checked declaration only, **not spending approval**.
- End-to-end CI starts the separate executable with the correct public synthetic key and then an unrelated key; verifies schema-constrained refusals; rejects hostile process arguments; never opens a real wallet or contacts RPC.
- The process stores no private keys. Normal output contains neither source transaction payload nor full intent envelope.

## Unsolved security requirements — release blockers

1. **OS isolation:** No sandbox policy, separate restricted OS identity, integrity-protected binary, network namespace, syscall filter, mandatory access control, secure launch configuration or process attestation. This is a **separate process, not a secure enclave**.
2. **Exclusive key access:** No hardware wallet or HSM is present. HGUET cannot prevent another application from invoking another wallet. Future device ports must not be accessible to an untrusted agent.
3. **Trusted configuration:** The process operator supplies a public-key pin as a launch argument; the agent JSON cannot override it, but a hostile parent controlling launch **can**. A production signer needs independently provisioned, integrity-protected policy and network identity.
4. **Trusted time and replay:** The OS clock is not trusted hardware time, and there is no persistent one-use nonce/intent replay ledger. A correctly signed intent could be reused while valid; solve before enabling any signing.
5. **Execution-time spend enforcement:** CPI, fees, arbitrary programs, Token-2022 hooks, ALT provenance, account ownership, delegate allowances, vault balances and time-of-check/time-of-use effects are not completely authenticated or bounded. RPC remains advisory.
6. **Human anti-substitution:** No trusted-display confirmation binds exact transaction bytes and recipient/caps to an authenticated user action.
7. **Formal assurance:** No adversarial fuzzing, isolated binary attestation or formal proof is completed. Green CI is not proof of OS or hardware isolation.

**Release gate:** A future device-accessible signer must authenticate its own pin, policy, network, one-use nonce, time and exact original transaction on a trusted path and enforce a defensible total asset/spend model. Until this exists, BLOCK must remain unconditional and no private-key operation may be connected.

## Synthetic verification

Rust module tests cover OperatorTrust configuration and hostile input shapes. CI runs scripts/check_isolated_signer.py against the separate built hguet-signer-isolate executable. All fixtures are public synthetic devnet test data. No payment, remote call or private key is used.
