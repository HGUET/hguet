# Current HGUET architecture — developer preview

The implemented Rust workspace is local-first. This document describes the source at the current development checkpoint; [earlier design specifications](README.md) are historical/proposed where not implemented.

| Crate | Implemented responsibility |
| --- | --- |
| hguet-core | Bounded original-wire parsing, message/transaction hashes, Ed25519 status, intent verification, verdict primitives |
| hguet-policy | Restrictive local configuration and supported direct-wire rules |
| hguet-rpc | Explicit HTTPS transport, genesis verification, simulation, ALT and token metadata, historical transaction decoder |
| hguet-cli (library + binary) | Reusable analysis orchestration, reports, CLI and demos |
| hguet-signer | Experimental refusal-only preflight/isolation mechanisms |
| hguet-cloud | Optional experimental quote/assessment and protocol transport; not mandatory or publicly deployed |

## Analysis and reporting

```text
Untrusted original transaction -> bounded core parser
                                    | 
                     +--------------+---------------+
                     |                              |
         Program inventory (programs.rs)      Analysis v1/v2
            |           |            |        + independent policy
            v           v            v        + pinned signed intent
         flow.rs   authority.rs    diff.rs    + optional RPC
            |           |
            +-----------+ -> report.rs (one inventory, two views)
                               |
                    versioned JSON / html.rs + report.css
```

The offline combined report decodes one program inventory and derives both asset and authority views from it. Separate standalone contracts are retained. The semantic diff compares raw instruction fingerprints and message context as well as decoded declarations; it does not claim semantic equivalence. The renderer is a passive projection, not a rule engine.

`flow_rpc.rs` adds correlation links to typed single-provider simulation evidence. `audit.rs` uses `hguet-rpc/src/history.rs` to retrieve a transaction by signature, verify original signatures, and retain historical metadata separately. No current state reads for historical audit. Original wire, CPI, net balance and later state snapshots are distinct evidence sources. Repeated links may point to the same observation and must not be summed.

`lab.rs` builds deterministic unsigned synthetic fixtures, runs the actual report/diff engines and emits JSON/HTML pairs with hashes. `demo.rs` retains the three original policy examples.

## Trust boundaries

Operator-controlled network, policy and issuer key are separate from untrusted agent input. No hidden network on offline paths. Simulation discloses transaction bytes to the explicit provider; historical lookup sends a public identifier. Provider genesis, balances, CPI and historical metadata are claims; local signature verification is not ledger consensus. No signing, custody, broadcast or positive authorization. Cloud remains optional and independent of the free engine.

See [CLI](../CLI.md), [contracts](../README.md#machine-readable-contracts), [security](../../SECURITY.md) and [measured verification](../release/community-0.1.0/VERIFICATION.md).
