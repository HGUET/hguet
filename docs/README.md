# HGUET documentation

Start with the [repository README](../README.md) and [quick start](../QUICKSTART.md). This index separates **current implemented contracts** from historical design and future release targets.

## User guides

| Document | Purpose |
| --- | --- |
| [CLI reference](CLI.md) | Current commands, output, exit codes, network boundaries |
| [Demo Lab](DEMO_LAB.md) | Six reproducible unsigned synthetic examples |
| [HTML reports](../protocol/html/README.md) | Portable report output and safe rendering |
| [Supported programs](../SUPPORTED-PROGRAMS.md) | Instruction-specific coverage |
| [Limitations](../LIMITATIONS.md) | What HGUET cannot prove |
| [Security policy](../SECURITY.md) | Responsible disclosure and trust boundaries |

## Machine-readable contracts

Default inspect/check analysis remains v1; report v2 is opt-in. The independent inventory reports have separate versioned JSON contracts. Resolve URN references against local schemas, not the network.

| Contract | Documentation |
| --- | --- |
| Analysis, intent, verdict, experimental Cloud v1 | [protocol/v1](../protocol/v1/README.md) |
| Scoped analysis v2 | [protocol/v2](../protocol/v2/README.md) |
| Program inventory | [programs/v1](../protocol/programs/v1/README.md) |
| Asset flow | [flow/v1](../protocol/flow/v1/README.md) |
| RPC flow | [flow-rpc/v1](../protocol/flow-rpc/v1/README.md) |
| Authority | [authority/v1](../protocol/authority/v1/README.md) |
| Diff | [diff/v1](../protocol/diff/v1/README.md) |
| Historical audit | [audit/v1](../protocol/audit/v1/README.md) |
| Combined report | [report/v1](../protocol/report/v1/README.md) |
| Demo Lab | [lab schema](../protocol/lab/v1/report.schema.json) and [guide](DEMO_LAB.md) |

## Engineering and verification

- [Current architecture](architecture/current.md): implemented crate/module responsibilities and trust boundaries.
- [Verification record](release/community-0.1.0/VERIFICATION.md): exact source, runs, artifacts, measured outcomes and outstanding failures.
- [Runtime harness](../testing/runtime/README.md) and [security benchmark](../testing/README.md): independent SDK construction, actual LiteSVM versus synthetic/mock scenarios.
- [Contributing](../CONTRIBUTING.md): scoped development and regression discipline.

## Release and design records

[Roadmap](release/community-0.1.0/ROADMAP.md), [Phase 2](release/community-0.1.0/PHASE_02.md), [coverage matrix](release/community-0.1.0/COVERAGE_MATRIX.md), [release gates](release/community-0.1.0/RELEASE_GATES.md) and [baseline](release/community-0.1.0/BASELINE.md) govern the unreleased 0.1.0 target.

[Architecture design archive](architecture/README.md) and [implementation history](implementation/README.md) retain earlier component designs and development checkpoints, including experimental Cloud and signer work. Do not treat target grammar or old counts in those documents as current availability. The current CLI, contracts and measured evidence take precedence.
