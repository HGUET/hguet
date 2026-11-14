# HGUET Cloud Value Benchmark v1

```bash
python testing/cloud-value/tools/build_cloud_value.py --check     # committed files == generator
python -m unittest discover -s testing/tests                      # verifier, mock, adapter, labelling, workflows
python testing/cloud-value/runner/run_cloud_value.py --hguet target/debug/hguet
# -> testing/cloud-value/reports/latest/report.html + report.json
```

See `RULES.md` for scenarios, evidence tiers, acceptance rules and metrics, and `../cloud/CONTRACT.md`
for the three-source contract.

## Connecting the real HGUET Server

The adapter speaks the **existing** public protocol (TLS 1.3 + 4-byte frame + Protobuf `Envelope` from
`protocol/v1/hguet.proto`); there is no HTTP endpoint to implement. See `PROTOCOL_INTEROP.md` for the
reconciliation, the verification pipeline, the devnet-only procedure (payments are made externally by the
operator) and the open questions. Without a pinned issuer key, a verifiable ML-DSA-87 backend and enforceable
PQ TLS the report says `real_server: unavailable` and sends nothing.

```bash
python testing/cloud-value/runner/run_cloud_value.py --hguet target/debug/hguet \n    --enable-real-server --real-server-host HOST --real-server-ca CA.pem [--payments-file payments.json]
```

Blind review of the 30 critical labels: `labeling/blind_review/README.md`, scoring with `labeling/score_review.py`.
