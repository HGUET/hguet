# HGUET Cloud Value Benchmark v1

```bash
python testing/cloud-value/tools/build_cloud_value.py --check     # committed files == generator
python -m unittest discover -s testing/tests                      # verifier, mock, adapter, labelling, workflows
python testing/cloud-value/runner/run_cloud_value.py --hguet target/debug/hguet
# -> testing/cloud-value/reports/latest/report.html + report.json
```

See `RULES.md` for scenarios, evidence tiers, acceptance rules and metrics, and `../cloud/CONTRACT.md`
for the three-source contract.

## Connecting a real HGUET Server

1. Implement `POST {base}/v1/assessments` per `server/real_server.py` (metadata-only request in; signed
   `CloudAssessment` envelope out, conforming to `protocol/v1/cloud-assessment.schema.json`).
2. Add a verifier for the server's signature algorithm to `verify/assessment_rules.SIGNATURE_ALGORITHMS`
   (`ml-dsa-87` is registered as *recognised but unsupported*) and pin its key in `PINNED_KEYS`.
3. Run, explicitly opting in (nothing is sent otherwise):

```bash
python testing/cloud-value/runner/run_cloud_value.py --hguet target/debug/hguet \
    --enable-real-server --real-server-url https://cloud.example.invalid
```

The report then gets a `real_server` column scored by the same strict verifier, with its own latency,
availability and privacy ledger (`requests_sent`, `bytes_sent`, `fields_sent`). Tamper scenarios are not
sent (they test the verifier). Without these flags the report says `real_server: unavailable`.
