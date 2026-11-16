"""Adversarial checks of the scorer and independent evidence rules."""
import copy
import json
import sys
import unittest
from pathlib import Path

TESTING = Path(__file__).resolve().parents[1]
CV = TESTING / "cloud-value"
sys.path[:0] = [str(TESTING / "runner"), str(CV / "verify"), str(CV / "labeling"), str(CV / "server")]
import run_benchmark as rb
import assessment_rules as rules
import independent_labeler as labeler
import reference_server as rs


class ReportContract(unittest.TestCase):
    def setUp(self):
        # Captured G-001 output: a fixed positive control, independent of schema-generated defaults.
        fixture = json.loads((TESTING / "tests/fixtures/g001-cli-contract.json").read_text())
        self.scenario = json.loads((TESTING / "scenarios/G-001.json").read_text())
        self.check = {"rc": 30, "stdout_json": fixture["check"], "stderr": ""}
        self.preflight = {"rc": 20, "stdout_json": fixture["preflight"]}

    def evaluate(self):
        return rb.evaluate(self.scenario, self.check, self.preflight)

    def test_positive_control(self):
        self.assertIsNone(self.evaluate()["failure_type"])
        self.assertEqual(rb.response_errors(self.check, self.scenario["input"]), [])

    def test_each_boundary_schema_violation_fails_scoring(self):
        original = copy.deepcopy(self.check)
        for field, value in (("signer_side_enforcement_integrated", True),
                             ("execution_bank_authenticated", True), ("block_reasons", []),
                             ("total_native_sol_spending_proven", "true"), ("version", 2)):
            with self.subTest(field=field):
                self.check = copy.deepcopy(original)
                self.check["stdout_json"]["signing_boundary"][field] = value
                self.assertEqual(self.evaluate()["failure_type"], "report_contract_violation")
                self.assertTrue(rb.response_errors(self.check, self.scenario["input"]))

    def test_schema_valid_identity_corruption_fails_scoring(self):
        original = copy.deepcopy(self.check)
        for obj, field, value in (("verdict", "message_sha256", "0" * 64),
                                  ("verdict", "transaction_sha256", "0" * 64),
                                  ("verdict", "message_sha256", None),
                                  ("verdict", "network", "mainnet"),
                                  ("signing_boundary", "message_sha256", "0" * 64)):
            with self.subTest(obj=obj, field=field, value=value):
                self.check = copy.deepcopy(original)
                self.check["stdout_json"][obj][field] = value
                self.assertEqual(self.evaluate()["failure_type"], "report_contract_violation")

    def test_refusal_schema_and_nested_boundary_are_checked(self):
        original = copy.deepcopy(self.preflight)
        for field, value in (("version", 2), ("original_message_sha256", "0" * 64),
                             ("original_transaction_sha256", "0" * 64)):
            with self.subTest(field=field):
                self.preflight = copy.deepcopy(original)
                self.preflight["stdout_json"]["signer_refusal"][field] = value
                self.assertEqual(self.evaluate()["failure_type"], "report_contract_violation")
        self.preflight = copy.deepcopy(original)
        self.preflight["stdout_json"]["signer_refusal"]["signing_boundary"]["block_reasons"] = []
        self.assertEqual(self.evaluate()["failure_type"], "report_contract_violation")


class RetractionTimeAndScope(unittest.TestCase):
    def setUp(self):
        self.record = json.loads((CV / "evidence/EV-0001.json").read_text())
        self.record.update(observed_at="2026-01-01T00:00:00Z", valid_until="2026-12-31T00:00:00Z",
                           confidence=1.0)
        self.record["claim"]["polarity"] = "adverse"
        self.record["provenance"]["tier"] = "historical_class"
        self.request = {"network": self.record["network"], "subjects": [self.record["subject"]]}
        self.now = "2026-06-01T00:00:00Z"
        self.notice = copy.deepcopy(self.record)
        self.notice.update(evidence_id="audit-retraction", retracts=self.record["evidence_id"],
                           observed_at=self.now)
        self.notice["claim"]["polarity"] = "retraction"

    def assert_outcome(self, notice, withdrawn):
        records = [self.record, notice]
        epoch = rules.parse_time(self.now)
        self.assertEqual(rules.Registry(records).eligibility(self.record, self.request, epoch),
                         "superseded" if withdrawn else None)
        inputs = {"cloud_request": self.request, "clock": self.now}
        self.assertEqual(labeler.derive_label(inputs, records)[0], "GOOD" if withdrawn else "BAD")
        server = rs.ReferenceCloudServer(CV / "evidence")
        server.records = records
        self.assertEqual(server._usable(self.record, self.request, epoch), not withdrawn)

    def test_time_boundaries_and_permanent_withdrawal(self):
        for timestamp, withdrawn in (("2026-07-01T00:00:00Z", False),
                                     (self.now, True), ("2026-05-31T23:59:59Z", True),
                                     (self.record["observed_at"], False),
                                     ("2025-12-31T23:59:59Z", False)):
            with self.subTest(timestamp=timestamp):
                notice = dict(self.notice, observed_at=timestamp)
                self.assert_outcome(notice, withdrawn)
        # An expired notice does not resurrect its withdrawn target.
        self.assert_outcome(dict(self.notice, observed_at="2026-02-01T00:00:00Z",
                                 valid_until="2026-03-01T00:00:00Z"), True)

    def test_wrong_scope_polarity_and_target_cannot_withdraw(self):
        for field, value in (("network", "mainnet" if self.record["network"] != "mainnet" else "devnet"),
                             ("subject", dict(self.record["subject"], id="different-subject")),
                             ("claim", dict(self.notice["claim"], polarity="adverse")),
                             ("retracts", "nonexistent")):
            with self.subTest(field=field):
                self.assert_outcome(dict(self.notice, **{field: value}), False)


if __name__ == "__main__":
    unittest.main()
