"""Self-tests of the Cloud evaluator contract (no HGUET binary, no network)."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

TESTING = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(TESTING / "cloud"), str(TESTING / "mocks"), str(TESTING / "runner")]
import compare  # noqa: E402
import evaluator  # noqa: E402

SCENARIOS = compare.load_scenarios()


def row(sid, decision, digest="a" * 64):
    base = {"id": sid, "truth": SCENARIOS[sid]["truth"]["label"], "decision": decision, "message_sha256": digest,
            "checks": {"required_findings": True, "decision_acceptable": True, "proven_properties": True},
            "invariants": {"gate_blocks": True}}
    return base


class Contract(unittest.TestCase):
    def test_result_requires_a_known_source_kind(self):
        with self.assertRaises(ValueError):
            evaluator.CloudResult("trust_me", "x", "p", True)
        for kind in evaluator.SOURCE_KINDS:
            evaluator.CloudResult(kind, "x", "p", False, reason="r")

    def test_real_server_is_unavailable_and_does_no_io(self):
        got = evaluator.RealServer().assess(SCENARIOS["G-001"], row("G-001", "UNKNOWN"))
        self.assertFalse(got.available)
        self.assertEqual(got.source_kind, "real_server")
        self.assertIsNone(got.assessment)

    def test_independent_proof_needs_provenance_and_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = evaluator.IndependentProof(tmp)
            local = row("B-001", "DENY")
            self.assertFalse(source.assess(SCENARIOS["B-001"], local).available)  # no proof file
            proof = Path(tmp) / "B-001.json"
            proof.write_text(json.dumps({"message_sha256": local["message_sha256"], "adverse": True}))
            self.assertFalse(source.assess(SCENARIOS["B-001"], local).available)  # no provenance
            proof.write_text(json.dumps({"message_sha256": "0" * 64, "adverse": True, "established_by": "x"}))
            self.assertFalse(source.assess(SCENARIOS["B-001"], local).available)  # wrong tx
            proof.write_text(json.dumps({"message_sha256": local["message_sha256"], "adverse": True,
                                         "established_by": "reference executor, reviewed"}))
            self.assertTrue(source.assess(SCENARIOS["B-001"], local).available)

    def test_sources_are_never_merged_in_the_comparison(self):
        rows = [row(sid, "UNKNOWN") for sid in ("G-001", "U-001")] + [row("B-001", "DENY")]
        report = {"results": rows}
        result = compare.compare(report, SCENARIOS)
        cloud = result["local_cloud"]
        self.assertEqual(set(cloud), set(evaluator.SOURCE_KINDS))
        self.assertIn("profiles", cloud["reference_mock"])
        self.assertNotIn("profiles", cloud["real_server"])
        self.assertIn("MODEL", cloud["reference_mock"]["disclaimer"])
        self.assertIn("UNAVAILABLE", cloud["real_server"]["disclaimer"])
        self.assertEqual(result["local_rpc"]["successful_simulation"], "not_measurable_through_cli")
        self.assertIn("never_merged", result)

    def test_hostile_cloud_never_creates_allow_and_amplification_is_visible(self):
        rows = [row("G-001", "UNKNOWN"), row("U-001", "UNKNOWN"), row("B-001", "DENY")]
        profiles = compare.compare({"results": rows}, SCENARIOS)["local_cloud"]["reference_mock"]["profiles"]
        for name, data in profiles.items():
            self.assertEqual(data["ALLOW_created_by_cloud"], 0, name)
        self.assertEqual(profiles["always_adverse"]["good_scenarios_blocked_only_because_of_cloud"], 1)
        self.assertEqual(profiles["always_benign"]["good_scenarios_blocked_only_because_of_cloud"], 0)
        for discarded in ("stale", "mismatched_binding"):
            self.assertEqual(profiles[discarded]["bad_scenarios_denied_only_because_of_cloud"], 0)
            self.assertEqual(profiles[discarded]["good_scenarios_blocked_only_because_of_cloud"], 0)
        self.assertEqual(profiles["oracle_upper_bound"]["bad_scenarios_denied_only_because_of_cloud"], 0)  # B-001 already DENY

    def test_oracle_profile_can_only_raise_severity(self):
        rows = [row("B-014", "UNKNOWN") if "B-014" in SCENARIOS else row("B-101", "UNKNOWN")]
        sid = rows[0]["id"]
        profiles = compare.compare({"results": rows}, SCENARIOS)["local_cloud"]["reference_mock"]["profiles"]
        self.assertEqual(profiles["oracle_upper_bound"]["bad_scenarios_denied_only_because_of_cloud"], 1, sid)


if __name__ == "__main__":
    unittest.main()
