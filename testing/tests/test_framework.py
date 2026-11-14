"""Self-tests of the benchmark framework (no HGUET binary needed)."""
import json
import socket
import sys
import unittest
from pathlib import Path

TESTING = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(TESTING / "lib"), str(TESTING / "mocks"), str(TESTING / "runner")]
import cloud_mock  # noqa: E402
import crypto_tx as ct  # noqa: E402
import rpc_mock  # noqa: E402
import run_benchmark as rb  # noqa: E402

SCENARIOS = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((TESTING / "scenarios").glob("*.json"))]


class Crypto(unittest.TestCase):
    def test_rfc8032_vectors(self):
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        self.assertEqual(ct.ed25519_public(seed).hex(),
                         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        self.assertEqual(ct.ed25519_sign(seed, b"").hex(),
                         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

    def test_base58_roundtrip(self):
        for raw in (b"", b"\0", b"\0\0abc", bytes(range(32))):
            self.assertEqual(ct.b58decode(ct.b58encode(raw)), raw)
        self.assertEqual(ct.SYSTEM, ct.b58encode(bytes(32)))


class Scenarios(unittest.TestCase):
    def test_mix_and_uniqueness(self):
        classes = [s["class"] for s in SCENARIOS]
        self.assertEqual((classes.count("GOOD"), classes.count("BAD"), classes.count("UNKNOWN")), (20, 25, 15))
        self.assertEqual(len({s["id"] for s in SCENARIOS}), 60)

    def test_every_scenario_is_complete_and_independent(self):
        for s in SCENARIOS:
            with self.subTest(s["id"]):
                self.assertEqual(s["format"], "hguet-bench-scenario/1")
                self.assertTrue(s["id"].startswith(s["class"][0]))
                self.assertGreaterEqual(len(s["rationale"]), 20)
                self.assertTrue(s["truth"]["authored_independently_of_tool"])
                self.assertEqual(s["truth"]["label"], s["class"])
                allowed = {"GOOD": {"ALLOW", "UNKNOWN"}, "BAD": {"DENY"}, "UNKNOWN": {"UNKNOWN"}}[s["class"]]
                self.assertEqual(set(s["truth"]["acceptable_decisions"]), allowed)
                self.assertIn("findings_required", s["expect"])
                if s["class"] == "BAD":
                    self.assertTrue(s["expect"]["findings_required"], "BAD must name the threat family")

    def test_smoke_set_covers_all_classes(self):
        smoke = [s["class"] for s in SCENARIOS if s["smoke"]]
        for cls in ("GOOD", "BAD", "UNKNOWN"):
            self.assertGreaterEqual(smoke.count(cls), 3)

    def test_known_defects_reference_real_scenarios(self):
        known = json.loads((TESTING / "known_defects.json").read_text())
        ids = {s["id"] for s in SCENARIOS}
        self.assertTrue(set(known) <= ids)


class Metrics(unittest.TestCase):
    def row(self, truth, decision, required_ok=True):
        return {"truth": truth, "decision": decision, "checks": {"required_findings": required_ok,
                "decision_acceptable": True, "proven_properties": True}, "invariants": {"gate_blocks": True}}

    def test_confusion_and_ratios_keep_unknown_and_deny_apart(self):
        rows = [self.row("GOOD", "UNKNOWN"), self.row("GOOD", "DENY"), self.row("BAD", "DENY"),
                self.row("BAD", "UNKNOWN"), self.row("UNKNOWN", "UNKNOWN"), self.row("UNKNOWN", "DENY")]
        m = rb.metrics(rows)
        self.assertEqual(m["confusion_matrix"]["BAD"]["UNKNOWN"], 1)
        self.assertEqual(m["confusion_matrix"]["UNKNOWN"]["DENY"], 1)
        s = m["summary"]
        self.assertEqual((s["false_block_rate"]["num"], s["false_block_rate"]["den"]), (1, 2))
        self.assertEqual((s["bad_denied"]["num"], s["bad_denied"]["den"]), (1, 2))
        self.assertEqual((s["bad_not_denied_but_blocked_only"]["num"], s["bad_not_denied_but_blocked_only"]["den"]), (1, 2))
        self.assertEqual((s["unknown_overclaimed_as_deny"]["num"], s["unknown_overclaimed_as_deny"]["den"]), (1, 2))
        self.assertIsNone(m["per_class"]["GOOD"]["precision"]["value"])  # 0/0 is n/a, not 0 or 1
        self.assertEqual(m["per_class"]["BAD"]["precision"]["den"], 3)  # DENY was predicted for one GOOD, one BAD and one UNKNOWN

    def test_block_only_is_not_detection(self):
        rows = [self.row("BAD", "UNKNOWN") for _ in range(3)]
        s = rb.metrics(rows)["summary"]
        self.assertEqual(s["bad_denied"]["num"], 0)
        self.assertEqual(s["signing_blocked_all_scenarios"]["num"], 3)

    def test_evaluate_flags_violated_invariants(self):
        scenario = next(x for x in SCENARIOS if x["id"] == "G-001")
        out = {"verdict": {"decision": "UNKNOWN", "findings": []},
               "signing_boundary": {"signing_gate": "block", "automated_signing_permitted": True}}
        result = rb.evaluate(scenario, {"rc": 30, "stdout_json": out, "stderr": ""}, None)
        self.assertFalse(result["invariants"]["gate_blocks"])
        self.assertEqual(result["failure_type"], "invariant_violation")
        out["signing_boundary"]["automated_signing_permitted"] = False
        out["verdict"]["total_spending_proven"] = True
        out["x"] = {"total_native_sol_spending_proven": True}
        result = rb.evaluate(scenario, {"rc": 30, "stdout_json": out, "stderr": ""}, None)
        self.assertFalse(result["invariants"]["no_spending_proof_claimed"])
        result = rb.evaluate(scenario, {"rc": 0, "stdout_json": {"verdict": {"decision": "UNKNOWN", "findings": []}},
                                        "stderr": ""}, None)
        self.assertFalse(result["invariants"]["exit_code_nonzero"])

    def test_error_is_not_a_decision(self):
        result = rb.evaluate(SCENARIOS[0], {"rc": -1, "stdout_json": None, "stderr": "boom"}, None)
        self.assertEqual((result["decision"], result["failure_type"]), ("ERROR", "error"))


class Mocks(unittest.TestCase):
    def test_cloud_rules(self):
        digest = "a" * 64
        good = cloud_mock.assessment(digest)
        self.assertEqual(cloud_mock.combine("DENY", digest, good)[0], "DENY")
        self.assertEqual(cloud_mock.combine("UNKNOWN", digest, good)[0], "UNKNOWN")
        self.assertNotEqual(cloud_mock.combine("UNKNOWN", digest, good)[0], "ALLOW")
        wrong = cloud_mock.assessment(digest, bound_to="b" * 64, finding={"severity": "critical"})
        self.assertEqual(cloud_mock.combine("UNKNOWN", digest, wrong)[0], "UNKNOWN")
        self.assertEqual(cloud_mock.combine("UNKNOWN", digest, None, cloud_required=True)[0], "UNKNOWN")
        adverse = cloud_mock.assessment(digest, finding={"severity": "critical"})
        self.assertEqual(cloud_mock.combine("UNKNOWN", digest, adverse)[0], "DENY")

    def test_rpc_mock_behaviours_are_deterministic(self):
        for behavior in ("closed_port", "non_tls_garbage", "hangup"):
            with rpc_mock.MockRpc(behavior) as mock:
                client = socket.socket()
                client.settimeout(2)
                if behavior == "closed_port":
                    with self.assertRaises(OSError):
                        client.connect(("127.0.0.1", mock.port))
                else:
                    client.connect(("127.0.0.1", mock.port))
                    client.sendall(b"x")
                    try:
                        data = client.recv(4096)
                    except OSError:  # peer reset on abrupt close (Windows): nothing was served
                        data = b""
                    self.assertEqual(bool(data), behavior == "non_tls_garbage")
                client.close()
        with self.assertRaises(ValueError):
            rpc_mock.MockRpc("real_server")


@unittest.skipIf(sys.platform == "win32", "needs an executable stub")
class RunnerIsNotVacuous(unittest.TestCase):
    """A tool that approves everything must make the benchmark fail loudly."""

    def test_always_allow_stub_fails_and_flags_unsafe(self):
        import os
        import stat
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "hguet"
            stub.write_text("#!%s\nimport json,sys\n"
                            "if '--version' in sys.argv: print('stub'); sys.exit(0)\n"
                            "print(json.dumps({'verdict':{'decision':'ALLOW','findings':[]},"
                            "'signing_boundary':{'signing_gate':'allow','automated_signing_permitted':True}}))\n"
                            "sys.exit(0)\n" % sys.executable)
            stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
            out = Path(tmp) / "out"
            done = subprocess.run([sys.executable, str(TESTING / "runner/run_benchmark.py"), "--hguet", str(stub),
                                   "--subset", "smoke", "--out", str(out), "--known-defects", str(Path(tmp) / "none")],
                                  capture_output=True, text=True)
            self.assertEqual(done.returncode, 1, done.stdout)
            report = json.loads((out / "report.json").read_text())
            types = {r["failure_type"] for r in report["results"]}
            self.assertIn("invariant_violation", types)
            self.assertEqual(report["totals"]["PASS"], 0)
            self.assertGreater(report["metrics"]["summary"]["bad_allowed_UNSAFE"]["num"], 0)
            self.assertEqual(report["metrics"]["summary"]["signing_blocked_all_scenarios"]["num"], 0)


if __name__ == "__main__":
    unittest.main()
