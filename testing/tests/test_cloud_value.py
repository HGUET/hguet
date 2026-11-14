"""Self-tests of the Cloud Value Benchmark (no real server, no HGUET binary except a stub)."""
import copy
import json
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

TESTING = Path(__file__).resolve().parents[1]
CV = TESTING / "cloud-value"
for sub in ("lib",):
    sys.path.insert(0, str(TESTING / sub))
for sub in ("server", "verify", "labeling", "tools"):
    sys.path.insert(0, str(CV / sub))
import assessment_rules as rules  # noqa: E402
import build_cloud_value as gen  # noqa: E402
import crypto_tx as ct  # noqa: E402
import independent_labeler as labeler  # noqa: E402
import real_server  # noqa: E402
import reference_server as rs  # noqa: E402

NOW = gen.NOW
INPUTS = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted((CV / "inputs").glob("CV-*.json"))}
TRUTH = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted((CV / "truth").glob("CV-*.json"))}
EVIDENCE = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((CV / "evidence").glob("EV-*.json"))]
REGISTRY = rules.Registry(EVIDENCE)


def first(kind, category="C01"):
    for sid, t in TRUTH.items():
        if t["kind"] == kind and t["category_id"] == category:
            return sid
    raise KeyError(kind)


class Dataset(unittest.TestCase):
    def test_shape(self):
        self.assertEqual((len(INPUTS), len(TRUTH)), (100, 100))
        cats, kinds = {}, {}
        for t in TRUTH.values():
            cats[t["category_id"]] = cats.get(t["category_id"], 0) + 1
            kinds[t["kind"]] = kinds.get(t["kind"], 0) + 1
        self.assertEqual(set(cats.values()), {10})
        self.assertEqual(len(cats), 10)
        self.assertEqual(set(kinds.values()), {10})

    def test_generator_matches_committed_files(self):
        self.assertEqual(subprocess.run([sys.executable, str(CV / "tools/build_cloud_value.py"), "--check"],
                                        capture_output=True, text=True).returncode, 0)

    def test_no_ground_truth_reaches_component_visible_data(self):
        visible = json.dumps(INPUTS, sort_keys=True) + json.dumps(EVIDENCE, sort_keys=True)
        for t in TRUTH.values():
            self.assertNotIn(t["canary"], visible)
        for needle in ('"truth"', '"acceptable_final"', '"decisive_evidence"', '"threat_present"', '"label"'):
            self.assertNotIn(needle, visible)
        for inp in INPUTS.values():
            self.assertEqual(set(inp), {"format", "id", "network", "clock", "transaction", "intent", "trusted_key",
                                        "policy_toml", "rpc", "cloud_request", "cloud_harness"})
            self.assertEqual(set(inp["cloud_request"]), {"format", "network", "data_scope", "profile", "message_sha256",
                                                         "transaction_sha256", "intent_sha256", "subjects"})
            self.assertEqual(inp["cloud_request"]["data_scope"], "metadata_only")

    def test_evidence_tiers_are_separate_and_honest(self):
        tiers = {e["provenance"]["tier"] for e in EVIDENCE}
        self.assertEqual(tiers, {"historical_class", "lab_simulation", "hypothetical"})
        for e in EVIDENCE:
            self.assertFalse(e["provenance"]["instance_verified"])
            for field in ("network", "observed_at", "valid_until", "confidence"):
                self.assertIn(field, e)
            self.assertIn(e["provenance"]["source"], {e["provenance"]["source"]})
            if e["provenance"]["tier"] == "lab_simulation":
                self.assertTrue(e["provenance"]["reproducible"])
        self.assertTrue(all(e["confidence"] < 0.5 for e in EVIDENCE if e["provenance"]["tier"] == "hypothetical"))

    def test_labels_are_reviewed_only_where_a_reviewer_exists(self):
        critical = [t for t in TRUTH.values() if t["labeling"]["critical"]]
        self.assertEqual(len(critical), 30)
        for t in critical:
            self.assertEqual(t["labeling"]["independent_review"]["status"], "pending_human_review")
            self.assertEqual(t["labeling"]["independent_review"]["reviewers"], [])
        packet = json.loads((CV / "labeling/review_packet.json").read_text())
        self.assertEqual(len(packet["cases"]), 30)
        for case in packet["cases"]:
            self.assertNotIn("label", case)  # the reviewer must not see the answer


class Verifier(unittest.TestCase):
    def setUp(self):
        self.sid = first("tp_historical")
        self.inp = INPUTS[self.sid]
        self.req = self.inp["cloud_request"]
        self.server = rs.ReferenceCloudServer(CV / "evidence", "strict")
        self.env = self.server.assess(self.req, NOW)

    def check(self, envelope, **kw):
        return rules.verify(envelope, self.req, REGISTRY, now_iso=NOW, **kw)

    def resign(self, mutate):
        body = copy.deepcopy(self.env["assessment"])
        mutate(body)
        return rs.sign_envelope(body)

    def test_honest_answer_is_accepted_with_correct_attribution(self):
        v = self.check(self.env)
        self.assertTrue(v["accepted"])
        self.assertEqual([f["effective_enforcement"] for f in v["findings_accepted"]], ["hard_deny"])
        self.assertEqual(set(v["evidence_used"]), set(TRUTH[self.sid]["decisive_evidence"]))
        self.assertEqual(rules.combine("UNKNOWN", v), "DENY")

    def test_every_discard_reason(self):
        bad_sig = copy.deepcopy(self.env)
        bad_sig["signature"]["sig_b58"] = ct.b58encode(bytes(64))
        self.assertEqual(self.check(bad_sig)["discard_reason"], "bad_signature")
        self.assertEqual(self.check(self.resign(lambda b: b.update(message_sha256="0" * 64)))["discard_reason"], "binding_mismatch")
        self.assertEqual(self.check(self.resign(lambda b: b.update(network="mainnet", genesis_hash=rs.GENESIS["mainnet"])))["discard_reason"], "network_mismatch")
        self.assertEqual(self.check(self.resign(lambda b: b.update(expires_at="2026-10-31T00:00:00Z")))["discard_reason"], "expired_or_not_yet_valid")
        self.assertEqual(self.check(self.resign(lambda b: b.pop("quote_id")))["discard_reason"], "schema_invalid")
        wrong_key = copy.deepcopy(self.env)
        wrong_key["signature"]["key_id"] = "someone-else"
        self.assertEqual(self.check(wrong_key)["discard_reason"], "unpinned_key")
        pq = copy.deepcopy(self.env)
        pq["signature"]["alg"] = "ml-dsa-87"
        self.assertEqual(self.check(pq)["discard_reason"], "unsupported_signature_alg")  # recognised, not verifiable here
        unknown = copy.deepcopy(self.env)
        unknown["signature"]["alg"] = "rot13"
        self.assertEqual(self.check(unknown)["discard_reason"], "unknown_signature_alg")
        self.assertEqual(self.check({"assessment": {}})["discard_reason"], "envelope_shape")
        self.assertEqual(self.check(None)["discard_reason"], "envelope_shape")

    def test_finding_without_matching_evidence_is_rejected_and_never_denies(self):
        def forge(body):
            body["findings"][0]["evidence_refs"] = ["EV-9999"]
        v = self.check(self.resign(forge))
        self.assertEqual(v["findings_accepted"], [])
        self.assertEqual(v["findings_rejected"][0]["rejected_reason"], "evidence_not_listed_or_digest_mismatch")
        self.assertEqual(rules.combine("UNKNOWN", v), "UNKNOWN")

        def hash_lie(body):
            body["sources"][0]["evidence_sha256"] = "0" * 64
        self.assertEqual(self.check(self.resign(hash_lie))["findings_accepted"], [])

    def test_blind_trust_mode_shows_the_harm(self):
        sid = first("fp_stale_retracted")
        inp = INPUTS[sid]
        naive = rs.ReferenceCloudServer(CV / "evidence", "naive").assess(inp["cloud_request"], NOW)
        strict_v = rules.verify(naive, inp["cloud_request"], REGISTRY, now_iso=NOW, mode="strict")
        trusting_v = rules.verify(naive, inp["cloud_request"], REGISTRY, now_iso=NOW, mode="trusting")
        self.assertEqual(rules.combine("UNKNOWN", strict_v), "UNKNOWN")
        self.assertEqual(rules.combine("UNKNOWN", trusting_v), "DENY")  # false accusation when blindly trusted
        reasons = {f["rejected_reason"] for f in strict_v["findings_rejected"]}
        self.assertTrue(reasons & {"expired", "superseded"})

    def test_hypothetical_evidence_can_never_accuse(self):
        sid = first("fp_hypothetical")
        inp = INPUTS[sid]
        naive = rs.ReferenceCloudServer(CV / "evidence", "naive").assess(inp["cloud_request"], NOW)
        v = rules.verify(naive, inp["cloud_request"], REGISTRY, now_iso=NOW)
        self.assertEqual(rules.combine("UNKNOWN", v), "UNKNOWN")
        for f in v["findings_accepted"]:
            self.assertEqual(f["effective_enforcement"], "inform")

    def test_conflicting_valid_evidence_caps_at_warn(self):
        sid = first("conflict")
        inp = INPUTS[sid]
        naive = rs.ReferenceCloudServer(CV / "evidence", "naive").assess(inp["cloud_request"], NOW)
        v = rules.verify(naive, inp["cloud_request"], REGISTRY, now_iso=NOW)
        self.assertIn(rules.combine("UNKNOWN", v), ("WARN", "UNKNOWN"))
        self.assertNotEqual(rules.combine("UNKNOWN", v), "DENY")

    def test_safety_claims_never_create_allow(self):
        sid = first("no_evidence")
        inp = INPUTS[sid]
        env = rs.ReferenceCloudServer(CV / "evidence", "oversell").assess(inp["cloud_request"], NOW)
        strict = rules.verify(env, inp["cloud_request"], REGISTRY, now_iso=NOW)
        trusting = rules.verify(env, inp["cloud_request"], REGISTRY, now_iso=NOW, mode="trusting")
        self.assertEqual(len(strict["unsupported_safety_claims"]), 1)
        self.assertEqual(len(trusting["trusted_unverified_safety_claims"]), 1)
        for v in (strict, trusting):
            self.assertEqual(rules.combine("UNKNOWN", v), "UNKNOWN")  # never ALLOW
        self.assertEqual(rules.combine("DENY", strict), "DENY")

    def test_local_deny_is_never_lowered(self):
        self.assertEqual(rules.combine("DENY", None), "DENY")
        self.assertEqual(rules.combine("DENY", self.check(self.env)), "DENY")


class RealServerInterface(unittest.TestCase):
    def test_default_is_unavailable_and_sends_nothing(self):
        adapter = real_server.RealServerAdapter()
        self.assertIn("not enabled", adapter.unavailable_reason())
        self.assertIsNone(adapter.assess(INPUTS["CV-001"]["cloud_request"], NOW))
        self.assertEqual((adapter.requests_sent, adapter.bytes_sent), (0, 0))
        self.assertIn("no real server URL", real_server.RealServerAdapter(enabled=True).unavailable_reason())
        self.assertIn("https", real_server.RealServerAdapter("http://example.org", True).unavailable_reason())

    def test_request_must_stay_metadata_only(self):
        adapter = real_server.RealServerAdapter("https://example.invalid", True)
        leaky = dict(INPUTS["CV-001"]["cloud_request"], raw_transaction="AAAA")
        with self.assertRaises(ValueError):
            adapter.assess(leaky, NOW)
        wrong_scope = dict(INPUTS["CV-001"]["cloud_request"], data_scope="raw_transaction")
        with self.assertRaises(ValueError):
            adapter.assess(wrong_scope, NOW)
        self.assertEqual(adapter.requests_sent, 0)

    def test_wire_conformance_against_a_local_stub_not_a_real_server(self):
        """Proves the plumbing (POST path, bounded read, verification). It measures NOTHING about a real server."""
        server = rs.ReferenceCloudServer(CV / "evidence", "strict")

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                assert set(body) <= real_server.ALLOWED_REQUEST_FIELDS
                payload = json.dumps(server.assess(body, NOW)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        httpd = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            adapter = real_server.RealServerAdapter("http://127.0.0.1:%d" % httpd.server_port, True,
                                                    allow_insecure_loopback=True, timeout=5)
            request = INPUTS[first("tp_historical")]["cloud_request"]
            envelope = adapter.assess(request, NOW)
            self.assertIsNotNone(envelope)
            self.assertTrue(rules.verify(envelope, request, REGISTRY, now_iso=NOW)["accepted"])
            self.assertEqual(adapter.requests_sent, 1)
            self.assertEqual(adapter.fields_sent, set(request))
        finally:
            httpd.shutdown()

    def test_unreachable_server_degrades_to_unavailable(self):
        adapter = real_server.RealServerAdapter("http://127.0.0.1:9", True, allow_insecure_loopback=True, timeout=1)
        self.assertIsNone(adapter.assess(INPUTS["CV-001"]["cloud_request"], NOW))


class Labeling(unittest.TestCase):
    def test_independent_rederivation_agrees_and_detects_disagreement(self):
        report = labeler.run()
        self.assertEqual(report["agreement"], {"agree": 100, "total": 100})
        self.assertIn("PENDING", report["human_review_status"])
        self.assertEqual(report["critical_with_human_review"], 0)
        # delete the decisive adverse evidence of one BAD scenario: the derivation must now disagree
        sid = first("tp_historical")
        decisive = set(TRUTH[sid]["decisive_evidence"])
        remaining = [e for e in EVIDENCE if e["evidence_id"] not in decisive]
        self.assertEqual(labeler.derive_label(INPUTS[sid], remaining)[0], "UNKNOWN")
        self.assertEqual(labeler.derive_label(INPUTS[sid], EVIDENCE)[0], "BAD")


@unittest.skipIf(sys.platform == "win32", "needs an executable stub")
class RunnerWithStub(unittest.TestCase):
    def test_report_keeps_sources_separate_and_real_server_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            stub = Path(tmp) / "hguet"
            nl = chr(92) + "n"
            stub.write_text("#!%s%simport json,sys%s"
                            "print(json.dumps({'verdict':{'decision':'UNKNOWN','findings':[]}}))%ssys.exit(30)%s"
                            % (sys.executable, nl, nl, nl, nl))
            stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
            out = Path(tmp) / "out"
            done = subprocess.run([sys.executable, str(CV / "runner/run_cloud_value.py"), "--hguet", str(stub), "--out", str(out)],
                                  capture_output=True, text=True)
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            report = json.loads((out / "report.json").read_text())
            self.assertEqual(report["real_server"]["status"], "unavailable")
            self.assertNotIn("metrics", report["real_server"])
            self.assertIn("never_merged", report)
            self.assertEqual(report["local"]["source"], "measured")
            self.assertEqual(report["reference_mock"]["source"], "MODEL")
            strict = report["reference_mock"]["metrics"]["strict/strict-client"]
            # the stub answers UNKNOWN even for the 10 local_covers cases, so all 30 BAD non-tamper cases have room
            self.assertEqual(strict["additional_true_positive"]["den"], 30)
            self.assertEqual(strict["allow_created"]["num"], 0)
            naive_trusting = report["reference_mock"]["metrics"]["naive/trusting-client"]
            self.assertGreater(naive_trusting["additional_false_positive"]["num"], 0)
            silent = report["reference_mock"]["metrics"]["silent/strict-client"]
            self.assertEqual(silent["availability"]["num"], 0)
            html = (out / "report.html").read_text()
            for needle in ("MEASURED - Local", "MODEL - Reference Mock", "Real HGUET Server: UNAVAILABLE", "synthetic"):
                self.assertIn(needle, html)


if __name__ == "__main__":
    unittest.main()
