"""Self-tests of the Cloud Value Benchmark (no real server, no HGUET binary except a stub)."""
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

TESTING = Path(__file__).resolve().parents[1]
CV = TESTING / "cloud-value"
sys.path.insert(0, str(TESTING / "lib"))
for sub in ("server", "verify", "labeling", "tools", "protocol"):
    sys.path.insert(0, str(CV / sub))
import assessment_rules as rules  # noqa: E402
import build_cloud_value as gen  # noqa: E402
import crypto_tx as ct  # noqa: E402
import independent_labeler as labeler  # noqa: E402
import jcs  # noqa: E402
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


def payload_of(signed):
    return jcs.parse_strict(signed["canonical_payload"])


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
            # an internal VIEW of protocol fields, explicitly not a public document
            self.assertEqual(inp["cloud_request"]["format"], "cv-request-view/1")

    def test_evidence_tiers_are_separate_and_honest(self):
        tiers = {e["provenance"]["tier"] for e in EVIDENCE}
        self.assertEqual(tiers, {"historical_class", "lab_simulation", "hypothetical"})
        for e in EVIDENCE:
            self.assertFalse(e["provenance"]["instance_verified"])
            for field in ("network", "observed_at", "valid_until", "confidence"):
                self.assertIn(field, e)
            if e["provenance"]["tier"] == "lab_simulation":
                self.assertTrue(e["provenance"]["reproducible"])
        self.assertTrue(all(e["confidence"] < 0.5 for e in EVIDENCE if e["provenance"]["tier"] == "hypothetical"))

    def test_labels_are_reviewed_only_where_a_reviewer_exists(self):
        critical = [t for t in TRUTH.values() if t["labeling"]["critical"]]
        self.assertEqual(len(critical), 30)
        for t in critical:
            self.assertEqual(t["labeling"]["independent_review"]["status"], "pending_human_review")
            self.assertEqual(t["labeling"]["independent_review"]["reviewers"], [])


class Verifier(unittest.TestCase):
    def setUp(self):
        self.sid = first("tp_historical")
        self.inp = INPUTS[self.sid]
        self.req = self.inp["cloud_request"]
        self.server = rs.ReferenceCloudServer(CV / "evidence", "strict")
        self.signed = self.server.assess(self.req, NOW)

    def check(self, signed, **kw):
        return rules.verify(signed, self.req, REGISTRY, now_iso=NOW, **kw)

    def resign(self, mutate):
        body = payload_of(self.signed)
        mutate(body)
        return rs.signer().sign(body)

    def test_honest_answer_is_accepted_with_correct_attribution(self):
        v = self.check(self.signed)
        self.assertTrue(v["accepted"], v["discard_reason"])
        self.assertEqual([f["effective_enforcement"] for f in v["findings_accepted"]], ["hard_deny"])
        self.assertEqual(set(v["evidence_used"]), set(TRUTH[self.sid]["decisive_evidence"]))
        self.assertEqual(rules.combine("UNKNOWN", v), "DENY")
        self.assertIn(v["signature"]["algorithm"], ("ML-DSA-87", "TEST-ONLY-ED25519"))
        self.assertTrue(v["signature"]["test_only_key"])

    def test_signed_payload_is_the_public_protocol_shape(self):
        self.assertEqual(set(self.signed), {"canonical_payload", "signature", "key_id", "signing_algorithm"})
        self.assertIsInstance(self.signed["canonical_payload"], bytes)
        self.assertTrue(jcs.is_canonical(self.signed["canonical_payload"]))
        self.assertIn(self.signed["signing_algorithm"], ("ML-DSA-87", "TEST-ONLY-ED25519"))

    def test_every_discard_reason(self):
        flipped = dict(self.signed, signature=bytes([self.signed["signature"][0] ^ 1]) + self.signed["signature"][1:])
        self.assertEqual(self.check(flipped)["discard_reason"], "bad_signature")
        self.assertEqual(self.check(self.resign(lambda b: b.update(message_sha256="0" * 64)))["discard_reason"], "binding_mismatch")
        self.assertEqual(self.check(self.resign(lambda b: b.update(network="mainnet", genesis_hash=rs.GENESIS["mainnet"])))["discard_reason"], "network_mismatch")
        self.assertEqual(self.check(self.resign(lambda b: b.update(genesis_hash="someone-elses-cluster")))["discard_reason"], "network_mismatch")
        self.assertEqual(self.check(self.resign(lambda b: b.update(environment="production")))["discard_reason"], "environment_mismatch")
        self.assertEqual(self.check(self.resign(lambda b: b.update(data_scope="raw_transaction")))["discard_reason"], "data_scope_mismatch")
        self.assertEqual(self.check(self.resign(lambda b: b.update(expires_at="2026-10-31T00:00:00Z")))["discard_reason"], "expired_or_not_yet_valid")
        self.assertEqual(self.check(self.resign(lambda b: b.pop("quote_id")))["discard_reason"], "schema_invalid")
        self.assertEqual(self.check(self.resign(lambda b: b.update(evidence_digest="0" * 64)))["discard_reason"], "evidence_digest_mismatch")
        self.assertEqual(self.check(self.resign(lambda b: b.update(subjects_sha256="0" * 64)))["discard_reason"], "binding_mismatch")
        self.assertEqual(rules.verify(self.signed, self.req, REGISTRY, now_iso=NOW, expected_quote_id="f" * 32)["discard_reason"], "binding_mismatch")
        self.assertEqual(self.check(dict(self.signed, key_id="someone-else"))["discard_reason"], "unknown_key")
        other_alg = "TEST-ONLY-ED25519" if self.signed["signing_algorithm"] == "ML-DSA-87" else "ML-DSA-87"
        self.assertIn(self.check(dict(self.signed, signing_algorithm=other_alg))["discard_reason"],
                      ("key_algorithm_mismatch", "unsupported_signature_alg"))
        self.assertEqual(self.check(dict(self.signed, signing_algorithm="rot13"))["discard_reason"], "algorithm_not_allowed")
        self.assertEqual(self.check({"canonical_payload": b"{}"})["discard_reason"], "envelope_shape")
        self.assertEqual(self.check(None)["discard_reason"], "envelope_shape")
        self.assertEqual(rules.verify(self.signed, self.req, REGISTRY, now_iso="2031-01-01T00:00:00Z")["discard_reason"],
                         "key_not_valid_at_time")

    def test_non_canonical_payload_is_refused_even_if_validly_signed(self):
        body = self.signed["canonical_payload"].replace(b'"kind":', b'"kind" :', 1)
        self.assertNotEqual(body, self.signed["canonical_payload"])
        self.assertEqual(self.check(rs.signer().sign_bytes(body))["discard_reason"], "non_canonical_payload")

    def test_test_keys_are_never_accepted_for_the_real_server_policy(self):
        v = self.check(self.signed, require_non_test_keys=True)
        self.assertEqual(v["discard_reason"], "test_key_not_allowed")
        self.assertEqual(rules.combine("UNKNOWN", v), "UNKNOWN")

    def test_ml_dsa_without_a_backend_is_unverifiable_never_accepted(self):
        forged = dict(self.signed, signing_algorithm="ML-DSA-87", key_id="bench-issuer-mldsa87-1")
        with mock.patch.object(rules.mldsa.BACKEND, "available", return_value=False):
            v = self.check(forged)
        self.assertEqual(v["discard_reason"], "unsupported_signature_alg")
        self.assertEqual(rules.combine("UNKNOWN", v), "UNKNOWN")

    def test_unverified_assessment_never_changes_a_verdict(self):
        bad = dict(self.signed, signature=bytes(len(self.signed["signature"])))
        for local in ("UNKNOWN", "DENY", "ALLOW"):
            self.assertEqual(rules.combine(local, self.check(bad)), local)
            self.assertEqual(rules.combine(local, None), local)

    def test_finding_without_matching_evidence_is_rejected_and_never_denies(self):
        def forge(body):
            body["findings"][0]["evidence_refs"] = ["EV-9999"]
        v = self.check(self.resign(forge))
        self.assertEqual(v["findings_accepted"], [])
        self.assertEqual(v["findings_rejected"][0]["rejected_reason"], "evidence_not_listed_or_digest_mismatch")
        self.assertEqual(rules.combine("UNKNOWN", v), "UNKNOWN")

        def hash_lie(body):
            body["sources"][0]["evidence_sha256"] = "0" * 64
        self.assertEqual(self.check(self.resign(hash_lie))["discard_reason"], "evidence_digest_mismatch")

    def test_blind_trust_mode_shows_the_harm(self):
        inp = INPUTS[first("fp_stale_retracted")]
        naive = rs.ReferenceCloudServer(CV / "evidence", "naive").assess(inp["cloud_request"], NOW)
        strict_v = rules.verify(naive, inp["cloud_request"], REGISTRY, now_iso=NOW, mode="strict")
        trusting_v = rules.verify(naive, inp["cloud_request"], REGISTRY, now_iso=NOW, mode="trusting")
        self.assertEqual(rules.combine("UNKNOWN", strict_v), "UNKNOWN")
        self.assertEqual(rules.combine("UNKNOWN", trusting_v), "DENY")  # false accusation when blindly trusted
        self.assertTrue({f["rejected_reason"] for f in strict_v["findings_rejected"]} & {"expired", "superseded"})

    def test_hypothetical_evidence_can_never_accuse(self):
        inp = INPUTS[first("fp_hypothetical")]
        naive = rs.ReferenceCloudServer(CV / "evidence", "naive").assess(inp["cloud_request"], NOW)
        v = rules.verify(naive, inp["cloud_request"], REGISTRY, now_iso=NOW)
        self.assertEqual(rules.combine("UNKNOWN", v), "UNKNOWN")
        for f in v["findings_accepted"]:
            self.assertEqual(f["effective_enforcement"], "inform")

    def test_conflicting_valid_evidence_caps_at_warn(self):
        inp = INPUTS[first("conflict")]
        naive = rs.ReferenceCloudServer(CV / "evidence", "naive").assess(inp["cloud_request"], NOW)
        v = rules.verify(naive, inp["cloud_request"], REGISTRY, now_iso=NOW)
        self.assertIn(rules.combine("UNKNOWN", v), ("WARN", "UNKNOWN"))

    def test_safety_claims_never_create_allow(self):
        inp = INPUTS[first("no_evidence")]
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
        self.assertEqual(rules.combine("DENY", self.check(self.signed)), "DENY")


class Labeling(unittest.TestCase):
    def test_independent_rederivation_agrees_and_detects_disagreement(self):
        report = labeler.run()
        self.assertEqual(report["agreement"], {"agree": 100, "total": 100})
        self.assertIn("PENDING", report["human_review_status"])
        self.assertEqual(report["critical_with_human_review"], 0)
        sid = first("tp_historical")
        decisive = set(TRUTH[sid]["decisive_evidence"])
        remaining = [e for e in EVIDENCE if e["evidence_id"] not in decisive]
        self.assertEqual(labeler.derive_label(INPUTS[sid], remaining)[0], "UNKNOWN")
        self.assertEqual(labeler.derive_label(INPUTS[sid], EVIDENCE)[0], "BAD")


class BlindReview(unittest.TestCase):
    def cases(self):
        return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted((CV / "labeling/blind_review").glob("CV-*.json"))}

    def test_thirty_label_free_self_contained_cases(self):
        cases = self.cases()
        critical = sorted(sid for sid, t in TRUTH.items() if t["labeling"]["critical"])
        self.assertEqual(len(cases), 30)
        self.assertEqual(sorted(cases), critical)
        for sid, case in cases.items():
            text = json.dumps(case)
            truth = TRUTH[sid]
            for secret in (truth["canary"], truth["kind"], truth["rationale"], "acceptable_final", '"decisive_evidence":',
                           "expected_verifier_discards", "threat_present"):
                self.assertNotIn(secret, text, (sid, secret))
            self.assertIsNone(case["questions"]["confidence_0_to_1"])
            self.assertIn("verdict", case["questions"])
            subjects = {(s["type"], s["id"]) for s in case["subjects_to_assess"]}
            related = {e["evidence_id"] for e in EVIDENCE if (e["subject"]["type"], e["subject"]["id"]) in subjects}
            self.assertEqual({e["evidence_id"] for e in case["available_independent_evidence"]}, related)
        covers = {t["kind"] for sid, t in TRUTH.items() if sid in cases}
        self.assertEqual(covers, {"tp_historical", "tp_lab", "fp_stale_retracted"})

    def test_scoring_reports_agreement_and_never_edits_truth(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("score_review", CV / "labeling/score_review.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertIsNone(module.kappa([], []))
        self.assertEqual(module.kappa(["BAD", "GOOD", "BAD", "UNKNOWN"], ["BAD", "GOOD", "BAD", "UNKNOWN"]), 1.0)
        self.assertLess(module.kappa(["BAD", "GOOD", "BAD", "GOOD"], ["GOOD", "BAD", "GOOD", "BAD"]), 0)
        before = {p.name: p.read_bytes() for p in (CV / "truth").glob("CV-*.json")}
        self.assertEqual(module.main(), 0)  # no responses yet: reports PENDING, edits nothing
        self.assertEqual(before, {p.name: p.read_bytes() for p in (CV / "truth").glob("CV-*.json")})
        report = json.loads((CV / "labeling/review_results.json").read_text()) if (CV / "labeling/review_results.json").exists() else None
        if report:
            self.assertTrue(report["status"].startswith("PENDING"))


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
            self.assertEqual(report["independent_proof"]["status"], "unavailable")
            self.assertIn("hguet.proto", report["real_server"]["protocol"])
            self.assertIn("never_merged", report)
            self.assertEqual(report["local"]["source"], "measured")
            self.assertEqual(report["reference_mock"]["source"], "MODEL")
            self.assertIn(report["reference_mock"]["signature_algorithm"], ("ML-DSA-87", "TEST-ONLY-ED25519"))
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
