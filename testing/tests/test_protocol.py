"""Protocol interoperability tests: codec derived from hguet.proto, JCS, ML-DSA-87 KATs, TLS flow harness."""
import hashlib
import json
import os
import ssl
import sys
import unittest
from pathlib import Path
from unittest import mock

TESTING = Path(__file__).resolve().parents[1]
CV = TESTING / "cloud-value"
sys.path.insert(0, str(TESTING / "lib"))
for sub in ("server", "verify", "protocol", "testserver"):
    sys.path.insert(0, str(CV / sub))
import assessment_rules as rules  # noqa: E402
import jcs  # noqa: E402
import mldsa  # noqa: E402
import proto_codec as pc  # noqa: E402
import protocol_client as client  # noqa: E402
import reference_server as rs  # noqa: E402
import tls_fixture  # noqa: E402
from common import (GENESIS, ProfileError, b58encode, build_client_evidence, canonical_memo,  # noqa: E402
                    canonical_solana_signature, validate_client_evidence)
from trust import TrustStore  # noqa: E402

NOW = "2026-11-01T00:00:00Z"
SIG1 = b58encode(bytes([1]) * 64)  # canonical Solana signature shape (64 bytes, Base58)
SIG2 = b58encode(bytes([2]) * 64)


def sig(label):
    """A deterministic, canonical-shaped synthetic Solana signature for a test payment label."""
    return b58encode(hashlib.sha256(label.encode()).digest() * 2)
INPUTS = {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted((CV / "inputs").glob("CV-*.json"))}
EVIDENCE = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((CV / "evidence").glob("EV-*.json"))]
REGISTRY = rules.Registry(EVIDENCE)
REQUIRE_PQ = os.environ.get("HGUET_REQUIRE_PQ") == "1"


class Codec(unittest.TestCase):
    def test_official_encoding_guide_vectors(self):
        # protobuf encoding guide: varint 150 -> 96 01 ; string "testing" ; packed repeated 3,270,86942
        self.assertEqual(pc.encode("ClientHello", {"max_minor": 150}), bytes.fromhex("109601"))
        self.assertEqual(pc.encode("ClientHello", {"cli_release": "testing"}), bytes.fromhex("2207") + b"testing")
        packed = bytes.fromhex("0a06038e029ea705")
        self.assertEqual(pc.encode("ClientHello", {"supported_majors": [3, 270, 86942]}), packed)
        self.assertEqual(pc.decode("ClientHello", packed), {"supported_majors": [3, 270, 86942]})

    def test_schema_is_derived_from_the_public_proto(self):
        text = pc.PROTO_PATH.read_text(encoding="utf-8")
        self.assertTrue(str(pc.PROTO_PATH).replace("\\", "/").endswith("protocol/v1/hguet.proto"))
        for name in ("Envelope", "PriceQuoteRequest", "PaidCheckRequest", "CheckResult", "SignedPayload", "ProtocolError"):
            self.assertIn(name, pc.SCHEMA["messages"])
            self.assertIn("message " + name, text)
        self.assertEqual(sorted(pc.SCHEMA["messages"]["Envelope"]["oneofs"]["payload"]),
                         sorted(["client_hello", "server_hello", "price_quote_request", "price_quote_result",
                                 "paid_check_request", "check_receipt", "paid_check_status", "check_result", "error"]))
        self.assertEqual(pc.SCHEMA["messages"]["PriceQuoteRequest"]["fields"][11]["name"], "subjects_sha256")

    def test_round_trip_of_every_flow_message(self):
        messages = {
            "ClientHello": {"supported_majors": [1], "max_minor": 0, "requested_capabilities": ["a", "b"], "cli_release": "x"},
            "ServerHello": {"selected_major": 1, "selected_minor": 0, "available_capabilities": ["a"], "server_release": "s"},
            "PriceQuoteRequest": {"network": "devnet", "genesis_hash": "g", "message_sha256": bytes(32), "profile": "strict",
                                  "scope": "DATA_SCOPE_METADATA_ONLY", "claim_secret_sha256": bytes(range(32)),
                                  "maximum_lamports": "100", "subjects": [{"category": "program", "network": "devnet", "subject_id": "P"}],
                                  "subjects_sha256": bytes(32), "complexity": {"risk_subjects": 1, "verified_from_raw_transaction": True}},
            "PaidCheckRequest": {"quote_id": bytes(16), "claim_secret": bytes(32), "payment_transaction_signature": "sig",
                                 "evidence": {"canonical_local_evidence_json": b"{}", "subjects": [], "local_decision": "UNKNOWN"}},
            "CheckResult": {"result": "RESULT_COMPLETED", "quote_id": bytes(16),
                            "signed_cloud_assessment": {"canonical_payload": b"{}", "signature": b"s", "key_id": "k", "signing_algorithm": "ML-DSA-87"}},
            "ProtocolError": {"code": "ERROR_CLAIM_AUTH_FAILED", "safe_message": "m", "retryable": True, "retry_after_seconds": 3},
        }
        for name, value in messages.items():
            decoded = pc.decode(name, pc.encode(name, value))
            self.assert_wire_equal(value, decoded, name)

    def assert_wire_equal(self, expected, got, where):
        """proto3 omits scalar defaults and empty repeated fields; everything else must survive exactly."""
        if isinstance(expected, dict):
            for key, value in expected.items():
                self.assert_wire_equal(value, got.get(key), "%s.%s" % (where, key))
        elif isinstance(expected, list):
            self.assertEqual(len(expected), len(got or []), where)
            for index, (e, g) in enumerate(zip(expected, got or [])):
                self.assert_wire_equal(e, g, "%s[%d]" % (where, index))
        elif expected in (0, "", b"", False) and got is None:
            return
        else:
            self.assertEqual(got, expected, where)

    def test_strict_decoding(self):
        with self.assertRaises(pc.ProtoError):
            pc.decode("ClientHello", bytes.fromhex("3801"))  # unknown field: protocol says refuse, never skip
        with self.assertRaises(pc.ProtoError):
            pc.decode("ClientHello", bytes.fromhex("2207") + b"abc")  # truncated string
        with self.assertRaises(pc.ProtoError):
            pc.decode("ClientHello", bytes.fromhex("08"))  # truncated varint tag payload
        with self.assertRaises(pc.ProtoError):
            pc.decode("ProtocolError", bytes.fromhex("0809"))  # enum value 9 is valid, 99 below is not
            pc.decode("ProtocolError", bytes.fromhex("0863"))
        envelope = {"protocol_major": 1, "request_id": bytes(16), "client_hello": {"max_minor": 0},
                    "server_hello": {"selected_major": 1}}
        with self.assertRaises(pc.ProtoError):
            pc.encode("Envelope", envelope)  # two oneof members
        with self.assertRaises(pc.ProtoError):
            pc.new_envelope("client_hello", {}, b"short")

    def test_framing(self):
        framed = pc.frame(b"abc")
        self.assertEqual(framed, b"\x00\x00\x00\x03abc")
        data = iter([framed[:4], framed[4:]])
        self.assertEqual(pc.read_frame(lambda n: next(data)), b"abc")
        with self.assertRaises(pc.ProtoError):
            pc.frame(bytes((1 << 20) + 1))
        with self.assertRaises(pc.ProtoError):
            pc.read_frame(lambda n: (1 << 20 + 1).to_bytes(4, "big")[:n] if False else b"\xff\xff\xff\xff")
        with self.assertRaises(pc.ProtoError):
            pc.read_frame(lambda n: b"\x00\x00\x00\x00")  # zero-length frame is invalid


S7_VECTORS = json.loads((CV / "protocol" / "s7-client-vectors.json").read_text(encoding="utf-8"))["cases"]


class S7Vectors(unittest.TestCase):
    """The client's own implementations reproduce the server's S7.1 golden vectors (same outcome, same error code)."""

    def cases(self, algo):
        found = [c for c in S7_VECTORS if c["algo"] == algo]
        self.assertTrue(any(c["expect"]["ok"] for c in found) and any(not c["expect"]["ok"] for c in found), algo)
        return found

    def test_proto_policy(self):
        for case in self.cases("proto_policy"):
            try:
                pc.decode("Envelope", bytes.fromhex(case["input"]["envelope_hex"]))
                got = {"ok": True}
            except pc.ProtoError as error:
                got = {"ok": False, "error": error.code}
            self.assertEqual(got, case["expect"], case["id"])

    def test_client_evidence(self):
        for case in self.cases("client_evidence"):
            data, decision = bytes.fromhex(case["input"]["bytes_hex"]), case["input"]["local_decision"]
            try:
                got = {"ok": True, "result": validate_client_evidence(data, decision)}
            except ProfileError as error:
                got = {"ok": False, "error": error.code}
            self.assertEqual(got, case["expect"], case["id"])

    def test_signature_and_memo_helpers(self):
        for case in self.cases("solana_signature"):
            self.assertEqual(canonical_solana_signature(case["input"]["signature"]), case["expect"]["ok"], case["id"])
        for case in self.cases("memo_reference"):
            self.assertEqual(canonical_memo(case["input"]["quote_id"]) is not None, case["expect"]["ok"], case["id"])

    def test_builder_output_is_always_valid_and_minimal(self):
        data = build_client_evidence("WARN", ["Z_CODE", "A_CODE"], ["rpc_agreement", "alt"])
        self.assertEqual(validate_client_evidence(data, "WARN"), "OK")
        self.assertEqual(data, b'{"coverage":["alt","rpc_agreement"],"finding_codes":["A_CODE","Z_CODE"],"kind":"hguet_client_evidence","local_decision":"WARN","schema_version":1}')
        self.assertEqual(validate_client_evidence(b"", "ALLOW"), "ABSENT")


class Jcs(unittest.TestCase):
    def test_canonical_form(self):
        self.assertEqual(jcs.canonicalize({"b": 2, "a": [True, None, "x\u0007"], "€": 1}),
                         b'{"a":[true,null,"x\\u0007"],"b":2,"\xe2\x82\xac":1}')
        # UTF-16 code-unit ordering: U+FFFF sorts after U+10000 (surrogates D800..) in JCS
        self.assertEqual(list(json.loads(jcs.canonicalize({"￿": 1, "\U00010000": 2}))), ["\U00010000", "￿"])
        self.assertTrue(jcs.is_canonical(b'{"a":1}'))
        self.assertFalse(jcs.is_canonical(b'{"a": 1}'))
        self.assertFalse(jcs.is_canonical(b'{"b":1,"a":2}'))

    def test_hostile_inputs(self):
        with self.assertRaises(jcs.JcsError):
            jcs.parse_strict(b'{"a":1,"a":2}')
        with self.assertRaises(jcs.JcsError):
            jcs.parse_strict(b'{"a":1.5}')
        with self.assertRaises(jcs.JcsError):
            jcs.canonicalize({"a": 1 << 60})
        with self.assertRaises(jcs.JcsError):
            jcs.canonicalize({"a": float("nan")})
        with self.assertRaises(jcs.JcsError):
            jcs.canonicalize({"a": 1e-9})


class MlDsa87(unittest.TestCase):
    def setUp(self):
        if not mldsa.BACKEND.available():
            if REQUIRE_PQ:
                self.fail("HGUET_REQUIRE_PQ=1 but no ML-DSA-87 backend: " + mldsa.BACKEND.reason)
            self.skipTest("ML-DSA-87 backend unavailable (%s): UNVERIFIED here, not passed" % mldsa.BACKEND.reason)

    def test_nist_acvp_known_answers(self):
        passed, total, failures = mldsa.run_known_answer_tests()
        self.assertEqual((passed, total, failures), (15, 15, []))
        data = json.loads(mldsa.VECTORS.read_text())
        self.assertEqual(sum(t["testPassed"] for t in data["tests"]), 3)  # 3 valid, 12 must be rejected
        self.assertIn("NIST ACVP", data["provenance"]["source"])

    def test_every_bit_of_input_matters(self):
        pem, pk = mldsa.BACKEND.test_keypair("kat-roundtrip")
        message = b"HGUET"
        sig = mldsa.BACKEND.test_sign(pem, message)
        self.assertTrue(mldsa.BACKEND.verify(pk, message, sig))
        self.assertFalse(mldsa.BACKEND.verify(pk, message + b"!", sig))
        self.assertFalse(mldsa.BACKEND.verify(pk, message, bytes([sig[0] ^ 1]) + sig[1:]))
        self.assertFalse(mldsa.BACKEND.verify(bytes([pk[0] ^ 1]) + pk[1:], message, sig))
        self.assertFalse(mldsa.BACKEND.verify(pk, message, sig, context=b"ctx"))  # context is bound
        self.assertFalse(mldsa.BACKEND.verify(pk, message, sig[:-1]))
        self.assertFalse(mldsa.BACKEND.verify(pk[:-1], message, sig))

    def test_committed_test_issuer_key_matches_its_derivation(self):
        import base64
        _, pk = mldsa.BACKEND.test_keypair("cloud-issuer-1")
        entry = TrustStore.test_issuers().keys["bench-issuer-mldsa87-1"]
        self.assertEqual(base64.b64decode(entry["public_key_b64"]), pk)
        self.assertTrue(entry["test_only"])


class Adapter(unittest.TestCase):
    def test_default_is_unavailable_and_says_why(self):
        adapter = client.RealServerAdapter()
        self.assertIn("not enabled", adapter.unavailable_reason())
        self.assertIsNone(adapter.assess(INPUTS["CV-001"]["cloud_request"], NOW))
        self.assertEqual((adapter.requests_sent, adapter.bytes_sent), (0, 0))
        self.assertIn("no real server host", client.RealServerAdapter(enabled=True).unavailable_reason())

    def test_real_server_stays_unavailable_without_a_pinned_issuer_key(self):
        adapter = client.RealServerAdapter("hguet.example.invalid", enabled=True)
        self.assertFalse((CV / "verify/trust/real_issuers.json").exists())
        self.assertIn("no pinned HGUET issuer key", adapter.unavailable_reason())

    def test_real_server_stays_unavailable_when_pq_group_cannot_be_enforced(self):
        stand_in = TrustStore.test_issuers()
        adapter = client.RealServerAdapter("hguet.example.invalid", enabled=True, trust=stand_in)
        with mock.patch.object(client.mldsa.BACKEND, "available", return_value=True), \
                mock.patch.object(client, "pq_group_enforceable", return_value=False):
            self.assertIn("SecP384r1MLKEM1024", adapter.unavailable_reason())
        with mock.patch.object(client.mldsa.BACKEND, "available", return_value=False):
            self.assertIn("ML-DSA-87 cannot be verified", adapter.unavailable_reason())

    def test_tls_context_cannot_be_weakened(self):
        context = client.make_tls_context()
        self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.minimum_version, ssl.TLSVersion.TLSv1_3)
        source = (CV / "server/protocol_client.py").read_text(encoding="utf-8")
        for forbidden in ("CERT_NONE", "check_hostname = False", "_create_unverified_context", "verify=False"):
            self.assertNotIn(forbidden, source)

    def test_no_second_public_protocol_exists(self):
        self.assertFalse((CV / "server/real_server.py").exists())
        text = "".join(p.read_text(encoding="utf-8") for p in (CV / "server").glob("*.py"))
        self.assertNotIn("/v1/assessments", text)
        self.assertNotIn("urllib.request", text)

    def test_subject_types_outside_the_public_vocabulary_are_not_sent(self):
        with self.assertRaises(client.ProtocolFailure) as caught:
            client.subject_messages([{"type": "alt_table", "id": "T"}], "devnet")
        self.assertEqual(caught.exception.reason, "subject_not_expressible_in_public_protocol")
        self.assertEqual(client.subject_messages([{"type": "account", "id": "A"}], "devnet")[0]["category"], "destination")


@unittest.skipUnless(tls_fixture.available(), "openssl CLI needed to build a throw-away test CA")
class TlsFlow(unittest.TestCase):
    """Conformance of the adapter against a harness that speaks the PUBLIC protocol. Not a real server."""

    @classmethod
    def setUpClass(cls):
        import protocol_test_server as pts
        cls.pts = pts
        cls.pki = tls_fixture.TestPki()
        cls.request = INPUTS["CV-001"]["cloud_request"]

    @classmethod
    def tearDownClass(cls):
        cls.pki.cleanup()

    def setUp(self):
        self.server = self.pts.ProtocolTestServer(CV / "evidence", *self.pki.server, clock_iso=NOW).start()
        self.adapter = self.adapter_for(self.server)

    def tearDown(self):
        self.server.stop()

    def adapter_for(self, server, **kw):
        adapter = client.RealServerAdapter("localhost", server.port, enabled=True, ca_file=self.pki.ca,
                                           conformance_test_classical_tls=True, test_trust_store=TrustStore.test_issuers(),
                                           genesis_map=GENESIS, timeout=5, **kw)
        adapter.registry = REGISTRY
        return adapter

    def test_full_paid_flow_verifies_and_binds_everything(self):
        quote, secret = self.adapter.request_quote(self.request, NOW)
        self.assertEqual(quote["environment"], "sandbox")
        self.assertEqual(quote["network"], self.request["network"])
        self.server.register_synthetic_payment(SIG1, int(quote["lamports_due"]))
        bundle = self.adapter.paid_check(self.request, quote, secret, SIG1, NOW)
        verification, receipt = bundle["verification"], bundle["receipt"]
        self.assertTrue(verification["accepted"], verification["discard_reason"])
        self.assertEqual(rules.combine("UNKNOWN", verification), "DENY")
        self.assertEqual(receipt["quote_id"], quote["quote_id"])
        self.assertEqual(receipt["analysis_state"], "completed")
        self.assertEqual(self.server.wire_log[:2], ["client_hello", "price_quote_request"])
        self.assertIn("paid_check_request", self.server.wire_log)
        self.assertEqual(set(self.server.tls_versions), {"TLSv1.3"})

    def test_payment_signatures_must_be_canonical_before_anything_is_sent(self):
        quote, secret = self.adapter.request_quote(self.request, NOW)
        sent = list(self.server.wire_log)
        for bad in ("SYNTHETIC-DEVNET-PAYMENT-1", "", "1" * 64, SIG1[:-1], SIG1.replace(SIG1[3], "0", 1)):
            with self.assertRaises(client.ProtocolFailure) as caught:
                self.adapter.paid_check(self.request, quote, secret, bad, NOW)
            self.assertEqual(caught.exception.reason, "payment_signature_not_canonical", bad)
        self.assertEqual(self.server.wire_log, sent, "nothing may be sent for a malformed signature")

    def test_server_rejects_capabilities_outside_the_registry_and_client_sends_registry_ids(self):
        quote, _ = self.adapter.request_quote(self.request, NOW)
        self.assertEqual(quote["requested_capabilities"], ["network_health"])
        with self.assertRaises(client.ProtocolFailure):
            session = self.adapter._session()
            try:
                self.adapter._handshake(session)
                name, body = session.exchange("price_quote_request", dict(
                    client.build_quote_request(self.request, bytes(32), 10 ** 9, GENESIS),
                    requested_capabilities=["subject_reputation_lookup"]))
                if name == "protocol_error":
                    raise client.ProtocolFailure("rejected", body.get("code", ""))
            finally:
                session.close()

    def test_memo_and_signature_helpers_follow_the_s7_1_rules(self):
        self.assertEqual(canonical_memo("a" * 32), "HGUET:" + "a" * 32)
        for bad in ("a" * 31, "A" * 32, "a" * 33, "", "g" * 32, "quote-123"):
            self.assertIsNone(canonical_memo(bad))
        self.assertTrue(canonical_solana_signature(SIG1))
        for bad in ("", "0" + SIG1[1:], SIG1[:-1], "1" * 64, "é" + SIG1, None, 5):
            self.assertFalse(canonical_solana_signature(bad), repr(bad))

    def test_paid_check_sends_only_the_redacted_client_evidence_profile(self):
        sent = []
        original = client.ProtocolSession.exchange

        def spy(session, name, body):
            if name == "paid_check_request":
                sent.append(body["evidence"])
            return original(session, name, body)

        quote, secret = self.adapter.request_quote(self.request, NOW)
        self.server.register_synthetic_payment(SIG1, int(quote["lamports_due"]))
        with mock.patch.object(client.ProtocolSession, "exchange", spy):
            self.adapter.paid_check(self.request, quote, secret, SIG1, NOW)
        self.assertEqual(len(sent), 1)
        self.assertEqual(validate_client_evidence(sent[0]["canonical_local_evidence_json"], sent[0]["local_decision"]), "OK")

    def test_without_an_external_payment_there_is_no_answer(self):
        self.assertIsNone(self.adapter.assess(self.request, NOW))
        self.assertNotIn("paid_check_request", self.server.wire_log)
        self.assertEqual(self.adapter.events[-1]["state"], "awaiting_external_payment")

    def test_assess_with_a_registered_payment_returns_a_verified_bundle(self):
        quote, secret = self.adapter.request_quote(self.request, NOW)
        self.server.register_synthetic_payment(SIG2, int(quote["lamports_due"]))
        self.adapter.payments = {self.request["message_sha256"]: {"payment_signature": SIG2,
                                                                  "claim_secret_hex": secret.hex()}}
        bundle = self.adapter.assess(self.request, NOW)
        self.assertIsNotNone(bundle)
        self.assertTrue(bundle["verification"]["accepted"])

    def failure(self, action):
        with self.assertRaises(client.ProtocolFailure) as caught:
            action()
        return caught.exception.reason

    def test_protocol_prescribed_rejections(self):
        quote, secret = self.adapter.request_quote(self.request, NOW)
        # claim secret is mandatory
        self.server.register_synthetic_payment(sig("P-A"), int(quote["lamports_due"]))
        self.assertEqual(self.failure(lambda: self.adapter.paid_check(self.request, quote, os.urandom(32), sig("P-A"), NOW)),
                         "server_error:ERROR_CLAIM_AUTH_FAILED")
        # an unknown / underpaid / unfinalised payment is refused
        self.assertEqual(self.failure(lambda: self.adapter.paid_check(self.request, quote, secret, sig("NOT-REGISTERED"), NOW)),
                         "server_error:ERROR_INVALID_PAYMENT")
        self.server.register_synthetic_payment(sig("P-LOW"), 1)
        self.assertEqual(self.failure(lambda: self.adapter.paid_check(self.request, quote, secret, sig("P-LOW"), NOW)),
                         "server_error:ERROR_INVALID_PAYMENT")
        self.server.register_synthetic_payment(sig("P-PENDING"), int(quote["lamports_due"]), finalized=False)
        self.assertEqual(self.failure(lambda: self.adapter.paid_check(self.request, quote, secret, sig("P-PENDING"), NOW)),
                         "server_error:ERROR_PAYMENT_NOT_FINALIZED")
        # one payment, one claim
        bundle = self.adapter.paid_check(self.request, quote, secret, sig("P-A"), NOW)
        self.assertTrue(bundle["verification"]["accepted"])
        other = INPUTS["CV-002"]["cloud_request"]
        other_quote, other_secret = self.adapter.request_quote(other, NOW)
        self.assertEqual(self.failure(lambda: self.adapter.paid_check(other, other_quote, other_secret, sig("P-A"), NOW)),
                         "server_error:ERROR_PAYMENT_ALREADY_CLAIMED")
        # quotes expire
        self.server.set_clock("2026-11-01T01:00:00Z")
        self.server.register_synthetic_payment(sig("P-LATE"), int(quote["lamports_due"]))
        self.assertEqual(self.failure(lambda: self.adapter.paid_check(self.request, quote, secret, sig("P-LATE"), NOW)),
                         "server_error:ERROR_QUOTE_EXPIRED")

    def test_price_cap_and_network_are_enforced(self):
        capped = self.adapter_for(self.server, maximum_lamports=1)
        self.assertEqual(self.failure(lambda: capped.request_quote(self.request, NOW)), "server_error:ERROR_PRICE_EXCEEDED")
        mainnet = dict(self.request, network="mainnet")
        self.assertEqual(self.failure(lambda: self.adapter.request_quote(mainnet, NOW)), "server_error:ERROR_WRONG_NETWORK")

    def test_untrusted_server_certificate_is_rejected(self):
        bad = self.pts.ProtocolTestServer(CV / "evidence", *self.pki.untrusted_server, clock_iso=NOW).start()
        try:
            adapter = self.adapter_for(bad)
            self.assertIsNone(adapter.assess(self.request, NOW))
            self.assertEqual(adapter.events[-1]["state"], "transport_failed")
            self.assertEqual(adapter.events[-1]["reason"], "SSLCertVerificationError")
            self.assertEqual(bad.wire_log, [])  # nothing was sent over an unauthenticated channel
        finally:
            bad.stop()

    def test_a_dishonest_server_answer_never_reaches_the_verdict(self):
        quote, secret = self.adapter.request_quote(self.request, NOW)
        self.server.register_synthetic_payment(sig("P-X"), int(quote["lamports_due"]))
        original = self.server.engine.assess_payload

        def other_transaction(view, now_iso):
            body = original(view, now_iso)
            body["message_sha256"] = "0" * 64  # an answer about a different transaction
            return body
        with mock.patch.object(self.server.engine, "assess_payload", side_effect=other_transaction):
            bundle = self.adapter.paid_check(self.request, quote, secret, sig("P-X"), NOW)
        self.assertFalse(bundle["verification"]["accepted"])
        self.assertEqual(bundle["verification"]["discard_reason"], "binding_mismatch")
        for local in ("UNKNOWN", "DENY"):
            self.assertEqual(rules.combine(local, bundle["verification"]), local)

    def test_receipt_must_bind_to_the_assessment(self):
        quote, secret = self.adapter.request_quote(self.request, NOW)
        self.server.register_synthetic_payment(sig("P-R"), int(quote["lamports_due"]))
        bundle = self.adapter.paid_check(self.request, quote, secret, sig("P-R"), NOW)
        stored = self.server.results[quote["quote_id"]]
        other_assessment = rs.signer().sign({"x": 1})
        with self.assertRaises(client.ProtocolFailure) as caught:
            client.verify_receipt(stored["signed_payment_receipt"], quote, other_assessment, TrustStore.test_issuers(),
                                  rs.parse_time(NOW), GENESIS, allowed_algorithms=frozenset({"ML-DSA-87", "TEST-ONLY-ED25519"}),
                                  require_non_test_keys=False)
        self.assertEqual(caught.exception.reason, "receipt_not_bound_to_assessment")
        self.assertTrue(bundle["receipt"]["cloud_assessment_sha256"])


if __name__ == "__main__":
    unittest.main()
