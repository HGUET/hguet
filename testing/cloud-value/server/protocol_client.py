"""Adapter from the Cloud Value Benchmark to the EXISTING public HGUET protocol (protocol/v1/hguet.proto).

There is no HTTP API and no second wire format. The transport is the documented one:
TLS 1.3 -> 4-byte big-endian frame length -> exactly one Protobuf `Envelope` (<= 1 MiB), flow

  ClientHello -> ServerHello -> PriceQuoteRequest -> PriceQuoteResult(signed quote)
     -> [payment made EXTERNALLY by the operator's own wallet] ->
  PaidCheckRequest -> CheckReceipt(pending) | CheckResult(signed CloudAssessment + signed PaymentReceipt)
  (PaidCheckStatus re-reads a result with the claim secret, never paying twice)

What this adapter will NOT do (by design, per cloud-protocol.md):
  * hold wallet keys, sign or broadcast a payment, or skip quote/payment/claim checks;
  * disable certificate verification, hostname checking, or accept TLS < 1.3;
  * believe an unverified answer: every SignedPayload goes through verify/assessment_rules.py first.

Honest limits (the adapter therefore reports `unavailable`):
  * the protocol requires the hybrid group SecP384r1MLKEM1024 and fail-closed on classical-only.
    Python's `ssl` can neither select nor read back the negotiated group, so the requirement cannot be
    enforced here. `unavailable_reason()` says so unless the explicit conformance-test switch is used,
    and conformance results are NEVER reported as real_server measurements.
  * no HGUET issuer key is pinned (verify/trust/real_issuers.json does not exist);
  * ML-DSA-87 verification needs OpenSSL >= 3.5.
"""
import hashlib
import json
import os
import socket
import ssl
import struct
import sys
import time
from pathlib import Path

CV = Path(__file__).resolve().parents[1]
for sub in ("protocol", "verify"):
    sys.path.insert(0, str(CV / sub))
sys.path.insert(0, str(CV.parent / "lib"))
import assessment_rules as rules  # noqa: E402
import jcs  # noqa: E402
import mldsa  # noqa: E402
import proto_codec as pc  # noqa: E402
from common import (DOMAINS, ENVIRONMENT_FOR_NETWORK, REAL_SERVER_CAPABILITIES, canonical_memo,  # noqa: E402
                    canonical_solana_signature, parse_time, subjects_digest)  # noqa: E402
from trust import TrustStore  # noqa: E402

# Public cluster genesis hashes. MUST be cross-checked with the cluster's getGenesisHash (protocol requirement).
REAL_GENESIS = {"devnet": "EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG",
                "testnet": "4uhcVJyU9pJkvQyS88uRDiswHXSCkY3zQawwpjk2NsNY",
                "mainnet": "5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d"}
# hguet.proto: Subject.category is documented as "program, mint, destination or merchant".
CATEGORY_FOR_SUBJECT_TYPE = {"program": "program", "mint": "mint", "account": "destination"}
CLI_RELEASE = "hguet-cloud-value-benchmark"
MAX_PENDING_POLLS = 5


class ProtocolFailure(Exception):
    """Any condition after which the answer must not be used. `reason` is machine-readable."""

    def __init__(self, reason, detail=""):
        super().__init__("%s %s" % (reason, detail))
        self.reason = reason


def make_tls_context(ca_file=None):
    """TLS client context: verification can only be made STRICTER here, never weaker."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    if ca_file:
        context.load_verify_locations(cafile=str(ca_file))  # pinned trust root(s)
    else:
        context.load_default_certs()
    return context


def pq_group_enforceable():
    """The protocol demands SecP384r1MLKEM1024 and fail-closed on anything else. This runtime cannot
    select or confirm it (no SSLContext.set_groups / negotiated-group accessor)."""
    return hasattr(ssl.SSLContext, "set_groups") and hasattr(ssl.SSLSocket, "group")


def subject_messages(subjects, network):
    out = []
    for subject in subjects:
        category = CATEGORY_FOR_SUBJECT_TYPE.get(subject["type"])
        if category is None:
            raise ProtocolFailure("subject_not_expressible_in_public_protocol",
                                  "type %r has no category in hguet.proto" % subject["type"])
        out.append({"category": category, "network": network, "subject_id": subject["id"]})
    return out


class ProtocolSession:
    def __init__(self, host, port, context, server_hostname=None, timeout=10.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.tls = context.wrap_socket(self.sock, server_hostname=server_hostname or host)
        self.tls.settimeout(timeout)
        self.bytes_sent = 0
        self.tls_version = self.tls.version()
        if self.tls_version != "TLSv1.3":
            raise ProtocolFailure("tls_version", self.tls_version)

    def _read_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.tls.recv(n - len(buf))
            if not chunk:
                raise ProtocolFailure("connection_closed")
            buf += chunk
        return buf

    def exchange(self, payload_name, payload):
        request_id = os.urandom(16)
        data = pc.frame(pc.encode("Envelope", pc.new_envelope(payload_name, payload, request_id)))
        self.tls.sendall(data)
        self.bytes_sent += len(data)
        try:
            reply = pc.decode("Envelope", pc.read_frame(self._read_exact))
        except pc.ProtoError as exc:
            raise ProtocolFailure("malformed_frame", str(exc)) from exc
        if reply.get("request_id") != request_id:
            raise ProtocolFailure("request_id_mismatch")
        if reply.get("protocol_major") != 1:
            raise ProtocolFailure("protocol_major_mismatch")
        name, body = pc.envelope_payload(reply)
        if name == "error":
            raise ProtocolFailure("server_error:" + str(body.get("code")), body.get("safe_message", ""))
        return name, body

    def close(self):
        try:
            self.tls.close()
        except OSError:
            pass


def build_quote_request(request, claim_secret_sha256, maximum_lamports, genesis_map):
    subjects = subject_messages(request["subjects"], request["network"])
    return {
        "network": request["network"], "genesis_hash": genesis_map[request["network"]],
        "message_sha256": bytes.fromhex(request["message_sha256"]),
        "intent_sha256": bytes.fromhex(request["intent_sha256"]) if request.get("intent_sha256") else b"",
        "profile": request["profile"], "requested_capabilities": list(REAL_SERVER_CAPABILITIES),
        "scope": "DATA_SCOPE_METADATA_ONLY", "claim_secret_sha256": claim_secret_sha256,
        "maximum_lamports": str(maximum_lamports), "subjects": subjects,
        "subjects_sha256": bytes.fromhex(subjects_digest(request["subjects"], request["network"])),
        "complexity": {"transaction_bytes": 0, "top_level_instructions": 0, "resolved_accounts": 0, "lookup_tables": 0,
                       "distinct_programs": 0, "risk_subjects": len(subjects), "verified_from_raw_transaction": False},
        "transaction_sha256": bytes.fromhex(request["transaction_sha256"]) if request.get("transaction_sha256") else b"",
    }


def verify_quote(signed_quote, request, claim_commitment_hex, maximum_lamports, trust, now, genesis_map, **policy):
    """Return the verified quote dict or raise ProtocolFailure. Pure function of its inputs."""
    payload, key, reason = rules.verify_signed_payload(signed_quote, "price_quote", trust, now, **policy)
    if reason:
        raise ProtocolFailure("quote_" + reason)
    quote_schema = json.loads((CV.parents[1] / "protocol/v1/payment-quote.schema.json").read_text(encoding="utf-8"))
    try:
        import jsonschema
        errors = [e.message for e in jsonschema.Draft202012Validator(quote_schema).iter_errors(payload)][:2]
    except ImportError:  # pragma: no cover
        errors = [k for k in quote_schema["required"] if k not in payload]
    if errors:
        raise ProtocolFailure("quote_schema_invalid", str(errors))
    expected = {"network": request["network"], "genesis_hash": genesis_map[request["network"]],
                "message_sha256": request["message_sha256"], "claim_secret_sha256": claim_commitment_hex,
                "subjects_sha256": subjects_digest(request["subjects"], request["network"]), "data_scope": "metadata_only",
                "environment": ENVIRONMENT_FOR_NETWORK[request["network"]]}
    for field, value in expected.items():
        if payload[field] != value:
            raise ProtocolFailure("quote_binding_mismatch", field)
    if payload["memo_reference"] != canonical_memo(payload["quote_id"]):
        raise ProtocolFailure("quote_memo_not_canonical")
    if int(payload["lamports_due"]) > int(maximum_lamports):
        raise ProtocolFailure("quote_price_exceeds_cap")
    if not parse_time(payload["issued_at"]) <= now < parse_time(payload["expires_at"]):
        raise ProtocolFailure("quote_expired_or_not_yet_valid")
    return payload


def verify_receipt(signed_receipt, quote, assessment_signed, trust, now, genesis_map, **policy):
    payload, key, reason = rules.verify_signed_payload(signed_receipt, "payment_receipt", trust, now, **policy)
    if reason:
        raise ProtocolFailure("receipt_" + reason)
    receipt_schema = json.loads((CV.parents[1] / "protocol/v1/payment-receipt.schema.json").read_text(encoding="utf-8"))
    try:
        import jsonschema
        errors = [e.message for e in jsonschema.Draft202012Validator(receipt_schema).iter_errors(payload)][:2]
    except ImportError:  # pragma: no cover
        errors = [k for k in receipt_schema["required"] if k not in payload]
    if errors:
        raise ProtocolFailure("receipt_schema_invalid", str(errors))
    for field in ("quote_id", "network", "genesis_hash", "message_sha256", "environment"):
        if payload[field] != quote[field]:
            raise ProtocolFailure("receipt_binding_mismatch", field)
    if payload["cloud_assessment_sha256"] != hashlib.sha256(assessment_signed["canonical_payload"]).hexdigest():
        raise ProtocolFailure("receipt_not_bound_to_assessment")
    if int(payload["lamports_paid"]) < int(quote["lamports_due"]) or payload["receiver"] != quote["receiver"]:
        raise ProtocolFailure("receipt_payment_mismatch")
    return payload


class RealServerAdapter:
    """Facade used by the runner. `assess()` returns a verified SignedPayload bundle or None (never a guess)."""
    kind = "real_server"

    def __init__(self, host=None, port=443, *, enabled=False, ca_file=None, trust=None, payments=None,
                 maximum_lamports=100_000_000, conformance_test_classical_tls=False, test_trust_store=None,
                 genesis_map=None, timeout=10.0):
        self.host, self.port, self.enabled, self.ca_file = host, port, enabled, ca_file
        self.payments = payments or {}  # message_sha256 -> {"payment_signature", "claim_secret_hex"}
        self.maximum_lamports = maximum_lamports
        self.conformance = conformance_test_classical_tls
        self.trust = test_trust_store if conformance_test_classical_tls else (trust or TrustStore.real_issuers())
        self.genesis_map = genesis_map or REAL_GENESIS
        self.timeout = timeout
        self.requests_sent = self.bytes_sent = 0
        self.fields_sent, self.last_latency_s, self.cost_units = set(), None, None
        self.quotes = {}
        self.events = []

    # ------------------------------------------------------------------ status
    def policy(self):
        if self.conformance:
            return {"allowed_algorithms": frozenset({"ML-DSA-87", "TEST-ONLY-ED25519"}), "require_non_test_keys": False}
        return {"allowed_algorithms": frozenset({"ML-DSA-87"}), "require_non_test_keys": True}

    def unavailable_reason(self):
        if not self.enabled:
            return "real server not enabled (--enable-real-server); nothing was sent"
        if not self.host:
            return "no real server host configured; nothing was sent"
        if self.trust is None:
            return "no pinned HGUET issuer key (verify/trust/real_issuers.json absent): signatures cannot be authenticated"
        if not mldsa.BACKEND.available() and not self.conformance:
            return "ML-DSA-87 cannot be verified here: " + mldsa.BACKEND.reason
        if not pq_group_enforceable() and not self.conformance:
            return ("the protocol requires SecP384r1MLKEM1024 and fail-closed on classical TLS; this runtime cannot "
                    "enforce or confirm the negotiated group")
        return None

    # -------------------------------------------------------------- operations
    def _session(self):
        return ProtocolSession(self.host, self.port, make_tls_context(self.ca_file), timeout=self.timeout)

    def _handshake(self, session):
        name, hello = session.exchange("client_hello", {"supported_majors": [1], "max_minor": 0,
                                                       "requested_capabilities": list(REAL_SERVER_CAPABILITIES),
                                                       "cli_release": CLI_RELEASE})
        if name != "server_hello" or hello.get("selected_major") != 1:
            raise ProtocolFailure("version_negotiation")

    def request_quote(self, request, now_iso):
        """Phase 1: obtain and VERIFY a signed quote. Pays nothing. Returns (quote_payload, claim_secret)."""
        claim_secret = os.urandom(32)
        commitment = hashlib.sha256(claim_secret).digest()
        message = build_quote_request(request, commitment, self.maximum_lamports, self.genesis_map)
        session = self._session()
        try:
            self._handshake(session)
            name, result = session.exchange("price_quote_request", message)
            self.requests_sent += 1
            self.fields_sent |= set(message)
            if name != "price_quote_result" or result.get("result") not in ("RESULT_COMPLETED", "RESULT_ACCEPTED"):
                raise ProtocolFailure("quote_not_issued", str(result.get("result")))
            quote = verify_quote(self._signed(result["signed_quote"]), request, commitment.hex(), self.maximum_lamports,
                                 self.trust, parse_time(now_iso), self.genesis_map, **self.policy())
        finally:
            self.bytes_sent += session.bytes_sent
            session.close()
        self.quotes[request["message_sha256"]] = (quote, claim_secret)
        return quote, claim_secret

    @staticmethod
    def _signed(message):
        return {"canonical_payload": message["canonical_payload"], "signature": message["signature"],
                "key_id": message["key_id"], "signing_algorithm": message["signing_algorithm"]}

    def paid_check(self, request, quote, claim_secret, payment_signature, now_iso):
        """Phase 2 (only after the operator paid EXTERNALLY): returns {verification, receipt} or raises."""
        if not canonical_solana_signature(payment_signature):
            raise ProtocolFailure("payment_signature_not_canonical")
        subjects = subject_messages(request["subjects"], request["network"])
        paid = {
            "quote_id": bytes.fromhex(quote["quote_id"]), "claim_secret": claim_secret,
            "payment_transaction_signature": payment_signature,
            "message_sha256": bytes.fromhex(request["message_sha256"]),
            "transaction_sha256": bytes.fromhex(request["transaction_sha256"]) if request.get("transaction_sha256") else b"",
            "intent_sha256": bytes.fromhex(request["intent_sha256"]) if request.get("intent_sha256") else b"",
            "network": request["network"], "genesis_hash": self.genesis_map[request["network"]],
            "profile": request["profile"], "requested_capabilities": list(REAL_SERVER_CAPABILITIES),
            "scope": "DATA_SCOPE_METADATA_ONLY", "raw_transaction_consent": False,
            "evidence": {"canonical_local_evidence_json": b"{}", "subjects": subjects, "local_decision": ""},
            "subjects_sha256": bytes.fromhex(subjects_digest(request["subjects"], request["network"])),
        }
        session = self._session()
        try:
            self._handshake(session)
            name, body = session.exchange("paid_check_request", paid)
            self.requests_sent += 1
            polls = 0
            while name == "check_receipt":
                polls += 1
                if polls > MAX_PENDING_POLLS or body.get("result") not in ("RESULT_PENDING", "RESULT_ACCEPTED"):
                    raise ProtocolFailure("check_not_completed", body.get("state", ""))
                time.sleep(min(int(body.get("retry_after_seconds", 1)), 2))
                name, body = session.exchange("paid_check_status", {"quote_id": paid["quote_id"],
                                                                      "claim_secret": claim_secret})
            if name != "check_result" or body.get("result") != "RESULT_COMPLETED":
                raise ProtocolFailure("unexpected_reply", name)
            assessment_signed = self._signed(body["signed_cloud_assessment"])
            now = parse_time(now_iso)
            wire_request = dict(request)
            verification = rules.verify(assessment_signed, wire_request, self.registry, now_iso=now_iso, mode="strict",
                                        trust=self.trust, expected_quote_id=quote["quote_id"],
                                        genesis_map=self.genesis_map, **self.policy())
            receipt = verify_receipt(self._signed(body["signed_payment_receipt"]), quote, assessment_signed,
                                     self.trust, now, self.genesis_map, **self.policy())
            return {"verification": verification, "receipt": receipt}
        finally:
            self.bytes_sent += session.bytes_sent
            session.close()

    registry = None  # set by the runner: the verifier's independent evidence registry

    def assess(self, request, now_iso):
        """Runner entry point. Without an external payment for this exact message there is NO answer."""
        if self.unavailable_reason():
            return None
        started = time.perf_counter()
        try:
            entry = self.payments.get(request["message_sha256"])
            quote, secret = self.quotes.get(request["message_sha256"]) or self.request_quote(request, now_iso)
            if entry is None:
                self.events.append({"message_sha256": request["message_sha256"], "state": "awaiting_external_payment",
                                    "lamports_due": quote["lamports_due"], "receiver": quote["receiver"],
                                    "memo_reference": quote["memo_reference"]})
                return None
            if entry.get("claim_secret_hex") and bytes.fromhex(entry["claim_secret_hex"]) != secret:
                secret = bytes.fromhex(entry["claim_secret_hex"])
            return self.paid_check(request, quote, secret, entry["payment_signature"], now_iso)
        except ProtocolFailure as exc:
            self.events.append({"message_sha256": request["message_sha256"], "state": "failed", "reason": exc.reason})
            return None
        except (OSError, ssl.SSLError, pc.ProtoError) as exc:
            self.events.append({"message_sha256": request["message_sha256"], "state": "transport_failed",
                                "reason": type(exc).__name__})
            return None
        finally:
            self.last_latency_s = time.perf_counter() - started
