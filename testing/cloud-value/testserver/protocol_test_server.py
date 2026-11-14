"""TEST HARNESS that speaks the PUBLIC HGUET protocol over TLS. It is NOT an HGUET Server.

Purpose: let the adapter's real TLS + framing + Protobuf + quote/payment/claim flow be exercised
without a deployed service. It enforces the checks the protocol prescribes (claim secret, quote
expiry, wrong network, payment uniqueness, price cap) and signs with the TEST issuer key.

Separation of interfaces: everything a client can reach is the public wire protocol. The harness-only
methods (`register_synthetic_payment`, `set_clock`) are plain Python calls on this object, are not
reachable over the network, and exist only because a test must stand in for the Solana ledger. There
is no shortcut that returns an assessment without a registered, finalized payment and the claim secret.
Devnet/testnet only: a mainnet request is refused with ERROR_WRONG_NETWORK.
"""
import hashlib
import os
import socket
import ssl
import struct
import sys
import threading
from pathlib import Path

CV = Path(__file__).resolve().parents[1]
for sub in ("protocol", "verify", "server"):
    sys.path.insert(0, str(CV / sub))
sys.path.insert(0, str(CV.parent / "lib"))
import crypto_tx as ct  # noqa: E402
import jcs  # noqa: E402
import proto_codec as pc  # noqa: E402
import reference_server as rs  # noqa: E402
from common import GENESIS, fmt_time, parse_time, subjects_digest  # noqa: E402

TYPE_FOR_CATEGORY = {"program": "program", "mint": "mint", "destination": "account"}
USD_PRICE_MICROS, SOL_USD_MICROS = 50_000, 150_000_000  # synthetic tariff / FX, nothing real


class ProtocolTestServer:
    def __init__(self, evidence_dir, cert_file, key_file, *, clock_iso, genesis_map=None, profile="strict"):
        self.engine = rs.ReferenceCloudServer(evidence_dir, profile)
        self.clock_iso = clock_iso
        self.genesis_map = genesis_map or GENESIS
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_cert_chain(cert_file, key_file)
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.quotes, self.results, self.payments, self.claimed = {}, {}, {}, {}
        self.receiver = ct.plain_pubkey("test-server-receiver")
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self.wire_log = []  # (payload name) for assertions; never contains secrets
        self.tls_versions = []

    # --------------------------------------------------- harness-only (not wire)
    def register_synthetic_payment(self, signature, lamports, finalized=True):
        self.payments[signature] = {"lamports": lamports, "finalized": finalized}

    def set_clock(self, iso):
        self.clock_iso = iso

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self._thread.join(3)
        self.listener.close()

    # ------------------------------------------------------------------ server
    def _serve(self):
        while not self._stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._connection, args=(raw,), daemon=True).start()

    def _connection(self, raw):
        try:
            conn = self.context.wrap_socket(raw, server_side=True)
            conn.settimeout(5)
            self.tls_versions.append(conn.version())

            def read_exact(n):
                buf = b""
                while len(buf) < n:
                    chunk = conn.recv(n - len(buf))
                    if not chunk:
                        raise ConnectionError("closed")
                    buf += chunk
                return buf
            while True:
                try:
                    envelope = pc.decode("Envelope", pc.read_frame(read_exact))
                except (ConnectionError, ssl.SSLError, socket.timeout, OSError):
                    return
                except pc.ProtoError:
                    return
                name, body = pc.envelope_payload(envelope)
                self.wire_log.append(name)
                reply_name, reply = self._dispatch(name, body)
                data = pc.frame(pc.encode("Envelope", pc.new_envelope(reply_name, reply, envelope["request_id"])))
                conn.sendall(data)
        except (ssl.SSLError, OSError):
            return
        finally:
            try:
                raw.close()
            except OSError:
                pass

    @staticmethod
    def _error(code, message="", retryable=False):
        return "error", {"code": code, "safe_message": message, "retryable": retryable, "retry_after_seconds": 0}

    def _dispatch(self, name, body):
        if name == "client_hello":
            if 1 not in body.get("supported_majors", []):
                return self._error("ERROR_PROTOCOL_UNSUPPORTED")
            return "server_hello", {"selected_major": 1, "selected_minor": 0,
                                    "available_capabilities": ["subject_reputation_lookup"],
                                    "server_release": "protocol-test-harness"}
        if name == "price_quote_request":
            return self._quote(body)
        if name == "paid_check_request":
            return self._paid(body)
        if name == "paid_check_status":
            return self._status(body)
        return self._error("ERROR_BAD_REQUEST", "unexpected message")

    # -------------------------------------------------------------- operations
    def _quote(self, req):
        if req.get("network") not in ("devnet", "testnet"):
            return self._error("ERROR_WRONG_NETWORK", "test harness serves sandbox networks only")
        if req.get("genesis_hash") != self.genesis_map[req["network"]]:
            return self._error("ERROR_WRONG_NETWORK", "genesis mismatch")
        if req.get("scope") != "DATA_SCOPE_METADATA_ONLY" or req.get("raw_transaction"):
            return self._error("ERROR_MISSING_CONSENT", "harness accepts metadata-only requests")
        if len(req.get("claim_secret_sha256", b"")) != 32 or len(req.get("message_sha256", b"")) != 32:
            return self._error("ERROR_BAD_REQUEST", "hash length")
        subjects = [{"type": TYPE_FOR_CATEGORY.get(s["category"], s["category"]), "id": s["subject_id"]}
                    for s in req.get("subjects", [])]
        if subjects_digest(subjects, req["network"]) != req["subjects_sha256"].hex():
            return self._error("ERROR_BAD_REQUEST", "subjects_sha256 does not match the subject set")
        due = USD_PRICE_MICROS * 10 ** 9 // SOL_USD_MICROS
        if due > int(req["maximum_lamports"]):
            return self._error("ERROR_PRICE_EXCEEDED")
        quote_id = os.urandom(16).hex()
        now = parse_time(self.clock_iso)
        complexity = dict(req["complexity"])
        quote = {
            "schema_version": 1, "kind": "native_sol_price_quote", "quote_id": quote_id, "environment": "sandbox",
            "network": req["network"], "genesis_hash": req["genesis_hash"], "asset": "SOL", "receiver": self.receiver,
            "memo_reference": "HGUET:" + quote_id, "message_sha256": req["message_sha256"].hex(),
            "transaction_sha256": req["transaction_sha256"].hex() if req.get("transaction_sha256") else None,
            "intent_sha256": req["intent_sha256"].hex() if req.get("intent_sha256") else None,
            "requested_profile": req["profile"], "requested_capabilities": list(req["requested_capabilities"]),
            "data_scope": "metadata_only", "subjects_sha256": req["subjects_sha256"].hex(),
            "claim_secret_sha256": req["claim_secret_sha256"].hex(),
            "usd_price_micros": str(USD_PRICE_MICROS), "sol_usd_price_micros": str(SOL_USD_MICROS),
            "oracle_source_id": "SYNTHETIC_TEST_ORACLE", "oracle_published_at": self.clock_iso,
            "oracle_confidence_bps": 20, "lamports_due": str(due), "issued_at": self.clock_iso,
            "expires_at": fmt_time(now + 900), "pricing_policy_version": "synthetic-test-tariff",
            "pricing_tier": "basic", "complexity": {k: complexity.get(k, 0) for k in (
                "transaction_bytes", "top_level_instructions", "resolved_accounts", "lookup_tables",
                "distinct_programs", "risk_subjects")} | {"verified_from_raw_transaction": False},
            "max_lamports_requested": req["maximum_lamports"],
        }
        self.quotes[quote_id] = {"quote": quote, "claim_sha256": req["claim_secret_sha256"], "subjects": subjects,
                                 "request": req}
        return "price_quote_result", {"result": "RESULT_COMPLETED",
                                      "signed_quote": rs.signer().sign(quote, "price_quote")}

    def _authenticate(self, quote_id_bytes, claim_secret):
        stored = self.quotes.get(quote_id_bytes.hex())
        if stored is None:
            return None, self._error("ERROR_BAD_REQUEST", "unknown quote")
        if hashlib.sha256(claim_secret).digest() != stored["claim_sha256"]:
            return None, self._error("ERROR_CLAIM_AUTH_FAILED")
        return stored, None

    def _paid(self, req):
        stored, error = self._authenticate(req.get("quote_id", b""), req.get("claim_secret", b""))
        if error:
            return error
        quote = stored["quote"]
        if parse_time(self.clock_iso) >= parse_time(quote["expires_at"]):
            return self._error("ERROR_QUOTE_EXPIRED")
        if (req.get("network") != quote["network"] or req.get("message_sha256", b"").hex() != quote["message_sha256"]
                or req.get("subjects_sha256", b"").hex() != quote["subjects_sha256"]):
            return self._error("ERROR_BAD_REQUEST", "request does not match the signed quote")
        signature = req.get("payment_transaction_signature", "")
        payment = self.payments.get(signature)
        if payment is None or payment["lamports"] < int(quote["lamports_due"]):
            return self._error("ERROR_INVALID_PAYMENT")
        if not payment["finalized"]:
            return self._error("ERROR_PAYMENT_NOT_FINALIZED", retryable=True)
        owner = self.claimed.setdefault(signature, quote["quote_id"])
        if owner != quote["quote_id"]:
            return self._error("ERROR_PAYMENT_ALREADY_CLAIMED")
        if quote["quote_id"] not in self.results:
            view = {"network": quote["network"], "message_sha256": quote["message_sha256"],
                    "intent_sha256": quote["intent_sha256"], "transaction_sha256": quote["transaction_sha256"],
                    "profile": quote["requested_profile"], "data_scope": "metadata_only", "subjects": stored["subjects"]}
            payload = self.engine.assess_payload(view, self.clock_iso)
            payload["quote_id"] = quote["quote_id"]
            signed = rs.signer().sign(payload, "cloud_assessment")
            receipt = {
                "schema_version": 1, "kind": "native_sol_payment_receipt", "quote_id": quote["quote_id"],
                "environment": "sandbox", "network": quote["network"], "genesis_hash": quote["genesis_hash"],
                "message_sha256": quote["message_sha256"], "payment_signature": signature.ljust(64, "x"),
                "payment_instruction_index": 0, "lamports_paid": str(payment["lamports"]), "receiver": quote["receiver"],
                "settled_slot": 1, "settled_commitment": "finalized", "analysis_state": "completed",
                "cloud_assessment_sha256": hashlib.sha256(signed["canonical_payload"]).hexdigest(),
                "issued_at": self.clock_iso,
            }
            self.results[quote["quote_id"]] = {"result": "RESULT_COMPLETED", "quote_id": bytes.fromhex(quote["quote_id"]),
                                               "signed_cloud_assessment": signed,
                                               "signed_payment_receipt": rs.signer().sign(receipt, "payment_receipt")}
        return "check_result", self.results[quote["quote_id"]]

    def _status(self, req):
        stored, error = self._authenticate(req.get("quote_id", b""), req.get("claim_secret", b""))
        if error:
            return error
        result = self.results.get(stored["quote"]["quote_id"])
        if result is None:
            return "check_receipt", {"result": "RESULT_PENDING", "quote_id": req["quote_id"], "state": "payment_pending",
                                     "retry_after_seconds": 1}
        return "check_result", result
