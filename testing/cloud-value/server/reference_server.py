"""Reference MOCK Cloud server for the Cloud Value Benchmark. MODEL ONLY.

It answers with the public protocol's `SignedPayload` (JCS canonical CloudAssessment signed over the
domain-separated bytes), built from the independent evidence fixtures. It never sees ground truth
(it takes the request view and the evidence directory only). Profiles model server behaviours a
verifier must cope with:

  strict   filters by network, validity window, retractions and tier; accuses only on verified
           historical/lab evidence; reports hypothetical risk as informational only
  naive    accuses on ANY adverse record (stale, retracted, other network, hypothetical)
  oversell strict, plus claims "safety:subject_reputable" even with no benign evidence
  silent   no answer (models an unreachable server)

Signature: ML-DSA-87 through OpenSSL >= 3.5 when present (a deterministic TEST key, see
verify/trust/test_issuers.json), otherwise the explicitly labelled TEST-ONLY-ED25519 fallback. The
algorithm used is reported with every result; neither is a production HGUET key.
"""
import hashlib
import json
import sys
import time
from pathlib import Path

CV = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CV.parent / "lib"))
sys.path.insert(0, str(CV / "verify"))
sys.path.insert(0, str(CV / "protocol"))
import crypto_tx as ct  # noqa: E402
import jcs  # noqa: E402
import mldsa  # noqa: E402
from common import DOMAINS, ENVIRONMENT_FOR_NETWORK, GENESIS, evidence_digest, evidence_sha256, fmt_time, parse_time, subjects_digest  # noqa: E402

COST_UNITS_PER_ASSESSMENT = 1.0  # nominal benchmark unit, NOT a price
KEY_IDS = {"ML-DSA-87": "bench-issuer-mldsa87-1", "TEST-ONLY-ED25519": "bench-issuer-ed25519-1"}


def load_evidence(directory):
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(Path(directory).glob("EV-*.json"))]


def evidence_digest_of(record):
    return evidence_sha256(record)


class TestSigner:
    """Signs protocol `SignedPayload`s with the deterministic TEST issuer key."""

    def __init__(self):
        self.mldsa = None
        if mldsa.BACKEND.available():
            self.mldsa = mldsa.BACKEND.test_keypair("cloud-issuer-1")[0]
        self.algorithm = "ML-DSA-87" if self.mldsa else "TEST-ONLY-ED25519"
        self.key_id = KEY_IDS[self.algorithm]

    def sign(self, payload_dict, purpose="cloud_assessment", *, flip_signature=False):
        return self.sign_bytes(jcs.canonicalize(payload_dict), purpose, flip_signature=flip_signature)

    def sign_bytes(self, body, purpose="cloud_assessment", *, flip_signature=False):
        """Sign arbitrary payload bytes (tests use this to produce validly signed NON-canonical payloads)."""
        message = DOMAINS[purpose] + body
        if self.mldsa:
            signature = mldsa.BACKEND.test_sign(self.mldsa, message)
        else:
            signature = ct.ed25519_sign(ct.seed_for("cloud:reference-signer"), message)
        if flip_signature:
            signature = bytes([signature[0] ^ 1]) + signature[1:]
        return {"canonical_payload": body, "signature": signature, "key_id": self.key_id,
                "signing_algorithm": self.algorithm}


SIGNER = None


def signer():
    global SIGNER
    if SIGNER is None:
        SIGNER = TestSigner()
    return SIGNER


class ReferenceCloudServer:
    kind = "reference_mock"

    def __init__(self, evidence_dir, profile="strict"):
        if profile not in ("strict", "naive", "oversell", "silent"):
            raise ValueError("unknown profile " + profile)
        self.profile = profile
        self.records = load_evidence(evidence_dir)
        self.cost_units = COST_UNITS_PER_ASSESSMENT
        self.last_latency_s = 0.0
        self._cache = {}

    # --- helpers -----------------------------------------------------------
    def _for_subjects(self, request):
        wanted = {(s["type"], s["id"]) for s in request["subjects"]}
        return [r for r in self.records if (r["subject"]["type"], r["subject"]["id"]) in wanted]

    def _retracted(self, record):
        return any(other.get("retracts") == record["evidence_id"] and
                   parse_time(other["observed_at"]) > parse_time(record["observed_at"]) for other in self.records)

    def _usable(self, record, request, now):
        if self.profile == "naive":
            return True
        return (record["network"] == request["network"]
                and parse_time(record["observed_at"]) <= now <= parse_time(record["valid_until"])
                and not self._retracted(record))

    # --- main --------------------------------------------------------------
    def assess_payload(self, request, now_iso):
        now = parse_time(now_iso)
        findings, cited = [], []
        usable = [r for r in self._for_subjects(request) if self._usable(r, request, now)]
        adverse = [r for r in usable if r["claim"]["polarity"] == "adverse"]
        benign = [r for r in usable if r["claim"]["polarity"] == "benign"]
        conflicting = bool(adverse and benign)
        for record in adverse:
            tier, conf = record["provenance"]["tier"], record["confidence"]
            strong = tier in ("historical_class", "lab_simulation") and conf >= 0.8
            if self.profile == "naive":
                enforcement, severity = "hard_deny", "critical"
            elif conflicting:
                continue  # reported as a conflict below, never as an accusation
            elif strong:
                warn_only = record["claim"]["code"] == "MINT_FREEZE_AUTHORITY_RISK"
                enforcement, severity = ("warn", "high") if warn_only else ("hard_deny", "critical")
            else:
                enforcement, severity = "inform", "info"
            findings.append({"code": record["claim"]["code"], "severity": severity, "enforcement": enforcement,
                             "evidence_refs": [record["evidence_id"]],
                             "summary": "%s (%s evidence)" % (record["claim"]["code"], tier)})
            cited.append(record)
        if conflicting:
            findings.append({"code": "EVIDENCE_CONFLICT", "severity": "medium", "enforcement": "warn",
                             "evidence_refs": [r["evidence_id"] for r in adverse + benign],
                             "summary": "valid evidence disagrees; unresolved"})
            cited.extend(adverse + benign)
        elif benign:
            cited.extend(benign)
        passed = ["subject_reputation"] if (adverse or benign) else []
        if benign and not conflicting:
            passed.append("safety:subject_reputable")
        if self.profile == "oversell" and "safety:subject_reputable" not in passed:
            passed.append("safety:subject_reputable")  # claimed without any supporting evidence
        unknown = [] if (adverse or benign) else ["subject_reputation"]
        cited = list({r["evidence_id"]: r for r in cited}.values())  # one source entry per evidence record
        return {
            "schema_version": 1, "kind": "cloud_assessment", "network": request["network"],
            "genesis_hash": GENESIS[request["network"]], "message_sha256": request["message_sha256"],
            "intent_sha256": request["intent_sha256"], "requested_profile": request["profile"],
            "capabilities_performed": ["subject_reputation_lookup"],
            "capabilities_unavailable": ["onchain_simulation", "alt_resolution"],
            "risk_snapshot_id": "bench-evidence-snapshot-v1", "ruleset_version": "reference-ruleset-1",
            "evidence_digest": evidence_digest(cited),
            "sources": [{"source_id": r["evidence_id"], "kind": r["provenance"]["tier"],
                         "observed_at": r["observed_at"], "evidence_sha256": evidence_digest_of(r),
                         "freshness_seconds": max(0, int(now - parse_time(r["observed_at"])))} for r in cited],
            "findings": findings,
            "coverage": {"required": ["subject_reputation"], "passed": passed, "unknown": unknown},
            "issued_at": now_iso, "expires_at": fmt_time(now + 3600),
            "quote_id": request["message_sha256"][:32], "environment": ENVIRONMENT_FOR_NETWORK[request["network"]],
            "data_scope": request["data_scope"], "subjects_sha256": subjects_digest(request["subjects"], request["network"]),
            "transaction_sha256": request["transaction_sha256"],
        }

    def assess(self, request, now_iso):
        started = time.perf_counter()
        if self.profile == "silent":
            self.last_latency_s = time.perf_counter() - started
            return None
        key = (self.profile, request["message_sha256"], now_iso)
        if key not in self._cache:
            self._cache[key] = signer().sign(self.assess_payload(request, now_iso))
        self.last_latency_s = time.perf_counter() - started
        return self._cache[key]
