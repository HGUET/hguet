"""Reference MOCK Cloud server for the Cloud Value Benchmark. MODEL ONLY.

It answers a metadata-only request with a signed CloudAssessment-shaped document built from the
independent evidence fixtures. It never sees ground truth (it takes the request and the evidence
directory only). Profiles model server behaviours a verifier must cope with:

  strict   filters by network, validity window, retractions and tier; accuses only on verified
           historical/lab evidence; reports hypothetical risk as informational only
  naive    accuses on ANY adverse record (stale, retracted, other network, hypothetical)
  oversell strict, plus claims "safety:subject_reputable" even with no benign evidence
  silent   no answer (models an unreachable server)

The signature scheme is a stand-in (Ed25519, key `cloud:reference-signer`). The real protocol uses
ML-DSA-87 over canonical JSON; the verifier takes the algorithm from a registry so that swap is a
configuration change, not a redesign.
"""
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

CV = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CV.parent / "lib"))
import crypto_tx as ct  # noqa: E402

SIGNER_LABEL = "cloud:reference-signer"
KEY_ID = "bench-cloud-key-1"
ALG = "reference-ed25519-v1"
DOMAIN = b"HGUET-CLOUD-ASSESSMENT\0"
GENESIS = {"devnet": "bench-genesis-devnet", "testnet": "bench-genesis-testnet", "mainnet": "bench-genesis-mainnet"}
COST_UNITS_PER_ASSESSMENT = 1.0  # nominal benchmark unit, NOT a price


def parse_time(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def fmt_time(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load_evidence(directory):
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(Path(directory).glob("EV-*.json"))]


def evidence_digest_of(record):
    return sha(ct.canonical_json(record))


def signer_public_b58():
    return ct.signer_pubkey(SIGNER_LABEL)


def sign_envelope(assessment, *, tamper_signature=False):
    signature = ct.ed25519_sign(ct.seed_for(SIGNER_LABEL), DOMAIN + ct.canonical_json(assessment))
    if tamper_signature:
        signature = bytes([signature[0] ^ 1]) + signature[1:]
    return {"assessment": assessment,
            "signature": {"alg": ALG, "key_id": KEY_ID, "sig_b58": ct.b58encode(signature)}}


class ReferenceCloudServer:
    kind = "reference_mock"

    def __init__(self, evidence_dir, profile="strict"):
        if profile not in ("strict", "naive", "oversell", "silent"):
            raise ValueError("unknown profile " + profile)
        self.profile = profile
        self.records = load_evidence(evidence_dir)
        self.cost_units = COST_UNITS_PER_ASSESSMENT
        self.last_latency_s = 0.0

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
    def assess(self, request, now_iso):
        started = time.perf_counter()
        if self.profile == "silent":
            self.last_latency_s = time.perf_counter() - started
            return None
        now = parse_time(now_iso)
        findings, cited, benign_cited = [], [], []
        adverse = benign = []
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
        assessment = {
            "schema_version": 1, "kind": "cloud_assessment", "network": request["network"],
            "genesis_hash": GENESIS[request["network"]], "message_sha256": request["message_sha256"],
            "intent_sha256": request["intent_sha256"], "requested_profile": request["profile"],
            "capabilities_performed": ["subject_reputation_lookup"],
            "capabilities_unavailable": ["onchain_simulation", "alt_resolution"],
            "risk_snapshot_id": "bench-evidence-snapshot-v1", "ruleset_version": "reference-ruleset-1",
            "evidence_digest": sha(ct.canonical_json(sorted(evidence_digest_of(r) for r in cited))),
            "sources": [{"source_id": r["evidence_id"], "kind": r["provenance"]["tier"],
                         "observed_at": r["observed_at"], "evidence_sha256": evidence_digest_of(r),
                         "freshness_seconds": max(0, int(now - parse_time(r["observed_at"])))} for r in cited],
            "findings": findings,
            "coverage": {"required": ["subject_reputation"], "passed": passed, "unknown": unknown},
            "issued_at": now_iso, "expires_at": fmt_time(now + 3600),
            "quote_id": request["message_sha256"][:32], "environment": "sandbox", "data_scope": request["data_scope"],
            "subjects_sha256": sha(ct.canonical_json(request["subjects"])),
            "transaction_sha256": request["transaction_sha256"],
        }
        self.last_latency_s = time.perf_counter() - started
        return sign_envelope(assessment)
