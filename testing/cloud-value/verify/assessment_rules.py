"""Client-side acceptance rules for a signed CloudAssessment (`SignedPayload` of hguet.proto).

The object verified here is exactly the public protocol's `SignedPayload`:
  {canonical_payload: bytes (JCS JSON), signature: bytes, key_id: str, signing_algorithm: str}
signed over  DOMAIN("HGUET-CLOUD-ASSESSMENT/v1\\0") || canonical_payload  (cloud-protocol.md). No
parallel wire format exists. A boolean claiming validity is never evidence; an assessment that is
not verified here is `accepted=False` and `combine()` ignores it completely.

Pipeline (the first failure discards the WHOLE assessment, with a machine-readable reason):
  S1 SignedPayload shape        S2 algorithm allowed for this source   S3 algorithm verifiable here
  S4 issuer key pinned, valid at `now`, right algorithm/purpose/environment, not a test key when
     `require_non_test_keys`    S5 signature valid over domain||payload   S6 payload is canonical JCS
  P1 schema (protocol/v1/cloud-assessment.schema.json)   P2 binding: message, transaction, subjects,
  intent, quote_id   P3 network + genesis + environment (mainnet=production, devnet/testnet=sandbox)
  P4 freshness window   P5 sources: evidence digest recomputed from the independent registry
Then per finding (strict mode; `trusting` skips this to expose the harm of blind trust):
  F1 evidence_refs listed in `sources` with matching digest     F2 record eligible (subject in request,
  same network, inside window, not retracted, polarity+code agree)     F3 enforcement capped by provenance
  (hard_deny needs historical or reproducible lab evidence with confidence >= 0.8; hypothetical = inform)
  F4 hard_deny capped at warn while strong eligible benign evidence for the same subject stands
Safety claims (`coverage.passed` entries starting with `safety:`) are information only and never ALLOW.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path

CV = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CV.parent / "lib"))
sys.path.insert(0, str(CV / "verify"))
sys.path.insert(0, str(CV / "protocol"))
import crypto_tx as ct  # noqa: E402
import jcs  # noqa: E402
import mldsa  # noqa: E402
from common import DOMAINS, ENVIRONMENT_FOR_NETWORK, GENESIS, evidence_digest, evidence_sha256, parse_time, subjects_digest  # noqa: E402
from trust import TrustStore  # noqa: E402

REPO = CV.parents[1]
SCHEMA_PATH = REPO / "protocol/v1/cloud-assessment.schema.json"
ENFORCEMENT_RANK = {"inform": 0, "warn": 1, "hard_deny": 2}
ALG_MLDSA, ALG_TEST_ED = "ML-DSA-87", "TEST-ONLY-ED25519"


def _ed_verify(public, message, signature):
    return ct.ed25519_verify(public, message, signature)


def _mldsa_verify(public, message, signature):
    return mldsa.BACKEND.verify(public, message, signature)


def signature_verifiers():
    """algorithm -> verifier, or None when no vetted backend exists (then the signature is UNVERIFIABLE)."""
    return {ALG_MLDSA: _mldsa_verify if mldsa.BACKEND.available() else None, ALG_TEST_ED: _ed_verify}


def _schema_errors(payload):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        import jsonschema
    except ImportError:  # pragma: no cover - structural fallback
        missing = [k for k in schema["required"] if k not in payload]
        extra = [k for k in payload if k not in schema["properties"]]
        return ["missing:" + ",".join(missing)] if missing else (["extra:" + ",".join(extra)] if extra else [])
    return [e.message for e in jsonschema.Draft202012Validator(schema).iter_errors(payload)][:3]


def _digest(record):
    return evidence_sha256(record)


class Registry:
    """Independent evidence store held by the verifier/evaluator (never by the server under test)."""

    def __init__(self, records):
        self.by_id = {r["evidence_id"]: r for r in records}
        self.records = records

    def retracted(self, record):
        return any(o.get("retracts") == record["evidence_id"] and
                   parse_time(o["observed_at"]) > parse_time(record["observed_at"]) for o in self.records)

    def eligibility(self, record, request, now):
        subjects = {(s["type"], s["id"]) for s in request["subjects"]}
        if (record["subject"]["type"], record["subject"]["id"]) not in subjects:
            return "subject_not_in_request"
        if record["network"] != request["network"]:
            return "wrong_network"
        if parse_time(record["observed_at"]) > now:
            return "not_yet_observed"
        if now > parse_time(record["valid_until"]):
            return "expired"
        if self.retracted(record):
            return "superseded"
        return None


def max_enforcement(record):
    tier, conf = record["provenance"]["tier"], record["confidence"]
    if tier == "historical_class" and conf >= 0.8:
        return "hard_deny"
    if tier == "lab_simulation" and record["provenance"].get("reproducible") and conf >= 0.8:
        return "hard_deny"
    if tier in ("historical_class", "lab_simulation") and conf >= 0.6:
        return "warn"
    return "inform"


def verify_signed_payload(signed, purpose, trust, now, *, allowed_algorithms, require_non_test_keys):
    """Return (payload_dict, key_entry, None) or (None, None, reason)."""
    if not isinstance(signed, dict) or set(signed) != {"canonical_payload", "signature", "key_id", "signing_algorithm"}:
        return None, None, "envelope_shape"
    payload_bytes, signature = signed["canonical_payload"], signed["signature"]
    if not isinstance(payload_bytes, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray)):
        return None, None, "envelope_shape"
    algorithm = signed["signing_algorithm"]
    if algorithm not in allowed_algorithms:
        return None, None, "algorithm_not_allowed"
    verifier = signature_verifiers().get(algorithm)
    if verifier is None:
        return None, None, "unsupported_signature_alg"  # recognised (e.g. ML-DSA-87) but cannot be verified here
    key, reason = trust.lookup(signed["key_id"], algorithm, purpose, now)
    if reason:
        return None, None, reason
    if require_non_test_keys and key.get("test_only"):
        return None, None, "test_key_not_allowed"
    if not verifier(TrustStore.public_bytes(key), DOMAINS[purpose] + bytes(payload_bytes), bytes(signature)):
        return None, None, "bad_signature"
    if not jcs.is_canonical(bytes(payload_bytes)):
        return None, None, "non_canonical_payload"
    return jcs.parse_strict(bytes(payload_bytes)), key, None


def verify(signed, request, registry, *, now_iso, mode="strict", trust=None, allowed_algorithms=None,
           require_non_test_keys=False, expected_quote_id=None, genesis_map=None):
    now = parse_time(now_iso)
    genesis_map = genesis_map or GENESIS
    trust = trust or TrustStore.test_issuers()
    allowed = allowed_algorithms or frozenset({ALG_MLDSA, ALG_TEST_ED})
    result = {"accepted": False, "discard_reason": None, "findings_accepted": [], "findings_rejected": [],
              "unsupported_safety_claims": [], "supported_safety_claims": [], "trusted_unverified_safety_claims": [],
              "evidence_used": [], "verified_evidence": [], "source_status": {}, "mode": mode, "signature": None}

    def discard(reason):
        result["accepted"] = False
        result["discard_reason"] = reason
        return result

    assessment, key, reason = verify_signed_payload(signed, "cloud_assessment", trust, now,
                                                    allowed_algorithms=allowed, require_non_test_keys=require_non_test_keys)
    if reason:
        return discard(reason)
    result["signature"] = {"algorithm": signed["signing_algorithm"], "key_id": signed["key_id"],
                           "test_only_key": bool(key.get("test_only"))}
    if _schema_errors(assessment):
        return discard("schema_invalid")
    if (assessment["message_sha256"] != request["message_sha256"]
            or assessment["transaction_sha256"] not in (None, request["transaction_sha256"])
            or assessment["intent_sha256"] not in (None, request["intent_sha256"])
            or assessment["subjects_sha256"] != subjects_digest(request["subjects"], request["network"])
            or (expected_quote_id is not None and assessment["quote_id"] != expected_quote_id)):
        return discard("binding_mismatch")
    if assessment["network"] != request["network"] or assessment["genesis_hash"] != genesis_map.get(request["network"]):
        return discard("network_mismatch")
    if assessment["environment"] != ENVIRONMENT_FOR_NETWORK[request["network"]] or \
            assessment["environment"] not in key["environments"]:
        return discard("environment_mismatch")
    if assessment["data_scope"] != request["data_scope"]:
        return discard("data_scope_mismatch")
    if not (parse_time(assessment["issued_at"]) <= now < parse_time(assessment["expires_at"])):
        return discard("expired_or_not_yet_valid")
    result["accepted"] = True
    sources = {s["source_id"]: s for s in assessment["sources"]}
    for source_id, source in sources.items():
        record = registry.by_id.get(source_id)
        ok = record is not None and _digest(record) == source["evidence_sha256"]
        result["source_status"][source_id] = "digest_ok" if ok else "digest_mismatch_or_unknown"
    # S7.1: evidence_digest is the digest of the union manifest of the cited records. It can only be recomputed
    # from records this verifier holds, so a cited source it cannot reproduce makes the digest unverifiable.
    if any(status != "digest_ok" for status in result["source_status"].values()) or             assessment["evidence_digest"] != evidence_digest([registry.by_id[sid] for sid in sources]):
        return discard("evidence_digest_mismatch")
    result["verified_evidence"] = sorted(
        sid for sid, status in result["source_status"].items()
        if status == "digest_ok" and registry.eligibility(registry.by_id[sid], request, now) is None
        and registry.by_id[sid]["claim"]["polarity"] in ("adverse", "benign")
        and max_enforcement(registry.by_id[sid]) in ("warn", "hard_deny"))
    for finding in assessment["findings"]:
        refs = finding["evidence_refs"]
        entry = {"code": finding["code"], "claimed_enforcement": finding["enforcement"], "evidence_refs": refs}
        if mode == "trusting":
            entry["effective_enforcement"] = finding["enforcement"]
            result["findings_accepted"].append(entry)
            result["evidence_used"].extend(refs)
            continue
        reason, effective, valid_refs = None, "inform", []
        if not refs:
            reason = "no_evidence_refs"
        for ref in refs:
            record = registry.by_id.get(ref)
            if ref not in sources or record is None or result["source_status"].get(ref) != "digest_ok":
                reason = "evidence_not_listed_or_digest_mismatch"
                break
            why = registry.eligibility(record, request, now)
            if why:
                reason = why
                break
            if finding["code"] == "EVIDENCE_CONFLICT":
                valid_refs.append(ref)
                continue
            if record["claim"]["polarity"] != "adverse" or record["claim"]["code"] != finding["code"]:
                reason = "evidence_does_not_support_claim"
                break
            effective = max_enforcement(record)
            valid_refs.append(ref)
        if finding["code"] == "EVIDENCE_CONFLICT" and reason is None:
            polarities = {registry.by_id[r]["claim"]["polarity"] for r in valid_refs}
            effective = "warn" if {"adverse", "benign"} <= polarities else "inform"
        if reason:
            entry["rejected_reason"] = reason
            result["findings_rejected"].append(entry)
            continue
        if effective == "hard_deny" and finding["code"] != "EVIDENCE_CONFLICT":
            primary = registry.by_id[refs[0]]
            for other in registry.records:
                if (other["subject"] == primary["subject"] and other["claim"]["polarity"] == "benign"
                        and registry.eligibility(other, request, now) is None
                        and max_enforcement(other) in ("hard_deny", "warn")):
                    effective = "warn"
                    entry["conflict_capped"] = True
                    break
        if ENFORCEMENT_RANK[finding["enforcement"]] > ENFORCEMENT_RANK[effective]:
            entry["capped_by_provenance"] = True
        else:
            effective = finding["enforcement"]
        entry["effective_enforcement"] = effective
        result["findings_accepted"].append(entry)
        result["evidence_used"].extend(valid_refs)
    for claim in [c for c in assessment["coverage"]["passed"] if c.startswith("safety:")]:
        benign = [sid for sid in sources if sid in registry.by_id and registry.by_id[sid]["claim"]["polarity"] == "benign"
                  and registry.eligibility(registry.by_id[sid], request, now) is None]
        if mode == "trusting":
            result["trusted_unverified_safety_claims"].append({"claim": claim})
        elif benign:
            result["supported_safety_claims"].append({"claim": claim, "evidence": benign})
        else:
            result["unsupported_safety_claims"].append({"claim": claim})
    result["evidence_used"] = sorted(set(result["evidence_used"]))
    return result


def combine(local_decision, verification):
    """Final decision from the local decision and VERIFIED Cloud findings only. An assessment that is
    missing or not `accepted` has NO effect. Never ALLOW from Cloud; a local DENY is never lowered."""
    order = {"ALLOW": 0, "UNKNOWN": 1, "WARN": 2, "DENY": 3}
    final = local_decision
    if verification and verification["accepted"]:
        for finding in verification["findings_accepted"]:
            raised = {"hard_deny": "DENY", "warn": "WARN"}.get(finding["effective_enforcement"])
            if raised and order[raised] > order.get(final, 1):
                final = raised
    return final


def b64(data):
    return base64.b64encode(data).decode()
