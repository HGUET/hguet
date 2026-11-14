"""Client-side acceptance rules for a signed CloudAssessment (the verifier under test's counterpart).

These rules decide what a CLI may believe, independent of ground truth. Ground truth is used only
afterwards, by the scorer, to judge whether the accepted/rejected outcome was right.

Pipeline (first failure discards the WHOLE assessment, with a machine-readable reason):
  R1 envelope shape            R2 signature algorithm supported   R3 key pinned
  R4 signature valid           R5 schema-conformant               R6 binding: message, transaction,
  network, genesis, subjects   R7 freshness window
Then, per finding (strict mode only; `trusting` mode skips this to expose the harm of blind trust):
  R8  every evidence_ref must be listed in `sources` and its recomputed digest must match the fixture
  R9  the cited record must be eligible: same network, inside its validity window, not retracted,
      subject present in the request, polarity adverse, same claim code
  R11 a hard_deny is capped at warn while strong, eligible benign evidence for the same subject stands
  R10 enforcement is capped by provenance: hard_deny needs historical_class or lab_simulation
      (reproducible for lab) with confidence >= 0.8; warn needs >= 0.6; hypothetical can only inform
Safety claims (`coverage.passed` entries starting with `safety:`) are accepted as information only
when a benign eligible record supports them; they NEVER yield ALLOW. Unsupported ones are counted.
"""
import hashlib
import json
import sys
from pathlib import Path

CV = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(CV.parent / "lib"))
sys.path.insert(0, str(CV / "server"))
import crypto_tx as ct  # noqa: E402
import reference_server as rs  # noqa: E402

REPO = CV.parents[1]
SCHEMA_PATH = REPO / "protocol/v1/cloud-assessment.schema.json"
ENFORCEMENT_RANK = {"inform": 0, "warn": 1, "hard_deny": 2}


def _ed25519_verifier(public_b58, message, signature_b58):
    try:
        return ct.ed25519_verify(ct.b58decode(public_b58), message, ct.b58decode(signature_b58))
    except (ValueError, IndexError):
        return False


# alg -> verifier(public_key, message, signature) ; None means "recognised but not implemented here"
SIGNATURE_ALGORITHMS = {"reference-ed25519-v1": _ed25519_verifier, "ml-dsa-87": None}
PINNED_KEYS = {rs.KEY_ID: (rs.ALG, rs.signer_public_b58())}


def _schema_errors(assessment):
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    try:
        import jsonschema
    except ImportError:  # pragma: no cover - fall back to the structural subset
        missing = [k for k in schema["required"] if k not in assessment]
        extra = [k for k in assessment if k not in schema["properties"]]
        return ["missing:" + ",".join(missing)] if missing else (["extra:" + ",".join(extra)] if extra else [])
    validator = jsonschema.Draft202012Validator(schema)
    return [e.message for e in validator.iter_errors(assessment)][:3]


def _digest(record):
    return hashlib.sha256(ct.canonical_json(record)).hexdigest()


class Registry:
    """Independent evidence store held by the verifier/evaluator (never by the server under test)."""

    def __init__(self, records):
        self.by_id = {r["evidence_id"]: r for r in records}
        self.records = records

    def retracted(self, record):
        return any(o.get("retracts") == record["evidence_id"] and
                   rs.parse_time(o["observed_at"]) > rs.parse_time(record["observed_at"]) for o in self.records)

    def eligibility(self, record, request, now):
        """Return None if usable as evidence for this request, else the reason string."""
        subjects = {(s["type"], s["id"]) for s in request["subjects"]}
        if (record["subject"]["type"], record["subject"]["id"]) not in subjects:
            return "subject_not_in_request"
        if record["network"] != request["network"]:
            return "wrong_network"
        if rs.parse_time(record["observed_at"]) > now:
            return "not_yet_observed"
        if now > rs.parse_time(record["valid_until"]):
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
    return "inform"  # hypothetical or weak


def verify(envelope, request, registry, *, now_iso, mode="strict", pinned=PINNED_KEYS):
    now = rs.parse_time(now_iso)
    result = {"accepted": False, "discard_reason": None, "findings_accepted": [], "findings_rejected": [],
              "unsupported_safety_claims": [], "supported_safety_claims": [], "trusted_unverified_safety_claims": [],
              "evidence_used": [], "verified_evidence": [], "source_status": {}, "mode": mode}

    def discard(reason):
        result["discard_reason"] = reason
        return result

    if not isinstance(envelope, dict) or set(envelope) != {"assessment", "signature"}:
        return discard("envelope_shape")
    assessment, signature = envelope["assessment"], envelope["signature"]
    if not isinstance(assessment, dict) or not isinstance(signature, dict):
        return discard("envelope_shape")
    alg = signature.get("alg")
    if alg not in SIGNATURE_ALGORITHMS:
        return discard("unknown_signature_alg")
    if SIGNATURE_ALGORITHMS[alg] is None:
        return discard("unsupported_signature_alg")  # recognised (ml-dsa-87) but no verifier available
    key = pinned.get(signature.get("key_id"))
    if not key or key[0] != alg:
        return discard("unpinned_key")
    if not SIGNATURE_ALGORITHMS[alg](key[1], rs.DOMAIN + ct.canonical_json(assessment), signature.get("sig_b58", "")):
        return discard("bad_signature")
    if _schema_errors(assessment):
        return discard("schema_invalid")
    if (assessment["message_sha256"] != request["message_sha256"]
            or assessment["transaction_sha256"] not in (None, request["transaction_sha256"])
            or assessment["subjects_sha256"] != hashlib.sha256(ct.canonical_json(request["subjects"])).hexdigest()):
        return discard("binding_mismatch")
    if assessment["network"] != request["network"] or assessment["genesis_hash"] != rs.GENESIS.get(request["network"]):
        return discard("network_mismatch")
    if not (rs.parse_time(assessment["issued_at"]) <= now < rs.parse_time(assessment["expires_at"])):
        return discard("expired_or_not_yet_valid")
    result["accepted"] = True
    sources = {s["source_id"]: s for s in assessment["sources"]}
    support = []
    for source_id, source in sources.items():
        record = registry.by_id.get(source_id)
        ok = record is not None and _digest(record) == source["evidence_sha256"]
        result["source_status"][source_id] = "digest_ok" if ok else "digest_mismatch_or_unknown"
    # Independently verified evidence = cited, digest-matching, eligible records of a non-hypothetical tier.
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
            # R11: a verifier must not escalate to DENY while strong, eligible benign evidence for
            # the same subject stands unresolved; the accusation is capped at warn.
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
        support.extend(valid_refs)
    for claim in [c for c in assessment["coverage"]["passed"] if c.startswith("safety:")]:
        benign = [source_id for source_id in sources
                  if source_id in registry.by_id and registry.by_id[source_id]["claim"]["polarity"] == "benign"
                  and registry.eligibility(registry.by_id[source_id], request, now) is None]
        if mode == "trusting":
            result["trusted_unverified_safety_claims"].append({"claim": claim})  # believed without checking
        elif benign:
            result["supported_safety_claims"].append({"claim": claim, "evidence": benign})
        else:
            result["unsupported_safety_claims"].append({"claim": claim})
    result["evidence_used"] = sorted(set(result["evidence_used"]))
    return result


def combine(local_decision, verification):
    """Final decision from the local decision and VERIFIED Cloud findings. Never ALLOW from Cloud;
    a local DENY is never lowered; only an accepted hard_deny/warn can raise severity."""
    order = {"ALLOW": 0, "UNKNOWN": 1, "WARN": 2, "DENY": 3}
    final = local_decision
    if verification and verification["accepted"]:
        for finding in verification["findings_accepted"]:
            raised = {"hard_deny": "DENY", "warn": "WARN"}.get(finding["effective_enforcement"])
            if raised and order[raised] > order.get(final, 1):
                final = raised
    return final
