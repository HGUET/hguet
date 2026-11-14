"""Mock HGUET Cloud + REFERENCE combination model. NOT the product, NOT evidence.

The real CLI does not implement Cloud ("Cloud/payment commands are NOT implemented"),
so there is no Cloud behaviour to measure. This module provides:

  * `assessment(...)` - deterministic, UNSIGNED, simplified stand-ins for a Cloud
    enrichment (not the signed CloudAssessment schema),
  * `combine(...)`    - the documented composition rules (interoperability.md /
    verdict-schema.md) written out as a small reference function.

The benchmark asserts those RULES on top of REAL local HGUET decisions. A pass means
"the specified rule, applied to real local output, behaves as documented". It says
nothing about the effectiveness, accuracy or availability of a real Cloud server.
"""
import time

SEVERITY = {"ALLOW": 0, "UNKNOWN": 1, "WARN": 2, "DENY": 3}


def assessment(message_sha256, *, finding=None, expires_in=3600, bound_to=None, now=None):
    now = int(time.time()) if now is None else now
    return {
        "kind": "mock_cloud_assessment", "mock": True,
        "message_sha256": bound_to or message_sha256,
        "issued_at": now, "expires_at": now + expires_in,
        "finding": finding,  # None = "no adverse data", or {"code": ..., "severity": "critical"}
    }


def combine(local_decision, local_message_sha256, cloud, *, cloud_required=False, now=None):
    """Return (decision, notes). Rules: local hard DENY cannot be overridden; invalid, expired or
    mismatched Cloud evidence is discarded; Cloud can never create ALLOW from UNKNOWN; adverse
    valid Cloud data can only raise severity; a Cloud-required profile without valid Cloud
    evidence is UNKNOWN."""
    now = int(time.time()) if now is None else now
    notes = []
    valid = (cloud is not None and cloud.get("message_sha256") == local_message_sha256
             and cloud.get("expires_at", 0) > now)
    if cloud is not None and not valid:
        notes.append("cloud_discarded")
    if local_decision == "DENY":
        return "DENY", notes + ["local_hard_deny_not_overridable"]
    if not valid:
        if cloud_required:
            return "UNKNOWN", notes + ["cloud_required_but_unavailable"]
        return local_decision, notes
    if cloud.get("finding"):
        raised = "DENY" if cloud["finding"].get("severity") == "critical" else "WARN"
        decision = max(local_decision, raised, key=lambda d: SEVERITY.get(d, 1))
        return decision, notes + ["cloud_adverse_finding_raised_severity"]
    return local_decision, notes + ["cloud_benign_cannot_create_allow"]
