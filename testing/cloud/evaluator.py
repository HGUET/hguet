"""Independent Cloud evaluator interface (contract: testing/cloud/CONTRACT.md).

Three kinds of result sources exist and are NEVER merged, averaged or ranked against each
other; every result carries its `source_kind` and every report keeps them in separate tables:

  reference_mock      deterministic stand-in written by the benchmark authors. It proves what
                      the documented composition rules do under chosen behaviours (a model).
                      It says nothing about any real service.
  real_server         a live HGUET Cloud implementation. Not available yet: the CLI has no
                      Cloud client, the signed CloudAssessment verifier is not integrated, and
                      this phase performs no network I/O. The adapter exists so the contract
                      is fixed before the server is.
  independent_proof   facts established by a reference execution or proof that is independent
                      of both HGUET and the mock (for example a trusted simulator run or a
                      human-audited proof file). Not available until proofs are authored.

Nothing here signs, holds keys, spends funds or contacts a network.
"""
import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

TESTING = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TESTING / "mocks"))
import cloud_mock  # noqa: E402

SOURCE_KINDS = ("reference_mock", "real_server", "independent_proof")
RESULT_FORMAT = "hguet-cloud-eval-result/1"


@dataclass
class CloudResult:
    source_kind: str
    source_id: str
    profile: str
    available: bool
    reason: str = ""
    assessment: dict = None
    format: str = RESULT_FORMAT
    notes: list = field(default_factory=list)

    def __post_init__(self):
        if self.source_kind not in SOURCE_KINDS:
            raise ValueError("unknown source kind: %r" % self.source_kind)

    def to_json(self):
        return asdict(self)


class CloudSource:
    kind = None

    def profiles(self):
        return ["default"]

    def assess(self, scenario, local_row, profile="default"):  # pragma: no cover - interface
        raise NotImplementedError


# ------------------------------------------------------------- reference mock
def _profile_silent(scenario, row, digest, now):
    return None


def _profile_oracle(scenario, row, digest, now):
    # DELIBERATELY CIRCULAR: derived from ground truth, so it is only an UPPER BOUND on what any
    # perfect Cloud could add. Never report it as an achieved or expected improvement.
    bad = scenario["truth"]["label"] == "BAD"
    return cloud_mock.assessment(digest, now=now, finding={"code": "MOCK_ORACLE", "severity": "critical"} if bad else None)


def _profile_always_benign(scenario, row, digest, now):
    return cloud_mock.assessment(digest, now=now)


def _profile_always_adverse(scenario, row, digest, now):
    return cloud_mock.assessment(digest, now=now, finding={"code": "MOCK_ALWAYS_ADVERSE", "severity": "critical"})


def _profile_stale(scenario, row, digest, now):
    return cloud_mock.assessment(digest, now=now, expires_in=-60, finding={"code": "MOCK_STALE", "severity": "critical"})


def _profile_mismatched(scenario, row, digest, now):
    return cloud_mock.assessment(digest, now=now, bound_to="f" * 64, finding={"code": "MOCK_WRONG_TX", "severity": "critical"})


MOCK_PROFILES = {
    "silent": _profile_silent,
    "oracle_upper_bound": _profile_oracle,
    "always_benign": _profile_always_benign,
    "always_adverse": _profile_always_adverse,
    "stale": _profile_stale,
    "mismatched_binding": _profile_mismatched,
}


class ReferenceMock(CloudSource):
    kind = "reference_mock"

    def profiles(self):
        return list(MOCK_PROFILES)

    def assess(self, scenario, local_row, profile="silent"):
        digest = local_row["message_sha256"]
        assessment = MOCK_PROFILES[profile](scenario, local_row, digest, int(time.time()))
        return CloudResult(self.kind, "reference-mock-v1", profile, True, assessment=assessment,
                           notes=["MODEL: deterministic stand-in, not a measurement of any real service"])


# ---------------------------------------------------------------- real server
class RealServer(CloudSource):
    """Placeholder adapter. Performs NO network I/O in this phase."""
    kind = "real_server"

    def assess(self, scenario, local_row, profile="default"):
        endpoint = os.environ.get("HGUET_CLOUD_ENDPOINT")
        reason = ("no HGUET_CLOUD_ENDPOINT configured; the CLI has no Cloud client" if not endpoint else
                  "real-server evaluation needs the signed CloudAssessment verifier and an explicit "
                  "opt-in network phase; neither exists yet, so nothing was sent")
        return CloudResult(self.kind, "real-server-unconfigured", profile, False, reason=reason)


# ---------------------------------------------------------- independent proof
class IndependentProof(CloudSource):
    """Reads reviewed proof files `testing/cloud/proofs/<scenario>.json` if present.

    A proof states facts established outside HGUET and the mock, for example:
      {"scenario": "B-001", "established_by": "reference executor X, reviewed by Y",
       "message_sha256": "...", "adverse": true, "evidence": ["..."]}
    """
    kind = "independent_proof"

    def __init__(self, directory=None):
        self.directory = Path(directory) if directory else TESTING / "cloud" / "proofs"

    def assess(self, scenario, local_row, profile="default"):
        path = self.directory / (scenario["id"] + ".json")
        if not path.exists():
            return CloudResult(self.kind, "proof-files", profile, False,
                               reason="no independent proof authored for this scenario")
        proof = json.loads(path.read_text(encoding="utf-8"))
        if proof.get("message_sha256") != local_row["message_sha256"] or not proof.get("established_by"):
            return CloudResult(self.kind, "proof-files", profile, False,
                               reason="proof is not bound to this transaction or lacks provenance")
        finding = {"code": "PROVEN_ADVERSE", "severity": "critical"} if proof.get("adverse") else None
        assessment = cloud_mock.assessment(local_row["message_sha256"], finding=finding, expires_in=3600)
        return CloudResult(self.kind, "proof-files", profile, True, assessment=assessment,
                           notes=["established_by: %s" % proof["established_by"]])


def all_sources():
    return [ReferenceMock(), RealServer(), IndependentProof()]
