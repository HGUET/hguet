#!/usr/bin/env python3
"""Compare Local Offline, Local + RPC and Local + Cloud on the SAME scenarios.

  python testing/cloud/compare.py --report testing/reports/latest/report.json [--out DIR]

Input: the report written by testing/runner/run_benchmark.py (real CLI results). The Cloud
column is computed per SOURCE KIND and per profile; tables of different source kinds are never
merged. Only `local_offline` and the transport-failure part of `local_rpc` are measurements of the
real CLI; everything under `local_cloud.reference_mock` is a MODEL (composition rules applied to
chosen mock behaviours), and `real_server` / `independent_proof` report "unavailable" until they exist.
"""
import argparse
import json
import sys
from pathlib import Path

TESTING = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(TESTING / "runner"), str(TESTING / "cloud"), str(TESTING / "mocks")]
import cloud_mock  # noqa: E402
import evaluator  # noqa: E402
import run_benchmark as rb  # noqa: E402

DISCLAIMER = {
    "local_offline": "MEASURED: real hguet binary, offline",
    "local_rpc": "MEASURED but limited: the CLI can only be driven to RPC transport failures without weakening TLS; "
                 "successful-simulation enrichment is covered by Rust unit tests, not here",
    "reference_mock": "MODEL: deterministic stand-in + documented composition rules; NOT evidence about a real Cloud",
    "real_server": "UNAVAILABLE: no Cloud client in the CLI and no verifier integrated",
    "independent_proof": "UNAVAILABLE unless reviewed proof files exist for a scenario",
}


def load_scenarios():
    out = {}
    for directory in ("scenarios", "scenarios-regression"):
        for path in sorted((TESTING / directory).glob("*.json")):
            scenario = json.loads(path.read_text(encoding="utf-8"))
            out[scenario["id"]] = scenario
    return out


def with_decision(row, decision):
    clone = dict(row)
    clone["decision"] = decision
    clone["checks"] = dict(row["checks"])  # only decision-based summaries are read from the clone
    return clone


def summarize(rows):
    m = rb.metrics(rows)
    s = m["summary"]
    keep = ("false_block_rate", "bad_denied", "bad_allowed_UNSAFE", "unknown_kept_unknown",
            "unknown_overclaimed_as_deny", "good_left_unknown", "good_resolved_as_allow", "unknown_allowed_UNSAFE")
    return {"confusion_matrix": m["confusion_matrix"], "summary": {k: s[k] for k in keep}}


def compare(report, scenarios):
    rows = [r for r in report["results"] if r["id"] in scenarios]
    result = {
        "format": "hguet-cloud-comparison/1",
        "never_merged": "each source kind is its own table; no combined or averaged figure exists",
        "disclaimers": DISCLAIMER,
        "scenario_count": len(rows),
        "local_offline": {"source": "measured", "metrics": summarize(rows)},
    }
    rpc_rows = [r for r in rows if scenarios[r["id"]]["input"]["rpc"]["mode"] == "mock"]
    result["local_rpc"] = {
        "source": "measured_limited",
        "scenarios_with_rpc_transport_failure": [r["id"] for r in rpc_rows],
        "decisions": {r["id"]: r["decision"] for r in rpc_rows},
        "successful_simulation": "not_measurable_through_cli",
    }
    cloud = {}
    for source in evaluator.all_sources():
        table = {"disclaimer": DISCLAIMER[source.kind]}
        if source.kind == "reference_mock":
            table["profiles"] = {}
            for profile in source.profiles():
                combined = []
                unsafe_allow = false_block_added = bad_uplift = 0
                for row in rows:
                    scenario = scenarios[row["id"]]
                    got = source.assess(scenario, row, profile)
                    decision, notes = cloud_mock.combine(row["decision"], row["message_sha256"], got.assessment)
                    combined.append(with_decision(row, decision))
                    unsafe_allow += decision == "ALLOW" and row["decision"] != "ALLOW"
                    false_block_added += (scenario["truth"]["label"] == "GOOD" and decision == "DENY"
                                          and row["decision"] != "DENY")
                    bad_uplift += (scenario["truth"]["label"] == "BAD" and decision == "DENY"
                                   and row["decision"] != "DENY")
                table["profiles"][profile] = {
                    "metrics": summarize(combined),
                    "ALLOW_created_by_cloud": unsafe_allow,
                    "good_scenarios_blocked_only_because_of_cloud": false_block_added,
                    "bad_scenarios_denied_only_because_of_cloud": bad_uplift,
                }
        else:
            reasons = {}
            for row in rows:
                got = source.assess(scenarios[row["id"]], row)
                reasons.setdefault((got.available, got.reason), []).append(row["id"])
            table["status"] = [{"available": avail, "reason": reason, "scenarios": len(ids)}
                               for (avail, reason), ids in sorted(reasons.items())]
        cloud[source.kind] = table
    result["local_cloud"] = cloud
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--report", default=str(TESTING / "reports/latest/report.json"))
    parser.add_argument("--out", default=None)
    args = parser.parse_args()
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    comparison = compare(report, load_scenarios())
    out = Path(args.out) if args.out else Path(args.report).parent
    out.mkdir(parents=True, exist_ok=True)
    (out / "cloud_comparison.json").write_text(json.dumps(comparison, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    off = comparison["local_offline"]["metrics"]["summary"]
    print("Cloud comparison over %d scenarios (sources never merged)" % comparison["scenario_count"])
    print("  [MEASURED] local_offline: BAD denied %d/%d, GOOD false blocks %d/%d, UNKNOWN overclaimed %d/%d" % (
        off["bad_denied"]["num"], off["bad_denied"]["den"], off["false_block_rate"]["num"], off["false_block_rate"]["den"],
        off["unknown_overclaimed_as_deny"]["num"], off["unknown_overclaimed_as_deny"]["den"]))
    for profile, data in comparison["local_cloud"]["reference_mock"]["profiles"].items():
        s = data["metrics"]["summary"]
        print("  [MODEL reference_mock/%s] BAD denied %d/%d (+%d via cloud), GOOD blocked +%d, ALLOW created by cloud %d" % (
            profile, s["bad_denied"]["num"], s["bad_denied"]["den"], data["bad_scenarios_denied_only_because_of_cloud"],
            data["good_scenarios_blocked_only_because_of_cloud"], data["ALLOW_created_by_cloud"]))
    for kind in ("real_server", "independent_proof"):
        print("  [%s] %s" % (kind, comparison["local_cloud"][kind]["status"][0]["reason"]))
    created = sum(d["ALLOW_created_by_cloud"] for d in comparison["local_cloud"]["reference_mock"]["profiles"].values())
    return 1 if created else 0


if __name__ == "__main__":
    sys.exit(main())
