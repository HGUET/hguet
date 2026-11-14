#!/usr/bin/env python3
"""HGUET Security Benchmark runner: executes the REAL `hguet` binary on every scenario.

  python testing/runner/run_benchmark.py --hguet target/debug/hguet [--subset smoke|all]
                                         [--out testing/reports/latest]

Scoring dimensions are kept apart on purpose:
  1. decision       truth label vs the decision HGUET returned (confusion matrix)
  2. threat         BAD only: DENY *and* the required finding family present
  3. proven-safe    properties HGUET must positively prove (intent signature, signer roles, ...)
  4. uncertainty    UNKNOWN truth must stay UNKNOWN (never DENY, never ALLOW) with the reason
  5. signing block  invariants on the final gate; BLOCK-only is NEVER counted as detection
Exit status is 1 on any unexpected failure, invariant violation, runner error or stale
known-defect entry; XFAIL (documented defects) never hide in the totals.
"""
import argparse
import html
import json
import os
import shlex
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TESTING = ROOT / "testing"
sys.path.insert(0, str(TESTING / "mocks"))
import cloud_mock  # noqa: E402
import rpc_mock  # noqa: E402

DECISIONS = ["ALLOW", "WARN", "DENY", "UNKNOWN", "ERROR"]
CLASSES = ["GOOD", "BAD", "UNKNOWN"]
CLASS_PREDICTED_AS = {"GOOD": "ALLOW", "BAD": "DENY", "UNKNOWN": "UNKNOWN"}


# ------------------------------------------------------------------ execution
def write_inputs(scenario, directory):
    directory.mkdir(parents=True, exist_ok=True)
    data = scenario["input"]
    files = {"tx": directory / "tx.b64"}
    files["tx"].write_text(data["transaction"]["data"] + "\n", encoding="ascii", newline="\n")
    if data["intent"] is not None:
        files["intent"] = directory / "intent.json"
        files["intent"].write_text(json.dumps(data["intent"], indent=2, sort_keys=True) + "\n", encoding="utf-8",
                                   newline="\n")
    if data["policy_toml"] is not None:
        files["policy"] = directory / "policy.toml"
        files["policy"].write_text(data["policy_toml"], encoding="utf-8", newline="\n")
    return files


def build_commands(hguet, scenario, files, rpc_url):
    data = scenario["input"]
    base = [hguet, "check", str(files["tx"]), "--encoding", data["transaction"]["encoding"], "--mode", "local",
            "--network", data["network"], "--json"]
    if rpc_url is None:
        base.append("--offline")
    else:
        base += ["--rpc-url", rpc_url]
    # `check` requires an --intent argument even when none exists (the repository CI passes a
    # nonexistent path for the same reason); an absent file means "no intent supplied".
    base += ["--intent", str(files["intent"] if "intent" in files else files["tx"].with_name("absent-intent.json"))]
    if data["trusted_key"] and "intent" in files:
        base += ["--trusted-key", data["trusted_key"]]
    if "policy" in files:
        base += ["--policy", str(files["policy"])]
    commands = {"check": base}
    if "intent" in files and data["trusted_key"]:
        commands["signer_preflight"] = [
            hguet, "signer-preflight", str(files["tx"]), "--offline", "--encoding",
            data["transaction"]["encoding"], "--network", data["network"], "--intent", str(files["intent"]),
            "--trusted-key", data["trusted_key"], "--json"]
    return commands


def execute(command, timeout=60):
    started = time.monotonic()
    try:
        done = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        rc, out, err = done.returncode, done.stdout, done.stderr
    except subprocess.TimeoutExpired:
        rc, out, err = -9, "", "timeout"
    except OSError as exc:
        rc, out, err = -1, "", str(exc)
    try:
        parsed = json.loads(out) if out.strip() else None
    except ValueError:
        parsed = None
    return {"rc": rc, "stdout_json": parsed, "stderr": err[-500:], "seconds": round(time.monotonic() - started, 3)}


# -------------------------------------------------------------------- scoring
def walk(node):
    if isinstance(node, dict):
        for key, value in node.items():
            yield key, value
            yield from walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from walk(item)


def lookup(document, path):
    node = document
    for part in path.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None, False
    return node, True


def evaluate(scenario, run, preflight):
    out = run["stdout_json"]
    result = {"decision": "ERROR", "findings": [], "reasons": [], "invariants": {}, "checks": {}}
    if run["rc"] in (-1, -9) or not isinstance(out, dict):
        result["reasons"].append("runner/cli error: rc=%s stderr=%s" % (run["rc"], run["stderr"].strip()[:160]))
        result["failure_type"] = "error"
        return result
    verdict = out.get("verdict")
    if isinstance(verdict, dict) and verdict.get("decision") in DECISIONS:
        result["decision"] = verdict["decision"].upper()
        result["findings"] = [f.get("code") for f in verdict.get("findings", [])]
    elif out.get("code") in ("BAD_INPUT", "BAD_POLICY", "BAD_SIGNED_INTENT"):
        result["findings"] = [out.get("code")]
        result["reasons"].append("tool rejected the input: %s %s" % (out.get("code"), str(out.get("error"))[:120]))
    expect, truth = scenario["expect"], scenario["truth"]
    findings = set(result["findings"])
    checks = result["checks"]
    checks["decision_acceptable"] = result["decision"] in truth["acceptable_decisions"]
    checks["required_findings"] = all(any(code in findings for code in group) for group in expect["findings_required"])
    checks["forbidden_findings_absent"] = not (findings & set(expect["findings_forbidden"]))
    proven_ok = True
    for rule in expect["proven"]:
        value, found = lookup(out, rule["path"])
        ok = found and (value == rule["equals"] if "equals" in rule else rule["contains"] in (value or []))
        if not ok:
            proven_ok = False
            result["reasons"].append("proven property missing: %s" % json.dumps(rule))
    checks["proven_properties"] = proven_ok
    # The tool's parse of the wire must agree with the independently computed message hash,
    # otherwise the scenario builder (not HGUET) is wrong and the result is not trustworthy.
    independent = scenario["input"].get("message_sha256_independent")
    parsed_hash = (out.get("inspection") or {}).get("message_sha256")
    checks["builder_agrees_with_parser"] = independent is None or parsed_hash is None or parsed_hash == independent
    if not checks["builder_agrees_with_parser"]:
        result["reasons"].append("scenario builder/parser message hash disagreement")
    # ---- final signing block invariants (never feeds detection metrics)
    inv = result["invariants"]
    inv["exit_code_nonzero"] = run["rc"] != 0
    inv["no_spending_proof_claimed"] = not any(
        isinstance(v, bool) and v and k.endswith("_proven") and "spending" in k for k, v in walk(out))
    boundary = out.get("signing_boundary")
    inv["gate_blocks"] = True if boundary is None else (
        boundary.get("signing_gate") == "block" and boundary.get("automated_signing_permitted") is False)
    inv["no_secret_fields"] = not any(("secret" in str(k).lower() or "private" in str(k).lower())
                                      for k, _ in walk(out))
    if preflight is not None:
        refusal = (preflight["stdout_json"] or {}).get("signer_refusal", {})
        inv["signer_preflight_blocks"] = (
            preflight["rc"] == 20 and refusal.get("signing_gate") == "block"
            and refusal.get("signing_permitted") is False and refusal.get("signature_created") is False
            and refusal.get("transaction_broadcast") is False and refusal.get("signer_backend_invoked") is False)
    for name, ok in inv.items():
        if not ok:
            result["reasons"].append("INVARIANT VIOLATED: " + name)
    label = truth["label"]
    if result["decision"] == "ERROR":
        failure = "error"
    elif not all(inv.values()):
        failure = "invariant_violation"  # signing-block violations outrank every accuracy failure
    elif label == "GOOD" and result["decision"] == "DENY":
        failure = "false_block"
    elif label == "BAD" and result["decision"] == "ALLOW":
        failure = "unsafe_allow"
    elif label == "BAD" and result["decision"] != "DENY":
        failure = "missed_threat"
    elif label == "UNKNOWN" and result["decision"] == "DENY":
        failure = "unknown_overclaimed_as_deny"
    elif label == "UNKNOWN" and result["decision"] == "ALLOW":
        failure = "unsafe_allow"
    elif not checks["builder_agrees_with_parser"]:
        failure = "scenario_builder_error"
    elif not checks["required_findings"]:
        failure = "wrong_or_missing_reason"
    elif not checks["forbidden_findings_absent"]:
        failure = "unexpected_finding"
    elif not checks["proven_properties"]:
        failure = "missing_proof"
    else:
        failure = None
    result["failure_type"] = failure
    return result


def confusion(results):
    matrix = {c: {d: 0 for d in DECISIONS} for c in CLASSES}
    for item in results:
        matrix[item["truth"]][item["decision"]] += 1
    return matrix


def ratio(num, den):
    return {"num": num, "den": den, "value": (round(num / den, 4) if den else None)}


def metrics(results):
    matrix = confusion(results)
    per_class = {}
    for cls in CLASSES:
        predicted = CLASS_PREDICTED_AS[cls]
        tp = matrix[cls][predicted]
        support = sum(matrix[cls].values())
        predicted_total = sum(matrix[c][predicted] for c in CLASSES)
        precision, recall = ratio(tp, predicted_total), ratio(tp, support)
        f1 = None
        if precision["value"] and recall["value"]:
            f1 = round(2 * precision["value"] * recall["value"] / (precision["value"] + recall["value"]), 4)
        per_class[cls] = {"treated_as_prediction": predicted, "precision": precision, "recall": recall,
                          "f1": f1, "support": support}
    good = [r for r in results if r["truth"] == "GOOD"]
    bad = [r for r in results if r["truth"] == "BAD"]
    unknown = [r for r in results if r["truth"] == "UNKNOWN"]
    summary = {
        "false_block_rate": ratio(sum(r["decision"] == "DENY" for r in good), len(good)),
        "good_resolved_as_allow": ratio(sum(r["decision"] == "ALLOW" for r in good), len(good)),
        "good_left_unknown": ratio(sum(r["decision"] == "UNKNOWN" for r in good), len(good)),
        "bad_denied": ratio(sum(r["decision"] == "DENY" for r in bad), len(bad)),
        "bad_denied_with_required_reason": ratio(
            sum(r["decision"] == "DENY" and r["checks"].get("required_findings", False) for r in bad), len(bad)),
        "bad_not_denied_but_blocked_only": ratio(
            sum(r["decision"] in ("UNKNOWN", "WARN") for r in bad), len(bad)),
        "bad_allowed_UNSAFE": ratio(sum(r["decision"] == "ALLOW" for r in bad), len(bad)),
        "unknown_kept_unknown": ratio(sum(r["decision"] == "UNKNOWN" for r in unknown), len(unknown)),
        "unknown_with_expected_reason": ratio(
            sum(r["decision"] == "UNKNOWN" and r["checks"].get("required_findings", False) for r in unknown),
            len(unknown)),
        "unknown_overclaimed_as_deny": ratio(sum(r["decision"] == "DENY" for r in unknown), len(unknown)),
        "unknown_allowed_UNSAFE": ratio(sum(r["decision"] == "ALLOW" for r in unknown), len(unknown)),
        "overall_acceptable_decision": ratio(sum(r["checks"].get("decision_acceptable", False) for r in results),
                                             len(results)),
        "required_findings_present": ratio(sum(r["checks"].get("required_findings", False) for r in results),
                                           len(results)),
        "proven_properties_hold": ratio(sum(r["checks"].get("proven_properties", False) for r in results),
                                        len(results)),
        "signing_blocked_all_scenarios": ratio(sum(all(r["invariants"].values()) and bool(r["invariants"])
                                                   for r in results), len(results)),
        "cli_errors": ratio(sum(r["decision"] == "ERROR" for r in results), len(results)),
    }
    return {"confusion_matrix": matrix, "per_class": per_class, "summary": summary,
            "note": "BLOCK-only is reported in signing_blocked_all_scenarios and is not counted as detection."}


# ----------------------------------------------------------------- cloud model
def cloud_track(results_by_id):
    """Reference-rule assertions over REAL local decisions. Model only; see mocks/cloud_mock.py."""
    cases = []

    def case(name, scenario_id, expected, **kw):
        row = results_by_id.get(scenario_id)
        if not row:
            return
        cloud_kwargs = kw.pop("cloud", None)
        cloud = None if cloud_kwargs is None else cloud_mock.assessment(row["message_sha256"], **cloud_kwargs)
        decision, notes = cloud_mock.combine(row["decision"], row["message_sha256"], cloud, **kw)
        cases.append({"case": name, "scenario": scenario_id, "local_decision": row["decision"],
                      "combined": decision, "expected": expected, "notes": notes, "pass": decision == expected})

    case("local hard DENY is not overridden by benign Cloud", "B-001", "DENY", cloud={})
    case("benign Cloud cannot turn local UNKNOWN into ALLOW", "U-001", "UNKNOWN", cloud={})
    case("Cloud bound to another message is discarded", "U-001", "UNKNOWN", cloud={"bound_to": "0" * 64,
                                                                                    "finding": {"severity": "critical"}})
    case("expired Cloud assessment is discarded", "U-001", "UNKNOWN", cloud={"expires_in": -10,
                                                                              "finding": {"severity": "critical"}})
    case("valid adverse Cloud finding raises UNKNOWN to DENY", "U-001", "DENY",
         cloud={"finding": {"code": "MOCK_KNOWN_DRAINER", "severity": "critical"}})
    case("Cloud-required profile without Cloud is UNKNOWN", "G-001", "UNKNOWN", cloud=None, cloud_required=True)
    return {
        "label": "MOCK CLOUD / REFERENCE MODEL - not HGUET behaviour, not evidence of real Cloud effectiveness",
        "cases": cases, "passed": ratio(sum(c["pass"] for c in cases), len(cases))}


# --------------------------------------------------------------------- report
def repro_command(parts):
    return " ".join(shlex.quote(p) for p in parts)


def render_html(report):
    esc = html.escape
    m = report["metrics"]
    rows = []
    for r in report["results"]:
        css = {"PASS": "pass", "XFAIL": "xfail", "FAIL": "fail", "XPASS": "xpass"}[r["outcome"]]
        reasons = "".join("<li>%s</li>" % esc(x) for x in r["reasons"])
        rows.append(
            "<tr class='%s'><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>"
            "<tr class='detail'><td colspan='7'><details><summary>%s</summary><p>%s</p>"
            "<p><b>Findings:</b> %s</p><ul>%s</ul><p><b>Required (any-of groups):</b> %s</p>"
            "<p><b>Reproduce:</b></p><pre>%s</pre></details></td></tr>"
            % (css, esc(r["id"]), r["truth"], esc(r["decision"]), esc(r["outcome"]), esc(r.get("failure_type") or "-"),
               esc(r["title"]), esc(r["title"]), esc(r["rationale"]), esc(", ".join(r["findings"]) or "-"), reasons,
               esc(json.dumps(r["findings_required"])), esc("\n".join(r["repro"]))))
    matrix = m["confusion_matrix"]
    head = "".join("<th>%s</th>" % d for d in DECISIONS)
    body = "".join("<tr><th>%s</th>%s</tr>" % (
        c, "".join("<td class='cell%s'>%d</td>" % (" hot" if matrix[c][d] else "", matrix[c][d]) for d in DECISIONS))
        for c in CLASSES)
    cls_rows = "".join(
        "<tr><td>%s</td><td>%s</td><td>%d/%d</td><td>%d/%d</td><td>%s</td></tr>" % (
            c, v["treated_as_prediction"], v["precision"]["num"], v["precision"]["den"], v["recall"]["num"],
            v["recall"]["den"], "n/a" if v["f1"] is None else v["f1"]) for c, v in m["per_class"].items())
    summ = "".join("<tr><td>%s</td><td>%d / %d</td><td>%s</td></tr>" % (
        esc(k), v["num"], v["den"], "n/a" if v["value"] is None else "%.1f%%" % (100 * v["value"]))
        for k, v in m["summary"].items())
    cloud = report["cloud_mock_track"]
    cloud_rows = "".join("<tr class='%s'><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
        "pass" if c["pass"] else "fail", esc(c["case"]), c["local_decision"], c["combined"], c["expected"])
        for c in cloud["cases"])
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HGUET Security Benchmark</title><style>
:root{--bg:#fff;--fg:#14181f;--mut:#5b6573;--line:#d8dde6;--ok:#e6f4ea;--bad:#fde8e8;--warn:#fff4d6;--hot:#dbe7ff}
@media (prefers-color-scheme:dark){:root{--bg:#10141a;--fg:#e7ebf2;--mut:#9aa6b6;--line:#2b3441;--ok:#14301f;--bad:#3a1818;--warn:#3a3014;--hot:#1b2d52}}
body{font:15px/1.5 system-ui,sans-serif;margin:0 auto;max-width:1100px;padding:16px;background:var(--bg);color:var(--fg)}
table{border-collapse:collapse;width:100%%;margin:8px 0}td,th{border:1px solid var(--line);padding:4px 8px;text-align:left;vertical-align:top}
tr.pass{background:var(--ok)}tr.fail{background:var(--bad)}tr.xfail,tr.xpass{background:var(--warn)}tr.detail{background:none}
.cell.hot{background:var(--hot);font-weight:700}.mut{color:var(--mut)}pre{white-space:pre-wrap;word-break:break-all;font-size:12px}
.banner{border:2px solid var(--line);padding:8px 12px;margin:12px 0}h1,h2{margin:.6em 0 .2em}
</style></head><body>
<h1>HGUET Security Benchmark</h1>
<p class="mut">commit %s &middot; %s &middot; %d scenarios (%s) &middot; real <code>hguet</code> binary, BLOCK-only, synthetic data only</p>
<div class="banner"><b>Outcome:</b> %d PASS &middot; %d FAIL &middot; %d XFAIL (documented defects) &middot; %d XPASS.
BLOCK-only is a separate invariant and is <b>not</b> counted as threat detection.</div>
<h2>Confusion matrix (rows = ground truth, columns = HGUET decision)</h2>
<table><tr><th></th>%s</tr>%s</table>
<h2>Per-class metrics (GOOD&harr;ALLOW, BAD&harr;DENY, UNKNOWN&harr;UNKNOWN)</h2>
<table><tr><th>class</th><th>predicted as</th><th>precision</th><th>recall</th><th>F1</th></tr>%s</table>
<h2>Headline rates (numerator / denominator)</h2><table><tr><th>metric</th><th>n / d</th><th>rate</th></tr>%s</table>
<h2>Mock Cloud track</h2><div class="banner">%s</div>
<table><tr><th>rule</th><th>local</th><th>combined</th><th>expected</th></tr>%s</table>
<h2>Scenarios</h2><table><tr><th>id</th><th>truth</th><th>HGUET</th><th>outcome</th><th>failure type</th><th>title</th><th></th></tr>%s</table>
<h2>Limits of this benchmark</h2><ul>%s</ul></body></html>""" % (
        esc(report["meta"]["commit"][:12]), esc(report["meta"]["generated_utc"]), len(report["results"]),
        esc(report["meta"]["subset"]), report["totals"]["PASS"], report["totals"]["FAIL"], report["totals"]["XFAIL"],
        report["totals"]["XPASS"], head, body, cls_rows, summ, esc(cloud["label"]), cloud_rows, "".join(rows),
        "".join("<li>%s</li>" % esc(x) for x in report["limits"]))


# ----------------------------------------------------------------------- main
def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--hguet", default=str(ROOT / "target/debug/hguet"))
    parser.add_argument("--scenarios", default=None, help="explicit directory (overrides --suite)")
    parser.add_argument("--suite", choices=("main", "regression", "all"), default="main",
                        help="main = the 60 original scenarios; regression = paired cases for fixed defects")
    parser.add_argument("--subset", choices=("smoke", "all"), default="all")
    parser.add_argument("--out", default=str(TESTING / "reports/latest"))
    parser.add_argument("--known-defects", default=str(TESTING / "known_defects.json"))
    args = parser.parse_args()
    hguet = str(Path(args.hguet).resolve())
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    known = json.loads(Path(args.known_defects).read_text()) if Path(args.known_defects).exists() else {}
    directories = [Path(args.scenarios)] if args.scenarios else {
        "main": [TESTING / "scenarios"], "regression": [TESTING / "scenarios-regression"],
        "all": [TESTING / "scenarios", TESTING / "scenarios-regression"]}[args.suite]
    scenarios = [json.loads(p.read_text(encoding="utf-8")) for d in directories for p in sorted(d.glob("*.json"))]
    if args.subset == "smoke":
        scenarios = [s for s in scenarios if s["smoke"]]
    results, errors = [], []
    for scenario in scenarios:
        files = write_inputs(scenario, out / "inputs" / scenario["id"])
        rpc = scenario["input"]["rpc"]
        mock = rpc_mock.MockRpc(rpc["behavior"]) if rpc["mode"] == "mock" else None
        try:
            if mock:
                mock.__enter__()
            commands = build_commands(hguet, scenario, files, mock.url if mock else None)
            run = execute(commands["check"])
            preflight = execute(commands["signer_preflight"]) if "signer_preflight" in commands else None
        finally:
            if mock:
                mock.__exit__(None, None, None)
        scored = evaluate(scenario, run, preflight)
        entry = scenario["id"]
        outcome = "PASS" if scored["failure_type"] is None else "FAIL"
        if entry in known and scored["failure_type"] != "invariant_violation":
            # A documented defect may be an accuracy gap, but NEVER a violated signing-block invariant.
            outcome = "XFAIL" if outcome == "FAIL" else "XPASS"
        out_json = run["stdout_json"] if isinstance(run["stdout_json"], dict) else {}
        results.append({
            "id": entry, "title": scenario["title"], "category": scenario["category"], "truth": scenario["truth"]["label"],
            "rationale": scenario["rationale"], "smoke": scenario["smoke"],
            "evidence_level": scenario["truth"]["evidence_level"],
            "decision": scored["decision"], "findings": scored["findings"], "reasons": scored["reasons"],
            "checks": scored["checks"], "invariants": scored["invariants"], "failure_type": scored["failure_type"],
            "outcome": outcome, "known_defect": known.get(entry), "exit_code": run["rc"],
            "preflight_exit_code": preflight["rc"] if preflight else None, "seconds": run["seconds"],
            "message_sha256": (out_json.get("inspection") or {}).get("message_sha256")
            or scenario["input"]["message_sha256_independent"] or "0" * 64,
            "findings_required": scenario["expect"]["findings_required"],
            "repro": [repro_command(c) for c in commands.values()],
        })
        if scored["decision"] == "ERROR":
            errors.append({"id": entry, "reasons": scored["reasons"], "stderr": run["stderr"]})
    by_id = {r["id"]: r for r in results}
    totals = {k: sum(r["outcome"] == k for r in results) for k in ("PASS", "FAIL", "XFAIL", "XPASS")}
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    version = subprocess.run([hguet, "--version"], capture_output=True, text=True).stdout.strip()
    report = {
        "meta": {"format": "hguet-bench-report/1", "commit": commit or "unknown", "hguet_version": version,
                 "subset": args.subset, "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "hguet_binary": hguet, "rerun": "python testing/runner/run_benchmark.py --hguet %s --subset %s"
                 % (hguet, args.subset)},
        "totals": totals, "metrics": metrics(results), "cloud_mock_track": cloud_track(by_id),
        "known_defects_registry": known, "errors": errors, "results": results,
        "limits": [
            "Offline CLI scenarios only: successful RPC simulation cannot be driven through the real CLI without trusting a custom CA (weakening TLS), so RPC enrichment is covered by Rust unit tests, not by this benchmark.",
            "The Cloud track checks documented composition rules on a mock; the CLI has no Cloud client. It is not evidence about a real server.",
            "ALLOW is structurally unreachable in the offline prototype; GOOD scenarios therefore score as UNKNOWN at best. 'good_left_unknown' is reported, not hidden.",
            "Ground truth was authored from threat semantics by the benchmark author; it is independent of HGUET output but not independently reviewed.",
            "60 scenarios give wide uncertainty (e.g. 1 miss in 25 is 4%); do not extrapolate rates to real traffic.",
        ]}
    (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "report.html").write_text(render_html(report), encoding="utf-8")
    m = report["metrics"]["summary"]
    print("HGUET Security Benchmark  commit=%s  scenarios=%d (%s)" % (report["meta"]["commit"][:10], len(results), args.subset))
    print("  outcome: %(PASS)d PASS  %(FAIL)d FAIL  %(XFAIL)d XFAIL  %(XPASS)d XPASS" % totals)
    for key in ("false_block_rate", "bad_denied", "bad_denied_with_required_reason", "bad_not_denied_but_blocked_only",
                "bad_allowed_UNSAFE", "unknown_kept_unknown", "unknown_overclaimed_as_deny", "good_left_unknown",
                "signing_blocked_all_scenarios", "cli_errors"):
        print("  %-34s %d/%d" % (key, m[key]["num"], m[key]["den"]))
    cloud = report["cloud_mock_track"]["passed"]
    print("  [MOCK CLOUD reference rules] %d/%d" % (cloud["num"], cloud["den"]))
    for r in results:
        if r["outcome"] in ("FAIL", "XPASS"):
            print("  %s %s truth=%s got=%s type=%s | %s" % (r["outcome"], r["id"], r["truth"], r["decision"],
                                                          r["failure_type"], "; ".join(r["reasons"])[:200]))
    print("  report: %s" % (out / "report.html"))
    bad_cloud = any(not c["pass"] for c in report["cloud_mock_track"]["cases"])
    failed = totals["FAIL"] or totals["XPASS"] or errors or bad_cloud
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
