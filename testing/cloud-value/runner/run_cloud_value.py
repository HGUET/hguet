#!/usr/bin/env python3
"""Cloud Value Benchmark v1 runner.

  python testing/cloud-value/runner/run_cloud_value.py --hguet target/debug/hguet [--out DIR]
         [--enable-real-server --real-server-url https://... ]

Measures what a Cloud adds (or wrongly adds) on top of the REAL local CLI, over 100 scenarios whose
decisive facts are not in the transaction. Sources are reported in separate sections and never merged:
  local              real `hguet check --offline`                      MEASURED
  rpc                real `hguet check --rpc-url <unreachable mock>`   MEASURED (transport failure only)
  reference_mock     reference server profiles x verifier modes        MODEL
  real_server        the real HGUET Server                             UNAVAILABLE unless explicitly enabled
Ground truth is loaded only by the scorer; components receive `inputs/` documents and the request.
"""
import argparse
import html
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path

CV = Path(__file__).resolve().parents[1]
TESTING = CV.parent
for sub in ("runner", "mocks"):
    sys.path.insert(0, str(TESTING / sub))
for sub in ("server", "verify", "labeling"):
    sys.path.insert(0, str(CV / sub))
import assessment_rules as rules  # noqa: E402
import independent_labeler  # noqa: E402
import real_server  # noqa: E402
import reference_server as rs  # noqa: E402
import rpc_mock  # noqa: E402
import run_benchmark as rb  # noqa: E402

SEV = {"ALLOW": 0, "UNKNOWN": 1, "WARN": 2, "DENY": 3, "ERROR": 1}
MOCK_PROFILES = ("strict", "naive", "oversell", "silent")
VERIFIER_MODES = ("strict", "trusting")


def load(directory, prefix):
    return {p.stem: json.loads(p.read_text(encoding="utf-8")) for p in sorted((CV / directory).glob(prefix + "*.json"))}


def leak_guard(inputs, truths, evidence):
    """No hidden label or canary may appear in anything a component can see."""
    visible = json.dumps(inputs, sort_keys=True) + json.dumps(evidence, sort_keys=True)
    for truth in truths.values():
        if truth["canary"] in visible:
            raise SystemExit("LEAK: ground-truth canary %s found in component-visible data" % truth["canary"])
    forbidden = ('"truth"', '"acceptable_final"', '"decisive_evidence"', '"threat_present"', '"expected_verifier_discards"')
    for needle in forbidden:
        if needle in visible:
            raise SystemExit("LEAK: forbidden ground-truth key %s present in component-visible data" % needle)


def apply_tamper(envelope, kind, request):
    """Harness-side tampering of an otherwise correct answer (tests the VERIFIER, not the server)."""
    if envelope is None or kind is None:
        return envelope
    body = json.loads(json.dumps(envelope["assessment"]))
    if kind == "bad_signature":
        sig = ct_flip(envelope["signature"]["sig_b58"])
        return {"assessment": body, "signature": dict(envelope["signature"], sig_b58=sig)}
    if kind == "wrong_binding":
        body["message_sha256"] = "0" * 64
    elif kind == "unsupported_safe_claim":
        body["findings"] = []
        body["coverage"]["passed"] = ["safety:subject_reputable"]
        body["coverage"]["unknown"] = []
    elif kind == "expired_assessment":
        body["expires_at"] = "2026-10-31T23:00:00Z"
    elif kind == "wrong_network_assessment":
        body["network"] = "mainnet"
        body["genesis_hash"] = rs.GENESIS["mainnet"]
    return rs.sign_envelope(body)  # a VALID signature over a wrong or dishonest body


def ct_flip(sig_b58):
    sys.path.insert(0, str(TESTING / "lib"))
    import crypto_tx as ct
    raw = bytearray(ct.b58decode(sig_b58))
    raw[0] ^= 1
    return ct.b58encode(bytes(raw))


# ------------------------------------------------------------------ local runs
def run_local(hguet, inputs, outdir, rpc_url=None):
    scenario = {"id": inputs["id"], "input": inputs}
    files = rb.write_inputs(scenario, outdir / "inputs" / inputs["id"])
    commands = rb.build_commands(hguet, scenario, files, rpc_url)
    run = rb.execute(commands["check"])
    out = run["stdout_json"] if isinstance(run["stdout_json"], dict) else {}
    verdict = out.get("verdict") or {}
    decision = verdict.get("decision", "ERROR")
    return {"decision": decision, "findings": [f.get("code") for f in verdict.get("findings", [])],
            "rc": run["rc"], "seconds": run["seconds"], "repro": rb.repro_command(commands["check"]),
            "signing_blocked": run["rc"] != 0 and (out.get("signing_boundary") is None or
                                                   out["signing_boundary"].get("automated_signing_permitted") is False)}


# ---------------------------------------------------------------- cloud config
def run_cloud_config(source, mode, inputs, truths, local, registry):
    rows = []
    for sid, inp in inputs.items():
        request = inp["cloud_request"]
        envelope = source.assess(request, inp["clock"])
        tamper = inp["cloud_harness"]["tamper"]
        if getattr(source, "kind", "") == "real_server" and tamper:
            rows.append({"id": sid, "not_applicable": "tamper scenarios test the verifier, not the server"})
            continue
        if envelope is not None:
            envelope = apply_tamper(envelope, tamper, request)
        verification = rules.verify(envelope, request, registry, now_iso=inp["clock"], mode=mode) if envelope else None
        strict_view = rules.verify(envelope, request, registry, now_iso=inp["clock"], mode="strict") if envelope else None
        claimed_accusations = []
        if envelope:
            claimed_accusations = [f for f in envelope["assessment"]["findings"] if f["enforcement"] in ("hard_deny", "warn")]
        final = rules.combine(local[sid]["decision"], verification)
        rows.append({
            "id": sid, "answered": envelope is not None, "final": final, "verification": verification,
            "claimed_accusations": len(claimed_accusations),
            "unsupported_claims_emitted": len(strict_view["unsupported_safety_claims"]) if strict_view else 0,
            "unsupported_claims_believed": len(verification["trusted_unverified_safety_claims"]) if (
                verification and mode == "trusting" and strict_view["unsupported_safety_claims"]) else 0,
            "latency_s": getattr(source, "last_latency_s", None), "cost": getattr(source, "cost_units", None),
        })
    return rows


# --------------------------------------------------------------------- scoring
def ratio(num, den):
    return {"num": num, "den": den, "value": round(num / den, 4) if den else None}


def score(rows, truths, local):
    applicable = [r for r in rows if not r.get("not_applicable")]
    t = lambda r: truths[r["id"]]  # noqa: E731
    L = lambda r: local[r["id"]]["decision"]  # noqa: E731
    final = lambda r: r["final"]  # noqa: E731
    room = [r for r in applicable if t(r)["label"] == "BAD" and not t(r)["tamper"]
            and L(r) not in t(r)["acceptable_final"]]
    add_tp = [r for r in room if final(r) in t(r)["acceptable_final"] and final(r) != L(r)]
    nonbad = [r for r in applicable if t(r)["label"] != "BAD"]
    add_fp = [r for r in nonbad if SEV.get(final(r), 1) > SEV.get(L(r), 1) and final(r) not in t(r)["acceptable_final"]]
    accusations = []
    for r in applicable:
        v = r.get("verification")
        if v and v["accepted"]:
            for f in v["findings_accepted"]:
                if f["effective_enforcement"] in ("hard_deny", "warn") and f["code"] != "EVIDENCE_CONFLICT":
                    if t(r)["label"] != "BAD" and final(r) in t(r)["acceptable_final"]:
                        continue  # a warning that the truth itself allows (e.g. unresolved conflict) is not a false accusation
                    accusations.append((r, f))
    correct_attr = [(r, f) for r, f in accusations if t(r)["label"] == "BAD"
                    and set(t(r)["decisive_evidence"]) <= set(r["verification"]["evidence_used"])]
    unknown_rows = [r for r in applicable if t(r)["label"] == "UNKNOWN"]
    unknown_ok = [r for r in unknown_rows if final(r) in t(r)["acceptable_final"]]
    cov_rows = [r for r in applicable if t(r)["decisive_evidence"] and not t(r)["tamper"]
                and t(r)["requires_cloud_evidence"]]
    cov_hit = [r for r in cov_rows if r.get("verification") and r["verification"]["accepted"]
               and set(r["verification"]["verified_evidence"]) & set(t(r)["decisive_evidence"])]
    tamper_rows = [r for r in applicable if t(r)["tamper"]]
    tamper_trusted = [r for r in tamper_rows if (final(r) != L(r) and t(r)["tamper"] != "unsupported_safe_claim")
                      or final(r) == "ALLOW"]
    rejected_attempts = [r for r in nonbad if r.get("claimed_accusations") and SEV.get(final(r), 1) <= SEV.get(L(r), 1)]
    answered = [r for r in applicable if r.get("answered")]
    latencies = [r["latency_s"] for r in answered if r.get("latency_s") is not None]
    cost_total = sum(r["cost"] for r in answered if r.get("cost") is not None) if answered else None
    useful = [r for r in add_tp if r in [x for x, _ in correct_attr]]
    reviewed = [r for r in useful if t(r)["labeling"]["independent_review"]["reviewers"]]
    return {
        "scenarios_applicable": len(applicable),
        "additional_true_positive": ratio(len(add_tp), len(room)),
        "additional_false_positive": ratio(len(add_fp), len(nonbad)),
        "false_accusation_rate": ratio(len(add_fp), len(nonbad)),
        "accusation_attempts_blocked_by_verifier": ratio(len(rejected_attempts), len(nonbad)),
        "correct_evidence_attribution": ratio(len(correct_attr), len(accusations)),
        "unsupported_safety_claims_emitted": ratio(sum(1 for r in applicable if r.get("unsupported_claims_emitted")), len(applicable)),
        "unsupported_safety_claims_believed": ratio(sum(1 for r in applicable if r.get("unsupported_claims_believed")), len(applicable)),
        "unknown_handling_correct": ratio(len(unknown_ok), len(unknown_rows)),
        "coverage_gained_from_verified_evidence": ratio(len(cov_hit), len(cov_rows)),
        "tampered_assessments_wrongly_trusted": ratio(len(tamper_trusted), len(tamper_rows)),
        "allow_created": ratio(sum(final(r) == "ALLOW" for r in applicable), len(applicable)),
        "availability": ratio(len(answered), len(applicable)),
        "latency_ms_mean": round(1000 * statistics.mean(latencies), 4) if latencies else None,
        "latency_ms_p95": round(1000 * sorted(latencies)[int(0.95 * (len(latencies) - 1))], 4) if latencies else None,
        "cost_units_total": cost_total,
        "useful_findings_truth_confirmed": len(useful),
        "useful_findings_independently_reviewed": len(reviewed),
        "cost_per_truth_confirmed_useful_finding": round(cost_total / len(useful), 3) if (cost_total and useful) else None,
        "cost_per_independently_reviewed_useful_finding": None if not reviewed else round(cost_total / len(reviewed), 3),
    }


def local_only_score(decisions, truths, local):
    rows = [{"id": sid, "final": d, "answered": False} for sid, d in decisions.items()]
    return score(rows, truths, local)


# ----------------------------------------------------------------- categories
def category_table(inputs, truths, local, configs):
    table = {}
    for sid, truth in truths.items():
        cat = table.setdefault(truth["category"], {"scenarios": 0, "local": {}, "additional_tp": {}, "additional_fp": {}})
        cat["scenarios"] += 1
        d = local[sid]["decision"]
        cat["local"][d] = cat["local"].get(d, 0) + 1
        for name, rows in configs.items():
            row = next((r for r in rows if r["id"] == sid), None)
            if not row or row.get("not_applicable"):
                continue
            final = row["final"]
            if truth["label"] == "BAD" and not truth["tamper"] and d not in truth["acceptable_final"] \
                    and final in truth["acceptable_final"] and final != d:
                cat["additional_tp"][name] = cat["additional_tp"].get(name, 0) + 1
            if truth["label"] != "BAD" and SEV.get(final, 1) > SEV.get(d, 1) and final not in truth["acceptable_final"]:
                cat["additional_fp"][name] = cat["additional_fp"].get(name, 0) + 1
    return table


# ---------------------------------------------------------------------- HTML
def metric_table(columns, caption):
    names = list(next(iter(columns.values())).keys())
    head = "".join("<th>%s</th>" % html.escape(c) for c in columns)

    def cell(v):
        if isinstance(v, dict) and "num" in v:
            return "%d/%d%s" % (v["num"], v["den"], "" if v["value"] is None else " (%.0f%%)" % (100 * v["value"]))
        return "n/a" if v is None else html.escape(str(v))

    body = "".join("<tr><td>%s</td>%s</tr>" % (html.escape(n), "".join("<td>%s</td>" % cell(c[n]) for c in columns.values()))
                   for n in names)
    return "<table><caption>%s</caption><tr><th>metric</th>%s</tr>%s</table>" % (html.escape(caption), head, body)


def render_html(report):
    esc = html.escape
    sections = [
        ("MEASURED - Local (real hguet, offline)", {"local": report["local"]["metrics"]}),
        ("MEASURED (limited) - Local + RPC: the RPC endpoint is unreachable; success-path simulation cannot be "
         "driven through the CLI", {"local+rpc(unreachable)": report["rpc"]["metrics"]}),
        ("MODEL - Reference Mock Cloud (profile / verifier mode). NOT a real service", report["reference_mock"]["metrics"]),
        ("Real HGUET Server: " + report["real_server"]["status"].upper(),
         {"real_server": report["real_server"]["metrics"]} if report["real_server"].get("metrics") else None),
    ]
    blocks = []
    for caption, cols in sections:
        if cols is None:
            blocks.append("<div class='banner'><b>%s</b><br>%s</div>" % (esc(caption), esc(report["real_server"]["reason"])))
        else:
            blocks.append(metric_table(cols, caption))
    cats = "".join("<tr><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
        esc(name), c["scenarios"], esc(json.dumps(c["local"], sort_keys=True)),
        esc(json.dumps(c["additional_tp"], sort_keys=True)), esc(json.dumps(c["additional_fp"], sort_keys=True)))
        for name, c in report["categories"].items())
    lab = report["labeling_quality"]
    detail = []
    for r in report["scenarios"]:
        detail.append("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            esc(r["id"]), esc(r["category"]), esc(r["kind"]), esc(r["label"]), esc(r["local_decision"]),
            esc(json.dumps(r["finals"], sort_keys=True))))
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HGUET Cloud Value Benchmark</title><style>
:root{--bg:#fff;--fg:#14181f;--mut:#5b6573;--line:#d8dde6;--warn:#fff4d6}
@media (prefers-color-scheme:dark){:root{--bg:#10141a;--fg:#e7ebf2;--mut:#9aa6b6;--line:#2b3441;--warn:#3a3014}}
body{font:14px/1.45 system-ui,sans-serif;margin:0 auto;max-width:1250px;padding:16px;background:var(--bg);color:var(--fg)}
table{border-collapse:collapse;margin:10px 0;display:block;overflow-x:auto}caption{text-align:left;font-weight:700;padding:6px 0}
td,th{border:1px solid var(--line);padding:3px 8px;text-align:left;vertical-align:top}.banner{border:2px solid var(--line);background:var(--warn);padding:8px 12px;margin:12px 0}
.mut{color:var(--mut)}h1,h2{margin:.7em 0 .2em}
</style></head><body><h1>HGUET Cloud Value Benchmark v1</h1>
<p class="mut">commit %s &middot; %s &middot; %d scenarios &middot; real <code>hguet</code> binary &middot; BLOCK-only &middot; synthetic data</p>
<div class="banner"><b>Read this first.</b> Sources are never merged. <b>real_server: %s.</b> Everything under "Reference Mock" is a
<b>model</b> built by the benchmark authors; it shows how verification rules behave under chosen server behaviours, not how any real
service performs. Evidence instances are synthetic (instance_verified=false). Label review: %s</div>
%s
<h2>By threat category (local vs Cloud-added)</h2><table><tr><th>category</th><th>n</th><th>local decisions</th><th>additional TP by config</th><th>additional FP by config</th></tr>%s</table>
<h2>Labelling quality</h2><p>Independent rule-based re-derivation agrees on %d/%d labels. Critical cases: %d, with human review: %d.
<br>%s</p>
<h2>Scenarios</h2><table><tr><th>id</th><th>category</th><th>kind</th><th>truth</th><th>local</th><th>final decision by config</th></tr>%s</table>
<h2>Limits</h2><ul>%s</ul></body></html>""" % (
        esc(report["meta"]["commit"][:12]), esc(report["meta"]["generated_utc"]), report["meta"]["scenarios"],
        esc(report["real_server"]["status"]), esc(lab["human_review_status"]), "\n".join(blocks), cats,
        lab["agreement"]["agree"], lab["agreement"]["total"], lab["critical_cases"], lab["critical_with_human_review"],
        esc("; ".join(lab["limits"])), "\n".join(detail), "".join("<li>%s</li>" % esc(x) for x in report["limits"]))


# ----------------------------------------------------------------------- main
def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--hguet", default=str(TESTING.parent / "target/debug/hguet"))
    parser.add_argument("--out", default=str(CV / "reports/latest"))
    parser.add_argument("--enable-real-server", action="store_true")
    parser.add_argument("--real-server-url", default=None)
    parser.add_argument("--allow-insecure-loopback", action="store_true", help="test switch: permit http://127.0.0.1")
    args = parser.parse_args()
    hguet = str(Path(args.hguet).resolve())
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    inputs, truths = load("inputs", "CV-"), load("truth", "CV-")
    evidence = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((CV / "evidence").glob("EV-*.json"))]
    leak_guard(inputs, truths, evidence)
    registry = rules.Registry(evidence)

    local, rpc_dec = {}, {}
    for sid, inp in inputs.items():
        local[sid] = run_local(hguet, inp, out)
        with rpc_mock.MockRpc("closed_port") as mock:
            rpc_dec[sid] = run_local(hguet, inp, out / "rpc", mock.url)
    local_decisions = {sid: v["decision"] for sid, v in local.items()}
    configs, metrics = {}, {}
    for profile in MOCK_PROFILES:
        for mode in VERIFIER_MODES:
            if profile == "silent" and mode == "trusting":
                continue
            name = "%s/%s-client" % (profile, mode)
            server = rs.ReferenceCloudServer(CV / "evidence", profile)
            configs[name] = run_cloud_config(server, mode, inputs, truths, local, registry)
            metrics[name] = score(configs[name], truths, local)
    real = real_server.RealServerAdapter(args.real_server_url, args.enable_real_server, args.allow_insecure_loopback)
    reason = real.unavailable_reason()
    real_section = {"status": "unavailable" if reason else "enabled", "reason": reason or "enabled by operator"}
    if not reason:
        rows = run_cloud_config(real, "strict", inputs, truths, local, registry)
        configs["real_server/strict-client"] = rows
        real_section["metrics"] = score(rows, truths, local)
        real_section["privacy"] = {"requests_sent": real.requests_sent, "bytes_sent": real.bytes_sent,
                                   "fields_sent": sorted(real.fields_sent)}
    report = {
        "meta": {"format": "hguet-cloud-value-report/1", "scenarios": len(inputs), "hguet_binary": hguet,
                 "commit": subprocess.run(["git", "rev-parse", "HEAD"], cwd=TESTING.parent, capture_output=True, text=True).stdout.strip() or "unknown",
                 "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                 "benchmark_clock": next(iter(inputs.values()))["clock"],
                 "rerun": "python testing/cloud-value/runner/run_cloud_value.py --hguet %s" % hguet},
        "never_merged": "local, rpc, reference_mock and real_server are separate sections; no combined figure exists",
        "local": {"source": "measured", "metrics": local_only_score(local_decisions, truths, local),
                  "decisions": local_decisions},
        "rpc": {"source": "measured_limited", "metrics": local_only_score({s: v["decision"] for s, v in rpc_dec.items()}, truths, local),
                "decisions_changed_vs_local": sorted(s for s in local if local[s]["decision"] != rpc_dec[s]["decision"])},
        "reference_mock": {"source": "MODEL", "metrics": metrics},
        "real_server": real_section,
        "categories": category_table(inputs, truths, local, configs),
        "labeling_quality": independent_labeler.run(),
        "signing_blocked_all_local": all(v["signing_blocked"] for v in local.values()),
        "scenarios": [{"id": sid, "category": truths[sid]["category"], "kind": truths[sid]["kind"],
                       "label": truths[sid]["label"], "local_decision": local[sid]["decision"],
                       "local_findings": local[sid]["findings"], "repro": local[sid]["repro"],
                       "finals": {n: next((r["final"] for r in rows if r["id"] == sid and not r.get("not_applicable")), None)
                                  for n, rows in configs.items()}} for sid in inputs],
        "limits": [
            "Reference mock results are a MODEL of verification behaviour, not evidence about a real server.",
            "All evidence instances are synthetic (instance_verified=false); tiers describe documented attack classes and recorded model runs, not verified incidents.",
            "Scenario, evidence and truth share one author; the rule-based re-derivation is not a human blind review (critical cases are packaged for one).",
            "RPC: only the unreachable-endpoint path is driven through the CLI; successful simulation would require weakening TLS verification.",
            "Cost units are nominal benchmark units, not prices.",
            "ML-DSA-87 (the real protocol signature) cannot be verified here: such answers are discarded as unsupported_signature_alg.",
        ],
    }
    (out / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (out / "report.html").write_text(render_html({**report,
        "reference_mock": {"metrics": metrics}, "local": report["local"], "rpc": report["rpc"]}), encoding="utf-8")
    print("Cloud Value Benchmark v1 - %d scenarios (sources never merged)" % len(inputs))
    lm = report["local"]["metrics"]
    print("  [MEASURED local] additional TP %d/%d (no cloud), local BAD denied %d" % (
        lm["additional_true_positive"]["num"], lm["additional_true_positive"]["den"],
        sum(1 for s, d in local_decisions.items() if truths[s]["label"] == "BAD" and d == "DENY")))
    for name, m in metrics.items():
        print("  [MODEL %-24s] +TP %2d/%d  +FP %2d/%d  attr %2d/%2d  unsupported-claims believed %2d  tamper trusted %d/%d  ALLOW %d" % (
            name, m["additional_true_positive"]["num"], m["additional_true_positive"]["den"],
            m["additional_false_positive"]["num"], m["additional_false_positive"]["den"],
            m["correct_evidence_attribution"]["num"], m["correct_evidence_attribution"]["den"],
            m["unsupported_safety_claims_believed"]["num"], m["tampered_assessments_wrongly_trusted"]["num"],
            m["tampered_assessments_wrongly_trusted"]["den"], m["allow_created"]["num"]))
    print("  [real_server] %s: %s" % (real_section["status"].upper(), real_section["reason"]))
    print("  labelling: rule re-derivation %d/%d agree; human review: %s" % (
        report["labeling_quality"]["agreement"]["agree"], report["labeling_quality"]["agreement"]["total"],
        report["labeling_quality"]["human_review_status"][:40]))
    print("  report: %s" % (out / "report.html"))
    any_allow = any(m["allow_created"]["num"] for m in metrics.values())
    return 1 if (any_allow or not report["signing_blocked_all_local"]) else 0


if __name__ == "__main__":
    sys.exit(main())
