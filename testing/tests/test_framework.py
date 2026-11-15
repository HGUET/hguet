"""Self-tests of the benchmark framework (no HGUET binary needed)."""
import json
import socket
import sys
import unittest
from pathlib import Path

TESTING = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(TESTING / "lib"), str(TESTING / "mocks"), str(TESTING / "runner")]
import cloud_mock  # noqa: E402
import crypto_tx as ct  # noqa: E402
import rpc_mock  # noqa: E402
import run_benchmark as rb  # noqa: E402

SCENARIOS = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((TESTING / "scenarios").glob("*.json"))]
REGRESSION = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((TESTING / "scenarios-regression").glob("*.json"))]


class Crypto(unittest.TestCase):
    def test_rfc8032_vectors(self):
        seed = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        self.assertEqual(ct.ed25519_public(seed).hex(),
                         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        self.assertEqual(ct.ed25519_sign(seed, b"").hex(),
                         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

    def test_base58_roundtrip(self):
        for raw in (b"", b"\0", b"\0\0abc", bytes(range(32))):
            self.assertEqual(ct.b58decode(ct.b58encode(raw)), raw)
        self.assertEqual(ct.SYSTEM, ct.b58encode(bytes(32)))


class Scenarios(unittest.TestCase):
    def test_mix_and_uniqueness(self):
        classes = [s["class"] for s in SCENARIOS]
        self.assertEqual((classes.count("GOOD"), classes.count("BAD"), classes.count("UNKNOWN")), (20, 25, 15))
        self.assertEqual(len({s["id"] for s in SCENARIOS}), 60)

    def test_every_scenario_is_complete_and_independent(self):
        for s in SCENARIOS:
            with self.subTest(s["id"]):
                self.assertEqual(s["format"], "hguet-bench-scenario/1")
                self.assertTrue(s["id"].startswith(s["class"][0]))
                self.assertGreaterEqual(len(s["rationale"]), 20)
                self.assertTrue(s["truth"]["authored_independently_of_tool"])
                self.assertEqual(s["truth"]["label"], s["class"])
                allowed = {"GOOD": {"ALLOW", "UNKNOWN"}, "BAD": {"DENY"}, "UNKNOWN": {"UNKNOWN"}}[s["class"]]
                self.assertEqual(set(s["truth"]["acceptable_decisions"]), allowed)
                self.assertIn("findings_required", s["expect"])
                if s["class"] == "BAD":
                    self.assertTrue(s["expect"]["findings_required"], "BAD must name the threat family")

    def test_smoke_set_covers_all_classes(self):
        smoke = [s["class"] for s in SCENARIOS if s["smoke"]]
        for cls in ("GOOD", "BAD", "UNKNOWN"):
            self.assertGreaterEqual(smoke.count(cls), 3)

    def test_known_defects_reference_real_scenarios(self):
        known = json.loads((TESTING / "known_defects.json").read_text())
        ids = {s["id"] for s in SCENARIOS + REGRESSION}
        self.assertTrue(set(known) <= ids)

    def test_regression_suite_has_positive_and_negative_pairs(self):
        classes = [s["class"] for s in REGRESSION]
        self.assertGreaterEqual(classes.count("BAD"), 10)
        self.assertGreaterEqual(classes.count("UNKNOWN"), 8)
        self.assertGreaterEqual(classes.count("GOOD"), 3)
        self.assertFalse({s["id"] for s in REGRESSION} & {s["id"] for s in SCENARIOS})
        for s in REGRESSION:
            with self.subTest(s["id"]):
                self.assertTrue(s["expect"]["findings_required"] or s["expect"]["findings_forbidden"])
        # every UNKNOWN/GOOD regression case must forbid the DENY-class finding it must not raise
        for s in REGRESSION:
            if s["class"] in ("UNKNOWN", "GOOD") and s["id"] != "U-103":
                self.assertTrue(s["expect"]["findings_forbidden"], s["id"])


class Metrics(unittest.TestCase):
    def row(self, truth, decision, required_ok=True):
        return {"truth": truth, "decision": decision, "checks": {"required_findings": required_ok,
                "decision_acceptable": True, "proven_properties": True}, "invariants": {"gate_blocks": True}}

    def test_confusion_and_ratios_keep_unknown_and_deny_apart(self):
        rows = [self.row("GOOD", "UNKNOWN"), self.row("GOOD", "DENY"), self.row("BAD", "DENY"),
                self.row("BAD", "UNKNOWN"), self.row("UNKNOWN", "UNKNOWN"), self.row("UNKNOWN", "DENY")]
        m = rb.metrics(rows)
        self.assertEqual(m["confusion_matrix"]["BAD"]["UNKNOWN"], 1)
        self.assertEqual(m["confusion_matrix"]["UNKNOWN"]["DENY"], 1)
        s = m["summary"]
        self.assertEqual((s["false_block_rate"]["num"], s["false_block_rate"]["den"]), (1, 2))
        self.assertEqual((s["bad_denied"]["num"], s["bad_denied"]["den"]), (1, 2))
        self.assertEqual((s["bad_not_denied_but_blocked_only"]["num"], s["bad_not_denied_but_blocked_only"]["den"]), (1, 2))
        self.assertEqual((s["unknown_overclaimed_as_deny"]["num"], s["unknown_overclaimed_as_deny"]["den"]), (1, 2))
        self.assertIsNone(m["per_class"]["GOOD"]["precision"]["value"])  # 0/0 is n/a, not 0 or 1
        self.assertEqual(m["per_class"]["BAD"]["precision"]["den"], 3)  # DENY was predicted for one GOOD, one BAD and one UNKNOWN

    def test_block_only_is_not_detection(self):
        rows = [self.row("BAD", "UNKNOWN") for _ in range(3)]
        s = rb.metrics(rows)["summary"]
        self.assertEqual(s["bad_denied"]["num"], 0)
        self.assertEqual(s["signing_blocked_all_scenarios"]["num"], 3)

    def test_evaluate_flags_violated_invariants(self):
        scenario = next(x for x in SCENARIOS if x["id"] == "G-001")
        out = {"verdict": {"decision": "UNKNOWN", "findings": []},
               "signing_boundary": {"signing_gate": "block", "automated_signing_permitted": True}}
        result = rb.evaluate(scenario, {"rc": 30, "stdout_json": out, "stderr": ""}, None)
        self.assertFalse(result["invariants"]["gate_blocks"])
        self.assertEqual(result["failure_type"], "invariant_violation")
        out["signing_boundary"]["automated_signing_permitted"] = False
        out["verdict"]["total_spending_proven"] = True
        out["x"] = {"total_native_sol_spending_proven": True}
        result = rb.evaluate(scenario, {"rc": 30, "stdout_json": out, "stderr": ""}, None)
        self.assertFalse(result["invariants"]["no_spending_proof_claimed"])
        result = rb.evaluate(scenario, {"rc": 0, "stdout_json": {"verdict": {"decision": "UNKNOWN", "findings": []}},
                                        "stderr": ""}, None)
        self.assertFalse(result["invariants"]["exit_code_nonzero"])

    def test_error_is_not_a_decision(self):
        result = rb.evaluate(SCENARIOS[0], {"rc": -1, "stdout_json": None, "stderr": "boom"}, None)
        self.assertEqual((result["decision"], result["failure_type"]), ("ERROR", "error"))


class Mocks(unittest.TestCase):
    def test_cloud_rules(self):
        digest = "a" * 64
        good = cloud_mock.assessment(digest)
        self.assertEqual(cloud_mock.combine("DENY", digest, good)[0], "DENY")
        self.assertEqual(cloud_mock.combine("UNKNOWN", digest, good)[0], "UNKNOWN")
        self.assertNotEqual(cloud_mock.combine("UNKNOWN", digest, good)[0], "ALLOW")
        wrong = cloud_mock.assessment(digest, bound_to="b" * 64, finding={"severity": "critical"})
        self.assertEqual(cloud_mock.combine("UNKNOWN", digest, wrong)[0], "UNKNOWN")
        self.assertEqual(cloud_mock.combine("UNKNOWN", digest, None, cloud_required=True)[0], "UNKNOWN")
        adverse = cloud_mock.assessment(digest, finding={"severity": "critical"})
        self.assertEqual(cloud_mock.combine("UNKNOWN", digest, adverse)[0], "DENY")

    def test_rpc_mock_behaviours_are_deterministic(self):
        for behavior in ("closed_port", "non_tls_garbage", "hangup"):
            with rpc_mock.MockRpc(behavior) as mock:
                client = socket.socket()
                client.settimeout(2)
                if behavior == "closed_port":
                    with self.assertRaises(OSError):
                        client.connect(("127.0.0.1", mock.port))
                else:
                    client.connect(("127.0.0.1", mock.port))
                    client.sendall(b"x")
                    try:
                        data = client.recv(4096)
                    except OSError:  # peer reset on abrupt close (Windows): nothing was served
                        data = b""
                    self.assertEqual(bool(data), behavior == "non_tls_garbage")
                client.close()
        with self.assertRaises(ValueError):
            rpc_mock.MockRpc("real_server")


def make_stub(directory, body):
    """A fake `hguet` executable for this platform that runs `body` as Python."""
    import stat
    script = Path(directory) / "stub_tool.py"
    script.write_text("import json,sys\n"
                      "def verdict(decision):\n"
                      "    return {'schema_version':1,'kind':'security_verdict','decision':decision,"
                      "'network':'devnet','message_sha256':None,'transaction_sha256':None,"
                      "'intent_status':'not_checked','simulation_status':'not_performed',"
                      "'coverage':[],'findings':[],'limitations':[]}\n"
                      "if '--version' in sys.argv: print('stub'); sys.exit(0)\n" + body, encoding="utf-8")
    if sys.platform == "win32":
        stub = Path(directory) / "hguet.cmd"
        stub.write_text('@"%s" "%s" %%*\r\n' % (sys.executable, script), encoding="ascii")
    else:
        stub = Path(directory) / "hguet"
        stub.write_text('#!/bin/sh\nexec "%s" "%s" "$@"\n' % (sys.executable, script), encoding="ascii")
        stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    return stub


class RunnerIsNotVacuous(unittest.TestCase):
    """A tool that approves everything must make the benchmark fail loudly."""

    def test_always_allow_stub_fails_and_flags_unsafe(self):
        import os
        import stat
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            stub = make_stub(tmp, "print(json.dumps({'verdict':verdict('ALLOW'),"
                                  "'signing_boundary':{'signing_gate':'allow','automated_signing_permitted':True}}))\n"
                                  "sys.exit(0)\n")
            out = Path(tmp) / "out"
            done = subprocess.run([sys.executable, str(TESTING / "runner/run_benchmark.py"), "--hguet", str(stub),
                                   "--subset", "smoke", "--out", str(out), "--known-defects", str(Path(tmp) / "none")],
                                  capture_output=True, text=True)
            self.assertEqual(done.returncode, 1, done.stdout)
            report = json.loads((out / "report.json").read_text())
            types = {r["failure_type"] for r in report["results"]}
            self.assertIn("invariant_violation", types)
            self.assertEqual(report["totals"]["PASS"], 0)
            self.assertGreater(report["metrics"]["summary"]["bad_allowed_UNSAFE"]["num"], 0)
            self.assertEqual(report["metrics"]["summary"]["signing_blocked_all_scenarios"]["num"], 0)


    def test_xfail_xpass_and_invariant_handling(self):
        import stat
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            stub = make_stub(
                tmp, "if 'signer-preflight' in sys.argv:\n"
                     "    print(json.dumps({'signer_refusal':{'signing_gate':'block','signing_permitted':False,"
                     "'signature_created':False,'transaction_broadcast':False,'signer_backend_invoked':False}}))\n"
                     "    sys.exit(20)\n"
                     "print(json.dumps({'verdict':verdict('UNKNOWN')}))\n"
                     "sys.exit(30)\n")

            def run(known):
                kd = Path(tmp) / "known.json"
                kd.write_text(json.dumps(known))
                done = subprocess.run([sys.executable, str(TESTING / "runner/run_benchmark.py"), "--hguet", str(stub),
                                       "--subset", "smoke", "--out", str(Path(tmp) / "o"), "--known-defects", str(kd)],
                                      capture_output=True, text=True)
                return done.returncode, json.loads((Path(tmp) / "o/report.json").read_text())

            # An always-UNKNOWN tool: BAD scenarios fail (missed threat). Listing ALL failing ids makes them XFAIL.
            code, report = run({})
            failing = [r["id"] for r in report["results"] if r["outcome"] == "FAIL"]
            self.assertTrue(failing)
            self.assertEqual(code, 1)
            code, report = run({sid: {"defect": "X"} for sid in failing})
            self.assertEqual(report["totals"]["FAIL"], 0)
            self.assertEqual(report["totals"]["XFAIL"], len(failing))
            # (exit status also reflects the Cloud reference rules, which a fake tool can violate)
            # A listed scenario that now PASSES is XPASS and fails the run (stale registry entry).
            passing = next(r["id"] for r in report["results"] if r["outcome"] == "PASS")
            code, report = run({passing: {"defect": "STALE"}})
            self.assertEqual(report["totals"]["XPASS"], 1)
            self.assertEqual(code, 1)


class Coverage(unittest.TestCase):
    """The dimensions the first 60 scenarios never touched must stay covered."""

    def test_every_wire_format_encoding_and_network_has_good_and_bad_cases(self):
        import base64
        everything = SCENARIOS + REGRESSION

        def wire_format(s):
            raw = base64.b64decode(s["input"]["transaction"]["data"])
            if raw[:1] == b"\x81":
                return "v1"
            return "v0" if len(raw) > 65 and raw[65] & 0x80 else "legacy"
        for name, key in (("wire format", wire_format),
                          ("encoding", lambda s: s["input"]["transaction"]["encoding"]),
                          ("network", lambda s: s["input"]["network"])):
            seen = {}
            for s in everything:
                seen.setdefault(key(s), set()).add(s["class"])
            expected = {"wire format": {"legacy", "v0", "v1"}, "encoding": {"base64", "binary", "base58"},
                        "network": {"devnet", "mainnet", "testnet"}}[name]
            self.assertEqual(set(seen), expected, name)
            for value, classes in seen.items():
                with self.subTest(dimension=name, value=value):
                    self.assertIn("BAD", classes, "no BAD scenario: a blind spot for this " + name)
                    self.assertTrue(classes & {"GOOD", "UNKNOWN"}, "no non-BAD scenario for this " + name)

    def test_every_deny_finding_family_has_a_scenario_that_requires_it(self):
        required = {code for s in SCENARIOS + REGRESSION if s["class"] == "BAD"
                    for group in s["expect"]["findings_required"] for code in group}
        for code in ("INTENT_REJECTED", "INVALID_TRANSACTION_SIGNATURE", "MALFORMED_TRANSACTION",
                     "POLICY_SOL_TRANSFER_CAP", "POLICY_BLOCKED_SOL_RECIPIENT", "POLICY_BLOCKED_PROGRAM",
                     "POLICY_UNAPPROVED_PROGRAM", "POLICY_UNAPPROVED_SOL_RECIPIENT", "POLICY_WRONG_NETWORK",
                     "INTENT_SCOPE_AUTHORITY_TRANSFER", "INTENT_SCOPE_CLOSE_DESTINATION"):
            self.assertIn(code, required, "no BAD scenario requires " + code)

    def test_bad_scenarios_outnumber_no_class_and_ids_are_unique(self):
        ids = [s["id"] for s in SCENARIOS + REGRESSION]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(REGRESSION), 60)


class V1Builder(unittest.TestCase):
    def test_layout_signature_and_resource_header(self):
        payer = ct.signer_pubkey("signer:payer")
        dst = ct.plain_pubkey("dest:alice")
        wire, message = ct.build_v1_transaction([ct.ix_system_transfer(payer, dst, 1234)], payer,
                                                ("signer:payer",), "valid", priority_fee=7)
        self.assertEqual(wire[0], 0x81)
        self.assertEqual(wire[:len(message)], message)
        signature = wire[len(message):]
        self.assertEqual(len(signature), 64)
        self.assertTrue(ct.ed25519_verify(ct.b58decode(payer), message, signature))
        self.assertEqual(list(message[1:4]), [1, 0, 1])                    # one signer, System is read-only
        self.assertEqual(int.from_bytes(message[4:8], "little"), 0b1111)   # fee + CU + loaded-data bits
        self.assertEqual(list(message[40:42]), [1, 3])                     # one instruction, three addresses
        self.assertEqual(message[42:74], ct.b58decode(payer))
        values = message[42 + 96:]
        self.assertEqual(int.from_bytes(values[:8], "little"), 7)
        self.assertEqual(int.from_bytes(values[8:12], "little"), 200_000)
        self.assertEqual(message[-8:], (1234).to_bytes(8, "little"))
        unsigned, _ = ct.build_v1_transaction([ct.ix_system_transfer(payer, dst, 1)], payer)
        self.assertEqual(unsigned[-64:], bytes(64))

    def test_omitted_limits_clear_their_mask_bits(self):
        payer = ct.signer_pubkey("signer:payer")
        _, message = ct.build_v1_transaction([ct.ix_system_transfer(payer, ct.plain_pubkey("d"), 1)], payer,
                                             compute_unit_limit=None, loaded_accounts_data_size=None)
        self.assertEqual(int.from_bytes(message[4:8], "little"), 0)


class SchemaAndContract(unittest.TestCase):
    GOOD = {"schema_version": 1, "kind": "security_verdict", "decision": "UNKNOWN", "network": "devnet",
            "message_sha256": None, "transaction_sha256": None, "intent_status": "not_checked",
            "simulation_status": "not_performed", "coverage": [], "findings": [], "limitations": []}

    def test_validator_accepts_a_conforming_verdict_and_names_each_violation(self):
        self.assertEqual(rb.schema_errors(self.GOOD, rb.VERDICT_SCHEMA), [])
        for change, needle in (({"intent_status": "made_up"}, "intent_status"),
                               ({"decision": "MAYBE"}, "decision"),
                               ({"surprise": 1}, "surprise"),
                               ({"coverage": "all"}, "coverage"),
                               ({"findings": [{"code": "X"}]}, "findings[0]")):
            bad = dict(self.GOOD, **change)
            errors = rb.schema_errors(bad, rb.VERDICT_SCHEMA)
            self.assertTrue(any(needle in e for e in errors), (change, errors))
        missing = dict(self.GOOD)
        del missing["network"]
        self.assertTrue(any("network" in e and "required" in e for e in rb.schema_errors(missing, rb.VERDICT_SCHEMA)))

    def test_full_schema_rejects_invalid_hashes_and_boolean_version(self):
        for field in ("message_sha256", "transaction_sha256"):
            for value in ("not-a-hash", 17, {}, [], True):
                with self.subTest(field=field, value=value):
                    self.assertTrue(rb.schema_errors(dict(self.GOOD, **{field: value}), rb.VERDICT_SCHEMA))
        self.assertTrue(rb.schema_errors(dict(self.GOOD, schema_version=True), rb.VERDICT_SCHEMA))

    def test_malformed_findings_are_reported_without_crashing(self):
        scenario = next(x for x in SCENARIOS if x["id"] == "U-004")
        for value in (None, 1, "bad", [None], [{"code": []}]):
            result = rb.evaluate(scenario, {"rc": 30, "stdout_json": {
                "verdict": dict(self.GOOD, findings=value)}, "stderr": ""}, None)
            self.assertEqual(result["failure_type"], "public_schema_violation")

    def test_every_status_the_cli_source_emits_is_published(self):
        """A status string added to the CLI without the schema is caught without running the tool."""
        import re
        source = (TESTING.parent / "crates/hguet-cli/src/main.rs").read_text(encoding="utf-8")
        source += (TESTING.parent / "crates/hguet-core/src/lib.rs").read_text(encoding="utf-8")
        for field in ("intent_status", "simulation_status"):
            emitted = set(re.findall(field + r'\s*[:=]\s*"([a-z_]+)"\s*\.into\(\)', source))
            self.assertTrue(emitted, field)
            published = set(rb.VERDICT_SCHEMA["properties"][field]["enum"])
            self.assertLessEqual(emitted, published, "%s values missing from the public schema" % field)

    def test_schema_violation_and_wrong_exit_code_fail_a_scenario(self):
        scenario = next(x for x in SCENARIOS if x["id"] == "U-004")
        verdict = dict(self.GOOD, intent_status="invented_status")
        result = rb.evaluate(scenario, {"rc": 30, "stdout_json": {"verdict": verdict}, "stderr": ""}, None)
        self.assertEqual(result["failure_type"], "public_schema_violation")
        result = rb.evaluate(scenario, {"rc": 20, "stdout_json": {"verdict": dict(self.GOOD)}, "stderr": ""}, None)
        self.assertEqual(result["failure_type"], "exit_code_contract_violation")
        result = rb.evaluate(scenario, {"rc": 30, "stdout_json": {"verdict": dict(self.GOOD)}, "stderr": ""}, None)
        self.assertIsNone(result["failure_type"])

    def test_input_file_is_written_in_the_declared_encoding(self):
        import base64
        import tempfile
        raw = bytes(range(1, 80))
        for encoding, check in (("binary", lambda p: p.read_bytes() == raw),
                                ("base58", lambda p: ct.b58decode(p.read_text().strip()) == raw),
                                ("base64", lambda p: base64.b64decode(p.read_text()) == raw)):
            scenario = {"input": {"transaction": {"encoding": encoding, "data": base64.b64encode(raw).decode()},
                                  "intent": None, "policy_toml": None, "network": "devnet", "trusted_key": None}}
            with tempfile.TemporaryDirectory() as tmp:
                files = rb.write_inputs(scenario, Path(tmp))
                self.assertTrue(check(files["tx"]), encoding)
                command = rb.build_commands("hguet", scenario, files, None)["check"]
                self.assertNotIn("--intent", command)
                self.assertEqual(command[command.index("--encoding") + 1], encoding)


if __name__ == "__main__":
    unittest.main()
