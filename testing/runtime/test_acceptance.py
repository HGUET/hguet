"""Acceptance tests do not require Solders or a compiled HGUET."""
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from acceptance import run_suite


class AcceptanceTests(unittest.TestCase):
    def run_cases(self, jobs, expected=("a", "b")):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "result.json"
            with contextlib.redirect_stdout(io.StringIO()):
                code = run_suite(jobs, expected, path, {})
            return code, json.loads(path.read_text(encoding="utf-8"))

    def test_complete_pass(self):
        code, report = self.run_cases([
            (("a", "b"), lambda: [{"case": name, "comparison": "PASS"} for name in ("a", "b")])])
        self.assertEqual((code, report["acceptance"], report["passed_count"]), (0, "PASS", 2))

    def test_failed_or_missing_status(self):
        for row in ({"case": "b", "comparison": "FAIL"}, {"case": "b"}):
            code, report = self.run_cases([
                (("a",), lambda: {"case": "a", "comparison": "PASS"}),
                (("b",), lambda: row)])
            self.assertEqual(code, 1)
            self.assertEqual(report["passed_count"], 1)

    def test_missing_and_duplicate(self):
        a = lambda: {"case": "a", "comparison": "PASS"}
        for jobs in ([(("a",), a)], [(("a",), a), (("a",), a)]):
            code, report = self.run_cases(jobs)
            self.assertEqual(code, 1)
            self.assertTrue(report["acceptance_issues"])

    def test_exception_preserves_previous_evidence(self):
        def fail():
            raise AssertionError("runtime rejected")
        code, report = self.run_cases([
            (("a",), lambda: {"case": "a", "comparison": "PASS"}),
            (("b",), fail)])
        self.assertEqual(code, 1)
        self.assertEqual(report["cases"][0]["comparison"], "PASS")
        self.assertIn("runtime rejected", report["cases"][1]["error"])

    def test_wrong_case_name(self):
        code, report = self.run_cases([(("a", "b"), lambda: [
            {"case": "a", "comparison": "PASS"}, {"case": "c", "comparison": "PASS"}])])
        self.assertEqual(code, 1)
        self.assertEqual(report["passed_count"], 0)


if __name__ == "__main__":
    unittest.main()
