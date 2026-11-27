"""Catalogue regressions use the real emission sources and mutated catalogue copies."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "validate_rule_catalogue", ROOT / "scripts/validate_rule_catalogue.py"
)
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


class RuleCatalogue(unittest.TestCase):
    def setUp(self):
        self.catalogue = json.loads((ROOT / "protocol/v2/rules.json").read_text())

    def validate(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            VALIDATOR.validate(self.catalogue)
        return output.getvalue()

    def test_current_catalogue_validates_and_discloses_regression_gaps(self):
        output = self.validate()
        self.assertIn("OPEN: 0 engine finding codes", output)
        for rule in self.catalogue["rules"]:
            if rule.get("test_status") == "TARGETED_REGRESSION_OPEN":
                self.assertIn(rule["legacy_code"], output)

    def test_missing_dynamic_and_direct_findings_fail_validation(self):
        original = copy.deepcopy(self.catalogue)
        for code in ["RPC_RESPONSE_INVALID", "INTENT_SCOPE_AUTHORITY_TRANSFER",
                     "TOKEN_ACCOUNT_CONTROL_UNSUPPORTED_ENCODING", "WIRE_TOKEN_DIRECT_DECODER_UNAVAILABLE"]:
            with self.subTest(code=code):
                self.catalogue = copy.deepcopy(original)
                self.catalogue["rules"] = [r for r in self.catalogue["rules"] if r["legacy_code"] != code]
                with self.assertRaisesRegex(AssertionError, code):
                    self.validate()

    def test_catalogue_paths_use_portable_repository_separators(self):
        for rule in self.catalogue["rules"]:
            references = [rule["source"], rule.get("test_source", rule["source"])]
            references.extend(rule.get("benchmark_fixtures", []))
            for reference in references:
                self.assertNotIn(chr(92), reference, (rule["legacy_code"], reference))
                self.assertFalse(Path(reference).is_absolute())

    def test_active_emission_cannot_be_marked_retired(self):
        rule = next(r for r in self.catalogue["rules"] if r["legacy_code"] == "RPC_RESPONSE_INVALID")
        rule["test_status"] = "RETIRED_REDUNDANT_CHECK"
        rule["lifecycle"] = "historical_not_emitted"
        with self.assertRaisesRegex(AssertionError, "retired finding is still emitted"):
            self.validate()

    def test_duplicate_rule_is_rejected(self):
        self.catalogue["rules"].append(copy.deepcopy(self.catalogue["rules"][0]))
        with self.assertRaisesRegex(AssertionError, "duplicate rule"):
            self.validate()

    def test_nonexistent_regression_reference_is_rejected(self):
        self.catalogue["rules"][0]["tests"] = ["missing_catalogue_regression_test"]
        with self.assertRaisesRegex(AssertionError, "missing_catalogue_regression_test"):
            self.validate()

    def test_empty_tests_require_explicit_open_status(self):
        self.catalogue["rules"][0]["tests"] = []
        self.catalogue["rules"][0]["test_status"] = "TARGETED_REGRESSION"
        with self.assertRaisesRegex(AssertionError, "unrecorded regression gap"):
            self.validate()

    def test_source_path_cannot_escape_repository(self):
        self.catalogue["rules"][0]["source"] = "../outside-catalogue-source.rs"
        with self.assertRaises(AssertionError):
            self.validate()


if __name__ == "__main__":
    unittest.main()
