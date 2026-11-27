"""Validate catalogue identities and references against the actual source tree."""
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def validate():
    catalogue = json.loads((ROOT / "protocol/v2/rules.json").read_text())
    seen = set()
    for rule in catalogue["rules"]:
        code = rule["legacy_code"]
        assert code not in seen, f"duplicate rule {code}"
        seen.add(code)
        assert rule["rule_id"] == "HGUET." + code
        assert rule["scope"] and rule["limitations"] and rule["evidence"]
        source_path = (ROOT / rule["source"]).resolve()
        assert source_path.is_relative_to(ROOT)
        source = source_path.read_text()
        assert '"' + code + '"' in source, f"missing source code {code}"
        assert rule["tests"], f"no regression test for {code}"
        test_source = (ROOT / rule.get("test_source", rule["source"])).resolve()
        assert test_source.is_relative_to(ROOT)
        test_text = test_source.read_text()
        for test in rule["tests"]:
            assert re.search(r"fn\s+" + re.escape(test) + r"\s*\(", test_text), (code, test)
        for reference in rule.get("benchmark_fixtures", []):
            path = (ROOT / reference).resolve()
            assert path.is_relative_to(ROOT)
            assert code in path.read_text(), (code, reference)
    policy = (ROOT / "crates/hguet-policy/src/lib.rs").read_text()
    assert set(re.findall(r'"(POLICY_[A-Z_]+)"', policy)).issubset(seen)
    print(f"PASS: {len(seen)} catalogue rules and their source/test/fixture references")


if __name__ == "__main__":
    validate()
