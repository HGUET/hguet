"""Validate catalogue identities and references against the actual source tree."""
import json
from functools import cache
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def validate(catalogue=None):
    @cache
    def read(path):
        return path.read_text(encoding="utf-8")

    if catalogue is None:
        catalogue = json.loads(read(ROOT / "protocol/v2/rules.json"))
    seen = set()
    for rule in catalogue["rules"]:
        code = rule["legacy_code"]
        assert code not in seen, f"duplicate rule {code}"
        seen.add(code)
        assert rule["rule_id"] == "HGUET." + code
        assert rule["scope"] and rule["limitations"] and rule["evidence"]
        source_path = (ROOT / rule["source"]).resolve()
        assert source_path.is_relative_to(ROOT)
        source = read(source_path)
        assert '"' + code + '"' in source, f"missing source code {code}"
        assert rule["tests"] or rule.get("test_status") == "TARGETED_REGRESSION_OPEN", f"unrecorded regression gap for {code}"
        test_source = (ROOT / rule.get("test_source", rule["source"])).resolve()
        assert test_source.is_relative_to(ROOT)
        test_text = read(test_source)
        for test in rule["tests"]:
            assert re.search(r"fn\s+" + re.escape(test) + r"\s*\(", test_text), (code, test)
        for reference in rule.get("benchmark_fixtures", []):
            path = (ROOT / reference).resolve()
            assert path.is_relative_to(ROOT)
            assert code in read(path), (code, reference)
    policy = read(ROOT / "crates/hguet-policy/src/lib.rs")
    assert set(re.findall(r'"(POLICY_[A-Z_]+)"', policy)).issubset(seen)
    print(f"PASS: {len(seen)} catalogue rules and their source/test/fixture references")
    engine = read(ROOT / "crates/hguet-cli/src/lib.rs").split("#[cfg(test)]")[0]
    emitted = set(re.findall(r'\.finding\(\s*"([A-Z][A-Z0-9_]+)"',engine))
    emitted.update(re.findall(r'\("([A-Z][A-Z0-9_]+)"\s*,\s*"(?:high|medium|critical)"\s*,',engine))
    # These modules return typed codes which the CLI forwards dynamically.
    # Signing-boundary reason strings are a different contract, not findings.
    scope_source = read(ROOT / "crates/hguet-core/src/intent_scope.rs").split("#[cfg(test)]")[0]
    emitted.update(re.findall(r'(?:code:\s*|gap\(\s*)"([A-Z][A-Z0-9_]+)"', scope_source))
    rpc_source = read(ROOT / "crates/hguet-rpc/src/lib.rs").split("#[cfg(test)]")[0]
    emitted.update(re.findall(r'Self::[A-Za-z]+\s*=>\s*"(RPC_[A-Z_]+)"', rpc_source))
    missing=sorted(emitted-seen)
    print(f"OPEN: {len(missing)} engine finding codes without individual catalogue entries")
    for code in missing:
        print("  "+code)
    assert not missing, "finding catalogue is incomplete: " + ", ".join(missing)
    gaps=[rule["legacy_code"] for rule in catalogue["rules"] if rule.get("test_status")=="TARGETED_REGRESSION_OPEN"]
    print(f"OPEN: {len(gaps)} catalogue entries without targeted regression references")
    for code in gaps:
        print("  "+code)


if __name__ == "__main__":
    validate()
