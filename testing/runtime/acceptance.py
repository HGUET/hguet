"""Fail-closed acceptance and incremental evidence for mandatory runtime cases."""
import json
from pathlib import Path

expected_cases = (
    "native_match", "native_repeated_over_cap", "transfer_checked", "approve",
    "set_authority", "token2022_transfer_fee", "token2022_wrong_fee",
    "transfer_checked_wrong_authority", "native_insufficient_balance",
    "v0_sdk_transfer", "v1_sdk_transfer", "v1_inline_resources",
    "v0_alt_native_transfer",
)


def run_suite(jobs, expected, output, metadata):
    """No missing, duplicate, unexpected, incomplete or failed case can pass."""
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    records = []
    issues = []

    def persist(final=False):
        passed = sum(row.get("comparison") == "PASS" for row in records)
        result = {**metadata, "cases": records, "acceptance_issues": issues,
                  "mandatory_count": len(expected), "passed_count": passed,
                  "acceptance": "PASS" if final and not issues and
                  len(records) == len(expected) and passed == len(expected)
                  else ("FAIL" if final else "INCOMPLETE")}
        temporary = output.with_name(output.name + ".tmp")
        temporary.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        temporary.replace(output)
        return result

    persist()
    seen = set()
    for names, execute in jobs:
        names = tuple(names)
        try:
            rows = execute()
            rows = rows if isinstance(rows, list) else [rows]
            if any(not isinstance(row, dict) for row in rows):
                raise ValueError("case returned a non-object record")
            actual = [row.get("case") for row in rows]
            if sorted(str(name) for name in actual) != sorted(names):
                raise ValueError(f"expected cases {names}, received {actual}")
        except Exception as exc:
            rows = [{"case": name, "comparison": "FAIL",
                     "error": f"{type(exc).__name__}: {exc}"} for name in names]
        for row in rows:
            name = row["case"]
            if name in seen or name not in expected:
                issues.append(f"duplicate or unexpected case: {name}")
            seen.add(name)
            if row.get("comparison") != "PASS":
                row = {**row, "comparison": "FAIL"}
                issues.append(f"comparison failed or missing: {name}")
            records.append(row)
        persist()
    for name in expected:
        if name not in seen:
            issues.append(f"mandatory case missing: {name}")
            records.append({"case": name, "comparison": "FAIL", "error": "not executed"})
    result = persist(final=True)
    print(json.dumps(result, indent=2))
    return 0 if result["acceptance"] == "PASS" else 1
