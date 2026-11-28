"""Check reproducibility, independent CLI parity, and passive lab HTML."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

from html_preview import PassiveMarkup
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from solders.transaction import VersionedTransaction

ROOT = Path(__file__).resolve().parents[2]
CASES = ("payment", "additional-debit", "authority", "token2022", "uncertainty", "diff")


def main():
    if not __debug__:
        raise SystemExit("assertions required")
    parser = argparse.ArgumentParser()
    parser.add_argument("--hguet", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    binary = args.hguet.resolve()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    directory = args.out.parent / "security-demo-lab"
    registry = Registry()
    for name in ("programs", "flow", "authority", "report", "diff"):
        schema = json.loads((ROOT / "protocol" / name / "v1" / "report.schema.json").read_text())
        registry = registry.with_resource(f"urn:hguet:{name}:v1", Resource.from_contents(schema))
    schema = json.loads((ROOT / "protocol/lab/v1/report.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema, registry=registry)

    def run(*options, data=None, code=0):
        p = subprocess.run([str(binary), *options], input=data, capture_output=True, timeout=30)
        assert p.returncode == code, (options, p.stderr, p.stdout[:500])
        return p.stdout

    manifest = json.loads(run("lab", "all", "--out", str(directory)))
    validator.validate(manifest)
    assert manifest == json.loads((directory / "manifest.json").read_text())
    assert manifest["cases"] == list(CASES)
    assert manifest["synthetic"] and manifest["offline"] and not manifest["execution_performed"]
    assert {e["file"] for e in manifest["files"]} == {f"{n}.{ext}" for n in CASES for ext in ("json", "html")}
    for entry in manifest["files"]:
        assert hashlib.sha256((directory / entry["file"]).read_bytes()).hexdigest() == entry["sha256"]
    cases = []
    for name in CASES:
        case = json.loads((directory / f"{name}.json").read_text())
        validator.validate(case)
        assert case == json.loads(run("lab", name, "--json"))
        assert case["synthetic"] and not case["execution_performed"]
        assert case["signing_authorization"] == "NOT_AUTHORIZED"
        raw = base64.b64decode(case["transaction_base64"], validate=True)
        tx = VersionedTransaction.from_bytes(raw)
        assert bytes(tx) == raw and all(bytes(s) == bytes(64) for s in tx.signatures)
        if name == "diff":
            with tempfile.TemporaryDirectory() as temp:
                original = Path(temp) / "before"
                original.write_bytes(base64.b64decode(case["before_transaction_base64"]))
                independent = json.loads(run("diff", str(original), "-", "--offline", data=raw))
        else:
            independent = json.loads(run("report", "-", "--offline", data=raw))
        assert independent == case["report"]
        html = (directory / f"{name}.html").read_text()
        assert html == run("lab", name, "--html").decode().rstrip("\n")
        assert "SYNTHETIC LAB" in html and "Never broadcast" in html
        markup = PassiveMarkup()
        markup.feed(html)
        markup.close()
        markup.verify()
        cases.append({"case":name,"comparison":"PASS"})
        args.out.write_text(json.dumps({"cases":cases,"acceptance":"INCOMPLETE"},indent=2))
    snapshot = (directory / "manifest.json").read_bytes()
    error = json.loads(run("lab", "all", "--out", str(directory), code=40))
    validator.validate(error)
    assert error["signing_authorization"] == "NOT_AUTHORIZED"
    assert (directory / "manifest.json").read_bytes() == snapshot
    assert json.loads(run("lab", "unknown", code=40))["kind"] == "hguet_lab_error"
    cases.append({"case":"no_overwrite_and_invalid_case","comparison":"PASS"})
    args.out.write_text(json.dumps({"cases":cases,"mandatory_count":7,
        "passed_count":len(cases),"acceptance":"PASS"},indent=2))
    print("PASS: 7 demo lab comparisons; 6 reproducible HTML and JSON pairs preserved")


if __name__ == "__main__":
    main()
