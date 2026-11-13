#!/usr/bin/env python3
"""Validate actual CLI output from a synthetic unsigned wire fixture."""
import json
import sys
from pathlib import Path
from jsonschema import Draft202012Validator

base = Path(__file__).resolve().parents[1]
schema = json.loads((base/"protocol/v1/security-verdict.schema.json").read_text())
report = json.loads(Path(sys.argv[1]).read_text())
Draft202012Validator(schema).validate(report["verdict"])
parsed = report["inspection"]
assert parsed["wire_format"] == "legacy"
assert parsed["transaction_bytes"] == 134
assert parsed["required_signatures"] == 1
assert parsed["instruction_count"] == 0
assert report["verdict"]["decision"] == "UNKNOWN"
assert report["verdict"]["simulation_status"] == "not_performed"
assert report["verdict"]["intent_status"] == "not_checked"
assert len(report["verdict"]["message_sha256"]) == 64
print("PASS: real CLI JSON conforms to public SecurityVerdict, no false ALLOW")
