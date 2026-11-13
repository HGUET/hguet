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
if len(sys.argv)>2:
    v1 = json.loads(Path(sys.argv[2]).read_text())
    Draft202012Validator(schema).validate(v1["verdict"])
    parsed_v1=v1["inspection"]
    assert parsed_v1["wire_format"]=="v1"
    assert parsed_v1["transaction_bytes"]==228
    assert parsed_v1["instruction_count"]==1
    assert parsed_v1["transaction_signature_status"]=="unsigned"
    assert parsed_v1["declared_system_transfer_lamports"]=="500"
    assert parsed_v1["system_transfers"][0]["lamports"]=="500"
    assert parsed_v1["resource_config"]["compute_unit_limit"]==200000
    assert parsed_v1["resource_config"]["loaded_accounts_data_size_limit"]==65536
    assert v1["verdict"]["decision"]=="UNKNOWN"
    assert v1["verdict"]["simulation_status"]=="not_performed"
if len(sys.argv)>3:
    direct = json.loads(Path(sys.argv[3]).read_text())
    Draft202012Validator(schema).validate(direct["verdict"])
    p = direct["inspection"]
    assert p["wire_format"] == "legacy"
    assert p["transaction_bytes"] == 311
    assert p["instruction_count"] == 1
    assert p["transaction_signature_status"] == "unsigned"
    assert p["program_ids"] == ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"]
    raw_ix = p["compiled_top_level_instructions"][0]
    assert raw_ix["instruction_index"] == 0
    assert raw_ix["program_index"] == 5
    assert raw_ix["account_indices"] == [1,3,2,4]
    assert raw_ix["data_base58"]
    v = direct["verdict"]
    assert v["decision"] == "UNKNOWN"
    assert v["simulation_status"] == "not_performed"
    assert "wire_direct_token_binary_decode" in v["coverage"]
    codes = [x["code"] for x in v["findings"]]
    assert "WIRE_TOKEN_DIRECT_MOVEMENT" in codes
    assert "WIRE_TOKEN_DIRECT_OPAQUE" not in codes
    assert "RPC_SIMULATION_ONLY" not in codes
    assert "WIRE_TOKEN_DIRECT_ALT_UNRESOLVED" not in codes
    print("PASS: original-wire TransferChecked detected offline, no ALLOW or simulated effects")
print("PASS: legacy and v1 CLI JSON validated; unsupported onchain effects remain UNKNOWN")
