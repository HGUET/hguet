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
if len(sys.argv)>5:
    permitted = json.loads(Path(sys.argv[4]).read_text())
    rejected = json.loads(Path(sys.argv[5]).read_text())
    for value in (permitted,rejected):
        Draft202012Validator(schema).validate(value["verdict"])
    assert permitted["verdict"]["decision"]=="UNKNOWN"
    assert permitted["verdict"]["intent_status"]=="signature_verified"
    assert permitted["verdict"]["simulation_status"]=="not_performed"
    assert "signed_direct_token_debit_limits" in permitted["verdict"]["coverage"]
    review = permitted["signed_token_spend_review"]
    assert review["limits_enforced_on_direct_wire_declarations"] is True
    assert review["total_spending_proven"] is False
    assert review["coverage"]=="direct_checked_wire_declarations_only"
    assert review["decoded_direct_debit_instructions"]==1
    assert len(review["debits"])==1
    assert review["debits"][0]["declared_raw"]=="1234"
    assert review["debits"][0]["signed_limit_raw"]=="1234"
    assert any(f["code"]=="SIGNED_INTENT_TOKEN_CAP_PARTIAL_COVERAGE"
               for f in permitted["verdict"]["findings"])
    assert rejected["verdict"]["decision"]=="DENY"
    assert rejected["verdict"]["intent_status"]=="rejected"
    assert rejected["verdict"]["simulation_status"]=="not_performed"
    assert any(f["code"]=="INTENT_REJECTED" and "exceed" in f["summary"]
               for f in rejected["verdict"]["findings"])
    print("PASS: exact-byte signed mint cap permits equal raw declared amount and rejects 1 over")
if len(sys.argv)>7:
    permitted = json.loads(Path(sys.argv[6]).read_text())
    rejected = json.loads(Path(sys.argv[7]).read_text())
    for report in (permitted,rejected):
        Draft202012Validator(schema).validate(report["verdict"])
        assert report["inspection"]["compiled_top_level_instructions"][0]["account_indices"] == [1,3,2,0]
    verdict=permitted["verdict"]
    assert verdict["decision"] == "UNKNOWN"
    assert verdict["intent_status"] == "signature_verified"
    assert verdict["simulation_status"] == "not_performed"
    assert "signed_direct_token_source_authority_roles" in verdict["coverage"]
    review = permitted["signed_token_source_review"]
    assert review["checked_direct_debit_instructions"] == 1
    assert review["transaction_required_signer_role_checked"] is True
    assert review["transaction_signatures_verified"] is False
    assert review["token_account_owner_verified"] is False
    assert review["total_spending_proven"] is False
    assert review["debits"][0]["declared_raw"] == "1234"
    assert review["debits"][0]["signed_limit_raw"] == "1234"
    assert any(x["code"]=="SIGNED_INTENT_SOURCE_SCOPE_PARTIAL_COVERAGE"
               for x in verdict["findings"])
    assert rejected["verdict"]["decision"]=="DENY"
    assert rejected["verdict"]["intent_status"]=="rejected"
    assert rejected["verdict"]["simulation_status"]=="not_performed"
    assert any(x["code"]=="INTENT_REJECTED" and "source" in x["summary"]
               for x in rejected["verdict"]["findings"])
    print("PASS: signed token source/required-signer scope exact-cap UNKNOWN and cap-over DENY")
print("PASS: legacy and v1 CLI JSON validated; unsupported onchain effects remain UNKNOWN")
