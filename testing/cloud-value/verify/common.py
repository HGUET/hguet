"""Shared constants for the verifier and the reference/test servers."""
import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "protocol"))
import jcs  # noqa: E402

GENESIS = {"devnet": "bench-genesis-devnet", "testnet": "bench-genesis-testnet", "mainnet": "bench-genesis-mainnet"}
ENVIRONMENT_FOR_NETWORK = {"mainnet": "production", "devnet": "sandbox", "testnet": "sandbox"}
# Domain-separated signing contexts from docs/architecture/cloud-protocol.md ("Signed report domains").
DOMAINS = {
    "cloud_assessment": b"HGUET-CLOUD-ASSESSMENT/v1\x00",
    "price_quote": b"HGUET-SOL-QUOTE/v1\x00",
    "payment_receipt": b"HGUET-SOL-PAYMENT-RECEIPT/v1\x00",
}


# Capability identifiers of the HGUET/server registry (docs/implementation/capability-registry.md). Only
# `network_health` is evaluated by a real server today; the other ids exist but are not implemented.
SERVER_CAPABILITY_IDS = ("network_health", "program_risk", "program_upgrade_history", "behavior_window",
                         "token_extensions", "authority_changes", "cpi_metadata", "independent_rpc_simulation",
                         "extra_feed_lookup")
REAL_SERVER_CAPABILITIES = ["network_health"]

_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data):
    number = int.from_bytes(data, "big")
    out = ""
    while number:
        number, rem = divmod(number, 58)
        out = _B58[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\x00"))) + out


def canonical_solana_signature(text):
    """S7.1: Base58 text of exactly 64 bytes that re-encodes to the identical text and is not all zero."""
    if not isinstance(text, str) or not text or not text.isascii() or any(c not in _B58 for c in text):
        return False
    number = 0
    for char in text:
        number = number * 58 + _B58.index(char)
    raw = number.to_bytes((number.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(text) - len(text.lstrip("1"))) + raw
    return len(raw) == 64 and b58encode(raw) == text and any(raw)


def canonical_memo(quote_id):
    """S7.1: the payment memo is exactly `HGUET:<quote_id>` with a 32-lowercase-hex quote id."""
    ok = isinstance(quote_id, str) and len(quote_id) == 32 and all(c in "0123456789abcdef" for c in quote_id)
    return "HGUET:" + quote_id if ok else None


class ProfileError(ValueError):
    """A violation of an S7.1 profile; `code` is the stable error code shared with the server's golden vectors."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


_CLIENT_EVIDENCE_KEYS = {"schema_version", "kind", "local_decision", "finding_codes", "coverage"}
CLIENT_EVIDENCE_DECISIONS = ("ALLOW", "WARN", "DENY", "UNKNOWN")
CLIENT_EVIDENCE_MAX_BYTES = 4096


def _strict_json(data):
    import json

    def pairs(items):
        keys = [k for k, _ in items]
        if len(set(keys)) != len(keys):
            raise ProfileError("JSON_DUPLICATE_KEY")
        return dict(items)

    def reject_float(_):
        raise ProfileError("JSON_FLOAT_NOT_ALLOWED")

    def reject_constant(_):
        raise ProfileError("JSON_MALFORMED")

    if data.startswith(b"\xef\xbb\xbf"):
        raise ProfileError("JSON_BOM")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise ProfileError("JSON_INVALID_UTF8") from None
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_float=reject_float, parse_constant=reject_constant)
    except ProfileError:
        raise
    except (ValueError, RecursionError):
        raise ProfileError("JSON_MALFORMED") from None


def _name_list(value, limit, first, rest):
    if not isinstance(value, list) or len(value) > limit:
        return None
    ok = all(isinstance(v, str) and 1 <= len(v) <= (128 if first.isupper() else 96) and v.isascii() and v[0] in first
             and all(c in rest for c in v) for v in value)
    return value if ok else None


def validate_client_evidence(data, local_decision):
    """S7.1 ClientEvidence redaction profile. Returns "ABSENT" (empty) or "OK"; raises ProfileError otherwise."""
    import string
    if not data:
        return "ABSENT"
    if len(data) > CLIENT_EVIDENCE_MAX_BYTES:
        raise ProfileError("CLIENT_EVIDENCE_TOO_LARGE")
    value = _strict_json(data)
    if not isinstance(value, dict) or set(value) != _CLIENT_EVIDENCE_KEYS:
        raise ProfileError("CLIENT_EVIDENCE_KEYS")
    schema = value["schema_version"]
    if isinstance(schema, bool) or schema != 1 or value["kind"] != "hguet_client_evidence":
        raise ProfileError("CLIENT_EVIDENCE_KIND")
    if value["local_decision"] not in CLIENT_EVIDENCE_DECISIONS:
        raise ProfileError("CLIENT_EVIDENCE_DECISION")
    upper, lower, digits = string.ascii_uppercase, string.ascii_lowercase, string.digits
    codes = _name_list(value["finding_codes"], 64, upper, upper + digits + "_")
    if codes is None:
        raise ProfileError("CLIENT_EVIDENCE_CODES")
    coverage = _name_list(value["coverage"], 32, lower, lower + digits + "_")
    if coverage is None:
        raise ProfileError("CLIENT_EVIDENCE_COVERAGE")
    if any(a >= b for a, b in zip(codes, codes[1:])) or any(a >= b for a, b in zip(coverage, coverage[1:])):
        raise ProfileError("CLIENT_EVIDENCE_NOT_SORTED_UNIQUE")
    if build_client_evidence(value["local_decision"], codes, coverage) != data:
        raise ProfileError("CLIENT_EVIDENCE_NOT_CANONICAL")
    if value["local_decision"] != local_decision:
        raise ProfileError("CLIENT_EVIDENCE_DECISION_MISMATCH")
    return "OK"


def build_client_evidence(local_decision, finding_codes=(), coverage=()):
    """Canonical redacted local evidence: ONLY decision, finding codes and coverage names. Never accounts, programs,
    amounts, instruction data, URLs, paths, intents or signatures."""
    import json
    body = {"schema_version": 1, "kind": "hguet_client_evidence", "local_decision": local_decision,
            "finding_codes": sorted(finding_codes), "coverage": sorted(coverage)}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def parse_time(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def fmt_time(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# Benchmark subject types -> public Subject.category. `alt_table` has no category in the public proto; it appears
# only in reference-server scenarios (never sent to a real server) and keeps its own name there.
CATEGORY_FOR_TYPE = {"program": "program", "mint": "mint", "account": "destination", "alt_table": "alt_table",
                     "destination": "destination", "merchant": "merchant"}  # last two: already S7.1 categories


def subjects_digest(subjects, network):
    """S7.1 canonical subject set (docs/architecture/canonical-contract-s7.md in HGUET/server, adopted by the
    benchmark): SHA-256(JCS([{category, network, subject_id}, ...])) sorted byte-wise by
    (category, network, subject_id); duplicates are an error. Address validity is the server's job and is not
    re-checked here because benchmark fixtures use synthetic ids."""
    items = [{"category": CATEGORY_FOR_TYPE[s["type"]], "network": network, "subject_id": s["id"]} for s in subjects]
    keys = [(i["category"].encode(), i["network"].encode(), i["subject_id"].encode()) for i in items]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate subject")
    ordered = [i for _, i in sorted(zip(keys, items), key=lambda p: p[0])]
    return hashlib.sha256(jcs.canonicalize(ordered)).hexdigest()


def evidence_manifest(records):
    """S7.1 manifest: JCS array of the records sorted by their own JCS bytes; a duplicate record is an error."""
    encoded = sorted(jcs.canonicalize(r) for r in records)
    if len(set(encoded)) != len(encoded):
        raise ValueError("duplicate evidence record")
    return b"[" + b",".join(encoded) + b"]"


def evidence_sha256(record):
    """Per-source digest: SHA-256 of the manifest the source attests (here: a manifest of its one record)."""
    return hashlib.sha256(evidence_manifest([record])).hexdigest()


def evidence_digest(records):
    """Assessment digest: SHA-256 of the manifest of the deduplicated union of all cited records."""
    unique = {jcs.canonicalize(r): r for r in records}
    return hashlib.sha256(evidence_manifest(list(unique.values()))).hexdigest()
