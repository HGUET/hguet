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
