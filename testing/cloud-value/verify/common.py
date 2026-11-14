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


def parse_time(text):
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def fmt_time(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def subjects_digest(subjects):
    """Canonical subject-set binding used by the benchmark. The public proto says only 'canonical sorted
    risk-subject set'; this exact canonicalisation is an ASSUMPTION to be confirmed by the protocol owners."""
    ordered = sorted(subjects, key=lambda s: (s["type"], s["id"]))
    return hashlib.sha256(jcs.canonicalize(ordered)).hexdigest()
