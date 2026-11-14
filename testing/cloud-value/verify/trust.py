"""Pinned issuer keys (trust store). A signature is only meaningful relative to a key the VERIFIER pins
independently of the message: unknown, expired, wrong-purpose or wrong-environment keys never verify."""
import base64
import json
from pathlib import Path

from common import parse_time

TRUST_DIR = Path(__file__).resolve().parent / "trust"


class TrustStore:
    def __init__(self, keys, source):
        self.keys = {k["key_id"]: k for k in keys}
        self.source = source

    @classmethod
    def load(cls, path):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("format") != "hguet-trust-store/1":
            raise ValueError("unsupported trust store format")
        return cls(data["keys"], str(path))

    @classmethod
    def test_issuers(cls):
        return cls.load(TRUST_DIR / "test_issuers.json")

    @classmethod
    def real_issuers(cls):
        """The real HGUET issuer pins. Returns None while none are provisioned (the default)."""
        path = TRUST_DIR / "real_issuers.json"
        return cls.load(path) if path.exists() else None

    def lookup(self, key_id, algorithm, purpose, now):
        """Return (key_entry, None) or (None, reason)."""
        key = self.keys.get(key_id)
        if key is None:
            return None, "unknown_key"
        if key["algorithm"] != algorithm:
            return None, "key_algorithm_mismatch"
        if not (parse_time(key["not_before"]) <= now <= parse_time(key["not_after"])):
            return None, "key_not_valid_at_time"
        if purpose not in key["purposes"]:
            return None, "key_wrong_purpose"
        return key, None

    @staticmethod
    def public_bytes(key):
        return base64.b64decode(key["public_key_b64"])
