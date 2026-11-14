"""ML-DSA-87 (FIPS 204) verification through OpenSSL >= 3.5 - a vetted implementation, NOT custom crypto.

No ML-DSA code is written here. The module only (a) wraps the `openssl` command line, (b) builds the
SubjectPublicKeyInfo for a raw 2592-byte key, and (c) is checked against the NIST ACVP FIPS 204
known-answer vectors (`vectors/mldsa87_acvp_sigver.json`, 15 external/pure ML-DSA-87 cases, 12 of
which MUST be rejected). If OpenSSL < 3.5 is the only thing available, the backend reports
`available() == False` and every ML-DSA-87 signature is treated as UNVERIFIABLE (discarded), never
accepted.

Signing exists for TEST fixtures only (deterministic key from a seed label; the benchmark's mock
server). The HGUET benchmark never holds a production issuer key.
"""
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

PK_LEN, SIG_LEN, SK_NOTE = 2592, 4627, "private keys exist only as test seeds"
# DER: SEQ{ SEQ{ OID 2.16.840.1.101.3.4.3.19 }, BIT STRING { 00 || raw public key } }
_ALG_ID = bytes.fromhex("300b0609608648016503040313")
VECTORS = Path(__file__).resolve().parent / "vectors" / "mldsa87_acvp_sigver.json"


def spki_der(raw_public_key: bytes) -> bytes:
    if len(raw_public_key) != PK_LEN:
        raise ValueError("ML-DSA-87 public key must be %d bytes" % PK_LEN)
    bits = b"\x00" + raw_public_key
    bit_string = b"\x03\x82" + len(bits).to_bytes(2, "big") + bits
    body = _ALG_ID + bit_string
    return b"\x30\x82" + len(body).to_bytes(2, "big") + body


class OpenSslMlDsa87:
    name = "openssl-cli"

    def __init__(self, binary=None):
        self.binary = binary or shutil.which("openssl")
        self._cache = {}
        self._available = None
        self.reason = ""

    def available(self):
        if self._available is not None:
            return self._available
        self._available = False
        if not self.binary:
            self.reason = "openssl not found"
            return False
        try:
            version = subprocess.run([self.binary, "version"], capture_output=True, text=True, timeout=10).stdout
            algos = subprocess.run([self.binary, "list", "-signature-algorithms"], capture_output=True,
                                   text=True, timeout=10).stdout
        except (OSError, subprocess.TimeoutExpired) as exc:
            self.reason = "openssl not runnable: %s" % exc
            return False
        if re.search(r"ML-DSA-87", algos):
            self._available = True
            self.version = version.strip()
        else:
            self.reason = "%s lacks ML-DSA-87 (needs OpenSSL >= 3.5)" % version.strip()
        return self._available

    def verify(self, public_key: bytes, message: bytes, signature: bytes, context: bytes = b"") -> bool:
        """True only on a verified signature. Any error, absence of backend or malformed input -> False."""
        if not self.available() or len(public_key) != PK_LEN or len(signature) != SIG_LEN or len(context) > 255:
            return False
        key = (hashlib.sha256(public_key).digest(), hashlib.sha256(message).digest(), hashlib.sha256(signature).digest(), context)
        if key in self._cache:
            return self._cache[key]
        with tempfile.TemporaryDirectory(prefix="mldsa-") as tmp:
            tmp = Path(tmp)
            (tmp / "pk.der").write_bytes(spki_der(public_key))
            (tmp / "m").write_bytes(message)
            (tmp / "s").write_bytes(signature)
            cmd = [self.binary, "pkeyutl", "-verify", "-pubin", "-inkey", str(tmp / "pk.der"), "-keyform", "DER",
                   "-rawin", "-in", str(tmp / "m"), "-sigfile", str(tmp / "s")]
            if context:
                cmd += ["-pkeyopt", "hexcontext-string:" + context.hex()]
            try:
                done = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                ok = done.returncode == 0 and "Successfully" in done.stdout
            except (OSError, subprocess.TimeoutExpired):
                ok = False
        self._cache[key] = ok
        return ok

    # ----------------------------------------------------------- test-only signing
    def test_keypair(self, label: str):
        """Deterministic TEST key (seed = SHA-256(label)). Returns (pem_text, raw_public_key)."""
        if not self.available():
            raise RuntimeError("ML-DSA-87 backend unavailable: " + self.reason)
        seed = hashlib.sha256(("hguet-bench-mldsa87-test-only:" + label).encode()).hexdigest()
        with tempfile.TemporaryDirectory(prefix="mldsa-") as tmp:
            pem = Path(tmp) / "k.pem"
            subprocess.run([self.binary, "genpkey", "-algorithm", "ML-DSA-87", "-pkeyopt", "hexseed:" + seed,
                            "-out", str(pem)], check=True, capture_output=True, timeout=30)
            der = subprocess.run([self.binary, "pkey", "-in", str(pem), "-pubout", "-outform", "DER"],
                                 check=True, capture_output=True, timeout=30).stdout
            return pem.read_text(), der[-PK_LEN:]

    def test_sign(self, pem_text: str, message: bytes, context: bytes = b"") -> bytes:
        with tempfile.TemporaryDirectory(prefix="mldsa-") as tmp:
            tmp = Path(tmp)
            (tmp / "k.pem").write_text(pem_text)
            (tmp / "m").write_bytes(message)
            cmd = [self.binary, "pkeyutl", "-sign", "-inkey", str(tmp / "k.pem"), "-rawin", "-in", str(tmp / "m"),
                   "-out", str(tmp / "s")]
            if context:
                cmd += ["-pkeyopt", "hexcontext-string:" + context.hex()]
            subprocess.run(cmd, check=True, capture_output=True, timeout=30)
            return (tmp / "s").read_bytes()


BACKEND = OpenSslMlDsa87()


def run_known_answer_tests(backend=BACKEND):
    """Return (passed, total, failures). Every ACVP vector must produce its expected accept/reject."""
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    failures, passed = [], 0
    for case in data["tests"]:
        got = backend.verify(bytes.fromhex(case["pk"]), bytes.fromhex(case["message"]),
                             bytes.fromhex(case["signature"]), bytes.fromhex(case["context"]))
        if got == case["testPassed"]:
            passed += 1
        else:
            failures.append({"tcId": case["tcId"], "expected": case["testPassed"], "got": got})
    return passed, len(data["tests"]), failures
