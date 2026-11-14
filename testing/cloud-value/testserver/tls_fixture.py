"""Throw-away test CA + server certificate (openssl CLI). TLS verification stays ON in every test:
the client trusts exactly this CA file and checks the hostname; nothing is ever switched off."""
import shutil
import subprocess
import tempfile
from pathlib import Path


def available():
    return shutil.which("openssl") is not None


class TestPki:
    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="hguet-test-pki-"))
        run = lambda *a: subprocess.run(a, check=True, capture_output=True, cwd=self.dir, timeout=60)  # noqa: E731
        run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", "ca.key", "-out", "ca.crt", "-subj", "/CN=hguet-bench-test-ca", "-days", "2")
        run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout",
            "srv.key", "-out", "srv.csr", "-subj", "/CN=localhost")
        (self.dir / "ext.cnf").write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\n")
        run("openssl", "x509", "-req", "-in", "srv.csr", "-CA", "ca.crt", "-CAkey", "ca.key", "-CAcreateserial",
            "-out", "srv.crt", "-days", "2", "-extfile", "ext.cnf")
        # a second, UNTRUSTED CA for negative tests (server cert signed by someone the client does not pin)
        run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-keyout", "evil.key", "-out", "evil.crt", "-subj", "/CN=untrusted-ca", "-days", "2")
        run("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout",
            "bad.key", "-out", "bad.csr", "-subj", "/CN=localhost")
        run("openssl", "x509", "-req", "-in", "bad.csr", "-CA", "evil.crt", "-CAkey", "evil.key", "-CAcreateserial",
            "-out", "bad.crt", "-days", "2", "-extfile", "ext.cnf")

    @property
    def ca(self):
        return str(self.dir / "ca.crt")

    @property
    def server(self):
        return str(self.dir / "srv.crt"), str(self.dir / "srv.key")

    @property
    def untrusted_server(self):
        return str(self.dir / "bad.crt"), str(self.dir / "bad.key")

    def cleanup(self):
        shutil.rmtree(self.dir, ignore_errors=True)
