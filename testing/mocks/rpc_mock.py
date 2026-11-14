"""Deterministic mock Solana RPC endpoints (transport level) for the benchmark.

HGUET only talks to HTTPS endpoints validated against the public WebPKI roots, so
a mock server CANNOT impersonate a real RPC provider to the real CLI without
weakening TLS verification (which this benchmark refuses to do). What a mock CAN
do honestly and deterministically is misbehave at the transport layer, and prove
the CLI fails closed:

  closed_port      nothing listens on the port (connection refused)
  non_tls_garbage  accepts, answers with a plaintext HTTP/JSON body (no TLS)
  hangup           accepts and closes immediately

Successful-simulation enrichment is exercised by the Rust unit tests through the
injectable `JsonRpcTransport`; it is out of reach of the CLI-level benchmark and is
reported as such. Nothing here forwards to a real network.
"""
import socket
import threading

_GARBAGE = (b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 40\r\n\r\n"
            b'{"jsonrpc":"2.0","result":{"value":null}}')


class MockRpc:
    def __init__(self, behavior):
        if behavior not in ("closed_port", "non_tls_garbage", "hangup"):
            raise ValueError("unknown mock RPC behavior: " + behavior)
        self.behavior = behavior
        self.port = None
        self.requests_seen = 0
        self._server = None
        self._thread = None

    def __enter__(self):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        self.port = probe.getsockname()[1]
        if self.behavior == "closed_port":
            probe.close()  # port is free and nothing listens: refused
            return self
        probe.listen(4)
        probe.settimeout(0.2)
        self._server = probe
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except (socket.timeout, OSError):
                continue
            self.requests_seen += 1
            try:
                if self.behavior == "non_tls_garbage":
                    conn.settimeout(1)
                    try:
                        conn.recv(4096)
                    except OSError:
                        pass
                    conn.sendall(_GARBAGE)
            except OSError:
                pass
            finally:
                conn.close()

    def __exit__(self, *exc):
        if self._server is not None:
            self._stop.set()
            self._thread.join(2)
            self._server.close()
        return False

    @property
    def url(self):
        return "https://127.0.0.1:%d" % self.port
