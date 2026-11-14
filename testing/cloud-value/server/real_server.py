"""Adapter for a REAL HGUET Server. Disabled unless explicitly enabled; sends NOTHING otherwise.

Connection contract (to be honoured by the server team; see testing/cloud-value/README.md):

  POST {base}/v1/assessments        Content-Type: application/json
  body  = a `hguet-cloud-request/1` document: network, data_scope="metadata_only", profile,
          message_sha256, transaction_sha256, intent_sha256 and `subjects` (program / account /
          mint / alt_table identifiers). No raw transaction bytes, no keys, no secrets, no
          ground truth. Payment/quote handling is out of scope for this adapter.
  reply = {"assessment": <CloudAssessment>, "signature": {alg, key_id, sig_b58}}

The reply is then verified by `verify/assessment_rules.py` exactly like the reference mock; the
algorithm registry already knows `ml-dsa-87` and reports `unsupported_signature_alg` until a
verifier is plugged in, so an unverifiable answer can never be believed.

Safeguards: both `enabled` and a URL are required; https only (loopback http only with the explicit
`allow_insecure_loopback` test switch); bounded timeout and response size; a hard allow-list of
request fields; no redirects followed.
"""
import json
import time
import urllib.error
import urllib.parse
import urllib.request

ALLOWED_REQUEST_FIELDS = {"format", "network", "data_scope", "profile", "message_sha256", "transaction_sha256",
                          "intent_sha256", "subjects"}
MAX_RESPONSE_BYTES = 262_144


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never follow redirects
        return None


class RealServerAdapter:
    kind = "real_server"

    def __init__(self, url=None, enabled=False, allow_insecure_loopback=False, timeout=10.0):
        self.url, self.enabled = url, enabled
        self.allow_insecure_loopback = allow_insecure_loopback
        self.timeout = timeout
        self.requests_sent = 0
        self.bytes_sent = 0
        self.fields_sent = set()
        self.last_latency_s = None
        self.cost_units = None  # unknown until the server publishes pricing

    def unavailable_reason(self):
        if not self.enabled:
            return "real server not enabled (pass --enable-real-server and --real-server-url); nothing was sent"
        if not self.url:
            return "no real server URL configured; nothing was sent"
        parsed = urllib.parse.urlparse(self.url)
        loopback = parsed.hostname in ("127.0.0.1", "localhost", "::1")
        if parsed.scheme != "https" and not (self.allow_insecure_loopback and loopback):
            return "real server URL must be https (loopback http only with the explicit test switch)"
        return None

    def assess(self, request, now_iso):
        reason = self.unavailable_reason()
        if reason:
            return None
        extra = set(request) - ALLOWED_REQUEST_FIELDS
        if extra or request.get("data_scope") != "metadata_only":
            raise ValueError("request would leak fields outside the metadata-only contract: %s" % sorted(extra))
        body = json.dumps(request, sort_keys=True).encode()
        endpoint = self.url.rstrip("/") + "/v1/assessments"
        opener = urllib.request.build_opener(_NoRedirect)
        started = time.perf_counter()
        try:
            req = urllib.request.Request(endpoint, data=body, method="POST",
                                         headers={"Content-Type": "application/json", "Accept": "application/json",
                                                  "User-Agent": "hguet-cloud-value-benchmark"})
            with opener.open(req, timeout=self.timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            self.requests_sent += 1
            self.bytes_sent += len(body)
            self.fields_sent |= set(request)
            self.last_latency_s = time.perf_counter() - started
            if len(raw) > MAX_RESPONSE_BYTES:
                return None
            return json.loads(raw)
        except (urllib.error.URLError, OSError, ValueError):
            self.last_latency_s = time.perf_counter() - started
            return None
