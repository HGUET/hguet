#!/usr/bin/env python3
"""Live multi-UID test of the BLOCK-only admission gateway (Linux, needs root).

Three dedicated, unprivileged, throw-away accounts:
  svc      - runs the admission gateway + protected launcher (service identity)
  allowed  - the only UID listed in the admission policy
  denied   - member of the same socket group (so it CAN connect) but NOT admitted
plus `nobody`, which is outside the socket group.

Path under test:
  Unix socket -> SO_PEERCRED -> protected launcher -> replay journal
  -> Bubblewrap -> BLOCK

Nothing here signs, holds a key, touches the network or any wallet. The signed
intent is the public synthetic 0x2a test fixture. Every system object created
is removed again. Prints SKIP (exit 0) when the environment cannot run it; a
SKIP is NOT a PASS and callers must report it as such.
"""
import grp
import hashlib
import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "target/debug/hguet-signer-isolate").resolve()
PIN = "2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ"
LIB = Path("/usr/lib/hguet-t-admission")
ETC = Path("/etc/hguet-t-admission")
VAR = Path("/var/lib/hguet-t-admission")
RUN = Path("/run/hguet-t-admission")
SOCK = RUN / "admission.sock"
JOURNAL = VAR / "replay"
SVC, ALLOWED, DENIED, GROUP = "hguett-svc", "hguett-ok", "hguett-no", "hguett-clients"


def skip(reason):
    print("SKIP: " + reason)
    sys.exit(0)


if sys.platform != "linux":
    skip("not Linux")
if os.geteuid() != 0:
    skip("root is required to create the three test identities")
for tool in ("useradd", "userdel", "groupadd", "groupdel", "runuser"):
    if not shutil.which(tool):
        skip(tool + " not available")
if not BIN.exists():
    skip("signer binary not built: " + str(BIN))
if not Path("/usr/bin/bwrap").exists():
    skip("bubblewrap not installed")
for leftover in (LIB, ETC, VAR, RUN):
    if leftover.exists():
        skip("stale test directory present, refusing to touch it: " + str(leftover))
for name in (SVC, ALLOWED, DENIED, GROUP):
    try:
        pwd.getpwnam(name)
        skip("test account already exists: " + name)
    except KeyError:
        pass

WIRE = (ROOT / "tests/fixtures/legacy-spl-transfer-checked-authority-signer.base64").read_text().strip()
ENVELOPE = json.loads((ROOT / "tests/fixtures/signed-direct-token-source-cap-equal.json").read_text())
REQUEST = json.dumps({
    "schema_version": 1, "kind": "hguet_signer_preflight",
    "original_transaction_b64": WIRE, "signed_intent": ENVELOPE,
}).encode()

CLIENT = r"""
import socket, sys
s = socket.socket(socket.AF_UNIX)
s.settimeout(30)
try:
    s.connect(sys.argv[1])
except OSError as e:
    print("CONNECT_FAILED " + e.__class__.__name__); sys.exit(3)
try:
    s.sendall(sys.stdin.buffer.read()); s.shutdown(socket.SHUT_WR)
except OSError:
    pass  # gateway may refuse and close before reading: that is the point
out = b""
try:
    while True:
        b = s.recv(65536)
        if not b:
            break
        out += b
except OSError:
    pass
sys.stdout.buffer.write(out)
"""

failures = []


def check(name, condition, detail=""):
    print(("  ok   " if condition else "  FAIL ") + name + ("" if condition else "  " + str(detail)))
    if not condition:
        failures.append(name)


def sh(*cmd, **kw):
    return subprocess.run(cmd, capture_output=True, timeout=60, **kw)


def as_user(user, *cmd, data=b""):
    return subprocess.run(["runuser", "-u", user, "--", *cmd], input=data,
                          capture_output=True, timeout=60)


def start_gateway():
    proc = subprocess.Popen(
        ["runuser", "-u", SVC, "--", "/usr/bin/python3",
         str(LIB / "scripts/run_signer_admission.py"), "--admission", str(ETC / "admission.json")],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for _ in range(100):
        if SOCK.exists() or proc.poll() is not None:
            break
        time.sleep(0.05)
    return proc


def finish_gateway(proc):
    try:
        out, err = proc.communicate(timeout=40)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return -9, out, err
    return proc.returncode, out, err


def journal():
    return sorted(os.listdir(JOURNAL))


def client(user, data=REQUEST):
    return as_user(user, "/usr/bin/python3", "-I", "-c", CLIENT, str(SOCK), data=data)


def setup():
    sh("groupadd", "--system", GROUP)
    sh("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", SVC)
    for user in (ALLOWED, DENIED):
        sh("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin",
           "--groups", GROUP, user)
    svc = pwd.getpwnam(SVC)
    for path, mode in ((LIB, 0o755), (LIB / "scripts", 0o755), (LIB / "bin", 0o755),
                       (ETC, 0o755), (VAR, 0o755)):
        path.mkdir(mode=mode, parents=True)
        os.chmod(path, mode)
    for name in ("run_signer_admission.py", "run_signer_protected.py", "run_signer_sandbox.py"):
        shutil.copy(ROOT / "scripts" / name, LIB / "scripts" / name)
        os.chmod(LIB / "scripts" / name, 0o644)
    shutil.copy(BIN, LIB / "bin/hguet-signer-isolate")
    os.chmod(LIB / "bin/hguet-signer-isolate", 0o755)
    JOURNAL.mkdir(mode=0o700)
    os.chown(JOURNAL, svc.pw_uid, svc.pw_gid)
    os.chmod(JOURNAL, 0o700)
    # Service-owned socket directory: group may traverse, nobody may write/rename.
    RUN.mkdir(mode=0o750)
    os.chown(RUN, svc.pw_uid, grp.getgrnam(GROUP).gr_gid)
    os.chmod(RUN, 0o2750)  # setgid: the socket inherits the client group
    digest = hashlib.sha256((LIB / "bin/hguet-signer-isolate").read_bytes()).hexdigest()
    (ETC / "policy.json").write_text(json.dumps({
        "schema_version": 1, "kind": "hguet_protected_signer_policy",
        "binary": str(LIB / "bin/hguet-signer-isolate"), "binary_sha256": digest,
        "network": "devnet", "trusted_key": PIN, "replay_directory": str(JOURNAL)}, sort_keys=True))
    (ETC / "admission.json").write_text(json.dumps({
        "schema_version": 1, "kind": "hguet_signer_admission", "socket_path": str(SOCK),
        "allowed_client_uid": pwd.getpwnam(ALLOWED).pw_uid,
        "protected_policy": str(ETC / "policy.json")}, sort_keys=True))
    for name in ("policy.json", "admission.json"):
        os.chmod(ETC / name, 0o644)


def teardown():
    for user in (ALLOWED, DENIED, SVC):
        sh("userdel", user)
    sh("groupdel", GROUP)
    for path in (LIB, ETC, VAR, RUN):
        shutil.rmtree(path, ignore_errors=True)


def probe_sandbox_as_service():
    # Fail closed is correct when namespaces are unavailable; but then the live
    # BLOCK path cannot be exercised and this must be reported as SKIP.
    result = as_user(SVC, "/usr/bin/bwrap", "--unshare-all", "--unshare-user", "--disable-userns",
                     "--assert-userns-disabled", "--cap-drop", "ALL", "--ro-bind", "/usr", "/usr",
                     "--ro-bind-try", "/lib", "/lib", "--ro-bind-try", "/lib64", "/lib64",
                     "/usr/bin/true")
    return result.returncode == 0


try:
    setup()
    if not probe_sandbox_as_service():
        teardown()
        skip("service identity cannot create the required Bubblewrap namespaces")
    print("admission gateway: multi-UID live test")

    # 1. Unauthorized UID: can connect (shared group) yet is refused by
    #    SO_PEERCRED before any payload is read and before the journal exists.
    gw = start_gateway()
    result = client(DENIED)
    code, out, err = finish_gateway(gw)
    check("unauthorized UID gets blocked reply, no signer output",
          b"HGUET_ADMISSION_BLOCKED" in result.stdout and b"signer_refusal" not in result.stdout, result)
    check("gateway exits 40 and names the UID refusal", code == 40 and b"unauthorized peer UID" in err, (code, err))
    check("replay journal untouched by unauthorized UID", journal() == [], journal())
    check("gateway removed its own socket", not SOCK.exists())

    # 2. Peer outside the socket group cannot even connect.
    gw = start_gateway()
    outsider = as_user("nobody", "/usr/bin/python3", "-I", "-c", CLIENT, str(SOCK), data=REQUEST)
    check("peer outside socket group cannot connect", b"CONNECT_FAILED" in outsider.stdout, outsider)

    # 3. Socket cannot be deleted/renamed/replaced by other UIDs while waiting.
    for user in (DENIED, ALLOWED, "nobody"):
        r = as_user(user, "/usr/bin/python3", "-I", "-c",
                    "import os,sys\n"
                    "p=sys.argv[1]\n"
                    "bad=[]\n"
                    "for f in (lambda: os.unlink(p), lambda: os.rename(p,p+'.x')):\n"
                    "    try: f(); bad.append('allowed')\n"
                    "    except OSError: pass\n"
                    "print('BAD' if bad else 'OK')", str(SOCK))
        check("UID %s cannot unlink/rename the admission socket" % user, r.stdout.strip() == b"OK", r)
    st = os.lstat(SOCK)
    check("socket is service-owned 0660", st.st_uid == pwd.getpwnam(SVC).pw_uid and (st.st_mode & 0o777) == 0o660,
          oct(st.st_mode))

    # 4. Allowed UID reaches BLOCK through the sandbox; intent is reserved.
    result = client(ALLOWED)
    code, out, err = finish_gateway(gw)
    try:
        refusal = json.loads(result.stdout)["signer_refusal"]
    except (ValueError, KeyError):
        refusal = {}
    check("allowed UID receives sandboxed BLOCK refusal",
          code == 20 and refusal.get("signing_gate") == "block"
          and refusal.get("signing_permitted") is False
          and refusal.get("signature_created") is False
          and refusal.get("transaction_broadcast") is False, (code, result.stdout[:200], err[:300]))
    check("intent signature verified inside sandbox but never approves",
          refusal.get("independent_intent_signature_verified") is True
          and refusal.get("reason_code") == "SIGNER_SIDE_ENFORCEMENT_NOT_IMPLEMENTED", refusal)
    check("exactly one replay marker reserved", len(journal()) == 1, journal())
    marker_before = journal()

    # 5. Replay of the same intent_id through the gateway is refused.
    gw = start_gateway()
    result = client(ALLOWED)
    code, out, err = finish_gateway(gw)
    # The gateway deliberately never forwards the child's stderr, so the cause
    # is confirmed below by invoking the launcher directly as the service UID.
    check("replayed intent_id refused by gateway, no signer output", code == 40
          and b"HGUET_ADMISSION_BLOCKED" in result.stdout
          and b"signer_refusal" not in result.stdout, (code, err[:300], result.stdout[:100]))
    check("replay did not alter the journal", journal() == marker_before, journal())

    # 6. Unprivileged callers cannot bypass the gateway by running the launcher.
    for user in (ALLOWED, DENIED):
        r = as_user(user, "/usr/bin/python3", "-E", "-s", str(LIB / "scripts/run_signer_protected.py"),
                    "--policy", str(ETC / "policy.json"), data=REQUEST)
        check("UID %s cannot run protected launcher directly" % user,
              r.returncode == 40 and b"signer_refusal" not in r.stdout, (r.returncode, r.stderr[:200]))
    check("direct attempts left journal unchanged", journal() == marker_before, journal())

    # 7. KNOWN LIMITATION (documented, asserted so a behaviour change is noticed):
    #    UID checks are not user authentication. Any process that already runs
    #    as the service UID can invoke the protected launcher directly,
    #    bypassing the gateway allow-list. It still gets only BLOCK.
    r = as_user(SVC, "/usr/bin/python3", "-E", "-s", str(LIB / "scripts/run_signer_protected.py"),
                "--policy", str(ETC / "policy.json"), data=REQUEST)
    check("reserved intent_id is the cause of the refusal (REPLAY_BLOCKED)",
          r.returncode == 40 and b"REPLAY_BLOCKED" in r.stderr, (r.returncode, r.stderr[:200]))
    for name in journal():
        os.unlink(JOURNAL / name)
    r = as_user(SVC, "/usr/bin/python3", "-E", "-s", str(LIB / "scripts/run_signer_protected.py"),
                "--policy", str(ETC / "policy.json"), data=REQUEST)
    try:
        bypass = json.loads(r.stdout)["signer_refusal"]
    except (ValueError, KeyError):
        bypass = {}
    check("service-UID bypass of gateway exists but is BLOCK-only (known limitation)",
          r.returncode == 20 and bypass.get("signing_permitted") is False
          and bypass.get("signature_created") is False, (r.returncode, r.stderr[:200]))
finally:
    teardown()

if failures:
    print("FAIL: " + "; ".join(failures))
    sys.exit(1)
print("PASS: Unix socket -> SO_PEERCRED -> protected signer -> replay journal -> Bubblewrap -> BLOCK, "
      "unauthorized/outsider/replay/direct-call refused, socket not removable by others")
