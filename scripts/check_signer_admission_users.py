#!/usr/bin/env python3
"""Live multi-UID test of the BLOCK-only admission architecture (Linux, root).

Throw-away unprivileged accounts:
  gw       gateway UID in the SPLIT topology (no access to the replay journal)
  signer   journal owner / backend UID (also the gateway UID in SINGLE topology)
  allowed  the only client UID admitted by the gateway
  denied   same socket group as `allowed` (can connect) but NOT admitted
  nobody   outside every socket group

Topology SINGLE: gateway and journal share the signer UID (documented bypass:
any process under that UID can run the launcher directly).
Topology SPLIT:  client -> gateway(gw) -> backend(signer, journal owner) ->
Bubblewrap -> BLOCK. The gateway UID can no longer run the launcher or open the
journal, closing the gateway-account bypass.

Nothing here signs, holds a key, uses the network or a wallet. The signed intent
is the public synthetic 0x2a test fixture. All system objects are removed again.

Exit codes: 0 PASS, 1 FAIL. Environment limits print SKIP and exit 0 UNLESS
HGUET_REQUIRE_LIVE=1, where a SKIP is a FAIL (a skipped security test is not a
passed one).
"""
import grp
import hashlib
import json
import os
import pwd
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BIN = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "target/debug/hguet-signer-isolate").resolve()
PIN = "2iXtA8oeZqUU5pofxK971TCEvFGfems2AcDRaZHKD2pQ"
LIB, ETC, VAR = Path("/usr/lib/hguet-t-admission"), Path("/etc/hguet-t-admission"), Path("/var/lib/hguet-t-admission")
RUN_GW, RUN_BK = Path("/run/hguet-t-admission"), Path("/run/hguet-t-backend")
SOCK, BSOCK = RUN_GW / "admission.sock", RUN_BK / "backend.sock"
JOURNAL = VAR / "replay"
GW, SIGNER, ALLOWED, DENIED = "hguett-gw", "hguett-sg", "hguett-ok", "hguett-no"
CLIENTS, BACKEND = "hguett-clients", "hguett-bk"
USERS, GROUPS = (GW, SIGNER, ALLOWED, DENIED), (CLIENTS, BACKEND)
REQUIRE_LIVE = os.environ.get("HGUET_REQUIRE_LIVE") == "1"


def skip(reason):
    if REQUIRE_LIVE:
        print("FAIL: required live test cannot run (HGUET_REQUIRE_LIVE=1): " + reason)
        sys.exit(1)
    print("SKIP: " + reason + " -- NOT a pass; the property is unverified here")
    sys.exit(0)


if sys.platform != "linux":
    skip("not Linux")
if os.geteuid() != 0:
    skip("root is required to create the test identities")
for tool in ("useradd", "userdel", "groupadd", "groupdel", "runuser", "usermod", "gpasswd"):
    if not shutil.which(tool):
        skip(tool + " not available")
if not BIN.exists():
    skip("signer binary not built: " + str(BIN))
if not Path("/usr/bin/bwrap").exists():
    skip("bubblewrap not installed")
for leftover in (LIB, ETC, VAR, RUN_GW, RUN_BK):
    if leftover.exists():
        skip("stale test directory present, refusing to touch it: " + str(leftover))
for name in USERS:
    try:
        pwd.getpwnam(name)
        skip("test account already exists: " + name)
    except KeyError:
        pass
for name in GROUPS:
    try:
        grp.getgrnam(name)
        skip("test group already exists: " + name)
    except KeyError:
        pass

WIRE = (ROOT / "tests/fixtures/legacy-spl-transfer-checked-authority-signer.base64").read_text().strip()
ENVELOPE = json.loads((ROOT / "tests/fixtures/signed-direct-token-source-cap-equal.json").read_text())
REQUEST = json.dumps({"schema_version": 1, "kind": "hguet_signer_preflight",
                      "original_transaction_b64": WIRE, "signed_intent": ENVELOPE}).encode()

CLIENT = r"""
import socket, sys, time
s = socket.socket(socket.AF_UNIX); s.settimeout(30)
try:
    s.connect(sys.argv[1])
except OSError as e:
    print("CONNECT_FAILED " + e.__class__.__name__); sys.exit(3)
data = sys.stdin.buffer.read()
try:
    s.sendall(data)
    if len(sys.argv) > 2:   # slow-drip mode: never finish the request
        time.sleep(float(sys.argv[2]))
    s.shutdown(socket.SHUT_WR)
except OSError:
    pass
out = b""
try:
    while True:
        b = s.recv(65536)
        if not b: break
        out += b
except OSError:
    pass
sys.stdout.buffer.write(out)
"""

failures = []


def check(name, ok, detail=""):
    print(("  ok   " if ok else "  FAIL ") + name + ("" if ok else "  " + repr(detail)[:400]))
    if not ok:
        failures.append(name)


def sh(*cmd):
    return subprocess.run(cmd, capture_output=True, timeout=60)


def as_user(user, *cmd, data=b""):
    return subprocess.run(["runuser", "-u", user, "--", *cmd], input=data, capture_output=True, timeout=60)


def uid(name):
    return pwd.getpwnam(name).pw_uid


def journal():
    return sorted(os.listdir(JOURNAL))


def clear_journal():
    for name in journal():
        os.unlink(JOURNAL / name)


def client(user, data=REQUEST, *extra):
    return as_user(user, "/usr/bin/python3", "-I", "-c", CLIENT, str(SOCK), *extra, data=data)


def spawn(user, script, *args):
    # setpriv execs the target directly (runuser would sit between us and the
    # service, swallowing SIGTERM), so stop() signals the real service process.
    return subprocess.Popen(["setpriv", "--reuid", str(uid(user)), "--regid", str(pwd.getpwnam(user).pw_gid),
                             "--init-groups", "/usr/bin/python3", str(LIB / "scripts" / script), *args],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def wait_for(path, proc):
    for _ in range(100):
        if os.path.lexists(path) or proc.poll() is not None:
            break
        time.sleep(0.05)


def finish(proc, timeout=40):
    try:
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return -9, out, err


def stop(proc):
    proc.send_signal(signal.SIGTERM)
    return finish(proc, 10)


def direct_launcher(user, data=REQUEST):
    return as_user(user, "/usr/bin/python3", "-E", "-s", str(LIB / "scripts/run_signer_protected.py"),
                   "--policy", str(ETC / "policy.json"), data=data)


def refused(result):
    return b"signer_refusal" not in result.stdout


def mkdir_owned(path, owner, group, mode):
    shutil.rmtree(path, ignore_errors=True)
    path.mkdir(mode=0o700)
    os.chown(path, uid(owner), grp.getgrnam(group).gr_gid)
    os.chmod(path, mode)


def write_cfg(split):
    gw_cfg = {"schema_version": 1, "kind": "hguet_signer_admission", "socket_path": str(SOCK),
              "allowed_client_uid": uid(ALLOWED), "protected_policy": str(ETC / "policy.json")}
    if split:
        gw_cfg.update(backend_socket=str(BSOCK), backend_uid=uid(SIGNER))
    (ETC / "admission.json").write_text(json.dumps(gw_cfg, sort_keys=True))
    (ETC / "backend.json").write_text(json.dumps({
        "schema_version": 1, "kind": "hguet_signer_backend", "socket_path": str(BSOCK),
        "allowed_gateway_uid": uid(GW), "protected_policy": str(ETC / "policy.json")}, sort_keys=True))
    for name in ("admission.json", "backend.json"):
        os.chmod(ETC / name, 0o644)


def setup():
    for group in GROUPS:
        sh("groupadd", "--system", group)
    for user, groups in ((GW, BACKEND), (SIGNER, None), (ALLOWED, CLIENTS), (DENIED, CLIENTS)):
        cmd = ["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin"]
        if groups:
            cmd += ["--groups", groups]
        sh(*cmd, user)
    for path in (LIB, LIB / "scripts", LIB / "bin", ETC, VAR):
        path.mkdir(mode=0o755, parents=True, exist_ok=True)
        os.chmod(path, 0o755)
    for name in ("run_signer_admission.py", "run_signer_backend.py",
                 "run_signer_protected.py", "run_signer_sandbox.py"):
        shutil.copy(ROOT / "scripts" / name, LIB / "scripts" / name)
        os.chmod(LIB / "scripts" / name, 0o644)
    shutil.copy(BIN, LIB / "bin/hguet-signer-isolate")
    os.chmod(LIB / "bin/hguet-signer-isolate", 0o755)
    JOURNAL.mkdir(mode=0o700)
    os.chown(JOURNAL, uid(SIGNER), pwd.getpwnam(SIGNER).pw_gid)
    digest = hashlib.sha256((LIB / "bin/hguet-signer-isolate").read_bytes()).hexdigest()
    (ETC / "policy.json").write_text(json.dumps({
        "schema_version": 1, "kind": "hguet_protected_signer_policy",
        "binary": str(LIB / "bin/hguet-signer-isolate"), "binary_sha256": digest,
        "network": "devnet", "trusted_key": PIN, "replay_directory": str(JOURNAL)}, sort_keys=True))
    os.chmod(ETC / "policy.json", 0o644)


def teardown():
    for user in USERS:
        sh("pkill", "-KILL", "-u", user)  # a crashed run must not leave services behind
        sh("userdel", user)
    for group in GROUPS:
        sh("groupdel", group)
    for path in (LIB, ETC, VAR, RUN_GW, RUN_BK):
        shutil.rmtree(path, ignore_errors=True)


def sandbox_works_for(user):
    r = as_user(user, "/usr/bin/bwrap", "--unshare-all", "--unshare-user", "--disable-userns",
                "--assert-userns-disabled", "--cap-drop", "ALL", "--ro-bind", "/usr", "/usr",
                "--ro-bind-try", "/lib", "/lib", "--ro-bind-try", "/lib64", "/lib64", "/usr/bin/true")
    return r.returncode == 0


def start_stack(split):
    """Return (gateway_user, backend_proc_or_None) with fresh socket directories."""
    gateway_user = GW if split else SIGNER
    mkdir_owned(RUN_GW, gateway_user, CLIENTS, 0o2750)
    backend = None
    if split:
        mkdir_owned(RUN_BK, SIGNER, BACKEND, 0o2750)
        backend = spawn(SIGNER, "run_signer_backend.py", "--backend", str(ETC / "backend.json"))
        wait_for(BSOCK, backend)
    return gateway_user, backend


def start_gateway(gateway_user, *extra):
    extra = extra or ("--once",)
    proc = spawn(gateway_user, "run_signer_admission.py", "--admission", str(ETC / "admission.json"), *extra)
    wait_for(SOCK, proc)
    return proc


def common_scenarios(split):
    tag = "[split] " if split else "[single] "
    clear_journal()
    gateway_user, backend = start_stack(split)

    # Unauthorized UID: may connect (shared group), refused by SO_PEERCRED before
    # any payload is read; the journal is never touched.
    gw = start_gateway(gateway_user)
    result = client(DENIED)
    code, out, err = finish(gw)
    check(tag + "unauthorized UID gets blocked reply, no signer output",
          b"HGUET_ADMISSION_BLOCKED" in result.stdout and refused(result), result.stdout)
    check(tag + "gateway exits 40 naming the UID refusal", code == 40 and b"unauthorized peer UID" in err, (code, err))
    check(tag + "journal untouched by unauthorized UID", journal() == [], journal())
    check(tag + "gateway removed its own socket", not SOCK.exists())

    # Outsider cannot connect; nobody can unlink/rename the live socket.
    gw = start_gateway(gateway_user)
    outsider = as_user("nobody", "/usr/bin/python3", "-I", "-c", CLIENT, str(SOCK), data=REQUEST)
    check(tag + "peer outside socket group cannot connect", b"CONNECT_FAILED" in outsider.stdout, outsider.stdout)
    probe = ("import os,sys\nbad=[]\n"
             "for f in (lambda: os.unlink(sys.argv[1]), lambda: os.rename(sys.argv[1], sys.argv[1]+'.x')):\n"
             "    try: f(); bad.append(1)\n    except OSError: pass\nprint('BAD' if bad else 'OK')")
    for user in (DENIED, ALLOWED, "nobody"):
        r = as_user(user, "/usr/bin/python3", "-I", "-c", probe, str(SOCK))
        check(tag + "UID %s cannot unlink/rename the admission socket" % user, r.stdout.strip() == b"OK", r.stdout)

    # Allowed UID -> sandboxed BLOCK; intent reserved.
    result = client(ALLOWED)
    code, out, err = finish(gw)
    try:
        refusal = json.loads(result.stdout)["signer_refusal"]
    except (ValueError, KeyError):
        refusal = {}
    check(tag + "allowed UID receives sandboxed BLOCK refusal",
          code == 20 and refusal.get("signing_gate") == "block" and refusal.get("signing_permitted") is False
          and refusal.get("signature_created") is False and refusal.get("transaction_broadcast") is False
          and refusal.get("signer_backend_invoked") is False, (code, result.stdout[:200], err[:300]))
    check(tag + "signature verified in sandbox yet never approved",
          refusal.get("independent_intent_signature_verified") is True
          and refusal.get("reason_code") == "SIGNER_SIDE_ENFORCEMENT_NOT_IMPLEMENTED", refusal)
    marker = journal()
    check(tag + "exactly one replay marker reserved", len(marker) == 1, marker)

    # Replay of the same intent_id.
    gw = start_gateway(gateway_user)
    result = client(ALLOWED)
    code, out, err = finish(gw)
    check(tag + "replayed intent_id refused, no signer output",
          code == 40 and b"HGUET_ADMISSION_BLOCKED" in result.stdout and refused(result), (code, result.stdout[:100]))
    check(tag + "replay did not alter the journal", journal() == marker, journal())
    r = direct_launcher(SIGNER)
    check(tag + "cause confirmed: REPLAY_BLOCKED", r.returncode == 40 and b"REPLAY_BLOCKED" in r.stderr, r.stderr[:200])
    return gateway_user, backend, marker


def single_only(gateway_user, marker):
    tag = "[single] "
    for user in (ALLOWED, DENIED):
        r = direct_launcher(user)
        check(tag + "UID %s cannot run protected launcher directly" % user, r.returncode == 40 and refused(r), r.stderr[:200])
    check(tag + "direct attempts left journal unchanged", journal() == marker, journal())
    clear_journal()
    r = direct_launcher(SIGNER)
    try:
        bypass = json.loads(r.stdout)["signer_refusal"]
    except (ValueError, KeyError):
        bypass = {}
    check(tag + "KNOWN LIMITATION: service UID bypasses gateway allow-list (BLOCK-only)",
          r.returncode == 20 and bypass.get("signing_permitted") is False and bypass.get("signature_created") is False,
          (r.returncode, r.stderr[:200]))
    clear_journal()


def split_only(backend, marker):
    tag = "[split] "
    # The gateway account can no longer reach the journal or run the launcher.
    r = direct_launcher(GW)
    check(tag + "gateway UID cannot run the protected launcher (bypass closed)",
          r.returncode == 40 and refused(r), (r.returncode, r.stderr[:200]))
    listing = as_user(GW, "/usr/bin/python3", "-I", "-c", "import os,sys\nprint(os.listdir(sys.argv[1]))", str(JOURNAL))
    check(tag + "gateway UID cannot read the replay journal", listing.returncode != 0, listing.stdout)
    check(tag + "gateway attempts left journal unchanged", journal() == marker, journal())

    # Backend rejects any non-gateway peer, even one inside its socket group.
    sh("usermod", "-aG", BACKEND, DENIED)
    r = as_user(DENIED, "/usr/bin/python3", "-I", "-c", CLIENT, str(BSOCK), data=REQUEST)
    sh("gpasswd", "-d", DENIED, BACKEND)
    check(tag + "backend refuses non-gateway peer UID before reading payload",
          b"HGUET_BACKEND_BLOCKED" in r.stdout and refused(r), r.stdout[:200])
    check(tag + "backend peer refusal left journal unchanged", journal() == marker, journal())

    # Service stop: backend gone -> gateway fails closed; restart keeps the journal.
    code, out, err = stop(backend)
    check(tag + "backend stop removes its socket and exits cleanly", code == 0 and not BSOCK.exists(), (code, err[:200]))
    gw = start_gateway(GW)
    r = client(ALLOWED)
    code, out, err = finish(gw)
    check(tag + "backend down: gateway fails closed, no signer output",
          code == 40 and refused(r) and b"signer backend unavailable" in err, (code, err[:200]))
    backend = spawn(SIGNER, "run_signer_backend.py", "--backend", str(ETC / "backend.json"))
    wait_for(BSOCK, backend)
    gw = start_gateway(GW)
    r = client(ALLOWED)
    code, out, err = finish(gw)
    check(tag + "after restart the reserved intent_id is still refused",
          code == 40 and refused(r) and journal() == marker, (code, journal()))

    # Journal filesystem errors: fail closed, no signer output, no marker.
    clear_journal()
    for label, mode in (("read-only journal", 0o500), ("group-accessible journal", 0o770)):
        os.chmod(JOURNAL, mode)
        gw = start_gateway(GW)
        r = client(ALLOWED)
        code, out, err = finish(gw)
        os.chmod(JOURNAL, 0o700)
        check(tag + label + ": request refused, nothing reserved",
              code == 40 and refused(r) and journal() == [], (code, journal()))

    # Corrupted / hostile agent input never reaches the journal.
    hostile = [b"", b"{", b"not json", b"\xff\xfe\x00", b"x" * 70000,
               REQUEST.replace(b'"kind"', b'"kind":"dup","kind"', 1),
               json.dumps({"schema_version": 1}).encode()]
    for index, payload in enumerate(hostile):
        gw = start_gateway(GW)
        r = client(ALLOWED, payload)
        code, out, err = finish(gw)
        check(tag + "hostile request #%d refused" % index, code == 40 and refused(r) and journal() == [],
              (code, journal()))

    # Live slow-drip: total deadline, not per-recv.
    gw = start_gateway(GW)
    started = time.monotonic()
    dripper = subprocess.Popen(["runuser", "-u", ALLOWED, "--", "/usr/bin/python3", "-I", "-c", CLIENT,
                                str(SOCK), "12"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    dripper.stdin.write(b"{")
    dripper.stdin.close()
    code, out, err = finish(gw, 20)
    elapsed = time.monotonic() - started
    dripper.kill()
    dripper.wait()  # stdin already closed: communicate() raises on Python 3.13
    check(tag + "slow-drip client cut off by the total deadline", code == 40 and elapsed < 10, (code, elapsed))
    check(tag + "slow-drip left journal empty", journal() == [], journal())

    # Persistent gateway: refused and hostile peers cannot end the service
    # (no one-shot DoS), and a later authorized request is still served.
    clear_journal()
    mkdir_owned(RUN_GW, GW, CLIENTS, 0o2750)
    gw = spawn(GW, "run_signer_admission.py", "--admission", str(ETC / "admission.json"))
    wait_for(SOCK, gw)
    client(DENIED)
    client(ALLOWED, b"not json")
    check(tag + "persistent gateway survives refused and hostile peers", gw.poll() is None and journal() == [],
          (gw.poll(), journal()))
    r = client(ALLOWED)
    served = b"signer_refusal" in r.stdout and len(journal()) == 1
    code, out, err = stop(gw)
    check(tag + "persistent gateway still serves an authorized request, then stops cleanly on SIGTERM",
          served and code == 0 and not SOCK.exists(), (served, code, err[:200]))
    clear_journal()

    # Socket substitution: a pre-existing path is refused and never deleted.
    mkdir_owned(RUN_GW, GW, CLIENTS, 0o2750)
    decoy = RUN_GW / "admission.sock"
    decoy.write_text("decoy")
    os.chown(decoy, uid(GW), 0)
    gw = start_gateway(GW)
    code, out, err = finish(gw)
    check(tag + "pre-existing file at socket path: refused, decoy preserved",
          code == 40 and b"already exists" in err and decoy.read_text() == "decoy", (code, err[:200]))
    decoy.unlink()
    os.symlink("/etc/passwd", decoy)
    os.lchown(decoy, uid(GW), 0)
    gw = start_gateway(GW)
    code, out, err = finish(gw)
    check(tag + "symlink at socket path: refused, link preserved and target untouched",
          code == 40 and decoy.is_symlink() and os.readlink(decoy) == "/etc/passwd", (code, err[:200]))
    decoy.unlink()

    # Corrupted operator policy: refuse to start and expose no socket.
    for target in ("admission.json", "policy.json"):
        original = (ETC / target).read_text()
        for broken in ("{", original[:-1] + ',"extra":1}', "\x00garbage"):
            (ETC / target).write_text(broken)
            gw = start_gateway(GW)
            code, out, err = finish(gw)
            check(tag + "corrupt %s refused at startup, no socket" % target,
                  code == 40 and not SOCK.exists(), (code, err[:200]))
        (ETC / target).write_text(original)
        os.chmod(ETC / target, 0o644)
    if backend:
        stop(backend)


def resilience():
    """Long-lived gateway + backend: sequential refusals, backend restart, slow
    peer head-of-line blocking, and one-winner replay under concurrent clients."""
    tag = "[resilience] "
    clear_journal()
    mkdir_owned(RUN_GW, GW, CLIENTS, 0o2750)
    mkdir_owned(RUN_BK, SIGNER, BACKEND, 0o2750)
    backend = spawn(SIGNER, "run_signer_backend.py", "--backend", str(ETC / "backend.json"))
    wait_for(BSOCK, backend)
    gw = spawn(GW, "run_signer_admission.py", "--admission", str(ETC / "admission.json"))
    wait_for(SOCK, gw)

    for _ in range(10):
        client(DENIED)
        client(ALLOWED, b"garbage")
    check(tag + "20 sequential refusals leave both services running and the journal empty",
          gw.poll() is None and backend.poll() is None and journal() == [], (gw.poll(), backend.poll(), journal()))

    stop(backend)
    r = client(ALLOWED)
    check(tag + "backend down: refused while the gateway keeps running",
          refused(r) and gw.poll() is None and journal() == [], (r.stdout[:80], gw.poll()))
    backend = spawn(SIGNER, "run_signer_backend.py", "--backend", str(ETC / "backend.json"))
    wait_for(BSOCK, backend)
    r = client(ALLOWED)
    check(tag + "after backend restart the gateway serves again", b"signer_refusal" in r.stdout and len(journal()) == 1,
          (r.stdout[:80], journal()))

    # Head-of-line blocking is bounded by the read deadline (requests are serial).
    clear_journal()
    dripper = subprocess.Popen(["runuser", "-u", ALLOWED, "--", "/usr/bin/python3", "-I", "-c", CLIENT,
                                str(SOCK), "30"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    dripper.stdin.write(b"{")
    dripper.stdin.close()
    time.sleep(0.3)
    started = time.monotonic()
    r = client(ALLOWED)
    latency = time.monotonic() - started
    dripper.kill()
    dripper.wait()  # stdin already closed: communicate() raises on Python 3.13
    print("  info %slegitimate client waited %.1fs behind a slow peer" % (tag, latency))
    check(tag + "client behind a slow peer is served within the bounded deadline",
          b"signer_refusal" in r.stdout and latency < 20, (latency, r.stdout[:80]))

    # Concurrent clients, same intent_id: exactly one winner, atomic journal.
    clear_journal()
    procs = [subprocess.Popen(["runuser", "-u", ALLOWED, "--", "/usr/bin/python3", "-I", "-c", CLIENT, str(SOCK)],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
             for _ in range(8)]
    outputs = []
    for proc in procs:
        out, _ = proc.communicate(REQUEST, timeout=120)
        outputs.append(out)
    winners = sum(1 for out in outputs if b"signer_refusal" in out)
    check(tag + "8 concurrent clients with one intent_id: exactly one reaches the signer, journal has one marker",
          winners == 1 and len(journal()) == 1, (winners, journal()))
    check(tag + "all services still running", gw.poll() is None and backend.poll() is None)
    stop(gw)
    stop(backend)


try:
    setup()
    if not sandbox_works_for(SIGNER):
        teardown()
        skip("service identity cannot create the required Bubblewrap namespaces")
    print("admission architecture: multi-UID live test")
    write_cfg(split=False)
    gateway_user, backend, marker = common_scenarios(split=False)
    single_only(gateway_user, marker)
    write_cfg(split=True)
    gateway_user, backend, marker = common_scenarios(split=True)
    split_only(backend, marker)
    resilience()
finally:
    teardown()

if failures:
    print("FAIL: " + "; ".join(failures))
    sys.exit(1)
print("PASS: Unix socket -> SO_PEERCRED -> [gateway -> backend ->] replay journal -> Bubblewrap -> BLOCK; "
      "unauthorized/outsider/replay/direct-call/hostile/timeout/socket-substitution/stop-restart cases refused")
