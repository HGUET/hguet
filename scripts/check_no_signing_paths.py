#!/usr/bin/env python3
"""Static guard: no key custody, signing or transaction-broadcast path exists.

Scans production Rust (``#[cfg(test)]`` items and ``*tests.rs`` files removed)
and the dependency manifests. It is a tripwire for NEW paths, not a proof of
absence: it cannot see behaviour hidden behind dynamic dispatch or FFI, and the
runtime guarantees are the Bubblewrap/seccomp tests. Any hit fails the build.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CRATES = ROOT / "crates"

# Crates that would bring wallets, key derivation, signing or broadcasting.
DENIED_PACKAGES = re.compile(
    r'^name = "(solana-[a-z0-9-]+|anchor-[a-z0-9-]+|spl-[a-z0-9-]+|bip39|tiny-bip39|'
    r'slip10|ed25519-dalek-bip32|keyring|rpassword|secp256k1|k256|web3|ethers[a-z-]*)"$',
    re.M)
# hguet-signer may only depend on this exact set (it must stay verify-only).
SIGNER_DEPS = {"hguet-core", "hguet-rpc", "serde", "serde_json", "base64", "bs58"}
DENIED_CODE = [
    (r"\bSigningKey\b", "ed25519 signing key"),
    (r"\bKeypair\b", "keypair"),
    (r"\bed25519_dalek::Signer\b", "ed25519 Signer trait"),
    (r"\.sign\(", "signing call"),
    (r"\bsign_message\b|\bsign_transaction\b|\bpartial_sign\b", "signing API"),
    (r"send_?[Tt]ransaction|sendRawTransaction|sendBundle|requestAirdrop", "broadcast API"),
    (r"from_secret|secret_key|private_key|SecretKey|seed_phrase|mnemonic", "secret material"),
]
# JSON-RPC methods that may be named in production code: read-only + simulation.
ALLOWED_RPC_METHODS = {"getMultipleAccounts", "getGenesisHash", "simulateTransaction"}
NETWORK_IN_SIGNER = re.compile(r"std::net|TcpStream|UdpSocket|\bureq\b|reqwest|hyper")


def strip_test_items(text):
    out, lines, i = [], text.split("\n"), 0
    while i < len(lines):
        if lines[i].strip().startswith("#[cfg(test)]"):
            depth, seen, i = 0, False, i + 1
            while i < len(lines):
                depth += lines[i].count("{") - lines[i].count("}")
                seen = seen or "{" in lines[i]
                end_stmt = not seen and lines[i].rstrip().endswith(";")
                i += 1
                if end_stmt or (seen and depth <= 0):
                    break
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def code_only(text):
    text = strip_test_items(text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return "\n".join(re.sub(r"//.*$", "", line) for line in text.split("\n"))


problems = []
lock = (ROOT / "Cargo.lock").read_text() if (ROOT / "Cargo.lock").exists() else ""
for match in DENIED_PACKAGES.finditer(lock):
    problems.append("denied package in Cargo.lock: " + match.group(1))

manifest = (CRATES / "hguet-signer/Cargo.toml").read_text()
section = re.search(r"\[dependencies\](.*?)(?:\n\[|\Z)", manifest, re.S).group(1)
deps = {m.group(1) for m in re.finditer(r"^([A-Za-z0-9_-]+)\s*=", section, re.M)}
if deps != SIGNER_DEPS:
    problems.append("hguet-signer dependency set changed: %s" % sorted(deps ^ SIGNER_DEPS))

scanned = 0
for path in sorted(CRATES.glob("*/src/**/*.rs")):
    if path.name == "tests.rs" or path.name.endswith("_tests.rs"):
        continue
    scanned += 1
    raw = path.read_text()
    code = code_only(raw)
    rel = path.relative_to(ROOT)
    for pattern, label in DENIED_CODE:
        for hit in re.finditer(pattern, code):
            line = code[:hit.start()].count("\n") + 1
            problems.append("%s: %s (%s)" % (rel, label, hit.group(0)))
    if "hguet-signer" in path.parts and NETWORK_IN_SIGNER.search(code):
        problems.append("%s: network API referenced from signer crate" % rel)
    if "hguet-rpc" in path.parts:
        for m in re.finditer(r'"method"\s*:\s*"([A-Za-z]+)"', code):
            if m.group(1) not in ALLOWED_RPC_METHODS:
                problems.append("%s: unapproved JSON-RPC method %s" % (rel, m.group(1)))

if scanned < 10:
    problems.append("scanner found suspiciously few source files: %d" % scanned)
if problems:
    print("FAIL: new signing/custody/broadcast path or network use:")
    for item in problems:
        print("  - " + item)
    sys.exit(1)
print("PASS: no key custody, signing API, broadcast API or unapproved RPC method in %d production sources" % scanned)
