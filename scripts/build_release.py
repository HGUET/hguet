#!/usr/bin/env python3
"""Reproducible release build of the HGUET CLI (Linux and Windows) with SHA-256.

Usage:
  python scripts/build_release.py [--out DIR]            build from the working tree
  python scripts/build_release.py --verify-reproducible  build committed HEAD twice
                                                         in two different directories
                                                         and require identical hashes

What makes it reproducible: pinned toolchain (rust-toolchain.toml), committed
Cargo.lock with --locked, CARGO_INCREMENTAL=0, SOURCE_DATE_EPOCH from the commit,
and --remap-path-prefix so build directories, CARGO_HOME and RUSTUP_HOME do not
leak into the binaries. Bit-for-bit equality is only claimed for the same
target, toolchain and OS image; the script PROVES it per run, it does not assume.

This builds the BLOCK-only CLI. It adds no key, signing or broadcast capability.
The artifacts are UNSIGNED: SHA256SUMS lets people compare builds, it is not
a publisher signature.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXE = ".exe" if os.name == "nt" else ""
# The signer isolate binary is only meaningful with the Linux sandbox launcher.
BINARIES = ["hguet"] + (["hguet-signer-isolate"] if sys.platform.startswith("linux") else [])


def run(cmd, cwd, env=None, capture=False):
    result = subprocess.run(cmd, cwd=cwd, env=env, check=True, text=True,
                            capture_output=capture)
    return result.stdout.strip() if capture else None


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def build(source, target_dir):
    """Build `source` into `target_dir`; return {name: sha256}."""
    cargo_home = Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
    rustup_home = Path(os.environ.get("RUSTUP_HOME", Path.home() / ".rustup"))
    epoch = os.environ.get("SOURCE_DATE_EPOCH") or run(
        ["git", "log", "-1", "--format=%ct"], ROOT, capture=True)
    flags = [
        "--remap-path-prefix=%s=/hguet" % source,
        "--remap-path-prefix=%s=/cargo" % cargo_home,
        "--remap-path-prefix=%s=/rustup" % rustup_home,
    ]
    env = dict(os.environ, CARGO_INCREMENTAL="0", SOURCE_DATE_EPOCH=epoch,
               CARGO_TARGET_DIR=str(target_dir),
               CARGO_ENCODED_RUSTFLAGS="\x1f".join(flags))
    env.pop("RUSTFLAGS", None)
    run(["cargo", "build", "--release", "--locked", "-p", "hguet", "-p", "hguet-signer"],
        source, env)
    return {name + EXE: sha256(target_dir / "release" / (name + EXE)) for name in BINARIES}


def toolchain():
    return {"rustc": run(["rustc", "-Vv"], ROOT, capture=True).replace("\n", "; "),
            "cargo": run(["cargo", "-V"], ROOT, capture=True)}


def export_head(destination):
    archive = destination.with_suffix(".tar")
    run(["git", "archive", "--format=tar", "-o", str(archive), "HEAD"], ROOT)
    destination.mkdir()
    run(["tar", "-xf", str(archive), "-C", str(destination)], ROOT)
    archive.unlink()


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--out", default=str(ROOT / "dist"))
    parser.add_argument("--verify-reproducible", action="store_true")
    args = parser.parse_args()
    out = Path(args.out).resolve()
    commit = run(["git", "rev-parse", "HEAD"], ROOT, capture=True)

    if args.verify_reproducible:
        if run(["git", "status", "--porcelain", "--untracked-files=no"], ROOT, capture=True):
            print("FAIL: working tree has uncommitted changes; HEAD is what gets verified")
            return 1
        with tempfile.TemporaryDirectory(prefix="hguet-repro-") as scratch:
            first_dir, second_dir = Path(scratch) / "a" / "src", Path(scratch) / "bb" / "other-path"
            first_dir.parent.mkdir()
            second_dir.parent.mkdir()
            export_head(first_dir)
            export_head(second_dir)
            first = build(first_dir, Path(scratch) / "t1")
            second = build(second_dir, Path(scratch) / "t2")
        if first != second:
            print("FAIL: builds differ between directories")
            for name in first:
                print("  %s %s %s" % (name, first[name], second[name]))
            return 1
        print("PASS: two builds from different directories are bit-identical")
        for name, digest in first.items():
            print("  %s  %s" % (digest, name))
        return 0

    target = out / "target"
    hashes = build(ROOT, target)
    dist = out / "dist"
    shutil.rmtree(dist, ignore_errors=True)
    dist.mkdir(parents=True)
    for name in hashes:
        shutil.copy2(target / "release" / name, dist / name)
    (dist / "SHA256SUMS").write_text("".join("%s  %s\n" % (h, n) for n, h in sorted(hashes.items())),
                                     encoding="utf-8", newline="\n")
    (dist / "BUILD-INFO.json").write_text(json.dumps({
        "commit": commit, "platform": sys.platform, "unsigned": True,
        "block_only": True, "toolchain": toolchain()}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8", newline="\n")
    print("Artifacts in %s (UNSIGNED, BLOCK-only):" % dist)
    for name, digest in sorted(hashes.items()):
        print("  %s  %s" % (digest, name))
    return 0


if __name__ == "__main__":
    sys.exit(main())
