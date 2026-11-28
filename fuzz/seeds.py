"""Materialize deterministic, checked-in public/synthetic seeds as binary files."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ("wire", "reports")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    seeds = []
    for path in sorted((ROOT / "tests/fixtures").rglob("*.base64")):
        raw = base64.b64decode(path.read_text().strip(), validate=True)
        seeds.append((str(path.relative_to(ROOT)), raw))
    history = ROOT / "testing/history/solana-docs-devnet-legacy.json"
    fixture = json.loads(history.read_text())
    raw = base64.b64decode(fixture["result"]["transaction"][0], validate=True)
    assert hashlib.sha256(raw).hexdigest() == fixture["wire_sha256"]
    seeds.append((str(history.relative_to(ROOT)), raw))
    # Minimal malformed boundaries complement valid seed messages.
    for size in (1, 64, 65, 1232, 1233, 4096, 4097):
        seeds.append((f"zero-{size}", bytes(size)))
    entries = []
    for source, raw in seeds:
        digest = hashlib.sha256(raw).hexdigest()
        for target in TARGETS:
            directory = args.out / target
            directory.mkdir(exist_ok=True)
            (directory / digest).write_bytes(raw)
        entries.append({"source": source, "bytes": len(raw), "sha256": digest})
    (args.out / "seed-manifest.json").write_text(json.dumps(entries, indent=2))
    print(f"Prepared {len(entries)} source seeds for each target")


if __name__ == "__main__":
    main()
