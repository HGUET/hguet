"""Package local measured evidence, preserving explicit source attribution."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--evidence",required=True)
    parser.add_argument("--source-commit",required=True)
    parser.add_argument("--out",required=True)
    args=parser.parse_args()
    root=Path(__file__).resolve().parents[1]
    source=subprocess.check_output(["git","rev-parse",args.source_commit+"^{commit}"],cwd=root,text=True).strip()
    evidence=Path(args.evidence).resolve()
    output=Path(args.out).resolve()
    if evidence==output or evidence in output.parents:
        raise SystemExit("output archive must be outside evidence directory")
    required=["build.log","clippy.log","tests.log","benchmark/report.json","runtime.json","demo.json","demo.txt"]
    for name in required:
        if not (evidence/name).is_file():
            raise SystemExit("missing evidence file "+name)
    files=sorted(path for path in evidence.rglob("*") if path.is_file())
    entries=[{"path":str(path.relative_to(evidence)).replace("\\","/"),
              "bytes":path.stat().st_size,"sha256":hashlib.sha256(path.read_bytes()).hexdigest()}
             for path in files]
    manifest={"manifest_version":1,"source_commit":source,
              "attribution":"Caller supplies the commit actually tested. Packaging does not rerun tests.",
              "files":entries}
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("xb") as target, zipfile.ZipFile(target,"w",zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("MANIFEST.json",json.dumps(manifest,indent=2)+"\n")
        for path,entry in zip(files,entries):
            archive.write(path,entry["path"])
    print(json.dumps({"archive":str(output),"source_commit":source,"file_count":len(files),
                      "sha256":hashlib.sha256(output.read_bytes()).hexdigest()}))


if __name__=="__main__":
    main()
