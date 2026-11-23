#!/usr/bin/env python3
"""Package previously verified artifacts; no host configuration or credentials are included."""
import argparse
import hashlib
from pathlib import Path
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--out",required=True,type=Path)
args=parser.parse_args()
args.out.parent.mkdir(parents=True,exist_ok=True)
files = {}
for component in ("platform-api","gateway"):
    jars=list((ROOT/component/"target").glob(component+"-*.jar"))
    if len(jars)!=1:
        raise SystemExit("Expected one packaged artifact in "+component+"/target")
    files["lib/"+component+".jar"] = jars[0]
for name in ("host_agent.py","native.py","diagnostics.py","identity.py"):
    files["agent/"+name] = ROOT/"agent"/name
for name in ("pilot.md","openapi.yaml","gateway-contract.md","integrations.md","verification.md"):
    files["docs/"+name] = ROOT/"docs"/name
files["tools/ticket-forwarder.py"]=ROOT/"tools"/"ticket-forwarder.py"
launcher = """#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
case "${1:-}" in
  platform|gateway)
    component="$1"
    shift
    [ "$component" != platform ] || component=platform-api
    exec "${JAVA_HOME:+$JAVA_HOME/bin/}java" -jar "$root/lib/$component.jar" "$@";;
  agent)
    shift
    exec python3 "$root/agent/host_agent.py" "$@";;
  *) echo 'Usage: sh run.sh platform|gateway|agent [arguments]' >&2; exit 2;;
esac
"""
with tempfile.NamedTemporaryFile(dir=args.out.parent) as tmp:
    with zipfile.ZipFile(tmp,"w",compression=zipfile.ZIP_DEFLATED,compresslevel=3) as bundle:
        sums=[]
        for entry,src in sorted(files.items()):
            data=src.read_bytes()
            bundle.writestr(entry,data)
            sums.append(hashlib.sha256(data).hexdigest()+"  "+entry)
        bundle.writestr("run.sh",launcher)
        sums.append(hashlib.sha256(launcher.encode()).hexdigest()+"  run.sh")
        bundle.writestr("SHA256SUMS","\n".join(sums)+"\n")
    tmp.flush()
    import shutil
    # Refuse to overwrite a previously generated release.
    with args.out.open("xb") as out:
        tmp.seek(0)
        shutil.copyfileobj(tmp,out)
