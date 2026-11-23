#!/usr/bin/env python3
"""Evaluate profiling and retained invocations only in a newly created synthetic JVM."""
import argparse
import json
import time
from pathlib import Path
import runpy
import tempfile

smoke = runpy.run_path(str(Path(__file__).with_name("arthas-smoke.py")))


def evaluate(call, *_):
    def results(command, timeout=5000):
        payload=smoke["expect_state"](call("exec",command=command,execTimeout=timeout),"fixture experiment")
        events=payload["body"]["results"]
        if not any(e.get("type")=="status" and e.get("statusCode")==0 for e in events):
            raise RuntimeError("Native experiment returned unsuccessful status")
        return events

    with tempfile.TemporaryDirectory(prefix="diagnostic-profile-") as scratch:
        file=Path(scratch)/"sample.collapsed"
        started=False
        try:
            results("profiler start --event wall")
            started=True
            time.sleep(2)
            results("profiler stop --format collapsed --file "+str(file))
            started=False
            if not file.is_file() or file.stat().st_size==0:
                raise RuntimeError("No profile artifact")
            print(json.dumps(dict(experiment="wall-profile",seconds=2,bytes=file.stat().st_size)))
        finally:
            if started:
                results("profiler stop --format collapsed --file "+str(file))
        file.unlink()
    try:
        results("tt -t io.diagnostic.fixture.Workload handleRequest -n 1")
        observed=results("tt -l")
        def count(events):
            return sum(len(e.get("timeFragmentList",[])) for e in events)
        if count(observed)<1:
            raise RuntimeError("No retained synthetic invocation")
        print(json.dumps(dict(experiment="retained-invocation",count=count(observed))))
    finally:
        results("tt --delete-all")
    if count(results("tt -l")):
        raise RuntimeError("Retained invocation remained after cleanup")
    return "wall profile removed, retained synthetic invocations removed"


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    for name in ("jdk","archive","classes"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--mode",choices=["attach","startup"],default="attach")
    args=parser.parse_args()
    smoke["run"](args.jdk.resolve(),args.archive.resolve(),
        "2f75ea954ead5d02c4a743ecd783fd92f546a44ef3aee437ea5066eb30ad07bf",
        args.classes.resolve(),args.mode,evaluate)
