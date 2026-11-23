#!/usr/bin/env python3
"""Validate bounded metadata for every diagnostic on a dual-loader fixture."""
import argparse
import json
from pathlib import Path
import runpy
import time

smoke = runpy.run_path(str(Path(__file__).with_name("arthas-smoke.py")))
from diagnostics import diagnostic


def exercise(call, *_):
    clazz, method = "io.diagnostic.fixture.Workload","handleRequest"
    def collect(cap, criteria):
        return diagnostic(call,cap,criteria,[clazz+"#"+method,clazz+"#idleProbe"],time.time()*1000+10000)
    assert collect("THREAD_LIST",None)["rows"]
    assert collect("THREAD_DETAIL",dict(threadId=1))["rows"]
    selected = dict(className=clazz,methodName=method)
    lookup = collect("CLASS_METHOD_LOOKUP",selected)["rows"]
    loaders = {m["loader"] for m in lookup}
    assert len(loaders) == 2 and len(lookup) == 4
    # This fixture deliberately defines the same class in two loaders, only one receives calls.
    for loader in loaders:
        selected["loader"] = loader
        watch = collect("METHOD_WATCH",selected)
        if watch["rows"]:
            break
    assert watch["rows"]
    for kind in ["TRACE","STACK","MONITOR"]:
        data = collect("METHOD_"+kind,selected)
        assert data["rows"], kind
        assert "synthetic fixture" not in json.dumps(data)
    selected["methodName"] = "idleProbe"
    assert collect("METHOD_WATCH",selected)["coverage"] == "NO_HIT"
    return "thread, class, Watch, Trace, Stack, Monitor, no-hit interrupt"


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("jdk","archive","classes"):
        parser.add_argument("--"+name,required=True,type=Path)
    parser.add_argument("--mode",default="attach",choices=["attach","startup"])
    args = parser.parse_args()
    smoke["run"](args.jdk.resolve(),args.archive.resolve(),
        "2f75ea954ead5d02c4a743ecd783fd92f546a44ef3aee437ea5066eb30ad07bf",
        args.classes.resolve(),args.mode,exercise)
