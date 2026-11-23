#!/usr/bin/env python3
"""Measure fixed synthetic workload with Arthas idle and during JVM snapshots."""
import argparse
import json
import math
import os
from pathlib import Path
import runpy
import time

smoke=runpy.run_path(str(Path(__file__).with_name("arthas-smoke.py")))
from native import snapshot


def measure(call,pid,log,seconds):
    def cpu():
        parts=Path(f"/proc/{pid}/stat").read_text().rsplit(")",1)[1].split()
        return (int(parts[11])+int(parts[12]))/os.sysconf("SC_CLK_TCK")
    def window(active):
        start=time.monotonic()
        begin_ms=time.time()*1000
        start_cpu=cpu()
        elapsed=[]
        while time.monotonic()-start < seconds:
            if active:
                before=time.monotonic()
                snapshot(call)
                elapsed.append((time.monotonic()-before)*1000)
            time.sleep(.75)
        duration=time.monotonic()-start
        # Drop the first reporting batch as it can straddle the phase boundary.
        rows=[r.split() for r in log.read_text().splitlines() if r.startswith("FIXTURE_WINDOW ")]
        rows=[r for r in rows if int(r[1])>=begin_ms][1:]
        if not rows: raise RuntimeError("Insufficient complete workload batches")
        return dict(seconds=round(duration,3),cpuCorePercent=round(100*(cpu()-start_cpu)/duration,3),
                    batches=len(rows),trades=sum(int(r[2]) for r in rows),expectedFailures=sum(int(r[3]) for r in rows),
                    worstBatchP95Millis=round(max(int(r[4]) for r in rows)/1e6,3),
                    snapshotCount=len(elapsed),snapshotP95Millis=round(sorted(elapsed)[math.ceil(.95*len(elapsed))-1],3)
                    if elapsed else None)
    baseline=window(False)
    active=window(True)
    print(json.dumps(dict(scope="single synthetic JVM; attached idle versus repeated snapshots",
                          baseline=baseline,active=active),sort_keys=True))
    return "two bounded load windows completed"


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    for name in ("jdk","archive","classes"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--seconds",type=int,default=20,choices=range(10,301),metavar="10..300")
    parser.add_argument("--mode",choices=["attach","startup"],default="attach")
    args=parser.parse_args()
    smoke["run"](args.jdk.resolve(),args.archive.resolve(),
        "2f75ea954ead5d02c4a743ecd783fd92f546a44ef3aee437ea5066eb30ad07bf",
        args.classes.resolve(),args.mode,measure=lambda call,pid,log:measure(call,pid,log,args.seconds))
