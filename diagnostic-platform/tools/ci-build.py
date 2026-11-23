"""Retry Maven Central throttling without retrying failed tests."""
import subprocess
import sys
import time

for attempt in range(3):
    with subprocess.Popen(["mvn","-B","-U","verify"],stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT,text=True) as build:
        throttled=False
        for line in build.stdout:
            sys.stdout.write(line)
            if "429" in line and ("Status" in line or "status" in line or "Too Many Requests" in line):
                throttled=True
        status=build.wait()
    if not status or not throttled or attempt==2:
        raise SystemExit(status)
    time.sleep(20*(attempt+1))
