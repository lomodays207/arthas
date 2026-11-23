"""Read target runtime and optional same-container identity from local evidence."""
import hashlib
import os
from pathlib import Path
import platform
import re
import subprocess
from native import process_start_ticks, require


def profile(jdk):
    output=subprocess.run([jdk/"bin/java","-XshowSettings:properties","-version"],stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT,check=True,timeout=8,text=True).stdout
    values={}
    for line in output.splitlines():
        key,sep,value=line.strip().partition(" = ")
        if sep and key in ("java.version","java.vendor","java.vm.name"):
            values[key]=value
    version=values["java.version"]
    require("Server VM" in values["java.vm.name"] and "OpenJ9" not in values["java.vm.name"],
            "Target VM not covered by the pilot")
    feature=int(re.match(r"(?:1\.)?(\d+)",version)[1])
    require(feature in (8,11,17,21,25) and platform.system()=="Linux" and platform.machine()=="x86_64",
            "No compatible pilot runtime profile")
    return dict(os="Linux",arch=platform.machine(),javaVersion=version,
                vendor=values["java.vendor"],vmName=values["java.vm.name"],javaFeature=feature)


def container_context(pid):
    context={key:os.environ.get("DIAGNOSTIC_"+key.upper(),"")
             for key in ("cluster","namespace","pod_uid","container_id")}
    require(all(re.fullmatch(r"[a-zA-Z0-9._-]{1,150}",v) for v in context.values()),
            "Container workload identity missing")
    require(re.fullmatch("[0-9a-f]{64}",context["container_id"]),"Container runtime ID required")
    require(context["container_id"] in Path(f"/proc/{pid}/cgroup").read_text(),
            "Container membership unavailable from local cgroup")
    require(Path(f"/proc/{pid}/ns/pid").samefile("/proc/self/ns/pid") and
            Path(f"/proc/{pid}/ns/mnt").samefile("/proc/self/ns/mnt"),"Target namespace mismatch")
    return context


def fingerprint(pid,jdk,container=None):
    proc=Path("/proc")/str(pid)
    require(proc.stat().st_uid==os.geteuid(),"Target UID differs")
    require((proc/"exe").samefile(jdk/"bin/java"),"Target executable differs")
    boot=Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    fields=[boot,str(os.geteuid()),str(pid),process_start_ticks(pid),str((proc/"ns/pid").stat().st_ino)]
    if container is not None:
        require(container==container_context(pid),"Container identity changed")
        fields.extend(container[k] for k in ("cluster","namespace","pod_uid","container_id"))
    return "linux2:"+hashlib.sha256(":".join(fields).encode()).hexdigest()
