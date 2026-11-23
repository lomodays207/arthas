"""Bounded Arthas operations against an identified loopback listener."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import time
import zipfile

HOST = "127.0.0.1"
MAX_RESPONSE_BYTES = 1024 * 1024


def unpack(archive, expected_sha256, destination):
    with archive.open("rb") as package:
        actual = hashlib.file_digest(package, "sha256").hexdigest()
        require(actual == expected_sha256, "Arthas ZIP digest mismatch")
        package.seek(0)
        with zipfile.ZipFile(package) as bundle:
            for entry in bundle.infolist():
                path = Path(entry.filename)
                require(
                    not path.is_absolute() and ".." not in path.parts,
                    "Arthas ZIP contains an invalid path",
                )
            bundle.extractall(destination)
    require((destination / "arthas-core.jar").is_file(), "Arthas ZIP has no core launcher")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def process_start_ticks(pid):
    stat = Path(f"/proc/{pid}/stat").read_text()
    return stat[stat.rindex(")") + 2:].split()[19]


def owned_listener(pid, port):
    """Verify the loopback TCP listener is a socket in the fixture process."""
    endpoint = f"0100007F:{port:04X}"
    inodes = set()
    tables = [("tcp", endpoint), ("tcp6", f"0000000000000000FFFF00000100007F:{port:04X}")]
    for table, address in tables:
        src = Path(f"/proc/{pid}/net/{table}")
        if not src.exists():
            continue
        for line in src.read_text().splitlines()[1:]:
            row = line.split()
            if row[1] == address and row[3] == "0A":
                inodes.add(f"socket:[{row[9]}]")
    for descriptor in Path(f"/proc/{pid}/fd").iterdir():
        try:
            if os.readlink(descriptor) in inodes:
                return True
        except FileNotFoundError:
            continue
    return False


def await_condition(description, check, seconds=12):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if check():
            return
        time.sleep(0.1)
    raise RuntimeError(description)


def request(pid, ticks, port, auth, action, **fields):
    require(process_start_ticks(pid) == ticks, "Fixture process changed")
    require(owned_listener(pid, port), "Listener is not owned by the fixture")
    connection = http.client.HTTPConnection(HOST, port, timeout=12)
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = f"Basic {auth}"
    try:
        connection.request("POST", "/api", json.dumps({"action": action, **fields}), headers)
        response = connection.getresponse()
        body = response.read(MAX_RESPONSE_BYTES + 1)
        require(len(body) <= MAX_RESPONSE_BYTES, "Arthas response exceeded limit")
        if response.status != 200:
            return response.status, None
        return response.status, json.loads(body)
    finally:
        connection.close()


def expect_state(result, action, expected="SUCCEEDED"):
    status, payload = result
    require(status == 200 and isinstance(payload, dict), f"{action} failed with HTTP {status}")
    require(payload.get("state") == expected, f"{action} state was {payload.get('state')}")
    return payload


def stop_listener(call, pid, port):
    try:
        call("exec", command="stop", execTimeout=5000)
    except (OSError, http.client.HTTPException):
        # Arthas may close the connection before it can reply to stop.
        pass
    await_condition("Arthas listener did not close", lambda: not owned_listener(pid, port))


def snapshot(call):
    jvm = expect_state(call("exec", command="jvm", execTimeout=5000), "jvm")
    detail = next(entry["jvmInfo"] for entry in jvm["body"]["results"] if entry["type"] == "jvm")
    memory = {entry["name"]: entry["value"] for entry in detail["MEMORY"]}
    threads = {entry["name"]: entry["value"] for entry in detail["THREAD"]}
    runtime = expect_state(
        call("exec", command="dashboard -n 1", execTimeout=5000), "dashboard")
    uptime_seconds = next(entry["runtimeInfo"]["uptime"] for entry in runtime["body"]["results"]
                          if entry["type"] == "dashboard")
    return {
        "heapUsedBytes": memory["HEAP-MEMORY-USAGE"]["used"],
        "heapCommittedBytes": memory["HEAP-MEMORY-USAGE"]["committed"],
        "nonHeapUsedBytes": memory["NO-HEAP-MEMORY-USAGE"]["used"],
        "threadCount": threads["COUNT"],
        "uptimeMillis": int(uptime_seconds * 1000),
    }
