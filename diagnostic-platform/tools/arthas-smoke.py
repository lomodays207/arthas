#!/usr/bin/env python3
"""Attach only to the synthetic child JVM started by this smoke test."""

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import time
import zipfile


FIXTURE_CLASS = "io.diagnostic.fixture.DiagnosticFixture"
APP_CLASS = "io.diagnostic.fixture.Workload"
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
    for line in Path(f"/proc/{pid}/net/tcp").read_text().splitlines()[1:]:
        row = line.split()
        if row[1] == endpoint and row[3] == "0A":
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


def observe_and_cancel(call):
    session = expect_state(call("init_session"), "init_session")
    session_id = session["sessionId"]
    consumer_id = session["consumerId"]
    try:
        version = expect_state(call("exec", command="version", execTimeout=5000), "version")
        versions = [value.get("version") for value in version["body"]["results"] if value.get("type") == "version"]
        require(len(versions) == 1 and versions[0].startswith("4."), "Expected Arthas 4.x")
        started = expect_state(
            call("async_exec", sessionId=session_id, command=f"watch {APP_CLASS} idleProbe '#cost' -n 1"),
            "async_exec", "SCHEDULED",
        )
        job_id = started["body"]["jobId"]

        def job_is_listening():
            results = expect_state(
                call("pull_results", sessionId=session_id, consumerId=consumer_id),
                "pull_results",
            )["body"]["results"]
            return any(
                event.get("type") == "enhancer"
                and event.get("jobId") == job_id
                and event.get("success") is True
                and event.get("effect", {}).get("methodCount", 0) > 0
                for event in results
            )

        await_condition("Arthas never confirmed that watch was listening", job_is_listening)
        stopped = expect_state(call("interrupt_job", sessionId=session_id), "interrupt_job")
        require(stopped["body"].get("jobId") == job_id, "Interrupt applied to the wrong job")
        require(stopped["body"].get("jobStatus") == "TERMINATED", "Job termination was not confirmed")
        diagnosis = expect_state(call("exec", command="jvm", execTimeout=5000), "jvm")
        require(
            any(value.get("type") == "jvm" for value in diagnosis["body"]["results"]),
            "JVM snapshot missing after cancellation",
        )
        return versions[0]
    finally:
        expect_state(call("close_session", sessionId=session_id), "close_session")


def stop_fixture_arthas(call, pid, port):
    try:
        call("exec", command="stop", execTimeout=5000)
    except (OSError, http.client.HTTPException):
        # Arthas may close the connection before it can reply to stop.
        pass
    await_condition("Arthas listener did not close", lambda: not owned_listener(pid, port))


def run(jdk, archive, sha256, classes, mode):
    password = secrets.token_urlsafe(32)
    encoded = base64.b64encode(f"fixture:{password}".encode()).decode()
    java = str(jdk / "bin" / "java")
    with tempfile.TemporaryDirectory(prefix="arthas-fixture-") as scratch:
        root = Path(scratch)
        arthas = root / "arthas"
        unpack(archive, sha256, arthas)
        with socket.socket() as port_reservation:
            port_reservation.bind((HOST, 0))
            port = port_reservation.getsockname()[1]
        (arthas / "arthas.properties").write_text(
            "arthas.config.overrideAll=true\n"
            "arthas.ip=127.0.0.1\n"
            "arthas.telnetPort=-1\n"
            f"arthas.httpPort={port}\n"
            "arthas.localConnectionNonAuth=false\n"
            "arthas.username=fixture\n"
            f"arthas.password={password}\n"
        )
        output = root / "fixture.log"
        options = [f"-Duser.home={root}", "-Djava.net.preferIPv4Stack=true"]
        if mode == "startup":
            options.append(f"-javaagent:{arthas / 'arthas-agent.jar'}")
        with output.open("w") as stream, subprocess.Popen(
            [java, *options, "-cp", str(classes), FIXTURE_CLASS],
            cwd=root,
            stdout=stream,
            stderr=subprocess.STDOUT,
        ) as fixture:
            try:
                def fixture_ready():
                    require(fixture.poll() is None, "Synthetic JVM exited before readiness")
                    return "FIXTURE_READY" in output.read_text()

                await_condition("Synthetic JVM did not report readiness", fixture_ready)
                pid = fixture.pid
                ticks = process_start_ticks(pid)
                require(Path(f"/proc/{pid}").stat().st_uid == os.geteuid(), "Fixture account mismatch")
                if mode == "attach":
                    launcher_classpath = [arthas / "arthas-core.jar"]
                    tools_jar = jdk / "lib" / "tools.jar"
                    if tools_jar.is_file():
                        launcher_classpath.append(tools_jar)
                    subprocess.run(
                        [
                            java, f"-Duser.home={root}", "-cp",
                            os.pathsep.join(map(str, launcher_classpath)), "com.taobao.arthas.core.Arthas",
                            "-pid", str(pid), "-core", str(arthas / "arthas-core.jar"),
                            "-agent", str(arthas / "arthas-agent.jar"), "-target-ip", HOST,
                            "-telnet-port", "-1", "-http-port", str(port),
                        ],
                        cwd=root, timeout=25, check=True,
                        stdout=None, stderr=None,
                    )
                await_condition("No fixture-owned Arthas listener found", lambda: owned_listener(pid, port))

                def call(action, **fields):
                    return request(pid, ticks, port, encoded, action, **fields)

                require(
                    request(pid, ticks, port, None, "exec", command="version")[0] in (401, 403),
                    "Unauthenticated local requests must be rejected",
                )
                try:
                    version = observe_and_cancel(call)
                finally:
                    stop_fixture_arthas(call, pid, port)
                require(fixture.poll() is None and process_start_ticks(pid) == ticks, "Fixture JVM restarted or exited")
                print(f"PASS ({mode}): Arthas {version}, local auth, JVM snapshot, watch intercept/cancel, listener closed, JVM alive")
            finally:
                if fixture.poll() is None:
                    fixture.terminate()
                    try:
                        fixture.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        fixture.kill()
                        fixture.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jdk", type=Path, required=True, help="Target JDK directory")
    parser.add_argument("--arthas-zip", type=Path, required=True)
    parser.add_argument("--sha256", required=True, help="Expected ZIP digest from the approved package record")
    parser.add_argument("--classes", type=Path, required=True, help="Compiled fixture classes")
    parser.add_argument("--mode", choices=("attach", "startup"), default="attach")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-fA-F]{64}", args.sha256):
        parser.error("--sha256 must contain 64 hexadecimal digits")
    run(args.jdk.resolve(), args.arthas_zip.resolve(), args.sha256.lower(), args.classes.resolve(), args.mode)


if __name__ == "__main__":
    main()
