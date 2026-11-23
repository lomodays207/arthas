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


import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))
from native import (await_condition, expect_state, owned_listener, process_start_ticks,
                    request, require, stop_listener as stop_fixture_arthas, unpack)


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


def run(jdk, archive, sha256, classes, mode, exercise=None):
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
                def release():
                    stop_fixture_arthas(call, pid, port)

                try:
                    if exercise is None:
                        version = observe_and_cancel(call)
                        message = f"Arthas {version}, local auth, JVM snapshot, watch intercept/cancel"
                    else:
                        message = exercise(call, release, f"fixture:{pid}:{ticks}")
                finally:
                    if owned_listener(pid, port) and process_start_ticks(pid) == ticks:
                        release()
                require(fixture.poll() is None and process_start_ticks(pid) == ticks, "Fixture JVM restarted or exited")
                print(f"PASS ({mode}): {message}, listener closed, JVM alive")
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
