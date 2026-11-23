#!/usr/bin/env python3
"""Exercise the packaged platform against an Arthas listener on a synthetic JVM."""

import argparse
import http.client
import json
import os
from pathlib import Path
import runpy
import secrets
import socket
import subprocess
import tempfile
import time


SMOKE = runpy.run_path(str(Path(__file__).with_name("arthas-smoke.py")))
require = SMOKE["require"]
MAX_BODY = 1024 * 1024


class Platform:
    def __init__(self, port, tokens):
        self.port = port
        self.tokens = tokens

    def request(self, method, path, expected, actor=None, body=None, idempotency_key=None):
        headers = {}
        if actor:
            headers["Authorization"] = f"Bearer {self.tokens[actor]}"
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        if body is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(body)
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=8)
        try:
            connection.request(method, path, body, headers)
            response = connection.getresponse()
            content = response.read(MAX_BODY + 1)
            require(response.status == expected, f"{method} {path} returned {response.status}, expected {expected}")
            require(len(content) <= MAX_BODY, "Platform response exceeded limit")
            return json.loads(content) if content else None
        finally:
            connection.close()

    def claim(self, expected_type, target, fingerprint):
        delivery = self.request("POST", "/api/v1/edge/claims", 200, "executor")
        require(delivery["type"] == expected_type, f"Expected {expected_type}, got {delivery['type']}")
        require(delivery["targetId"] == target and delivery["fingerprint"] == fingerprint,
                "Assigned target does not match the fixture")
        require(delivery["leaseUntil"] > time.time_ns() // 1_000_000, "Delivery has already expired")
        return delivery

    def complete(self, delivery, completion, result=None):
        body = {"leaseToken": delivery["leaseToken"], "completion": completion}
        if result is not None:
            body["result"] = result
        self.request("POST", f"/api/v1/edge/operations/{delivery['operationId']}/complete",
                     204, "executor", body)


from native import snapshot


def exercise(platform, feature, call, release, fingerprint):
    platform.request("POST", "/api/v1/assets", 201, "admin", {
        "assetId": "fixture", "appId": "fixture", "environmentName": "test",
        "zoneId": "lab", "agentId": "local-agent", "displayName": "Synthetic fixture",
        "members": ["operator"],
    })
    platform.request("POST", "/api/v1/assets/fixture/jvms", 201, "admin", {
        "targetId": "fixture-jvm", "fingerprint": fingerprint, "javaFeature": feature,
    })
    grant = platform.request("POST", "/api/v1/grants", 201, "operator", {
        "targetId": "fixture-jvm", "capabilities": ["JVM_OVERVIEW"],
        "ticketId": "synthetic", "requestedUntil": time.time_ns() // 1_000_000 + 300_000,
    })
    grant_id = grant["grantId"]
    session_body = {"targetId": "fixture-jvm", "grantId": grant_id}
    platform.request("POST", "/api/v1/sessions", 403, "operator", session_body)
    platform.request("POST", f"/api/v1/grants/{grant_id}/decisions", 200, "approver", {
        "eventId": "synthetic-approval", "decision": "APPROVE", "reasonCode": "fixture",
        "expectedRevision": grant["revision"],
    })
    session = platform.request("POST", "/api/v1/sessions", 202, "operator", session_body)
    session_path = f"/api/v1/sessions/{session['sessionId']}"
    attach = platform.claim("ATTACH", "fixture-jvm", fingerprint)
    SMOKE["expect_state"](call("exec", command="version", execTimeout=5000), "version")
    platform.complete(attach, "ATTACHED")
    require(platform.request("GET", session_path, 200, "operator")["state"] == "ACTIVE",
            "Session did not activate")
    task = platform.request("POST", f"{session_path}/tasks", 202, "operator",
                            {"capability": "JVM_OVERVIEW"}, "fixture-snapshot")
    dispatch = platform.claim("SNAPSHOT", "fixture-jvm", fingerprint)
    require(dispatch["generation"] == attach["generation"] and dispatch["taskId"] == task["taskId"],
            "Task is bound to a different session generation")
    result = snapshot(call)
    require(result["heapCommittedBytes"] > 0 and result["threadCount"] > 0, "Missing JVM measurements")
    platform.complete(dispatch, "DONE", result)
    task = platform.request("GET", f"/api/v1/tasks/{task['taskId']}", 200, "operator")
    require(task["state"] == "SUCCEEDED" and task["result"] == result, "Platform snapshot differs from source")
    platform.request("DELETE", session_path, 200, "operator")
    time.sleep(0.6)
    cleanup = platform.claim("RELEASE", "fixture-jvm", fingerprint)
    release()
    platform.complete(cleanup, "RELEASED")
    events = platform.request("GET", "/api/v1/audit/events?targetId=fixture-jvm", 200, "admin")
    require(any(event["action"] == "OPERATION_COMPLETED" and event["reasonCode"] == "RELEASED"
                for event in events), "Release audit is missing")
    return "authorization, session, leased task, Arthas snapshot, scheduled cleanup and audit"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ("platform-java", "platform-jar", "jdk", "arthas-zip", "classes"):
        parser.add_argument("--" + arg, type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--java-feature", type=int, required=True)
    parser.add_argument("--mode", choices=("attach", "startup"), default="attach")
    args = parser.parse_args()
    tokens = {role: secrets.token_urlsafe(36) for role in ("admin", "approver", "operator", "executor")}
    env = {**os.environ, **{f"DIAGNOSTIC_{role.upper()}_TOKEN": token for role, token in tokens.items()}}
    with tempfile.TemporaryDirectory(prefix="diagnostic-platform-fixture-") as directory:
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        with (Path(directory) / "platform.log").open("w") as log, subprocess.Popen(
            [str(args.platform_java.resolve()), "-jar", str(args.platform_jar.resolve()),
             f"--server.port={port}", "--diagnostic.idle-release-ms=200"],
            cwd=directory, env=env, stdout=log, stderr=subprocess.STDOUT,
        ) as process:
            try:
                platform = Platform(port, tokens)

                def ready():
                    require(process.poll() is None, "Packaged platform exited before readiness")
                    try:
                        return platform.request("GET", "/actuator/health", 200)["status"] == "UP"
                    except (OSError, http.client.HTTPException):
                        return False

                SMOKE["await_condition"]("Packaged platform did not start", ready, seconds=25)
                SMOKE["run"](args.jdk.resolve(), args.arthas_zip.resolve(), args.sha256.lower(),
                              args.classes.resolve(), args.mode,
                              lambda call, release, fingerprint: exercise(
                                  platform, args.java_feature, call, release, fingerprint))
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=8)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == "__main__":
    main()
