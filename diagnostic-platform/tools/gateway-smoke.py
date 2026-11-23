#!/usr/bin/env python3
"""Exercise two certificate-bound agents against the packaged gateway and platform."""
import argparse
import contextlib
import hashlib
import http.client
import json
import os
from pathlib import Path
import runpy
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time

PLATFORM = runpy.run_path(str(Path(__file__).with_name("control-plane-smoke.py")))["Platform"]


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def issue(name, usage):
    run("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN="+name,
        "-keyout", name+".key", "-out", name+".csr")
    ext = Path(name+".ext")
    ext.write_text("basicConstraints=CA:FALSE\nextendedKeyUsage="+usage+"\nsubjectAltName=IP:127.0.0.1\n")
    run("openssl", "x509", "-req", "-in", name+".csr", "-CA", "ca.pem", "-CAkey", "ca.key",
        "-CAcreateserial", "-days", "1", "-extfile", str(ext), "-out", name+".pem")
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(Path(name+".pem").read_text())).hexdigest()


@contextlib.contextmanager
def server(java, jar, listen, env, *args):
    with Path(jar.stem+".log").open("w+") as log:
        proc = subprocess.Popen([java, "-jar", jar, "--server.port="+str(listen), *args],
                                env=dict(os.environ, **env), stdout=log, stderr=subprocess.STDOUT)
        try:
            for _ in range(250):
                if proc.poll() is not None:
                    log.seek(0)
                    raise RuntimeError(log.read()[-4000:])
                try:
                    with socket.create_connection(("127.0.0.1", listen), .2):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise RuntimeError("startup timeout")
            yield proc
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


def host_agent_smoke(api, gateway_port, stalled_gateway, jdk, archive, classes):
    agent_script = Path(__file__).resolve().parents[1] / "agent" / "host_agent.py"
    sys.path.insert(0, str(agent_script.parent))
    from identity import fingerprint, profile
    from native import await_condition, owned_listener
    import sqlite3

    with open("fixture.log","w") as log, subprocess.Popen(
            [jdk/"bin/java","-Djava.net.preferIPv4Stack=true","-cp",classes,"io.diagnostic.fixture.DiagnosticFixture"],
            stdout=log,stderr=log) as fixture:
        try:
            await_condition("Fixture start failed",lambda:"FIXTURE_READY" in Path("fixture.log").read_text())
            identity = fingerprint(fixture.pid,jdk)
            cfg = dict(pid=fixture.pid,jdk=str(jdk),gateway=f"https://127.0.0.1:{gateway_port}",
                       ca="ca.pem",cert="a.pem",key="a.key",targetId="real",fingerprint=identity,
                       gateways=["https://127.0.0.1:"+str(port()),f"https://127.0.0.1:{gateway_port}"],
                       stateDir="agent-state",archive=str(archive),runtimeProfile=profile(jdk),
                       sha256="2f75ea954ead5d02c4a743ecd783fd92f546a44ef3aee437ea5066eb30ad07bf")
            Path("agent.json").write_text(json.dumps(cfg))
            api.request("POST","/api/v1/assets/test/jvms",201,"admin",
                        dict(targetId="real", fingerprint=identity, javaFeature=int(os.environ.get("TARGET_FEATURE",17))))
            g = api.request("POST","/api/v1/grants",201,"operator",dict(targetId="real",capabilities=["JVM_OVERVIEW"],
                            requestedUntil=int(time.time()*1000)+300000,ticketId="fixture"))
            api.request("POST","/api/v1/grants/"+g["grantId"]+"/decisions",200,"approver",
                        dict(decision="APPROVE",eventId="real",expectedRevision=1,reasonCode="fixture"))
            session = api.request("POST","/api/v1/sessions",202,"operator",dict(targetId="real",grantId=g["grantId"]))
            url = "/api/v1/sessions/"+session["sessionId"]
            def start():
                return subprocess.Popen([sys.executable,agent_script,"--config","agent.json"])
            worker = start()
            try:
                await_condition("Agent did not attach",lambda:api.request("GET",url,200,"operator")["state"]=="ACTIVE",35)
                # Restart hard, preserving the local journal and the already-managed listener.
                worker.kill()
                worker.wait(10)
                worker=start()
                task = api.request("POST",url+"/tasks",202,"operator",dict(capability="JVM_OVERVIEW"),"real")
                def sampled():
                    t = api.request("GET","/api/v1/tasks/"+task["taskId"],200,"operator")
                    return t["state"] == "SUCCEEDED" and t["result"]["threadCount"]>0
                await_condition("No native snapshot",sampled,20)
                with sqlite3.connect("agent-state/journal.db") as journal:
                    native_port = journal.execute("SELECT port FROM instance").fetchone()[0]
                assert owned_listener(fixture.pid,native_port)
                if stalled_gateway:
                    stalled_gateway.send_signal(signal.SIGSTOP)
                    try:
                        await_condition("Agent did not reap offline listener",
                                        lambda:not owned_listener(fixture.pid,native_port),65)
                    finally:
                        stalled_gateway.send_signal(signal.SIGCONT)
                else:
                    worker.terminate()
                    worker.wait(20)
                    worker = start()
                assert fixture.poll() is None
                def reconciled():
                    audit=api.request("GET","/api/v1/audit/events?targetId=real",200,"admin")
                    return any(e["action"]=="AGENT_RELEASE_CONFIRMED" for e in audit)
                await_condition("Release proof missing after reconnection",reconciled,20)
                assert not owned_listener(fixture.pid,native_port)
                print("PASS host agent: native attach, structured snapshot, local cleanup, restart reconciliation")
            finally:
                worker.terminate()
                worker.wait(20)
        finally:
            fixture.terminate()
            fixture.wait(8)


def exercise(java, platform, gateway, host_args, network_loss):
    tokens = {k:secrets.token_urlsafe(36) for k in ["admin","operator","approver","a","b"]}
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days","1","-subj","/CN=smoke-ca",
        "-addext","basicConstraints=critical,CA:TRUE","-keyout","ca.key","-out","ca.pem")
    issue("server","serverAuth")
    pins = {k:issue(k,"clientAuth") for k in ["a","b","unbound"]}
    api_port, edge_port = port(), port()
    env = {"DIAGNOSTIC_"+k.upper()+"_TOKEN":tokens[k] for k in ["admin","operator","approver"]}
    env["DIAGNOSTIC_AGENT_TOKENS"] = ",".join(k+"="+tokens[k] for k in ["a","b"])
    edge_env = {"DIAGNOSTIC_CERT_TOKENS": ",".join(pins[k]+"="+tokens[k] for k in ["a","b"])}

    def edge(identity, endpoint="claims", body=None):
        ctx = ssl.create_default_context(cafile="ca.pem")
        if identity:
            ctx.load_cert_chain(identity+".pem", identity+".key")
        con = http.client.HTTPSConnection("127.0.0.1", edge_port, context=ctx, timeout=5)
        try:
            con.request("POST", "/edge/v1/"+endpoint, json.dumps(body) if body else None)
            response = con.getresponse()
            raw = response.read()
            return response.status, json.loads(raw) if raw else None
        finally:
            con.close()

    with server(java, platform, api_port, env), server(java, gateway, edge_port, edge_env,
            "--diagnostic.platform-port="+str(api_port), "--server.ssl.enabled=true",
            "--server.ssl.certificate=server.pem","--server.ssl.certificate-private-key=server.key",
            "--server.ssl.trust-certificate=ca.pem") as edge_process:
        api = PLATFORM(api_port, tokens)
        assert api.request("GET","/api/v1/me",200,"operator")["role"] == "OPERATOR"
        api.request("GET","/api/v1/grants",401)
        api.request("POST","/api/v1/assets",201,"admin",dict(assetId="test",appId="test",
            environmentName="test",zoneId="test",agentId="a",displayName="test",members=["operator"]))
        api.request("POST","/api/v1/assets/test/jvms",201,"admin",dict(targetId="test",fingerprint="test",
            javaFeature=17))
        grant = api.request("POST","/api/v1/grants",201,"operator",dict(targetId="test",
            capabilities=["JVM_OVERVIEW"],ticketId="test",requestedUntil=int(time.time()*1000)+60000))
        assert api.request("GET","/api/v1/grants",200,"approver")[0]["grantId"] == grant["grantId"]
        api.request("POST","/api/v1/grants/"+grant["grantId"]+"/decisions",200,"approver",dict(
            eventId="test",decision="APPROVE",reasonCode="test",expectedRevision=1))
        api.request("POST","/api/v1/sessions",202,"operator",dict(targetId="test",grantId=grant["grantId"]))
        try:
            edge(None)
        except (ssl.SSLError, ConnectionError, http.client.RemoteDisconnected):
            pass
        else:
            raise AssertionError("Client certificate must be required at handshake")
        assert edge("unbound")[0] == 403
        assert edge("b")[0] == 204
        status, item = edge("a")
        assert status == 200 and item["type"] == "ATTACH"
        endpoint = "operations/"+item["operationId"]+"/complete"
        receipt = dict(leaseToken=item["leaseToken"],completion="ATTACHED")
        assert edge("b",endpoint,receipt)[0] == 403
        assert edge("a",endpoint,receipt)[0] == 204
        assert edge("a",endpoint,receipt)[0] == 204
        release = "targets/test/generations/1/released"
        assert edge("b",release)[0] == 403
        assert edge("a",release)[0] == 204
        assert edge("a",release)[0] == 204
        if host_args:
            host_agent_smoke(api,edge_port,edge_process if network_loss else None,*host_args)
        print("PASS two-agent mTLS, authenticated claim, cross-agent rejection and replay")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ["java","platform","gateway"]:
        parser.add_argument("--"+name, required=True, type=Path)
    for name in ["jdk","archive","classes"]:
        parser.add_argument("--"+name,type=Path)
    parser.add_argument("--network-loss",action="store_true")
    args = parser.parse_args()
    host_args = [v.resolve() for v in [args.jdk,args.archive,args.classes] if v]
    if len(host_args) not in (0,3):
        parser.error("Supply --jdk, --archive and --classes together")
    paths = [v.resolve() for v in [args.java,args.platform,args.gateway]]
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        exercise(*paths,host_args,args.network_loss)
