#!/usr/bin/env python3
"""Single-target Linux pilot agent. The target is selected by its local owner."""
import argparse
import base64
import shutil
import signal
import fcntl
import hashlib
import tempfile
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import ssl
import subprocess
import time
from urllib.parse import urlsplit

import native
from diagnostics import diagnostic, source_preview


from identity import container_context, fingerprint, profile


def discover(jdk, container=False):
    runtime = profile(jdk)
    for proc in Path("/proc").iterdir():
        if proc.name.isdecimal():
            try:
                pid = int(proc.name)
                context = container_context(pid) if container else None
                print(json.dumps(dict(pid=pid, fingerprint=fingerprint(pid,jdk,context), runtimeProfile=runtime,
                                      container=context)))
            except (OSError, RuntimeError):
                continue


class Agent:
    def __init__(self, cfg, root):
        self.cfg, self.root = cfg, root
        self.previews = {}
        self.last_recovery = 0
        self.pid, self.jdk = int(cfg["pid"]), Path(cfg["jdk"]).resolve()
        native.require(profile(self.jdk) == cfg["runtimeProfile"], "Configured runtime profile differs")
        self.urls = [urlsplit(url) for url in cfg.get("gateways",[cfg.get("gateway","")])]
        native.require(0 < len(self.urls) <= 4, "Invalid gateway set")
        for url in self.urls:
            native.require(url.scheme == "https" and url.hostname and url.path in ("", "/")
                           and not url.username and not url.query and not url.fragment, "Invalid gateway")
        self.gateway_index = 0
        self.tls = ssl.create_default_context(cafile=cfg["ca"])
        self.tls.load_cert_chain(cfg["cert"], cfg["key"])
        self.db = sqlite3.connect(root / "journal.db")
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS instance (generation INTEGER PRIMARY KEY, port INTEGER, password TEXT, state TEXT);
            CREATE TABLE IF NOT EXISTS receipt (id TEXT PRIMARY KEY, operation TEXT, body TEXT, sent INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS releases (generation INTEGER PRIMARY KEY);
            CREATE TABLE IF NOT EXISTS binding (id INTEGER PRIMARY KEY CHECK(id=1), target TEXT, fingerprint TEXT);
        """)
        self.db.execute("INSERT OR IGNORE INTO binding VALUES (1,?,?)", (cfg["targetId"],cfg["fingerprint"]))
        bound = self.db.execute("SELECT target,fingerprint FROM binding").fetchone()
        native.require(tuple(bound) == (cfg["targetId"],cfg["fingerprint"]), "State directory belongs to another target")
        self.db.commit()

    def edge(self, path, body=None):
        url = self.urls[self.gateway_index]
        con = http.client.HTTPSConnection(url.hostname, url.port or 443, context=self.tls, timeout=5)
        try:
            con.request("POST", "/edge/v1/"+path, json.dumps(body) if body else None,
                        {"Content-Type":"application/json"})
            response = con.getresponse()
            raw = response.read(16385)
            if response.status == 409 and path.startswith("operations/") and len(raw)<=16384:
                if json.loads(raw).get("code")=="OPERATION_STATE_CHANGED":
                    return None  # Center already fenced this generation; never execute it again.
            native.require(len(raw) <= 16384 and response.status in (200,204),
                           "Gateway status " + str(response.status))
            return json.loads(raw) if raw else None
        except (OSError,http.client.HTTPException,RuntimeError):
            self.gateway_index=(self.gateway_index+1)%len(self.urls)
            raise
        finally:
            con.close()

    def same(self):
        return fingerprint(self.pid, self.jdk, self.cfg.get("container")) == self.cfg["fingerprint"]

    def call(self, row, action, **args):
        native.require(self.same(), "Target identity changed")
        auth = base64.b64encode(("agent:"+row["password"]).encode()).decode()
        return native.request(self.pid, native.process_start_ticks(self.pid), row["port"], auth, action, **args)

    def prepare_media(self, generation):
        archive=Path(self.cfg["archive"])
        digest=self.cfg["sha256"]
        with archive.open("rb") as file:
            native.require(hashlib.file_digest(file,"sha256").hexdigest()==digest,"Arthas archive digest mismatch")
        cache=self.root/("distribution-"+digest)
        if not cache.is_dir():
            with tempfile.TemporaryDirectory(dir=self.root) as scratch:
                staging=Path(scratch)/"unpacked"
                staging.mkdir()
                native.unpack(archive,digest,staging)
                staging.rename(cache)
        # Keep classpath-local properties private to this attach generation.
        package=self.root/("media-"+str(generation))
        shutil.copytree(cache,package,copy_function=os.link,ignore=shutil.ignore_patterns("arthas.properties"))
        return package

    def external_media(self):
        for descriptor in Path(f"/proc/{self.pid}/fd").iterdir():
            try:
                target=Path(os.readlink(descriptor).removesuffix(" (deleted)"))
            except FileNotFoundError:
                continue
            if target.name in ("arthas-core.jar","arthas-agent.jar") and not target.is_relative_to(self.root):
                return True
        return False

    def attach(self, op):
        gen = op["generation"]
        prev = self.db.execute("SELECT * FROM instance ORDER BY generation DESC LIMIT 1").fetchone()
        if prev and (prev["generation"] >= gen or prev["state"] != "CLOSED"):
            return "UNKNOWN", None
        if self.external_media():
            return "FAILED", None
        package = self.prepare_media(gen)
        with socket.socket() as sock:
            sock.bind((native.HOST, 0))
            port = sock.getsockname()[1]
        password = secrets.token_urlsafe(36)
        (package / "arthas.properties").write_text(
            "arthas.config.overrideAll=true\narthas.ip=127.0.0.1\narthas.telnetPort=-1\n"
            f"arthas.httpPort={port}\narthas.localConnectionNonAuth=false\narthas.username=agent\n"
            f"arthas.password={password}\n")
        self.db.execute("INSERT INTO instance VALUES (?,?,?,'STARTING')",(gen,port,password))
        self.db.commit()
        native.require(self.same() and time.time()*1000 < op["leaseUntil"], "Attach lease expired")
        cp = [package/"arthas-core.jar"]
        if (self.jdk/"lib/tools.jar").is_file():
            cp.append(self.jdk/"lib/tools.jar")
        subprocess.run([self.jdk/"bin/java", "-Duser.home="+str(self.root), "-cp", os.pathsep.join(map(str,cp)),
                        "com.taobao.arthas.core.Arthas", "-pid", str(self.pid), "-core", cp[0],
                        "-agent", package/"arthas-agent.jar", "-target-ip",native.HOST,
                        "-telnet-port","-1","-http-port",str(port)], cwd=self.root, check=True, timeout=20,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        native.await_condition("No owned listener", lambda: self.same() and native.owned_listener(self.pid,port))
        native.require(native.request(self.pid,native.process_start_ticks(self.pid),port,None,"exec",command="version")[0]
                       in (401,403), "Native authentication required")
        row = self.db.execute("SELECT * FROM instance WHERE generation=?", (gen,)).fetchone()
        native.expect_state(self.call(row,"exec",command="version",execTimeout=3000),"version")
        self.db.execute("UPDATE instance SET state='READY' WHERE generation=?",(gen,))
        self.db.commit()
        return "ATTACHED", None

    def release(self, row, offline=False):
        if row["state"] != "CLOSED":
            if native.owned_listener(self.pid,row["port"]):
                native.stop_listener(lambda action,**args:self.call(row,action,**args),self.pid,row["port"])
            elif row["state"] == "STARTING":
                raise RuntimeError("Incomplete attach requires reconciliation")
            self.record_closed(row,offline)
        return "RELEASED", None

    def record_closed(self,row,offline):
        self.db.execute("UPDATE instance SET state='CLOSED',password='' WHERE generation=?",(row["generation"],))
        if offline:
            self.db.execute("INSERT OR IGNORE INTO releases VALUES (?)",(row["generation"],))
        self.db.commit()
        shutil.rmtree(self.root / ("media-"+str(row["generation"])), ignore_errors=True)

    def recover_interrupted(self):
        # A process crash can leave a durable intent without a native completion.
        # Reconcile by shutting down our authenticated endpoint, never by reissuing the intent.
        for item in self.db.execute("SELECT operation FROM receipt WHERE body IS NULL").fetchall():
            op=json.loads(item["operation"])
            row=self.db.execute("SELECT * FROM instance WHERE generation=?",(op["generation"],)).fetchone()
            if row is None:
                continue
            if row["state"]=="CLOSED":
                self.db.execute("INSERT OR IGNORE INTO releases VALUES (?)",(row["generation"],))
            else:
                self.cleanup_one(row)
            body=dict(completion="UNKNOWN",leaseToken=op["leaseToken"])
            self.db.execute("UPDATE receipt SET body=? WHERE id=?",(json.dumps(body),op["operationId"]))
            self.db.commit()

    def perform(self, op):
        if op["targetId"] != self.cfg["targetId"] or op["fingerprint"] != self.cfg["fingerprint"]:
            return "UNKNOWN", None
        try:
            same = self.same()
        except FileNotFoundError:
            if Path(f"/proc/{self.pid}").exists():
                raise
            same = False
        if not same:
            return ("TARGET_GONE" if op["type"] in ("ATTACH","RELEASE","EMERGENCY_RELEASE") else "FAILED"), None
        if op["type"] == "ATTACH":
            return self.attach(op)
        row = self.db.execute("SELECT * FROM instance WHERE generation=?",(op["generation"],)).fetchone()
        if not row:
            return "UNKNOWN", None
        if op["type"] in ("RELEASE","EMERGENCY_RELEASE"):
            return self.release(row)
        if op["type"] == "CANCEL":
            # A serial worker cannot be running another request. An interrupted native query
            # requires proof of termination before the platform can release its task slot.
            for receipt in self.db.execute("SELECT operation,body FROM receipt WHERE body IS NOT NULL"):
                previous = json.loads(receipt["operation"])
                if (previous.get("taskId") == op["taskId"] and previous["type"] == "SNAPSHOT" and
                        json.loads(receipt["body"])["completion"] in ("DONE","FAILED")):
                    return "STOPPED", None
            return ("STOPPED" if row["state"] == "CLOSED" else "UNKNOWN"), None
        if (op["type"] == "SNAPSHOT" and row["state"] == "READY" and
                time.time()*1000 < min(op["taskDeadline"],op["leaseUntil"])):
            def permitted():
                proof = self.edge("operations/"+op["operationId"]+"/authority",{"leaseToken":op["leaseToken"]})
                return proof["permitted"]
            if not permitted():
                return "FAILED", None
            def call(action, **args):
                return self.call(row,action,**args)
            if op.get("capability") in (None,"JVM_OVERVIEW"):
                return "DONE", native.snapshot(call)
            params = op.get("criteria") or {}
            if op["capability"] == "CODE_VIEW":
                allowed=self.cfg.get("allowedCodeClasses",[])
                if params.get("className") not in allowed:
                    return "FAILED", None
                evidence,preview=source_preview(call,params,allowed)
                if preview:
                    self.previews[op["operationId"]]=(time.monotonic()+60,preview)
                return "DONE",evidence
            if params.get("className") and params["className"]+"#"+params["methodName"] not in self.cfg.get("allowedMethods",[]):
                return "FAILED", None
            return "DONE", diagnostic(call,op["capability"],op["criteria"],self.cfg.get("allowedMethods",[]),
                                      min(op["leaseUntil"],op["taskDeadline"]),permitted)
        return "UNKNOWN", None

    def tick(self):
        if time.monotonic()-self.last_recovery>=5:
            self.last_recovery=time.monotonic()
            try:
                self.recover_interrupted()
            except (OSError,RuntimeError,http.client.HTTPException) as error:
                print("Interrupted intent remains unconfirmed:",type(error).__name__,flush=True)
        self.previews={key:value for key,value in self.previews.items() if value[0]>time.monotonic()}
        for row in self.db.execute("SELECT * FROM receipt WHERE sent=0 ORDER BY rowid LIMIT 20").fetchall():
            op = json.loads(row["operation"])
            body = json.loads(row["body"]) if row["body"] else dict(leaseToken=op["leaseToken"],completion="UNKNOWN")
            if row["id"] in self.previews:
                body["preview"]=self.previews[row["id"]][1]
            self.edge("operations/"+row["id"]+"/complete",body)
            self.previews.pop(row["id"],None)
            self.db.execute("UPDATE receipt SET sent=1 WHERE id=?",(row["id"],))
            self.db.commit()
        for row in self.db.execute("SELECT generation FROM releases ORDER BY generation").fetchall():
            gen = row["generation"]
            self.edge(f"targets/{self.cfg['targetId']}/generations/{gen}/released")
            self.db.execute("DELETE FROM releases WHERE generation=?", (gen,))
            self.db.commit()
        op = self.edge("claims")
        if not op:
            return
        cursor = self.db.execute("INSERT OR IGNORE INTO receipt(id,operation) VALUES (?,?)",
                                 (op["operationId"],json.dumps(op)))
        self.db.commit()
        if cursor.rowcount == 0:
            return
        try:
            status, result = self.perform(op)
        except Exception as error:
            print("Native operation requires reconciliation:", type(error).__name__, flush=True)
            status, result = "UNKNOWN", None
        body = dict(leaseToken=op["leaseToken"],completion=status)
        if result is not None:
            body["evidence" if "rows" in result else "result"] = result
        self.db.execute("UPDATE receipt SET body=? WHERE id=?",(json.dumps(body),op["operationId"]))
        self.db.commit()

    def cleanup_one(self,row):
        try:
            same=self.same()
        except FileNotFoundError:
            if Path(f"/proc/{self.pid}").exists():
                raise
            same=False
        if same:
            self.release(row,offline=True)
        else:
            # The enrolled process has disappeared. Do not touch its replacement.
            self.record_closed(row,True)

    def cleanup(self):
        for row in self.db.execute("SELECT * FROM instance WHERE state!='CLOSED'").fetchall():
            try:
                self.cleanup_one(row)
            except (OSError,RuntimeError,http.client.HTTPException) as error:
                print("Local cleanup remains unconfirmed:",type(error).__name__,flush=True)

    def serve(self):
        last = time.monotonic()
        try:
            while True:
                try:
                    self.tick()
                    last = time.monotonic()
                except (RuntimeError,OSError,http.client.HTTPException) as error:
                    print("Gateway unavailable or reconciliation required:", type(error).__name__,flush=True)
                    if time.monotonic()-last > 45:
                        self.cleanup()
                time.sleep(.5)
        finally:
            self.cleanup()


def main():
    parser = argparse.ArgumentParser()
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--discover",metavar="JDK",type=Path)
    modes.add_argument("--config",type=Path)
    parser.add_argument("--container",action="store_true",help="Require verified same-container membership in discovery")
    args = parser.parse_args()
    if args.discover:
        discover(args.discover.resolve(),args.container)
        return
    os.umask(0o077)
    cfg = json.loads(args.config.read_text())
    root = Path(cfg["stateDir"]).resolve()
    root.mkdir(mode=0o700,parents=True,exist_ok=True)
    native.require(root.stat().st_uid == os.geteuid() and not root.stat().st_mode & 0o077, "Private state required")
    with (root/"agent.lock").open("a") as lock:
        fcntl.flock(lock,fcntl.LOCK_EX | fcntl.LOCK_NB)
        def terminate(signum, frame):
            raise SystemExit(0)
        signal.signal(signal.SIGTERM,terminate)
        Agent(cfg,root).serve()


if __name__ == "__main__":
    main()
