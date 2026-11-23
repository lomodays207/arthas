"""Project bounded Arthas responses into typed diagnostic metadata."""
import re
import time
from native import expect_state, require


def events(call, command):
    return expect_state(call("exec", command=command, execTimeout=3500), "query")["body"]["results"]


def observe(call, command, kind, deadline, permitted):
    session = expect_state(call("init_session"), "init")
    sid, consumer = session["sessionId"], session["consumerId"]
    job = None
    finished = False
    output = []
    try:
        start = expect_state(call("async_exec",sessionId=sid,command=command),"start","SCHEDULED")
        job = start["body"]["jobId"]
        until = min(time.monotonic()+3, time.monotonic()+max(0, deadline/1000-time.time()-1))
        while time.monotonic() < until and permitted():
            batch = expect_state(call("pull_results",sessionId=sid,consumerId=consumer),"poll")["body"]["results"]
            for item in batch:
                if item.get("jobId") != job:
                    continue
                if item["type"] == kind:
                    output.append(item)
                if item["type"] == "status":
                    require(item.get("statusCode") == 0,"Native operation failed")
                    finished = True
            if finished:
                break
            time.sleep(.08)
        return output
    finally:
        try:
            if job is not None and not finished:
                stop = expect_state(call("interrupt_job",sessionId=sid),"interrupt")["body"]
                require(stop.get("jobId") == job and stop.get("jobStatus") == "TERMINATED","Missing stop proof")
        finally:
            expect_state(call("close_session",sessionId=sid),"close")


def frame(item):
    return dict(className=item["className"],methodName=item["methodName"],line=item.get("lineNumber",-1))


def diagnostic(call, capability, criteria, allowed_methods, deadline, permitted=lambda:True):
    p = criteria or {}
    rows = []
    partial = False
    if capability == "THREAD_LIST":
        for event in events(call,"thread"):
            for thread in event.get("threadStats",[]):
                if thread.get("id",0)>0 and thread.get("state") and p.get("threadState") in (None,thread["state"]):
                    rows.append(dict(threadId=thread["id"],state=thread["state"],cpuPercent=max(0,thread["cpu"])))
    elif capability == "THREAD_DETAIL":
        tid = p["threadId"]
        require(type(tid) is int and 0 < tid < 2**63,"Invalid thread ID")
        for event in events(call,"thread "+str(tid)):
            info = event.get("threadInfo",{})
            owner=info.get("lockOwnerId",-1)
            for f in info.get("stackTrace",[]):
                row=dict(frame(f),threadId=tid,state=info["threadState"])
                if owner>0:
                    row["ownerThreadId"]=owner
                rows.append(row)
    else:
        clazz, method, loader = p["className"],p["methodName"],p.get("loader")
        require(re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$.]{0,149}",clazz) and
                re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{0,79}",method) and
                (not loader or re.fullmatch("[0-9a-f]{1,8}",loader)), "Invalid method selector")
        require(clazz+"#"+method in allowed_methods,"Method outside local allowlist")
        selection = (("--classloader "+loader+" ") if loader else "")+clazz+" "+method
        if capability == "CLASS_METHOD_LOOKUP":
            for event in events(call,"sm -d "+selection):
                m = event.get("methodInfo")
                if m:
                    rows.append(dict(className=m["declaringClass"],methodName=m["methodName"],
                                     loader=m["classLoaderHash"],descriptor=m["descriptor"]))
        else:
            require(loader and capability in ("METHOD_WATCH","METHOD_TRACE","METHOD_STACK","METHOD_MONITOR"),
                    "Invalid observation")
            kind = capability.removeprefix("METHOD_").lower()
            command = kind + (" -c 1 " if kind=="monitor" else " ") + selection
            if kind == "watch":
                command += " '#cost'"
            # The first invocation can already be on-stack when Trace attaches.
            limit = "2" if kind == "trace" else "1"
            for event in observe(call,command+" -n "+limit,kind,deadline,permitted):
                if kind == "watch":
                    rows.append(dict(className=clazz,methodName=method,costMs=event["cost"],state=event["accessPoint"]))
                elif kind == "stack":
                    rows.extend(frame(f) for f in event["stackTrace"])
                elif kind == "monitor":
                    for m in event["monitorDataList"]:
                        rows.append(dict(className=clazz,methodName=method,success=m["success"],failed=m["failed"],
                                         costMs=m["cost"]/max(1,m["total"])))
                else:
                    if rows:
                        continue
                    partial = True
                    nodes = [(event["root"],0)]
                    while nodes and len(rows)<13:
                        node,depth = nodes.pop()
                        if node.get("type") == "method":
                            rows.append(dict(frame(node),costMs=node.get("cost",0)/1e6,depth=depth))
                        nodes.extend((child,depth+1) for child in reversed(node.get("children",[])))
    coverage = "TRUNCATED" if len(rows)>12 else ("COMPLETE" if rows else "PARTIAL" if partial else "NO_HIT")
    return dict(coverage=coverage, sampledAt=int(time.time()*1000),rows=rows[:12])


def source_preview(call,criteria,allowed_classes):
    clazz,method,loader=criteria["className"],criteria.get("methodName"),criteria["loader"]
    require(clazz in allowed_classes and re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$.]{0,149}",clazz) and
            re.fullmatch("[0-9a-f]{1,8}",loader) and
            (method is None or re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{0,79}",method)),"Invalid source selector")
    output=events(call,"jad --source-only -c "+loader+" "+clazz+(" "+method if method else ""))
    values=[e["source"] for e in output if e.get("type")=="jad" and isinstance(e.get("source"),str)]
    text=values[0] if len(values)==1 else ""
    row=dict(className=clazz,loader=loader)
    if method:
        row["methodName"]=method
    return dict(coverage="TRUNCATED" if len(text)>960 else "COMPLETE" if text else "NO_HIT",
                sampledAt=int(time.time()*1000),rows=[row] if text else []),text[:960]
