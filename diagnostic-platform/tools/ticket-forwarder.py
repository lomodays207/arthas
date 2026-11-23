#!/usr/bin/env python3
"""Forward reference metadata to the configured ITSM ingestion endpoint."""
import argparse
import http.client
import json
import os
import ssl
import time
from urllib.parse import urlsplit


def send(url,method,token,context,body=None,key=None):
    address=urlsplit(url)
    if address.scheme=="https":
        con=http.client.HTTPSConnection(address.hostname,address.port or 443,context=context,timeout=6)
    elif address.scheme=="http" and address.hostname=="127.0.0.1":
        con=http.client.HTTPConnection(address.hostname,address.port or 80,timeout=6)
    else:
        raise ValueError("HTTPS or loopback origin required")
    headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"}
    if key: headers["Idempotency-Key"]=key
    try:
        con.request(method,address.path or "/",json.dumps(body) if body is not None else None,headers)
        response=con.getresponse()
        if not 200 <= response.status < 300:
            raise RuntimeError("Upstream status "+str(response.status))
        data=response.read(131073)
        if len(data)>131072: raise RuntimeError("Upstream response too large")
        return data
    finally:
        con.close()


def forward(base,endpoint,token,remote,ctx):
    feed=base.rstrip("/")+"/api/v1/integrations/tickets/events"
    events=json.loads(send(feed,"GET",token,ctx))
    for event in events:
        key=event["eventId"]
        send(endpoint,"POST",remote,ctx,event,key)
        send(feed+"/"+key+"/ack","POST",token,ctx)
    return len(events)


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--once",action="store_true")
    args=parser.parse_args()
    cfg=[os.environ[k] for k in ("DIAGNOSTIC_PLATFORM_URL","DIAGNOSTIC_ITSM_URL","DIAGNOSTIC_ITSM_TOKEN","ITSM_RECEIVER_TOKEN")]
    ctx=ssl.create_default_context(cafile=os.environ.get("DIAGNOSTIC_CA_FILE"))
    while True:
        try:
            forward(*cfg,ctx)
        except (OSError,http.client.HTTPException,RuntimeError):
            if args.once: raise
            print("Delivery pending; retrying",flush=True)
        if args.once: break
        time.sleep(5)
