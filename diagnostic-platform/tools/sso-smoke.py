"""Exercise signed access tokens against a packaged control plane."""
import argparse
import base64
import json
import os
from pathlib import Path
import runpy
import subprocess
import tempfile
import time

helpers=runpy.run_path(str(Path(__file__).with_name("gateway-smoke.py")))
def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=")
def signed(audience,expiry,subject="user",issuer="https://sso.example"):
    payload=dict(iss=issuer,aud=audience,exp=expiry,sub=subject,diagnostic_role="ADMIN")
    data=b64(b'{"alg":"RS256","typ":"JWT"}')+b"."+b64(json.dumps(payload).encode())
    signature=subprocess.run(["openssl","dgst","-sha256","-sign","signing.key"],input=data,capture_output=True,check=True).stdout
    return (data+b"."+b64(signature)).decode()
if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--java",required=True,type=Path)
    parser.add_argument("--platform",required=True,type=Path)
    args=parser.parse_args()
    java,jar=args.java.resolve(),args.platform.resolve()
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        helpers["run"]("openssl","genpkey","-algorithm","RSA","-pkeyopt","rsa_keygen_bits:2048","-out","signing.key")
        helpers["run"]("openssl","pkey","-in","signing.key","-pubout","-out","issuer.pem")
        env=dict(DIAGNOSTIC_SSO_PUBLIC_KEY="issuer.pem",DIAGNOSTIC_SSO_ISSUER="https://sso.example",
                 DIAGNOSTIC_SSO_AUDIENCE="diagnostics",DIAGNOSTIC_SSO_SUBJECTS="user=OPERATOR")
        port=helpers["port"]()
        future=int(time.time())+120
        valid=signed("diagnostics",future)
        tokens=dict(valid=valid,wrongAud=signed("other",future),expired=signed("diagnostics",future-180),
                    unknown=signed("diagnostics",future,"other"),wrongIssuer=signed("diagnostics",future,issuer="other"),
                    tampered=valid[:-15]+"invalid")
        with helpers["server"](java,jar,port,env):
            api=helpers["PLATFORM"](port,tokens)
            assert api.request("GET","/api/v1/me",200,"valid")==dict(id="sso.user",role="OPERATOR")
            for invalid in tokens.keys()-{"valid"}:
                api.request("GET","/api/v1/me",401,invalid)
            api.request("GET","/api/v1/management/channels",403,"valid")
            print("PASS signed identity, local role binding, issuer, audience, expiry, subject and signature checks")
