from pathlib import Path
import tempfile,runpy,os,secrets,argparse,shutil
from playwright.sync_api import sync_playwright
parser=argparse.ArgumentParser()
parser.add_argument("--java",type=Path,required=True)
parser.add_argument("--platform",type=Path,required=True)
args=parser.parse_args()
java,jar=args.java.resolve(),args.platform.resolve()
browser=shutil.which("google-chrome") or shutil.which("chromium")
g=runpy.run_path(str(Path(__file__).with_name("gateway-smoke.py")))
roles={k:secrets.token_urlsafe(36) for k in ['admin','approver','operator','executor']}
port=g['port']()
with tempfile.TemporaryDirectory() as d:
 os.chdir(d)
 with g['server'](java,jar,port,{'DIAGNOSTIC_'+k.upper()+'_TOKEN':v for k,v in roles.items()}),sync_playwright() as pw:
  api=g['PLATFORM'](port,roles)
  api.request('POST','/api/v1/assets',201,'admin',dict(assetId='test',appId='app',environmentName='test',zoneId='lab',agentId='local-agent',displayName='Test',members=['operator']))
  api.request('POST','/api/v1/assets/test/jvms',201,'admin',dict(targetId='target',javaFeature=17,fingerprint='test'))
  b=pw.chromium.launch(executable_path=browser,args=['--no-sandbox'])
  def login(role):
   p=b.new_page();p.goto(f'http://127.0.0.1:{port}/console.html');p.locator('#token').fill(roles[role]);p.locator('#login button').click();p.locator('#history').wait_for();return p
  p=login('operator');p.locator('#ticket').fill('ticket');p.locator('#requested').select_option(['JVM_OVERVIEW','THREAD_LIST']);p.locator('#apply').click();p.get_by_text('已提交授权申请',exact=False).wait_for()
  a=login('approver');a.locator('#approve').click();a.get_by_text('ticket · APPROVE',exact=False).wait_for()
  p.locator('#refresh').click();p.wait_for_function("document.querySelector('#grant').selectedOptions[0].text.includes('GRANTED')")
  p.locator('#open').click();p.locator('#workspace').wait_for()
  op=api.claim('ATTACH','target','test');api.complete(op,'ATTACHED');p.wait_for_function("document.querySelector('#sessionState').textContent.includes('ACTIVE')")
  p.locator('#capability').select_option('THREAD_LIST');p.locator('#sample').click()
  p.get_by_text('QUEUED',exact=False).first.wait_for()
  op=api.claim('SNAPSHOT','target','test')
  api.request('POST','/api/v1/edge/operations/'+op['operationId']+'/complete',204,'executor',dict(leaseToken=op['leaseToken'],completion='DONE',evidence=dict(coverage='COMPLETE',sampledAt=123,rows=[dict(threadId=11,cpuPercent=2.5,state='RUNNABLE')])))
  p.locator('td',has_text='RUNNABLE').wait_for()
  p.locator('#close').click();p.wait_for_function("document.querySelector('#workspace').hidden");b.close()
  print('PASS browser login, multi-capability request/approval, session, typed thread result and close')
