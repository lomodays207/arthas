'use strict';
const el = id => document.getElementById(id);
const show = (id, visible) => { el(id).hidden = !visible; };
const path = encodeURIComponent;
let stream;
let token = '', session, task, grants = [], timer, epoch = 0, pendingKey;
async function api(url, method = 'GET', body, key) {
  const current = epoch;
  const headers = {Authorization: 'Bearer ' + token};
  if (body) headers['Content-Type'] = 'application/json';
  if (key) headers['Idempotency-Key'] = key;
  const response = await fetch('/api/v1' + url, {method, headers, body: JSON.stringify(body), cache: 'no-store'});
  const value = await response.text();
  if (current !== epoch) throw Error('会话已切换');
  if (!response.ok) throw Error(response.status + ' ' + (value ? JSON.parse(value).code || '' : ''));
  return value ? JSON.parse(value) : null;
}
function record(message) {
  const item = document.createElement('li');
  item.textContent = new Date().toLocaleTimeString() + ' · ' + message;
  el('events').prepend(item);
  while (el('events').children.length > 60) el('events').lastChild.remove();
}
function action(id, handler, event = 'click') {
  el(id).addEventListener(event, async e => {
    e.preventDefault();
    const control = e.submitter || e.currentTarget;
    control.disabled = true;
    try { el('message').textContent = ''; await handler(); }
    catch (err) { el('message').textContent = err.message; }
    finally { control.disabled = false; }
  });
}
function options(id, items, key, label) {
  el(id).replaceChildren(...items.map(item => new Option(label(item), item[key])));
}
async function targets() {
  const asset = el('asset').value;
  options('target', asset ? await api('/assets/' + path(asset) + '/jvms') : [], 'targetId',
    t => t.targetId + ' · Java ' + t.javaFeature);
}
async function refresh() {
  grants = await api('/grants');
  options('grant', grants, 'grantId', g => [g.targetId, g.ticketId, g.capabilities, g.state].join(' · '));
}
const caps = {JVM_OVERVIEW:'JVM 快照',THREAD_LIST:'线程热点',THREAD_DETAIL:'线程堆栈',
  CLASS_METHOD_LOOKUP:'类及方法定位',METHOD_WATCH:'方法观测',METHOD_TRACE:'调用树',
  METHOD_STACK:'调用路径',METHOD_MONITOR:'调用统计'};
const capOptions = values => values.map(k => ({key:k,label:caps[k]}));
options('requested', capOptions(Object.keys(caps)), 'key', x => x.label);
el('requested').options[0].selected = true;
function fields() {
  const cap = el('capability').value;
  show('threadField',cap === 'THREAD_DETAIL');
  show('methodFields',cap === 'CLASS_METHOD_LOOKUP' || cap.startsWith('METHOD_'));
}
action('capability',fields,'change');
action('login', async () => {
  token = el('token').value;
  const me = await api('/me');
  if (!['ADMIN','OPERATOR','APPROVER'].includes(me.role)) throw Error('此身份无法进入工作台');
  const assets = await api('/assets');
  options('asset', assets, 'assetId', a => a.displayName + ' · ' + a.environmentName);
  const params = new URLSearchParams(location.search);
  const assetId = params.get('asset');
  if (assets.some(a=>a.assetId === assetId)) el('asset').value = assetId;
  await targets();
  if (assetId === el('asset').value && [...el('target').options].some(t=>t.value === params.get('target'))) {
    el('target').value = params.get('target');
  }
  el('ticket').value = (params.get('ticket') || '').slice(0,100);
  show('management',me.role === 'ADMIN'); show('sharing',me.role === 'OPERATOR');
  if (me.role !== 'ADMIN') await refresh();
  el('token').value = '';
  for (const id of ['assets','logout','history']) show(id, true);
  show('login', false); show('audit', me.role === 'ADMIN');
  show('operator', me.role === 'OPERATOR'); show('open', me.role === 'OPERATOR');
  show('approvals', me.role !== 'ADMIN'); show('decisions', me.role === 'APPROVER');
  record(me.id + ' 已登录');
}, 'submit');
action('asset', targets, 'change');
action('refresh', refresh);
action('apply', async () => {
  await api('/grants','POST',{targetId:el('target').value, capabilities:Array.from(el('requested').selectedOptions,x=>x.value),
    ticketId:el('ticket').value.trim(), requestedUntil:Date.now()+3600000});
  await refresh(); record('已提交授权申请');
});
for (const decision of ['APPROVE','DENY','REVOKE']) action(decision.toLowerCase(), async () => {
  const g = grants.find(g => g.grantId === el('grant').value);
  if (!g) throw Error('请选择授权记录');
  await api('/grants/'+path(g.grantId)+'/decisions','POST',{decision,expectedRevision:g.revision,
    eventId:crypto.randomUUID(),reasonCode:el('reason').value});
  await refresh(); record(g.ticketId + ' · ' + decision);
});
action('audit', async () => {
  const events = await api('/audit/events?targetId='+path(el('target').value));
  record('审计记录 '+events.length+' 条');
  for (const e of events) record(new Date(e.occurredAt).toLocaleString()+' '+e.actorId+' '+e.action+' '+(e.reasonCode || ''));
});
const sessionUrl = () => '/sessions/'+path(session.sessionId);
const terminal = state => ['SUCCEEDED','FAILED','CANCELLED','TIMED_OUT'].includes(state);
function renderTask(t) {
  if (!task || task.state !== t.state) record(t.taskId+' · '+t.state);
  task = t;
  el('metrics').replaceChildren(); el('observations').replaceChildren();
  if (t.evidence) {
    const ev = t.evidence;
    const caption = document.createElement('p');
    caption.textContent = new Date(ev.sampledAt).toLocaleString()+' · '+
      ({COMPLETE:'已返回',PARTIAL:'命中但调用树不完整',TRUNCATED:'已截断',NO_HIT:'未命中'}[ev.coverage]);
    el('observations').append(caption);
    const table = document.createElement('table');
    const keys = [...new Set(ev.rows.flatMap(row => Object.keys(row)))];
    const header = table.createTHead().insertRow();
    const names = {threadId:'线程 ID',cpuPercent:'CPU %',state:'状态',className:'类',methodName:'方法',
      loader:'加载器',descriptor:'方法描述符',costMs:'耗时 (ms)',success:'成功',failed:'失败',line:'源代码行',depth:'调用层级'};
    for (const key of keys) header.appendChild(document.createElement('th')).textContent = names[key] || key;
    for (const row of ev.rows) {
      const tr = table.insertRow(); for (const key of keys) tr.insertCell().textContent = row[key] ?? '';
    }
    el('observations').append(table);
  }
  if (!t.result) return;
  const labels = {heapUsedBytes:'已用堆（字节）',heapCommittedBytes:'已提交堆（字节）',
    nonHeapUsedBytes:'已用非堆（字节）',threadCount:'线程数',uptimeMillis:'运行时间（毫秒）'};
  el('metrics').replaceChildren();
  for (const [k,label] of Object.entries(labels)) {
    const name = document.createElement('dt'), value = document.createElement('dd');
    name.textContent = label; value.textContent = t.result[k].toLocaleString(); el('metrics').append(name,value);
  }
}
async function monitor(id) {
  if (session?.sessionId !== id) return;
  try {
    const fresh = await api('/sessions/'+path(id)+'/heartbeat','POST');
    if (session?.sessionId !== id) return;
    session = fresh; el('sessionState').textContent = session.targetId+' · '+session.state;
    if (!el('shared').hidden && session.state === 'ACTIVE') {
      const overview = await api(sessionUrl()+'/overview');
      if (overview.result) el('overview').textContent =
        (overview.stale?'上次快照':'共享快照')+' · '+new Date(overview.receivedAt).toLocaleTimeString()+' · '+
        '堆内存 '+Math.round(overview.result.heapUsedBytes/1048576)+' MiB · '+overview.result.threadCount+' 个线程';
    }
    if (task && !terminal(task.state)) renderTask(await api('/tasks/'+path(task.taskId)));
  } catch (e) { el('message').textContent = e.message; }
  if (session?.sessionId === id) timer = setTimeout(() => monitor(id), 3000);
}
action('open', async () => {
  if (session) throw Error('请先关闭当前会话');
  const g = grants.find(g => g.grantId === el('grant').value);
  if (!g || g.state !== 'GRANTED') throw Error('请选择已批准的授权');
  session = await api('/sessions','POST',{targetId:g.targetId,grantId:g.grantId});
  options('capability',capOptions(g.capabilities.split(',')),'key',x=>x.label); fields();
  show('shared',g.capabilities.split(',').includes('JVM_OVERVIEW')); el('overview').textContent='';
  show('workspace',true); await monitor(session.sessionId);
});
async function follow(id) {
  stream?.abort();
  const controller = new AbortController();
  stream = controller;
  let cursor = 0;
  while (!controller.signal.aborted && task?.taskId === id && !terminal(task.state)) {
    try {
      const response = await fetch('/api/v1/tasks/'+path(id)+'/events',{
        headers:{Authorization:'Bearer '+token,'Last-Event-ID':String(cursor)},signal:controller.signal});
      if (!response.ok) return;
      const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = '';
      for (;;) {
        const {value,done} = await reader.read();
        if (done) break;
        buffer += value;
        let end;
        while ((end = buffer.indexOf('\n\n')) >= 0) {
          const block = buffer.slice(0,end); buffer = buffer.slice(end+2);
          const data = block.split('\n').find(line=>line.startsWith('data:'));
          if (data && task?.taskId === id) {
            const event = JSON.parse(data.slice(5)); cursor = event.sequenceNo;
            record(id+' · '+event.state);
            if (terminal(event.state)) {
              const final = await api('/tasks/'+path(id));
              if (task?.taskId === id) renderTask(final);
              return;
            }
          }
        }
      }
    } catch (e) { if (controller.signal.aborted) return; }
    await new Promise(resolve=>setTimeout(resolve,1000));
  }
}

action('sample', async () => {
  if (task && !terminal(task.state)) throw Error('当前任务仍在执行');
  pendingKey ||= crypto.randomUUID();
  const capability = el('capability').value;
  let criteria;
  if (capability === 'THREAD_DETAIL') criteria = {threadId:Number(el('threadId').value)};
  if (capability === 'CLASS_METHOD_LOOKUP' || capability.startsWith('METHOD_')) {
    criteria = {className:el('className').value.trim(),methodName:el('methodName').value.trim(),
      loader:el('loader').value.trim() || null};
  }
  renderTask(await api(sessionUrl()+'/tasks','POST',{capability,criteria},pendingKey));
  pendingKey = null; void follow(task.taskId);
});
action('cancel', async () => {
  if (!task) throw Error('当前无任务');
  renderTask(await api('/tasks/'+path(task.taskId)+'/cancel','POST'));
});
action('close', async () => {
  await api(sessionUrl(),'DELETE'); stream?.abort(); clearTimeout(timer); session = task = pendingKey = null;
  el('metrics').replaceChildren(); el('observations').replaceChildren(); show('workspace',false); record('会话已关闭');
});
action('logout', async () => {
  try { if (session) await api(sessionUrl(),'DELETE'); }
  finally { ++epoch; token = ''; clearTimeout(timer); location.reload(); }
});

let policy;
function management(value) { el('managementData').textContent = JSON.stringify(value,null,2); }
action('channels',async()=>management(await api('/management/channels')));
action('cleanup',async()=>management(await api('/management/cleanup')));
action('getPolicy',async()=>{
  policy = await api('/assets/'+path(el('asset').value)+'/policy');
  el('quota').value = policy.maxSessions; el('pause').checked = policy.paused;
  management(policy);
});
action('setPolicy',async()=>{
  if (!policy || policy.assetId !== el('asset').value) throw Error('请先读取当前实例策略');
  policy = await api('/assets/'+path(policy.assetId)+'/policy','PUT',{expectedRevision:policy.revision,
    paused:el('pause').checked,maxSessions:Number(el('quota').value)});
  management(policy);
});
action('share',async()=>{
  if (!task || task.state !== 'SUCCEEDED') throw Error('请先完成诊断');
  const g = await api('/grants/'+path(session.grantId));
  const ref = await api('/tasks/'+path(task.taskId)+'/references','POST',{readerId:el('readerId').value.trim(),
    expiresAt:Math.min(Date.now()+600000,g.expiresAt)});
  el('refId').value = ref.referenceId; record('已创建证据引用');
});
action('readRef',async()=>{
  el('referenceData').textContent = '';
  const t = await api('/references/'+path(el('refId').value.trim()));
  el('referenceData').textContent = JSON.stringify(t.result || t.evidence,null,2);
});
action('revokeRef',async()=>{
  await api('/references/'+path(el('refId').value.trim()),'DELETE');
  el('referenceData').textContent = ''; record('证据引用已撤销');
});

action('shared',async()=>{ const v=await api(sessionUrl()+'/overview','POST'); record(v.pending?'共享快照采集中':'已复用最近五秒的快照'); });
