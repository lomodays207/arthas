'use strict';
const el = id => document.getElementById(id);
const show = (id, visible) => { el(id).hidden = !visible; };
const path = encodeURIComponent;
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
  options('grant', grants, 'grantId', g => [g.targetId, g.ticketId, g.state].join(' · '));
}
action('login', async () => {
  token = el('token').value;
  const me = await api('/me');
  if (!['ADMIN','OPERATOR','APPROVER'].includes(me.role)) throw Error('此身份无法进入工作台');
  const assets = await api('/assets');
  options('asset', assets, 'assetId', a => a.displayName + ' · ' + a.environmentName);
  await targets();
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
  await api('/grants','POST',{targetId:el('target').value, capabilities:['JVM_OVERVIEW'],
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
    if (task && !terminal(task.state)) renderTask(await api('/tasks/'+path(task.taskId)));
  } catch (e) { el('message').textContent = e.message; }
  if (session?.sessionId === id) timer = setTimeout(() => monitor(id), 3000);
}
action('open', async () => {
  if (session) throw Error('请先关闭当前会话');
  const g = grants.find(g => g.grantId === el('grant').value);
  if (!g || g.state !== 'GRANTED') throw Error('请选择已批准的授权');
  session = await api('/sessions','POST',{targetId:g.targetId,grantId:g.grantId});
  show('workspace',true); await monitor(session.sessionId);
});
action('sample', async () => {
  if (task && !terminal(task.state)) throw Error('当前任务仍在执行');
  pendingKey ||= crypto.randomUUID();
  renderTask(await api(sessionUrl()+'/tasks','POST',{capability:'JVM_OVERVIEW'},pendingKey));
  pendingKey = null;
});
action('cancel', async () => {
  if (!task) throw Error('当前无任务');
  renderTask(await api('/tasks/'+path(task.taskId)+'/cancel','POST'));
});
action('close', async () => {
  await api(sessionUrl(),'DELETE'); clearTimeout(timer); session = task = pendingKey = null;
  el('metrics').replaceChildren(); show('workspace',false); record('会话已关闭');
});
action('logout', async () => {
  try { if (session) await api(sessionUrl(),'DELETE'); }
  finally { ++epoch; token = ''; clearTimeout(timer); location.reload(); }
});
