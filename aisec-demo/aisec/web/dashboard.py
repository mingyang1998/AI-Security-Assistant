"""AISOC Web 控制台（单页面应用）。

嵌入到 soc-agent 的 FastAPI 应用中，提供：
- Agent 列表与状态
- 实时事件流
- 告警列表
- Skill/MCP 扫描
- 自然语言 Chat
"""
from __future__ import annotations

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AISOC - AI安全运营中心</title>
<style>
:root {
  --bg: #0f1117; --surface: #1a1d27; --surface2: #242836;
  --border: #2e3348; --text: #e4e6f0; --text2: #8b8fa3;
  --primary: #6c5ce7; --primary2: #a29bfe;
  --success: #00b894; --warning: #fdcb6e; --danger: #e17055; --info: #74b9ff;
  --radius: 8px;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }

/* Layout */
.app { display: flex; height: 100vh; }
.sidebar { width: 220px; background: var(--surface); border-right: 1px solid var(--border); display: flex; flex-direction: column; }
.sidebar-logo { padding: 20px 16px; font-size: 18px; font-weight: 700; color: var(--primary2); border-bottom: 1px solid var(--border); }
.sidebar-logo small { display: block; font-size: 11px; color: var(--text2); font-weight: 400; margin-top: 4px; }
.nav { flex: 1; padding: 12px 8px; }
.nav-item { display: flex; align-items: center; gap: 10px; padding: 10px 12px; border-radius: var(--radius); cursor: pointer; color: var(--text2); font-size: 14px; transition: all .15s; margin-bottom: 2px; }
.nav-item:hover { background: var(--surface2); color: var(--text); }
.nav-item.active { background: var(--primary); color: #fff; }
.nav-item .icon { font-size: 16px; width: 20px; text-align: center; }
.main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
.header { padding: 16px 24px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
.header h1 { font-size: 16px; font-weight: 600; }
.header .status-badge { font-size: 12px; padding: 4px 10px; border-radius: 12px; background: rgba(0,184,148,.15); color: var(--success); }
.content { flex: 1; overflow-y: auto; padding: 24px; }

/* Cards */
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-bottom: 24px; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; }
.card-title { font-size: 12px; color: var(--text2); text-transform: uppercase; letter-spacing: .5px; margin-bottom: 8px; }
.card-value { font-size: 28px; font-weight: 700; }
.card-value.success { color: var(--success); }
.card-value.warning { color: var(--warning); }
.card-value.danger { color: var(--danger); }
.card-value.info { color: var(--info); }

/* Tables */
.table-wrap { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow: hidden; }
.table-header { padding: 16px 20px; border-bottom: 1px solid var(--border); display: flex; align-items: center; justify-content: space-between; }
.table-header h3 { font-size: 14px; font-weight: 600; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; padding: 10px 16px; font-size: 12px; color: var(--text2); text-transform: uppercase; letter-spacing: .5px; border-bottom: 1px solid var(--border); background: var(--surface2); }
td { padding: 10px 16px; font-size: 13px; border-bottom: 1px solid var(--border); }
tr:last-child td { border-bottom: none; }
tr:hover td { background: rgba(108,92,231,.05); }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; }
.badge-online { background: rgba(0,184,148,.15); color: var(--success); }
.badge-offline { background: rgba(225,112,85,.15); color: var(--danger); }
.badge-safe { background: rgba(0,184,148,.15); color: var(--success); }
.badge-suspicious { background: rgba(253,203,110,.15); color: var(--warning); }
.badge-dangerous { background: rgba(225,112,85,.15); color: var(--danger); }
.badge-allow { background: rgba(0,184,148,.15); color: var(--success); }
.badge-deny { background: rgba(225,112,85,.15); color: var(--danger); }
.badge-rate_limit { background: rgba(253,203,110,.15); color: var(--warning); }
.badge-soc_approval { background: rgba(116,185,255,.15); color: var(--info); }

/* Event log */
.event-log { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); max-height: 400px; overflow-y: auto; font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 12px; }
.event-item { padding: 8px 16px; border-bottom: 1px solid var(--border); display: flex; gap: 12px; }
.event-item:last-child { border-bottom: none; }
.event-time { color: var(--text2); white-space: nowrap; min-width: 70px; }
.event-type { font-weight: 600; min-width: 140px; }
.event-type.agent_registered { color: var(--success); }
.event-type.agent_offline { color: var(--danger); }
.event-type.shadow_agent_detected { color: var(--warning); }
.event-type.request_blocked { color: var(--danger); }
.event-type.request_proxied { color: var(--info); }
.event-type.chat { color: var(--primary2); }
.event-type.scan_skill { color: var(--warning); }
.event-payload { color: var(--text2); flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

/* Chat */
.chat-container { display: flex; flex-direction: column; height: calc(100vh - 140px); }
.chat-messages { flex: 1; overflow-y: auto; padding: 16px 0; }
.chat-msg { margin-bottom: 16px; }
.chat-msg.user { text-align: right; }
.chat-msg .bubble { display: inline-block; max-width: 70%; padding: 10px 14px; border-radius: 12px; font-size: 13px; line-height: 1.5; text-align: left; }
.chat-msg.user .bubble { background: var(--primary); color: #fff; border-bottom-right-radius: 4px; }
.chat-msg.assistant .bubble { background: var(--surface2); color: var(--text); border-bottom-left-radius: 4px; }
.chat-msg .meta { font-size: 11px; color: var(--text2); margin-top: 4px; }
.chat-input-wrap { display: flex; gap: 8px; padding-top: 16px; border-top: 1px solid var(--border); }
.chat-input { flex: 1; padding: 10px 14px; border-radius: var(--radius); border: 1px solid var(--border); background: var(--surface2); color: var(--text); font-size: 14px; outline: none; }
.chat-input:focus { border-color: var(--primary); }
.chat-send { padding: 10px 20px; border-radius: var(--radius); border: none; background: var(--primary); color: #fff; font-size: 14px; cursor: pointer; }
.chat-send:hover { background: var(--primary2); }
.chat-send:disabled { opacity: .5; cursor: not-allowed; }

/* Scan */
.scan-form { display: flex; gap: 8px; margin-bottom: 16px; }
.scan-input { flex: 1; padding: 10px 14px; border-radius: var(--radius); border: 1px solid var(--border); background: var(--surface2); color: var(--text); font-size: 14px; outline: none; }
.scan-input:focus { border-color: var(--primary); }
.scan-btn { padding: 10px 20px; border-radius: var(--radius); border: none; background: var(--primary); color: #fff; font-size: 14px; cursor: pointer; }
.scan-btn:hover { background: var(--primary2); }
.scan-result { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 20px; }
.scan-result pre { white-space: pre-wrap; word-break: break-all; font-size: 12px; color: var(--text2); }

/* Section visibility */
.section { display: none; }
.section.active { display: block; }

/* Scrollbar */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: var(--text2); }

/* Refresh spinner */
.spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid var(--border); border-top-color: var(--primary); border-radius: 50%; animation: spin .6s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
</style>
</head>
<body>
<div class="app">
  <!-- Sidebar -->
  <div class="sidebar">
    <div class="sidebar-logo">AISOC<small>AI安全运营中心 v0.4</small></div>
    <div class="nav">
      <div class="nav-item active" data-section="dashboard"><span class="icon">&#9632;</span> 仪表盘</div>
      <div class="nav-item" data-section="agents"><span class="icon">&#9654;</span> Agent 列表</div>
      <div class="nav-item" data-section="events"><span class="icon">&#9881;</span> 事件审计</div>
      <div class="nav-item" data-section="scan"><span class="icon">&#128269;</span> 安全扫描</div>
      <div class="nav-item" data-section="msp"><span class="icon">&#128737;</span> 模型安全</div>
      <div class="nav-item" data-section="trust"><span class="icon">&#9989;</span> 信任评分</div>
      <div class="nav-item" data-section="chat"><span class="icon">&#128172;</span> 智能对话</div>
    </div>
  </div>

  <!-- Main -->
  <div class="main">
    <div class="header">
      <h1 id="page-title">仪表盘</h1>
      <span class="status-badge" id="conn-status">已连接</span>
    </div>
    <div class="content">
      <!-- Dashboard -->
      <div class="section active" id="sec-dashboard">
        <div class="grid">
          <div class="card"><div class="card-title">在线 Agent</div><div class="card-value success" id="stat-agents">-</div></div>
          <div class="card"><div class="card-title">今日事件</div><div class="card-value info" id="stat-events">-</div></div>
          <div class="card"><div class="card-title">拦截请求</div><div class="card-value warning" id="stat-blocked">-</div></div>
          <div class="card"><div class="card-title">影子 Agent</div><div class="card-value danger" id="stat-shadow">-</div></div>
        </div>
        <div class="table-wrap">
          <div class="table-header"><h3>最近事件</h3><button onclick="loadEvents()" style="background:none;border:1px solid var(--border);color:var(--text2);padding:4px 10px;border-radius:4px;cursor:pointer;font-size:12px">刷新</button></div>
          <div class="event-log" id="dash-events"><div style="padding:20px;color:var(--text2);text-align:center">加载中...</div></div>
        </div>
      </div>

      <!-- Agents -->
      <div class="section" id="sec-agents">
        <div class="table-wrap">
          <div class="table-header"><h3>已注册 Agent</h3><button onclick="loadAgents()" style="background:none;border:1px solid var(--border);color:var(--text2);padding:4px 10px;border-radius:4px;cursor:pointer;font-size:12px">刷新</button></div>
          <table><thead><tr><th>Agent ID</th><th>名称</th><th>角色</th><th>信任分</th><th>状态</th><th>最后心跳</th></tr></thead>
          <tbody id="agent-table"><tr><td colspan="6" style="text-align:center;color:var(--text2)">加载中...</td></tr></tbody></table>
        </div>
      </div>

      <!-- Events -->
      <div class="section" id="sec-events">
        <div class="table-wrap">
          <div class="table-header"><h3>审计事件流</h3><div><select id="event-filter" onchange="loadEvents()" style="background:var(--surface2);color:var(--text);border:1px solid var(--border);padding:4px 8px;border-radius:4px;font-size:12px"><option value="">全部</option><option value="agent_registered">注册</option><option value="agent_offline">离线</option><option value="shadow_agent_detected">影子Agent</option><option value="request_blocked">拦截</option><option value="request_proxied">代理</option><option value="chat">对话</option></select> <button onclick="loadEvents()" style="background:none;border:1px solid var(--border);color:var(--text2);padding:4px 10px;border-radius:4px;cursor:pointer;font-size:12px">刷新</button></div></div>
          <div class="event-log" id="event-log" style="max-height:600px"><div style="padding:20px;color:var(--text2);text-align:center">加载中...</div></div>
        </div>
      </div>

      <!-- Scan -->
      <div class="section" id="sec-scan">
        <h3 style="margin-bottom:16px;font-size:15px">Skill / MCP 安全扫描</h3>
        <div class="scan-form">
          <input class="scan-input" id="scan-path" placeholder="输入文件路径，如 examples/suspicious_skill.py" value="examples/suspicious_skill.py">
          <select id="scan-type" style="background:var(--surface2);color:var(--text);border:1px solid var(--border);padding:10px;border-radius:var(--radius);font-size:14px">
            <option value="skill">Skill 扫描</option>
            <option value="mcp">MCP 扫描</option>
          </select>
          <button class="scan-btn" onclick="runScan()">扫描</button>
        </div>
        <div class="scan-result" id="scan-result" style="display:none"></div>
      </div>

      <!-- MSP 模型安全 -->
      <div class="section" id="sec-msp">
        <div class="grid">
          <div class="card"><div class="card-title">熔断状态</div><div class="card-value" id="msp-breaker-status">-</div></div>
          <div class="card"><div class="card-title">熔断模型</div><div class="card-value" id="msp-breaker-model" style="font-size:16px">-</div></div>
          <div class="card"><div class="card-title">熔断原因</div><div class="card-value" id="msp-breaker-reason" style="font-size:14px">-</div></div>
        </div>
        <div style="margin-bottom:16px">
          <button class="scan-btn" onclick="resetBreaker()" style="background:var(--danger)">重置熔断</button>
          <button class="scan-btn" onclick="loadMsp()" style="margin-left:8px">刷新</button>
        </div>
        <div class="table-wrap">
          <div class="table-header"><h3>黑白名单</h3></div>
          <table><thead><tr><th>类型</th><th>SHA256</th><th>来源</th></tr></thead>
          <tbody id="msp-lists"><tr><td colspan="3" style="text-align:center;color:var(--text2)">加载中...</td></tr></tbody></table>
        </div>
      </div>

      <!-- Trust 信任评分 -->
      <div class="section" id="sec-trust">
        <div class="table-wrap">
          <div class="table-header"><h3>动态信任评分</h3><button onclick="loadTrust()" style="background:none;border:1px solid var(--border);color:var(--text2);padding:4px 10px;border-radius:4px;cursor:pointer;font-size:12px">刷新</button></div>
          <table><thead><tr><th>Agent ID</th><th>名称</th><th>信任分</th><th>信任等级</th><th>状态</th></tr></thead>
          <tbody id="trust-table"><tr><td colspan="5" style="text-align:center;color:var(--text2)">加载中...</td></tr></tbody></table>
        </div>
        <div class="table-wrap" style="margin-top:16px">
          <div class="table-header"><h3>告警列表</h3><button onclick="loadAlerts()" style="background:none;border:1px solid var(--border);color:var(--text2);padding:4px 10px;border-radius:4px;cursor:pointer;font-size:12px">刷新</button></div>
          <table><thead><tr><th>告警文件</th><th>操作</th></tr></thead>
          <tbody id="alerts-table"><tr><td colspan="2" style="text-align:center;color:var(--text2)">加载中...</td></tr></tbody></table>
        </div>
      </div>

      <!-- Chat -->
      <div class="section" id="sec-chat">
        <div class="chat-container">
          <div class="chat-messages" id="chat-messages">
            <div class="chat-msg assistant"><div class="bubble">你好！我是 AISOC 安全运营助手。你可以问我关于 Agent 状态、安全事件、扫描结果等问题。</div></div>
          </div>
          <div class="chat-input-wrap">
            <input class="chat-input" id="chat-input" placeholder="输入问题，如：当前有哪些影子Agent？" onkeydown="if(event.key==='Enter')sendChat()">
            <button class="chat-send" id="chat-send" onclick="sendChat()">发送</button>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
const BASE = location.origin;
let autoRefreshId = null;

// --- Navigation ---
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', () => {
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    item.classList.add('active');
    const sec = item.dataset.section;
    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    document.getElementById('sec-' + sec).classList.add('active');
    const titles = {dashboard:'仪表盘',agents:'Agent 列表',events:'事件审计',scan:'安全扫描',msp:'模型安全',trust:'信任评分',chat:'智能对话'};
    document.getElementById('page-title').textContent = titles[sec] || sec;
    if (sec === 'dashboard') { loadDashboard(); }
    if (sec === 'agents') { loadAgents(); }
    if (sec === 'events') { loadEvents(); }
    if (sec === 'msp') { loadMsp(); }
    if (sec === 'trust') { loadTrust(); }
  });
});

// --- API helpers ---
async function api(path, opts = {}) {
  try {
    const r = await fetch(BASE + path, {headers: {'Content-Type': 'application/json'}, ...opts});
    return await r.json();
  } catch(e) {
    console.error('API error:', e);
    return null;
  }
}

// --- Dashboard ---
async function loadDashboard() {
  const [agents, events] = await Promise.all([api('/registry/agents'), api('/events?limit=50')]);
  if (!agents || !events) return;

  const online = agents.filter(a => a.status === 'online').length;
  document.getElementById('stat-agents').textContent = online;

  const evts = events.events || [];
  document.getElementById('stat-events').textContent = evts.length;
  document.getElementById('stat-blocked').textContent = evts.filter(e => e.type === 'request_blocked').length;
  document.getElementById('stat-shadow').textContent = evts.filter(e => e.type === 'shadow_agent_detected').length;

  renderEventLog('dash-events', evts.slice(0, 20));
}

// --- Agents ---
async function loadAgents() {
  const agents = await api('/registry/agents');
  if (!agents) return;
  const tbody = document.getElementById('agent-table');
  if (!agents.length) { tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text2)">暂无注册 Agent</td></tr>'; return; }
  tbody.innerHTML = agents.map(a => `<tr>
    <td style="font-family:monospace">${esc(a.agent_id)}</td>
    <td>${esc(a.name || '')}</td>
    <td>${esc(a.role || '')}</td>
    <td>${a.trust_score ?? '-'}</td>
    <td><span class="badge badge-${a.status || 'offline'}">${a.status || 'unknown'}</span></td>
    <td style="font-size:12px;color:var(--text2)">${a.last_heartbeat ? new Date(a.last_heartbeat * 1000).toLocaleTimeString() : '-'}</td>
  </tr>`).join('');
}

// --- Events ---
async function loadEvents() {
  const filter = document.getElementById('event-filter')?.value || '';
  const data = await api('/events?limit=200');
  if (!data) return;
  let evts = data.events || [];
  if (filter) evts = evts.filter(e => e.type === filter);
  renderEventLog('event-log', evts);
}

function renderEventLog(containerId, evts) {
  const el = document.getElementById(containerId);
  if (!evts.length) { el.innerHTML = '<div style="padding:20px;color:var(--text2);text-align:center">暂无事件</div>'; return; }
  el.innerHTML = evts.map(e => {
    const t = e.ts ? new Date(e.ts * 1000).toLocaleTimeString() : '';
    const p = e.payload ? JSON.stringify(e.payload).substring(0, 120) : '';
    return `<div class="event-item">
      <span class="event-time">${t}</span>
      <span class="event-type ${e.type}">${e.type}</span>
      <span class="event-payload">${esc(p)}</span>
    </div>`;
  }).join('');
}

// --- MSP 模型安全 ---
async function loadMsp() {
  const [breaker, wl, bl] = await Promise.all([
    api('/model-breaker'),
    api('/whitelist'),
    api('/blacklist'),
  ]);
  // 熔断状态
  const tripped = breaker?.tripped;
  const statusEl = document.getElementById('msp-breaker-status');
  const modelEl = document.getElementById('msp-breaker-model');
  const reasonEl = document.getElementById('msp-breaker-reason');
  if (tripped) {
    statusEl.textContent = '已熔断';
    statusEl.className = 'card-value danger';
    modelEl.textContent = breaker.model || '-';
    reasonEl.textContent = breaker.reason || '-';
  } else {
    statusEl.textContent = '正常';
    statusEl.className = 'card-value success';
    modelEl.textContent = '-';
    reasonEl.textContent = '-';
  }
  // 黑白名单
  const tbody = document.getElementById('msp-lists');
  const wlItems = (wl?.items || []).map(i => `<tr><td><span class="badge badge-safe">白名单</span></td><td style="font-family:monospace;font-size:11px">${esc(i.sha256 || i)}</td><td>${esc(i.source || i.path || '-')}</td></tr>`);
  const blItems = (bl?.items || []).map(i => `<tr><td><span class="badge badge-dangerous">黑名单</span></td><td style="font-family:monospace;font-size:11px">${esc(i.sha256 || i)}</td><td>${esc(i.source || i.path || '-')}</td></tr>`);
  const all = [...wlItems, ...blItems];
  tbody.innerHTML = all.length ? all.join('') : '<tr><td colspan="3" style="text-align:center;color:var(--text2)">暂无记录</td></tr>';
}

async function resetBreaker() {
  if (!confirm('确认重置模型熔断器？这将恢复模型服务。')) return;
  const data = await api('/model-breaker/reset', {method: 'POST'});
  if (data?.ok) { alert('熔断已重置'); loadMsp(); }
  else { alert('重置失败: ' + (data?.error || 'unknown')); }
}

// --- Trust 信任评分 ---
async function loadTrust() {
  const [trustData, alertsData] = await Promise.all([api('/trust'), api('/alerts')]);
  // 信任评分表
  const tbody = document.getElementById('trust-table');
  const agents = trustData?.agents || [];
  if (!agents.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text2)">暂无数据</td></tr>';
  } else {
    tbody.innerHTML = agents.map(a => {
      const level = a.trust_level || 'unknown';
      const levelClass = level === 'trusted' ? 'safe' : level === 'suspicious' ? 'suspicious' : 'dangerous';
      return `<tr>
        <td style="font-family:monospace">${esc(a.agent_id)}</td>
        <td>${esc(a.name || '')}</td>
        <td>${a.trust_score ?? '-'}</td>
        <td><span class="badge badge-${levelClass}">${level}</span></td>
        <td><span class="badge badge-${a.status || 'offline'}">${a.status || 'unknown'}</span></td>
      </tr>`;
    }).join('');
  }
  // 告警列表
  const atbody = document.getElementById('alerts-table');
  const alerts = alertsData?.items || [];
  if (!alerts.length) {
    atbody.innerHTML = '<tr><td colspan="2" style="text-align:center;color:var(--text2)">暂无告警</td></tr>';
  } else {
    atbody.innerHTML = alerts.map(a => `<tr>
      <td style="font-family:monospace;font-size:12px">${esc(a)}</td>
      <td><a href="#" onclick="viewAlert('${esc(a)}');return false" style="color:var(--primary2)">查看</a></td>
    </tr>`).join('');
  }
}

async function viewAlert(filename) {
  const data = await api('/alerts/' + encodeURIComponent(filename));
  if (!data) { alert('加载失败'); return; }
  const w = window.open('', '_blank');
  w.document.write('<pre style="font-family:monospace;font-size:13px;padding:20px;background:#1a1d27;color:#e4e6f0;white-space:pre-wrap">' + esc(typeof data === 'string' ? data : JSON.stringify(data, null, 2)) + '</pre>');
}

// --- Scan ---
async function runScan() {
  const path = document.getElementById('scan-path').value.trim();
  const type = document.getElementById('scan-type').value;
  if (!path) return;
  const resultEl = document.getElementById('scan-result');
  resultEl.style.display = 'block';
  resultEl.innerHTML = '<div style="text-align:center;padding:20px"><div class="spinner"></div> 扫描中...</div>';
  const data = await api(`/tools/scan_${type}`, {method: 'POST', body: JSON.stringify({args: {path}})});
  if (!data || !data.ok) { resultEl.innerHTML = '<div style="color:var(--danger)">扫描失败: ' + esc(data?.error || 'unknown') + '</div>'; return; }
  const r = data.result;
  const risk = r.risk || {};
  const level = risk.level || 'unknown';
  const score = risk.score ?? '-';
  resultEl.innerHTML = `
    <div style="display:flex;gap:16px;align-items:center;margin-bottom:16px">
      <div><strong>风险等级</strong><br><span class="badge badge-${level}" style="font-size:14px;padding:4px 12px">${level.toUpperCase()}</span></div>
      <div><strong>综合评分</strong><br><span style="font-size:24px;font-weight:700;color:${level==='safe'?'var(--success)':level==='suspicious'?'var(--warning)':'var(--danger)'}">${score}</span></div>
      <div><strong>文件</strong><br><code>${esc(r.path || path)}</code></div>
      <div><strong>SHA256</strong><br><code style="font-size:11px">${esc(r.sha256 || '-')}</code></div>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:16px">
      <div style="background:var(--surface2);padding:12px;border-radius:var(--radius)"><strong>静态分析</strong><br>分数: ${r.static?.score ?? '-'}<br><small>${esc((r.static?.reasons||[]).join('; '))}</small></div>
      <div style="background:var(--surface2);padding:12px;border-radius:var(--radius)"><strong>语义分析</strong><br>分数: ${r.semantic?.score ?? '-'}<br><small>${esc(r.semantic?.reason || '-')}</small></div>
      <div style="background:var(--surface2);padding:12px;border-radius:var(--radius)"><strong>行为分析</strong><br>分数: ${r.behavior?.score ?? '-'}<br><small>${esc((r.behavior?.reasons||[]).join('; '))}</small></div>
    </div>
    <details><summary style="cursor:pointer;color:var(--primary2)">原始 JSON</summary><pre>${esc(JSON.stringify(r, null, 2))}</pre></details>`;
}

// --- Chat ---
async function sendChat() {
  const input = document.getElementById('chat-input');
  const query = input.value.trim();
  if (!query) return;
  input.value = '';
  appendChat('user', query);
  const sendBtn = document.getElementById('chat-send');
  sendBtn.disabled = true;
  sendBtn.textContent = '思考中...';
  const data = await api('/chat', {method: 'POST', body: JSON.stringify({query})});
  sendBtn.disabled = false;
  sendBtn.textContent = '发送';
  const reply = data?.reply || data?.error || '无响应';
  const mock = data?.mock_mode ? ' [Mock模式]' : '';
  appendChat('assistant', reply + mock);
}

function appendChat(role, text) {
  const container = document.getElementById('chat-messages');
  const div = document.createElement('div');
  div.className = 'chat-msg ' + role;
  div.innerHTML = `<div class="bubble">${esc(text)}</div><div class="meta">${role === 'user' ? '你' : 'SOC Agent'} · ${new Date().toLocaleTimeString()}</div>`;
  container.appendChild(div);
  container.scrollTop = container.scrollHeight;
}

// --- Utils ---
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

// --- Auto refresh ---
function startAutoRefresh() {
  loadDashboard();
  autoRefreshId = setInterval(() => {
    const active = document.querySelector('.section.active');
    if (active?.id === 'sec-dashboard') loadDashboard();
  }, 10000);
}

startAutoRefresh();
</script>
</body>
</html>"""
