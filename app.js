'use strict';
/* ═══════════════════════════════════════════════════════════════
   STATE
═══════════════════════════════════════════════════════════════ */
let authToken   = null;
let currentUser = null;
let feedCount   = 0;

// In-memory mock stores (so add/delete actually works within session)
const mockDB = {
  threats: [
    { id:1, timestamp:new Date().toISOString(), ip_address:'192.168.1.100', event_type:'suspicious_login', severity:'HIGH',   threat_score:75, resolved:false },
    { id:2, timestamp:new Date().toISOString(), ip_address:'10.0.0.50',     event_type:'port_scan',        severity:'MEDIUM', threat_score:45, resolved:false },
    { id:3, timestamp:new Date(Date.now()-900000).toISOString(), ip_address:'203.0.113.42', event_type:'brute_force', severity:'HIGH', threat_score:82, resolved:true }
  ],
  firewall: [
    { id:1, rule_type:'ip_block',   value:'192.168.1.200', action:'block', hits:5,  description:'Blocked suspicious IP' },
    { id:2, rule_type:'user_agent', value:'bot*',          action:'block', hits:12, description:'Block bot traffic' }
  ],
  users: [
    { id:1, username:'admin',  role:'admin',  totp_enabled:true,  locked_until:null, fail_count:0, last_login:new Date().toISOString() },
    { id:2, username:'viewer', role:'viewer', totp_enabled:false, locked_until:null, fail_count:0, last_login:new Date().toISOString() }
  ],
  sessions: [
    { id:'sess-abc123def456', user_id:1, username:'admin',  ip_address:'127.0.0.1', device_fp:'Chrome/Windows', created_at:new Date().toISOString(), expires_at:new Date(Date.now()+21600000).toISOString(), revoked:false },
    { id:'sess-def789ghi012', user_id:2, username:'viewer', ip_address:'127.0.0.1', device_fp:'Firefox/Mac',    created_at:new Date().toISOString(), expires_at:new Date(Date.now()+21600000).toISOString(), revoked:false }
  ],
  audit: [
    { id:1, timestamp:new Date().toISOString(),              action:'login',         username:'admin',  ip_address:'127.0.0.1', result:'success', resource:'auth' },
    { id:2, timestamp:new Date(Date.now()-60000).toISOString(), action:'device_toggle', username:'admin',  ip_address:'127.0.0.1', result:'success', resource:'living_room/lights' },
    { id:3, timestamp:new Date(Date.now()-120000).toISOString(), action:'login',        username:'viewer', ip_address:'127.0.0.1', result:'success', resource:'auth' }
  ],
  vault: {},
  nextId: 100
};

/* ═══════════════════════════════════════════════════════════════
   CLOCK
═══════════════════════════════════════════════════════════════ */
function updateClock() {
  const time = new Date().toLocaleTimeString("en-GB", {
    timeZone: "Asia/Phnom_Penh",
    hour12: false
  });

  document.getElementById("clock").textContent = time;
}

setInterval(updateClock, 1000);
updateClock();

/* ═══════════════════════════════════════════════════════════════
   LOGIN
═══════════════════════════════════════════════════════════════ */
async function doLogin() {
  const username = document.getElementById('login-user').value.trim();
  const password = document.getElementById('login-pass').value;
  const totp     = document.getElementById('login-totp').value.trim();
  const errEl    = document.getElementById('login-error');
  const btn      = document.getElementById('login-btn');

  errEl.style.display = 'none';
  btn.textContent = 'AUTHENTICATING...';
  btn.disabled = true;

  await delay(600);

  // Validate credentials
  const valid =
    (username === 'admin'  && password === 'Admin@1234') ||
    (username === 'viewer' && password === 'View@5678');

  if (!valid) {
    showLoginErr('Invalid credentials. Try admin/Admin@1234 or viewer/View@5678');
    btn.textContent = 'AUTHENTICATE →';
    btn.disabled = false;
    return;
  }

  // FIX: TOTP check — only validate if the TOTP field is visible AND the user typed something
  const totpVisible = document.getElementById('totp-field').style.display !== 'none';
  if (totpVisible) {
    if (!totp) {
      showLoginErr('TOTP code is required.');
      btn.textContent = 'AUTHENTICATE →';
      btn.disabled = false;
      return;
    }
    if (totp !== '123456') {
      showLoginErr('Invalid TOTP code. Use 123456 for demo.');
      btn.textContent = 'AUTHENTICATE →';
      btn.disabled = false;
      return;
    }
  }

  // Success
  authToken   = 'mock_token_' + Date.now();
  currentUser = { username, role: username === 'admin' ? 'admin' : 'viewer', sub: username === 'admin' ? 1 : 2 };

  document.getElementById('login-overlay').style.display = 'none';
  addFeedEvent('info', 'AUTH_SUCCESS', `Login: ${username}`, '127.0.0.1');
  loadDashboard();
  setInterval(loadDashboard, 30000);
  toast(`Welcome, ${username}! Session established.`, 'green');
}

function showLoginErr(msg) {
  const el = document.getElementById('login-error');
  el.textContent = msg;
  el.style.display = 'block';
}

document.addEventListener('keydown', e => {
  if (e.key === 'Enter') {
    const overlay = document.getElementById('login-overlay');
    if (overlay && overlay.style.display !== 'none') doLogin();
  }
});

/* ═══════════════════════════════════════════════════════════════
   MOCK API — operates on mockDB in memory
═══════════════════════════════════════════════════════════════ */
async function api(path, opts = {}) {
  await delay(150);
  const method = (opts.method || 'GET').toUpperCase();
  const body   = opts.body || {};

  // ── Dashboard
  if (path.includes('/dashboard')) {
    const unresolved = mockDB.threats.filter(t => !t.resolved).length;
    const critical   = mockDB.threats.filter(t => !t.resolved && t.severity === 'HIGH').length;
    return {
      threats: { unresolved, total: mockDB.threats.length, critical, recent: mockDB.threats.slice(-3).reverse() },
      firewall_blocks: mockDB.firewall.reduce((s,r) => s + r.hits, 0),
      active_sessions: mockDB.sessions.filter(s => !s.revoked).length,
      user_count: mockDB.users.length,
      audit_count: mockDB.audit.length,
      recent_audit: mockDB.audit.slice(-5).reverse(),
      threat_by_type: Object.entries(
        mockDB.threats.reduce((acc, t) => { acc[t.event_type] = (acc[t.event_type]||0)+1; return acc; }, {})
      ).map(([event_type, count]) => ({ event_type, count }))
    };
  }

  // ── Threats
  if (path.match(/\/threats\/(\d+)\/resolve/) && method === 'POST') {
    const id = parseInt(path.match(/\/threats\/(\d+)/)[1]);
    const t  = mockDB.threats.find(x => x.id === id);
    if (t) { t.resolved = true; addAuditEntry('threat_resolve', `threat #${id}`); }
    return { success:true };
  }
  if (path.includes('/threats')) {
    return { recent: [...mockDB.threats].reverse() };
  }

  // ── Firewall
  if (path.match(/\/firewall\/(\d+)/) && method === 'DELETE') {
    const id = parseInt(path.match(/\/firewall\/(\d+)/)[1]);
    const idx = mockDB.firewall.findIndex(r => r.id === id);
    if (idx > -1) { mockDB.firewall.splice(idx, 1); addAuditEntry('fw_rule_delete', `rule #${id}`); }
    return { success:true };
  }
  if (path.includes('/firewall') && method === 'POST') {
    const rule = { id: ++mockDB.nextId, rule_type:body.rule_type, value:body.value, action:body.action, hits:0, description:body.description||'' };
    mockDB.firewall.push(rule);
    addAuditEntry('fw_rule_add', `${body.action} ${body.value}`);
    return rule;
  }
  if (path.includes('/firewall')) {
    return [...mockDB.firewall];
  }

  // ── Users
  if (path.match(/\/users\/(\d+)\/unlock/) && method === 'POST') {
    const id = parseInt(path.match(/\/users\/(\d+)/)[1]);
    const u  = mockDB.users.find(x => x.id === id);
    if (u) { u.locked_until = null; u.fail_count = 0; addAuditEntry('user_unlock', `user #${id}`); }
    return { success:true };
  }
  if (path.includes('/users') && method === 'POST') {
    if (mockDB.users.find(u => u.username === body.username)) return { error: 'Username already exists' };
    const u = { id: ++mockDB.nextId, username:body.username, role:body.role, totp_enabled:false, locked_until:null, fail_count:0, last_login:null };
    mockDB.users.push(u);
    addAuditEntry('user_create', body.username);
    return u;
  }
  if (path.includes('/users')) {
    return [...mockDB.users];
  }

  // ── Sessions
  if (path.match(/\/sessions\/(.+)\/revoke/) && method === 'POST') {
    const id = path.match(/\/sessions\/(.+)\/revoke/)[1];
    const s  = mockDB.sessions.find(x => x.id === id);
    if (s) { s.revoked = true; addAuditEntry('session_revoke', id.slice(0,12)); }
    return { success:true };
  }
  if (path.includes('/sessions')) {
    return mockDB.sessions.filter(s => !s.revoked);
  }

  // ── Audit verify (mock hash chain)
  if (path.includes('/audit/verify')) {
    return { valid:true, entries: mockDB.audit.length };
  }

  // ── Audit
  if (path.includes('/audit')) {
    return { entries:[...mockDB.audit].reverse(), total: mockDB.audit.length };
  }

  // ── Vault
  if (path.includes('/vault') && method === 'POST') {
    mockDB.vault[body.key] = body.value;
    addAuditEntry('vault_write', body.key);
    return { success:true };
  }
  if (path.match(/\/vault\/(.+)/) && method === 'GET') {
    const key = path.match(/\/vault\/(.+)/)[1];
    return mockDB.vault[key] ? { key, value: mockDB.vault[key] } : { error:'Key not found' };
  }

  return { success:true };
}

/* Helpers */
function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

function addAuditEntry(action, resource) {
  mockDB.audit.push({
    id: ++mockDB.nextId,
    timestamp: new Date().toISOString(),
    action, resource,
    username: currentUser ? currentUser.username : 'system',
    ip_address: '127.0.0.1',
    result: 'success'
  });
}

/* ═══════════════════════════════════════════════════════════════
   DASHBOARD
═══════════════════════════════════════════════════════════════ */
async function loadDashboard() {
  try {
    const d = await api('/api/security/dashboard');

    set('h-threats',  d.threats.unresolved);
    set('h-blocked',  d.firewall_blocks);
    set('h-sessions', d.active_sessions);
    set('h-users',    d.user_count);
    set('s-threats',  d.threats.unresolved);
    set('s-blocked',  d.firewall_blocks);
    set('s-sessions', d.active_sessions);
    set('s-audit',    d.audit_count);
    set('nav-threat-count', d.threats.unresolved);

    // Threat meter
    const score = Math.min(d.threats.critical * 25 + d.threats.unresolved * 5, 100);
    const fill  = document.getElementById('threat-fill');
    const color = score > 70 ? 'var(--red)' : score > 40 ? 'var(--amber)' : 'var(--green)';
    fill.style.width      = score + '%';
    fill.style.background = color;
    styleEl('threat-level-val', color);
    set('threat-level-val', score);
    set('threat-text', score > 70 ? 'CRITICAL' : score > 40 ? 'ELEVATED' : score > 10 ? 'GUARDED' : 'NOMINAL');

    // Threat chart
    const chart = document.getElementById('threat-chart');
    if (d.threat_by_type.length) {
      const max = Math.max(...d.threat_by_type.map(t => t.count));
      const clr = { suspicious_login:'var(--red)', port_scan:'var(--amber)', brute_force:'var(--red)', scanner_detected:'var(--green-dim)', xss_attempt:'var(--blue)', path_traversal:'var(--blue)' };
      chart.innerHTML = d.threat_by_type.map(t => `
        <div class="h-bar-row">
          <div class="h-bar-label">${t.event_type.replace(/_/g,' ')}</div>
          <div class="h-bar-track">
            <div class="h-bar-fill" style="width:${(t.count/max*100).toFixed(1)}%; background:${clr[t.event_type]||'var(--green)'}; color:${clr[t.event_type]||'var(--green)'}"></div>
          </div>
          <div class="h-bar-val">${t.count}</div>
        </div>`).join('');
    } else {
      chart.innerHTML = '<div style="font-family:var(--mono);font-size:10px;color:var(--text-dim);padding:12px 0">No threat events recorded.</div>';
    }

    // Recent audit
    const tbody = document.getElementById('recent-audit-tbody');
    tbody.innerHTML = d.recent_audit.map(e => `
      <tr>
        <td>${e.timestamp.slice(11,19)}</td>
        <td style="color:var(--green)">${e.action}</td>
        <td>${e.username || '—'}</td>
        <td style="color:var(--text-dim)">${e.ip_address || '—'}</td>
        <td><span class="badge badge-${e.result === 'success' ? 'success' : 'fail'}">${e.result}</span></td>
      </tr>`).join('');

    ri();
  } catch(e) { console.error('Dashboard error:', e); }
}

/* ═══════════════════════════════════════════════════════════════
   NAVIGATION
═══════════════════════════════════════════════════════════════ */
function nav(page, el) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('page-' + page).classList.add('active');
  el.classList.add('active');

  const loaders = {
    threats:  loadThreats,
    firewall: loadFirewall,
    users:    loadUsers,
    sessions: loadSessions,
    audit:    loadAudit,
    rooms:    initRooms
  };
  if (loaders[page]) loaders[page]();
  ri();
}

function toggleForm(id) {
  const el = document.getElementById(id);
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
  ri();
}

/* ═══════════════════════════════════════════════════════════════
   THREATS
═══════════════════════════════════════════════════════════════ */
async function loadThreats() {
  const d = await api('/api/security/threats');
  const tbody = document.getElementById('threat-tbody');
  tbody.innerHTML = d.recent.map(t => `
    <tr>
      <td style="color:var(--text-dim)">${t.timestamp.slice(0,19).replace('T',' ')}</td>
      <td style="font-family:var(--mono);color:var(--amber)">${t.ip_address}</td>
      <td style="color:var(--text)">${t.event_type.replace(/_/g,' ')}</td>
      <td><span class="badge badge-${t.severity.toLowerCase()}">${t.severity}</span></td>
      <td style="font-family:var(--mono);color:${t.threat_score>70?'var(--red)':'var(--amber)'}">${t.threat_score}</td>
      <td>${t.resolved
        ? '<span style="color:var(--text-dim);font-size:10px;font-family:var(--mono)">RESOLVED</span>'
        : `<button class="btn btn-ghost" style="font-size:9px;padding:4px 10px" onclick="resolveT(${t.id})">Resolve</button>`
      }</td>
    </tr>`).join('') || '<tr><td colspan="6" style="color:var(--text-dim);text-align:center;padding:20px;font-family:var(--mono);font-size:10px">No threats detected</td></tr>';
  ri();
}

async function resolveT(id) {
  await api(`/api/security/threats/${id}/resolve`, { method:'POST' });
  toast('Threat resolved', 'green');
  addFeedEvent('info', 'THREAT_RESOLVED', `Event #${id}`, '—');
  loadThreats();
  loadDashboard();
}

/* ═══════════════════════════════════════════════════════════════
   FIREWALL
═══════════════════════════════════════════════════════════════ */
async function loadFirewall() {
  const rules = await api('/api/security/firewall');
  const tbody = document.getElementById('fw-tbody');
  tbody.innerHTML = rules.map(r => `
    <tr>
      <td style="color:var(--text-dim);font-family:var(--mono)">${r.id}</td>
      <td><span class="badge badge-${r.rule_type}">${r.rule_type.replace(/_/g,' ')}</span></td>
      <td style="font-family:var(--mono);font-size:10px">${r.value}</td>
      <td><span class="badge badge-${r.action}">${r.action.toUpperCase()}</span></td>
      <td style="font-family:var(--mono);color:var(--text-dim)">${r.hits}</td>
      <td style="color:var(--text-dim);font-size:11px">${r.description || '—'}</td>
      <td><button class="btn btn-red" style="font-size:9px;padding:4px 10px" onclick="deleteFWRule(${r.id})"><i data-lucide="trash-2"></i></button></td>
    </tr>`).join('') || '<tr><td colspan="7" style="color:var(--text-dim);text-align:center;padding:20px;font-family:var(--mono);font-size:10px">No rules defined</td></tr>';
  ri();
}

async function addFWRule() {
  const rule_type   = document.getElementById('fw-type').value;
  const value       = document.getElementById('fw-value').value.trim();
  const action      = document.getElementById('fw-action').value;
  const description = document.getElementById('fw-desc').value.trim();
  if (!value) { toast('Enter a value for the rule', 'red'); return; }
  await api('/api/security/firewall', { method:'POST', body:{rule_type, value, action, description} });
  toast('Rule added', 'green');
  addFeedEvent('info', 'FW_RULE_ADDED', `${action.toUpperCase()} ${value}`, '—');
  document.getElementById('add-rule-form').style.display = 'none';
  loadFirewall();
}

async function deleteFWRule(id) {
  await api(`/api/security/firewall/${id}`, { method:'DELETE' });
  toast('Rule deleted', 'amber');
  addFeedEvent('high', 'FW_RULE_REMOVED', `Rule #${id}`, '—');
  loadFirewall();
}

/* ═══════════════════════════════════════════════════════════════
   USERS
═══════════════════════════════════════════════════════════════ */
async function loadUsers() {
  const users = await api('/api/security/users');
  const tbody = document.getElementById('users-tbody');
  tbody.innerHTML = users.map(u => {
    const locked = u.locked_until && new Date(u.locked_until) > new Date();
    return `<tr>
      <td style="font-family:var(--mono)">${u.username}</td>
      <td><span class="badge badge-${u.role}">${u.role}</span></td>
      <td>${u.totp_enabled ? '<span style="color:var(--green);font-family:var(--mono);font-size:10px">✓ ON</span>' : '<span style="color:var(--text-dim);font-family:var(--mono);font-size:10px">OFF</span>'}</td>
      <td style="font-family:var(--mono);color:${u.fail_count>0?'var(--amber)':'var(--text-dim)'}">${u.fail_count}</td>
      <td><span class="badge ${locked?'badge-block':'badge-success'}">${locked?'LOCKED':'ACTIVE'}</span></td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--text-dim)">${u.last_login ? u.last_login.slice(0,16).replace('T',' ') : 'Never'}</td>
      <td>${locked ? `<button class="btn btn-ghost" style="font-size:9px;padding:4px 9px" onclick="unlockUser(${u.id})"><i data-lucide="lock-open"></i></button>` : '—'}</td>
    </tr>`;
  }).join('');
  ri();
}

// FIX: Password strength is now computed locally — no fetch() call
function checkPwStrength(pw) {
  const bar   = document.getElementById('pw-strength-bar');
  const fill  = document.getElementById('pw-strength-fill');
  const label = document.getElementById('pw-strength-label');
  if (!pw) { bar.style.display='none'; return; }
  bar.style.display = 'block';

  let score = 0;
  const issues = [];
  if (pw.length >= 8)  score += 25; else issues.push('Min 8 chars');
  if (/[A-Z]/.test(pw)) score += 25; else issues.push('Add uppercase');
  if (/[0-9]/.test(pw)) score += 25; else issues.push('Add a number');
  if (/[^A-Za-z0-9]/.test(pw)) score += 25; else issues.push('Add a symbol');

  const levels = { 25:'Weak', 50:'Fair', 75:'Strong', 100:'Excellent' };
  const colors = { Weak:'var(--red)', Fair:'var(--amber)', Strong:'var(--blue)', Excellent:'var(--green)' };
  const lbl    = levels[score] || 'Weak';
  fill.style.width      = score + '%';
  fill.style.background = colors[lbl];
  label.textContent     = lbl + (issues.length ? ' — ' + issues[0] : '');
  label.style.color     = colors[lbl];
}

async function addUser() {
  const username = document.getElementById('new-uname').value.trim();
  const password = document.getElementById('new-upass').value;
  const role     = document.getElementById('new-urole').value;
  if (!username || !password) { toast('Fill all fields', 'red'); return; }
  const res = await api('/api/security/users', { method:'POST', body:{username, password, role} });
  if (res.error) { toast(res.error, 'red'); return; }
  toast(`User "${username}" created`, 'green');
  addFeedEvent('info', 'USER_CREATED', username, '—');
  document.getElementById('add-user-form').style.display = 'none';
  document.getElementById('new-uname').value = '';
  document.getElementById('new-upass').value = '';
  document.getElementById('pw-strength-bar').style.display = 'none';
  loadUsers();
}

async function unlockUser(id) {
  await api(`/api/security/users/${id}/unlock`, { method:'POST' });
  toast('User unlocked', 'green');
  addFeedEvent('info', 'USER_UNLOCKED', `user #${id}`, '—');
  loadUsers();
}

/* ═══════════════════════════════════════════════════════════════
   SESSIONS
═══════════════════════════════════════════════════════════════ */
async function loadSessions() {
  const sessions = await api('/api/security/sessions');
  const tbody = document.getElementById('sessions-tbody');
  // FIX: s.id is a string, so slice is safe; was crashing before with numeric IDs
  tbody.innerHTML = sessions.map(s => `
    <tr>
      <td style="font-family:var(--mono);font-size:9px;color:var(--text-dim)">${String(s.id).slice(0,14)}…</td>
      <td style="font-family:var(--mono);color:var(--green)">${s.username}</td>
      <td style="font-family:var(--mono);color:var(--amber)">${s.ip_address || '—'}</td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--text-dim)">${s.created_at.slice(0,16).replace('T',' ')}</td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--text-dim)">${s.expires_at.slice(0,16).replace('T',' ')}</td>
      <td><button class="btn btn-red" style="font-size:9px;padding:4px 9px" onclick="revokeSession('${s.id}')"><i data-lucide="x"></i> Revoke</button></td>
    </tr>`).join('') || '<tr><td colspan="6" style="text-align:center;padding:20px;color:var(--text-dim);font-family:var(--mono);font-size:10px">No active sessions</td></tr>';
  ri();
}

async function revokeSession(id) {
  await api(`/api/security/sessions/${id}/revoke`, { method:'POST' });
  toast('Session revoked', 'red');
  addFeedEvent('critical', 'SESSION_REVOKED', String(id).slice(0,12), '—');
  loadSessions();
}

/* ═══════════════════════════════════════════════════════════════
   AUDIT
═══════════════════════════════════════════════════════════════ */
async function loadAudit() {
  const d = await api('/api/security/audit');
  const tbody = document.getElementById('audit-tbody');
  tbody.innerHTML = d.entries.map(e => `
    <tr>
      <td style="font-family:var(--mono);font-size:10px;color:var(--text-dim)">${e.timestamp.slice(0,19).replace('T',' ')}</td>
      <td style="font-family:var(--mono);font-size:10px">${e.username || '—'}</td>
      <td style="color:var(--green);font-family:var(--mono);font-size:10px">${e.action}</td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--text-dim)">${e.resource || '—'}</td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--amber)">${e.ip_address || '—'}</td>
      <td><span class="badge badge-${e.result==='success'?'success':'fail'}">${e.result}</span></td>
    </tr>`).join('');
  ri();
}

async function verifyAudit() {
  // FIX: Uses mock api() instead of raw fetch()
  const d  = await api('/api/security/audit/verify');
  const el = document.getElementById('integrity-result');
  if (d.valid) {
    el.innerHTML = `<div class="integrity-ok"><i data-lucide="shield-check"></i> Chain intact — ${d.entries} entries verified. No tampering detected.</div>`;
    toast('Audit chain valid ✓', 'green');
  } else {
    el.innerHTML = `<div class="integrity-fail"><i data-lucide="alert-triangle"></i> INTEGRITY VIOLATION detected.</div>`;
    toast('Chain integrity FAILED', 'red');
  }
  ri();
}

/* ═══════════════════════════════════════════════════════════════
   VAULT
═══════════════════════════════════════════════════════════════ */
async function saveSecret() {
  const key   = document.getElementById('vault-key').value.trim();
  const value = document.getElementById('vault-val').value;
  if (!key || !value) { toast('Key and value are required', 'red'); return; }
  await api('/api/security/vault', { method:'POST', body:{key, value} });
  toast(`Secret "${key}" encrypted & stored`, 'green');
  addFeedEvent('info', 'VAULT_WRITE', key, '—');
  document.getElementById('vault-val').value = '';
}

async function readSecret() {
  const key = document.getElementById('vault-key').value.trim();
  if (!key) { toast('Enter a key name to retrieve', 'red'); return; }
  const d   = await api(`/api/security/vault/${key}`);
  const el  = document.getElementById('vault-result');
  el.style.display = 'block';
  if (d.value) {
    el.innerHTML = `<span style="color:var(--text-dim)">KEY:</span> <span style="color:var(--green)">${d.key}</span> &nbsp;|&nbsp; <span style="color:var(--text-dim)">VALUE:</span> <span style="color:var(--amber)">${d.value}</span>`;
    addFeedEvent('high', 'VAULT_READ', key, '—');
  } else {
    el.innerHTML = `<span style="color:var(--red)">Key not found: ${key}</span>`;
  }
}

/* ═══════════════════════════════════════════════════════════════
   EVENT FEED
═══════════════════════════════════════════════════════════════ */
function addFeedEvent(level, type, details, ip) {
  feedCount++;
  document.getElementById('feed-count').textContent = feedCount;
  const feed = document.getElementById('event-feed');
  const item = document.createElement('div');
  item.className = `event-item ${level}`;
  const c = level === 'critical' ? 'var(--red)' : level === 'high' ? 'var(--amber)' : level === 'success' ? 'var(--blue)' : 'var(--green)';
  item.innerHTML = `
    <div class="event-time">${new Date().toTimeString().slice(0,8)}</div>
    <div class="event-type" style="color:${c}">${type.replace(/_/g,' ')}</div>
    <div class="event-ip">${details} · ${ip}</div>`;
  feed.insertBefore(item, feed.firstChild);
  while (feed.children.length > 80) feed.removeChild(feed.lastChild);
}

/* ═══════════════════════════════════════════════════════════════
   TOAST
═══════════════════════════════════════════════════════════════ */
function toast(msg, color = 'green') {
  const c = document.getElementById('toasts');
  const t = document.createElement('div');
  t.className = 'toast-msg';
  t.style.borderLeft = `3px solid var(--${color})`;
  t.style.color = `var(--${color})`;
  t.textContent = msg;
  c.appendChild(t);
  setTimeout(() => { t.style.opacity='0'; t.style.transition='opacity 0.3s'; setTimeout(() => t.remove(), 300); }, 3200);
}

/* ═══════════════════════════════════════════════════════════════
   ROOM CONTROL
═══════════════════════════════════════════════════════════════ */
const ROOMS = [
  { id:'living_room',    name:'Living Room',    icon:'sofa',    status:'online',  devices:['lights','camera','motion','lock'] },
  { id:'kitchen',        name:'Kitchen',        icon:'chef-hat',status:'online',  devices:['lights','smoke','gas','appliances'] },
  { id:'bedroom_master', name:'Master Bedroom', icon:'bed',     status:'online',  devices:['lights','camera','windows','climate'] },
  { id:'garage',         name:'Garage',         icon:'car',     status:'warning', devices:['lights','door','motion','vehicle'] },
  { id:'office',         name:'Home Office',    icon:'monitor', status:'online',  devices:['lights','network','webcam','lock'] },
  { id:'bathroom',       name:'Bathroom',       icon:'droplet', status:'online',  devices:['lights','leak','fan','temp'] }
];

// Default ON states
const ROOM_DEFAULTS = {
  living_room:    { lights:true,  camera:true,  motion:true,  lock:true },
  kitchen:        { lights:false, smoke:true,   gas:true,     appliances:false },
  bedroom_master: { lights:false, camera:false, windows:true, climate:true },
  garage:         { lights:false, door:true,    motion:true,  vehicle:true },
  office:         { lights:false, network:true, webcam:true,  lock:true },
  bathroom:       { lights:false, leak:true,    fan:false,    temp:true }
};

// Alerts for garage to show warning state
const ROOM_INITIAL_ALERTS = {
  garage: { type:'warning', text:'Door left open for 15 minutes' }
};

function buildRooms() {
  const grid = document.getElementById('room-grid');
  grid.innerHTML = ROOMS.map(room => {
    const alert = ROOM_INITIAL_ALERTS[room.id];
    const alertHtml = alert
      ? `<div class="alert-item ${alert.type}"><i data-lucide="${alert.type==='warning'?'alert-triangle':'check-circle'}"></i>${alert.text}</div>`
      : `<div class="alert-item success"><i data-lucide="check-circle"></i>All systems operational</div>`;

    const controls = room.devices.map(dev => {
      const checked = (ROOM_DEFAULTS[room.id]?.[dev] !== false) ? 'checked' : '';
      return `<div class="control-row">
        <label>${deviceLabel(dev)}</label>
        <label class="toggle-switch">
          <input type="checkbox" id="${dev}-${room.id}" ${checked} data-room="${room.id}" data-device="${dev}">
          <span class="slider"></span>
        </label>
      </div>`;
    }).join('');

    return `<div class="room-card" data-room="${room.id}">
      <div class="room-header">
        <div class="room-name"><i data-lucide="${room.icon}"></i>${room.name}</div>
        <div class="room-status" id="status-${room.id}">
          <span class="status-dot ${room.status}"></span>
          <span>${room.status === 'warning' ? 'WARNING' : 'SECURE'}</span>
        </div>
      </div>
      <div class="room-controls">${controls}</div>
      <div class="room-alerts" id="alerts-${room.id}">${alertHtml}</div>
    </div>`;
  }).join('');
}

function deviceLabel(dev) {
  const labels = {
    lights:'Lighting', camera:'Security Camera', motion:'Motion Sensor',
    lock:'Door Lock', smoke:'Smoke Detector', gas:'Gas Sensor',
    appliances:'Smart Appliances', windows:'Window Sensors', climate:'Climate Control',
    door:'Garage Door', vehicle:'Vehicle Detection', network:'Network Security',
    webcam:'Webcam Privacy', leak:'Water Leak Sensor', fan:'Ventilation Fan', temp:'Temp Control'
  };
  return labels[dev] || dev;
}

let roomsBuilt = false;

function initRooms() {
  if (!roomsBuilt) {
    buildRooms();
    roomsBuilt = true;
    ri();

    // FIX: Use single 'change' event listener on the grid — no onclick/ontouchstart conflicts
    document.getElementById('room-grid').addEventListener('change', e => {
      const input = e.target;
      if (input.type !== 'checkbox') return;
      const room   = input.dataset.room;
      const device = input.dataset.device;
      if (!room || !device) return;

      const isOn = input.checked;

      // Haptic feedback on mobile
      if (navigator.vibrate) navigator.vibrate(isOn ? 50 : [50, 30, 50]);

      updateRoomStatus(room);
      updateRoomAlert(room, device, isOn);

      const roomName = ROOMS.find(r => r.id === room)?.name || room;
      addFeedEvent('info', isOn ? 'DEVICE_ON' : 'DEVICE_OFF', `${deviceLabel(device)} · ${roomName}`, 'LOCAL');
      toast(`${deviceLabel(device)} ${isOn ? 'enabled' : 'disabled'} in ${roomName}`, isOn ? 'green' : 'amber');
    });
  }

  // Always refresh statuses when navigating to the page
  ROOMS.forEach(r => updateRoomStatus(r.id));
}

// FIX: Use .querySelector('span') to target the text node reliably, not lastChild
function updateRoomStatus(roomId) {
  const statusEl  = document.getElementById(`status-${roomId}`);
  if (!statusEl) return;
  const dot       = statusEl.querySelector('.status-dot');
  const textSpan  = statusEl.querySelector('span:not(.status-dot)');
  const room      = ROOMS.find(r => r.id === roomId);
  if (!room) return;

  let active = 0, total = 0;
  room.devices.forEach(dev => {
    const cb = document.getElementById(`${dev}-${roomId}`);
    if (cb) { total++; if (cb.checked) active++; }
  });

  if (active === total) {
    dot.className = 'status-dot online';
    if (textSpan) textSpan.textContent = 'SECURE';
  } else if (active >= Math.ceil(total / 2)) {
    dot.className = 'status-dot warning';
    if (textSpan) textSpan.textContent = 'PARTIAL';
  } else {
    dot.className = 'status-dot offline';
    if (textSpan) textSpan.textContent = 'VULNERABLE';
  }
}

function updateRoomAlert(roomId, device, isOn) {
  const alertsEl = document.getElementById(`alerts-${roomId}`);
  if (!alertsEl) return;

  const criticalOff = {
    lock:   { type:'warning', icon:'alert-triangle', text:'Door lock disabled — security risk' },
    camera: { type:'warning', icon:'alert-triangle', text:'Security camera offline' },
    smoke:  { type:'error',   icon:'x-circle',       text:'Smoke detector disabled — fire hazard!' },
    gas:    { type:'error',   icon:'x-circle',       text:'Gas sensor disabled — safety risk!' }
  };

  if (!isOn && criticalOff[device]) {
    const a = criticalOff[device];
    alertsEl.innerHTML = `<div class="alert-item ${a.type}"><i data-lucide="${a.icon}"></i>${a.text}</div>`;
    ri();
    return;
  }

  // Check if all critical are OK
  const room = ROOMS.find(r => r.id === roomId);
  const criticals = ['lock','camera','smoke','gas'].filter(d => room.devices.includes(d));
  const allOk = criticals.every(d => {
    const cb = document.getElementById(`${d}-${roomId}`);
    return !cb || cb.checked;
  });

  if (allOk) {
    alertsEl.innerHTML = `<div class="alert-item success"><i data-lucide="check-circle"></i>All security systems operational</div>`;
    ri();
  }
}

function setAllRoomStatus(mode) {
  if (!roomsBuilt) { toast('Navigate to Room Control first', 'amber'); return; }

  const configs = {
    secure:  { devices: ['lock','camera','motion','smoke','gas','windows','vehicle','network','webcam','leak'], status:'online',  statusText:'SECURE',   alertType:'success', alertIcon:'shield-check', alertText:'All rooms locked down' },
    standby: { devices: ['lock','smoke','gas','leak'], disableOthers:true, status:'warning', statusText:'STANDBY',  alertType:'warning', alertIcon:'pause',       alertText:'Standby mode active' },
    alert:   { devices: ['smoke','gas','leak','motion','camera'], disableOthers:true, status:'offline', statusText:'ALERT', alertType:'error',   alertIcon:'bell',        alertText:'Alert mode activated' }
  };

  const cfg = configs[mode];
  ROOMS.forEach(room => {
    room.devices.forEach(dev => {
      const cb = document.getElementById(`${dev}-${room.id}`);
      if (!cb) return;
      if (cfg.disableOthers) {
        cb.checked = cfg.devices.includes(dev);
      } else {
        if (cfg.devices.includes(dev)) cb.checked = true;
      }
    });

    const statusEl = document.getElementById(`status-${room.id}`);
    const dot      = statusEl?.querySelector('.status-dot');
    const txt      = statusEl?.querySelector('span:not(.status-dot)');
    if (dot) dot.className = `status-dot ${cfg.status}`;
    if (txt) txt.textContent = cfg.statusText;

    const alertsEl = document.getElementById(`alerts-${room.id}`);
    if (alertsEl) alertsEl.innerHTML = `<div class="alert-item ${cfg.alertType}"><i data-lucide="${cfg.alertIcon}"></i>${cfg.alertText}</div>`;
  });

  addFeedEvent('critical', `GLOBAL_${mode.toUpperCase()}`, 'All rooms', 'SYSTEM');
  toast(`All rooms → ${mode.toUpperCase()} mode`, mode === 'secure' ? 'green' : mode === 'standby' ? 'amber' : 'red');
  ri();
}

/* ═══════════════════════════════════════════════════════════════
   UTILS
═══════════════════════════════════════════════════════════════ */
function set(id, val) { const el = document.getElementById(id); if (el) el.textContent = val; }
function styleEl(id, color) { const el = document.getElementById(id); if (el) el.style.color = color; }
function ri() { if (typeof lucide !== 'undefined') lucide.createIcons(); }  // re-init lucide icons

/* ═══════════════════════════════════════════════════════════════
   INIT
═══════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', () => {
  ri();
});
