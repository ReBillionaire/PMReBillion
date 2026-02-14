// ══════════════════════════════════════════════════════════════
// ReBillion PM — Frontend Application (v3 — Server-Backed)
// ══════════════════════════════════════════════════════════════

// ── XSS Sanitizer ──
const _esc_el = document.createElement('div');
function esc(str) { if (!str) return ''; _esc_el.textContent = String(str); return _esc_el.innerHTML; }

// ── Utilities ──
function uid() { return 'id_' + Date.now().toString(36) + '_' + Math.random().toString(36).substr(2, 7); }
function now() { return new Date().toISOString(); }
function fmtDate(iso) { if (!iso) return '\u2014'; try { const d = new Date(iso); if (isNaN(d.getTime())) return '\u2014'; return d.toLocaleDateString('en-US', { month:'short', day:'numeric' }); } catch(e) { return '\u2014'; } }
function fmtDateTime(iso) { try { const d = new Date(iso); if (isNaN(d.getTime())) return '\u2014'; return d.toLocaleDateString('en-US', { month:'short', day:'numeric', hour:'numeric', minute:'2-digit' }); } catch(e) { return '\u2014'; } }
function isOverdue(dateStr) { if (!dateStr) return false; try { return new Date(dateStr) < new Date(); } catch(e) { return false; } }

// ── CSRF Token Helper ──
function getCSRFToken() {
  const meta = document.querySelector('meta[name="csrf-token"]');
  if (meta) return meta.getAttribute('content');
  const cookie = document.cookie.split('; ').find(row => row.startsWith('csrfToken='));
  return cookie ? decodeURIComponent(cookie.split('=')[1]) : null;
}

// ══════════════════════════════════════════════════════════════
// API CLIENT
// ══════════════════════════════════════════════════════════════
const api = {
  getCSRFHeaders() {
    const token = getCSRFToken();
    return token ? { 'X-CSRF-Token': token } : {};
  },
  async get(url) {
    const res = await fetch(url);
    if (res.status === 401) { window.location.href = '/login.html'; throw new Error('Not authenticated'); }
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },
  async post(url, data) {
    const headers = { 'Content-Type': 'application/json', ...this.getCSRFHeaders() };
    const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(data) });
    if (res.status === 401) { window.location.href = '/login.html'; throw new Error('Not authenticated'); }
    if (!res.ok) { const err = await res.json().catch(() => ({ message: 'Request failed' })); throw new Error(err.message); }
    return res.json();
  },
  async put(url, data) {
    const headers = { 'Content-Type': 'application/json', ...this.getCSRFHeaders() };
    const res = await fetch(url, { method: 'PUT', headers, body: JSON.stringify(data) });
    if (res.status === 401) { window.location.href = '/login.html'; throw new Error('Not authenticated'); }
    if (!res.ok) { const err = await res.json().catch(() => ({ message: 'Request failed' })); throw new Error(err.message); }
    return res.json();
  },
  async del(url) {
    const headers = { ...this.getCSRFHeaders() };
    const res = await fetch(url, { method: 'DELETE', headers });
    if (res.status === 401) { window.location.href = '/login.html'; throw new Error('Not authenticated'); }
    if (!res.ok) throw new Error('Delete failed');
    return res.json();
  }
};

// ══════════════════════════════════════════════════════════════
// INDEXEDDB CACHE
// ══════════════════════════════════════════════════════════════
const idbCache = {
  db: null,
  async init() {
    return new Promise((resolve, reject) => {
      const req = indexedDB.open('rb_pm_cache', 1);
      req.onupgradeneeded = (e) => {
        const db = e.target.result;
        if (!db.objectStoreNames.contains('state')) db.createObjectStore('state');
        if (!db.objectStoreNames.contains('sync_queue')) db.createObjectStore('sync_queue', { keyPath: 'id' });
      };
      req.onsuccess = () => { idbCache.db = req.result; resolve(); };
      req.onerror = () => { console.warn('IndexedDB not available'); resolve(); };
    });
  },
  async saveState(data) {
    if (!this.db) return;
    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction('state', 'readwrite');
        tx.objectStore('state').put(data, 'app_state');
        tx.oncomplete = resolve;
        tx.onerror = () => resolve();
      } catch(e) { resolve(); }
    });
  },
  async loadState() {
    if (!this.db) return null;
    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction('state', 'readonly');
        const req = tx.objectStore('state').get('app_state');
        req.onsuccess = () => resolve(req.result || null);
        req.onerror = () => resolve(null);
      } catch(e) { resolve(null); }
    });
  },
  async queueAction(action) {
    if (!this.db) return;
    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction('sync_queue', 'readwrite');
        tx.objectStore('sync_queue').put({ ...action, id: action.id || uid(), timestamp: now() });
        tx.oncomplete = resolve;
        tx.onerror = () => resolve();
      } catch(e) { resolve(); }
    });
  },
  async getQueue() {
    if (!this.db) return [];
    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction('sync_queue', 'readonly');
        const req = tx.objectStore('sync_queue').getAll();
        req.onsuccess = () => resolve(req.result || []);
        req.onerror = () => resolve([]);
      } catch(e) { resolve([]); }
    });
  },
  async clearQueue() {
    if (!this.db) return;
    return new Promise((resolve) => {
      try {
        const tx = this.db.transaction('sync_queue', 'readwrite');
        tx.objectStore('sync_queue').clear();
        tx.oncomplete = resolve;
        tx.onerror = () => resolve();
      } catch(e) { resolve(); }
    });
  }
};

// ══════════════════════════════════════════════════════════════
// DATA MODEL & STEP DEFINITIONS
// ══════════════════════════════════════════════════════════════
const PHASES = [
  { id:'phase1', name:'Sales & Discovery', color:'#4B876C', weeks:'0\u20131', team:'Sales',
    steps: [
      { id:'p1s1', name:'Lead Qualification', desc:'Qualify: company type, volume, pain points, tech stack, budget. Identify scenario profile.' },
      { id:'p1s2', name:'Discovery Call', desc:'30\u201345 min structured call: workflow, tech landscape, pain points, baselines.' },
      { id:'p1s3', name:'Follow-Up & Demo Scheduling', desc:'Follow-up email, schedule tailored demo within 3\u20135 days.' },
      { id:'p1s4', name:'Tailored Product Demo', desc:'45\u201360 min live demo: AI doc processing, integrations, compliance, agent portal.' },
      { id:'p1s5', name:'Proposal & Objection Handling', desc:'Deliver pricing, handle objections, share time commitment overview.' },
      { id:'p1s6', name:'Contract Signed & Deal Closed', desc:'Finalize agreement, complete Handoff Form, schedule warm intro.' }
    ],
    gate: { id:'g1', name:'GATE 1: Sales \u2192 Onboarding', desc:'Contract signed. Handoff form complete. Discovery materials transferred.' }
  },
  { id:'phase2', name:'Data Collection & Gathering', color:'#00838f', weeks:'1\u20132', team:'Onboarding',
    steps: [
      { id:'p2s1', name:'Welcome Email & Info Packet', desc:'Send welcome email, timeline, info request packet. Introduce AM.' },
      { id:'p2s2', name:'Onboarding Kick-Off Call', desc:'30-min call: walk through process, review packet, identify tech contact.' },
      { id:'p2s3', name:'Technology Stack Inventory', desc:'Map full tech: TMS, CRM, doc storage, e-sign, accounting, MLS.' },
      { id:'p2s4', name:'API Credentials & Access', desc:'Collect API keys, OAuth auths. Secure transfer only.' },
      { id:'p2s5', name:'Workflow & Contract Docs', desc:'Document transaction types, forms, compliance, checklists.' },
      { id:'p2s6', name:'Agent Roster Collection', desc:'Collect agent list with all details. Provide roster template.' },
      { id:'p2s7', name:'Data Migration Planning', desc:'Decide migration approach: new files, parallel run, or full migration.', isNew:true },
      { id:'p2s8', name:'Data Package Assembly', desc:'Compile all 9 items into standardized folder.' },
      { id:'p2s9', name:'Pre-Config Internal Sync', desc:'30-min internal call: sold vs. build alignment, risks, go-live target.', isNew:true },
      { id:'p2s10', name:'Data Package Handoff', desc:'Atul reviews for completeness. Accepts when all 9 items confirmed.' }
    ],
    gate: { id:'g2', name:'GATE 2: Onboarding \u2192 Technical', desc:'Data package complete. Internal sync done. Migration confirmed.' }
  },
  { id:'phase3', name:'Config, Setup & Handover', color:'#2e7d32', weeks:'2\u20134', team:'Implementation',
    steps: [
      { id:'p3s1', name:'Tenant Creation & Provisioning', desc:'Create workspace in staging. Provision users, configure RBAC.' },
      { id:'p3s2', name:'Workflow & Field Configuration', desc:'Transaction types, checklists, field mapping, templates, notifications.' },
      { id:'p3s3', name:'Integration Setup', desc:'Connect FUB, SkySlope/Dotloop, OTC, GDrive, Brokermint. 48hr escalation rule.' },
      { id:'p3s4', name:'Internal Testing & QA', desc:'3\u20135 sample transactions in staging. Test all flows. Promote to UAT.' },
      { id:'g3', name:'GATE 3: Config \u2192 UAT', desc:'QA passed. No critical defects. Promote Staging \u2192 UAT.', isGate:true },
      { id:'p3s5', name:'Client UAT', desc:'Walk client through 1\u20132 real transactions in UAT. Document feedback.' },
      { id:'g4', name:'GATE 4: UAT \u2192 Training', desc:'All critical feedback resolved. Client sign-off received.', isGate:true },
      { id:'p3s6', name:'Training Sessions', desc:'Role-based: Admin/Broker 60min, TC 90min, Agents 30min. All recorded.' },
      { id:'g5', name:'GATE 5: Training \u2192 Go-Live', desc:'All sessions done. Recordings delivered. SLA shared. Agent email sent.', isGate:true },
      { id:'p3s7', name:'GO-LIVE & Supported Launch', desc:'Promote to production. Standby for first 5 files. SLA active.' },
      { id:'p3s8', name:'Agent Adoption Tracking', desc:'Day 3/7/14/30 checkpoints. Q&A sessions. Address resistance.', isNew:true },
      { id:'p3s9', name:'Post-Launch Support', desc:'Week 1 daily, Week 2\u20134 biweekly, Month 2+ monthly reviews.' },
      { id:'p3s10', name:'ROI & Success Metrics Review', desc:'Compare KPIs vs discovery baselines at 30-day and 90-day.', isNew:true }
    ],
    gate: { id:'g6', name:'GATE 6: Go-Live \u2192 Steady-State', desc:'First 5 txns done. 30-day review complete. NPS collected. Onboarding closed.' }
  }
];

function getAllCheckpoints() {
  const items = [];
  PHASES.forEach(p => {
    p.steps.forEach(s => { items.push({ ...s, phase: p.id, type: s.isGate ? 'gate' : 'step', phaseColor: p.color }); });
    if (p.gate) items.push({ ...p.gate, phase: p.id, type:'gate', phaseColor: p.color });
  });
  return items;
}
const ALL_CHECKPOINTS = getAllCheckpoints();

function getPhaseStepIds(phaseId) {
  return ALL_CHECKPOINTS.filter(c => c.phase === phaseId).map(c => c.id);
}

// ══════════════════════════════════════════════════════════════
// STATE
// ══════════════════════════════════════════════════════════════
let state = {
  clients: [], team: [], activities: [],
  currentUser: null, // { id, name, role, email, color }
  currentView: 'dashboard', detailClientId: null,
  editingClientId: null, noteTarget: null, linkTarget: null, clientActionTarget: null,
  previousView: 'dashboard', searchTerm: '',
  isOffline: false
};

// ══════════════════════════════════════════════════════════════
// TOAST
// ══════════════════════════════════════════════════════════════
function showToast(msg, type='info') {
  const t = document.getElementById('toast');
  t.textContent = msg; t.className = 'toast ' + type + ' show';
  setTimeout(() => t.className = 'toast', 3000);
}

// ══════════════════════════════════════════════════════════════
// CLIENT HELPERS
// ══════════════════════════════════════════════════════════════
function ensureSteps(client) {
  if (!client.steps) client.steps = {};
  ALL_CHECKPOINTS.forEach(cp => {
    if (!client.steps[cp.id]) client.steps[cp.id] = { status:'pending', note:'', links:[], completedDate:null, completedBy:null, clientActionNote:'', clientActionResponse:'', clientActionRespondedAt:null };
    if (!client.steps[cp.id].links) client.steps[cp.id].links = [];
    if (client.steps[cp.id].clientActionNote === undefined) client.steps[cp.id].clientActionNote = '';
    if (client.steps[cp.id].clientActionResponse === undefined) client.steps[cp.id].clientActionResponse = '';
    if (client.steps[cp.id].clientActionRespondedAt === undefined) client.steps[cp.id].clientActionRespondedAt = null;
  });
  return client;
}
function hasBlockedSteps(client) {
  ensureSteps(client);
  return ALL_CHECKPOINTS.some(cp => (client.steps[cp.id] || {}).status === 'blocked');
}
function blockedStepCount(client) {
  ensureSteps(client);
  return ALL_CHECKPOINTS.filter(cp => (client.steps[cp.id] || {}).status === 'blocked').length;
}
function clientProgress(client) {
  const c = ensureSteps(client);
  const total = ALL_CHECKPOINTS.length;
  const done = ALL_CHECKPOINTS.filter(cp => (c.steps[cp.id] || {}).status === 'completed').length;
  return { done, total, pct: Math.round((done/total)*100) };
}
function clientCurrentPhase(client) {
  const c = ensureSteps(client);
  for (const cp of ALL_CHECKPOINTS) { if ((c.steps[cp.id] || {}).status !== 'completed') return cp.phase; }
  return 'phase3';
}
function phaseProgress(client, phaseId) {
  const c = ensureSteps(client);
  const ids = getPhaseStepIds(phaseId);
  const done = ids.filter(id => (c.steps[id] || {}).status === 'completed').length;
  return { done, total: ids.length, pct: ids.length ? Math.round((done/ids.length)*100) : 0 };
}
function userName(id) {
  if (!id || id === 'system') return 'System';
  if (id === 'client') return 'Client';
  const u = state.team.find(t => t.id === id);
  return u ? u.name : 'Unknown';
}
function userColor(id) {
  if (!id || id === 'system') return '#607d8b';
  if (id === 'client') return '#D05F0D';
  const u = state.team.find(t => t.id === id);
  return u ? u.color : '#999';
}

// ══════════════════════════════════════════════════════════════
// DATA LOADING
// ══════════════════════════════════════════════════════════════
async function loadAllData() {
  try {
    const [meRes, clientsRes, teamRes, activitiesRes] = await Promise.all([
      api.get('/api/auth/me'),
      api.get('/api/clients'),
      api.get('/api/team'),
      api.get('/api/activities')
    ]);
    state.currentUser = meRes;
    state.clients = (clientsRes.clients || []).map(ensureSteps);
    state.team = teamRes.team || [];
    state.activities = activitiesRes.activities || [];
    state.isOffline = false;

    // Cache to IndexedDB
    await idbCache.saveState({ clients: state.clients, team: state.team, activities: state.activities, currentUser: state.currentUser });

    // Sync any queued offline actions
    const queue = await idbCache.getQueue();
    if (queue.length > 0) {
      await replayQueue(queue);
      await idbCache.clearQueue();
      // Reload after sync
      const freshClients = await api.get('/api/clients');
      state.clients = (freshClients.clients || []).map(ensureSteps);
      showToast(`Synced ${queue.length} offline change${queue.length > 1 ? 's' : ''}`, 'success');
    }
    return true;
  } catch(e) {
    console.warn('Failed to load from server, trying cache:', e.message);
    return loadFromCache();
  }
}

async function loadFromCache() {
  const cached = await idbCache.loadState();
  if (cached) {
    state.clients = (cached.clients || []).map(ensureSteps);
    state.team = cached.team || [];
    state.activities = cached.activities || [];
    state.currentUser = cached.currentUser;
    state.isOffline = true;
    showToast('Working offline with cached data', 'warn');
    return true;
  }
  return false;
}

async function replayQueue(queue) {
  for (const action of queue.sort((a,b) => a.timestamp.localeCompare(b.timestamp))) {
    try {
      switch(action.type) {
        case 'create_client': await api.post('/api/clients', action.data); break;
        case 'update_client': await api.put(`/api/clients/${action.data.id}`, action.data); break;
        case 'delete_client': await api.del(`/api/clients/${action.data.id}`); break;
        case 'update_step': await api.put(`/api/clients/${action.data.clientId}/steps/${action.data.stepId}`, action.data); break;
        case 'save_note': await api.put(`/api/clients/${action.data.clientId}/steps/${action.data.stepId}/note`, action.data); break;
        case 'add_link': await api.post(`/api/clients/${action.data.clientId}/steps/${action.data.stepId}/links`, { url: action.data.url, label: action.data.label }); break;
        case 'remove_link': await api.del(`/api/clients/${action.data.clientId}/steps/${action.data.stepId}/links/${action.data.linkId}`); break;
        case 'create_team': await api.post('/api/team', action.data); break;
        case 'delete_team': await api.del(`/api/team/${action.data.id}`); break;
      }
    } catch(e) {
      console.warn('Failed to replay action:', action.type, e.message);
    }
  }
}

// ══════════════════════════════════════════════════════════════
// OFFLINE DETECTION
// ══════════════════════════════════════════════════════════════
function updateOfflineStatus(offline) {
  state.isOffline = offline;
  const banner = document.getElementById('offline-banner');
  if (offline) {
    banner.classList.add('show');
    document.body.classList.add('offline');
  } else {
    banner.classList.remove('show');
    document.body.classList.remove('offline');
  }
}

window.addEventListener('online', async () => {
  updateOfflineStatus(false);
  await loadAllData();
  render();
  showToast('Back online', 'success');
});
window.addEventListener('offline', () => {
  updateOfflineStatus(true);
  showToast('You are offline', 'warn');
});

// Heartbeat every 60s
setInterval(async () => {
  try {
    await fetch('/api/auth/me', { method: 'GET' });
    if (state.isOffline) {
      updateOfflineStatus(false);
      await loadAllData();
      render();
    }
  } catch(e) {
    if (!state.isOffline) updateOfflineStatus(true);
  }
}, 60000);

// Auto-save to IndexedDB every 5 minutes
setInterval(async () => {
  await idbCache.saveState({ clients: state.clients, team: state.team, activities: state.activities, currentUser: state.currentUser });
}, 300000);

// ══════════════════════════════════════════════════════════════
// NAVIGATION
// ══════════════════════════════════════════════════════════════
function switchView(view) {
  if (state.currentView !== 'detail') state.previousView = state.currentView;
  state.currentView = view;
  if (view !== 'detail') state.detailClientId = null;
  document.querySelectorAll('.nav-item').forEach(el => el.classList.toggle('active', el.dataset.view === view));
  render();
  document.getElementById('sidebar').classList.remove('open');
  document.getElementById('sidebar-overlay').classList.remove('open');
}
function openClientDetail(id) {
  state.previousView = state.currentView;
  state.detailClientId = id;
  state.currentView = 'detail';
  render();
}
function goBack() { switchView(state.previousView || 'dashboard'); }
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sidebar-overlay').classList.toggle('open');
}

function onSearch() {
  state.searchTerm = document.getElementById('search-input').value.trim().toLowerCase();
  render();
  const inp = document.getElementById('search-input');
  if (inp) { inp.value = state.searchTerm; inp.focus(); }
}
function getFilteredClients() {
  if (!state.searchTerm) return state.clients;
  return state.clients.filter(c =>
    c.company.toLowerCase().includes(state.searchTerm) ||
    (c.contactName || '').toLowerCase().includes(state.searchTerm) ||
    (c.contactEmail || '').toLowerCase().includes(state.searchTerm)
  );
}

// ══════════════════════════════════════════════════════════════
// RENDER ENGINE
// ══════════════════════════════════════════════════════════════
function render() {
  const c = document.getElementById('view-content');
  const titles = { dashboard:'Dashboard', pipeline:'Pipeline', clients:'All Clients', team:'Team Management', activity:'Activity Log', flow:'Flow Reference', detail:'Client Detail' };
  document.getElementById('view-title').textContent = titles[state.currentView] || 'Dashboard';
  document.getElementById('client-count').textContent = state.clients.length;
  const searchEl = document.getElementById('global-search');
  searchEl.style.display = ['clients','pipeline','dashboard'].includes(state.currentView) ? 'flex' : 'none';
  try {
    switch(state.currentView) {
      case 'dashboard': c.innerHTML = renderDashboard(); break;
      case 'pipeline': c.innerHTML = renderPipeline(); break;
      case 'clients': c.innerHTML = renderClients(); break;
      case 'team': c.innerHTML = renderTeam(); break;
      case 'activity': c.innerHTML = renderActivity(); break;
      case 'flow': c.innerHTML = renderFlow(); break;
      case 'detail': c.innerHTML = renderDetail(); break;
      default: c.innerHTML = renderDashboard();
    }
  } catch(e) {
    console.error('Render error:', e);
    c.innerHTML = '<div class="empty-state"><h3>Something went wrong</h3><p>' + esc(e.message) + '</p></div>';
  }
  populateTeamSelects();
}

// ══════════════════════════════════════════════════════════════
// RENDER VIEWS
// ══════════════════════════════════════════════════════════════
function renderDashboard() {
  const all = getFilteredClients();
  const active = all.filter(c => c.status === 'active').length;
  const atRisk = all.filter(c => c.status === 'at_risk').length;
  const completed = all.filter(c => c.status === 'completed').length;
  const overdue = all.filter(c => c.status !== 'completed' && isOverdue(c.targetGoLive)).length;
  const p1 = all.filter(c => clientCurrentPhase(c)==='phase1' && c.status!=='completed').length;
  const p2 = all.filter(c => clientCurrentPhase(c)==='phase2' && c.status!=='completed').length;
  const p3 = all.filter(c => clientCurrentPhase(c)==='phase3' && c.status!=='completed').length;

  let recentActivity = state.activities.slice(0, 8).map(a => {
    const cl = state.clients.find(c => c.id === a.client_id);
    const clName = cl ? esc(cl.company) : '';
    return `<div class="activity-item"><div class="activity-dot" style="background:${esc(userColor(a.user_id))}"></div><div><div class="activity-text"><strong>${esc(userName(a.user_id))}</strong> ${esc(a.action)}${clName ? ' \u2014 <em>'+clName+'</em>' : ''}</div><div class="activity-time">${fmtDateTime(a.timestamp)}</div></div></div>`;
  }).join('');

  const blockedCount = all.filter(c => c.status!=='completed' && hasBlockedSteps(c)).length;

  let clientRows = all.filter(c => c.status!=='completed').slice(0, 8).map(c => {
    const prog = clientProgress(c);
    const phase = clientCurrentPhase(c);
    const pColor = PHASES.find(p => p.id===phase)?.color || '#999';
    const pLabel = PHASES.find(p => p.id===phase)?.name || '';
    const od = isOverdue(c.targetGoLive) && c.status !== 'completed';
    const blocked = hasBlockedSteps(c);
    const bCount = blockedStepCount(c);
    return `<tr onclick="openClientDetail('${esc(c.id)}')" ${blocked?'style="background:#fff3e0;border-left:3px solid #e65100"':''}><td><strong>${esc(c.company)}</strong>${od ? '<span class="overdue-tag">OVERDUE</span>' : ''}${blocked ? '<span style="background:#e65100;color:#fff;font-size:9px;padding:1px 6px;border-radius:3px;font-weight:700;margin-left:6px;vertical-align:middle">'+bCount+' BLOCKED</span>' : ''}</td><td><span class="status status-${esc(c.status)}">${esc(c.status.replace('_',' '))}</span></td><td style="color:${pColor};font-weight:600;font-size:12px">${esc(pLabel)}</td><td><div style="display:flex;align-items:center;gap:8px"><div style="flex:1;height:4px;background:#e0e0e0;border-radius:2px;overflow:hidden"><div style="height:100%;width:${prog.pct}%;background:${pColor};border-radius:2px"></div></div><span style="font-size:11px;font-weight:600;color:${pColor}">${prog.pct}%</span></div></td></tr>`;
  }).join('');

  return `
    <div class="stats-row">
      <div class="stat-card blue"><div class="stat-label">Active Clients</div><div class="stat-value">${active}</div><div class="stat-sub">Currently onboarding</div></div>
      <div class="stat-card amber"><div class="stat-label">At Risk</div><div class="stat-value">${atRisk}</div><div class="stat-sub">Need attention</div></div>
      <div class="stat-card red"><div class="stat-label">Overdue</div><div class="stat-value">${overdue}</div><div class="stat-sub">Past go-live date</div></div>
      <div class="stat-card green"><div class="stat-label">Completed</div><div class="stat-value">${completed}</div><div class="stat-sub">Successfully onboarded</div></div>
      <div class="stat-card teal"><div class="stat-label">In Pipeline</div><div class="stat-value">${p1+p2+p3}</div><div class="stat-sub">P1: ${p1} \u00b7 P2: ${p2} \u00b7 P3: ${p3}</div></div>
      ${blockedCount > 0 ? '<div class="stat-card" style="border-color:#e65100"><div class="stat-label" style="color:#e65100">Blocked</div><div class="stat-value" style="color:#e65100">'+blockedCount+'</div><div class="stat-sub">Have blocked tasks</div></div>' : ''}
    </div>
    <div class="two-col">
      <div class="card"><div class="card-header"><h3>Active Clients</h3><button class="btn btn-sm btn-outline" onclick="switchView('clients')">View All</button></div><div class="card-body" style="padding:0"><div class="table-wrap">${clientRows ? '<table class="table"><thead><tr><th>Client</th><th>Status</th><th>Phase</th><th>Progress</th></tr></thead><tbody>'+clientRows+'</tbody></table>' : '<div class="empty-state" style="padding:40px"><p>No active clients yet. Click "New Client" to get started.</p></div>'}</div></div></div>
      <div class="card"><div class="card-header"><h3>Recent Activity</h3><button class="btn btn-sm btn-outline" onclick="switchView('activity')">View All</button></div><div class="card-body">${recentActivity || '<p class="text-sm text-muted">No activity yet.</p>'}</div></div>
    </div>`;
}

function renderPipeline() {
  const all = getFilteredClients();
  function col(phaseId, name, color) {
    const clients = all.filter(c => clientCurrentPhase(c)===phaseId && c.status!=='completed');
    const cards = clients.map(c => {
      const prog = clientProgress(c);
      const sU = state.team.find(t => t.id===c.salesLead);
      const oU = state.team.find(t => t.id===c.onboardingLead);
      const od = isOverdue(c.targetGoLive);
      return `<div class="pipeline-card" onclick="openClientDetail('${esc(c.id)}')">
        <div class="pc-name">${esc(c.company)}${od ? '<span class="overdue-tag">OVERDUE</span>':''}</div>
        <div class="pc-company">${esc((c.scenario||'').replace(/-/g,' '))} \u00b7 ${c.type==='tc_company'?'TC Co':'Brokerage'}</div>
        <div class="pc-progress"><div class="pc-progress-bar" style="width:${prog.pct}%;background:${color}"></div></div>
        <div class="pc-meta"><div class="pc-step">${prog.done}/${prog.total} \u00b7 ${prog.pct}%</div><div class="pc-avatars">${sU?'<div class="pc-avatar" style="background:'+sU.color+'">'+esc(sU.name[0])+'</div>':''}${oU?'<div class="pc-avatar" style="background:'+oU.color+'">'+esc(oU.name[0])+'</div>':''}</div></div>
        <div style="margin-top:6px"><span class="status status-${esc(c.status)}">${esc(c.status.replace('_',' '))}</span></div></div>`;
    }).join('');
    return `<div class="pipeline-col"><div class="pipeline-col-header"><div class="phase-dot" style="background:${color}"></div><h4>${esc(name)}</h4><span class="count">${clients.length}</span></div><div class="pipeline-col-body">${cards||'<div class="pipeline-empty">No clients in this phase</div>'}</div></div>`;
  }
  const done = all.filter(c => c.status==='completed');
  return `<div class="pipeline">${col('phase1','Phase 1: Sales & Discovery','#4B876C')}${col('phase2','Phase 2: Data Collection','#00838f')}${col('phase3','Phase 3: Config & Handover','#2e7d32')}</div>${done.length?'<div class="section-header" style="margin-top:28px"><h3>Completed ('+done.length+')</h3></div><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px">'+done.map(c=>'<div class="pipeline-card" onclick="openClientDetail(\''+esc(c.id)+'\')" style="background:#f1f8e9;border:1px solid #c8e6c9"><div class="pc-name">'+esc(c.company)+'</div><div class="pc-company">'+esc(c.type==='tc_company'?'TC Co':'Brokerage')+'</div><div style="margin-top:6px"><span class="status status-completed">Completed</span></div></div>').join('')+'</div>':''}`;
}

function renderClients() {
  const all = getFilteredClients();
  if (!all.length) {
    return state.searchTerm
      ? '<div class="empty-state"><h3>No matching clients</h3><p>Try a different search term.</p></div>'
      : '<div class="empty-state"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg><h3>No Clients Yet</h3><p>Add your first client to start tracking.</p><button class="btn btn-primary" onclick="openAddClientModal()">Add First Client</button></div>';
  }
  const rows = all.map(c => {
    const prog = clientProgress(c);
    const phase = clientCurrentPhase(c);
    const pColor = PHASES.find(p => p.id===phase)?.color||'#999';
    const pName = PHASES.find(p => p.id===phase)?.name||'';
    const od = isOverdue(c.targetGoLive) && c.status!=='completed';
    return `<tr onclick="openClientDetail('${esc(c.id)}')"><td><strong>${esc(c.company)}</strong>${od?'<span class="overdue-tag">OVERDUE</span>':''}<br><span class="text-sm text-muted">${esc(c.contactName||'')}</span></td><td>${c.type==='tc_company'?'TC Company':'Brokerage'}</td><td><span class="status status-${esc(c.status)}">${esc(c.status.replace('_',' '))}</span></td><td style="color:${pColor};font-weight:600;font-size:12px">${esc(pName)}</td><td><div style="display:flex;align-items:center;gap:8px"><div style="flex:1;height:4px;background:#e0e0e0;border-radius:2px;overflow:hidden;min-width:60px"><div style="height:100%;width:${prog.pct}%;background:${pColor};border-radius:2px"></div></div><span style="font-size:11px;font-weight:600;color:${pColor}">${prog.pct}%</span></div></td><td>${fmtDate(c.targetGoLive)}</td><td><button class="btn btn-sm btn-ghost" onclick="event.stopPropagation();openEditClientModal('${esc(c.id)}')" aria-label="Edit">Edit</button> <button class="btn btn-sm btn-ghost" style="color:var(--red)" onclick="event.stopPropagation();deleteClient('${esc(c.id)}')" aria-label="Delete">Del</button></td></tr>`;
  }).join('');
  return `<div class="card"><div class="card-body" style="padding:0"><div class="table-wrap"><table class="table"><thead><tr><th>Client</th><th>Type</th><th>Status</th><th>Phase</th><th>Progress</th><th>Go-Live</th><th></th></tr></thead><tbody>${rows}</tbody></table></div></div></div>`;
}

function renderTeam() {
  const members = state.team.filter(t => t.type==='member');
  const observers = state.team.filter(t => t.type==='observer');
  function cards(list) {
    return list.map(t => {
      const isDef = t.isDefault || t.is_default;
      return `<div class="team-card"><div class="team-avatar" style="background:${esc(t.color)}">${esc(t.name[0])}</div><div class="team-info"><div class="team-name">${esc(t.name)}</div><div class="team-role">${esc(t.role)}</div><div class="team-type" style="color:${t.type==='observer'?'var(--amber)':'var(--green)'}">${t.type==='observer'?'Observer':'Member'}${t.email?' \u00b7 '+esc(t.email):''}</div></div>${!isDef?'<div class="team-actions"><button class="btn-icon" onclick="removeTeamMember(\''+esc(t.id)+'\')" aria-label="Remove '+esc(t.name)+'"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18 6L6 18M6 6l12 12"/></svg></button></div>':''}</div>`;
    }).join('');
  }
  return `<div class="section-header"><h3>Team Members (${members.length})</h3><button class="btn btn-primary btn-sm" onclick="openModal('modal-team')"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M12 5v14M5 12h14"/></svg> Add Member</button></div><div class="team-grid mb-lg">${cards(members)}</div>${observers.length?'<div class="section-header"><h3>Observers ('+observers.length+')</h3></div><div class="team-grid">'+cards(observers)+'</div>':''}`;
}

function renderActivity() {
  if (!state.activities.length) return '<div class="empty-state"><p>No activity recorded yet.</p></div>';
  const items = state.activities.slice(0, 60).map(a => {
    const cl = state.clients.find(c => c.id===a.client_id);
    return `<div class="activity-item"><div class="activity-dot" style="background:${esc(userColor(a.user_id))}"></div><div><div class="activity-text"><strong>${esc(userName(a.user_id))}</strong> ${esc(a.action)}${cl?' \u2014 <em style="cursor:pointer;color:var(--blue)" onclick="openClientDetail(\''+esc(cl.id)+'\')">'+esc(cl.company)+'</em>':''}${a.details?'<br><span class="text-sm text-muted">'+esc(a.details)+'</span>':''}</div><div class="activity-time">${fmtDateTime(a.timestamp)}</div></div></div>`;
  }).join('');
  return `<div class="card"><div class="card-header"><h3>Activity Log</h3><button class="btn btn-sm btn-outline" onclick="clearActivities()">Clear</button></div><div class="card-body"><div class="activity-list">${items}</div></div></div>`;
}

function renderFlow() {
  return '<div class="mb-md"><p class="text-sm text-muted">Interactive reference of the full onboarding flow.</p></div><div class="flow-ref-embed"><iframe src="/ReBillion_Onboarding_Flow.html" title="Flow Diagram"></iframe></div>';
}

// ══════════════════════════════════════════════════════════════
// CLIENT DETAIL VIEW
// ══════════════════════════════════════════════════════════════
function renderDetail() {
  const c = state.clients.find(cl => cl.id===state.detailClientId);
  if (!c) return '<div class="empty-state"><h3>Client not found</h3><button class="btn btn-primary" onclick="goBack()">Go Back</button></div>';
  ensureSteps(c);
  const prog = clientProgress(c);
  const sU = state.team.find(t => t.id===c.salesLead);
  const oU = state.team.find(t => t.id===c.onboardingLead);
  const od = isOverdue(c.targetGoLive) && c.status!=='completed';

  function renderStepItems(phase) {
    let items = [...phase.steps];
    if (phase.gate) items.push(phase.gate);
    items = items.map(item => {
      const cp = ALL_CHECKPOINTS.find(ch => ch.id===item.id);
      return cp || { ...item, type: item.isGate ? 'gate' : 'step', phaseColor: phase.color };
    });
    return items.map(item => {
      const st = c.steps[item.id] || { status:'pending', note:'', links:[] };
      const links = st.links || [];
      const isGate = item.type==='gate';
      const badgeBg = isGate ? 'var(--amber)' : (item.isNew ? 'var(--purple)' : phase.color);
      const label = isGate ? item.id.toUpperCase() : item.id.replace(/p\ds/,'');
      const completedInfo = st.completedDate ? ' ('+fmtDate(st.completedDate)+(st.completedBy?' by '+esc(userName(st.completedBy)):'')+')' : '';
      const linksHtml = links.length ? '<div style="margin-top:4px;display:flex;flex-wrap:wrap;gap:4px">' + links.map(l =>
        '<span style="display:inline-flex;align-items:center;gap:4px;background:#e8f0ec;border:1px solid #a3c9b3;border-radius:4px;padding:2px 8px;font-size:11px">' +
        '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#4B876C" stroke-width="2"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>' +
        '<a href="'+esc(l.url)+'" target="_blank" rel="noopener" style="color:#4B876C;text-decoration:none;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" onclick="event.stopPropagation()" title="'+esc(l.url)+'">'+esc(l.label || l.url)+'</a>' +
        '<button onclick="event.stopPropagation();removeLink(\''+esc(c.id)+'\',\''+esc(item.id)+'\',\''+esc(l.id)+'\')" style="background:none;border:none;cursor:pointer;color:#c62828;font-size:12px;padding:0;line-height:1" title="Remove link">\u00d7</button></span>'
      ).join('') + '</div>' : '';
      return `<div class="step-item ${esc(st.status)} ${isGate?'gate-item':''}">
        <div class="step-num-badge" style="background:${badgeBg}">${esc(isGate?item.id.toUpperCase():label)}</div>
        <div class="step-info">
          <div class="step-name">${esc(item.name)}${item.isNew?' <span style="background:var(--purple);color:#fff;font-size:9px;padding:1px 5px;border-radius:3px;font-weight:700">NEW</span>':''}${st.status==='completed'?'<span style="font-size:10px;color:var(--green);margin-left:6px">'+esc(completedInfo)+'</span>':''}</div>
          <div class="step-desc-text">${esc(item.desc)}</div>
          ${st.note?'<div style="margin-top:4px;padding:6px 8px;background:var(--amber-light);border-radius:6px;font-size:11px;color:#6d4c00"><strong>Note:</strong> '+esc(st.note)+'</div>':''}
          ${st.clientActionNote?'<div style="margin-top:4px;padding:6px 8px;background:#fff3e0;border:1.5px solid #ffb74d;border-radius:6px;font-size:11px;color:#e65100;display:flex;align-items:center;gap:6px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#e65100" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg><span><strong>Client Action:</strong> '+esc(st.clientActionNote)+'</span></div>':''}
          ${(st.clientActionNote && st.clientActionResponse)?'<div style="margin-top:4px;padding:6px 8px;background:#e8f0ec;border:1.5px solid #4B876C;border-radius:6px;font-size:11px;color:#1a3a2a;display:flex;align-items:center;gap:6px"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#4B876C" stroke-width="2"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z"/></svg><span><strong>Client Response:</strong> '+esc(st.clientActionResponse)+'<span style="color:var(--muted);font-size:10px;margin-left:6px">'+(st.clientActionRespondedAt?fmtDateTime(st.clientActionRespondedAt):'')+'</span></span></div>':''}
          ${linksHtml}
        </div>
        <div class="step-actions">
          <button class="step-status-btn ${st.status==='pending'?'active-pending':''}" onclick="event.stopPropagation();setStepStatus('${esc(c.id)}','${esc(item.id)}','pending')" title="Pending">\u25cb</button>
          <button class="step-status-btn ${st.status==='in_progress'?'active-progress':''}" onclick="event.stopPropagation();setStepStatus('${esc(c.id)}','${esc(item.id)}','in_progress')" title="In Progress">\u25d0</button>
          <button class="step-status-btn ${st.status==='completed'?'active-done':''}" onclick="event.stopPropagation();setStepStatus('${esc(c.id)}','${esc(item.id)}','completed')" title="Done">\u25cf</button>
          <button class="step-status-btn ${st.status==='blocked'?'active-blocked':''}" onclick="event.stopPropagation();setStepStatus('${esc(c.id)}','${esc(item.id)}','blocked')" title="Blocked">\u2715</button>
          <button class="step-notes-btn ${st.note?'has-note':''}" onclick="event.stopPropagation();openNoteModal('${esc(c.id)}','${esc(item.id)}')" title="${st.note?'Edit note':'Add note'}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 00-2 2v14a2 2 0 002 2h14a2 2 0 002-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 013 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
          </button>
          <button class="step-notes-btn ${links.length?'has-note':''}" onclick="event.stopPropagation();openLinkModal('${esc(c.id)}','${esc(item.id)}')" title="${links.length?links.length+' link(s)':'Attach link'}" style="${links.length?'color:#4B876C':''}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>
          </button>
          <button class="step-notes-btn ${st.clientActionNote?'has-note':''}" onclick="event.stopPropagation();openClientActionModal('${esc(c.id)}','${esc(item.id)}')" title="${st.clientActionNote?'Edit client action request':'Request client action'}" style="${st.clientActionNote?'color:#e65100':''}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          </button>
        </div>
      </div>`;
    }).join('');
  }

  function buildPhaseBlock(phase) {
    const pp = phaseProgress(c, phase.id);
    const cls = phase.id==='phase1'?'phase1':phase.id==='phase2'?'phase2':'phase3';
    return `<div class="phase-section"><div class="phase-section-header ${cls}"><div class="phase-icon" style="background:${phase.color}">${phase.id==='phase1'?'1':phase.id==='phase2'?'2':'3'}</div><h3>${esc(phase.name)}</h3><div class="phase-progress" style="color:${phase.color}">${pp.done}/${pp.total} \u00b7 ${pp.pct}%</div></div><div class="step-list">${renderStepItems(phase)}</div></div>`;
  }

  const statusOpts = ['active','paused','at_risk','completed'].map(s => '<option value="'+s+'"'+(c.status===s?' selected':'')+'>'+s.replace('_',' ')+'</option>').join('');

  return `
    <button class="back-btn" onclick="goBack()"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg> Back</button>
    <div class="detail-header">
      <div class="detail-header-left">
        <h2>${esc(c.company)}${od?'<span class="overdue-tag" style="font-size:11px;margin-left:10px;vertical-align:middle">OVERDUE</span>':''}</h2>
        <div class="company">${c.type==='tc_company'?'TC Company':'Brokerage'} \u00b7 ${esc((c.scenario||'').replace(/-/g,' '))} \u00b7 ${esc(c.contactName||'')}${c.contactEmail?' ('+esc(c.contactEmail)+')':''}</div>
        <div style="margin-top:8px;display:flex;gap:12px;flex-wrap:wrap;font-size:12px;color:var(--muted)">
          ${sU?'<span>Sales: <strong style="color:'+sU.color+'">'+esc(sU.name)+'</strong></span>':''}
          ${oU?'<span>Onboarding: <strong style="color:'+oU.color+'">'+esc(oU.name)+'</strong></span>':''}
          ${c.targetGoLive?'<span>Go-Live: <strong'+(od?' style="color:var(--red)"':'')+'>'+fmtDate(c.targetGoLive)+'</strong></span>':''}
          ${c.txns?'<span>~'+esc(String(c.txns))+' txns/mo</span>':''}
        </div>
      </div>
      <div class="detail-header-right">
        <button class="btn btn-sm btn-outline" onclick="generateOnboardingLink('${esc(c.id)}')" title="Generate & copy onboarding form link">
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 13a5 5 0 007.54.54l3-3a5 5 0 00-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 00-7.54-.54l-3 3a5 5 0 007.07 7.07l1.71-1.71"/></svg>
          ${c.onboardingToken ? 'Copy Form Link' : 'Get Form Link'}
        </button>
        ${c.googleDriveUrl ? '<a href="'+esc(c.googleDriveUrl)+'" target="_blank" rel="noopener" class="btn btn-sm btn-outline" style="text-decoration:none" title="Open Google Drive folder"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 19a2 2 0 01-2 2H4a2 2 0 01-2-2V5a2 2 0 012-2h5l2 3h9a2 2 0 012 2z"/></svg> Drive</a>' : ''}
        <button class="btn btn-sm btn-outline" onclick="openEditClientModal('${esc(c.id)}')">Edit</button>
        <select class="btn btn-outline" style="font-size:12px;cursor:pointer" onchange="updateClientStatus('${esc(c.id)}',this.value)">${statusOpts}</select>
      </div>
    </div>
    ${c.onboardingStatus === 'submitted' ? '<div style="margin:12px 0;padding:10px 16px;background:#e8f5e9;border:1px solid #a5d6a7;border-radius:8px;font-size:13px;color:#2e7d32;display:flex;align-items:center;gap:8px"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2e7d32" stroke-width="2.5" stroke-linecap="round"><polyline points="20 6 9 17 4 12"/></svg> Onboarding form submitted</div>' : c.onboardingStatus === 'in_progress' ? '<div style="margin:12px 0;padding:10px 16px;background:#fff3e0;border:1px solid #ffcc80;border-radius:8px;font-size:13px;color:#e65100;display:flex;align-items:center;gap:8px"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#e65100" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Onboarding form in progress</div>' : ''}
    <div class="detail-progress mb-lg"><div class="detail-progress-bar-wrap"><div class="detail-progress-bar" style="width:${prog.pct}%"></div></div><div class="detail-progress-text"><span>${prog.done} of ${prog.total} steps completed</span><span>${prog.pct}%</span></div></div>
    ${PHASES.map(p => buildPhaseBlock(p)).join('')}
    ${c.notes?'<div class="card" style="margin-top:20px"><div class="card-header"><h3>Client Notes</h3></div><div class="card-body"><p class="text-sm">'+esc(c.notes)+'</p></div></div>':''}`;
}

// ══════════════════════════════════════════════════════════════
// ACTIONS (Server-backed with offline fallback)
// ══════════════════════════════════════════════════════════════
async function setStepStatus(clientId, stepId, status) {
  const c = state.clients.find(cl => cl.id===clientId);
  if (!c) { showToast('Client not found','warn'); return; }
  const prev = (c.steps[stepId] || {}).status;
  if (prev === status) return;

  // Optimistic update
  if (!c.steps[stepId]) c.steps[stepId] = { status:'pending', note:'', completedDate:null, completedBy:null };
  c.steps[stepId].status = status;
  if (status==='completed') { c.steps[stepId].completedDate = now(); c.steps[stepId].completedBy = state.currentUser?.id; }
  else { c.steps[stepId].completedDate = null; c.steps[stepId].completedBy = null; }
  render();

  try {
    if (state.isOffline) throw new Error('offline');
    await api.put(`/api/clients/${clientId}/steps/${stepId}`, { status, note: c.steps[stepId].note });
    // Refresh activities
    const actRes = await api.get('/api/activities?limit=20');
    state.activities = actRes.activities || [];
  } catch(e) {
    await idbCache.queueAction({ type: 'update_step', data: { clientId, stepId, status, note: c.steps[stepId].note } });
  }
  await idbCache.saveState({ clients: state.clients, team: state.team, activities: state.activities, currentUser: state.currentUser });
}

async function updateClientStatus(clientId, status) {
  const c = state.clients.find(cl => cl.id===clientId);
  if (!c) return;
  c.status = status;
  render();
  try {
    if (state.isOffline) throw new Error('offline');
    await api.put(`/api/clients/${clientId}`, { status });
  } catch(e) {
    await idbCache.queueAction({ type: 'update_client', data: { id: clientId, status } });
  }
}

function openNoteModal(clientId, stepId) {
  const c = state.clients.find(cl => cl.id===clientId);
  if (!c) { showToast('Client not found','warn'); return; }
  state.noteTarget = { clientId, stepId };
  const si = ALL_CHECKPOINTS.find(ch => ch.id===stepId);
  document.getElementById('modal-note-title').textContent = 'Note: '+(si?.name||stepId);
  document.getElementById('fn-note').value = (c.steps[stepId] || {}).note || '';
  openModal('modal-note');
}

async function saveStepNote() {
  if (!state.noteTarget) return;
  const { clientId, stepId } = state.noteTarget;
  const c = state.clients.find(cl => cl.id===clientId);
  if (!c) { showToast('Client was deleted','warn'); closeModal('modal-note'); return; }
  const note = document.getElementById('fn-note').value.trim();
  if (!c.steps[stepId]) c.steps[stepId] = { status:'pending', note:'', completedDate:null, completedBy:null };
  c.steps[stepId].note = note;
  closeModal('modal-note');
  render();
  showToast('Note saved','success');
  try {
    if (state.isOffline) throw new Error('offline');
    await api.put(`/api/clients/${clientId}/steps/${stepId}/note`, { note });
  } catch(e) {
    await idbCache.queueAction({ type: 'save_note', data: { clientId, stepId, note } });
  }
}

// ── Link Attachment ──
function openLinkModal(clientId, stepId) {
  const c = state.clients.find(cl => cl.id===clientId);
  if (!c) { showToast('Client not found','warn'); return; }
  state.linkTarget = { clientId, stepId };
  const si = ALL_CHECKPOINTS.find(ch => ch.id===stepId);
  document.getElementById('modal-link-title').textContent = 'Attach Link: '+(si?.name||stepId);
  document.getElementById('fl-url').value = '';
  document.getElementById('fl-label').value = '';
  openModal('modal-link');
  setTimeout(() => document.getElementById('fl-url').focus(), 100);
}

async function saveLinkAttachment() {
  if (!state.linkTarget) return;
  const { clientId, stepId } = state.linkTarget;
  const c = state.clients.find(cl => cl.id===clientId);
  if (!c) { showToast('Client was deleted','warn'); closeModal('modal-link'); return; }
  const url = document.getElementById('fl-url').value.trim();
  const label = document.getElementById('fl-label').value.trim();
  if (!url) { showToast('URL is required','warn'); return; }
  // Basic URL validation
  if (!/^https?:\/\/.+/i.test(url) && !url.startsWith('/')) {
    showToast('Enter a valid URL (http:// or https://)','warn'); return;
  }
  closeModal('modal-link');
  // Optimistic update
  if (!c.steps[stepId]) c.steps[stepId] = { status:'pending', note:'', links:[], completedDate:null, completedBy:null };
  if (!c.steps[stepId].links) c.steps[stepId].links = [];
  const tempLink = { id: uid(), url, label: label || '', addedBy: state.currentUser?.id, addedAt: now() };
  c.steps[stepId].links.push(tempLink);
  render();
  showToast('Link attached','success');
  try {
    if (state.isOffline) throw new Error('offline');
    const serverLink = await api.post(`/api/clients/${clientId}/steps/${stepId}/links`, { url, label });
    // Replace temp link with server response
    const idx = c.steps[stepId].links.findIndex(l => l.id === tempLink.id);
    if (idx >= 0) c.steps[stepId].links[idx] = serverLink;
    // Refresh activities
    const actRes = await api.get('/api/activities?limit=20');
    state.activities = actRes.activities || [];
    render();
  } catch(e) {
    if (!state.isOffline) showToast('Link saved locally, will sync later','warn');
    await idbCache.queueAction({ type: 'add_link', data: { clientId, stepId, url, label } });
  }
  await idbCache.saveState({ clients: state.clients, team: state.team, activities: state.activities, currentUser: state.currentUser });
}

async function removeLink(clientId, stepId, linkId) {
  const c = state.clients.find(cl => cl.id===clientId);
  if (!c) return;
  if (!c.steps[stepId] || !c.steps[stepId].links) return;
  c.steps[stepId].links = c.steps[stepId].links.filter(l => l.id !== linkId);
  render();
  showToast('Link removed','info');
  try {
    if (state.isOffline) throw new Error('offline');
    await api.del(`/api/clients/${clientId}/steps/${stepId}/links/${linkId}`);
  } catch(e) {
    await idbCache.queueAction({ type: 'remove_link', data: { clientId, stepId, linkId } });
  }
  await idbCache.saveState({ clients: state.clients, team: state.team, activities: state.activities, currentUser: state.currentUser });
}

// ── Client Action Request ──
function openClientActionModal(clientId, stepId) {
  const c = state.clients.find(cl => cl.id===clientId);
  if (!c) { showToast('Client not found','warn'); return; }
  state.clientActionTarget = { clientId, stepId };
  const si = ALL_CHECKPOINTS.find(ch => ch.id===stepId);
  document.getElementById('modal-client-action-title').textContent = 'Request Client Action: '+(si?.name||stepId);
  document.getElementById('fca-note').value = (c.steps[stepId] || {}).clientActionNote || '';
  openModal('modal-client-action');
  setTimeout(() => document.getElementById('fca-note').focus(), 100);
}

async function saveClientAction() {
  if (!state.clientActionTarget) return;
  const { clientId, stepId } = state.clientActionTarget;
  const c = state.clients.find(cl => cl.id===clientId);
  if (!c) { showToast('Client was deleted','warn'); closeModal('modal-client-action'); return; }
  const note = document.getElementById('fca-note').value.trim();
  if (!note) { showToast('Please enter an action note','warn'); return; }
  closeModal('modal-client-action');
  // Optimistic update
  if (!c.steps[stepId]) c.steps[stepId] = { status:'pending', note:'', links:[], completedDate:null, completedBy:null, clientActionNote:'' };
  c.steps[stepId].clientActionNote = note;
  render();
  showToast('Client action request sent','success');
  try {
    if (state.isOffline) throw new Error('offline');
    await api.put(`/api/clients/${clientId}/steps/${stepId}/client-action`, { note });
    const actRes = await api.get('/api/activities?limit=20');
    state.activities = actRes.activities || [];
  } catch(e) {
    if (!state.isOffline) showToast('Action request saved locally','warn');
  }
  await idbCache.saveState({ clients: state.clients, team: state.team, activities: state.activities, currentUser: state.currentUser });
}

async function clearClientAction() {
  if (!state.clientActionTarget) return;
  const { clientId, stepId } = state.clientActionTarget;
  const c = state.clients.find(cl => cl.id===clientId);
  if (!c) { closeModal('modal-client-action'); return; }
  closeModal('modal-client-action');
  if (c.steps[stepId]) c.steps[stepId].clientActionNote = '';
  render();
  showToast('Client action cleared','info');
  try {
    if (state.isOffline) throw new Error('offline');
    await api.put(`/api/clients/${clientId}/steps/${stepId}/client-action`, { note: '' });
    const actRes = await api.get('/api/activities?limit=20');
    state.activities = actRes.activities || [];
  } catch(e) {}
  await idbCache.saveState({ clients: state.clients, team: state.team, activities: state.activities, currentUser: state.currentUser });
}

async function deleteClient(id) {
  if (!confirm('Delete this client? This cannot be undone.')) return;
  const c = state.clients.find(cl => cl.id===id);
  const origClients = [...state.clients];
  state.clients = state.clients.filter(cl => cl.id!==id);
  if (state.detailClientId===id) goBack();
  else render();
  try {
    if (state.isOffline) throw new Error('offline');
    await api.del(`/api/clients/${id}`);
    showToast('Client deleted','info');
  } catch(e) {
    if (state.isOffline || e.message === 'offline') {
      await idbCache.queueAction({ type: 'delete_client', data: { id } });
      showToast('Client deleted (offline)','warn');
    } else {
      // Revert optimistic update on server error
      state.clients = origClients;
      render();
      showToast('Failed to delete: ' + e.message, 'warn');
    }
  }
}

// ══════════════════════════════════════════════════════════════
// ONBOARDING LINK
// ══════════════════════════════════════════════════════════════
async function generateOnboardingLink(clientId) {
  const c = state.clients.find(cl => cl.id===clientId);
  if (!c) return;
  if (c.onboardingToken) {
    // Already has a token, just copy the link
    const url = window.location.origin + '/onboarding.html?token=' + c.onboardingToken;
    await navigator.clipboard.writeText(url);
    showToast('Onboarding link copied!','success');
    return;
  }
  try {
    const result = await api.post(`/api/clients/${clientId}/onboarding-token`, {});
    c.onboardingToken = result.token;
    const url = result.url || (window.location.origin + '/onboarding.html?token=' + result.token);
    await navigator.clipboard.writeText(url);
    showToast('Onboarding link generated & copied!','success');
    render();
  } catch(e) {
    showToast('Failed to generate link: '+e.message,'warn');
  }
}

// ══════════════════════════════════════════════════════════════
// MODALS
// ══════════════════════════════════════════════════════════════
function openModal(id) { document.getElementById(id).classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }

function openAddClientModal() {
  state.editingClientId = null;
  document.getElementById('modal-client-title').textContent = 'Add New Client';
  document.getElementById('btn-save-client').textContent = 'Save Client';
  ['f-company','f-contact','f-email','f-txns','f-notes','f-drive-url'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('f-golive').value = '';
  document.getElementById('f-type').value = 'brokerage';
  document.getElementById('f-scenario').value = 'single-office';
  clearFormErrors();
  populateTeamSelects();
  openModal('modal-client');
}

function openEditClientModal(id) {
  const c = state.clients.find(cl => cl.id===id);
  if (!c) return;
  state.editingClientId = id;
  document.getElementById('modal-client-title').textContent = 'Edit Client';
  document.getElementById('btn-save-client').textContent = 'Update Client';
  document.getElementById('f-company').value = c.company;
  document.getElementById('f-type').value = c.type;
  document.getElementById('f-contact').value = c.contactName || '';
  document.getElementById('f-email').value = c.contactEmail || '';
  document.getElementById('f-scenario').value = c.scenario || 'single-office';
  document.getElementById('f-txns').value = c.txns || '';
  document.getElementById('f-golive').value = c.targetGoLive || '';
  document.getElementById('f-notes').value = c.notes || '';
  document.getElementById('f-drive-url').value = c.googleDriveUrl || '';
  clearFormErrors();
  populateTeamSelects();
  setTimeout(() => {
    if (c.salesLead) document.getElementById('f-sales').value = c.salesLead;
    if (c.onboardingLead) document.getElementById('f-onboarding').value = c.onboardingLead;
  }, 0);
  openModal('modal-client');
}

function clearFormErrors() {
  document.querySelectorAll('.form-group.has-error').forEach(el => el.classList.remove('has-error'));
}

async function saveClient() {
  clearFormErrors();
  let valid = true;
  const company = document.getElementById('f-company').value.trim();
  if (!company) { document.getElementById('fg-company').classList.add('has-error'); valid = false; }
  const contactName = document.getElementById('f-contact').value.trim();
  if (!contactName) { document.getElementById('fg-contact').classList.add('has-error'); valid = false; }
  const email = document.getElementById('f-email').value.trim();
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { document.getElementById('fg-email').classList.add('has-error'); valid = false; }
  const txnsRaw = document.getElementById('f-txns').value;
  const txns = txnsRaw ? parseInt(txnsRaw, 10) : null;
  if (txnsRaw && (isNaN(txns) || txns < 0 || txns > 99999)) { document.getElementById('fg-txns').classList.add('has-error'); valid = false; }
  if (!valid) return;

  const data = {
    company,
    type: document.getElementById('f-type').value,
    contactName,
    contactEmail: email,
    scenario: document.getElementById('f-scenario').value,
    salesLead: document.getElementById('f-sales').value || null,
    onboardingLead: document.getElementById('f-onboarding').value || null,
    txns, targetGoLive: document.getElementById('f-golive').value || null,
    notes: document.getElementById('f-notes').value.trim(),
    googleDriveUrl: document.getElementById('f-drive-url').value.trim()
  };

  closeModal('modal-client');
  try {
    if (state.isOffline) throw new Error('offline');
    if (state.editingClientId) {
      const updated = await api.put(`/api/clients/${state.editingClientId}`, data);
      const idx = state.clients.findIndex(cl => cl.id===state.editingClientId);
      if (idx >= 0) state.clients[idx] = ensureSteps(updated);
      showToast('Client updated','success');
    } else {
      const created = await api.post('/api/clients', data);
      state.clients.unshift(ensureSteps(created));
      showToast('Client added','success');
    }
    // Refresh activities
    const actRes = await api.get('/api/activities?limit=60');
    state.activities = actRes.activities || [];
  } catch(e) {
    if (state.editingClientId) {
      const idx = state.clients.findIndex(cl => cl.id===state.editingClientId);
      if (idx >= 0) Object.assign(state.clients[idx], data);
      await idbCache.queueAction({ type: 'update_client', data: { id: state.editingClientId, ...data } });
      showToast('Client updated (offline)','warn');
    } else {
      const offlineClient = { id: uid(), ...data, status: 'active', steps: {}, createdAt: now() };
      ensureSteps(offlineClient);
      state.clients.unshift(offlineClient);
      await idbCache.queueAction({ type: 'create_client', data });
      showToast('Client added (offline)','warn');
    }
  }
  render();
  await idbCache.saveState({ clients: state.clients, team: state.team, activities: state.activities, currentUser: state.currentUser });
}

async function saveTeamMember() {
  const name = document.getElementById('ft-name').value.trim();
  if (!name) { document.getElementById('fg-tname').classList.add('has-error'); return; }
  document.getElementById('fg-tname').classList.remove('has-error');
  const data = { name, role: document.getElementById('ft-role').value, email: document.getElementById('ft-email').value.trim(), type: document.getElementById('ft-type').value };
  closeModal('modal-team');
  try {
    if (state.isOffline) throw new Error('offline');
    const member = await api.post('/api/team', data);
    state.team.push(member);
    showToast(name+' added to team','success');
  } catch(e) {
    const colors = ['#4B876C','#00838f','#2e7d32','#7b1fa2','#c62828','#ef6c00','#283593','#00695c','#4e342e','#37474f'];
    state.team.push({ id: uid(), ...data, color: colors[state.team.length%colors.length], isDefault: false });
    await idbCache.queueAction({ type: 'create_team', data });
    showToast(name+' added (offline)','warn');
  }
  render();
  document.getElementById('ft-name').value = '';
  document.getElementById('ft-email').value = '';
}

async function removeTeamMember(id) {
  const m = state.team.find(t => t.id===id);
  if (!confirm('Remove '+m?.name+'?')) return;
  state.team = state.team.filter(t => t.id!==id);
  render();
  showToast(m?.name+' removed','info');
  try {
    if (state.isOffline) throw new Error('offline');
    await api.del(`/api/team/${id}`);
  } catch(e) {
    await idbCache.queueAction({ type: 'delete_team', data: { id } });
  }
}

async function clearActivities() {
  if (!confirm('Clear all activity?')) return;
  state.activities = [];
  render();
  try { if (!state.isOffline) await api.del('/api/activities'); } catch(e) {}
}

function populateTeamSelects() {
  const salesSel = document.getElementById('f-sales');
  const obSel = document.getElementById('f-onboarding');
  if (salesSel) {
    const st = state.team.filter(t => t.role==='Sales');
    salesSel.innerHTML = '<option value="">\u2014 Select \u2014</option>' + st.map(t => '<option value="'+t.id+'">'+esc(t.name)+'</option>').join('');
  }
  if (obSel) {
    const ot = state.team.filter(t => t.role.includes('Onboarding')||t.role.includes('Account'));
    obSel.innerHTML = '<option value="">\u2014 Select \u2014</option>' + ot.map(t => '<option value="'+t.id+'">'+esc(t.name)+'</option>').join('');
  }
}

// ══════════════════════════════════════════════════════════════
// EXPORT / IMPORT
// ══════════════════════════════════════════════════════════════
async function exportData(format) {
  if (!format) format = 'xlsx';
  try {
    if (state.isOffline) {
      // Export from local cache as JSON (no Excel generation offline)
      const json = JSON.stringify({ clients: state.clients, team: state.team, activities: state.activities, exportDate: now() }, null, 2);
      downloadFile(new Blob([json], { type:'application/json' }), 'ReBillion_PM_Backup_'+new Date().toISOString().slice(0,10)+'.json');
      showToast('Backup exported (JSON, offline)','success');
      return;
    }
    const endpoint = format === 'xlsx' ? '/api/backup/export-xlsx' : '/api/backup/export';
    const res = await fetch(endpoint);
    if (res.status === 401) { window.location.href = '/login.html'; return; }
    if (!res.ok) { const err = await res.json().catch(() => ({ message: 'Export failed' })); throw new Error(err.message); }
    const blob = await res.blob();
    const ext = format === 'xlsx' ? '.xlsx' : '.json';
    downloadFile(blob, 'ReBillion_PM_Backup_'+new Date().toISOString().slice(0,10)+ext);
    showToast('Backup exported ('+format.toUpperCase()+')','success');
  } catch(e) {
    showToast('Export failed: '+e.message,'warn');
  }
}

function downloadFile(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function importData(event) {
  const file = event.target.files[0];
  if (!file) return;
  if (!confirm('Import will REPLACE all current data. Are you sure?')) { event.target.value=''; return; }

  const isJSON = file.name.endsWith('.json');
  const isXLSX = file.name.endsWith('.xlsx');
  if (!isJSON && !isXLSX) {
    showToast('Please select a .json or .xlsx backup file','warn');
    event.target.value = '';
    return;
  }

  if (isJSON) {
    const reader = new FileReader();
    reader.onload = async function(e) {
      try {
        const parsed = JSON.parse(e.target.result);
        if (!parsed.clients || !parsed.team) throw new Error('Invalid backup file');
        if (state.isOffline) {
          state.clients = parsed.clients.map(ensureSteps);
          state.team = parsed.team;
          state.activities = parsed.activities || [];
          await idbCache.saveState({ clients: state.clients, team: state.team, activities: state.activities, currentUser: state.currentUser });
          showToast('Data imported (offline)','warn');
        } else {
          await api.post('/api/backup/import', parsed);
          await loadAllData();
          showToast('Data imported successfully','success');
        }
        render();
      } catch(err) {
        showToast('Import failed: '+err.message,'warn');
      }
      event.target.value = '';
    };
    reader.readAsText(file);
  } else {
    // XLSX import — send binary to server for parsing
    try {
      const formData = new FormData();
      formData.append('file', file);
      const csrfToken = getCSRFToken();
      const headers = {};
      if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
      const res = await fetch('/api/backup/import-xlsx', { method: 'POST', headers, body: formData });
      if (res.status === 401) { window.location.href = '/login.html'; return; }
      if (!res.ok) { const err = await res.json().catch(() => ({ message: 'Import failed' })); throw new Error(err.message); }
      await loadAllData();
      render();
      showToast('Excel data imported successfully','success');
    } catch(err) {
      showToast('Import failed: '+err.message,'warn');
    }
    event.target.value = '';
  }
}

// ══════════════════════════════════════════════════════════════
// LOGOUT
// ══════════════════════════════════════════════════════════════
async function handleLogout() {
  try { await api.post('/api/auth/logout', {}); } catch(e) {}
  window.location.href = '/login.html';
}

// ══════════════════════════════════════════════════════════════
// KEYBOARD SHORTCUTS
// ══════════════════════════════════════════════════════════════
document.addEventListener('keydown', function(e) {
  if (e.key==='Escape') {
    document.querySelectorAll('.modal-overlay.active').forEach(m => m.classList.remove('active'));
  }
  if ((e.ctrlKey||e.metaKey) && e.key==='n' && !e.target.closest('.modal') && e.target.tagName!=='INPUT' && e.target.tagName!=='TEXTAREA') {
    e.preventDefault(); openAddClientModal();
  }
  if (e.key==='Enter' && e.target.classList.contains('nav-item')) {
    e.target.click();
  }
});

// ══════════════════════════════════════════════════════════════
// INIT
// ══════════════════════════════════════════════════════════════
(async function init() {
  await idbCache.init();
  const loaded = await loadAllData();
  if (!loaded) {
    window.location.href = '/login.html';
    return;
  }
  // Set user info in sidebar
  if (state.currentUser) {
    document.getElementById('current-user-avatar').textContent = state.currentUser.name[0];
    document.getElementById('current-user-name').textContent = state.currentUser.name;
    document.getElementById('current-user-role').textContent = state.currentUser.role;
  }
  // Hide loading screen
  document.getElementById('loading-screen').style.display = 'none';
  render();
})();
