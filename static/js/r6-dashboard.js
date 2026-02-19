/**
 * R6 FHIR Agent Dashboard — Interactive Showcase
 *
 * Demonstrates MCP tool-loop, FHIR R6 CRUD, tenant isolation,
 * de-identification, audit trail, human-in-the-loop, and OAuth flows.
 */

const API = '/r6/fhir';
const TENANT = 'demo-tenant';

// --------------- API Client ---------------

async function r6Fetch(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', 'X-Tenant-Id': TENANT, ...(opts.headers || {}) };
  const res = await fetch(`${API}${path}`, { ...opts, headers });
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = text; }
  return { status: res.status, headers: Object.fromEntries(res.headers.entries()), body };
}

// --------------- JSON Syntax Highlighting ---------------

function highlightJSON(obj, indent = 2) {
  const raw = typeof obj === 'string' ? obj : JSON.stringify(obj, null, indent);
  return raw
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"([^"]+)":/g, '<span class="jk">"$1"</span>:')
    .replace(/: "(.*?)"/g, ': <span class="js">"$1"</span>')
    .replace(/: (-?\d+\.?\d*)/g, ': <span class="jn">$1</span>')
    .replace(/: (true|false)/g, ': <span class="jb">$1</span>')
    .replace(/: (null)/g, ': <span class="jl">$1</span>');
}

function showResult(id, data, status) {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerHTML = highlightJSON(typeof data === 'object' ? data : { raw: data });
  if (status) {
    const badge = status < 300 ? 'success' : status < 500 ? 'warning' : 'danger';
    el.insertAdjacentHTML('beforebegin',
      `<div class="r6-tag r6-tag-${badge === 'success' ? 'read' : badge === 'warning' ? 'write' : 'security'}" style="margin-bottom:0.5rem">HTTP ${status}</div>`);
  }
}

function clearResult(id) {
  const el = document.getElementById(id);
  if (el) { el.innerHTML = ''; el.previousElementSibling?.classList.contains('r6-tag') && el.previousElementSibling.remove(); }
}

function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `r6-status-msg ${type}`;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

function setLoading(btnId, loading) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  if (loading) {
    btn.disabled = true;
    btn._origHTML = btn.innerHTML;
    btn.innerHTML = '<span class="r6-spinner"></span> Running...';
  } else {
    btn.disabled = false;
    if (btn._origHTML) btn.innerHTML = btn._origHTML;
  }
}

// --------------- 1. System Health ---------------

async function loadSystemHealth() {
  try {
    const res = await r6Fetch('/metadata');
    if (res.status === 200) {
      const cs = res.body;
      document.getElementById('stat-version').textContent = cs.software?.version || '—';
      document.getElementById('stat-fhir').textContent = cs.fhirVersion || '—';
      const types = (cs.rest?.[0]?.resource || []).map(r => r.type);
      document.getElementById('stat-resources').textContent = types.length;
      const ops = (cs.rest?.[0]?.operation || []).map(o => o.name);
      document.getElementById('stat-operations').textContent = ops.length;
      document.getElementById('stat-status').innerHTML = '<span style="color:var(--r6-success)">Online</span>';
    }
  } catch (e) {
    document.getElementById('stat-status').innerHTML = '<span style="color:var(--r6-danger)">Offline</span>';
  }
}

// --------------- 2. Patient Explorer ---------------

async function loadSamplePatient() {
  setLoading('btn-load-patient', true);
  const patient = {
    resourceType: 'Patient', id: 'demo-pt-1',
    name: [{ family: 'Martinez', given: ['Elena', 'Sofia'] }],
    gender: 'female', birthDate: '1985-07-22',
    identifier: [{ system: 'http://hospital.example/mrn', value: 'MRN98765432' }],
    address: [{ line: ['742 Evergreen Terrace'], city: 'Portland', state: 'OR', postalCode: '97201', country: 'US' }],
    telecom: [{ system: 'phone', value: '503-555-0142', use: 'home' }]
  };

  // Get a step-up token first
  const tokenRes = await r6Fetch('/internal/step-up-token', { method: 'POST', body: JSON.stringify({ tenant_id: TENANT }) });
  const token = tokenRes.body?.token;

  const res = await r6Fetch('/Patient', {
    method: 'POST',
    headers: { 'X-Step-Up-Token': token || '' },
    body: JSON.stringify(patient)
  });

  if (res.status === 201 || res.status === 200) {
    toast('Patient created successfully', 'success');
    // Now read it back (redacted)
    const readRes = await r6Fetch(`/Patient/demo-pt-1`);
    showResult('patient-result', readRes.body);
    document.getElementById('patient-etag').textContent = readRes.headers['etag'] || '—';
  } else {
    showResult('patient-result', res.body);
  }
  setLoading('btn-load-patient', false);
}

async function searchPatients() {
  setLoading('btn-search-patients', true);
  const res = await r6Fetch('/Patient?_count=10');
  showResult('patient-result', res.body);
  setLoading('btn-search-patients', false);
}

async function searchPatientCount() {
  setLoading('btn-patient-count', true);
  const res = await r6Fetch('/Patient?_summary=count');
  showResult('patient-result', res.body);
  setLoading('btn-patient-count', false);
}

// --------------- 3. Agent Tool Loop ---------------

const TOOL_DEFS = [
  { name: 'context.get', desc: 'Retrieve bounded context envelope', tier: 'read' },
  { name: 'fhir.read', desc: 'Read a FHIR resource (redacted)', tier: 'read' },
  { name: 'fhir.search', desc: 'Search FHIR resources', tier: 'read' },
  { name: 'fhir.validate', desc: 'Validate a resource against R6', tier: 'read' },
  { name: 'fhir.propose_write', desc: 'Validate + preview a write (no commit)', tier: 'write' },
  { name: 'fhir.commit_write', desc: 'Commit a write (requires step-up)', tier: 'write' },
];

function renderToolCards() {
  const container = document.getElementById('tool-cards');
  if (!container) return;
  container.innerHTML = TOOL_DEFS.map(t => `
    <div class="tool-card" data-tool="${t.name}" onclick="selectTool('${t.name}')">
      <div class="d-flex align-items-center gap-2">
        <span class="tool-name">${t.name}</span>
        <span class="r6-tag r6-tag-${t.tier === 'read' ? 'read' : 'write'}">${t.tier}</span>
      </div>
      <div class="tool-desc">${t.desc}</div>
    </div>
  `).join('');
}

function selectTool(name) {
  document.querySelectorAll('.tool-card').forEach(c => c.classList.toggle('active', c.dataset.tool === name));
  document.getElementById('selected-tool').textContent = name;
  // Pre-fill example input
  const examples = {
    'fhir.read': { resource_type: 'Patient', resource_id: 'demo-pt-1' },
    'fhir.search': { resource_type: 'Patient', _count: 5 },
    'fhir.validate': { resource: { resourceType: 'Observation', status: 'final', code: { coding: [{ system: 'http://loinc.org', code: '2339-0' }] } } },
    'context.get': { context_id: '(ingest a bundle first)' },
    'fhir.propose_write': { resource: { resourceType: 'Observation', id: 'new-obs', status: 'preliminary', code: { coding: [{ system: 'http://loinc.org', code: '8867-4' }] } }, operation: 'create' },
    'fhir.commit_write': { resource: { resourceType: 'Patient', id: 'demo-pt-1', name: [{ family: 'Martinez-Updated' }], gender: 'female', birthDate: '1985-07-22' }, operation: 'update' },
  };
  document.getElementById('tool-input').value = JSON.stringify(examples[name] || {}, null, 2);
}

async function executeSelectedTool() {
  const toolName = document.getElementById('selected-tool').textContent;
  if (!toolName || toolName === '—') { toast('Select a tool first', 'error'); return; }

  setLoading('btn-exec-tool', true);
  clearResult('tool-result');

  let input;
  try {
    input = JSON.parse(document.getElementById('tool-input').value);
  } catch { toast('Invalid JSON input', 'error'); setLoading('btn-exec-tool', false); return; }

  let res;
  try {
    switch (toolName) {
      case 'fhir.read':
        res = await r6Fetch(`/${input.resource_type}/${input.resource_id}`);
        break;
      case 'fhir.search': {
        const params = new URLSearchParams();
        if (input.patient) params.set('patient', input.patient);
        if (input._count) params.set('_count', input._count);
        if (input._summary) params.set('_summary', input._summary);
        res = await r6Fetch(`/${input.resource_type}?${params}`);
        break;
      }
      case 'fhir.validate':
        res = await r6Fetch(`/${input.resource.resourceType}/$validate`, {
          method: 'POST', body: JSON.stringify(input.resource)
        });
        break;
      case 'context.get':
        res = await r6Fetch(`/context/${input.context_id}`);
        break;
      case 'fhir.propose_write':
        // Propose = validate only
        res = await r6Fetch(`/${input.resource.resourceType}/$validate`, {
          method: 'POST', body: JSON.stringify(input.resource)
        });
        res.body = { operation: input.operation, validation: res.body, requires_step_up: true, message: 'Validated. Provide X-Step-Up-Token to commit.' };
        break;
      case 'fhir.commit_write': {
        const tkRes = await r6Fetch('/internal/step-up-token', { method: 'POST', body: JSON.stringify({ tenant_id: TENANT }) });
        const tok = tkRes.body?.token;
        const method = input.operation === 'create' ? 'POST' : 'PUT';
        const url = input.operation === 'create' ? `/${input.resource.resourceType}` : `/${input.resource.resourceType}/${input.resource.id}`;
        res = await r6Fetch(url, {
          method,
          headers: { 'X-Step-Up-Token': tok || '', 'X-Human-Confirmed': 'true' },
          body: JSON.stringify(input.resource)
        });
        break;
      }
      default:
        res = { status: 400, body: { error: 'Unknown tool' } };
    }
  } catch (e) {
    res = { status: 500, body: { error: e.message } };
  }

  showResult('tool-result', res.body, res.status);
  setLoading('btn-exec-tool', false);
  refreshAuditFeed();
}

// --------------- 4. Context Builder ---------------

async function ingestDemoBundle() {
  setLoading('btn-ingest', true);
  clearResult('context-result');

  const bundle = {
    resourceType: 'Bundle', type: 'collection',
    entry: [
      { resource: { resourceType: 'Patient', id: 'ctx-pt-1', name: [{ family: 'Nguyen', given: ['Tran'] }], gender: 'male', birthDate: '1972-11-03', identifier: [{ value: 'MRN555111' }] } },
      { resource: { resourceType: 'Observation', id: 'ctx-obs-1', status: 'final', code: { coding: [{ system: 'http://loinc.org', code: '2339-0', display: 'Glucose' }] }, subject: { reference: 'Patient/ctx-pt-1' }, valueQuantity: { value: 110, unit: 'mg/dL' } } },
      { resource: { resourceType: 'Observation', id: 'ctx-obs-2', status: 'final', code: { coding: [{ system: 'http://loinc.org', code: '8867-4', display: 'Heart rate' }] }, subject: { reference: 'Patient/ctx-pt-1' }, valueQuantity: { value: 72, unit: '/min' } } },
    ]
  };

  const res = await r6Fetch('/Bundle/$ingest-context', { method: 'POST', body: JSON.stringify(bundle) });
  showResult('context-result', res.body, res.status);

  if (res.status === 201 && res.body.context_id) {
    window._lastContextId = res.body.context_id;
    document.getElementById('last-context-id').textContent = res.body.context_id;
    toast(`Context created: ${res.body.resource_count} resources`, 'success');
  }
  setLoading('btn-ingest', false);
  refreshAuditFeed();
}

async function retrieveContext() {
  const cid = window._lastContextId || document.getElementById('context-id-input')?.value;
  if (!cid) { toast('Ingest a bundle first to get a context ID', 'error'); return; }
  setLoading('btn-get-context', true);
  const res = await r6Fetch(`/context/${cid}`);
  showResult('context-result', res.body, res.status);
  setLoading('btn-get-context', false);
}

// --------------- 5. De-identification ---------------

async function runDeidentify() {
  setLoading('btn-deidentify', true);

  // Ensure patient exists
  const tkRes = await r6Fetch('/internal/step-up-token', { method: 'POST', body: JSON.stringify({ tenant_id: TENANT }) });
  const token = tkRes.body?.token;
  await r6Fetch('/Patient', {
    method: 'POST',
    headers: { 'X-Step-Up-Token': token || '' },
    body: JSON.stringify({
      resourceType: 'Patient', id: 'deid-pt-1',
      name: [{ family: 'Washington', given: ['George'] }],
      birthDate: '1978-04-12', gender: 'male',
      identifier: [{ system: 'http://example.org/ssn', value: '123-45-6789' }],
      address: [{ line: ['1600 Pennsylvania Ave'], city: 'Washington', state: 'DC', postalCode: '20500' }],
      telecom: [{ system: 'phone', value: '202-456-1111' }]
    })
  });

  // Read raw (redacted but with structure)
  const rawRes = await r6Fetch('/Patient/deid-pt-1');
  document.getElementById('deid-raw').innerHTML = highlightJSON(rawRes.body);

  // De-identify
  const deidRes = await r6Fetch('/Patient/deid-pt-1/$deidentify');
  document.getElementById('deid-safe').innerHTML = highlightJSON(deidRes.body);

  setLoading('btn-deidentify', false);
  refreshAuditFeed();
}

// --------------- 6. Human-in-the-Loop Demo ---------------

async function demoHumanInLoop() {
  setLoading('btn-hitl-demo', true);
  clearResult('hitl-result');

  const obs = {
    resourceType: 'Observation', id: 'hitl-obs-1', status: 'final',
    code: { coding: [{ system: 'http://loinc.org', code: '2339-0' }] },
    valueQuantity: { value: 200, unit: 'mg/dL' }
  };

  // Step 1: Try without human confirmation → expect 428
  const tkRes = await r6Fetch('/internal/step-up-token', { method: 'POST', body: JSON.stringify({ tenant_id: TENANT }) });
  const token = tkRes.body?.token;

  const res1 = await r6Fetch('/Observation', {
    method: 'POST',
    headers: { 'X-Step-Up-Token': token || '' },
    body: JSON.stringify(obs)
  });

  const step1 = { step: '1 — Without X-Human-Confirmed', status: res1.status, body: res1.body };

  // Step 2: With human confirmation → expect 201
  const tkRes2 = await r6Fetch('/internal/step-up-token', { method: 'POST', body: JSON.stringify({ tenant_id: TENANT }) });
  const token2 = tkRes2.body?.token;
  obs.id = 'hitl-obs-2';
  const res2 = await r6Fetch('/Observation', {
    method: 'POST',
    headers: { 'X-Step-Up-Token': token2 || '', 'X-Human-Confirmed': 'true' },
    body: JSON.stringify(obs)
  });

  const step2 = { step: '2 — With X-Human-Confirmed: true', status: res2.status, body: res2.body };

  showResult('hitl-result', { walkthrough: [step1, step2] });
  toast('Human-in-the-loop demo complete', 'success');
  setLoading('btn-hitl-demo', false);
  refreshAuditFeed();
}

// --------------- 7. OAuth / Security ---------------

async function demoOAuthFlow() {
  setLoading('btn-oauth-demo', true);
  clearResult('oauth-result');

  const steps = [];

  // Step 1: Register client
  const regRes = await r6Fetch('/oauth/register', {
    method: 'POST',
    body: JSON.stringify({ client_name: 'Demo Agent', redirect_uris: ['http://localhost:5000/callback'], scope: 'fhir.read context.read' })
  });
  steps.push({ step: '1 — Dynamic Client Registration', status: regRes.status, client_id: regRes.body?.client_id });

  if (regRes.status !== 201) {
    showResult('oauth-result', { steps });
    setLoading('btn-oauth-demo', false);
    return;
  }

  const clientId = regRes.body.client_id;

  // Step 2: PKCE challenge
  const verifier = Array.from(crypto.getRandomValues(new Uint8Array(32)), b => b.toString(16).padStart(2, '0')).join('');
  const encoder = new TextEncoder();
  const hash = await crypto.subtle.digest('SHA-256', encoder.encode(verifier));
  const challenge = btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

  const authRes = await r6Fetch(`/oauth/authorize?client_id=${clientId}&redirect_uri=http://localhost:5000/callback&scope=fhir.read&code_challenge=${challenge}&code_challenge_method=S256&state=demo-state`);
  steps.push({ step: '2 — Authorization (PKCE S256)', status: authRes.status, code: authRes.body?.code ? '***' + authRes.body.code.slice(-8) : null });

  if (!authRes.body?.code) {
    showResult('oauth-result', { steps });
    setLoading('btn-oauth-demo', false);
    return;
  }

  // Step 3: Token exchange
  const tokenRes = await r6Fetch('/oauth/token', {
    method: 'POST',
    body: JSON.stringify({ grant_type: 'authorization_code', code: authRes.body.code, code_verifier: verifier, client_id: clientId })
  });
  steps.push({ step: '3 — Token Exchange', status: tokenRes.status, token_type: tokenRes.body?.token_type, scope: tokenRes.body?.scope, expires_in: tokenRes.body?.expires_in });

  // Step 4: Revoke
  if (tokenRes.body?.access_token) {
    const revRes = await r6Fetch('/oauth/revoke', {
      method: 'POST',
      body: JSON.stringify({ token: tokenRes.body.access_token })
    });
    steps.push({ step: '4 — Token Revocation', status: revRes.status });
  }

  showResult('oauth-result', { walkthrough: steps });
  toast('OAuth 2.1 + PKCE flow complete', 'success');
  setLoading('btn-oauth-demo', false);
}

// --------------- 8. Audit Trail ---------------

async function refreshAuditFeed() {
  try {
    const res = await r6Fetch('/AuditEvent?_count=20');
    if (res.status !== 200) return;

    const entries = res.body.entry || [];
    const feed = document.getElementById('audit-feed');
    if (!feed) return;

    if (entries.length === 0) {
      feed.innerHTML = '<div class="text-muted" style="padding:1rem;font-size:0.85rem">No audit events yet. Interact with the panels above to generate events.</div>';
      return;
    }

    feed.innerHTML = entries.map(e => {
      const r = e.resource;
      const type = r.type?.display || r.action || '?';
      const entity = r.entity?.[0]?.what?.reference || '';
      const time = r.recorded ? new Date(r.recorded).toLocaleTimeString() : '';
      const ok = r.outcome?.code?.code === '0';
      return `
        <div class="audit-entry">
          <span class="audit-dot ${type}"></span>
          <div>
            <span class="audit-text"><strong>${type}</strong> ${entity}</span>
            <div class="audit-time">${time} — ${ok ? 'success' : 'failure'}</div>
          </div>
        </div>`;
    }).join('');

    document.getElementById('stat-audits').textContent = res.body.total || entries.length;
  } catch { /* silent */ }
}

async function exportAuditNDJSON() {
  setLoading('btn-export-audit', true);
  try {
    const res = await fetch(`${API}/AuditEvent/$export`, { headers: { 'X-Tenant-Id': TENANT } });
    const text = await res.text();
    const blob = new Blob([text], { type: 'application/x-ndjson' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'audit-trail.ndjson'; a.click();
    URL.revokeObjectURL(url);
    toast('Audit trail exported', 'success');
  } catch (e) {
    toast('Export failed: ' + e.message, 'error');
  }
  setLoading('btn-export-audit', false);
}

// --------------- 9. Validate Demo ---------------

async function validateDemo() {
  setLoading('btn-validate', true);
  clearResult('validate-result');
  const input = document.getElementById('validate-input').value;
  let resource;
  try { resource = JSON.parse(input); } catch { toast('Invalid JSON', 'error'); setLoading('btn-validate', false); return; }
  const rt = resource.resourceType;
  if (!rt) { toast('resourceType is required', 'error'); setLoading('btn-validate', false); return; }
  const res = await r6Fetch(`/${rt}/$validate`, { method: 'POST', body: JSON.stringify(resource) });
  showResult('validate-result', res.body, res.status);
  setLoading('btn-validate', false);
}

// --------------- Walkthrough Mode ---------------

const WALKTHROUGH_STEPS = [
  { title: 'Load Sample Patient', action: loadSamplePatient, panel: 'patient-panel' },
  { title: 'Ingest Bundle + Build Context', action: ingestDemoBundle, panel: 'context-panel' },
  { title: 'Execute Agent Tool (fhir.read)', action: async () => { selectTool('fhir.read'); await executeSelectedTool(); }, panel: 'tools-panel' },
  { title: 'De-identify Patient (Safe Harbor)', action: runDeidentify, panel: 'deid-panel' },
  { title: 'Human-in-the-Loop Enforcement', action: demoHumanInLoop, panel: 'hitl-panel' },
  { title: 'Full OAuth 2.1 + PKCE Flow', action: demoOAuthFlow, panel: 'oauth-panel' },
];

let walkthroughIdx = -1;

function startWalkthrough() {
  walkthroughIdx = 0;
  runWalkthroughStep();
}

async function runWalkthroughStep() {
  if (walkthroughIdx >= WALKTHROUGH_STEPS.length) {
    document.getElementById('walkthrough-bar').style.display = 'none';
    toast('Walkthrough complete!', 'success');
    walkthroughIdx = -1;
    return;
  }
  const step = WALKTHROUGH_STEPS[walkthroughIdx];
  const bar = document.getElementById('walkthrough-bar');
  bar.style.display = 'flex';
  bar.querySelector('.step-counter').textContent = `${walkthroughIdx + 1}/${WALKTHROUGH_STEPS.length}`;
  bar.querySelector('.step-text').textContent = step.title;

  // Scroll panel into view
  const panel = document.getElementById(step.panel);
  if (panel) panel.scrollIntoView({ behavior: 'smooth', block: 'center' });

  await step.action();
  walkthroughIdx++;
  // Auto-advance after a brief pause
  setTimeout(runWalkthroughStep, 1200);
}

// --------------- Init ---------------

document.addEventListener('DOMContentLoaded', () => {
  loadSystemHealth();
  renderToolCards();
  refreshAuditFeed();
  // Poll audit feed every 10s
  setInterval(refreshAuditFeed, 10000);
});
