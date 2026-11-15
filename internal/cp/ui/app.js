'use strict';
// Everything shown comes from users and hosts, so it is never parsed as HTML:
// only textContent and DOM nodes are used (a test enforces this).
const $ = (id) => document.getElementById(id);
const el = (tag, text, cls) => { const e = document.createElement(tag); if (text !== undefined) e.textContent = text; if (cls) e.className = cls; return e; };
const clear = (n) => { while (n.firstChild) n.removeChild(n.firstChild); };

let me = { permissions: [] };
let mode = 'simple'; // three screens (alerts, users, apps); 'advanced' shows all of them (ADM-001)
try { if (localStorage.getItem('ztx-mode') === 'advanced') mode = 'advanced'; } catch (e) { mode = 'simple'; }
const can = (p) => Modes.can(me.permissions, p);

let token = null;
try { token = sessionStorage.getItem('ztx-token'); } catch (e) { token = null; }

async function api(method, path, body, raw) {
  const r = await fetch(path, { method, headers: Object.assign({ 'Authorization': 'Bearer ' + token },
    body ? { 'Content-Type': 'application/json' } : {}), body: body ? JSON.stringify(body) : undefined });
  const text = await r.text();
  if (r.status === 401) { signOut(); throw new Error('Your session is not valid. Sign in again.'); }
  if (!r.ok) { let m = text; try { m = JSON.parse(text).message || text; } catch (e) {} throw new Error(r.status + ': ' + m); }
  if (raw) return text;
  return text ? JSON.parse(text) : null;
}

function table(cols, rows) {
  const t = el('table'), h = el('tr');
  cols.forEach((c) => h.appendChild(el('th', c)));
  t.appendChild(h);
  rows.forEach((r) => { const tr = el('tr'); r.forEach((c) => { const td = el('td'); if (c instanceof Node) td.appendChild(c); else td.textContent = c === undefined || c === null ? '' : String(c); tr.appendChild(td); }); t.appendChild(tr); });
  return t;
}
function btn(label, fn, cls) { const b = el('button', label, cls); b.addEventListener('click', async () => { b.disabled = true; try { await fn(); } catch (e) { alert(e.message); } b.disabled = false; }); return b; }
function field(label, input) { const l = el('label', label + ' '); l.appendChild(input); return l; }
const when = (s) => { const d = new Date(s); return isNaN(d) ? '' : d.toLocaleString(); };
const view = () => $('view');
function show(...nodes) { const v = view(); clear(v); nodes.forEach((n) => v.appendChild(n)); }
function failure(e) { show(el('p', e.message, 'err')); }

const tabs = {
  Overview: async () => {
    const [alerts, digest] = await Promise.all([api('GET', '/v1/alerts?open=1'), api('GET', '/v1/digest?format=text', null, true)]);
    const a = el('div'); a.appendChild(el('h2', 'Open alerts'));
    if (!alerts.length) a.appendChild(el('p', 'No open alerts.', 'ok'));
    alerts.forEach((x) => { const c = el('div', undefined, 'card'); c.appendChild(el('strong', x.message)); c.appendChild(el('div', 'What to do: ' + x.recommended_action)); c.appendChild(el('div', 'Opened ' + when(x.opened), 'muted')); a.appendChild(c); });
    const d = el('div'); d.appendChild(el('h2', 'This week')); d.appendChild(el('pre', digest));
    show(a, d);
  },
  Incidents: async () => {
    const list = await api('GET', '/v1/incidents');
    const out = el('div'); out.appendChild(el('h2', 'Incidents (last 24 hours)'));
    out.appendChild(el('p', 'Several things the product saw about one person, put together. Severity is from fixed rules, not a model.', 'muted'));
    if (!list.length) out.appendChild(el('p', 'No incidents.', 'ok'));
    list.forEach((i) => { const c = el('div', undefined, 'card'); const cls = i.severity === 'high' ? 'err' : (i.severity === 'medium' ? 'warn' : 'muted');
      c.appendChild(el('strong', i.severity.toUpperCase() + ': ' + i.summary, cls));
      i.recommended_actions.forEach((a) => c.appendChild(el('div', 'What to do: ' + a)));
      c.appendChild(el('div', 'Risk score ' + i.risk_score + ', last seen ' + when(i.last_seen), 'muted')); out.appendChild(c); });
    show(out);
  },
  Access: async () => {
    const f = { user: el('input'), app: el('input'), action: el('select') };
    ['', 'allow', 'deny', 'warn'].forEach((o) => { const opt = el('option', o || 'any'); opt.value = o; f.action.appendChild(opt); });
    const out = el('div');
    const go = async () => {
      const q = new URLSearchParams({ limit: '100' });
      if (f.user.value) q.set('user', f.user.value); if (f.app.value) q.set('app', f.app.value); if (f.action.value) q.set('action', f.action.value);
      const rows = (await api('GET', '/v1/decisions?' + q)).reverse();
      clear(out);
      out.appendChild(table(['Time', 'Kind', 'User', 'App or host', 'Result', 'Rule', 'Reason'], rows.map((r) => [when(r.ts), r.kind + (r.workspace ? ' (workspace)' : ''), r.user, r.app || r.target, r.action, r.rule, r.reason])));
      if (!rows.length) out.appendChild(el('p', 'Nothing matches.', 'muted'));
    };
    const row = el('div', undefined, 'row');
    row.append(field('User', f.user), field('App', f.app), field('Result', f.action), btn('Search', go, 'primary'));
    show(el('h2', 'Access decisions'), row, out); await go();
  },
  People: async () => {
    const [users, devices, risks, health] = await Promise.all([api('GET', '/v1/users'), api('GET', '/v1/devices'), api('GET', '/v1/risk'), api('GET', '/v1/health')]);
    const healthOf = {}; health.forEach((h) => { healthOf[h.device] = h; });
    const pctText = (v) => (v === undefined || v === null ? '?' : v + '%');
    const healthText = (id) => { const h = healthOf[id]; if (!h) return 'no report'; const t = 'CPU ' + pctText(h.cpu_load_pct) + ', memory ' + pctText(h.mem_used_pct) + ', disk ' + pctText(h.disk_used_pct) + (h.stale ? ' (old report)' : ''); const x = h.experience && h.experience.known ? ' | Experience ' + h.experience.score + '/100: ' + h.experience.explain : ''; return h.findings.length ? t + x + ' - ' + h.findings.map((f) => f.message).join('; ') : t + x; };
    const riskOf = {}; risks.forEach((r) => { riskOf[r.user] = r; });
    const reload = () => tabs.People().catch(failure);
    const isRestricted = (x) => (x.Groups || []).indexOf('restricted') >= 0;
    const actions = (x) => { const d = el('span'); if (x.Disabled || !can('support')) return d;
      d.appendChild(isRestricted(x)
        ? btn('Lift restriction', async () => { await api('POST', '/v1/users/' + encodeURIComponent(x.Subject) + '/unrestrict'); await reload(); })
        : btn('Restrict', async () => { if (confirm('Restrict ' + x.Subject + '? The safe-default policy blocks them within seconds, without waiting for your identity provider.')) { await api('POST', '/v1/users/' + encodeURIComponent(x.Subject) + '/restrict', { reason: 'restricted from the console' }); await reload(); } }));
      if (can('write')) d.appendChild(btn('Disable', async () => { if (confirm('Disable ' + x.Subject + '? Their sessions end within seconds.')) { await api('POST', '/v1/users/' + encodeURIComponent(x.Subject) + '/disable'); await reload(); } }, 'danger'));
      return d; };
    const riskText = (x) => { const r = riskOf[x.Subject]; return r ? r.score + ' (' + r.reasons.join('; ') + ')' : '0'; };
    const u = table(['User', 'Email', 'Groups', 'State', 'Risk', ''], users.map((x) => [x.Subject, x.Email, (x.Groups || []).join(', '), x.Disabled ? 'disabled' : (isRestricted(x) ? 'restricted' : 'active'), riskText(x), actions(x)]));
    const d = table(['Device', 'User', 'State', 'Health', ''], devices.map((x) => [x.id, x.user, x.revoked ? 'revoked' : 'active', healthText(x.id),
      x.revoked || !can('support') ? '' : btn('Revoke', async () => { if (confirm('Revoke device ' + x.id + '?')) { await api('POST', '/v1/devices/' + encodeURIComponent(x.id) + '/revoke'); await reload(); } }, 'danger')]));
    show(el('h2', 'People'), u, el('h2', 'Devices'), d);
  },
  Approvals: async () => {
    const all = await api('GET', '/v1/approvals');
    const reload = () => tabs.Approvals().catch(failure);
    const row = (r) => [when(r.requested), r.user, r.app, r.attempts, r.state === 'approved' ? 'approved until ' + when(r.until) : r.state,
      r.state === 'pending' ? (() => { const d = el('span');
        d.appendChild(btn('Approve 1 hour', async () => { await api('POST', '/v1/approvals/' + r.id + '/approve', { minutes: 60 }); await reload(); }, 'primary'));
        d.appendChild(btn('Approve 8 hours', async () => { await api('POST', '/v1/approvals/' + r.id + '/approve', { minutes: 480 }); await reload(); }));
        d.appendChild(btn('Deny', async () => { await api('POST', '/v1/approvals/' + r.id + '/deny'); await reload(); }, 'danger')); return d; })()
        : (r.state === 'approved' ? btn('End now', async () => { await api('POST', '/v1/approvals/' + r.id + '/end'); await reload(); }, 'danger') : '')];
    show(el('h2', 'Access requests'), el('p', 'People appear here when a rule that requires approval blocks them. Approved access ends on its own.', 'muted'),
      table(['Requested', 'User', 'App', 'Attempts', 'State', ''], all.map(row)));
    if (!all.length) view().appendChild(el('p', 'No requests.', 'muted'));
  },
  Inspection: async () => {
    const cfg = await api('GET', '/v1/inspection');
    const ta = el('textarea'); ta.value = (cfg.exempt || []).join('\n'); ta.style.minHeight = '90px';
    const save = (enabled) => async () => { const exempt = ta.value.split('\n').map((x) => x.trim()).filter(Boolean);
      await api('PUT', '/v1/inspection', { enabled: enabled, exempt: exempt }); await tabs.Inspection(); };
    const dl = btn('Download the inspection certificate', async () => {
      const r = await fetch('/v1/inspection/ca.pem', { headers: { 'Authorization': 'Bearer ' + token } });
      if (!r.ok) throw new Error('Enable inspection first.');
      const blob = await r.blob(); const a = el('a'); a.setAttribute('href', URL.createObjectURL(blob)); a.setAttribute('download', 'inspection-ca.pem'); a.click(); });
    const row = el('div', undefined, 'row');
    row.append(cfg.enabled ? btn('Turn inspection off', save(false), 'danger') : btn('Turn inspection on', save(true), 'primary'), btn('Save exemptions', save(cfg.enabled)), dl);
    show(el('h2', 'Web traffic inspection'),
      el('p', cfg.enabled ? 'Inspection is ON: HTTPS to non-exempt sites is decrypted so rules can use URL paths and methods.' : 'Inspection is OFF: HTTPS passes through untouched and rules see host names only.', cfg.enabled ? 'warn' : 'muted'),
      el('p', 'Devices must trust this tenant\'s inspection certificate (install it in the system or browser trust store, for example with your device management tool) or inspected sites will show certificate errors. Sites that refuse a replaced certificate (banking, health, some apps) belong on the exempt list. The decision log records inspection-handshake-failed for them.', 'muted'),
      el('h2', 'Never decrypt these domains (one per line, subdomains included)'), ta, row);
  },
  Apps: async () => {
    const [segs, pol] = await Promise.all([api('GET', '/v1/segments'), api('GET', '/v1/policies/private').catch(() => null)]);
    const access = {}; Modes.appAccess(segs, pol && pol.policy ? pol.policy : pol).forEach((a) => { access[a.id] = a.access; });
    const who = (id) => { const d = el('div'); (access[id] || []).forEach((l) => d.appendChild(el('div', l, l.indexOf('Nobody') === 0 || l.indexOf('Except') === 0 ? 'muted' : undefined))); return d; };
    const simple = mode !== 'advanced';
    const cols = simple ? ['App', 'Who can reach it'] : ['Name', 'Connector group', 'Class', 'Targets', 'Who can reach it'];
    const rows = segs.map((s) => simple ? [s.id, who(s.id)] : [s.id, s.group, s.class || '', (s.targets || []).map((t) => t.host + ':' + (t.ports || []).join('/')).join(', '), who(s.id)]);
    show(el('h2', 'Private applications'), table(cols, rows),
      el('p', 'Apps are only reachable through the broker; their addresses are never sent to users. An app that no rule allows is out of reach for everyone.', 'muted'));
  },
  Policy: async () => {
    const out = el('div'), ta = el('textarea'), res = el('pre');
    const kind = el('select'); ['private', 'web'].forEach((k) => kind.appendChild(el('option', k)));
    const load = async () => { try { ta.value = JSON.stringify(await api('GET', '/v1/policies/' + kind.value), null, 2); } catch (e) { ta.value = e.message; } };
    kind.addEventListener('change', load);
    const sim = btn('Simulate against the last 7 days', async () => { try { const draft = JSON.parse(ta.value); res.textContent = JSON.stringify(await api('POST', '/v1/policies/private/simulate', { policy: draft, days: 7 }), null, 2); } catch (e) { res.textContent = e.message; } }, 'primary');
    const row = el('div', undefined, 'row'); row.append(field('Policy', kind), sim);
    out.append(el('h2', 'Policy'), el('p', 'Edit a draft below and simulate it. Nothing is saved from this page; apply a change with the API once the simulation looks right.', 'muted'), row, ta, res);
    show(out); await load();
  },
  Reports: async () => {
    const [ev, sug] = await Promise.all([api('GET', '/v1/evidence?format=text', null, true), api('GET', '/v1/suggestions')]);
    const s = el('div'); s.appendChild(el('h2', 'Suggestions'));
    (sug.device_problems || []).forEach((p) => s.appendChild(el('div', p, 'card warn')));
    (sug.rule_suggestions || []).forEach((x) => { const c = el('div', undefined, 'card'); c.appendChild(el('strong', x.summary)); c.appendChild(el('pre', JSON.stringify(x.draft_rule, null, 2))); c.appendChild(el('div', x.caution, 'muted')); s.appendChild(c); });
    if (!(sug.device_problems || []).length && !(sug.rule_suggestions || []).length) s.appendChild(el('p', 'No suggestions.', 'muted'));
    show(s, el('h2', 'Insurance questionnaire evidence'), el('pre', ev));
  },
  Investigate: async () => {
    const u = el('input'), out = el('div');
    const go = async () => {
      if (!u.value) return; const r = await api('GET', '/v1/investigate?user=' + encodeURIComponent(u.value));
      clear(out); out.appendChild(el('div', r.summary, 'card'));
      out.appendChild(table(['Time', 'What', 'Result', 'Why', 'Fix'], r.timeline.map((s) => [when(s.ts), s.what + (s.count > 1 ? ' (x' + s.count + ')' : ''), s.outcome, s.why, s.fix])));
    };
    const row = el('div', undefined, 'row'); row.append(field('User', u), btn('Investigate', go, 'primary'));
    show(el('h2', 'Why was someone blocked?'), row, out);
  },
};

function signOut() { token = null; try { sessionStorage.removeItem('ztx-token'); } catch (e) {} render(); }

async function open(name) {
  Array.from($('tabs').children).forEach((b) => b.setAttribute('aria-current', b.dataset.tab === name ? 'true' : 'false'));
  try { await tabs[name](); } catch (e) { failure(e); }
}

async function render() {
  const nav = $('tabs'); clear(nav); clear($('who'));
  if (!token) { $('login').hidden = false; view().hidden = true; return; }
  $('login').hidden = true; view().hidden = false;
  try { me = await api('GET', '/v1/me'); } catch (e) { if (!token) return; me = { permissions: ['read'] }; }
  const list = Modes.visibleTabs(mode, me.permissions);
  list.forEach((t) => { const b = el('button', t.label); b.dataset.tab = t.name; b.addEventListener('click', () => open(t.name)); nav.appendChild(b); });
  const other = mode === 'advanced' ? 'simple' : 'advanced';
  $('who').appendChild(el('span', (me.name || '') + (me.role ? ' (' + me.role + ') ' : ' '), 'muted'));
  $('who').appendChild(btn(other === 'advanced' ? 'Show all screens' : 'Show fewer screens', async () => { mode = other; try { localStorage.setItem('ztx-mode', mode); } catch (e) {} await render(); }));
  $('who').appendChild(btn('Sign out', async () => signOut()));
  if (list.length) open(list[0].name); else show(el('p', 'This role has no screens.', 'muted'));
}

$('loginform').addEventListener('submit', async (ev) => {
  ev.preventDefault(); $('loginerr').textContent = '';
  token = $('token').value; $('token').value = '';
  try { await api('GET', '/v1/segments'); try { sessionStorage.setItem('ztx-token', token); } catch (e) {} render(); }
  catch (e) { token = null; $('loginerr').textContent = e.message; }
});
render();
