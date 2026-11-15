'use strict';
// The console's logic that is not about the page: which screens a person sees in the simple and the
// advanced mode and for their role, and a plain-language reading of who can reach each app. It touches no
// page element, so it is tested with Node (internal/cp/uitest) and is not loaded as HTML anywhere.
var Modes = (function () {
  // name: the screen; label: what the simple mode calls it; simple: part of the three simple screens;
  // needs: the permission its data needs (GET /v1/me lists the permissions of the signed-in role).
  const TABS = [
    { name: 'Overview', label: 'Alerts', simple: true, needs: 'read' },
    { name: 'People', label: 'Users', simple: true, needs: 'read' },
    { name: 'Apps', label: 'Apps', simple: true, needs: 'read' },
    { name: 'Incidents', needs: 'logs' },
    { name: 'Access', needs: 'logs' },
    { name: 'Approvals', needs: 'read' },
    { name: 'Inspection', needs: 'read' },
    { name: 'Policy', needs: 'read' },
    { name: 'Reports', needs: 'audit' },
    { name: 'Investigate', needs: 'read' },
    { name: 'Versions', needs: 'read' },
  ];

  // visibleTabs: in the simple mode the three screens (users, apps, alerts), in the advanced mode all of
  // them, and in either mode only those the role has the permission for. Each is { name, label }.
  function visibleTabs(mode, perms) {
    const has = (p) => (perms || []).indexOf(p) >= 0;
    return TABS.filter((t) => (mode === 'advanced' || t.simple) && has(t.needs)).map((t) => ({ name: t.name, label: mode === 'advanced' ? t.name : (t.label || t.name) }));
  }

  // can: whether the role may do something, for hiding the buttons it would be refused.
  function can(perms, p) { return (perms || []).indexOf(p) >= 0; }

  function who(m) {
    const parts = [];
    if (m.groups && m.groups.length) parts.push('people in ' + m.groups.join(' or '));
    if (m.users && m.users.length) parts.push(m.users.join(' or '));
    return parts.length ? parts.join(', and ') : 'everyone';
  }

  // describeRule: one rule as a sentence a person can read.
  function describeRule(r) {
    const m = r.match || {};
    let s = who(m);
    const conds = [];
    if (m.posture) conds.push('from devices that pass the health checks');
    if (m.time) conds.push('only at set times');
    if (m.network) conds.push('only from set networks');
    if (m.workspace === true) conds.push('only in the workspace browser');
    if (r.action === 'isolate') conds.push('only in the workspace browser');
    if (r.action === 'require_approval') conds.push('after an administrator approves');
    if (m.max_risk !== undefined && m.max_risk !== null) conds.push('while their risk score is low');
    return conds.length ? s + ', ' + Array.from(new Set(conds)).join(', ') : s;
  }

  // appAccess: for each app, the sentences of the rules that let someone reach it, in the order the policy
  // is evaluated. Private apps are refused unless a rule allows them, so an app with none is out of reach.
  // A deny rule ahead of an allow rule is shown too, as "Except: ...".
  function appAccess(segments, policy) {
    const rules = ((policy && policy.rules) || []).slice().sort((a, b) => (a.priority || 0) - (b.priority || 0));
    return (segments || []).map((seg) => {
      const lines = [];
      rules.forEach((r) => {
        const apps = (r.match && r.match.apps) || [];
        if (apps.length && apps.indexOf(seg.id) < 0) return;
        if (r.action === 'deny') lines.push('Except: ' + describeRule(r));
        else if (r.action === 'allow' || r.action === 'require_approval' || r.action === 'isolate') lines.push(describeRule(r));
      });
      const allowed = lines.filter((l) => l.indexOf('Except: ') !== 0).length;
      return { id: seg.id, access: allowed ? lines : ['Nobody: no rule allows it'] };
    });
  }

  return { TABS, visibleTabs, can, describeRule, appAccess };
})();
if (typeof module !== 'undefined') module.exports = Modes;
