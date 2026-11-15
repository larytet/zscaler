'use strict';
// Run by internal/cp/ui_test.go with Node. No framework: assert and exit status.
const assert = require('assert');
const Modes = require('../ui/modes.js');
const names = (l) => l.map((t) => t.name).join(',');
const labels = (l) => l.map((t) => t.label).join(',');

const owner = ['read', 'logs', 'audit', 'support', 'write', 'sensitive', 'admins'];
// the simple mode shows three screens, named in plain words
assert.strictEqual(names(Modes.visibleTabs('simple', owner)), 'Overview,People,Apps');
assert.strictEqual(labels(Modes.visibleTabs('simple', owner)), 'Alerts,Users,Apps');
// the advanced mode shows everything the role may see, under the real names
assert.strictEqual(Modes.visibleTabs('advanced', owner).length, Modes.TABS.length);
assert.strictEqual(labels(Modes.visibleTabs('advanced', owner)), names(Modes.visibleTabs('advanced', owner)));
// anything that is not 'advanced' is the simple mode: an unknown or missing value must not open the advanced screens
for (const m of [undefined, null, '', 'expert', 'ADVANCED']) assert.strictEqual(names(Modes.visibleTabs(m, owner)), 'Overview,People,Apps', String(m));
// roles: a viewer has no logs or audit; the audit screens are for those who may read them
const viewer = ['read'];
assert.strictEqual(names(Modes.visibleTabs('advanced', viewer)), 'Overview,People,Apps,Approvals,Inspection,Policy,Investigate');
const auditor = ['read', 'logs', 'audit'];
assert.ok(names(Modes.visibleTabs('advanced', auditor)).includes('Reports') && names(Modes.visibleTabs('advanced', auditor)).includes('Incidents'));
assert.ok(!names(Modes.visibleTabs('advanced', viewer)).includes('Incidents') && !names(Modes.visibleTabs('advanced', viewer)).includes('Reports'));
// a role with no permissions, or no list at all, sees nothing
assert.strictEqual(Modes.visibleTabs('advanced', []).length, 0);
assert.strictEqual(Modes.visibleTabs('advanced', undefined).length, 0);
// every screen needs a permission the server knows
for (const t of Modes.TABS) assert.ok(['read', 'logs', 'audit', 'support', 'write', 'sensitive', 'admins'].includes(t.needs), t.name);
// the three simple screens are exactly the ones marked simple
assert.deepStrictEqual(Modes.TABS.filter((t) => t.simple).map((t) => t.name), ['Overview', 'People', 'Apps']);
assert.ok(Modes.can(owner, 'write') && !Modes.can(viewer, 'write') && !Modes.can(undefined, 'read'));

// who can reach an app, in words
const segs = [{ id: 'erp' }, { id: 'wiki' }, { id: 'hr' }, { id: 'lonely' }];
const policy = { rules: [
  { id: 'r-late', priority: 30, action: 'allow', match: { groups: ['hr-team'], apps: ['hr'], time: { from: '09:00' } } },
  { id: 'deny', priority: 1, action: 'deny', match: { groups: ['restricted'] } },
  { id: 'staff', priority: 10, action: 'allow', match: { groups: ['all-staff'], apps: ['erp', 'wiki'], posture: { disk_encrypted: true } } },
  { id: 'jit', priority: 20, action: 'require_approval', match: { groups: ['contractors'], apps: ['wiki'] } },
  { id: 'iso', priority: 25, action: 'isolate', match: { groups: ['all-staff'], apps: ['hr'] } },
] };
const acc = Object.fromEntries(Modes.appAccess(segs, policy).map((a) => [a.id, a.access]));
assert.deepStrictEqual(acc.erp, ['Except: people in restricted', 'people in all-staff, from devices that pass the health checks']);
assert.deepStrictEqual(acc.wiki, ['Except: people in restricted', 'people in all-staff, from devices that pass the health checks', 'people in contractors, after an administrator approves']);
assert.deepStrictEqual(acc.hr, ['Except: people in restricted', 'people in all-staff, only in the workspace browser', 'people in hr-team, only at set times']);
// an app no rule reaches is out of reach, and the deny-only rule does not make it reachable
assert.deepStrictEqual(Modes.appAccess([{ id: 'lonely' }], { rules: [policy.rules[1]] })[0].access, ['Nobody: no rule allows it']);
assert.deepStrictEqual(Modes.appAccess([{ id: 'x' }], { rules: [] })[0].access, ['Nobody: no rule allows it']);
assert.deepStrictEqual(Modes.appAccess([{ id: 'x' }], null)[0].access, ['Nobody: no rule allows it']);
assert.deepStrictEqual(Modes.appAccess(null, policy), []);
// a rule with no group and no user is everyone; users are named
assert.strictEqual(Modes.describeRule({ action: 'allow', match: {} }), 'everyone');
assert.strictEqual(Modes.describeRule({ action: 'allow', match: { users: ['alice', 'bob'] } }), 'alice or bob');
assert.strictEqual(Modes.describeRule({ action: 'allow', match: { groups: ['a', 'b'], users: ['c'] } }), 'people in a or b, and c');
// a rule that has no match at all does not crash
assert.strictEqual(Modes.describeRule({ action: 'allow' }), 'everyone');
console.log('modes: ok');
