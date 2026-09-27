// import-export.test.js — the owner's export/import of system configuration and
// users (secbin-export/v1). Both need the owner's password again (step-up);
// the owner's password and recovery codes are never exported; an import is
// previewed (dry run) and applied all-or-nothing; imported credentials log in
// with the original password; an existing account (the owner included) never
// has its credentials changed; every field is re-validated server-side.
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, login, proofFor, USER_PW, freshIp } from './helpers.js';

let oc;
beforeAll(async () => { oc = await owner(); });

const CURRENT = proofFor('owner-password');
const exportDoc = async (opts) => {
  const r = await fetchJson('/api/private/admin/export', { method: 'POST', cookie: oc, body: { current: CURRENT, ...opts } });
  expect(r.status).toBe(200);
  return (await r.json()).document;
};
const importDoc = (document, decisions, dryRun = true, current = CURRENT) =>
  fetchJson('/api/private/admin/import', { method: 'POST', cookie: oc, body: { current, document, decisions, dryRun } });
const userId = async (name) => (await (await fetchJson('/api/private/admin/users', { cookie: oc })).json()).users.find((u) => u.username === name)?.id;

describe('admin export', () => {
  it('needs the owner password again, and a wrong one counts as a failure', async () => {
    expect((await fetchJson('/api/private/admin/export', { method: 'POST', cookie: oc, body: { system: true } })).status).toBe(400);
    const wrong = await fetchJson('/api/private/admin/export', { method: 'POST', cookie: oc, body: { current: proofFor('not-it'), system: true }, ip: freshIp() });
    expect(wrong.status).toBe(403);
    expect((await wrong.json()).error).toBe('wrong_password');
    const u = await makeUser('ie-plain');
    const asUser = await fetchJson('/api/private/admin/export', { method: 'POST', cookie: u.cookie, body: { current: proofFor('user-password-123') } });
    expect(asUser.status).toBe(403);
  });

  it('exports the chosen parts, never the owner or sessions; API keys only when asked', async () => {
    const u = await makeUser('ie-export');
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch: { maxViews: 7, apiEnabled: true } } });
    await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { current: proofFor(USER_PW), name: 'k' } });
    const doc = await exportDoc({ system: true, users: 'all', parts: ['credentials', 'role'] });
    expect(doc.format).toBe('secbin-export/v1');
    expect(doc.users.some((x) => x.username === 'owner')).toBe(false);
    expect(doc.owner).toBeUndefined(); // the owner's passkeys only when asked
    const e = doc.users.find((x) => x.username === 'ie-export');
    expect(Object.keys(e).sort()).toEqual(['credentials', 'role', 'username']);
    expect(Object.keys(e.credentials).sort()).toEqual(['disabled', 'salt', 't', 'verifier']);
    // A user's role, by name; the role travels in `system`.
    expect(e.role).toBe(`user ${u.id}`);
    const role = doc.system.roles.find((r) => r.name === `user ${u.id}`);
    expect(role.limits.all).toMatchObject({ maxViews: 7, apiEnabled: true });
    expect(JSON.stringify(doc)).not.toMatch(/sbk_|"sid"|sess_ver|key_hash|"hash"|"keys"|recoveryCodes/);
    // Unless asked for, no API keys or passkeys leave the server.
    expect(Object.keys(doc.system).sort()).toEqual(['ipRules', 'limits', 'public', 'quotas', 'roles', 'settings', 'turnstile', 'viewerRules']);
    // The Default role (system.limits.all) holds a value for every option.
    expect(Object.keys(doc.system.limits.all)).toContain('pwMinLength');
    // Parts are optional.
    const onlyRole = await exportDoc({ users: [u.id], parts: ['role'] });
    expect(onlyRole.system).toBeUndefined();
    expect(onlyRole.users).toEqual([{ username: 'ie-export', role: `user ${u.id}` }]);
    // No parts → no users; unknown part names are ignored.
    expect((await exportDoc({ users: [u.id], parts: [] })).users).toEqual([]);
    expect((await exportDoc({ users: [u.id], parts: ['config', 'password'] })).users).toEqual([]);
    // Selecting the owner's id exports nothing for it.
    const ownerId = await userId('owner');
    expect((await exportDoc({ users: [ownerId], parts: ['credentials'] })).users).toEqual([]);
    expect((await exportDoc({ users: [{ id: ownerId, parts: ['credentials', 'recoveryCodes'] }] })).users).toEqual([]);
  });

  it('chooses the parts per user', async () => {
    const a = await makeUser('ie-per-a');
    const b = await makeUser('ie-per-b');
    const doc = await exportDoc({ users: [{ id: a.id, parts: ['credentials'] }, { id: b.id, parts: ['role', 'recoveryCodes', 'passkeys'] }, { id: a.id, parts: ['role'] }] });
    expect(doc.users).toHaveLength(2); // a user appears once (its first entry)
    expect(Object.keys(doc.users.find((x) => x.username === 'ie-per-a')).sort()).toEqual(['credentials', 'username']);
    const eb = doc.users.find((x) => x.username === 'ie-per-b');
    expect(Object.keys(eb).sort()).toEqual(['passkeys', 'recoveryCodes', 'role', 'username']);
    expect(eb.passkeys).toEqual({ mfa: false, keys: [] });
    expect(eb.recoveryCodes).toEqual([]);
    const audit = (await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json()).rows;
    expect(audit.some((r) => r.action === 'export.users' && r.detail === 'credentials: ie-per-a')).toBe(true);
    expect(audit.some((r) => r.action === 'export.users' && r.detail === 'role+passkeys+recoveryCodes: ie-per-b')).toBe(true);
  });
});

describe('admin import', () => {
  it('round-trips a deleted user: preview, apply, log in with the original password', async () => {
    const u = await makeUser('ie-roundtrip', 'roundtrip-password-1');
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch: { maxViews: 3 } } });
    await fetchJson('/api/private/admin/quotas', { method: 'PUT', cookie: oc, body: { scope: u.id, list: [{ channel: 'all', kind: 'all', n: 1, unit: 'd', max: 4 }] } });
    const doc = await exportDoc({ users: [u.id], parts: ['credentials', 'role'] });
    expect((await fetchJson(`/api/private/admin/users/${u.id}`, { method: 'DELETE', cookie: oc, headers: { 'x-secbin-intent': '1' } })).status).toBe(200);

    const preview = await importDoc(doc, { system: false, users: { 'ie-roundtrip': {} } });
    expect(preview.status).toBe(200);
    const p = await preview.json();
    expect(p.applied).toBe(false);
    expect(p.plan.users).toEqual([{ username: 'ie-roundtrip', as: 'ie-roundtrip', action: 'create', changes: ['credentials', `role user ${u.id}`], skipped: [], role: `user ${u.id}` }]);
    expect(p.plan.owner).toBeNull();
    expect(await userId('ie-roundtrip')).toBeUndefined(); // a preview changes nothing

    const applied = await importDoc(doc, { system: false, users: { 'ie-roundtrip': {} } }, false);
    expect(applied.status).toBe(200);
    expect((await applied.json()).applied).toBe(true);
    const cookie = await login('ie-roundtrip', 'roundtrip-password-1');
    const me = await (await fetchJson('/api/private/me', { cookie })).json();
    expect(me.limits.maxViews).toBe(3);
    expect(me.quotas.some((q) => q.max === 4)).toBe(true);
    const audit = await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json();
    expect(audit.rows.some((r) => r.action === 'user.imported' && /^create: role=user /.test(r.detail))).toBe(true);
  });

  it('create vs update must match what is there; the owner can be updated but never re-created', async () => {
    const u = await makeUser('ie-conflict', 'conflict-password-1');
    const doc = await exportDoc({ users: [u.id], parts: ['credentials'] });
    const clash = await importDoc(doc, { system: false, users: { 'ie-conflict': {} } }, false);
    expect(clash.status).toBe(409);
    const cp = (await clash.json()).plan;
    expect(cp.users[0].action).toBe('conflict');
    expect(cp.errors.join(' ')).toMatch(/already exists here — choose "update existing"/);
    // Renamed: a second account with the same password.
    expect((await importDoc(doc, { system: false, users: { 'ie-conflict': { as: 'ie-conflict-2' } } }, false)).status).toBe(200);
    await login('ie-conflict-2', 'conflict-password-1');
    // "update" for an account that does not exist is refused.
    const none = await (await importDoc(doc, { system: false, users: { 'ie-conflict': { as: 'ie-nobody-here', action: 'update' } } })).json();
    expect(none.plan.users[0].action).toBe('refused');
    expect(none.plan.errors.join(' ')).toMatch(/does not exist here, so it cannot be updated/);
    // As the owner: "create" is a conflict; "update" changes nothing here (no role, no password).
    expect((await importDoc(doc, { system: false, users: { 'ie-conflict': { as: 'owner' } } }, false)).status).toBe(409);
    const up = await importDoc(doc, { system: false, users: { 'ie-conflict': { as: 'owner', action: 'update' } } }, false);
    expect(up.status).toBe(200);
    const upPlan = (await up.json()).plan;
    expect(upPlan.users[0]).toMatchObject({ action: 'update', owner: true, changes: [], skipped: ['password and disabled flag: an existing account keeps its own'] });
    await login('owner', 'owner-password'); // still the owner's own password
    expect((await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'owner', proof: proofFor('conflict-password-1') }, ip: freshIp() })).status).toBe(401);
  });

  it('updating an existing account never changes its password, sessions, API keys or disabled flag', async () => {
    const a = await makeUser('ie-over-a', 'first-password-12');
    const b = await makeUser('ie-over-b', 'second-password-1');
    for (const x of [a, b]) await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: x.id, channel: 'all', patch: { apiEnabled: true } } });
    const keyA = (await (await fetchJson('/api/private/me/keys', { method: 'POST', cookie: a.cookie, body: { current: proofFor('first-password-12'), name: 'a-key' } })).json()).key;
    await fetchJson('/api/private/me/keys', { method: 'POST', cookie: b.cookie, body: { current: proofFor('second-password-1'), name: 'b-key' } });
    const doc = await exportDoc({ users: [b.id], parts: ['credentials', 'apiKeys'] });
    doc.users[0].credentials.disabled = true;
    const pre = await (await importDoc(doc, { system: false, users: { 'ie-over-b': { as: 'ie-over-a', action: 'update' } } })).json();
    expect(pre.plan.errors).toEqual([]);
    expect(pre.plan.users[0]).toMatchObject({ action: 'update', changes: [] });
    expect(pre.plan.users[0].skipped).toEqual(['password and disabled flag: an existing account keeps its own', 'API keys: an existing account keeps its own']);
    expect((await importDoc(doc, { system: false, users: { 'ie-over-b': { as: 'ie-over-a', action: 'update' } } }, false)).status).toBe(200);
    expect((await fetchJson('/api/private/me', { cookie: a.cookie })).status).toBe(200); // its session still works
    await login('ie-over-a', 'first-password-12');
    expect((await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'ie-over-a', proof: proofFor('second-password-1') }, ip: freshIp() })).status).toBe(401);
    expect((await fetchJson('/api/private/policy', { headers: { authorization: `Bearer ${keyA}` } })).status).toBe(200);
    const keys = (await (await fetchJson('/api/private/me/keys', { cookie: a.cookie })).json()).keys;
    expect(keys.map((k) => k.name)).toEqual(['a-key']);
    const audit = (await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json()).rows;
    expect(audit.some((r) => r.action === 'user.imported' && r.detail === 'update from=ie-over-b: no changes; skipped 2')).toBe(true);
  });

  it('the preview calls out a change to public (anonymous) access', async () => {
    const doc = await exportDoc({ system: true });
    doc.system.settings['public.enabled'] = !doc.system.settings['public.enabled'];
    const { plan } = await (await importDoc(doc, { system: true, users: {} })).json();
    expect(plan.warnings.some((w) => w.includes('public.enabled'))).toBe(true);
  });

  it('role-only entries cannot create accounts; system settings are applied', async () => {
    const u = await makeUser('ie-config');
    const doc = await exportDoc({ system: true, users: [u.id], parts: ['role'] });
    doc.users[0].username = 'ie-nobody';
    doc.system.settings['files.grantSec'] = 1800;
    const r = await importDoc(doc, { system: true, users: { 'ie-nobody': {} } }, false);
    expect(r.status).toBe(409);
    const ok = await importDoc(doc, { system: true, users: {} }, false);
    expect(ok.status).toBe(200);
    const plan = (await ok.json()).plan;
    expect(plan.system.settings).toEqual(expect.arrayContaining([expect.objectContaining({ key: 'files.grantSec', to: 1800 })]));
    const ov = await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json();
    expect(ov.settings['files.grantSec']).toBe(1800);
  });

  it('re-validates every field of an untrusted document', async () => {
    const u = await makeUser('ie-validate');
    const base = await exportDoc({ system: true, users: [u.id], parts: ['credentials', 'role'] });
    const variants = [
      (d) => { d.format = 'other'; },
      (d) => { d.extra = 1; },
      (d) => { d.users[0].credentials.t = 1; },
      (d) => { d.users[0].credentials.verifier = 'zz'; },
      (d) => { d.users[0].config = { role: 'Default' }; }, // the shape before per-user parts
      (d) => { d.users[0].role = ''; },
      (d) => { d.users[0].role = { name: 'x' }; },
      (d) => { d.users[0].role = 'Owner'; }, // the Owner role belongs to the owner only
      (d) => { d.users[0].role = 'x\ny'; },
      (d) => { d.system = { ...(d.system || {}), roles: [{ name: 'Owner', ownQuotas: false, limits: { all: {}, api: {} }, quotas: [], viewerRules: [] }] }; },
      (d) => { d.users[0].username = '../x'; },
      (d) => { d.system.settings['guard.login.max'] = 0; },
      (d) => { d.system.ipRules.push({ cidr: 'not-an-ip', action: 'block' }); },
      (d) => { d.users.push({ ...d.users[0] }); },
      (d) => { d.users[0].owner = true; },
      (d) => { d.owner = {}; },
      (d) => { d.owner = { passkeys: { keys: [] }, password: 'x' }; },
      (d) => { d.owner = { recoveryCodes: [] }; },
    ];
    for (const [i, mutate] of variants.entries()) {
      const d = structuredClone(base);
      mutate(d);
      const r = await importDoc(d, { system: false, users: {} });
      expect([i, r.status]).toEqual([i, 400]);
    }
    const proto = JSON.parse(JSON.stringify(base).replace('"users":[', '"__proto__":{"x":1},"users":['));
    expect((await importDoc(proto, { system: false, users: {} })).status).toBe(400);
    // Decisions are validated too.
    expect((await importDoc(base, { system: false, users: { 'not-in-doc': {} } })).status).toBe(400);
    expect((await importDoc(base, { system: false, users: { 'ie-validate': { as: 'bad name!' } } })).status).toBe(400);
    expect((await importDoc(base, { system: false, users: { 'ie-validate': { action: 'overwrite' } } })).status).toBe(400);
    expect((await importDoc(base, { system: false, users: { 'ie-validate': { overwrite: true } } })).status).toBe(400);
    expect((await importDoc(base, { system: false, owner: { passkeys: true }, users: {} })).status).toBe(400); // no owner part in the file
  });

  it('review hardening: no self-block, full audit, clean notes', async () => {
    const a = await makeUser('ie-keys-a', 'keys-password-123');
    await exportDoc({ users: [a.id], parts: ['credentials'] });
    // An imported block rule covering the importing owner's own address is refused.
    const sys = await exportDoc({ system: true });
    sys.system.ipRules = [{ cidr: '203.0.113.0/24', action: 'block', note: 'line1\nline2' }];
    const imp = (ip) => fetchJson('/api/private/admin/import', { method: 'POST', cookie: oc, ip, body: { current: CURRENT, document: sys, decisions: { system: true, users: {} }, dryRun: false } });
    const self = await imp('203.0.113.7');
    expect(self.status).toBe(409);
    expect((await self.json()).plan.errors.join(' ')).toMatch(/block your own address/);
    // From elsewhere it applies, with the note cleaned and every change audited.
    sys.system.settings['guard.login.max'] = 50;
    expect((await imp('198.51.100.200')).status).toBe(200);
    const rules = await (await fetchJson('/api/private/admin/ip-rules', { cookie: oc })).json();
    expect(rules.rules.find((r) => r.cidr === '203.0.113.0/24').note).toBe('line1 line2');
    const audit = (await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json()).rows;
    expect(audit.some((r) => r.action === 'settings.updated' && /guard\.login\.max=50/.test(r.detail))).toBe(true);
    expect(audit.some((r) => r.action === 'iprule.added' && /block 203\.0\.113\.0\/24/.test(r.detail))).toBe(true);
    expect(audit.some((r) => r.action === 'export.users' && /credentials: ie-keys-a/.test(r.detail))).toBe(true);
    await fetchJson(`/api/private/admin/ip-rules/${rules.rules.find((r) => r.cidr === '203.0.113.0/24').id}`, { method: 'DELETE', cookie: oc, headers: { 'x-secbin-intent': '1' } });
  });
});
