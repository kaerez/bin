// import-export.test.js — the owner's export/import of system configuration and
// users (secbin-export/v1). Both need the owner's password again (step-up);
// the owner is never exported and cannot be imported over; an import is
// previewed (dry run) and applied all-or-nothing; imported credentials log in
// with the original password; every field is re-validated server-side.
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, login, proofFor, freshIp } from './helpers.js';

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

  it('exports the chosen parts, never the owner, sessions or API keys', async () => {
    const u = await makeUser('ie-export');
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch: { maxViews: 7, apiEnabled: true } } });
    await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { name: 'k' } });
    const doc = await exportDoc({ system: true, users: 'all', credentials: true, config: true });
    expect(doc.format).toBe('secbin-export/v1');
    expect(doc.users.some((x) => x.username === 'owner')).toBe(false);
    const e = doc.users.find((x) => x.username === 'ie-export');
    expect(Object.keys(e).sort()).toEqual(['config', 'credentials', 'username']);
    expect(Object.keys(e.credentials).sort()).toEqual(['disabled', 'salt', 't', 'verifier']);
    expect(e.config.limits.all).toMatchObject({ maxViews: 7, apiEnabled: true });
    expect(JSON.stringify(doc)).not.toMatch(/sbk_|"sid"|sess_ver|key_hash|"hash"|"keys"/);
    expect(Object.keys(doc.system).sort()).toEqual(['ipRules', 'limits', 'quotas', 'settings', 'viewerRules']);
    // Parts are optional.
    const onlyConfig = await exportDoc({ users: [u.id], config: true });
    expect(onlyConfig.system).toBeUndefined();
    expect(onlyConfig.users).toHaveLength(1);
    expect(onlyConfig.users[0].credentials).toBeUndefined();
    // Selecting the owner's id exports nothing for it.
    const ownerId = await userId('owner');
    expect((await exportDoc({ users: [ownerId], credentials: true })).users).toEqual([]);
  });
});

describe('admin import', () => {
  it('round-trips a deleted user: preview, apply, log in with the original password', async () => {
    const u = await makeUser('ie-roundtrip', 'roundtrip-password-1');
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch: { maxViews: 3 } } });
    await fetchJson('/api/private/admin/quotas', { method: 'PUT', cookie: oc, body: { scope: u.id, list: [{ channel: 'all', kind: 'all', n: 1, unit: 'd', max: 4 }] } });
    const doc = await exportDoc({ users: [u.id], credentials: true, config: true });
    expect((await fetchJson(`/api/private/admin/users/${u.id}`, { method: 'DELETE', cookie: oc, headers: { 'x-secbin-intent': '1' } })).status).toBe(200);

    const preview = await importDoc(doc, { system: false, users: { 'ie-roundtrip': {} } });
    expect(preview.status).toBe(200);
    const p = await preview.json();
    expect(p.applied).toBe(false);
    expect(p.plan.users).toEqual([{ username: 'ie-roundtrip', as: 'ie-roundtrip', parts: ['credentials', 'config'], action: 'create' }]);
    expect(await userId('ie-roundtrip')).toBeUndefined(); // a preview changes nothing

    const applied = await importDoc(doc, { system: false, users: { 'ie-roundtrip': {} } }, false);
    expect(applied.status).toBe(200);
    expect((await applied.json()).applied).toBe(true);
    const cookie = await login('ie-roundtrip', 'roundtrip-password-1');
    const me = await (await fetchJson('/api/private/me', { cookie })).json();
    expect(me.limits.maxViews).toBe(3);
    expect(me.quotas.some((q) => q.max === 4)).toBe(true);
    const audit = await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json();
    expect(audit.rows.some((r) => r.action === 'user.imported')).toBe(true);
  });

  it('refuses conflicts unless overwritten or renamed, and never imports over the owner', async () => {
    const u = await makeUser('ie-conflict', 'conflict-password-1');
    const doc = await exportDoc({ users: [u.id], credentials: true });
    const clash = await importDoc(doc, { system: false, users: { 'ie-conflict': {} } }, false);
    expect(clash.status).toBe(409);
    expect((await clash.json()).plan.users[0].action).toBe('conflict');
    // Renamed: a second account with the same password.
    expect((await importDoc(doc, { system: false, users: { 'ie-conflict': { as: 'ie-conflict-2' } } }, false)).status).toBe(200);
    await login('ie-conflict-2', 'conflict-password-1');
    // Over the owner: refused even with overwrite.
    const r = await importDoc(doc, { system: false, users: { 'ie-conflict': { as: 'owner', overwrite: true } } }, false);
    expect(r.status).toBe(409);
    expect((await r.json()).plan.users[0].action).toBe('refused');
    await login('owner', 'owner-password'); // still the owner's own password
  });

  it('overwriting credentials ends the account\'s sessions', async () => {
    const a = await makeUser('ie-over-a', 'first-password-12');
    const b = await makeUser('ie-over-b', 'second-password-1');
    const doc = await exportDoc({ users: [b.id], credentials: true });
    expect((await importDoc(doc, { system: false, users: { 'ie-over-b': { as: 'ie-over-a', overwrite: true } } }, false)).status).toBe(200);
    expect((await fetchJson('/api/private/me', { cookie: a.cookie })).status).toBe(401);
    await login('ie-over-a', 'second-password-1');
  });

  it('config-only entries cannot create accounts; system settings are applied', async () => {
    const u = await makeUser('ie-config');
    const doc = await exportDoc({ system: true, users: [u.id], config: true });
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
    const base = await exportDoc({ system: true, users: [u.id], credentials: true, config: true });
    const variants = [
      (d) => { d.format = 'other'; },
      (d) => { d.extra = 1; },
      (d) => { d.users[0].credentials.t = 1; },
      (d) => { d.users[0].credentials.verifier = 'zz'; },
      (d) => { d.users[0].config.limits.all.maxViews = -1; },
      (d) => { d.users[0].config.limits.api.fileTypeMode = 'allow'; },
      (d) => { d.users[0].username = '../x'; },
      (d) => { d.system.settings['guard.login.max'] = 0; },
      (d) => { d.system.ipRules.push({ cidr: 'not-an-ip', action: 'block' }); },
      (d) => { d.users.push({ ...d.users[0] }); },
      (d) => { d.users[0].role = 'owner'; },
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
  });

  it('review hardening: API keys revoked on credential overwrite, no self-block, full audit, clean notes', async () => {
    const a = await makeUser('ie-keys-a', 'keys-password-123');
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: a.id, channel: 'all', patch: { apiEnabled: true } } });
    const key = (await (await fetchJson('/api/private/me/keys', { method: 'POST', cookie: a.cookie, body: { name: 'k' } })).json()).key;
    const doc = await exportDoc({ users: [a.id], credentials: true });
    const pre = await (await importDoc(doc, { system: false, users: { 'ie-keys-a': { overwrite: true } } })).json();
    expect(pre.plan.users[0].note).toMatch(/revokes its API keys/);
    expect((await importDoc(doc, { system: false, users: { 'ie-keys-a': { overwrite: true } } }, false)).status).toBe(200);
    const withKey = await fetchJson('/api/private/paste', { method: 'POST', headers: { authorization: `Bearer ${key}` }, body: { paste: {} } });
    expect(withKey.status).toBe(401);

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
