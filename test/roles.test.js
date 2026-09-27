// roles.test.js — every user has exactly one role (Default unless given
// another). The Owner role is built in and locked; the Default role holds a
// value for every option; custom roles inherit whatever they leave unset from
// Default. Accounts have no settings of their own any more.
import { describe, it, expect, beforeAll } from 'vitest';
import { SELF } from 'cloudflare:test';
import { owner, makeUser, fetchJson, freshIp, proofFor, createNote, ORIGIN, USER_PW } from './helpers.js';
import { SoftAuthenticator } from './soft-authenticator.js';

let oc;
beforeAll(async () => { oc = await owner(); });

// Straight to the Worker (helpers.fetchJson maps per-user scopes onto roles).
const raw = (path, { method = 'GET', body } = {}) => SELF.fetch(`${ORIGIN}${path}`, { method, redirect: 'manual',
  headers: { cookie: oc, 'content-type': 'application/json', 'x-secbin-intent': '1', 'cf-connecting-ip': freshIp() }, body: body === undefined ? undefined : JSON.stringify(body) });
const roles = async () => (await (await raw('/api/private/admin/roles')).json()).roles;
const newRole = async (name) => { const r = await raw('/api/private/admin/roles', { method: 'POST', body: { name } }); expect(r.status).toBe(201); return (await r.json()).id; };
const assign = (uid, roleId) => raw(`/api/private/admin/users/${uid}/role`, { method: 'PUT', body: { roleId } });
const limits = (scope, patch, channel = 'all') => raw('/api/private/admin/limits', { method: 'PATCH', body: { scope, channel, patch } });
const me = async (cookie) => (await (await fetchJson('/api/private/me', { cookie })).json());
const errorOf = async (r) => (await r.json()).error;

describe('built-in roles', () => {
  it('lists Owner (locked) and Default; every user starts on Default', async () => {
    const u = await makeUser('ro-start');
    const list = await roles();
    expect(list[0]).toMatchObject({ id: 'owner', name: 'Owner', builtin: true, locked: true, users: 1 });
    expect(list[1]).toMatchObject({ id: 'default', name: 'Default', builtin: true });
    const users = (await (await raw('/api/private/admin/users')).json()).users;
    expect(users.find((x) => x.id === u.id).roleId).toBe('default');
    expect(users.find((x) => x.role === 'owner').roleId).toBe('owner');
  });

  it('the Owner role cannot be given or taken; the public account has none', async () => {
    const u = await makeUser('ro-owner');
    expect(await errorOf(await assign(u.id, 'owner'))).toBe('owner_role');
    const ownerId = (await (await raw('/api/private/admin/users')).json()).users.find((x) => x.role === 'owner').id;
    expect(await errorOf(await assign(ownerId, 'default'))).toBe('owner_role');
    expect((await assign('public-user-0000', 'default')).status).toBe(403);
    expect((await raw('/api/private/admin/roles/owner', { method: 'DELETE' })).status).toBe(404);
  });

  it('the Default role holds a value for every option: no "inherit" there', async () => {
    const ov = await (await raw('/api/private/admin/overview')).json();
    for (const k of ['maxViews', 'pwMinLength', 'passkeys', 'passkeysMax', 'sessionIdleSec', 'viewerMaxBytes', 'urlRules']) expect(ov.limits.all, k).toHaveProperty(k);
    expect(ov.limits.all.sessionIdleSec).toBe(ov.settings['session.idleSec']);
    expect((await limits('global', { maxViews: 'inherit' })).status).toBe(400);
    expect((await limits('global', { maxViews: null })).status).toBe(200); // "no limit" is a value
  });

  it('accounts have no settings of their own', async () => {
    const u = await makeUser('ro-own');
    const r = await limits(u.id, { maxViews: 3 });
    expect(r.status).toBe(400);
    expect(await errorOf(r)).toBe('use_a_role');
    expect((await raw('/api/private/admin/quotas', { method: 'PUT', body: { scope: u.id, list: [] } })).status).toBe(400);
  });
});

describe('custom roles', () => {
  it('inherit what they leave unset from Default, and follow changes to Default', async () => {
    const u = await makeUser('ro-inherit');
    const id = await newRole('Editors');
    expect((await assign(u.id, id)).status).toBe(200);
    expect((await limits(`role:${id}`, { maxViews: 25 })).status).toBe(200);
    expect((await me(u.cookie)).limits.maxViews).toBe(25);
    await limits('global', { maxExpireSec: 7200 });
    expect((await me(u.cookie)).limits.maxExpireSec).toBe(7200); // inherited, live
    expect((await limits(`role:${id}`, { maxViews: 'inherit' })).status).toBe(200);
    await limits('global', { maxViews: 9 });
    expect((await me(u.cookie)).limits.maxViews).toBe(9);
    await limits('global', { maxViews: null, maxExpireSec: null });
  });

  it('rename, duplicate (also from Default) and delete; names are unique; deleting moves users to Default', async () => {
    const id = await newRole('Interns');
    expect(await errorOf(await raw('/api/private/admin/roles', { method: 'POST', body: { name: 'interns' } }))).toBe('name_taken');
    expect(await errorOf(await raw('/api/private/admin/roles', { method: 'POST', body: { name: 'Default' } }))).toBe('name_taken');
    expect((await raw(`/api/private/admin/roles/${id}`, { method: 'PATCH', body: { name: 'Trainees' } })).status).toBe(200);
    await limits(`role:${id}`, { maxViews: 4, apiEnabled: true });
    const copy = await raw('/api/private/admin/roles', { method: 'POST', body: { from: id, name: 'Trainees 2' } });
    const copyId = (await copy.json()).id;
    const d = await (await raw(`/api/private/admin/roles/${copyId}`)).json();
    expect(d.limits.all).toEqual({ maxViews: 4, apiEnabled: true });
    const fromDefault = (await (await raw('/api/private/admin/roles', { method: 'POST', body: { from: 'default', name: 'Snapshot' } })).json()).id;
    const snap = await (await raw(`/api/private/admin/roles/${fromDefault}`)).json();
    expect(Object.keys(snap.limits.all)).toContain('pwMinLength'); // a copy of every Default value
    const u = await makeUser('ro-delete');
    await assign(u.id, id);
    const del = await raw(`/api/private/admin/roles/${id}`, { method: 'DELETE' });
    expect(await del.json()).toMatchObject({ ok: true, moved: 1 });
    const users = (await (await raw('/api/private/admin/users')).json()).users;
    expect(users.find((x) => x.id === u.id).roleId).toBe('default');
    expect((await raw(`/api/private/admin/roles/${id}`)).status).toBe(404);
    expect((await roles()).some((r) => r.name === 'Trainees')).toBe(false);
  });

  it("quotas: Default's unless the role has its own list", async () => {
    const u = await makeUser('ro-quota');
    const id = await newRole('Quota role');
    await assign(u.id, id);
    await raw('/api/private/admin/quotas', { method: 'PUT', body: { scope: 'global', list: [{ channel: 'all', kind: 'all', n: 1, unit: 'd', max: 50 }] } });
    expect((await me(u.cookie)).quotas.map((q) => q.max)).toEqual([50]);
    await raw('/api/private/admin/quotas', { method: 'PUT', body: { scope: `role:${id}`, list: [{ channel: 'all', kind: 'all', n: 1, unit: 'd', max: 2 }] } });
    expect((await me(u.cookie)).quotas.map((q) => q.max)).toEqual([2]);
    expect((await createNote(u.cookie, { text: '1' })).res.status).toBe(201);
    expect((await createNote(u.cookie, { text: '2' })).res.status).toBe(201);
    expect((await createNote(u.cookie, { text: '3' })).res.status).toBe(429);
    await raw(`/api/private/admin/roles/${id}`, { method: 'PATCH', body: { ownQuotas: false } });
    expect((await me(u.cookie)).quotas.map((q) => q.max)).toEqual([50]);
    await raw('/api/private/admin/quotas', { method: 'PUT', body: { scope: 'global', list: [] } });
  });

  it('per-role session timeouts, passkey count and previewable size', async () => {
    const u = await makeUser('ro-values');
    const id = await newRole('Short sessions');
    await assign(u.id, id);
    await limits(`role:${id}`, { sessionIdleSec: 600, sessionAbsSec: 3600, passkeysMax: 1, viewer: true, viewerMaxBytes: 1024 * 1024 });
    const login = await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'ro-values', proof: proofFor(USER_PW) }, ip: freshIp() });
    expect(login.headers.get('set-cookie')).toMatch(/Max-Age=600\b/);
    const cookie = login.headers.get('set-cookie').split(';')[0];
    // One passkey at most.
    const auth = new SoftAuthenticator();
    const add = async () => {
      const o = await (await fetchJson('/api/private/me/passkeys/options', { method: 'POST', body: {}, cookie, ip: freshIp() })).json();
      if (!o.publicKey) return o.error;
      const credential = await auth.create(o.publicKey, ORIGIN);
      return (await fetchJson('/api/private/me/passkeys', { method: 'POST', body: { challengeId: o.challengeId, credential, name: 'k', current: proofFor(USER_PW) }, cookie, ip: freshIp() })).status;
    };
    expect(await add()).toBe(201);
    expect(await add()).toBe('too_many_passkeys');
    // The owner keeps the server-wide values.
    const ownerLogin = await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'owner', proof: proofFor('owner-password') }, ip: freshIp() });
    expect(ownerLogin.headers.get('set-cookie')).not.toMatch(/Max-Age=600\b/);
  });
});

describe('roles in export and import', () => {
  it('round-trip: the role travels in system, the user carries its name', async () => {
    const CURRENT = proofFor('owner-password');
    const u = await makeUser('ro-export', 'export-password-12');
    const id = await newRole('Exported role');
    await assign(u.id, id);
    await limits(`role:${id}`, { maxViews: 13 });
    const doc = (await (await raw('/api/private/admin/export', { method: 'POST', body: { current: CURRENT, system: true, users: [u.id], credentials: true, config: true } })).json()).document;
    expect(doc.users[0].config).toEqual({ role: 'Exported role' });
    expect(doc.system.roles.find((r) => r.name === 'Exported role').limits.all).toEqual({ maxViews: 13 });
    await raw(`/api/private/admin/users/${u.id}`, { method: 'DELETE' });
    await raw(`/api/private/admin/roles/${id}`, { method: 'DELETE' });
    // Without the system part the role is missing: refused in the preview.
    const noSys = await (await raw('/api/private/admin/import', { method: 'POST', body: { current: CURRENT, document: doc, decisions: { system: false, users: { 'ro-export': {} } }, dryRun: true } })).json();
    expect(noSys.plan.errors.join(' ')).toMatch(/role "Exported role" does not exist here/);
    const ok = await raw('/api/private/admin/import', { method: 'POST', body: { current: CURRENT, document: doc, decisions: { system: true, users: { 'ro-export': {} } }, dryRun: false } });
    expect(ok.status).toBe(200);
    const cookie = (await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'ro-export', proof: proofFor('export-password-12') }, ip: freshIp() })).headers.get('set-cookie').split(';')[0];
    expect((await me(cookie)).limits.maxViews).toBe(13);
  });

  it('a file from before roles: per-user settings are checked, then ignored with a warning', async () => {
    const CURRENT = proofFor('owner-password');
    const doc = { format: 'secbin-export/v1', created: 1, users: [{ username: 'ro-legacy', credentials: { salt: 'AAAAAAAAAAAAAAAAAAAAAA', t: 3, verifier: 'a'.repeat(64), disabled: false }, config: { limits: { all: { maxViews: 2 }, api: {} }, quotas: [], viewerRules: [] } }] };
    const r = await (await raw('/api/private/admin/import', { method: 'POST', body: { current: CURRENT, document: doc, decisions: { system: false, users: { 'ro-legacy': {} } }, dryRun: true } })).json();
    expect(r.plan.warnings.join(' ')).toMatch(/per-user settings in the file are ignored/);
    expect(r.plan.users[0].parts).toEqual(['credentials']);
  });
});
