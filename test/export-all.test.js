// export-all.test.js — every part of an export is optional and chosen twice:
// when exporting and again when importing. Parts: settings, roles (Default +
// custom), IP rules, the panel's Turnstile keys, the public account; per user:
// credentials, role, API keys (they keep working), passkeys and recovery codes
// (passkeys only on the same hostname).
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, freshIp, proofFor, ORIGIN, USER_PW } from './helpers.js';
import { SoftAuthenticator } from './soft-authenticator.js';

let oc;
beforeAll(async () => { oc = await owner(); });
const CURRENT = proofFor('owner-password');
const post = (path, body, cookie = oc) => fetchJson(path, { method: 'POST', body, cookie, ip: freshIp() });
const exportDoc = async (opts) => { const r = await post('/api/private/admin/export', { current: CURRENT, ...opts }); expect(r.status).toBe(200); return (await r.json()).document; };
const importDoc = (document, decisions, dryRun = true) => post('/api/private/admin/import', { current: CURRENT, document, decisions, dryRun });
const del = (id) => fetchJson(`/api/private/admin/users/${id}`, { method: 'DELETE', cookie: oc, headers: { 'x-secbin-intent': '1' } });
const login = async (username, password) => (await post('/api/auth/login', { username, proof: proofFor(password) }, undefined));

describe('choosing parts', () => {
  it('exports only the system parts asked for', async () => {
    const d = await exportDoc({ system: { ipRules: true, turnstile: true } });
    expect(Object.keys(d.system).sort()).toEqual(['ipRules', 'turnstile']);
    const r = await exportDoc({ system: { roles: true } });
    expect(Object.keys(r.system).sort()).toEqual(['limits', 'quotas', 'roles', 'viewerRules']);
  });

  it('imports only the system parts chosen, and refuses a part the file lacks', async () => {
    const r = await fetchJson('/api/private/admin/turnstile', { method: 'PUT', cookie: oc, body: { sitekey: '0x4AAAAAAAexportsite', secret: '0x4AAAAAAAexportsecret1', current: CURRENT } });
    expect(r.status).toBe(200);
    const doc = await exportDoc({ system: true });
    expect(doc.system.turnstile).toEqual({ sitekey: '0x4AAAAAAAexportsite', secret: '0x4AAAAAAAexportsecret1' });
    await fetchJson('/api/private/admin/turnstile', { method: 'PUT', cookie: oc, body: { clear: true, current: CURRENT } });
    const p = await (await importDoc(doc, { system: { turnstile: true }, users: {} })).json();
    expect(p.plan.system.parts).toEqual(['turnstile']);
    expect((await importDoc(doc, { system: { turnstile: true }, users: {} }, false)).status).toBe(200);
    expect(await (await fetchJson('/api/private/admin/turnstile', { cookie: oc })).json()).toMatchObject({ sitekey: '0x4AAAAAAAexportsite', secretSet: true });
    await fetchJson('/api/private/admin/turnstile', { method: 'PUT', cookie: oc, body: { clear: true, current: CURRENT } });
    const small = await exportDoc({ system: { ipRules: true } });
    expect((await importDoc(small, { system: { settings: true }, users: {} })).status).toBe(400);
  });

  it('the public account travels on its own', async () => {
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: 'public-user-0000', channel: 'all', patch: { maxViews: 4 } } });
    const doc = await exportDoc({ system: { public: true } });
    expect(doc.system.public.limits.all.maxViews).toBe(4);
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: 'public-user-0000', channel: 'all', patch: { maxViews: 9 } } });
    expect((await importDoc(doc, { system: { public: true }, users: {} }, false)).status).toBe(200);
    const d = await (await fetchJson('/api/private/admin/users/public-user-0000', { cookie: oc })).json();
    expect(d.limits.all.maxViews).toBe(4);
  });
});

describe('users: API keys and passkeys', () => {
  it('keys, passkeys and recovery codes keep working after a round trip; parts are chosen per user', async () => {
    const u = await makeUser('ea-full');
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch: { apiEnabled: true } } });
    const key = (await (await post('/api/private/me/keys', { name: 'cli', scopes: ['policy'], current: proofFor(USER_PW) }, u.cookie)).json()).key;
    const auth = new SoftAuthenticator();
    const o = await (await post('/api/private/me/passkeys/options', {}, u.cookie)).json();
    const reg = await (await post('/api/private/me/passkeys', { challengeId: o.challengeId, credential: await auth.create(o.publicKey, ORIGIN), name: 'Laptop', current: proofFor(USER_PW) }, u.cookie)).json();
    const doc = await exportDoc({ system: { roles: true }, users: [u.id], credentials: true, config: true, apiKeys: true, passkeys: true });
    const e = doc.users[0];
    expect(e.apiKeys).toHaveLength(1);
    expect(e.apiKeys[0]).toMatchObject({ name: 'cli', scopes: ['policy'] });
    expect(JSON.stringify(e)).not.toContain(key); // the hash only
    expect(e.passkeys.keys).toHaveLength(1);
    expect(e.passkeys.recoveryCodes).toHaveLength(20);
    expect((await del(u.id)).status).toBe(200);

    // Credentials only: no keys, no passkeys.
    const partial = await (await importDoc(doc, { system: false, users: { 'ea-full': { parts: ['credentials'] } } })).json();
    expect(partial.plan.users[0].parts).toEqual(['credentials']);
    // Everything.
    const plan = await (await importDoc(doc, { system: { roles: true }, users: { 'ea-full': {} } })).json();
    expect(plan.plan.errors).toEqual([]);
    expect(plan.plan.warnings.join(' ')).toMatch(/API key will work here/);
    expect((await importDoc(doc, { system: { roles: true }, users: { 'ea-full': {} } }, false)).status).toBe(200);
    expect((await fetchJson('/api/private/policy', { headers: { authorization: `Bearer ${key}` } })).status).toBe(200);
    const po = await (await post('/api/auth/passkey/options', {}, undefined)).json();
    expect((await post('/api/auth/passkey/login', { challengeId: po.challengeId, credential: await auth.get(po.publicKey, ORIGIN) }, undefined)).status).toBe(200);
    expect((await post('/api/auth/recovery', { username: 'ea-full', code: reg.codes[0] }, undefined)).status).toBe(200);
    expect((await login('ea-full', USER_PW)).status).toBe(200);
  });

  it('refuses keys or passkeys that belong to another account here; warns about another hostname', async () => {
    const a = await makeUser('ea-a');
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: a.id, channel: 'all', patch: { apiEnabled: true } } });
    await post('/api/private/me/keys', { name: 'k', current: proofFor(USER_PW) }, a.cookie);
    const doc = await exportDoc({ users: [a.id], credentials: true, apiKeys: true, passkeys: true });
    doc.users[0].username = 'ea-b';
    const p = await (await importDoc(doc, { system: false, users: { 'ea-b': {} } })).json();
    expect(p.plan.errors.join(' ')).toMatch(/already belongs to another account/);
    doc.origin = 'https://elsewhere.example';
    doc.users[0].apiKeys = [];
    doc.users[0].passkeys.keys = [{ id: 'A'.repeat(22), name: 'x', publicKey: 'AAAA', alg: -7, signCount: 0, transports: [], backupEligible: false, backedUp: false, created: 1, lastUsed: null }];
    const w = await (await importDoc(doc, { system: false, users: { 'ea-b': {} } })).json();
    expect(w.plan.warnings.join(' ')).toMatch(/registered for elsewhere.example and will not work on/);
  });

  it('validates the new parts', async () => {
    const u = await makeUser('ea-val');
    const base = await exportDoc({ users: [u.id], credentials: true, apiKeys: true, passkeys: true });
    for (const mutate of [
      (d) => { d.users[0].apiKeys = [{ hash: 'zz', name: 'k', created: 1, expires: null, lastUsed: null, scopes: ['notes'] }]; },
      (d) => { d.users[0].apiKeys = [{ hash: 'a'.repeat(64), name: 'k', created: 1, expires: null, lastUsed: null, scopes: ['admin'] }]; },
      (d) => { d.users[0].passkeys.recoveryCodes = ['nope']; },
      (d) => { d.users[0].passkeys.keys = [{ id: 'short', name: 'x', publicKey: 'AA', alg: -7, signCount: 0, transports: [], backupEligible: false, backedUp: false, created: 1, lastUsed: null }]; },
      (d) => { d.users[0].passkeys.keys = [{ id: 'A'.repeat(22), name: 'x', publicKey: 'AA', alg: 1, signCount: 0, transports: [], backupEligible: false, backedUp: false, created: 1, lastUsed: null }]; },
      (d) => { d.system = { turnstile: { sitekey: 'bad key', secret: 'x' } }; },
      (d) => { d.system = { limits: { all: {}, api: {} } }; }, // the Default role goes as a whole
    ]) {
      const d = structuredClone(base);
      mutate(d);
      expect((await importDoc(d, { system: false, users: {} })).status).toBe(400);
    }
    expect((await importDoc(base, { system: false, users: { 'ea-val': { parts: ['config'] } } })).status).toBe(400); // not in the file
  });
});
