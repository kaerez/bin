// api-scopes.test.js — per-key API scopes: chosen at creation (the creation
// scopes by default; "read" and "manage" are opted into), enforced on each
// API-key route, listed with the key. "read" lists the key user's shares and
// their receipts, "manage" labels / extends / revokes them — only their own,
// under the admin's locks and the account's API limits.
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, proofFor, USER_PW, createNote, openNote, intent } from './helpers.js';
import { encryptPaste } from '../public/js/crypto.js';

let oc;
beforeAll(async () => { oc = await owner(); });
const bearer = (k) => ({ authorization: `Bearer ${k}` });
const limits = (scope, patch, channel = 'all') => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope, channel, patch } });
const mkKey = async (u, body) => fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { current: proofFor(USER_PW), ...body } });
/** A user with API keys enabled and one key per requested scope set. */
async function apiUser(name, sets) {
  const u = await makeUser(name);
  expect((await limits(u.id, { apiEnabled: true })).status).toBe(200);
  const keys = {};
  for (const [label, scopes] of Object.entries(sets)) {
    const r = await mkKey(u, { name: label, scopes });
    expect(r.status).toBe(201);
    keys[label] = (await r.json()).key;
  }
  return { ...u, keys };
}
const nowSec = () => Math.floor(Date.now() / 1000);

describe('API key scopes', () => {
  it('defaults to the creation scopes, validates, and enforces per route', async () => {
    const u = await makeUser('scopes-user');
    await limits(u.id, { apiEnabled: true });
    const mk = (body) => mkKey(u, body);
    const all = await (await mk({ name: 'default' })).json();
    const files = await (await mk({ name: 'files-only', scopes: ['files'] })).json();
    expect((await mk({ name: 'everything', scopes: ['manage', 'read', 'policy', 'files', 'notes'] })).status).toBe(201);
    for (const bad of [[], ['admin'], 'notes', ['notes', 'nope'], ['account'], ['read', 'write']]) expect((await mk({ name: 'bad', scopes: bad })).status).toBe(400);
    const { keys } = await (await fetchJson('/api/private/me/keys', { cookie: u.cookie })).json();
    // Least privilege: without a choice a key only creates (read / manage are opt-in).
    expect(keys.find((k) => k.name === 'default').scopes).toEqual(['notes', 'files', 'policy']);
    expect(keys.find((k) => k.name === 'files-only').scopes).toEqual(['files']);
    expect(keys.find((k) => k.name === 'everything').scopes).toEqual(['notes', 'files', 'policy', 'read', 'manage']); // canonical order

    const { body } = await encryptPaste({ text: 'x' });
    expect((await fetchJson('/api/private/paste', { method: 'POST', headers: bearer(all.key), body: { paste: body } })).status).toBe(201);
    const denied = await fetchJson('/api/private/paste', { method: 'POST', headers: bearer(files.key), body: { paste: body } });
    expect(denied.status).toBe(403);
    expect((await denied.json()).error).toBe('scope_denied');
    expect((await fetchJson('/api/private/policy', { headers: bearer(files.key) })).status).toBe(403);
    expect((await fetchJson('/api/private/policy', { headers: bearer(all.key) })).status).toBe(200);
    expect((await fetchJson('/api/private/file', { method: 'POST', headers: bearer(files.key), body: { views: 1, expire: '1h', padded: 65536, files: 1, maxFile: 10 } })).status).toBe(201);
    // The default key cannot list or change anything.
    for (const [path, init] of [['/api/private/shares', {}], ['/api/private/shares/kAAAAAAAAAAAAAAAAAAAAA', { method: 'PATCH', body: { label: 'x' } }]]) {
      const r = await fetchJson(path, { ...init, headers: bearer(all.key) });
      expect(r.status).toBe(403);
      expect(await r.json()).toMatchObject({ error: 'scope_denied' });
    }
    // Keys never reach session-only routes, whatever their scopes.
    expect((await fetchJson('/api/private/me', { headers: bearer(all.key) })).status).toBe(403);
  });

  it('scopes can be changed later (PATCH), by the user and by the owner', async () => {
    const u = await apiUser('scopes-edit', { k: ['notes'] });
    expect((await fetchJson('/api/private/shares', { headers: bearer(u.keys.k) })).status).toBe(403);
    const { keys } = await (await fetchJson('/api/private/me/keys', { cookie: u.cookie })).json();
    const id = keys[0].id;
    const r = await fetchJson(`/api/private/me/keys/${id}`, { method: 'PATCH', cookie: u.cookie, body: { scopes: ['notes', 'read'], current: proofFor(USER_PW) } });
    expect(r.status).toBe(200);
    expect((await fetchJson('/api/private/shares', { headers: bearer(u.keys.k) })).status).toBe(200);
    // The owner, for another user (Admin → Users → API keys): no confirmation.
    const ar = await fetchJson(`/api/private/admin/users/${u.id}/keys/${id}`, { method: 'PATCH', cookie: oc, body: { scopes: ['manage'] } });
    expect(ar.status).toBe(200);
    expect((await fetchJson('/api/private/shares', { headers: bearer(u.keys.k) })).status).toBe(403);
    const made = await fetchJson(`/api/private/admin/users/${u.id}/keys`, { method: 'POST', cookie: oc, body: { name: 'by-owner', scopes: ['read'] } });
    expect(made.status).toBe(201);
    expect((await fetchJson('/api/private/shares', { headers: bearer((await made.json()).key) })).status).toBe(200);
  });
});

describe('"read": the key user\'s shares and receipts', () => {
  it('lists, shows one share and its receipts — only the key user\'s own', async () => {
    const u = await apiUser('read-user', { read: ['read'], create: ['notes'] });
    const other = await makeUser('read-other');
    const mine = await createNote(null, { views: 3, bar: true }, { label: 'mine', headers: bearer(u.keys.create) });
    expect(mine.res.status).toBe(201);
    const bySession = await createNote(u.cookie, {}, { label: 'from the browser' });
    const theirs = await createNote(other.cookie, {}, { label: 'theirs' });
    expect((await openNote(mine.id, mine.fragment)).res.status).toBe(200);

    const list = await fetchJson('/api/private/shares', { headers: bearer(u.keys.read) });
    expect(list.status).toBe(200);
    const l = await list.json();
    expect(l.rows.map((r) => r.id).sort()).toEqual([mine.id, bySession.id].sort());
    expect(l.total).toBe(2);
    const row = l.rows.find((r) => r.id === mine.id);
    expect(row).toMatchObject({ label: 'mine', status: 'active', views_total: 3, left: 2, opens: 1, locked: 0 });
    expect(list.headers.get('set-cookie')).toBeNull(); // a key never gets a session
    // The same filters as the dashboard.
    expect((await (await fetchJson('/api/private/shares?q=browser', { headers: bearer(u.keys.read) })).json()).rows.map((r) => r.id)).toEqual([bySession.id]);
    expect((await (await fetchJson('/api/private/shares?status=revoked', { headers: bearer(u.keys.read) })).json()).total).toBe(0);

    const one = await fetchJson(`/api/private/shares/${mine.id}`, { headers: bearer(u.keys.read) });
    expect(one.status).toBe(200);
    const { share } = await one.json();
    expect(share).toMatchObject({ id: mine.id, kind: 'text', label: 'mine', status: 'active', views_total: 3, left: 2, opens: 1 });
    expect(share.user_id).toBeUndefined();

    const opens = await (await fetchJson(`/api/private/shares/${mine.id}/opens`, { headers: bearer(u.keys.read) })).json();
    expect(opens.total).toBe(1);
    expect(Object.keys(opens.rows[0])).toEqual(['ts']); // the same fields as the dashboard (receipt* limits)

    // Someone else's share: not found, exactly as for a stranger's session.
    for (const path of [`/api/private/shares/${theirs.id}`, `/api/private/shares/${theirs.id}/opens`]) {
      const r = await fetchJson(path, { headers: bearer(u.keys.read) });
      expect(r.status).toBe(404);
    }
    // "read" never changes anything.
    for (const [path, init] of [[`/api/private/shares/${mine.id}`, { method: 'PATCH', body: { label: 'x' } }], [`/api/private/shares/${mine.id}/revoke`, { method: 'POST', headers: intent }]]) {
      const r = await fetchJson(path, { ...init, headers: { ...init.headers, ...bearer(u.keys.read) } });
      expect(r.status).toBe(403);
      expect((await r.json()).error).toBe('scope_denied');
    }
    // The session's view is unchanged.
    const s = await (await fetchJson(`/api/private/shares/${mine.id}`, { cookie: u.cookie })).json();
    expect(s.share.id).toBe(mine.id);
  });
});

describe('"manage": label, extend and revoke the key user\'s shares', () => {
  it('labels, extends views and expiry, and revokes; logs the key', async () => {
    const u = await apiUser('manage-user', { manage: ['manage'], read: ['read'] });
    const n = await createNote(u.cookie, { views: 2, bar: true, expire: '1h' });
    const patch = (id, body, key = u.keys.manage) => fetchJson(`/api/private/shares/${id}`, { method: 'PATCH', headers: bearer(key), body });

    expect((await patch(n.id, { label: 'renamed by the API' })).status).toBe(200);
    expect((await patch(n.id, { views: 6 })).status).toBe(200);
    const until = nowSec() + 3 * 86400;
    expect((await patch(n.id, { expires: until })).status).toBe(200);
    const { share } = await (await fetchJson(`/api/private/shares/${n.id}`, { headers: bearer(u.keys.read) })).json();
    expect(share).toMatchObject({ label: 'renamed by the API', views_total: 6, left: 6, expires: until });
    // Increase-only, as in the dashboard.
    expect((await patch(n.id, { expires: nowSec() + 60 })).status).toBe(400);
    expect((await patch(n.id, {})).status).toBe(400);
    expect((await patch(n.id, { label: 'x'.repeat(101) })).status).toBe(400);

    // Revoke: the intent header is required, then the content is gone.
    expect((await fetchJson(`/api/private/shares/${n.id}/revoke`, { method: 'POST', headers: bearer(u.keys.manage) })).status).toBe(400);
    const rv = await fetchJson(`/api/private/shares/${n.id}/revoke`, { method: 'POST', headers: { ...bearer(u.keys.manage), ...intent } });
    expect(rv.status).toBe(200);
    expect([404, 410]).toContain((await fetchJson(`/api/paste/${n.id}`)).status);
    expect((await (await fetchJson(`/api/private/shares/${n.id}`, { headers: bearer(u.keys.read) })).json()).share.status).toBe('revoked');
    expect((await patch(n.id, { views: 9 })).status).toBe(409); // no longer active

    // The activity log names the key (its id, never the secret).
    const { keys } = await (await fetchJson('/api/private/me/keys', { cookie: u.cookie })).json();
    const kid = keys.find((k) => k.name === 'manage').id;
    const { rows } = await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json();
    expect(rows.find((r) => r.action === 'share.revoked').detail).toContain(`apikey=${kid}`);
    expect(rows.filter((r) => r.action === 'share.updated').every((r) => r.detail.includes(`apikey=${kid}`))).toBe(true);
    expect(JSON.stringify(rows)).not.toContain(u.keys.manage);
  });

  it('never touches another user\'s share', async () => {
    const u = await apiUser('manage-stranger', { manage: ['manage', 'read'] });
    const other = await makeUser('manage-victim');
    const n = await createNote(other.cookie, { views: 2, bar: true });
    expect((await fetchJson(`/api/private/shares/${n.id}`, { method: 'PATCH', headers: bearer(u.keys.manage), body: { label: 'mine now' } })).status).toBe(404);
    expect((await fetchJson(`/api/private/shares/${n.id}/revoke`, { method: 'POST', headers: { ...bearer(u.keys.manage), ...intent } })).status).toBe(404);
    expect((await fetchJson(`/api/private/shares/${n.id}/opens`, { headers: bearer(u.keys.manage) })).status).toBe(404);
    expect((await openNote(n.id, n.fragment)).res.status).toBe(200); // still there
  });

  it('respects the administrator\'s share locks exactly like the session', async () => {
    const u = await apiUser('manage-locked', { manage: ['manage'] });
    const n = await createNote(u.cookie, { views: 2, bar: true });
    const lock = (locked) => fetchJson(`/api/private/admin/shares/${n.id}/lock`, { method: 'POST', cookie: oc, body: { locked } });
    expect((await lock(true)).status).toBe(200);
    for (const auth of [{ headers: bearer(u.keys.manage) }, { cookie: u.cookie }]) {
      const e = await fetchJson(`/api/private/shares/${n.id}`, { method: 'PATCH', ...auth, body: { views: 5 } });
      expect(e.status).toBe(423);
      expect((await e.json()).error).toBe('share_locked');
      const r = await fetchJson(`/api/private/shares/${n.id}/revoke`, { method: 'POST', ...auth, headers: { ...auth.headers, ...intent } });
      expect(r.status).toBe(423);
    }
    expect((await openNote(n.id, n.fragment)).res.status).toBe(200); // nothing was destroyed
    expect((await lock(false)).status).toBe(200);
    expect((await fetchJson(`/api/private/shares/${n.id}/revoke`, { method: 'POST', headers: { ...bearer(u.keys.manage), ...intent } })).status).toBe(200);
  });

  it('holds extensions made with a key to the account\'s API limits', async () => {
    const u = await apiUser('manage-limits', { manage: ['manage'] });
    const n = await createNote(u.cookie, { views: 2, bar: true, expire: '1h' });
    expect((await limits(u.id, { maxViews: 4, maxExpireSec: 7200, allowUnlimitedViews: false }, 'api')).status).toBe(200);
    const viaKey = (body) => fetchJson(`/api/private/shares/${n.id}`, { method: 'PATCH', headers: bearer(u.keys.manage), body });
    const tooMany = await viaKey({ views: 5 });
    expect(tooMany.status).toBe(403);
    expect(await tooMany.json()).toMatchObject({ error: 'too_many_views', max: 4 });
    expect((await (await viaKey({ views: null })).json()).error).toBe('unlimited_views_disabled');
    expect((await (await viaKey({ expires: nowSec() + 86400 })).json()).error).toBe('expiry_too_long');
    expect((await viaKey({ views: 4 })).status).toBe(200);
    // The browser (channel "all") still has the account's full limits.
    expect((await fetchJson(`/api/private/shares/${n.id}`, { method: 'PATCH', cookie: u.cookie, body: { views: 8, expires: nowSec() + 86400 } })).status).toBe(200);
  });
});

describe('what stops a key', () => {
  it('API use turned off for the account, a disabled account, and admin routes', async () => {
    const u = await apiUser('stop-user', { all: ['notes', 'files', 'policy', 'read', 'manage'] });
    const n = await createNote(u.cookie, { views: 2, bar: true });
    expect((await fetchJson('/api/private/shares', { headers: bearer(u.keys.all) })).status).toBe(200);

    // Keys never reach the account, its keys, or the admin panel.
    for (const path of ['/api/private/me', '/api/private/me/keys', '/api/private/me/activity', '/api/private/admin/shares', `/api/private/admin/shares/${n.id}`, '/api/private/admin/users']) {
      const r = await fetchJson(path, { headers: bearer(u.keys.all) });
      expect(r.status).toBe(403);
      expect((await r.json()).error).toBe('api_key_not_allowed');
    }
    expect((await fetchJson(`/api/private/admin/shares/${n.id}/revoke`, { method: 'POST', headers: { ...bearer(u.keys.all), ...intent } })).status).toBe(403);

    // apiEnabled off stops existing keys at once, on every route.
    expect((await limits(u.id, { apiEnabled: false })).status).toBe(200);
    for (const [path, init] of [['/api/private/shares', {}], [`/api/private/shares/${n.id}/opens`, {}], [`/api/private/shares/${n.id}`, { method: 'PATCH', body: { label: 'x' } }], [`/api/private/shares/${n.id}/revoke`, { method: 'POST', headers: intent }]]) {
      const r = await fetchJson(path, { ...init, headers: { ...init.headers, ...bearer(u.keys.all) } });
      expect(r.status).toBe(401);
      expect((await r.json()).error).toBe('invalid_api_key');
    }
    expect((await limits(u.id, { apiEnabled: true })).status).toBe(200);
    expect((await fetchJson('/api/private/shares', { headers: bearer(u.keys.all) })).status).toBe(200);

    // A disabled account: refused, even with a valid key.
    await fetchJson(`/api/private/admin/users/${u.id}`, { method: 'PATCH', cookie: oc, body: { disabled: true } });
    for (const [path, init] of [['/api/private/shares', {}], [`/api/private/shares/${n.id}/revoke`, { method: 'POST', headers: intent }]]) {
      const r = await fetchJson(path, { ...init, headers: { ...init.headers, ...bearer(u.keys.all) } });
      expect(r.status).toBe(403);
      expect((await r.json()).error).toBe('account_disabled');
    }
    expect((await openNote(n.id, n.fragment)).res.status).toBe(200);
  });

  it('a malformed, unknown or revoked key', async () => {
    const u = await apiUser('stop-revoked', { r: ['read'] });
    expect((await fetchJson('/api/private/shares', { headers: { authorization: 'Bearer nope' } })).status).toBe(401);
    expect((await fetchJson('/api/private/shares', { headers: bearer(`sbk_${'A'.repeat(43)}`) })).status).toBe(401);
    const { keys } = await (await fetchJson('/api/private/me/keys', { cookie: u.cookie })).json();
    await fetchJson(`/api/private/me/keys/${keys[0].id}`, { method: 'DELETE', cookie: u.cookie, headers: intent, body: { current: proofFor(USER_PW) } });
    expect((await fetchJson('/api/private/shares', { headers: bearer(u.keys.r) })).status).toBe(401);
  });
});

describe('export / import of the new scopes', () => {
  const CURRENT = proofFor('owner-password');
  it('keeps "read" and "manage" across a round trip; the key keeps working', async () => {
    const u = await apiUser('scopes-portable', { rm: ['read', 'manage'] });
    const exp = await fetchJson('/api/private/admin/export', { method: 'POST', cookie: oc, body: { current: CURRENT, users: [u.id], credentials: true, apiKeys: true } });
    expect(exp.status).toBe(200);
    const { document } = await exp.json();
    expect(document.users[0].apiKeys[0].scopes).toEqual(['read', 'manage']);
    expect((await fetchJson(`/api/private/admin/users/${u.id}`, { method: 'DELETE', cookie: oc, headers: intent })).status).toBe(200);
    expect((await fetchJson('/api/private/shares', { headers: bearer(u.keys.rm) })).status).toBe(401);

    // An unknown scope is refused by the import validation.
    const bad = structuredClone(document);
    bad.users[0].apiKeys[0].scopes = ['read', 'admin'];
    expect((await fetchJson('/api/private/admin/import', { method: 'POST', cookie: oc, body: { current: CURRENT, document: bad, decisions: { system: false, users: { 'scopes-portable': {} } } } })).status).toBe(400);

    const imp = await fetchJson('/api/private/admin/import', { method: 'POST', cookie: oc, body: { current: CURRENT, document, decisions: { system: false, users: { 'scopes-portable': {} } }, dryRun: false } });
    expect(imp.status).toBe(200);
    // The imported account has the Default role (API keys off): turn API use on for it.
    const users = await (await fetchJson('/api/private/admin/users', { cookie: oc })).json();
    const nu = users.users.find((x) => x.username === 'scopes-portable');
    expect((await limits(nu.id, { apiEnabled: true })).status).toBe(200);
    const r = await fetchJson('/api/private/shares', { headers: bearer(u.keys.rm) });
    expect(r.status).toBe(200);
    expect((await fetchJson('/api/private/paste', { method: 'POST', headers: bearer(u.keys.rm), body: { paste: (await encryptPaste({ text: 'x' })).body } })).status).toBe(403);
  });
});
