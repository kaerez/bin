// api-scopes.test.js — per-key API scopes: chosen at creation (every scope by
// default), enforced on each API-key route, listed with the key.
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson } from './helpers.js';
import { encryptPaste } from '../public/js/crypto.js';

let oc;
beforeAll(async () => { oc = await owner(); });

describe('API key scopes', () => {
  it('defaults to every scope, validates, and enforces per route', async () => {
    const u = await makeUser('scopes-user');
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch: { apiEnabled: true } } });
    const mk = async (body) => fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body });
    const all = await (await mk({ name: 'all' })).json();
    const files = await (await mk({ name: 'files-only', scopes: ['files'] })).json();
    for (const bad of [[], ['admin'], 'notes', ['notes', 'nope']]) expect((await mk({ name: 'bad', scopes: bad })).status).toBe(400);
    const { keys } = await (await fetchJson('/api/private/me/keys', { cookie: u.cookie })).json();
    expect(keys.find((k) => k.name === 'all').scopes).toEqual(['notes', 'files', 'policy']);
    expect(keys.find((k) => k.name === 'files-only').scopes).toEqual(['files']);

    const bearer = (k) => ({ authorization: `Bearer ${k}` });
    const { body } = await encryptPaste({ text: 'x' });
    expect((await fetchJson('/api/private/paste', { method: 'POST', headers: bearer(all.key), body: { paste: body } })).status).toBe(201);
    const denied = await fetchJson('/api/private/paste', { method: 'POST', headers: bearer(files.key), body: { paste: body } });
    expect(denied.status).toBe(403);
    expect((await denied.json()).error).toBe('scope_denied');
    expect((await fetchJson('/api/private/policy', { headers: bearer(files.key) })).status).toBe(403);
    expect((await fetchJson('/api/private/policy', { headers: bearer(all.key) })).status).toBe(200);
    expect((await fetchJson('/api/private/file', { method: 'POST', headers: bearer(files.key), body: { views: 1, expire: '1h', padded: 65536, files: 1, maxFile: 10 } })).status).toBe(201);
    // Keys never reach session-only routes, whatever their scopes.
    expect((await fetchJson('/api/private/me', { headers: bearer(all.key) })).status).toBe(403);
  });
});
