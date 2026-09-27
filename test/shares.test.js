// shares.test.js — "My shares": ownership-scoped listing with live status,
// labels, increases (views / expiry) capped by the user's limits and never
// decreasing, irreversible revoke; API keys only with the read / manage scope.
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, createNote, openNote, intent, proofFor, USER_PW } from './helpers.js';

let oc;
beforeAll(async () => { oc = await owner(); });

const list = async (cookie, qs = '') => (await fetchJson(`/api/private/shares${qs}`, { cookie })).json();
const patch = (cookie, id, body) => fetchJson(`/api/private/shares/${id}`, { method: 'PATCH', cookie, body });

describe('my shares', () => {
  it('lists only my shares, with labels and live view counts; search by label', async () => {
    const u = await makeUser('sharer');
    const other = await makeUser('stranger');
    const a = await createNote(u.cookie, { text: 'a', bar: true, views: 3 }, { label: 'invoice for bob' });
    await createNote(u.cookie, { text: 'b' }, { label: 'misc' });
    await createNote(other.cookie, { text: 'c' }, { label: 'not yours' });
    await openNote(a.id, a.fragment);
    const mine = await list(u.cookie);
    expect(mine.rows.map((r) => r.label).sort()).toEqual(['invoice for bob', 'misc']);
    const row = mine.rows.find((r) => r.id === a.id);
    expect(row).toMatchObject({ kind: 'text', views_total: 3, left: 2, status: 'active' });
    expect((await list(u.cookie, '?q=invoice')).rows).toHaveLength(1);
    expect((await patch(other.cookie, a.id, { label: 'hijack' })).status).toBe(404);
    expect((await fetchJson(`/api/private/shares/${a.id}/revoke`, { method: 'POST', cookie: other.cookie, headers: intent })).status).toBe(404);
  });

  it('increases views and expiry within limits only, never decreases', async () => {
    const u = await makeUser('raiser');
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch: { maxViews: 10, maxExpireSec: 86400, allowUnlimitedViews: false } } });
    const n = await createNote(u.cookie, { text: 'x', bar: true, views: 2, expire: '1h' });
    const head = await (await fetchJson(`/api/paste/${n.id}`)).json();
    expect((await patch(u.cookie, n.id, { views: 1 })).status).toBe(400);
    expect((await patch(u.cookie, n.id, { views: 11 })).status).toBe(403);
    expect((await patch(u.cookie, n.id, { views: null })).status).toBe(403); // unlimited not allowed
    expect((await patch(u.cookie, n.id, { views: 5 })).status).toBe(200);
    expect((await patch(u.cookie, n.id, { expires: head.meta.expires - 10 })).status).toBe(400);
    expect((await patch(u.cookie, n.id, { expires: Math.floor(Date.now() / 1000) + 2 * 86400 })).status).toBe(403);
    const later = head.meta.expires + 3600;
    expect((await patch(u.cookie, n.id, { expires: later, label: 'raised' })).status).toBe(200);
    const h2 = await (await fetchJson(`/api/paste/${n.id}`)).json();
    expect(h2.meta).toMatchObject({ views: 5, left: 5, expires: later });
    const row = (await list(u.cookie)).rows.find((r) => r.id === n.id);
    expect(row).toMatchObject({ label: 'raised', views_total: 5 });
  });

  it('extends a KV note’s expiry; revoke is immediate and final', async () => {
    const n = await createNote(oc, { text: 'kv', expire: '1h' });
    const head = await (await fetchJson(`/api/paste/${n.id}`)).json();
    expect((await patch(oc, n.id, { views: 5 })).status).toBe(400); // already unlimited
    expect((await patch(oc, n.id, { expires: head.meta.expires + 60 })).status).toBe(200);
    expect((await (await fetchJson(`/api/paste/${n.id}`)).json()).meta.expires).toBe(head.meta.expires + 60);
    expect((await fetchJson(`/api/private/shares/${n.id}/revoke`, { method: 'POST', cookie: oc })).status).toBe(400); // intent header
    expect((await fetchJson(`/api/private/shares/${n.id}/revoke`, { method: 'POST', cookie: oc, headers: intent })).status).toBe(200);
    expect((await fetchJson(`/api/paste/${n.id}`)).status).toBe(404);
    expect((await patch(oc, n.id, { expires: head.meta.expires + 120 })).status).toBe(409);
    expect((await list(oc)).rows.find((r) => r.id === n.id).status).toBe('revoked');
  });

  it('takes an API key only with the matching scope (the full matrix is in api-scopes.test.js)', async () => {
    const u = await makeUser('sharer-key');
    expect((await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch: { apiEnabled: true } } })).status).toBe(200);
    const { key } = await (await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { name: 'create-only', current: proofFor(USER_PW) } })).json();
    // A create-only key (the default scopes) is refused; an unknown key is not a key.
    const denied = await fetchJson('/api/private/shares', { headers: { authorization: `Bearer ${key}` } });
    expect(denied.status).toBe(403);
    expect((await denied.json()).error).toBe('scope_denied');
    const unknown = await fetchJson('/api/private/shares', { headers: { authorization: `Bearer sbk_${'A'.repeat(43)}` } });
    expect(unknown.status).toBe(401);
    expect((await unknown.json()).error).toBe('invalid_api_key');
  });
});
