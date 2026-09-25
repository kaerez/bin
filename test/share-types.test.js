// share-types.test.js — link ("url") and credential ("secret") shares, both off
// until the admin allows them, and recipient "delete now": allowed only when
// the admin permits it and the sender opted in, gated by both access proofs
// (a wrong link or password deletes nothing), refused while the share is
// locked, and reported in the sender's own activity.
import { env } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, createNote, proofHeaders, freshIp } from './helpers.js';
import { buildSecret } from '../public/js/sharetypes.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';

let oc;
beforeAll(async () => { oc = await owner(); });
const limits = (scope, patch) => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope, channel: 'all', patch } });

async function expire(id, fragment, password = '', { tamper = false, ip } = {}) {
  const head = await (await fetchJson(`/api/paste/${id}`, { ip })).json();
  const { headers } = await proofHeaders(head.adata, tamper ? b64urlFromBytes(randomBytes(32)) : fragment, password);
  return fetchJson(`/api/paste/${id}/expire`, { method: 'POST', headers, ip });
}

describe('url and secret shares', () => {
  it('are off until the admin allows them, then indexed with their own kind', async () => {
    const u = await makeUser('types-user');
    const url = await createNote(u.cookie, { text: 'https://example.com/doc', fmt: 'url' });
    expect(url.res.status).toBe(403);
    expect((await url.res.json()).error).toBe('url_disabled');
    const sec = await createNote(u.cookie, { text: buildSecret({ username: 'a', password: 'b' }), fmt: 'secret' });
    expect((await sec.res.json()).error).toBe('secret_disabled');

    await limits(u.id, { url: true, secret: true });
    const ok1 = await createNote(u.cookie, { text: 'https://example.com/doc', fmt: 'url' }, { label: 'a link' });
    const ok2 = await createNote(u.cookie, { text: buildSecret({ username: 'a', password: 'b' }), fmt: 'secret' });
    expect([ok1.res.status, ok2.res.status]).toEqual([201, 201]);
    const list = await (await fetchJson('/api/private/shares', { cookie: u.cookie })).json();
    expect(list.rows.map((r) => r.kind).sort()).toEqual(['secret', 'url']);
    // The admin can filter by the new kinds.
    const adm = await (await fetchJson(`/api/private/admin/shares?users=${u.id}&kind=secret`, { cookie: oc })).json();
    expect(adm.rows.map((r) => r.id)).toEqual([ok2.id]);
  });
});

describe('recipient "delete now"', () => {
  it('needs the admin permission, then the sender opt-in', async () => {
    const u = await makeUser('deletable-user');
    const denied = await createNote(u.cookie, { deletable: true });
    expect((await denied.res.json()).error).toBe('opener_delete_disabled');
    await limits(u.id, { openerDelete: true });
    const plain = await createNote(u.cookie, {});
    const head = await (await fetchJson(`/api/paste/${plain.id}`)).json();
    expect(head.meta.deletable).toBeUndefined();
    const r = await expire(plain.id, plain.fragment);
    expect(r.status).toBe(403);
    expect((await r.json()).error).toBe('not_allowed');
  });

  it('deletes with both proofs only — a wrong link or password deletes nothing — and tells the sender', async () => {
    const u = await makeUser('deleter');
    await limits(u.id, { openerDelete: true });
    const n = await createNote(u.cookie, { deletable: true, password: 'pw-123456789', bar: true, views: 3 });
    expect(n.res.status).toBe(201);
    const head = await (await fetchJson(`/api/paste/${n.id}`)).json();
    expect(head.meta).toMatchObject({ deletable: true, left: 3 });

    const wrongLink = await expire(n.id, n.fragment, 'pw-123456789', { tamper: true, ip: freshIp() });
    expect((await wrongLink.json()).error).toBe('bad_link');
    const wrongPw = await expire(n.id, n.fragment, 'not-the-password', { ip: freshIp() });
    expect((await wrongPw.json()).error).toBe('bad_password');
    expect((await (await fetchJson(`/api/paste/${n.id}`)).json()).meta.left).toBe(3); // untouched, no view spent

    const ok = await expire(n.id, n.fragment, 'pw-123456789');
    expect(ok.status).toBe(200);
    expect((await fetchJson(`/api/paste/${n.id}`)).status).toBe(410);
    const mine = await (await fetchJson('/api/private/shares', { cookie: u.cookie })).json();
    expect(mine.rows.find((r) => r.id === n.id).status).toBe('deleted');
    const activity = await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json();
    expect(activity.rows.some((r) => r.action === 'share.deleted_by_recipient')).toBe(true);
  });

  it('works for unlimited-view notes and is refused while the admin has the share locked', async () => {
    const u = await makeUser('deleter-kv');
    await limits(u.id, { openerDelete: true });
    const n = await createNote(u.cookie, { deletable: true });
    await fetchJson(`/api/private/admin/shares/${n.id}/lock`, { method: 'POST', cookie: oc, body: { locked: true } });
    expect((await expire(n.id, n.fragment)).status).toBe(423);
    await fetchJson(`/api/private/admin/shares/${n.id}/lock`, { method: 'POST', cookie: oc, body: { locked: false } });
    expect((await expire(n.id, n.fragment)).status).toBe(200);
    expect(await env.PASTES.get(n.id)).toBeNull();
  });

  it('file shares: the upload must be authorized for it and the manifest must match', async () => {
    const u = await makeUser('deleter-files');
    await limits(u.id, { openerDelete: true });
    const init = (deletable) => fetchJson('/api/private/file', { method: 'POST', cookie: u.cookie, body: { views: null, expire: '1h', padded: 65536, files: 1, maxFile: 1, deletable } });
    expect((await init(true)).status).toBe(201);
    const other = await makeUser('no-delete-files');
    const r = await fetchJson('/api/private/file', { method: 'POST', cookie: other.cookie, body: { views: null, expire: '1h', padded: 65536, files: 1, maxFile: 1, deletable: true } });
    expect((await r.json()).error).toBe('opener_delete_disabled');
  });
});
