// public-access.test.js — anonymous creation through the built-in public
// account: off by default; the tracker (cookie + ETag + client copies) is
// issued statelessly, self-heals, breaks ties by use/age and blocks only an
// undecidable conflict; quotas are counted per tracker, per network, or both
// (permissive / restrictive); new senders are rate-limited per network on
// their first creation (never on page visits); the public account can never sign in, be
// deleted, renamed, impersonated, exported or hold API keys.
import { describe, it, expect, beforeAll } from 'vitest';
import { encryptPaste } from '../public/js/crypto.js';
import { owner, fetchJson, freshIp, proofFor, intent } from './helpers.js';

const PUBLIC_ID = 'public-user-0000';
let oc;
beforeAll(async () => { oc = await owner(); });

const settings = (patch) => fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: patch });
const quotas = (list) => fetchJson('/api/private/admin/quotas', { method: 'PUT', cookie: oc, body: { scope: PUBLIC_ID, list } });
const cookieVal = (res) => (res.headers.get('set-cookie') || '').match(/__Host-secbin_aid=([A-Za-z0-9_-]{32})/)?.[1] ?? null;

async function tracker(ip, { cookie, etag, copies } = {}) {
  const headers = {};
  if (cookie) headers.cookie = `__Host-secbin_aid=${cookie}`;
  if (etag) headers['if-none-match'] = `"${etag}"`;
  if (copies) headers['x-secbin-aid-copies'] = copies;
  const res = await fetchJson('/api/public/t', { headers, ip });
  return { res, aid: cookieVal(res), body: res.status === 200 ? await res.json() : null };
}

async function publicNote(ip, aid, extra = {}) {
  const { body } = await encryptPaste({ text: 'anonymous', bar: true, views: 1, expire: '1h', ...extra });
  const headers = aid ? { cookie: `__Host-secbin_aid=${aid}`, 'x-secbin-aid': aid } : {};
  return fetchJson('/api/public/paste', { method: 'POST', headers, ip, body: { paste: body, label: 'planted label' } });
}

describe('public access', () => {
  it('is off by default', async () => {
    expect(await (await fetchJson('/api/public/profile')).json()).toEqual({ enabled: false });
    expect((await publicNote(freshIp())).status).toBe(403);
  });

  it('tracker mode: issues, re-seeds, and counts the quota per browser', async () => {
    await settings({ 'public.enabled': true, 'public.tracking': 'tracker', 'public.newTrackersPerIp': 5 });
    await quotas([{ channel: 'all', kind: 'all', n: 1, unit: 'd', max: 2 }]);
    const prof = await (await fetchJson('/api/public/profile')).json();
    expect(prof).toMatchObject({ enabled: true, tracking: 'tracker' });
    expect(prof.notice).toMatch(/identifier/);
    expect(prof.limits.files).toBe(false); // conservative public defaults

    const ip = freshIp();
    const first = await tracker(ip);
    expect(first.body.status).toBe('new');
    expect(first.res.headers.get('etag')).toBe(`"${first.aid}"`);
    expect(first.res.headers.get('cache-control')).toMatch(/private/);
    expect(first.res.headers.get('cache-control')).not.toMatch(/no-store/); // the browser must keep the ETag copy
    expect(first.res.headers.get('set-cookie')).toMatch(/HttpOnly; SameSite=Strict/);
    // Every copy agreeing → 304 (the browser's cached body carries the id).
    expect((await tracker(ip, { cookie: first.aid, etag: first.aid })).res.status).toBe(304);
    // Cookie cleared: the ETag and a client copy restore it.
    const healed = await tracker(ip, { etag: first.aid, copies: `ls=${first.aid};idb=garbage` });
    expect(healed.body).toMatchObject({ aid: first.aid, status: 'healed' });

    // Creating needs the id in both the cookie and the header.
    expect((await publicNote(ip)).status).toBe(428);
    expect((await publicNote(ip, first.aid)).status).toBe(201);
    expect((await publicNote(ip, first.aid)).status).toBe(201);
    const over = await publicNote(ip, first.aid);
    expect(over.status).toBe(429);
    // A fresh browser on the same network has its own quota…
    const other = await tracker(ip);
    expect(other.aid).not.toBe(first.aid);
    expect((await publicNote(ip, other.aid)).status).toBe(201);
  });

  it('ignores ids it did not issue, and breaks a tie between unused ids by age', async () => {
    await settings({ 'public.enabled': true, 'public.tracking': 'tracker' });
    const forged = await tracker(freshIp(), { cookie: 'A'.repeat(32), etag: 'B'.repeat(32) });
    expect(forged.body.status).toBe('new');
    expect(forged.aid).not.toBe('A'.repeat(32));
    const older = (await tracker(freshIp())).aid;
    await new Promise((r) => setTimeout(r, 1100)); // ids carry their issue second
    const newer = (await tracker(freshIp())).aid;
    // Two tabs racing on a first visit: one copy each, neither has created anything.
    const r = await tracker(freshIp(), { cookie: newer, etag: older });
    expect(r.body).toMatchObject({ aid: older, status: 'healed' });
  });

  it('blocks when two ids that both created shares tie, and the admin can unblock', async () => {
    await settings({ 'public.enabled': true, 'public.tracking': 'tracker', 'public.newTrackersPerIp': 5 });
    await quotas([{ channel: 'all', kind: 'all', n: 1, unit: 'd', max: 100 }]);
    const a = (await tracker(freshIp())).aid;
    const b = (await tracker(freshIp())).aid;
    expect((await publicNote(freshIp(), a)).status).toBe(201);
    expect((await publicNote(freshIp(), b)).status).toBe(201);
    // One copy each of two used ids: undecidable.
    const r = await tracker(freshIp(), { cookie: a, etag: b });
    expect(r.res.status).toBe(403);
    expect((await r.res.json()).error).toBe('tracker_conflict');
    expect((await publicNote(freshIp(), a)).status).toBe(403); // now blocked
    const admin = await (await fetchJson('/api/private/admin/public?blocked=true', { cookie: oc })).json();
    expect(admin.trackers.rows.length).toBeGreaterThanOrEqual(2);
    for (const t of admin.trackers.rows) {
      expect((await fetchJson(`/api/private/admin/public/trackers/${t.id}`, { method: 'POST', cookie: oc, body: { action: 'unblock' } })).status).toBe(200);
    }
    // A majority decides (2 × a vs 1 × b); duplicate client copies do not add votes.
    const maj = await tracker(freshIp(), { cookie: a, etag: a, copies: `ls=${b}` });
    expect(maj.body).toMatchObject({ aid: a, status: 'healed' });
    const stuffed = await tracker(freshIp(), { cookie: a, copies: `ls=${b};ls=${b};ls=${b};idb=${b}` });
    expect(stuffed.body.aid).toBe(b); // ls + idb (2) beat the cookie (1) — but ls counts once
    const once = await tracker(freshIp(), { cookie: a, etag: a, copies: `ls=${b};ls=${b};ls=${b}` });
    expect(once.body.aid).toBe(a);
  });

  it('limits new senders per network on their first creation, never on page visits', async () => {
    await settings({ 'public.enabled': true, 'public.tracking': 'tracker', 'public.newTrackersPerIp': 2 });
    await quotas([{ channel: 'all', kind: 'all', n: 1, unit: 'd', max: 100 }]);
    const ip = freshIp();
    const ids = [];
    for (let i = 0; i < 6; i++) {
      const t = await tracker(ip);
      expect(t.res.status).toBe(200); // visiting costs nothing
      ids.push(t.aid);
    }
    expect((await publicNote(ip, ids[0])).status).toBe(201);
    expect((await publicNote(ip, ids[1])).status).toBe(201);
    const third = await publicNote(ip, ids[2]);
    expect(third.status).toBe(429);
    expect((await third.json()).error).toBe('tracker_rate_limited');
    expect((await publicNote(ip, ids[0])).status).toBe(201); // known senders carry on
    // Shares are counted per id, successes only; labels are never kept.
    const admin = await (await fetchJson('/api/private/admin/public', { cookie: oc })).json();
    const uses = admin.trackers.rows.map((r) => r.uses).sort((x, y) => y - x);
    expect(uses[0]).toBeGreaterThanOrEqual(2);
    const list = await (await fetchJson(`/api/private/admin/shares?users=${PUBLIC_ID}`, { cookie: oc })).json();
    expect(list.rows.every((r) => !r.label)).toBe(true);
    await settings({ 'public.newTrackersPerIp': 5 });
  });

  it('ip mode needs no browser storage; both modes count tracker and network', async () => {
    await quotas([{ channel: 'all', kind: 'all', n: 1, unit: 'd', max: 1 }]);
    await settings({ 'public.enabled': true, 'public.tracking': 'ip' });
    const ip = freshIp();
    const t = await tracker(ip);
    expect(t.body).toEqual({ mode: 'ip', aid: null });
    expect(t.res.headers.get('set-cookie')).toBeNull();
    expect((await publicNote(ip)).status).toBe(201);
    expect((await publicNote(ip)).status).toBe(429);
    expect((await publicNote(freshIp())).status).toBe(201);

    // both-restrictive: over on either → refused.
    await settings({ 'public.tracking': 'both-restrictive' });
    const ip2 = freshIp();
    const a1 = (await tracker(ip2)).aid;
    expect((await publicNote(ip2, a1)).status).toBe(201);
    const a2 = (await tracker(ip2)).aid; // new browser, same network (already over)
    expect((await publicNote(ip2, a2)).status).toBe(429);
    // both-permissive: refused only when both are over.
    await settings({ 'public.tracking': 'both-permissive' });
    expect((await publicNote(ip2, a2)).status).toBe(201); // a2 fresh, network over
    expect((await publicNote(ip2, a2)).status).toBe(429); // now both over
    await settings({ 'public.tracking': 'tracker' });
  });

  it('respects the public limits (files off by default) and records shares under the public account', async () => {
    await settings({ 'public.enabled': true, 'public.tracking': 'ip' });
    await quotas([{ channel: 'all', kind: 'all', n: 1, unit: 'd', max: 100 }]);
    const ip = freshIp();
    const f = await fetchJson('/api/public/file', { method: 'POST', ip, body: { views: 1, expire: '1h', padded: 65536 } });
    expect((await f.json()).error).toBe('files_disabled');
    expect((await publicNote(ip, null, { bar: false, views: undefined })).status).toBe(403); // unlimited views off
    const ok = await publicNote(ip);
    const { id } = await ok.json();
    const list = await (await fetchJson(`/api/private/admin/shares?users=${PUBLIC_ID}`, { cookie: oc })).json();
    expect(list.rows.map((r) => r.id)).toContain(id);
    expect(list.rows[0].username).toBe('(public)');
  });

  it('the public account cannot sign in, be deleted, renamed, impersonated, exported, or hold keys', async () => {
    expect((await fetchJson('/api/auth/login', { method: 'POST', body: { username: '(public)', proof: proofFor('') || proofFor('x') } })).status).toBe(401);
    expect((await fetchJson(`/api/private/admin/users/${PUBLIC_ID}`, { method: 'DELETE', cookie: oc, headers: intent })).status).toBe(403);
    expect((await fetchJson(`/api/private/admin/users/${PUBLIC_ID}`, { method: 'PATCH', cookie: oc, body: { disabled: true } })).status).toBe(403);
    expect((await fetchJson(`/api/private/admin/users/${PUBLIC_ID}/password`, { method: 'POST', cookie: oc, body: { salt: 'A'.repeat(22), t: 3, proof: proofFor('abcdefghijkl') } })).status).toBe(403);
    expect((await fetchJson(`/api/private/admin/users/${PUBLIC_ID}/impersonate`, { method: 'POST', cookie: oc, headers: intent })).status).toBe(404);
    const exp = await fetchJson('/api/private/admin/export', { method: 'POST', cookie: oc, body: { current: proofFor('owner-password'), users: [PUBLIC_ID], credentials: true, config: true } });
    expect((await exp.json()).document.users).toEqual([]);
    // Its limits are editable like any account's.
    expect((await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: PUBLIC_ID, channel: 'all', patch: { maxViews: 3 } } })).status).toBe(200);
    expect((await (await fetchJson('/api/public/profile')).json()).limits.maxViews).toBe(3);
  });
});
