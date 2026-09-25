// admin.test.js — owner administration: users, password reset without the
// current password, impersonation (restrictions + dual activity views),
// capability limits, API-channel restriction semantics, quotas with windows,
// settings validation, and the Guard (scopes, blocks, IP rules, lockout,
// DISABLE_BFP kill switches).
import { env } from 'cloudflare:test';
import { describe, it, expect, beforeAll, vi, afterEach } from 'vitest';
import { ORIGIN, owner, login, makeUser, fetchJson, cookieOf, salt16, proofFor, intent, freshIp, createNote, openNote } from './helpers.js';
import worker from '../src/index.js';
import { parseIp, parseCidr, cidrContains, trackingKey, normalizeRule } from '../src/lib/ip.js';
import { invalidateGuardCaches } from '../src/lib/guard.js';

let oc;
beforeAll(async () => { oc = await owner(); });
afterEach(() => { vi.useRealTimers(); invalidateGuardCaches(); });

const limits = (scope, channel, patch) => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope, channel, patch } });
const quotas = (scope, list) => fetchJson('/api/private/admin/quotas', { method: 'PUT', cookie: oc, body: { scope, list } });

describe('users', () => {
  it('only the owner administers; users can be disabled, renamed, reset and deleted', async () => {
    const u = await makeUser('alice');
    expect((await fetchJson('/api/private/admin/users', { cookie: u.cookie })).status).toBe(403);
    const list = await (await fetchJson('/api/private/admin/users', { cookie: oc })).json();
    expect(list.users.map((x) => x.username)).toContain('alice');
    // Reset password without the current one → old sessions die, new password works.
    expect((await fetchJson(`/api/private/admin/users/${u.id}/password`, { method: 'POST', cookie: oc, body: { salt: salt16(), t: 3, proof: proofFor('new-alice-pw') } })).status).toBe(200);
    expect((await fetchJson('/api/private/me', { cookie: u.cookie })).status).toBe(401);
    const c2 = await login('alice', 'new-alice-pw');
    // Disable → sessions die and login is refused.
    await fetchJson(`/api/private/admin/users/${u.id}`, { method: 'PATCH', cookie: oc, body: { disabled: true } });
    expect((await fetchJson('/api/private/me', { cookie: c2 })).status).toBe(401);
    expect((await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'alice', proof: proofFor('new-alice-pw') } })).status).toBe(403);
    // The owner cannot be disabled or deleted.
    const me = await (await fetchJson('/api/private/me', { cookie: oc })).json();
    expect((await fetchJson(`/api/private/admin/users/${me.user.id}`, { method: 'PATCH', cookie: oc, body: { disabled: true } })).status).toBe(403);
    expect((await fetchJson(`/api/private/admin/users/${me.user.id}`, { method: 'DELETE', cookie: oc, headers: intent })).status).toBe(403);
    expect((await fetchJson(`/api/private/admin/users/${u.id}`, { method: 'DELETE', cookie: oc, headers: intent })).status).toBe(200);
  });

  it('rejects bad usernames and duplicate names', async () => {
    expect((await fetchJson('/api/private/admin/users', { method: 'POST', cookie: oc, body: { username: 'x', salt: salt16(), t: 3, proof: proofFor('p') } })).status).toBe(400);
    await makeUser('bob');
    expect((await fetchJson('/api/private/admin/users', { method: 'POST', cookie: oc, body: { username: 'BOB', salt: salt16(), t: 3, proof: proofFor('p') } })).status).toBe(409);
  });
});

describe('impersonation', () => {
  it('acts as the user, blocks admin + key minting, and logs truthfully', async () => {
    const u = await makeUser('carol');
    const imp = await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent });
    expect(imp.status).toBe(200);
    const ic = cookieOf(imp);
    const me = await (await fetchJson('/api/private/me', { cookie: ic })).json();
    expect(me.user.username).toBe('carol');
    expect(me.impersonatedBy).toBe('owner');
    expect((await fetchJson('/api/private/admin/users', { cookie: ic })).status).toBe(403);
    expect((await fetchJson('/api/private/me/keys', { method: 'POST', cookie: ic, body: { name: 'x' } })).status).toBe(403);
    const n = await createNote(ic, { text: 'made while impersonated' }, { label: 'imp' });
    expect(n.res.status).toBe(201);
    // The user's own log shows the action as theirs (no actor field at all)…
    const mine = await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json();
    const row = mine.rows.find((r) => r.action === 'share.created');
    expect(row).toBeTruthy();
    expect(Object.keys(row)).not.toContain('actor');
    // …while the admin audit shows the real actor.
    const audit = await (await fetchJson(`/api/private/admin/audit?user=${u.id}`, { cookie: oc })).json();
    const a = audit.rows.find((r) => r.action === 'share.created');
    expect(a.actor).toBe('owner');
    expect(a.subject).toBe('carol');
    // Return to admin.
    const back = await fetchJson('/api/private/admin/unimpersonate', { method: 'POST', cookie: ic, headers: intent });
    expect(back.status).toBe(200);
    const again = await (await fetchJson('/api/private/me', { cookie: cookieOf(back) })).json();
    expect(again.user.role).toBe('owner');
  });
});

describe('capability limits and quotas', () => {
  it('enforces feature flags, view/expiry caps and unlimited-view permission', async () => {
    const u = await makeUser('dave');
    await limits(u.id, 'all', { text: false });
    expect((await createNote(u.cookie, { text: 'x' })).res.status).toBe(403);
    await limits(u.id, 'all', { text: 'inherit', maxViews: 5, allowUnlimitedViews: false, maxExpireSec: 3600 });
    expect((await createNote(u.cookie, { text: 'x', bar: true, views: 6 })).res.status).toBe(403);
    expect((await createNote(u.cookie, { text: 'x' })).res.status).toBe(403); // unlimited views
    expect((await createNote(u.cookie, { text: 'x', bar: true, views: 5, expire: '2h' })).res.status).toBe(403);
    expect((await createNote(u.cookie, { text: 'x', bar: true, views: 5, expire: '1h' })).res.status).toBe(201);
    const me = await (await fetchJson('/api/private/me', { cookie: u.cookie })).json();
    expect(me.limits).toMatchObject({ text: true, maxViews: 5, allowUnlimitedViews: false, maxExpireSec: 3600 });
  });

  it('rejects invalid limit values', async () => {
    const u = await makeUser('erin');
    for (const patch of [{ maxViews: 0 }, { text: 'yes' }, { nope: 1 }, { apiMaxKeys: null }]) {
      expect((await limits(u.id, 'all', patch)).status).toBe(400);
    }
    expect((await limits(u.id, 'api', { apiEnabled: true })).status).toBe(400); // not an API-channel key
  });

  it('quotas: fixed windows, GUI + API counted together, API can only restrict further', async () => {
    const u = await makeUser('frank');
    await limits(u.id, 'all', { apiEnabled: true });
    const key = (await (await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { name: 'k' } })).json()).key;
    const bearer = { authorization: `Bearer ${key}` };
    // GUI allows 3/day, API allows 5/day → API gets min: still bounded by the 3 total.
    expect((await quotas(u.id, [{ channel: 'all', kind: 'all', n: 1, unit: 'd', max: 3 }, { channel: 'api', kind: 'all', n: 1, unit: 'd', max: 5 }])).status).toBe(200);
    expect((await createNote(u.cookie, { text: '1' })).res.status).toBe(201);
    expect((await createNote(null, { text: '2' }, { headers: bearer })).res.status).toBe(201);
    expect((await createNote(u.cookie, { text: '3' })).res.status).toBe(201);
    const over = await createNote(null, { text: '4' }, { headers: bearer });
    expect(over.res.status).toBe(429);
    expect((await over.res.json()).error).toBe('quota_exceeded');
    // API stricter than GUI: API 1/day, GUI 10/day.
    await quotas(u.id, [{ channel: 'all', kind: 'all', n: 1, unit: 'd', max: 10 }, { channel: 'api', kind: 'text', n: 1, unit: 'd', max: 1 }]);
    expect((await createNote(null, { text: 'a' }, { headers: bearer })).res.status).toBe(201);
    expect((await createNote(null, { text: 'b' }, { headers: bearer })).res.status).toBe(429);
    expect((await createNote(u.cookie, { text: 'c' })).res.status).toBe(201); // GUI still fine
    // A new window resets the counter.
    vi.useFakeTimers({ now: Date.now() + 2 * 86400 * 1000, toFake: ['Date'] });
    expect((await createNote(null, { text: 'd' }, { headers: bearer })).res.status).toBe(201);
  });

  it('global quotas apply per user; rejects malformed quotas', async () => {
    expect((await quotas('global', [{ channel: 'all', kind: 'text', n: 1, unit: 'mo', max: 2 }])).status).toBe(200);
    const u = await makeUser('gina');
    expect((await createNote(u.cookie, { text: '1' })).res.status).toBe(201);
    expect((await createNote(u.cookie, { text: '2' })).res.status).toBe(201);
    expect((await createNote(u.cookie, { text: '3' })).res.status).toBe(429);
    expect((await createNote(oc, { text: 'owner is unlimited' })).res.status).toBe(201);
    expect((await quotas('global', [])).status).toBe(200);
    for (const q of [{ channel: 'x', kind: 'all', n: 1, unit: 'd', max: 1 }, { channel: 'all', kind: 'all', n: 0, unit: 'd', max: 1 }, { channel: 'all', kind: 'all', n: 1, unit: 'w', max: 1 }]) {
      expect((await quotas('global', [q])).status).toBe(400);
    }
  });
});

describe('settings validation', () => {
  it('bounds every value and keeps idle ≤ absolute', async () => {
    const bad = [{ 'session.idleSec': 1 }, { 'files.maxShareBytes': 3 * 1024 ** 3 }, { 'viewer.enabled': 'yes' }, { nope: 1 },
      { 'session.idleSec': 86400 * 30, 'session.absSec': 86400 }];
    for (const b of bad) expect((await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: b })).status).toBe(400);
    const ok = await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'files.maxShareBytes': 2 * 1024 ** 3 } });
    expect(ok.status).toBe(200);
    const ov = await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json();
    expect(ov.settings['files.maxShareBytes']).toBe(2 * 1024 ** 3);
    expect(ov.env).toMatchObject({ sessionKeys: true, bfpDisabled: false });
  });
});

describe('guard: brute-force protection', () => {
  const setRule = (scope, max, windowSec, blockSec) => fetchJson('/api/private/admin/settings', {
    method: 'PATCH', cookie: oc, body: { [`guard.${scope}.max`]: max, [`guard.${scope}.windowSec`]: windowSec, [`guard.${scope}.blockSec`]: blockSec },
  });

  it('blocks an IP after X invalid fetches (wrong links included), visible + unblockable by the admin', async () => {
    await setRule('invalid', 3, 600, 600);
    invalidateGuardCaches();
    const n = await createNote(oc, { text: 'x', bar: true, password: 'pw-123456789' });
    const ip = freshIp();
    for (let i = 0; i < 2; i++) expect((await openNote(n.id, n.fragment, 'wrong-guess', { ip })).res.status).toBe(403);
    expect((await openNote(n.id, n.fragment, 'wrong-guess', { ip })).res.status).toBe(429);
    // Even the right password is refused while blocked — and the view is intact.
    expect((await fetchJson(`/api/paste/${n.id}`, { ip })).status).toBe(429);
    const g = await (await fetchJson('/api/private/admin/guard', { cookie: oc })).json();
    const b = g.blocks.find((x) => x.key === `${ip}/32` && x.scope === 'invalid');
    expect(b).toBeTruthy();
    expect((await fetchJson('/api/private/admin/guard/unblock', { method: 'POST', cookie: oc, body: { scope: 'invalid', key: b.key } })).status).toBe(200);
    expect((await openNote(n.id, n.fragment, 'pw-123456789', { ip })).res.status).toBe(200);
    await setRule('invalid', 60, 600, 1800);
  });

  it('login scope + account lockout (owner excluded)', async () => {
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'lockout.max': 2, 'lockout.windowSec': 600, 'lockout.lockSec': 600 } });
    invalidateGuardCaches();
    await makeUser('henry', 'henry-password-1');
    for (let i = 0; i < 2; i++) await fetchJson('/api/auth/login', { method: 'POST', ip: freshIp(), body: { username: 'henry', proof: proofFor('bad') } });
    const locked = await fetchJson('/api/auth/login', { method: 'POST', ip: freshIp(), body: { username: 'henry', proof: proofFor('henry-password-1') } });
    expect(locked.status).toBe(423);
    const users = (await (await fetchJson('/api/private/admin/users', { cookie: oc })).json()).users;
    const h = users.find((x) => x.username === 'henry');
    expect(h.locked).toBe(true);
    await fetchJson(`/api/private/admin/users/${h.id}/unlock`, { method: 'POST', cookie: oc, headers: intent });
    expect((await fetchJson('/api/auth/login', { method: 'POST', ip: freshIp(), body: { username: 'henry', proof: proofFor('henry-password-1') } })).status).toBe(200);
    // The owner is never locked out.
    for (let i = 0; i < 3; i++) await fetchJson('/api/auth/login', { method: 'POST', ip: freshIp(), body: { username: 'owner', proof: proofFor('bad') } });
    expect((await fetchJson('/api/auth/login', { method: 'POST', ip: freshIp(), body: { username: 'owner', proof: proofFor('owner-password') } })).status).toBe(200);
  });

  it('manual IP rules: block CIDRs (v4 + v6), allow beats block, DISABLE_BFP bypasses', async () => {
    const add = (cidr, action) => fetchJson('/api/private/admin/ip-rules', { method: 'POST', cookie: oc, body: { cidr, action, note: 'test' } });
    expect((await add('203.0.113.0/24', 'block')).status).toBe(201);
    expect((await add('2001:db8::/32', 'block')).status).toBe(201);
    expect((await add('not-an-ip', 'block')).status).toBe(400);
    invalidateGuardCaches();
    expect((await fetchJson('/api/config', { ip: '203.0.113.9' })).status).toBe(403);
    expect((await fetchJson('/api/config', { ip: '2001:db8:1:2::5' })).status).toBe(403);
    expect((await fetchJson('/api/config', { ip: '203.0.114.1' })).status).toBe(200);
    const allow = await (await add('203.0.113.9', 'allow')).json();
    invalidateGuardCaches();
    expect((await fetchJson('/api/config', { ip: '203.0.113.9' })).status).toBe(200);
    expect((await fetchJson('/api/config', { ip: '203.0.113.10' })).status).toBe(403);
    const bypass = await worker.fetch(new Request(`${ORIGIN}/api/config`, { headers: { 'cf-connecting-ip': '203.0.113.10' } }), { ...env, DISABLE_BFP: 'TRUE' }, { waitUntil() {} });
    expect(bypass.status).toBe(200);
    const rules = (await (await fetchJson('/api/private/admin/ip-rules', { cookie: oc })).json()).rules;
    for (const r of rules) await fetchJson(`/api/private/admin/ip-rules/${r.id}`, { method: 'DELETE', cookie: oc, headers: intent });
    void allow;
  });

  it('DISABLE_BFP_SETUP only lifts protection for setup', async () => {
    await setRule('setup', 1, 600, 600);
    invalidateGuardCaches();
    const ip = freshIp();
    const call = (e) => worker.fetch(new Request(`${ORIGIN}/api/auth/setup`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': ip },
      body: JSON.stringify({ token: 'wrong-wrong-wrong-wrong-wrong-wrong-wrong', username: 'x', salt: salt16(), t: 3, proof: proofFor('x') }),
    }), { ...env, AUTHN: 'another-valid-setup-token-0123456789', ...e }, { waitUntil() {} });
    expect((await call({})).status).toBe(429); // first failure hits max=1 → blocked
    expect((await call({})).status).toBe(429);
    expect((await call({ DISABLE_BFP_SETUP: 'true' })).status).toBe(403); // guard off: plain wrong-token
    await setRule('setup', 5, 3600, 3600);
  });
});

describe('ip.js', () => {
  it('parses, normalizes and matches v4/v6 CIDRs and aggregates v6 to /64', () => {
    expect(parseIp('1.2.3.4')).toEqual({ v: 4, n: 0x01020304n });
    expect(parseIp('::ffff:1.2.3.4')).toEqual({ v: 4, n: 0x01020304n });
    expect(parseIp('999.1.1.1')).toBeNull();
    expect(parseIp('1::2::3')).toBeNull();
    expect(normalizeRule('10.1.2.3/8')).toBe('10.0.0.0/8');
    expect(normalizeRule('2001:DB8::1/32')).toBe('2001:db8:0:0:0:0:0:0/32');
    expect(cidrContains(parseCidr('10.0.0.0/8'), parseIp('10.200.1.1'))).toBe(true);
    expect(cidrContains(parseCidr('10.0.0.0/8'), parseIp('11.0.0.1'))).toBe(false);
    expect(cidrContains(parseCidr('::/0'), parseIp('2001::1'))).toBe(true);
    expect(trackingKey('2001:db8:1:2:3:4:5:6')).toBe('2001:db8:1:2:0:0:0:0/64');
    expect(trackingKey('198.51.100.7')).toBe('198.51.100.7/32');
    expect(trackingKey('garbage')).toBe('invalid');
  });
});
