// admin-ux.test.js — owner and admin behaviour: global settings never apply
// to the owner; the admin UI cannot reset the owner's own password (Account
// does, with the current password); "no limit" API keys; defaults exposed to
// the admin; IP rules as ranges; fetches of shares that ended are not counted
// as invalid.
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, freshIp, createNote, openNote, salt16, proofFor, intent } from './helpers.js';
import { invalidateGuardCaches } from '../src/lib/guard.js';
import { genId } from '../src/lib/ids.js';
import { normalizeRule, parseRule, ruleContains, parseIp } from '../src/lib/ip.js';
import { HARD_MAX_SHARE_BYTES } from '../public/js/files.js';

const MiB = 1024 * 1024;
let oc;
beforeAll(async () => { oc = await owner(); });

const settings = (patch) => fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: patch });
const me = async (cookie) => (await fetchJson('/api/private/me', { cookie })).json();

describe('global settings never apply to the owner', () => {
  it('share-size cap and viewer switch restrict users, not the owner', async () => {
    const u = await makeUser('ux-cap');
    expect((await settings({ 'files.maxShareBytes': MiB, 'viewer.enabled': false })).status).toBe(200);
    const mine = await me(oc);
    expect(mine.caps.maxShareBytes).toBe(HARD_MAX_SHARE_BYTES);
    expect(mine.viewer.enabled).toBe(true);
    const theirs = await me(u.cookie);
    expect(theirs.caps.maxShareBytes).toBe(MiB);
    expect(theirs.viewer.enabled).toBe(false);
    // The server enforces it too: the owner may start a share above the global cap.
    const init = (cookie) => fetchJson('/api/private/file', { method: 'POST', cookie, body: { views: 1, expire: '1h', padded: 4 * MiB, files: 1, maxFile: 4 * MiB } });
    expect((await init(oc)).status).toBe(201);
    expect((await init(u.cookie)).status).toBe(413);
    await settings({ 'files.maxShareBytes': 100 * MiB });
  });
});

describe('owner password', () => {
  it('cannot be reset from the admin API (only from Account, with the current password)', async () => {
    const { users } = await (await fetchJson('/api/private/admin/users', { cookie: oc })).json();
    const o = users.find((x) => x.role === 'owner');
    const r = await fetchJson(`/api/private/admin/users/${o.id}/password`, { method: 'POST', cookie: oc, body: { salt: salt16(), t: 3, proof: proofFor('another-password-1') } });
    expect(r.status).toBe(403);
    expect((await r.json()).error).toBe('use_account_page');
  });
});

describe('API keys: "no limit"', () => {
  it('accepts null for apiMaxKeys and lets the user go past the old default of 5', async () => {
    const u = await makeUser('ux-keys');
    const limits = (patch) => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch } });
    expect((await limits({ apiEnabled: true, apiMaxKeys: null })).status).toBe(200);
    for (let i = 0; i < 6; i++) {
      expect((await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { name: `k${i}` } })).status).toBe(201);
    }
    expect((await me(u.cookie)).apiKeys.max).toBe(1000);
  });
});

describe('defaults are visible to the admin', () => {
  it('overview carries built-in defaults and what users inherit', async () => {
    const o = await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json();
    expect(o.defaults.limits.apiMaxKeys).toBe(5);
    expect(o.defaults.settings['guard.invalid.max']).toBe(60);
    expect(o.defaults.inherited).toHaveProperty('maxViews');
  });
});

describe('IP rules: ranges as well as CIDR', () => {
  it('parses, normalizes and matches ranges', () => {
    expect(normalizeRule('10.0.0.5-10.0.0.20')).toBe('10.0.0.5-10.0.0.20');
    expect(normalizeRule(' 10.0.0.0 - 10.0.0.255 ')).toBe('10.0.0.0/24'); // an aligned block collapses to CIDR
    expect(normalizeRule('2001:db8::-2001:db8::ffff')).toBe('2001:db8:0:0:0:0:0:0/112');
    expect(normalizeRule('10.0.0.9-10.0.0.1')).toBeNull(); // reversed
    expect(normalizeRule('10.0.0.1-::1')).toBeNull(); // mixed families
    const r = parseRule('10.0.0.5-10.0.0.20');
    expect(ruleContains(r, parseIp('10.0.0.5'))).toBe(true);
    expect(ruleContains(r, parseIp('10.0.0.20'))).toBe(true);
    expect(ruleContains(r, parseIp('10.0.0.21'))).toBe(false);
  });

  it('a block range denies addresses inside it only', async () => {
    const add = await fetchJson('/api/private/admin/ip-rules', { method: 'POST', cookie: oc, body: { cidr: '192.0.2.10-192.0.2.19', action: 'block', note: 'range' } });
    expect(add.status).toBe(201);
    const { id, cidr } = await add.json();
    expect(cidr).toBe('192.0.2.10-192.0.2.19');
    invalidateGuardCaches();
    expect((await fetchJson('/api/config', { ip: '192.0.2.15' })).status).toBe(403);
    expect((await fetchJson('/api/config', { ip: '192.0.2.20' })).status).toBe(200);
    await fetchJson(`/api/private/admin/ip-rules/${id}`, { method: 'DELETE', cookie: oc, headers: intent });
    invalidateGuardCaches();
  });
});

describe('invalid fetches exclude shares that ended', () => {
  it('re-fetching a used-up share is not counted; unknown ids are', async () => {
    expect((await settings({ 'guard.invalid.max': 3 })).status).toBe(200);
    invalidateGuardCaches();
    const u = await makeUser('ux-invalid');
    const note = await createNote(u.cookie, { views: 1, bar: true });
    expect(note.res.status).toBe(201);
    expect((await openNote(note.id, note.fragment, '', { ip: freshIp() })).res.status).toBe(200); // last view: gone now
    const late = freshIp();
    for (let i = 0; i < 6; i++) {
      expect((await fetchJson(`/api/paste/${note.id}`, { ip: late })).status).toBe(410); // never 429
    }
    const prober = freshIp();
    const codes = [];
    for (let i = 0; i < 5; i++) codes.push((await fetchJson(`/api/paste/${genId('b')}`, { ip: prober })).status);
    expect(codes).toContain(429);
    await settings({ 'guard.invalid.max': 60 });
    invalidateGuardCaches();
  });
});
