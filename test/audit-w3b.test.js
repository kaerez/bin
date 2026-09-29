// audit-w3b.test.js — the fixes of security audit W3, part B:
//   B-1  wrong share passwords are counted per share, from any network: at
//        share.pwMaxFails (default 20, an owner setting) within the window the
//        share's password is locked (every kind: KV notes, burn notes, file
//        shares; open and "delete now"), even for the right password, for a
//        period that doubles on each new lock; the lock is in the share user's
//        log; invalid requests are also counted per IPv6 /48;
//   B-2  "delete now" on an id that was never a share is a counted "gone";
//   B-3  a chunk request without a valid download grant gets the same counted
//        403 whatever its index;
//   B-5  GET /api/public/t has a per-network limit.
// The invalid-fetch rule stays: the right key for an ended share, and the
// right password, are never counted as invalid.
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { env, SELF, runInDurableObject } from 'cloudflare:test';
import { owner, makeUser, fetchJson, createNote, openNote, proofHeaders, freshIp, ORIGIN, intent, csrfHeaders } from './helpers.js';
import { encryptPaste } from '../public/js/crypto.js';
import { layout, buildManifest, importFileKey, encryptChunk, readStreamChunk } from '../public/js/files.js';
import { utf8, randomBytes, b64urlFromBytes } from '../public/js/bytes.js';
import { invalidateGuardCaches, guardShardFor, guardKeyFor, PASSWORD_LOCKED, TRACKER_FETCH, WIDE_INVALID_FACTOR } from '../src/lib/guard.js';
import { sharePwRule, lockSeconds, pwFailed, pwLockedUntil, PW_LOCK_MAX_FACTOR } from '../src/lib/sharepw.js';
import { SETTINGS, weakenedSettings, settingsWithDefaults } from '../src/lib/settings.js';

let oc;
beforeAll(async () => { oc = await owner(); });
afterEach(() => vi.useRealTimers());

const nowSec = () => Math.floor(Date.now() / 1000);
const settings = async (patch, opts = {}) => {
  const r = await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: patch, ...opts });
  invalidateGuardCaches();
  return r;
};
const activity = async (cookie) => (await (await fetchJson('/api/private/me/activity', { cookie })).json()).rows;
const randomProofs = () => ({ 'x-link-proof': b64urlFromBytes(randomBytes(32)), 'x-key-proof': b64urlFromBytes(randomBytes(32)) });
const madeUp = (cls) => `${cls}${b64urlFromBytes(randomBytes(16))}`;
/** Move the clock (Date only) to `sec` seconds after `t0` (ms). */
const at = (t0, sec) => vi.useFakeTimers({ now: t0 + sec * 1000, toFake: ['Date'] });

/** Upload a one-file share as `cookie` (a password, views, "delete now" as asked). */
async function upload(cookie, { password = '', views = null, deletable = false, bytes = utf8('file body') } = {}) {
  const files = [{ path: 'f.txt', bytes, type: 'text/plain' }];
  const l = layout(files.map((f) => ({ path: f.path, type: f.type, size: f.bytes.length, mtime: 0 })), []);
  const manifest = buildManifest({ entries: l.entries, total: l.total });
  const init = await fetchJson('/api/private/file', { method: 'POST', cookie, body: { views, expire: '1d', padded: l.padded, files: 1, maxFile: bytes.length, ...(deletable ? { deletable: true } : {}) } });
  expect(init.status).toBe(201);
  const { id, uploadtoken, chunks } = await init.json();
  const key = await importFileKey(manifest.fk);
  const sources = files.map((f, i) => ({ off: l.entries[i].off, size: f.bytes.length, read: async (a, b) => f.bytes.slice(a, b) }));
  for (let i = 0; i < chunks; i++) {
    const ct = await encryptChunk(key, i, chunks, await readStreamChunk(sources, i, l.total));
    const r = await SELF.fetch(`${ORIGIN}/api/private/file/${id}/chunk/${i}`, { method: 'PUT', headers: { cookie, ...(await csrfHeaders(cookie)), 'content-type': 'application/octet-stream', 'x-upload-token': uploadtoken }, body: ct });
    expect(r.status).toBe(200);
  }
  const { body, fragment } = await encryptPaste({ text: JSON.stringify(manifest), fmt: 'files', bar: views !== null, views: views ?? undefined, expire: '1d', password, deletable });
  const fin = await fetchJson(`/api/private/file/${id}/finalize`, { method: 'POST', cookie, headers: { 'x-upload-token': uploadtoken }, body: { paste: body } });
  expect(fin.status).toBe(200);
  return { id, fragment, chunks };
}

async function openFile(id, fragment, password, ip) {
  const head = await (await fetchJson(`/api/file/${id}`, { ip })).json();
  const { headers } = await proofHeaders(head.adata, fragment, password);
  return fetchJson(`/api/file/${id}/open`, { method: 'POST', headers, ip });
}
async function expireNow(kind, id, fragment, password, ip) {
  const head = await (await fetchJson(`/api/${kind}/${id}`, { ip })).json();
  const { headers } = await proofHeaders(head.adata, fragment, password);
  return fetchJson(`/api/${kind}/${id}/expire`, { method: 'POST', headers, ip });
}
const getChunk = (id, path, grant, ip) => SELF.fetch(`${ORIGIN}/api/file/${id}/chunk/${path}`, { headers: { 'x-download-grant': grant, ...(ip ? { 'cf-connecting-ip': ip } : {}) } });

/** Seed the Guard's counter of `scope` for tracking key `key` to `count` (instead of making those requests one by one). */
async function seedCounter(scope, key, count) {
  const tag = await guardKeyFor(env, key);
  await runInDurableObject(guardShardFor(env, tag), (_inst, state) => {
    const sql = state.storage.sql;
    const row = sql.exec('SELECT count FROM tracking WHERE scope = ? AND key = ?', scope, tag).toArray()[0];
    expect(row?.count).toBe(1);
    sql.exec('UPDATE tracking SET count = ? WHERE scope = ? AND key = ?', count, scope, tag);
  });
}

describe('B-1: the per-share password lockout (src/lib/sharepw.js)', () => {
  it('the rule: the N-th failure in the window locks; each new lock lasts twice as long, at most 64 times the first', () => {
    const rule = sharePwRule(settingsWithDefaults({}));
    expect(rule).toEqual({ max: 20, windowSec: 900, lockSec: 900 });
    let st = null;
    for (let i = 1; i < rule.max; i++) {
      const f = pwFailed(st, rule, 1000 + i);
      expect(f.locked).toBeNull();
      st = f.next;
    }
    const f = pwFailed(st, rule, 1100);
    expect(f.locked).toEqual({ until: 1100 + 900, strike: 1 });
    expect(pwLockedUntil(f.next, 1100 + 899)).toBe(2000);
    expect(pwLockedUntil(f.next, 2000)).toBeNull();
    // Failures older than the window start the count again.
    const stale = pwFailed({ n: rule.max - 1, since: 0, until: null, strikes: 0 }, rule, rule.windowSec + 1);
    expect([stale.next.n, stale.locked]).toEqual([1, null]);
    expect([1, 2, 3, 7, 8, 20].map((s) => lockSeconds(rule, s))).toEqual([900, 1800, 3600, 57600, 57600, 57600]);
    expect(lockSeconds(rule, 99)).toBe(900 * PW_LOCK_MAX_FACTOR);
    expect(lockSeconds({ ...rule, lockSec: 30 * 86400 }, 5)).toBe(30 * 86400);
  });

  it('wrong passwords spread over many IPv6 /64s lock a note for every network, the right password too; the lock is in its user\'s log', async () => {
    const u = await makeUser('w3b-kv-lock');
    const n = await createNote(u.cookie, { text: 'guarded note', password: 'the-right-one' });
    expect(n.res.status).toBe(201);
    const { max } = sharePwRule(settingsWithDefaults({}));
    let until = null;
    // One guess per /64 (each far below the per-network limit), all inside one /48.
    for (let i = 0; i < max; i++) {
      const { res } = await openNote(n.id, n.fragment, `guess-${i}`, { ip: `2001:db8:b1:${(i + 1).toString(16)}::1` });
      const body = await res.json();
      expect([res.status, body.error]).toEqual([403, 'bad_password']);
      if (i < max - 1) expect(body.until).toBeUndefined();
      else until = body.until;
    }
    expect(until).toBeGreaterThanOrEqual(nowSec() + 900 - 5);
    expect(until).toBeLessThanOrEqual(nowSec() + 900);
    // Locked, from any network (IPv4 and another /48): even the right password, and nothing is released.
    for (const ip of [freshIp(), '2001:db8:b2:1::1']) {
      const { res } = await openNote(n.id, n.fragment, 'the-right-one', { ip });
      const body = await res.json();
      expect([res.status, body.error, body.until]).toEqual([429, 'password_locked', until]);
      expect(body.message).toMatch(/^Too many wrong passwords for this share\. Try again at \d{4}-\d\d-\d\d \d\d:\d\d UTC\.$/);
      expect(body.ct).toBeUndefined();
      expect(Number(res.headers.get('retry-after'))).toBeGreaterThan(0);
    }
    const locks = (await activity(u.cookie)).filter((a) => a.action === 'share.password_locked');
    expect(locks.map((a) => a.detail)).toEqual([`id=${n.id} until=${until} lock=1`]);
  }, 60000);

  it('the lock ends on time, a new one lasts twice as long, and the right password (accepted) clears the count', async () => {
    expect((await settings({ 'share.pwMaxFails': 3 })).status).toBe(200);
    try {
      const n = await createNote(oc, { text: 'expiring lock', password: 'pw-ok' });
      const t0 = Date.now();
      const lockOnce = async (sec) => {
        at(t0, sec);
        let last;
        for (let i = 0; i < 3; i++) last = await (await openNote(n.id, n.fragment, `bad-${i}`, { ip: freshIp() })).res.json();
        expect(last.error).toBe('bad_password');
        return last.until - Math.floor((t0 + sec * 1000) / 1000);
      };
      expect(await lockOnce(0)).toBe(900);
      at(t0, 899);
      expect((await openNote(n.id, n.fragment, 'pw-ok', { ip: freshIp() })).res.status).toBe(429);
      // Past the end: another three wrong ones lock it again, for twice as long.
      expect(await lockOnce(901)).toBe(1800);
      at(t0, 901 + 1799);
      expect((await openNote(n.id, n.fragment, 'pw-ok', { ip: freshIp() })).res.status).toBe(429);
      expect(await lockOnce(901 + 1801)).toBe(3600);
      // After that one: the right password opens, and the next lock starts from the first length again.
      at(t0, 901 + 1801 + 3601);
      const ok = await openNote(n.id, n.fragment, 'pw-ok', { ip: freshIp() });
      expect(ok.res.status).toBe(200);
      expect(await lockOnce(901 + 1801 + 3602)).toBe(900);
      // Newest first: the fourth lock (the first length again), the third, the second, the first.
      const rows = (await activity(oc)).filter((a) => a.action === 'share.password_locked' && a.detail.startsWith(`id=${n.id} `));
      expect(rows.map((a) => a.detail.replace(/ until=\d+/, ''))).toEqual([4, 3, 2, 1].map((k) => `id=${n.id} lock=${k === 4 ? 1 : k}`));
    } finally {
      vi.useRealTimers();
      await settings({ 'share.pwMaxFails': 20 });
    }
  }, 60000);

  it('burn notes and file shares lock too (open and "delete now"), and no view is spent', async () => {
    expect((await settings({ 'share.pwMaxFails': 3 })).status).toBe(200);
    try {
      const b = await createNote(oc, { text: 'burn guarded', password: 'burn-pw', bar: true, views: 2, deletable: true });
      expect(b.res.status).toBe(201);
      await openNote(b.id, b.fragment, 'no-1', { ip: freshIp() });
      await expireNow('paste', b.id, b.fragment, 'no-2', freshIp());
      const third = await (await openNote(b.id, b.fragment, 'no-3', { ip: freshIp() })).res.json();
      expect([third.error, Number.isSafeInteger(third.until)]).toEqual(['bad_password', true]);
      const locked = await openNote(b.id, b.fragment, 'burn-pw', { ip: freshIp() });
      expect([locked.res.status, (await locked.res.json()).error]).toEqual([429, 'password_locked']);
      expect((await (await fetchJson(`/api/paste/${b.id}`)).json()).meta.left).toBe(2); // nothing spent
      expect((await expireNow('paste', b.id, b.fragment, 'burn-pw', freshIp())).status).toBe(429);

      const f = await upload(oc, { password: 'file-pw', views: 3, deletable: true });
      for (let i = 0; i < 2; i++) expect((await openFile(f.id, f.fragment, `nope-${i}`, freshIp())).status).toBe(403);
      const last = await (await expireNow('file', f.id, f.fragment, 'nope-x', freshIp())).json();
      expect([last.error, Number.isSafeInteger(last.until)]).toEqual(['bad_password', true]);
      const lockedFile = await openFile(f.id, f.fragment, 'file-pw', freshIp());
      expect([lockedFile.status, (await lockedFile.json()).error]).toEqual([429, 'password_locked']);
      expect((await (await fetchJson(`/api/file/${f.id}`)).json()).meta.left).toBe(3);
      // Once it ends, the right password opens (one view).
      at(Date.now(), 901);
      const open = await openFile(f.id, f.fragment, 'file-pw', freshIp());
      expect(open.status).toBe(200);
      expect((await open.json()).paste.meta.left).toBe(2);
      const logged = (await activity(oc)).filter((a) => a.action === 'share.password_locked').map((a) => a.detail.split(' ')[0]);
      expect(logged).toEqual(expect.arrayContaining([`id=${b.id}`, `id=${f.id}`]));
    } finally {
      vi.useRealTimers();
      await settings({ 'share.pwMaxFails': 20 });
    }
  }, 60000);

  it('the right password never counts; attempts on a locked share are not invalid fetches but have their own limit', async () => {
    expect((await settings({ 'share.pwMaxFails': 3 })).status).toBe(200);
    try {
      const n = await createNote(oc, { text: 'often opened', password: 'right' });
      const ip = freshIp();
      // Far more right-password opens than any threshold: none is counted.
      for (let i = 0; i < 25; i++) expect((await openNote(n.id, n.fragment, 'right', { ip })).res.status).toBe(200);
      // A share without a password has nothing to guess: wrong key proofs are never counted per share.
      const plain = await createNote(oc, { text: 'no password' });
      const head = await (await fetchJson(`/api/paste/${plain.id}`)).json();
      const { headers } = await proofHeaders(head.adata, plain.fragment, '');
      for (let i = 0; i < 5; i++) {
        const r = await fetchJson(`/api/paste/${plain.id}/open`, { method: 'POST', ip: freshIp(), headers: { ...headers, 'x-key-proof': b64urlFromBytes(randomBytes(32)) } });
        expect((await r.json()).error).toBe('bad_password');
      }
      expect((await openNote(plain.id, plain.fragment, '', { ip: freshIp() })).res.status).toBe(200);
      // Lock the password note from elsewhere.
      for (let i = 0; i < 3; i++) await openNote(n.id, n.fragment, `x${i}`, { ip: freshIp() });
      // One network keeps trying, right and wrong: always password_locked, never the invalid block.
      const probe = freshIp();
      for (let i = 0; i < 70; i++) {
        const { res } = await openNote(n.id, n.fragment, i % 2 ? 'right' : `wrong-${i}`, { ip: probe });
        expect([res.status, (await res.json()).error]).toEqual([429, 'password_locked']);
      }
      expect((await fetchJson(`/api/paste/${madeUp('k')}`, { ip: probe })).status).toBe(404); // not blocked
      // Their own limit (PASSWORD_LOCKED): seeded to one short of it, then 429 rate_limited.
      const other = freshIp();
      expect((await openNote(n.id, n.fragment, 'right', { ip: other })).res.status).toBe(429);
      await seedCounter('password-locked', `${other}/32`, PASSWORD_LOCKED.max - 2);
      expect((await (await openNote(n.id, n.fragment, 'right', { ip: other })).res.json()).error).toBe('password_locked');
      const over = (await openNote(n.id, n.fragment, 'right', { ip: other })).res;
      expect([over.status, (await over.json()).error, over.headers.get('retry-after')]).toEqual([429, 'rate_limited', String(PASSWORD_LOCKED.blockSec)]);
    } finally {
      await settings({ 'share.pwMaxFails': 20 });
    }
  }, 120000);

  it('share.pwMaxFails, pwWindowSec and pwLockSec are owner settings: bounded, and loosening them needs the step-up', async () => {
    const ov = await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json();
    expect(ov.defaults.settings).toMatchObject({ 'share.pwMaxFails': 20, 'share.pwWindowSec': 900, 'share.pwLockSec': 900 });
    for (const bad of [{ 'share.pwMaxFails': 0 }, { 'share.pwWindowSec': 10 }, { 'share.pwLockSec': 31 * 86400 }]) {
      expect((await settings(bad)).status).toBe(400);
    }
    expect(SETTINGS['share.pwMaxFails']).toMatchObject({ min: 1, def: 20 });
    const base = settingsWithDefaults({});
    expect(weakenedSettings(base, { ...base, 'share.pwMaxFails': 21, 'share.pwWindowSec': 60, 'share.pwLockSec': 60 }))
      .toEqual(['share.pwMaxFails', 'share.pwWindowSec', 'share.pwLockSec']);
    expect(weakenedSettings(base, { ...base, 'share.pwMaxFails': 5, 'share.pwLockSec': 3600 })).toEqual([]);
    const loose = await settings({ 'share.pwMaxFails': 50 }, { step: false });
    expect([loose.status, (await loose.json()).weakens]).toEqual([400, ['share.pwMaxFails']]);
    expect((await settings({ 'share.pwMaxFails': 5 }, { step: false })).status).toBe(200); // tightening needs nothing
    expect((await settings({ 'share.pwMaxFails': 20 })).status).toBe(200);
  });

  it('invalid requests are also counted per IPv6 /48: spreading them over /64s ends in a block of the /48', async () => {
    expect((await settings({ 'guard.invalid.max': 2, 'guard.invalid.windowSec': 600, 'guard.invalid.blockSec': 600 })).status).toBe(200);
    try {
      const wide = 2 * WIDE_INVALID_FACTOR;
      let last;
      // One made-up id from each /64: every /64 stays below its own limit (2).
      for (let i = 0; i < wide; i++) {
        last = await fetchJson(`/api/paste/${madeUp('k')}`, { ip: `2001:db8:c1:${(i + 1).toString(16)}::5` });
        if (i < wide - 1) expect(last.status).toBe(404);
      }
      expect([last.status, (await last.json()).error]).toEqual([429, 'blocked']);
      // The whole /48 is blocked now, a /64 that never sent anything included; another /48 is not.
      expect((await fetchJson(`/api/paste/${madeUp('k')}`, { ip: '2001:db8:c1:ffff::9' })).status).toBe(429);
      expect((await fetchJson(`/api/paste/${madeUp('k')}`, { ip: '2001:db8:c2:1::9' })).status).toBe(404);
      // The owner sees it (scope invalid-wide) and lifts it like the others.
      const g = await (await fetchJson('/api/private/admin/guard', { cookie: oc })).json();
      const b = g.blocks.find((x) => x.scope === 'invalid-wide' && x.addr === '2001:db8:c1:0:0:0:0:0/48');
      expect(b).toBeTruthy();
      expect((await fetchJson('/api/private/admin/guard/unblock', { method: 'POST', cookie: oc, body: { scope: 'invalid-wide', key: b.key } })).status).toBe(200);
      expect((await fetchJson(`/api/paste/${madeUp('k')}`, { ip: '2001:db8:c1:ffff::9' })).status).toBe(404);
      // IPv4 has no wider count: its /32 is the network.
      const v4 = freshIp();
      expect((await fetchJson(`/api/paste/${madeUp('k')}`, { ip: v4 })).status).toBe(404);
      expect((await fetchJson(`/api/paste/${madeUp('k')}`, { ip: v4 })).status).toBe(429);
    } finally {
      await settings({ 'guard.invalid.max': 60, 'guard.invalid.windowSec': 600, 'guard.invalid.blockSec': 1800 });
    }
  }, 60000);
});

describe('B-2: "delete now" on a made-up id', () => {
  it('is a counted "gone" like on the other routes; an id that was a share is never counted with its right key', async () => {
    const ip = freshIp();
    let last;
    let n = 0;
    for (; n < 80; n++) {
      last = await fetchJson(`/api/${n % 2 ? 'file' : 'paste'}/${madeUp(n % 2 ? 'f' : 'k')}/expire`, { method: 'POST', ip, headers: randomProofs() });
      if (last.status === 429) break;
      expect([last.status, (await last.json()).error]).toEqual([410, 'gone']);
    }
    expect([last.status, (await last.json()).error]).toEqual([429, 'blocked']);
    expect(n).toBeLessThanOrEqual(60);
    // A note that was a share (revoked): its right key on "delete now", many times, is never counted.
    const s = await createNote(oc, { text: 'was a share', deletable: true });
    const head = await (await fetchJson(`/api/paste/${s.id}`)).json();
    const { headers } = await proofHeaders(head.adata, s.fragment, '');
    expect((await fetchJson(`/api/private/shares/${s.id}/revoke`, { method: 'POST', cookie: oc, headers: intent })).status).toBe(200);
    const ip2 = freshIp();
    for (let i = 0; i < 70; i++) {
      const r = await fetchJson(`/api/paste/${s.id}/expire`, { method: 'POST', ip: ip2, headers });
      expect(r.status).toBe(410);
    }
    expect((await fetchJson(`/api/paste/${madeUp('k')}`, { ip: ip2 })).status).toBe(404); // not blocked
  }, 120000);
});

describe('B-3: chunk requests without a valid grant', () => {
  it('get the same counted 403 whatever the index; a valid grant still tells an out-of-range index (404)', async () => {
    const f = await upload(oc);
    expect(f.chunks).toBe(1);
    const forged = b64urlFromBytes(randomBytes(32));
    for (const path of ['0', '1', '999', '0/0', '5/2']) {
      const r = await getChunk(f.id, path, forged, freshIp());
      expect([r.status, (await r.json()).error], path).toEqual([403, 'bad_grant']);
    }
    // Out of range with a forged grant: counted as invalid until the block.
    const ip = freshIp();
    let r;
    let n = 0;
    for (; n < 80; n++) { r = await getChunk(f.id, String(1 + n), forged, ip); if (r.status === 429) break; expect(r.status).toBe(403); await r.arrayBuffer(); }
    expect(r.status).toBe(429);
    expect(n).toBeLessThanOrEqual(60);
    // The recipient's own grant: chunk 0 downloads, chunk 1 does not exist.
    const open = await openFile(f.id, f.fragment, '', freshIp());
    const { grant } = await open.json();
    expect((await getChunk(f.id, '0', grant)).status).toBe(200);
    const out = await getChunk(f.id, '1', grant);
    expect([out.status, (await out.json()).error]).toEqual([404, 'not_found']);
  }, 60000);

  it('a Drive share\'s files (the ref route) are not told either: the grant is checked first', async () => {
    const id = madeUp('f');
    const stub = env.FILESHARE.get(env.FILESHARE.idFromName(id));
    const paste = { v: 2, ct: 'x', wk: 'y', adata: { bar: false }, meta: { expire: '1d' } };
    expect((await stub.initRefs({ id, dth: 'd', refs: [{ key: 'd/u/n1', chunks: 2, size: 10 }], views: null, expire: '1d', ttl: 86400, paste, acc: { lh: 'a', kh: 'b' } })).status).toBe('ok');
    for (const [ref, i] of [[0, 0], [0, 5], [3, 0]]) expect((await stub.chunkAccessRef('forged-hash', ref, i)).status).toBe('bad_grant');
    expect((await stub.chunkAccess('forged-hash', 7)).status).toBe('bad_grant');
  });
});

describe('B-5: the tracker route has a per-network limit', () => {
  it('GET /api/public/t: TRACKER_FETCH.max − 1 per network per window, then 429 rate_limited; other networks unaffected', async () => {
    expect((await settings({ 'public.enabled': true, 'public.tracking': 'tracker' })).status).toBe(200);
    try {
      const ip = freshIp();
      expect((await fetchJson('/api/public/t', { ip })).status).toBe(200);
      await seedCounter('tracker-fetch', `${ip}/32`, TRACKER_FETCH.max - 2);
      expect((await fetchJson('/api/public/t', { ip })).status).toBe(200);
      const over = await fetchJson('/api/public/t', { ip });
      expect([over.status, (await over.json()).error, over.headers.get('retry-after')]).toEqual([429, 'rate_limited', String(TRACKER_FETCH.blockSec)]);
      expect((await fetchJson('/api/public/t', { ip: freshIp() })).status).toBe(200);
      // Not an invalid block: the network still reads shares.
      expect((await fetchJson(`/api/paste/${madeUp('k')}`, { ip })).status).toBe(404);
    } finally {
      await settings({ 'public.enabled': false });
    }
  });
});
