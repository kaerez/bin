// audit-limits.test.js — per-network limits from the security audit of main:
//   C3  every Turnstile token that reaches siteverify (sign-in, account
//       changes, anonymous creation) counts towards "turnstile-verify";
//       beyond it `429 rate_limited` without a siteverify call, per network,
//       liftable by the owner; a cross-site request is refused uncounted;
//   C4  POST /api/auth/prelogin counts towards "prelogin" per network: the
//       refusal is the same for every username, only prelogin is refused (the
//       account still signs in, from that network too), and another site's
//       requests are refused uncounted;
//   C6  the anonymous tracker table: a refused create gives its new row (and
//       the network's allowance) back, new ids are also counted per IPv6 /48,
//       and a full table makes room from the least recently seen rows (never
//       a blocked one) instead of refusing every new sender.
import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { env, createExecutionContext, waitOnExecutionContext, runInDurableObject } from 'cloudflare:test';
import worker from '../src/index.js';
import { setSiteverify } from '../src/lib/turnstile.js';
import { TURNSTILE_VERIFY, PRELOGIN } from '../src/lib/guard.js';
import { MAX_TRACKERS, TRACKER_EVICT } from '../src/directory-do.js';
import { encryptPaste } from '../public/js/crypto.js';
import { owner, makeUser, fetchJson, freshIp, proofFor, ORIGIN, USER_PW } from './helpers.js';

const PUBLIC_ID = 'public-user-0000';
const TS_ENV = { ...env, TURNSTILE_SITEKEY: '0x4AAAAAAAtestsitekey', TURNSTILE_SECRET: '0x4AAAAAAAtestsecretvalue' };
let oc;
beforeAll(async () => { oc = await owner(); });

const settings = (patch) => fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: patch });
const unblock = (scope, key) => fetchJson('/api/private/admin/guard/unblock', { method: 'POST', cookie: oc, body: { scope, key } });
const guardBlocks = async () => (await (await fetchJson('/api/private/admin/guard', { cookie: oc })).json()).blocks;

/** The Worker with Turnstile configured (SELF runs without it). */
async function tsFetch(path, { body, ip, token, headers = {} } = {}) {
  const h = { 'content-type': 'application/json', ...headers };
  if (ip) h['cf-connecting-ip'] = ip;
  if (token) h['x-secbin-turnstile'] = token;
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(`${ORIGIN}${path}`, { method: 'POST', headers: h, body: JSON.stringify(body ?? {}) }), TS_ENV, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

describe('C3: siteverify is behind a per-network limit', () => {
  let calls = 0;
  let prev;
  beforeAll(() => { prev = setSiteverify(async () => { calls++; return Response.json({ success: false, 'error-codes': ['invalid-input-response'] }); }); });
  afterEach(() => { calls = 0; });

  it('junk tokens: at most TURNSTILE_VERIFY.max − 1 reach siteverify per network, then 429 without a call; another network is not affected; the owner lifts it', async () => {
    const ip = freshIp();
    const login = (from, token = 'junk-token') => tsFetch('/api/auth/login', { ip: from, token, body: { username: 'nobody-here', proof: proofFor('x') } });
    for (let i = 0; i < TURNSTILE_VERIFY.max - 1; i++) {
      const r = await login(ip);
      expect(r.status).toBe(403);
      expect((await r.json()).error).toBe('turnstile_failed');
    }
    expect(calls).toBe(TURNSTILE_VERIFY.max - 1);
    const over = await login(ip);
    expect([over.status, over.headers.get('retry-after')]).toEqual([429, String(TURNSTILE_VERIFY.blockSec)]);
    expect((await over.json()).error).toBe('rate_limited');
    // The other routes behind the CAPTCHA share the scope (here the recovery-code sign-in).
    const pub = await tsFetch('/api/auth/recovery', { ip, token: 'junk-token', body: { username: 'nobody-here', code: 'x' } });
    expect(pub.status).toBe(429);
    expect(calls).toBe(TURNSTILE_VERIFY.max - 1); // the refusals made no subrequest
    // Another network still reaches siteverify.
    expect((await login(freshIp())).status).toBe(403);
    expect(calls).toBe(TURNSTILE_VERIFY.max);
    // The owner sees the block and can lift it like the other scopes.
    expect((await guardBlocks()).some((b) => b.scope === 'turnstile-verify' && b.key === `${ip}/32`)).toBe(true);
    expect((await unblock('turnstile-verify', `${ip}/32`)).status).toBe(200);
    expect((await login(ip)).status).toBe(403);
  }, 60000);

  it('a missing token and a cross-site request are refused before anything is counted or sent', async () => {
    const ip = freshIp();
    for (let i = 0; i < TURNSTILE_VERIFY.max + 5; i++) {
      const none = await tsFetch('/api/auth/login', { ip, body: { username: 'u', proof: proofFor('x') } });
      expect((await none.json()).error).toBe('turnstile_required');
      const cross = await tsFetch('/api/auth/login', { ip, token: 'junk-token', headers: { 'sec-fetch-site': 'cross-site' }, body: { username: 'u', proof: proofFor('x') } });
      expect(cross.status).toBe(403);
      expect((await cross.json()).error).toBe('cross_site');
    }
    expect(calls).toBe(0);
    expect((await tsFetch('/api/auth/login', { ip, token: 'junk-token', body: { username: 'u', proof: proofFor('x') } })).status).toBe(403); // still within the limit
  }, 60000);

  afterAll(() => setSiteverify(prev));
});

describe('C4: prelogin is behind a per-network limit that locks out no one', () => {
  it('beyond PRELOGIN.max − 1 per window: 429 for any username, the account still signs in, the owner lifts it', async () => {
    const u = await makeUser('prelogin-limit');
    const ip = freshIp();
    const pre = (username, from = ip, headers) => fetchJson('/api/auth/prelogin', { method: 'POST', ip: from, body: { username }, headers });
    // Another site's requests are refused before they are counted.
    for (let i = 0; i < 10; i++) expect((await pre('prelogin-limit', ip, { 'sec-fetch-site': 'cross-site' })).status).toBe(403);
    const real = await (await pre('prelogin-limit')).json();
    const fake = await (await pre('no-such-user-here')).json();
    expect(Object.keys(fake).sort()).toEqual(Object.keys(real).sort()); // the fake salt, as before
    for (let i = 2; i < PRELOGIN.max - 1; i++) expect((await pre(i % 2 ? 'prelogin-limit' : `nobody-${i}`)).status).toBe(200);
    const a = await pre('prelogin-limit');
    const b = await pre('no-such-user-here');
    expect([a.status, b.status]).toEqual([429, 429]);
    const [ja, jb] = [await a.json(), await b.json()];
    expect(ja.error).toBe('rate_limited');
    expect({ ...ja, until: 0 }).toEqual({ ...jb, until: 0 }); // says nothing about accounts
    expect(a.headers.get('retry-after')).toBe(String(PRELOGIN.blockSec));
    // Nobody is locked out: the account signs in, from this network too, and prelogin works elsewhere.
    expect((await fetchJson('/api/auth/login', { method: 'POST', ip, body: { username: 'prelogin-limit', proof: proofFor(USER_PW) } })).status).toBe(200);
    expect((await pre('prelogin-limit', freshIp())).status).toBe(200);
    expect(u.id).toBeTruthy();
    expect((await guardBlocks()).some((x) => x.scope === 'prelogin' && x.key === `${ip}/32`)).toBe(true);
    expect((await unblock('prelogin', `${ip}/32`)).status).toBe(200);
    expect((await pre('prelogin-limit')).status).toBe(200);
  }, 60000);
});

describe('C6: the anonymous tracker table cannot be filled', () => {
  const tracker = async (ip) => {
    const res = await fetchJson('/api/public/t', { ip });
    return (res.headers.get('set-cookie') || '').match(/__Host-secbin_aid=([A-Za-z0-9_-]{32})/)[1];
  };
  const note = async (ip, aid, text = 'anonymous') => {
    const { body } = await encryptPaste({ text, bar: true, views: 1, expire: '1h' });
    return fetchJson('/api/public/paste', { method: 'POST', ip, headers: { cookie: `__Host-secbin_aid=${aid}`, 'x-secbin-aid': aid }, body: { paste: body } });
  };
  const total = async () => (await (await fetchJson('/api/private/admin/public', { cookie: oc })).json()).trackers.total;
  const dir = () => env.DIRECTORY.get(env.DIRECTORY.idFromName('directory'));

  beforeAll(async () => {
    await settings({ 'public.enabled': true, 'public.tracking': 'tracker', 'public.newTrackersPerIp': 2 });
    await fetchJson('/api/private/admin/quotas', { method: 'PUT', cookie: oc, body: { scope: PUBLIC_ID, list: [{ channel: 'all', kind: 'all', n: 1, unit: 'd', max: 1000 }] } });
  });
  afterAll(async () => { await settings({ 'public.enabled': false, 'public.newTrackersPerIp': 5 }); });

  it('a refused create stores nothing: its new row and the network\'s allowance come back', async () => {
    const ip = freshIp();
    const before = await total();
    for (let i = 0; i < 6; i++) {
      const bad = await fetchJson('/api/public/paste', { method: 'POST', ip, headers: { cookie: `__Host-secbin_aid=${await tracker(ip)}`, 'x-secbin-aid': 'x' }, body: {} });
      expect(bad.status).toBe(428); // cookie and header disagree: never stored
      const aid = await tracker(ip);
      const refused = await fetchJson('/api/public/paste', { method: 'POST', ip, headers: { cookie: `__Host-secbin_aid=${aid}`, 'x-secbin-aid': aid }, body: { paste: { v: 2 } } });
      expect(refused.status).toBe(400); // a malformed share, refused after the tracker was looked at
    }
    expect(await total()).toBe(before);
    // The network's allowance (2 new ids per window) is intact.
    expect((await note(ip, await tracker(ip))).status).toBe(201);
    expect((await note(ip, await tracker(ip))).status).toBe(201);
    expect(await total()).toBe(before + 2);
    const third = await note(ip, await tracker(ip));
    expect([third.status, (await third.json()).error]).toEqual([429, 'tracker_rate_limited']);
    expect(await total()).toBe(before + 2);
  }, 60000);

  it('new ids are also counted per IPv6 /48: rotating /64s does not multiply the allowance', async () => {
    await settings({ 'public.newTrackersPerIp': 1 });
    const wide = 16 * 1; // WIDE_FACTOR × public.newTrackersPerIp
    const codes = [];
    for (let i = 0; i < wide + 2; i++) {
      const ip = `2001:db8:4c6:${(i + 1).toString(16)}::7`; // a new /64 each time, one /48
      codes.push((await note(ip, await tracker(ip))).status);
    }
    expect(codes.slice(0, wide)).toEqual(Array(wide).fill(201));
    expect(codes.slice(wide)).toEqual([429, 429]);
    // Another /48 is not affected; the owner sees the block and can lift it.
    expect((await note('2001:db8:4c7:1::7', await tracker('2001:db8:4c7:1::7'))).status).toBe(201);
    const block = (await guardBlocks()).find((b) => b.scope === 'public-trackers' && /^2001:db8:4c6:0:0:0:0:0\/48$/.test(b.key));
    expect(block).toBeTruthy();
    expect((await unblock('public-trackers', block.key)).status).toBe(200);
    expect((await note('2001:db8:4c6:99::7', await tracker('2001:db8:4c6:99::7'))).status).toBe(201);
    await settings({ 'public.newTrackersPerIp': 2 });
  }, 60000);

  it('a full table makes room from the least recently seen rows (never a blocked one) instead of refusing', async () => {
    const ts = Math.floor(Date.now() / 1000);
    await runInDurableObject(dir(), (_inst, state) => {
      const sql = state.storage.sql;
      sql.exec(`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < ?)
        INSERT INTO trackers (id_hash, created, last_seen, ip_hash) SELECT 'syn' || i, ?, ? + i, 'syn' FROM n`, MAX_TRACKERS, ts - 400000, ts - 300000);
      sql.exec("INSERT INTO trackers (id_hash, created, last_seen, ip_hash, blocked, reason) VALUES ('synblocked', ?, ?, 'syn', 1, 'admin')", ts - 500000, ts - 500000);
      sql.exec("INSERT INTO usage (quota_id, user_id, bucket, count, ts) VALUES ('q', 'pub:t:syn1', 0, 1, ?)", ts);
    });
    try {
      const ip = freshIp();
      expect((await note(ip, await tracker(ip))).status).toBe(201); // not "at capacity"
      await runInDurableObject(dir(), (_inst, state) => {
        const sql = state.storage.sql;
        const has = (id) => sql.exec('SELECT COUNT(*) AS c FROM trackers WHERE id_hash = ?', id).one().c === 1;
        expect(has('syn1')).toBe(false);
        expect(has(`syn${TRACKER_EVICT}`)).toBe(false);
        expect(has(`syn${TRACKER_EVICT + 1}`)).toBe(true);
        expect(has('synblocked')).toBe(true); // stays blocked
        expect(sql.exec("SELECT COUNT(*) AS c FROM usage WHERE user_id = 'pub:t:syn1'").one().c).toBe(0); // its counters went with it
        expect(sql.exec('SELECT COUNT(*) AS c FROM trackers').one().c).toBeLessThanOrEqual(MAX_TRACKERS);
      });
    } finally {
      await runInDurableObject(dir(), (_inst, state) => { state.storage.sql.exec("DELETE FROM trackers WHERE id_hash LIKE 'syn%'"); });
    }
  }, 60000);
});
