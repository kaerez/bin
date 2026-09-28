// audit-limits.test.js — per-network limits from the security audit of main
// (and its review, R1–R3):
//   C3  tokens siteverify rejects (sign-in, account changes, anonymous
//       creation) count towards "turnstile-verify"; once a network reached it,
//       its tokens get `429 rate_limited` without a call, until the owner
//       lifts it; accepted tokens are never counted; a missing token and a
//       cross-site request are refused uncounted;
//   C4  POST /api/auth/prelogin is limited per network ("prelogin") and per
//       network and username ("prelogin-user", a keyed hash of the name): the
//       refusal is the same for every username, passkeys and the sign-in
//       routes never look at these scopes, and another site's requests are
//       refused uncounted;
//   C6  the anonymous tracker table: a refused create gives its new row (and
//       the network's allowance) back and never counts towards the /48, new
//       ids are counted per IPv6 /48 once they created a share, and a full
//       table makes room from the least recently seen rows (never a blocked
//       one) instead of refusing every new sender.
import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest';
import { env, createExecutionContext, waitOnExecutionContext, runInDurableObject } from 'cloudflare:test';
import worker from '../src/index.js';
import { setSiteverify } from '../src/lib/turnstile.js';
import { TURNSTILE_VERIFY, PRELOGIN, PRELOGIN_USER } from '../src/lib/guard.js';
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

describe('C3 / R1: tokens siteverify rejects are limited per network; accepted ones never are', () => {
  const HOST = new URL(ORIGIN).hostname;
  let calls = 0;
  let prev;
  // "ok:<action>#n" passes for that action on this host (each token once); anything else is rejected.
  beforeAll(() => {
    const seen = new Set();
    prev = setSiteverify(async (form) => {
      calls++;
      const t = form.get('response');
      const m = /^ok:([^#]+)/.exec(t);
      if (!m || seen.has(t)) return Response.json({ success: false, 'error-codes': ['invalid-input-response'] });
      seen.add(t);
      return Response.json({ success: true, hostname: HOST, action: m[1] });
    });
  });
  afterEach(() => { calls = 0; });
  afterAll(() => setSiteverify(prev));
  const login = (from, token, username = 'nobody-here', pw = 'x') => tsFetch('/api/auth/login', { ip: from, token, body: { username, proof: proofFor(pw) } });

  it('rejected tokens: TURNSTILE_VERIFY.max reach siteverify, then 429 without a call; another network is not affected; the owner lifts it', async () => {
    const ip = freshIp();
    for (let i = 0; i < TURNSTILE_VERIFY.max; i++) {
      const r = await login(ip, 'junk-token');
      expect(r.status).toBe(403);
      expect((await r.json()).error).toBe('turnstile_failed');
    }
    expect(calls).toBe(TURNSTILE_VERIFY.max);
    const over = await login(ip, 'junk-token');
    expect([over.status, over.headers.get('retry-after')]).toEqual([429, String(TURNSTILE_VERIFY.blockSec)]);
    expect((await over.json()).error).toBe('rate_limited');
    // Once blocked, the other routes behind the CAPTCHA share the scope (here the recovery-code sign-in).
    expect((await tsFetch('/api/auth/recovery', { ip, token: 'junk-token', body: { username: 'nobody-here', code: 'x' } })).status).toBe(429);
    expect(calls).toBe(TURNSTILE_VERIFY.max); // the refusals made no subrequest
    // Another network still reaches siteverify.
    expect((await login(freshIp(), 'junk-token')).status).toBe(403);
    expect(calls).toBe(TURNSTILE_VERIFY.max + 1);
    // The owner sees the block and can lift it like the other scopes.
    expect((await guardBlocks()).some((b) => b.scope === 'turnstile-verify' && b.addr === `${ip}/32`)).toBe(true);
    expect((await unblock('turnstile-verify', `${ip}/32`)).status).toBe(200);
    expect((await login(ip, 'junk-token')).status).toBe(403);
  }, 60000);

  it('accepted tokens are never counted: a busy network signs in far more than TURNSTILE_VERIFY.max times', async () => {
    await makeUser('ts-busy-nat');
    const ip = freshIp();
    for (let i = 0; i < TURNSTILE_VERIFY.max + 30; i++) {
      const r = await login(ip, `ok:login#${ip}-${i}`, 'ts-busy-nat', USER_PW);
      expect(r.status, `sign-in #${i + 1}`).toBe(200);
    }
    // Rejected tokens from that network are still counted from zero.
    for (let i = 0; i < TURNSTILE_VERIFY.max; i++) expect((await login(ip, 'junk-token')).status).toBe(403);
    expect((await login(ip, `ok:login#${ip}-last`, 'ts-busy-nat', USER_PW)).status).toBe(429);
    expect((await unblock('turnstile-verify', `${ip}/32`)).status).toBe(200);
  }, 120000);

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
    expect((await login(ip, 'junk-token')).status).toBe(403); // still within the limit
  }, 60000);
});

describe('C4 / R2: prelogin is limited per network and per username, and says nothing about accounts', () => {
  const pre = (username, ip, headers) => fetchJson('/api/auth/prelogin', { method: 'POST', ip, body: { username }, headers });

  it('per username: PRELOGIN_USER.max − 1 per network, the same refusal for a real and a made-up name; other names, other networks, passkeys and direct sign-in unaffected; the owner lifts it', async () => {
    await makeUser('prelogin-limit');
    const ip = freshIp();
    // Another site's requests are refused before they are counted.
    for (let i = 0; i < 30; i++) expect((await pre('prelogin-limit', ip, { 'sec-fetch-site': 'cross-site' })).status).toBe(403);
    const real = await (await pre('prelogin-limit', ip)).json();
    const fake = await (await pre('no-such-user-here', ip)).json();
    expect(Object.keys(fake).sort()).toEqual(Object.keys(real).sort()); // the fake salt, as before
    for (let i = 1; i < PRELOGIN_USER.max - 1; i++) {
      expect((await pre('prelogin-limit', ip)).status).toBe(200);
      expect((await pre('No-Such-User-Here', ip)).status).toBe(200); // the name is counted lowercased
    }
    const a = await pre('Prelogin-Limit', ip);
    const b = await pre('no-such-user-here', ip);
    expect([a.status, b.status]).toEqual([429, 429]);
    expect([a.headers.get('retry-after'), b.headers.get('retry-after')]).toEqual([String(PRELOGIN.blockSec), String(PRELOGIN.blockSec)]);
    expect(await a.json()).toEqual(await b.json()); // identical: it says nothing about accounts
    // Another username from this network, and this username from another network, still get their salt.
    expect((await pre('someone-else', ip)).status).toBe(200);
    expect((await pre('prelogin-limit', freshIp())).status).toBe(200);
    // Passkeys, recovery codes and the sign-in itself never look at these scopes.
    expect((await fetchJson('/api/auth/passkey/options', { method: 'POST', ip, body: {} })).status).toBe(200);
    expect((await fetchJson('/api/auth/login', { method: 'POST', ip, body: { username: 'prelogin-limit', proof: proofFor(USER_PW) } })).status).toBe(200);
    // The owner sees the block (a keyed hash of the name, never the name) and lifts it.
    // One block per name from this network (both names reached the limit); the row keys are keyed hashes.
    const blocks = (await guardBlocks()).filter((x) => x.scope === 'prelogin-user' && x.addr.startsWith(`${ip}/32#`));
    expect(blocks).toHaveLength(2);
    for (const block of blocks) {
      expect(block.addr).toMatch(/#[0-9a-f]{16}$/);
      expect(block.addr).not.toContain('prelogin-limit');
      expect((await unblock('prelogin-user', block.key)).status).toBe(200);
    }
    expect((await pre('prelogin-limit', ip)).status).toBe(200);
  }, 60000);

  it('per network: PRELOGIN.max − 1 per window whatever the names, then 429 for every name; passkeys unaffected; the owner lifts it', async () => {
    const ip = freshIp();
    for (let i = 0; i < PRELOGIN.max - 1; i++) {
      const r = await pre(`name-${i % 40}`, ip); // 15 per name, under the per-username limit
      expect(r.status, `prelogin #${i + 1}`).toBe(200);
      await r.arrayBuffer();
    }
    const over = await pre('a-fresh-name', ip);
    expect([over.status, (await over.json()).error]).toEqual([429, 'rate_limited']);
    expect((await fetchJson('/api/auth/passkey/options', { method: 'POST', ip, body: {} })).status).toBe(200);
    expect((await pre('a-fresh-name', freshIp())).status).toBe(200);
    expect((await unblock('prelogin', `${ip}/32`)).status).toBe(200);
    expect((await pre('a-fresh-name', ip)).status).toBe(200);
  }, 120000);
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
    const block = (await guardBlocks()).find((b) => b.scope === 'public-trackers' && /^2001:db8:4c6:0:0:0:0:0\/48$/.test(b.addr));
    expect(block).toBeTruthy();
    expect((await unblock('public-trackers', block.key)).status).toBe(200);
    expect((await note('2001:db8:4c6:99::7', await tracker('2001:db8:4c6:99::7'))).status).toBe(201);
    await settings({ 'public.newTrackersPerIp': 2 });
  }, 60000);

  it('R3: refused creates from one /64 never count towards its /48: a neighbouring /64 still starts sharing', async () => {
    await settings({ 'public.newTrackersPerIp': 1 });
    try {
      const attacker = '2001:db8:5a1:1::66';
      for (let i = 0; i < 16 * 1 * 3; i++) { // three times the /48's allowance
        const aid = await tracker(attacker);
        const r = await fetchJson('/api/public/paste', { method: 'POST', ip: attacker, headers: { cookie: `__Host-secbin_aid=${aid}`, 'x-secbin-aid': aid }, body: { paste: { v: 2 } } });
        expect(r.status, `refused create #${i + 1}`).toBe(400);
      }
      expect((await guardBlocks()).some((b) => b.scope === 'public-trackers' && b.addr.startsWith('2001:db8:5a1:'))).toBe(false);
      // The neighbour /64 in the same /48 starts sharing with a new browser, and so does the attacker's /64 (its allowance came back).
      expect((await note('2001:db8:5a1:2::7', await tracker('2001:db8:5a1:2::7'))).status).toBe(201);
      expect((await note(attacker, await tracker(attacker))).status).toBe(201);
    } finally {
      await settings({ 'public.newTrackersPerIp': 2 });
    }
  }, 120000);

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
