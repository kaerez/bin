// kit-status.test.js — the Drive kits' key version and freshness, and the
// set-up page's proposed keys (docs/DRIVE.md §3, §3.1, §3.2), in workerd, in
// a storage of its own:
//  - set-up: the server proposes a root MEK and a first sub-MEK to the setup
//    token's holder only; nothing is stored until the set-up uses the pair
//    ("Use these"); "Generate again" replaces it; an old, an expired or an
//    unknown pair is refused before the owner is made;
//  - the keyring's version goes up by one on every key change (a sub-MEK
//    added, rotated, its dates edited, made current, deleted; a root change
//    and its undo; a restore that writes a key), not on a note or a
//    finished re-seal, and both kits carry it;
//  - the personal kit's state: the last download and its version, and
//    `stale` once the keys changed (or a scheduled sub-MEK it lacks
//    started), on the Account route and the Drive state; the owner acting
//    as the user can neither download nor clear it;
//  - with Turnstile keys set, the personal kit's Download and Verify need a
//    fresh CAPTCHA token for "account"; without keys they need none.
// Synthetic data only.
import { env, runInDurableObject, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index.js';
import { setSiteverify } from '../src/lib/turnstile.js';
import { AUTHN, ORIGIN, fetchJson, intent, salt16, proofFor, login, setOwnerCookie, owner, makeUser, cookieOf, USER_PW, csrfHeaders, STATE_CHANGING } from './helpers.js';
import { enableDrive, uploadFile } from './drive-helpers.js';
import { dirStub } from './reverse-helpers.js';
import { keyBytes, keyCheckValue, saltCheckValue, keyFingerprint } from '../public/js/drivekeys.js';

const OWNER_PW = 'owner-password';
const STEP = { current: proofFor(OWNER_PW) };
const K = '/api/private/admin/keys';
const errorOf = async (r) => (await r.json()).error;
const post = (path, body = {}, cookie, headers = intent) => fetchJson(path, { method: 'POST', cookie, headers, body });
const keyring = () => runInDurableObject(dirStub(), (inst, state) => ({
  root: state.storage.sql.exec("SELECT v FROM meta WHERE k = 'mek.root'").toArray().length,
  subs: state.storage.sql.exec('SELECT COUNT(*) AS c FROM meks').one().c,
  owner: state.storage.sql.exec("SELECT COUNT(*) AS c FROM users WHERE role = 'owner'").one().c,
}));

describe('set-up: the proposed Drive keys ("Use these" / "Generate again")', () => {
  // The first test of the file: the instance has no owner and no keyring yet.
  it('proposed to the setup token\'s holder only; nothing stored until the set-up uses the chosen pair; then the keys are that pair', async () => {
    const cand = (body, headers = intent) => fetchJson('/api/auth/setup/candidate', { method: 'POST', headers, body });
    // The intent header, the token: refused without them, and nothing is made.
    expect(await errorOf(await cand({ token: AUTHN }, {}))).toBe('missing_intent');
    const bad = await cand({ token: 'not-the-setup-token-0123456789' });
    expect([bad.status, await errorOf(bad)]).toEqual([403, 'bad_token']);
    const p1 = await (await cand({ token: AUTHN })).json();
    expect(p1.root).toMatchObject({ id: expect.stringMatching(/^[A-Za-z0-9_-]{16}$/), key: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/) });
    expect(p1.root.fp).toBe(await keyFingerprint(keyBytes(p1.root.key)));
    expect(p1.sub.fp).toBe(await keyFingerprint(keyBytes(p1.sub.key)));
    expect(p1.root.key).not.toBe(p1.sub.key);
    // A proposal is not a keyring.
    expect(await keyring()).toEqual({ root: 0, subs: 0, owner: 0 });
    // "Generate again": a new pair; the first one is gone.
    const p2 = await (await cand({ token: AUTHN })).json();
    expect(p2.root.key).not.toBe(p1.root.key);
    const setupWith = (keys) => fetchJson('/api/auth/setup', { method: 'POST', body: { token: AUTHN, username: 'owner', salt: salt16(), t: 3, proof: proofFor(OWNER_PW), keys } });
    const old = await setupWith({ mode: 'generated', root: p1.root.id, sub: p1.sub.id });
    expect([old.status, await errorOf(old)]).toEqual([410, 'candidate_expired']);
    // Mixed up (the sub-MEK's id for the root): refused too. Neither made the owner.
    expect((await setupWith({ mode: 'generated', root: p2.sub.id, sub: p2.root.id })).status).toBe(410);
    expect(await keyring()).toEqual({ root: 0, subs: 0, owner: 0 });
    // A pair past its 10 minutes is refused.
    await runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec("UPDATE mek_candidates SET exp = exp - 700 WHERE sid = 'setup:'"));
    expect((await setupWith({ mode: 'generated', root: p2.root.id, sub: p2.sub.id })).status).toBe(410);
    expect(await keyring()).toEqual({ root: 0, subs: 0, owner: 0 });
    // The chosen pair: the owner is made and the keys are exactly the ones shown.
    const p3 = await (await cand({ token: AUTHN })).json();
    const r = await setupWith({ mode: 'generated', root: p3.root.id, sub: p3.sub.id });
    expect(r.status, await r.clone().text()).toBe(200);
    expect(await r.json()).toMatchObject({ ok: true, keys: 'created' });
    const oc = await login('owner', OWNER_PW);
    setOwnerCookie(oc);
    const st = await (await fetchJson(K, { cookie: oc })).json();
    expect(st.root.fp).toBe(p3.root.fp);
    expect(st.subs.map((s) => s.fp)).toEqual([p3.sub.fp]);
    expect((await (await post(`${K}/root/show`, STEP, oc)).json()).key).toBe(p3.root.key);
    expect((await (await post(`${K}/subs/${st.current}/show`, STEP, oc)).json()).key).toBe(p3.sub.key);
    expect(st.version).toMatchObject({ n: 1 });
    // Used up, and no more proposals once there is a keyring.
    const again = await cand({ token: AUTHN });
    expect([again.status, await errorOf(again)]).toEqual([409, 'keys_exist']);
    const left = await runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec("SELECT COUNT(*) AS c FROM mek_candidates WHERE sid = 'setup:'").one().c);
    expect(left).toBe(0);
    // The admin audit: fingerprints only, never a key.
    const audit = JSON.stringify((await (await fetchJson('/api/private/admin/audit?limit=500', { cookie: oc })).json()).rows);
    expect(audit).toContain(p3.root.fp);
    expect(audit).toContain('generated at set-up, shown and chosen');
    for (const p of [p1, p2, p3]) for (const k of [p.root.key, p.sub.key]) expect(audit).not.toContain(k);
  });
});

describe('the keyring version', () => {
  const version = async () => (await (await fetchJson(K, { cookie: await owner() })).json()).version.n;
  const candidate = async (purpose) => (await (await post(`${K}/candidate`, { purpose, ...STEP }, await owner())).json()).id;
  async function runJob() {
    let job = null;
    for (let n = 0; n < 200; n++) {
      ({ job } = await (await post(`${K}/jobs/step`, {}, await owner())).json());
      if (!job || job.finished) break;
    }
    return job;
  }

  it('goes up by one on every key change (add, rotate, dates, current, delete, root change and undo, a restore), not on a note or a finished re-seal; both kits carry it', async () => {
    const oc = await owner();
    let n = await version();
    const step = async (what, fn, by = 1) => { const r = await fn(); expect(r.status, `${what}: ${await r.clone().text()}`).toBe(200); expect(await version(), what).toBe(n + by); n += by; return r.json(); };
    const t = Math.floor(Date.now() / 1000);
    const first = (await (await fetchJson(K, { cookie: oc })).json()).subs[0];
    await step('rotate', async () => post(`${K}/subs`, { candidate: await candidate('sub'), rotate: true, ...STEP }, oc));
    const added = await step('add (scheduled)', async () => post(`${K}/subs`, { candidate: await candidate('sub'), from: t + 86400, ...STEP }, oc));
    await step('dates', () => fetchJson(`${K}/subs/${first.id}`, { method: 'PATCH', cookie: oc, headers: intent, body: { from: first.from - 100, ...STEP } }));
    await step('a note only', () => fetchJson(`${K}/subs/${first.id}`, { method: 'PATCH', cookie: oc, headers: intent, body: { note: 'a note', ...STEP } }), 0);
    await step('set current', () => post(`${K}/subs/${added.id}/current`, STEP, oc));
    await step('delete', () => fetchJson(`${K}/subs/${first.id}`, { method: 'DELETE', cookie: oc, headers: intent, body: STEP }));
    await step('root change', async () => post(`${K}/root`, { candidate: await candidate('root'), ...STEP }, oc));
    await step('root change undone', () => post(`${K}/root/undo`, STEP, oc));
    await runJob();
    expect(await version(), 'a finished re-seal is not a key change').toBe(n);
    // A restore that writes a key: a sub-MEK the server lost, put back from the key kit.
    const kit = (await (await post(`${K}/kit`, STEP, oc)).json());
    expect(kit.material.keyVersion).toMatchObject({ n, at: expect.any(Number) });
    expect(kit.kit.v).toBe(n);
    const lost = kit.material.subs.find((s) => s.id !== kit.material.current) || kit.material.subs[0];
    await runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec('UPDATE meks SET sealed = ? WHERE id = ?', 'm1.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', lost.id));
    const restored = await (await post(`${K}/restore`, { root: kit.material.root, subs: [lost], salts: {}, dryRun: false, ...STEP }, oc)).json();
    expect(restored.subs).toEqual([{ id: lost.id, result: 'restored' }]);
    expect(await version()).toBe(n + 1);
    n += 1;
    // A restore that changes nothing is not a key change.
    await post(`${K}/restore`, { root: kit.material.root, subs: kit.material.subs, salts: {}, dryRun: false, ...STEP }, oc);
    expect(await version()).toBe(n);
    // The key kit's Verify says the version now.
    const v = await (await post(`${K}/verify`, { root: await keyCheckValue(keyBytes(kit.material.root.key), 'mek') }, oc)).json();
    expect(v.version).toMatchObject({ n });
  });
});

describe('the personal kit: last download, version and the stale notice', () => {
  const kitState = async (cookie) => (await fetchJson('/api/private/drive/kit', { cookie })).json();
  const driveState = async (cookie) => (await (await fetchJson('/api/private/drive', { cookie })).json()).kit;
  const download = (cookie) => post('/api/private/drive/kit', { current: proofFor(USER_PW) }, cookie);
  const impersonate = async (uid) => cookieOf(await fetchJson(`/api/private/admin/users/${uid}/impersonate`, { method: 'POST', cookie: await owner(), headers: intent }));

  it('recorded with the key version at each download; stale after a key change or when a scheduled sub-MEK it lacks starts; the owner acting as the user cannot clear it', async () => {
    const oc = await owner();
    const u = await makeUser('kit-status-u');
    await enableDrive(u.id);
    await uploadFile(u.cookie, 'root', 10);
    // Never downloaded: no notice (nothing is out of date), the version shown.
    const st0 = await kitState(u.cookie);
    const v0 = (await (await fetchJson(K, { cookie: oc })).json()).version;
    expect(st0).toEqual({ version: v0.n, versionAt: v0.at, last: null, stale: false });
    expect(await driveState(u.cookie)).toMatchObject({ last: null, stale: false });
    // A download: its version and date recorded; the kit holds the version.
    const t0 = Math.floor(Date.now() / 1000);
    const r = await (await download(u.cookie)).json();
    expect(r.kit.keyVersion).toBe(v0.n);
    expect(r.status).toMatchObject({ version: v0.n, last: { version: v0.n }, stale: false });
    const st1 = await kitState(u.cookie);
    expect(st1.last.at).toBeGreaterThanOrEqual(t0);
    expect(st1).toMatchObject({ last: { version: v0.n }, stale: false });
    // No key detail in the state.
    expect(JSON.stringify(st1)).not.toMatch(/fp|mek|kek|salt/i);
    // The owner rotates: the user's kit is out of date, on both pages' routes.
    const c = await (await post(`${K}/candidate`, { purpose: 'sub', ...STEP }, oc)).json();
    expect((await post(`${K}/subs`, { candidate: c.id, rotate: true, ...STEP }, oc)).status).toBe(200);
    expect(await kitState(u.cookie)).toMatchObject({ version: v0.n + 1, last: { version: v0.n }, stale: true });
    expect(await driveState(u.cookie)).toMatchObject({ stale: true });
    // The owner acting as the user sees the user's Drive state, but can neither download nor clear it.
    const ic = await impersonate(u.id);
    expect(await driveState(ic)).toMatchObject({ stale: true });
    const imp = await post('/api/private/drive/kit', {}, ic);
    expect([imp.status, await errorOf(imp)]).toEqual([403, 'impersonating']);
    expect(await errorOf(await fetchJson('/api/private/drive/kit', { cookie: ic }))).toBe('impersonating');
    expect(await kitState(u.cookie)).toMatchObject({ last: { version: v0.n }, stale: true });
    // The user downloads again: the notice clears.
    await download(u.cookie);
    expect(await kitState(u.cookie)).toMatchObject({ version: v0.n + 1, last: { version: v0.n + 1 }, stale: false });
    expect(await driveState(u.cookie)).toMatchObject({ stale: false });
    // A scheduled sub-MEK: a key change (stale), then a new kit (not stale) that does not hold it yet...
    const t = Math.floor(Date.now() / 1000);
    const c2 = await (await post(`${K}/candidate`, { purpose: 'sub', ...STEP }, oc)).json();
    const sched = await (await post(`${K}/subs`, { candidate: c2.id, from: t + 3600, ...STEP }, oc)).json();
    expect((await kitState(u.cookie)).stale).toBe(true);
    await download(u.cookie);
    expect((await kitState(u.cookie)).stale).toBe(false);
    // ...and once it starts (time passes: its dates moved into the past here, no key change), the kit lacks the current one.
    await runInDurableObject(dirStub(), (inst, state) => {
      state.storage.sql.exec('UPDATE meks SET until_ts = ? WHERE until_ts = ?', t - 60, t + 3600);
      state.storage.sql.exec('UPDATE meks SET from_ts = ? WHERE id = ?', t - 60, sched.id);
    });
    expect(await kitState(u.cookie)).toMatchObject({ stale: true, last: { version: (await kitState(u.cookie)).version } });
    // Deleting the account removes its record.
    await fetchJson(`/api/private/admin/users/${u.id}`, { method: 'DELETE', cookie: oc, headers: intent });
    const rec = await runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec('SELECT COUNT(*) AS c FROM meta WHERE k = ?', `ukit:${u.id}`).one().c);
    expect(rec).toBe(0);
  });
});

// ── the CAPTCHA on the personal kit (Turnstile keys set) ────────────────────
const SITEKEY = '0x4AAAAAAAtestsitekey';
const TS_ENV = { ...env, TURNSTILE_SITEKEY: SITEKEY, TURNSTILE_SECRET: '0x4AAAAAAAtestsecretvalue' };
const HOST = new URL(ORIGIN).hostname;
async function tsFetch(path, { method = 'GET', body, cookie, headers = {}, token } = {}) {
  const h = { ...headers };
  if (body !== undefined) h['content-type'] = 'application/json';
  if (cookie) h.cookie = cookie;
  if (token) h['x-secbin-turnstile'] = token;
  if (cookie && STATE_CHANGING.has(method)) Object.assign(h, await csrfHeaders(cookie));
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(`${ORIGIN}${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body) }), TS_ENV, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

describe('the CAPTCHA on the personal kit (Account page)', () => {
  it('with Turnstile keys: Download and Verify need a fresh token for "account" (checked before the step-up); none needed without keys', async () => {
    const u = await makeUser('kit-captcha-u');
    await enableDrive(u.id);
    await uploadFile(u.cookie, 'root', 10);
    const seen = new Set();
    const prev = setSiteverify(async (form) => {
      const t = form.get('response');
      if (seen.has(t)) return Response.json({ success: false, 'error-codes': ['timeout-or-duplicate'] });
      seen.add(t);
      const m = /^ok:([^#]+)/.exec(t);
      return Response.json(m ? { success: true, hostname: HOST, action: m[1] } : { success: false });
    });
    try {
      const dl = (token, body = { current: proofFor(USER_PW) }) => tsFetch('/api/private/drive/kit', { method: 'POST', cookie: u.cookie, headers: intent, body, token });
      // No token, a token of another form, a used token: refused, nothing handed out, no download recorded.
      const none = await dl(null);
      expect([none.status, await errorOf(none)]).toEqual([403, 'turnstile_required']);
      expect(await errorOf(await dl('ok:login#1'))).toBe('turnstile_failed');
      // Checked before the step-up: a wrong password with no token spends no password attempt.
      expect(await errorOf(await dl(null, { current: proofFor('wrong-password') }))).toBe('turnstile_required');
      expect((await (await fetchJson('/api/private/drive/kit', { cookie: u.cookie })).json()).last).toBeNull();
      const ok = await dl('ok:account#1');
      expect(ok.status, await ok.clone().text()).toBe(200);
      const kit = (await ok.json()).kit;
      expect(await errorOf(await dl('ok:account#1'))).toBe('turnstile_failed');
      // Verify, too.
      const checks = { keks: {}, salt: await saltCheckValue(kit.userSalt, u.id) };
      for (const x of kit.keks) checks.keks[x.mekId] = await keyCheckValue(keyBytes(x.kek), 'kek');
      const vf = (token) => tsFetch('/api/private/drive/kit/verify', { method: 'POST', cookie: u.cookie, headers: intent, body: checks, token });
      expect(await errorOf(await vf(null))).toBe('turnstile_required');
      const v = await vf('ok:account#2');
      expect(v.status).toBe(200);
      expect(await v.json()).toMatchObject({ complete: true, version: kit.keyVersion });
      // The state is a read: no token needed.
      expect((await tsFetch('/api/private/drive/kit', { cookie: u.cookie })).status).toBe(200);
    } finally {
      setSiteverify(prev);
    }
    // Without Turnstile keys (the default env), no token is asked for.
    expect((await post('/api/private/drive/kit', { current: proofFor(USER_PW) }, u.cookie)).status).toBe(200);
  });
});
