// captcha.test.js — CAPTCHA on shares (the shareCaptcha / reverseCaptcha role
// options, src/lib/settings.js; grants, src/lib/human.js): the options resolve
// for the owner, the Default role, custom roles and the public account; every
// create path applies the role (allow / require / off), the API included; a
// protected share serves nothing — head, open, "delete now", chunks — without
// a grant, on every kind of share (a route sweep that fails when a content
// route is added without the check); grants are bound to the share and the
// network, expire, slide and are capped; the check spends no view and is not
// counted as an invalid fetch; a reverse link's session start needs a grant
// (one per start) only when the link has the flag; the pages get the strict
// CSP and a page key, and only the check page the Turnstile CSP; the options
// travel in an export's roles part.
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { env, SELF, createExecutionContext, waitOnExecutionContext, runInDurableObject } from 'cloudflare:test';
import worker from '../src/index.js';
import { setSiteverify } from '../src/lib/turnstile.js';
import { CSP, TURNSTILE_CSP } from '../src/lib/http.js';
import { SCHEMA_VERSION } from '../src/directory-do.js';
import { SHARE_GRANT_SEC, SHARE_GRANT_CAP_SEC } from '../src/lib/human.js';
import publicRoutesSource from '../src/routes/public.js?raw';
import { owner, makeUser, fetchJson, freshIp, proofFor, ORIGIN, USER_PW, intent, proofHeaders } from './helpers.js';
import { enableDrive, driveLimits, uploadFile } from './drive-helpers.js';
import { receiver, newReverse, dirStub, driveOf } from './reverse-helpers.js';
import { linkProof, passwordProof } from '../public/js/reversekeys.js';
import { encryptPaste } from '../public/js/crypto.js';
import { layout, buildManifest, importFileKey, encryptChunk, readStreamChunk } from '../public/js/files.js';
import { b64urlFromBytes, bytesFromB64url, fromUtf8, randomBytes, utf8 } from '../public/js/bytes.js';

const TS_ENV = { ...env, TURNSTILE_SITEKEY: '0x4AAAAAAAtestsitekey', TURNSTILE_SECRET: '0x4AAAAAAAtestsecretvalue' };
const HOST = new URL(ORIGIN).hostname;
const PUBLIC_ID = 'public-user-0000';
const MSG = 'This share requires a CAPTCHA; open it in a browser.';

// Some tests create dozens of shares (every create path, every kind): more time than the default 5 s.
vi.setConfig({ testTimeout: 60000 });

let oc;
let restoreSiteverify;
beforeAll(async () => {
  oc = await owner();
  // Tokens "ok:<action>[#n]" pass for that action on this host, once each (as Cloudflare does).
  const seen = new Set();
  restoreSiteverify = setSiteverify(async (form) => {
    const t = form.get('response');
    if (seen.has(t)) return Response.json({ success: false, 'error-codes': ['timeout-or-duplicate'] });
    seen.add(t);
    const m = /^ok:([^#]+)/.exec(t);
    return Response.json(m ? { success: true, hostname: HOST, action: m[1] } : { success: false });
  });
  return () => setSiteverify(restoreSiteverify);
});
afterEach(() => vi.useRealTimers());

let tokenSeq = 0;
const token = (action) => `ok:${action}#${++tokenSeq}`;

/** The Worker with Turnstile keys configured (SELF runs without). */
async function ts(path, { method = 'GET', body, cookie, headers = {}, ip } = {}) {
  const h = { ...headers };
  if (body !== undefined) h['content-type'] = 'application/json';
  if (cookie) h.cookie = cookie;
  if (ip) h['cf-connecting-ip'] = ip;
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(`${ORIGIN}${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' }), TS_ENV, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}
const errorOf = async (r) => (await r.clone().json()).error;
const limits = (scope, patch) => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope, channel: 'all', patch } });
const me = async (cookie) => (await fetchJson('/api/private/me', { cookie })).json();
const bearer = (k) => ({ authorization: `Bearer ${k}` });

// ── share builders (as the browsers and the CLI send them) ─────────────────

/** A note: views null → KV (unlimited), a number → a burn note. */
async function note(auth, { views = null, captcha, password = '', expire = '1h' } = {}) {
  const { body, fragment } = await encryptPaste({ text: 'the secret', bar: views !== null, views: views ?? undefined, expire, password });
  const res = await fetchJson('/api/private/paste', { method: 'POST', ...auth, body: { paste: body, ...(captcha === undefined ? {} : { captcha }) } });
  return { res, fragment, adata: body.adata, password, ...(res.status === 201 ? await res.clone().json() : {}) };
}

/** A file share of one small file (the full chunked upload). */
async function fileShare(auth, { views = null, captcha } = {}) {
  const files = [{ path: 'a.txt', type: 'text/plain', bytes: utf8('file content') }];
  const l = layout(files.map((f) => ({ path: f.path, type: f.type, size: f.bytes.length, mtime: 0 })), []);
  const manifest = buildManifest({ entries: l.entries, total: l.total });
  const init = await fetchJson('/api/private/file', { method: 'POST', ...auth, body: { views, expire: '1h', padded: l.padded, files: 1, maxFile: files[0].bytes.length, ...(captcha === undefined ? {} : { captcha }) } });
  if (init.status !== 201) return { res: init };
  const i0 = await init.json();
  const key = await importFileKey(manifest.fk);
  const sources = files.map((f, i) => ({ off: l.entries[i].off, size: f.bytes.length, read: async (a, b) => f.bytes.slice(a, b) }));
  for (let i = 0; i < i0.chunks; i++) {
    const ct = await encryptChunk(key, i, i0.chunks, await readStreamChunk(sources, i, l.total));
    const r = await SELF.fetch(`${ORIGIN}/api/private/file/${i0.id}/chunk/${i}`, { method: 'PUT', headers: { ...(auth.cookie ? { cookie: auth.cookie } : {}), ...(auth.headers || {}), 'content-type': 'application/octet-stream', 'x-upload-token': i0.uploadtoken }, body: ct });
    expect(r.status).toBe(200);
  }
  const { body, fragment } = await encryptPaste({ text: JSON.stringify(manifest), fmt: 'files', bar: views !== null, views: views ?? undefined, expire: '1h' });
  const fin = await fetchJson(`/api/private/file/${i0.id}/finalize`, { method: 'POST', ...auth, headers: { ...(auth.headers || {}), 'x-upload-token': i0.uploadtoken }, body: { paste: body } });
  expect(fin.status).toBe(200);
  const f = await fin.json();
  return { res: init, id: i0.id, fragment, adata: body.adata, captcha: i0.captcha, finCaptcha: f.captcha, password: '' };
}

/** A Drive share of one Drive file. */
async function driveShare(cookie, { views = null, captcha } = {}) {
  const file = await uploadFile(cookie, 'root', 40);
  const manifest = { v: 3, kind: 'refs', entries: [{ path: 'd.bin', size: 40, type: 'application/octet-stream', mtime: 0, ref: 0, fk: b64urlFromBytes(randomBytes(32)) }], dirs: [] };
  const { body, fragment } = await encryptPaste({ text: JSON.stringify(manifest), fmt: 'files', bar: views !== null, views: views ?? undefined, expire: '1h' });
  const res = await fetchJson('/api/private/drive/shares', { method: 'POST', cookie, body: { nodes: [file.id], views, expire: '1h', paste: body, ...(captcha === undefined ? {} : { captcha }) } });
  return { res, fragment, adata: body.adata, password: '', ...(res.status === 201 ? await res.clone().json() : {}) };
}

const kindOf = (id) => (id[0] === 'f' ? 'file' : 'paste');
/** A CAPTCHA grant for share `id` from network `ip` (the check page's call). */
async function grantFor(id, ip) {
  const r = await ts(`/api/${kindOf(id)}/${id}/human`, { method: 'POST', ip, headers: { ...intent, 'x-secbin-turnstile': token('share-open') } });
  expect(r.status).toBe(200);
  return (await r.json()).grant;
}
const hh = (grant) => (grant ? { 'x-secbin-human': grant } : {});
async function head(s, ip, grant) { return ts(`/api/${kindOf(s.id)}/${s.id}`, { ip, headers: hh(grant) }); }
async function openIt(s, ip, grant) {
  const { headers } = await proofHeaders(s.adata, s.fragment, s.password);
  return ts(`/api/${kindOf(s.id)}/${s.id}/open`, { method: 'POST', ip, headers: { ...headers, ...hh(grant) } });
}
async function expireIt(s, ip, grant) {
  const { headers } = await proofHeaders(s.adata, s.fragment, s.password);
  return ts(`/api/${kindOf(s.id)}/${s.id}/expire`, { method: 'POST', ip, headers: { ...headers, ...hh(grant) } });
}
const chunk = (s, dl, ip, grant) => ts(`/api/file/${s.id}/chunk/${s.drive ? '0/0' : '0'}`, { ip, headers: { 'x-download-grant': dl, ...hh(grant) } });

async function apiKeyFor(u) {
  expect((await limits(u.id, { apiEnabled: true })).status).toBe(200);
  const r = await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { current: proofFor(USER_PW), name: 'k', scopes: ['notes', 'files', 'read'] } });
  expect(r.status).toBe(201);
  return (await r.json()).key;
}

// ── the role options ───────────────────────────────────────────────────────
describe('role options', () => {
  it('resolve for the owner (locked: allow), the Default role (holds values), a custom role (inherits) and the public account (none)', async () => {
    expect(SCHEMA_VERSION).toBe(15);
    const rows = await runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec("SELECT key, value FROM limits WHERE user_id = '' AND channel = 'all' AND key LIKE '%Captcha%' ORDER BY key").toArray());
    expect(rows).toEqual([
      { key: 'reverseCaptcha', value: '"require"' }, { key: 'reverseCaptchaDefault', value: '"on"' },
      { key: 'shareCaptcha', value: '"allow"' }, { key: 'shareCaptchaDefault', value: '"off"' },
    ]);
    const o = await me(oc);
    expect(o.limits).toMatchObject({ shareCaptcha: 'allow', shareCaptchaDefault: 'off', reverseCaptcha: 'allow', reverseCaptchaDefault: 'on' });
    const u = await makeUser('cap-roles');
    expect((await me(u.cookie)).limits).toMatchObject({ shareCaptcha: 'allow', shareCaptchaDefault: 'off', reverseCaptcha: 'require', reverseCaptchaDefault: 'on' });
    // A custom role sets one option; the rest follow Default, live.
    expect((await limits(u.id, { shareCaptcha: 'require' })).status).toBe(200);
    expect((await me(u.cookie)).limits).toMatchObject({ shareCaptcha: 'require', shareCaptchaDefault: 'off', reverseCaptcha: 'require' });
    expect((await limits('global', { shareCaptchaDefault: 'on' })).status).toBe(200);
    expect((await me(u.cookie)).limits.shareCaptchaDefault).toBe('on');
    expect((await limits(u.id, { shareCaptcha: 'inherit' })).status).toBe(200);
    expect((await me(u.cookie)).limits.shareCaptcha).toBe('allow');
    expect((await limits('global', { shareCaptchaDefault: 'off' })).status).toBe(200);
    // Values are checked; the owner's role cannot be changed (it has no rows); the public account has none.
    for (const bad of [{ shareCaptcha: 'maybe' }, { reverseCaptchaDefault: true }, { shareCaptcha: null }]) expect((await limits(u.id, bad)).status).toBe(400);
    expect((await limits(PUBLIC_ID, { shareCaptcha: 'require' })).status).toBe(400);
    const pub = await (await fetchJson(`/api/private/admin/users/${PUBLIC_ID}`, { cookie: oc })).json();
    expect(pub.effective.all).toMatchObject({ shareCaptcha: 'off', reverseCaptcha: 'off' });
    // captchaActive: whether the server enforces it (Turnstile keys).
    expect((await me(u.cookie)).captchaActive).toBe(false);
    expect((await (await ts('/api/private/me', { cookie: u.cookie })).json()).captchaActive).toBe(true);
  });
});

// ── creation: the server applies the role ─────────────────────────────────
describe('every create path applies the role (allow / require / off)', () => {
  let u;
  let key;
  beforeAll(async () => {
    u = await makeUser('cap-create');
    await enableDrive(u.id, { reverseEnabled: true });
    key = await apiKeyFor(u);
  });
  const paths = () => ({
    'note (session)': (c) => note({ cookie: u.cookie }, { captcha: c }),
    'burn note (session)': (c) => note({ cookie: u.cookie }, { views: 2, captcha: c }),
    'note (API key)': (c) => note({ headers: bearer(key) }, { captcha: c }),
    'file share (session)': (c) => fileShare({ cookie: u.cookie }, { captcha: c }),
    'file share (API key)': (c) => fileShare({ headers: bearer(key) }, { captcha: c }),
    'Drive share': (c) => driveShare(u.cookie, { captcha: c }),
  });
  const flagOf = async (s) => {
    const row = (await (await fetchJson(`/api/private/shares/${s.id}`, { cookie: u.cookie })).json()).share;
    // The stored record decides what is served: with Turnstile on, no grant → refused.
    const h = await head(s, freshIp());
    expect(row.captcha).toBe(h.status === 403);
    if (h.status === 403) expect(await errorOf(h)).toBe('captcha_required');
    return row.captcha;
  };

  it('allow: the request decides, else the role\'s default', async () => {
    await driveLimits(u.id, { shareCaptcha: 'allow', shareCaptchaDefault: 'off' });
    for (const [name, make] of Object.entries(paths())) {
      const on = await make(true);
      expect(on.res.status, name).toBe(201);
      expect(on.captcha ?? on.finCaptcha, name).toBe(true);
      expect(await flagOf(on), name).toBe(true);
      expect(await flagOf(await make(false)), name).toBe(false);
      expect(await flagOf(await make(undefined)), name).toBe(false);
    }
    await driveLimits(u.id, { shareCaptchaDefault: 'on' });
    for (const [name, make] of Object.entries(paths())) expect(await flagOf(await make(undefined)), name).toBe(true);
  });

  it('require: always on, whatever is asked', async () => {
    await driveLimits(u.id, { shareCaptcha: 'require', shareCaptchaDefault: 'off' });
    for (const [name, make] of Object.entries(paths())) {
      for (const c of [false, undefined, true]) {
        const s = await make(c);
        expect(s.res.status, name).toBe(201);
        expect(await flagOf(s), name).toBe(true);
      }
    }
  });

  it('off: never, and asking for it is refused (the sender is never misled)', async () => {
    await driveLimits(u.id, { shareCaptcha: 'off', shareCaptchaDefault: 'on' });
    for (const [name, make] of Object.entries(paths())) {
      const s = await make(true);
      expect(s.res.status, name).toBe(403);
      expect(await errorOf(s.res), name).toBe('captcha_disabled');
      expect(await flagOf(await make(undefined)), name).toBe(false);
      expect(await flagOf(await make(false)), name).toBe(false);
    }
    // Not a boolean: refused.
    await driveLimits(u.id, { shareCaptcha: 'allow' });
    for (const [name, make] of Object.entries(paths())) expect((await make('yes')).res.status, name).toBe(400);
  });

  it('reverse shares: the same, with their own options', async () => {
    const r = await receiver('cap-create-rev');
    const flag = async (id) => (await (await fetchJson('/api/private/drive/reverse', { cookie: r.cookie })).json()).reverse.find((x) => x.id === id).captcha;
    // The Default role requires it (every link had it before these options).
    let x = await newReverse(r.cookie, { captcha: false });
    expect(x.res.status).toBe(201);
    expect((await x.res.json()).captcha).toBe(true);
    expect(await flag(x.id)).toBe(true);
    await driveLimits(r.id, { reverseCaptcha: 'allow', reverseCaptchaDefault: 'off' });
    x = await newReverse(r.cookie);
    expect(await flag(x.id)).toBe(false);
    x = await newReverse(r.cookie, { captcha: true });
    expect(await flag(x.id)).toBe(true);
    const row = (await (await fetchJson(`/api/private/shares/${x.id}`, { cookie: r.cookie })).json()).share;
    expect(row).toMatchObject({ kind: 'reverse', captcha: true });
    await driveLimits(r.id, { reverseCaptcha: 'off' });
    x = await newReverse(r.cookie, { captcha: true });
    expect(x.res.status).toBe(403);
    expect(await errorOf(x.res)).toBe('captcha_disabled');
    // The refused claim released its id: nothing was created.
    expect((await (await fetchJson('/api/private/drive/reverse', { cookie: r.cookie })).json()).reverse.some((y) => y.id === x.id)).toBe(false);
    x = await newReverse(r.cookie);
    expect(await flag(x.id)).toBe(false);
  });

  it('the owner chooses per share (off by default for shares, on for reverse shares); the public account never has one', async () => {
    const n = await note({ cookie: oc });
    expect(n.captcha).toBe(false);
    expect((await note({ cookie: oc }, { captcha: true })).captcha).toBe(true);
    // Anonymous sharing (the public account): asking for it is refused.
    expect((await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'public.enabled': true, 'public.tracking': 'ip' } })).status).toBe(200);
    try {
      const { body } = await encryptPaste({ text: 'anon', bar: true, views: 1, expire: '1h' });
      const ok = await fetchJson('/api/public/paste', { method: 'POST', body: { paste: body }, headers: { 'sec-fetch-site': 'same-origin' }, ip: freshIp() });
      expect(ok.status).toBe(201);
      expect((await ok.json()).captcha).toBe(false);
      const refused = await fetchJson('/api/public/paste', { method: 'POST', body: { paste: body, captcha: true }, headers: { 'sec-fetch-site': 'same-origin' }, ip: freshIp() });
      expect(refused.status).toBe(403);
      expect(await errorOf(refused)).toBe('captcha_disabled');
    } finally {
      await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'public.enabled': false, 'public.tracking': 'tracker' } });
    }
  });
});

// ── enforcement on every content route ─────────────────────────────────────
describe('a protected share serves nothing without a grant', () => {
  let u;
  beforeAll(async () => {
    u = await makeUser('cap-enforce');
    await enableDrive(u.id);
    await driveLimits(u.id, { shareCaptcha: 'allow' });
  });
  const make = async (kind, captcha = true) => {
    if (kind === 'kv') return note({ cookie: u.cookie }, { captcha });
    if (kind === 'burn') return note({ cookie: u.cookie }, { views: 5, captcha });
    if (kind === 'file') return fileShare({ cookie: u.cookie }, { views: 5, captcha });
    return { ...(await driveShare(u.cookie, { views: 5, captcha })), drive: true };
  };

  it('covers every share-content route of src/routes/public.js (fails when a new one is added without the check)', () => {
    // The routes /api/(paste|file)/<id>[/<action>]: the head (no action), and
    // each action below, are swept in the next test; "human" is the check
    // itself; DELETE (the sender's delete token) is not a recipient's route.
    // A new action there fails this until the sweep covers it.
    const line = publicRoutesSource.split('\n').find((l) => l.includes('/^\\/api\\/(paste|file)\\/'));
    expect(line).toBeTruthy();
    expect(/\(\?:\\\/\(([a-z|]+)\)/.exec(line)[1].split('|').sort()).toEqual(['chunk', 'expire', 'human', 'open']);
  });

  it('head, open, "delete now" and chunks: 403 captcha_required on every kind (KV note, burn note, file share, Drive share); with a grant they work', async () => {
    for (const kind of ['kv', 'burn', 'file', 'drive']) {
      const s = await make(kind);
      expect(s.res.status, kind).toBe(201);
      const ip = freshIp();
      for (const res of [await head(s, ip), await openIt(s, ip), await expireIt(s, ip)]) {
        expect([res.status, await errorOf(res)], kind).toEqual([403, 'captcha_required']);
        expect((await res.clone().json()).message).toBe(MSG);
      }
      const grant = await grantFor(s.id, ip);
      expect((await head(s, ip, grant)).status, kind).toBe(200);
      const o = await openIt(s, ip, grant);
      expect(o.status, kind).toBe(200);
      if (kind === 'file' || kind === 'drive') {
        const dl = (await o.json()).grant;
        // A download grant alone is not enough: the chunk needs the CAPTCHA grant too.
        const c0 = await chunk(s, dl, ip);
        expect([c0.status, await errorOf(c0)], kind).toEqual([403, 'captcha_required']);
        const c1 = await chunk(s, dl, ip, grant);
        expect(c1.status, kind).toBe(200);
        await c1.arrayBuffer();
      }
    }
  });

  it('"delete now" with a grant works; without one not even the lock or the permission is told', async () => {
    await driveLimits(u.id, { openerDelete: true });
    const { body, fragment } = await encryptPaste({ text: 'x', bar: true, views: 3, expire: '1h', deletable: true });
    const res = await fetchJson('/api/private/paste', { method: 'POST', cookie: u.cookie, body: { paste: body, captcha: true } });
    expect(res.status).toBe(201);
    const s = { ...(await res.json()), fragment, adata: body.adata, password: '' };
    const ip = freshIp();
    expect(await errorOf(await expireIt(s, ip))).toBe('captcha_required');
    const lock = (locked) => fetchJson(`/api/private/admin/shares/${s.id}/lock`, { method: 'POST', cookie: oc, body: { locked } });
    expect((await lock(true)).status).toBe(200);
    expect(await errorOf(await expireIt(s, ip))).toBe('captcha_required');
    const g = await grantFor(s.id, ip);
    expect((await expireIt(s, ip, g)).status).toBe(423);
    expect((await lock(false)).status).toBe(200);
    expect((await expireIt(s, ip, g)).status).toBe(200);
    expect((await head(s, ip, g)).status).toBe(410);
  });

  it('an unprotected share needs nothing; with no Turnstile keys a protected one opens without a grant (inactive, never locked)', async () => {
    for (const kind of ['kv', 'burn', 'file', 'drive']) {
      const plain = await make(kind, false);
      const ip = freshIp();
      expect((await head(plain, ip)).status, kind).toBe(200);
      expect((await openIt(plain, ip)).status, kind).toBe(200);
      const prot = await make(kind, true);
      expect((await fetchJson(`/api/${kindOf(prot.id)}/${prot.id}`, { ip })).status, kind).toBe(200);
      // …and the grant route has nothing to give then.
      expect(await (await fetchJson(`/api/${kindOf(prot.id)}/${prot.id}/human`, { method: 'POST', headers: intent, ip })).json()).toEqual({ grant: null, expires: null });
    }
  });

  it('refusals are not counted as invalid fetches (existing limits stay): no block after many', async () => {
    const s = await make('kv');
    const ip = freshIp();
    for (let i = 0; i < 70; i++) expect((await head(s, ip)).status).toBe(403);
    expect((await head(s, ip, await grantFor(s.id, ip))).status).toBe(200);
    // A wrong key with a valid grant still counts (and a blocked network is refused before anything).
    const grant = await grantFor(s.id, ip);
    const { headers } = await proofHeaders(s.adata, b64urlFromBytes(randomBytes(32)));
    const bad = await ts(`/api/paste/${s.id}/open`, { method: 'POST', ip, headers: { ...headers, ...hh(grant) } });
    expect(await errorOf(bad)).toBe('bad_link');
  });

  it('the API and the CLI cannot pass it: a clear 403 captcha_required', async () => {
    const s = await make('burn');
    const r = await ts(`/api/paste/${s.id}`, { headers: { 'user-agent': 'secbin-cli' } });
    expect(r.status).toBe(403);
    expect(await r.json()).toEqual({ error: 'captcha_required', message: MSG });
  });
});

// ── the grant ──────────────────────────────────────────────────────────────
describe('the grant', () => {
  let u;
  beforeAll(async () => { u = await makeUser('cap-grant'); await driveLimits(u.id, { shareCaptcha: 'require' }); });

  it('needs a Turnstile token for "share-open" (and the intent header); it is bound to its share and network, and to its kind', async () => {
    const a = await note({ cookie: u.cookie });
    const b = await note({ cookie: u.cookie });
    const ip = freshIp();
    const post = (id, headers) => ts(`/api/paste/${id}/human`, { method: 'POST', ip, headers });
    expect((await post(a.id, { 'x-secbin-turnstile': token('share-open') })).status).toBe(400); // no intent
    expect(await errorOf(await post(a.id, intent))).toBe('turnstile_required');
    expect(await errorOf(await post(a.id, { ...intent, 'x-secbin-turnstile': token('login') }))).toBe('turnstile_failed');
    expect(await errorOf(await post(a.id, { ...intent, 'x-secbin-turnstile': 'nope' }))).toBe('turnstile_failed');
    const g = await grantFor(a.id, ip);
    expect(g).toMatch(/^h1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/);
    expect((await head(a, ip, g)).status).toBe(200);
    expect((await head(b, ip, g)).status).toBe(403); // another share
    expect((await head(a, freshIp(), g)).status).toBe(403); // another network
    // Tampered, truncated or forged: refused.
    const [v, body, mac] = g.split('.');
    const claims = JSON.parse(fromUtf8(bytesFromB64url(body)));
    const forged = `${v}.${b64urlFromBytes(utf8(JSON.stringify({ ...claims, id: b.id })))}.${mac}`;
    for (const x of [forged, `${v}.${body}`, `${g}x`, 'h1.e30.' + 'A'.repeat(43)]) expect((await head(b, ip, x)).status).toBe(403);
    // A reverse grant is not a share grant.
    const r = await receiver('cap-grant-rev');
    const link = await newReverse(r.cookie);
    const rg = (await (await ts(`/api/reverse/${link.id}/human`, { method: 'POST', ip, headers: { ...intent, 'x-secbin-turnstile': token('reverse-upload') } })).json()).grant;
    expect((await head(a, ip, rg)).status).toBe(403);
  });

  it(`lasts ${SHARE_GRANT_SEC / 60} minutes, slides while used (and with the keep-alive), and never past ${SHARE_GRANT_CAP_SEC / 3600} hours`, async () => {
    const s = await note({ cookie: u.cookie }, { expire: '7d' });
    const ip = freshIp();
    const t0 = Date.now();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(t0);
    let g = await grantFor(s.id, ip);
    vi.setSystemTime(t0 + (SHARE_GRANT_SEC + 1) * 1000);
    expect((await head(s, ip, g)).status).toBe(403); // lapsed
    vi.setSystemTime(t0);
    g = await grantFor(s.id, ip);
    // Used after 5 minutes: renewed (the response carries the new grant).
    vi.setSystemTime(t0 + 300 * 1000);
    const used = await head(s, ip, g);
    expect(used.status).toBe(200);
    const renewed = used.headers.get('x-secbin-human');
    expect(renewed).toMatch(/^h1\./);
    vi.setSystemTime(t0 + (SHARE_GRANT_SEC + 60) * 1000);
    expect((await head(s, ip, g)).status).toBe(403); // the old one lapsed
    expect((await head(s, ip, renewed)).status).toBe(200); // the renewed one still works
    // The keep-alive renews without a token; an invalid grant there is refused.
    let cur = renewed;
    for (let t = SHARE_GRANT_SEC + 60; t < SHARE_GRANT_CAP_SEC; t += 500) {
      vi.setSystemTime(t0 + t * 1000);
      const k = await ts(`/api/paste/${s.id}/human`, { method: 'POST', ip, headers: { ...intent, ...hh(cur) } });
      expect(k.status).toBe(200);
      cur = (await k.json()).grant;
    }
    vi.setSystemTime(t0 + (SHARE_GRANT_CAP_SEC + 1) * 1000);
    expect((await head(s, ip, cur)).status).toBe(403); // capped
    const k = await ts(`/api/paste/${s.id}/human`, { method: 'POST', ip, headers: { ...intent, ...hh(cur) } });
    expect(await errorOf(k)).toBe('captcha_required');
  });
});

// ── views ──────────────────────────────────────────────────────────────────
describe('views are spent only by the open that follows the check', () => {
  it('neither the check nor a refused request spends a view', async () => {
    const u = await makeUser('cap-views');
    await driveLimits(u.id, { shareCaptcha: 'require' });
    for (const s of [await note({ cookie: u.cookie }, { views: 2 }), await fileShare({ cookie: u.cookie }, { views: 2 })]) {
      const ip = freshIp();
      for (let i = 0; i < 3; i++) expect((await openIt(s, ip)).status).toBe(403);
      const g = await grantFor(s.id, ip);
      await grantFor(s.id, ip); // a second check: still nothing spent
      expect((await (await head(s, ip, g)).json()).meta).toMatchObject({ views: 2, left: 2 });
      const o = await (await openIt(s, ip, g)).json();
      expect((o.paste || o).meta.left).toBe(1);
      expect((await (await head(s, ip, g)).json()).meta.left).toBe(1);
    }
  });
});

// ── reverse shares ─────────────────────────────────────────────────────────
describe('reverse shares: the uploader\'s session start', () => {
  let r;
  beforeAll(async () => { r = await receiver('cap-rev'); await driveLimits(r.id, { reverseCaptcha: 'allow' }); });
  const beginWith = async (link, ip, { grant, password, turnstile } = {}) => {
    const headers = { ...intent, 'x-link-proof': await linkProof(link.pub) };
    if (password) {
      const head = await (await ts(`/api/reverse/${link.id}/open`, { method: 'POST', ip, headers })).json();
      headers['x-key-proof'] = await passwordProof(password, head.password.salt, head.password.t, link.pub);
    }
    if (grant) headers['x-secbin-human'] = grant;
    if (turnstile) headers['x-secbin-turnstile'] = turnstile;
    return ts(`/api/reverse/${link.id}/begin`, { method: 'POST', ip, headers });
  };
  const rgrant = async (link, ip) => {
    const res = await ts(`/api/reverse/${link.id}/human`, { method: 'POST', ip, headers: { ...intent, 'x-secbin-turnstile': token('reverse-upload') } });
    expect(res.status).toBe(200);
    return (await res.json()).grant;
  };

  it('with the flag: a grant per session start, checked before the password; a wrong password spends it', async () => {
    const link = await newReverse(r.cookie, { captcha: true, password: 'open sesame' });
    const ip = freshIp();
    const head = await (await ts(`/api/reverse/${link.id}/open`, { method: 'POST', ip, headers: { ...intent, 'x-link-proof': await linkProof(link.pub) } })).json();
    expect(head.captcha).toBe(true);
    // No grant: refused before the password is looked at (no wrong-password count).
    for (const pw of ['wrong', 'open sesame']) {
      const res = await beginWith(link, ip, { password: pw });
      expect([res.status, await errorOf(res)]).toEqual([403, 'captcha_required']);
    }
    const pwfails = async () => runInDurableObject(driveOf(r.id), (inst, state) => state.storage.sql.exec('SELECT pwfails FROM reverse WHERE id = ?', link.id).one().pwfails);
    expect(await pwfails()).toBe(0);
    // The grant route: a token for "reverse-upload" only.
    const bad = await ts(`/api/reverse/${link.id}/human`, { method: 'POST', ip, headers: { ...intent, 'x-secbin-turnstile': token('share-open') } });
    expect(await errorOf(bad)).toBe('turnstile_failed');
    // A wrong password spends the grant: the next guess needs another CAPTCHA.
    let g = await rgrant(link, ip);
    expect(await errorOf(await beginWith(link, ip, { grant: g, password: 'wrong' }))).toBe('bad_password');
    expect(await pwfails()).toBe(1);
    expect(await errorOf(await beginWith(link, ip, { grant: g, password: 'open sesame' }))).toBe('captcha_required');
    g = await rgrant(link, ip);
    expect(await errorOf(await beginWith(link, freshIp(), { grant: g, password: 'open sesame' }))).toBe('captcha_required'); // another network
    const ok = await beginWith(link, ip, { grant: g, password: 'open sesame' });
    expect(ok.status).toBe(200);
    expect(typeof (await ok.json()).grant).toBe('string');
    // Used once: a second session needs a second CAPTCHA.
    expect(await errorOf(await beginWith(link, ip, { grant: g, password: 'open sesame' }))).toBe('captcha_required');
    // A share grant is not a reverse grant; a Turnstile token still works as before.
    const n = await note({ cookie: oc }, { captcha: true });
    expect(await errorOf(await beginWith(link, ip, { grant: await grantFor(n.id, ip), password: 'open sesame' }))).toBe('captcha_required');
    expect((await beginWith(link, ip, { turnstile: token('reverse-upload'), password: 'open sesame' })).status).toBe(200);
  });

  it('without the flag: no check at all; with no Turnstile keys the flag is inactive', async () => {
    const plain = await newReverse(r.cookie, { captcha: false });
    const ip = freshIp();
    const head = await (await ts(`/api/reverse/${plain.id}/open`, { method: 'POST', ip, headers: { ...intent, 'x-link-proof': await linkProof(plain.pub) } })).json();
    expect(head.captcha).toBe(false);
    expect((await beginWith(plain, ip)).status).toBe(200);
    expect(await (await ts(`/api/reverse/${plain.id}/human`, { method: 'POST', ip, headers: { ...intent, 'x-secbin-turnstile': token('reverse-upload') } })).json()).toEqual({ grant: null, expires: null });
    const flagged = await newReverse(r.cookie, { captcha: true });
    const off = await fetchJson(`/api/reverse/${flagged.id}/open`, { method: 'POST', ip, headers: { ...intent, 'x-link-proof': await linkProof(flagged.pub) } });
    expect((await off.json()).captcha).toBe(false);
    expect((await fetchJson(`/api/reverse/${flagged.id}/begin`, { method: 'POST', ip, headers: { ...intent, 'x-link-proof': await linkProof(flagged.pub) } })).status).toBe(200);
  });
});

// ── the pages ──────────────────────────────────────────────────────────────
describe('the pages: strict where the key is, the Turnstile CSP only on the check page', () => {
  const nav = { 'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate', 'sec-fetch-site': 'none' };
  const keyOf = (html) => /<meta name="secbin-page-key" content="([A-Za-z0-9_-]{22})\.([A-Za-z0-9_-]{43})">/.exec(html);

  it('/p/<id> and /r/<id>: always the strict CSP; a page key only on a real navigation, the same for the same nonce', async () => {
    const u = await makeUser('cap-pages');
    await driveLimits(u.id, { shareCaptcha: 'require' });
    const s = await note({ cookie: u.cookie });
    const r = await receiver('cap-pages-rev');
    const link = await newReverse(r.cookie); // Default role: required
    for (const path of [`/p/${s.id}`, `/r/${link.id}`]) {
      const page = await ts(path, { headers: nav });
      expect(page.status).toBe(200);
      expect(page.headers.get('content-security-policy')).toBe(CSP);
      expect(page.headers.get('cross-origin-embedder-policy')).toBe('require-corp');
      expect(page.headers.get('cache-control')).toBe('no-store');
      const html = await page.text();
      expect(html).not.toContain('challenges.cloudflare.com');
      const k = keyOf(html);
      expect(k).not.toBeNull();
      // Back from the check page (?n=…): the page key for that nonce again.
      const again = keyOf(await (await ts(`${path}?n=${k[1]}`, { headers: nav })).text());
      expect(again.slice(1)).toEqual(k.slice(1));
      expect(keyOf(await (await ts(path, { headers: nav })).text())[1]).not.toBe(k[1]); // a new nonce otherwise
      // fetch() (what a script could do) gets no page key.
      for (const h of [{}, { 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors' }, { 'sec-fetch-dest': 'document', 'sec-fetch-mode': 'cors' }, { 'sec-fetch-dest': 'iframe', 'sec-fetch-mode': 'navigate' }]) {
        expect(keyOf(await (await ts(`${path}?n=${k[1]}`, { headers: h })).text())).toBeNull();
      }
      // The check page: Turnstile's CSP (no COEP), its own script, no share code.
      const check = await ts(`${path}?check`, { headers: nav });
      expect(check.status).toBe(200);
      expect(check.headers.get('content-security-policy')).toBe(TURNSTILE_CSP);
      expect(check.headers.get('cross-origin-embedder-policy')).toBeNull();
      expect(check.headers.get('cache-control')).toBe('no-store');
      const ch = await check.text();
      expect(ch).toContain('/js/check.js');
      expect(ch).not.toMatch(/\/js\/(view|reverse)\.js/);
      expect(keyOf(ch)).toBeNull();
      // Without Turnstile keys: back to the page (no third-party script anywhere).
      const off = await SELF.fetch(`${ORIGIN}${path}?check`, { redirect: 'manual' });
      expect(off.status).toBe(302);
      expect(off.headers.get('location')).toBe(path);
    }
    // An unprotected share (or an unknown / malformed id) never gets the check page.
    const plain = await note({ cookie: oc });
    for (const path of [`/p/${plain.id}`, `/p/k${'A'.repeat(22)}`, '/p/nope']) {
      const res = await ts(`${path}?check`);
      expect([res.status, res.headers.get('location')]).toEqual([302, path]);
    }
    for (const p of ['/check', '/check/', '/check/index.html']) {
      const res = await ts(p);
      expect(res.status, p).toBe(404);
      expect(res.headers.get('content-security-policy')).toBe(CSP);
      await res.text();
    }
  });
});

// ── export / import ────────────────────────────────────────────────────────
describe('export / import', () => {
  it('the options travel in the roles part (the Default role and custom roles)', async () => {
    const u = await makeUser('cap-export');
    await driveLimits(u.id, { shareCaptcha: 'require', reverseCaptcha: 'off' });
    expect((await limits('global', { shareCaptchaDefault: 'on' })).status).toBe(200);
    const CURRENT = proofFor('owner-password');
    const doc = (await (await fetchJson('/api/private/admin/export', { method: 'POST', cookie: oc, body: { current: CURRENT, system: { roles: true } } })).json()).document;
    expect(doc.system.limits.all).toMatchObject({ shareCaptcha: 'allow', shareCaptchaDefault: 'on', reverseCaptcha: 'require', reverseCaptchaDefault: 'on' });
    const role = doc.system.roles.find((x) => x.name === `user ${u.id}`);
    expect(role.limits.all).toMatchObject({ shareCaptcha: 'require', reverseCaptcha: 'off' });
    // Changed on the server, then the import puts them back.
    await driveLimits(u.id, { shareCaptcha: 'off', reverseCaptcha: 'inherit' });
    expect((await limits('global', { shareCaptchaDefault: 'off' })).status).toBe(200);
    const imp = await fetchJson('/api/private/admin/import', { method: 'POST', cookie: oc, body: { current: CURRENT, document: doc, decisions: { system: true, users: {} }, dryRun: false } });
    expect(imp.status).toBe(200);
    expect((await me(u.cookie)).limits).toMatchObject({ shareCaptcha: 'require', shareCaptchaDefault: 'on', reverseCaptcha: 'off' });
    // An invalid value in a document is refused.
    doc.system.limits.all.shareCaptcha = 'sometimes';
    const bad = await fetchJson('/api/private/admin/import', { method: 'POST', cookie: oc, body: { current: CURRENT, document: doc, decisions: { system: true, users: {} }, dryRun: true } });
    expect(bad.status).toBe(400);
    expect((await limits('global', { shareCaptchaDefault: 'off' })).status).toBe(200);
  });
});
