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
import { CSP, TURNSTILE_CSP, API_CSP } from '../src/lib/http.js';
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
let siteverifyCalls = 0; // every call that reached Cloudflare's siteverify (the fake below)
beforeAll(async () => {
  oc = await owner();
  // Tokens "ok:<action>[#n]" pass for that action on this host, once each (as Cloudflare does).
  const seen = new Set();
  restoreSiteverify = setSiteverify(async (form) => {
    siteverifyCalls += 1;
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

  it('the extend route keeps the CAPTCHA: after a label, more views or a later expiry, every kind still refuses without a grant', async () => {
    for (const kind of ['kv', 'burn', 'file', 'drive']) {
      const s = await make(kind);
      expect(s.res.status, kind).toBe(201);
      const expires = Math.floor(Date.now() / 1000) + 2 * 3600;
      const patch = { label: `extended ${kind}`, expires, ...(kind === 'kv' ? {} : { views: 10 }) };
      const ext = await fetchJson(`/api/private/shares/${s.id}`, { method: 'PATCH', cookie: u.cookie, body: patch });
      expect(ext.status, kind).toBe(200);
      const row = (await (await fetchJson(`/api/private/shares/${s.id}`, { cookie: u.cookie })).json()).share;
      expect(row, kind).toMatchObject({ captcha: true, label: `extended ${kind}`, expires });
      const ip = freshIp();
      for (const res of [await head(s, ip), await openIt(s, ip), await expireIt(s, ip)]) {
        expect([res.status, await errorOf(res)], kind).toEqual([403, 'captcha_required']);
      }
      const grant = await grantFor(s.id, ip);
      const h = await (await head(s, ip, grant)).json();
      expect(h.meta.expires, kind).toBe(expires);
      if (kind !== 'kv') expect(h.meta.left, kind).toBe(10);
      expect((await openIt(s, ip, grant)).status, kind).toBe(200);
    }
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

  it('the extend route keeps a link\'s CAPTCHA: after a later expiry, a session start still needs a grant', async () => {
    const link = await newReverse(r.cookie, { captcha: true, expire: '1h' });
    const expires = Math.floor(Date.now() / 1000) + 3 * 3600;
    expect((await fetchJson(`/api/private/shares/${link.id}`, { method: 'PATCH', cookie: r.cookie, body: { expires, label: 'extended link' } })).status).toBe(200);
    expect((await (await fetchJson(`/api/private/shares/${link.id}`, { cookie: r.cookie })).json()).share).toMatchObject({ captcha: true, expires });
    const ip = freshIp();
    const head = await (await ts(`/api/reverse/${link.id}/open`, { method: 'POST', ip, headers: { ...intent, 'x-link-proof': await linkProof(link.pub) } })).json();
    expect(head).toMatchObject({ captcha: true, expires });
    expect(await errorOf(await beginWith(link, ip))).toBe('captcha_required');
    expect((await beginWith(link, ip, { grant: await rgrant(link, ip) })).status).toBe(200);
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

// ── F2: the grant routes are metered ───────────────────────────────────────
describe('the CAPTCHA checks are metered per network (F2)', () => {
  const invalidCount = async (ip) => {
    const g = await (await fetchJson('/api/private/admin/guard', { cookie: oc })).json();
    return g.tracking.find((t) => t.scope === 'invalid' && t.key === `${ip}/32`)?.count ?? 0;
  };
  const human = (path, ip, headers) => ts(path, { method: 'POST', ip, headers: { ...intent, ...headers } });

  it('a missing or failed token counts as an invalid request (share and reverse grant routes)', async () => {
    const u = await makeUser('cap-f2');
    await driveLimits(u.id, { shareCaptcha: 'require' });
    const s = await note({ cookie: u.cookie });
    const r = await receiver('cap-f2-rev');
    const link = await newReverse(r.cookie, { captcha: true });
    for (const path of [`/api/paste/${s.id}/human`, `/api/reverse/${link.id}/human`]) {
      const ip = freshIp();
      expect(await invalidCount(ip)).toBe(0);
      expect(await errorOf(await human(path, ip, { 'x-secbin-turnstile': 'nope' }))).toBe('turnstile_failed');
      expect(await errorOf(await human(path, ip, {}))).toBe('turnstile_required');
      expect(await errorOf(await human(path, ip, { 'x-secbin-turnstile': token('login') }))).toBe('turnstile_failed');
      expect(await invalidCount(ip)).toBe(3);
      // A good token is not counted.
      expect((await human(path, ip, { 'x-secbin-turnstile': token(path.includes('reverse') ? 'reverse-upload' : 'share-open') })).status).toBe(200);
      expect(await invalidCount(ip)).toBe(3);
    }
    // The reverse session start's own token path is counted the same way.
    const ip = freshIp();
    const res = await ts(`/api/reverse/${link.id}/begin`, { method: 'POST', ip, headers: { ...intent, 'x-link-proof': await linkProof(link.pub), 'x-secbin-turnstile': 'nope' } });
    expect(await errorOf(res)).toBe('turnstile_failed');
    expect(await invalidCount(ip)).toBe(1);
  });

  it(`at most 30 checks per network and window reach siteverify; then 429 rate_limited before any call to Cloudflare (renewals are not limited)`, async () => {
    const id = `k${b64urlFromBytes(randomBytes(16))}`; // no share needed: the route looks nothing up
    const ip = freshIp();
    let grant;
    for (let i = 0; i < 30; i++) {
      const res = await human(`/api/paste/${id}/human`, ip, { 'x-secbin-turnstile': token('share-open') });
      expect(res.status, `call ${i + 1}`).toBe(200);
      grant = (await res.json()).grant;
    }
    const before = siteverifyCalls;
    for (const path of [`/api/paste/${id}/human`, `/api/file/f${b64urlFromBytes(randomBytes(16))}/human`]) {
      const over = await human(path, ip, { 'x-secbin-turnstile': token('share-open') });
      expect([over.status, await errorOf(over)]).toEqual([429, 'rate_limited']);
      expect(over.headers.get('retry-after')).toBe('600');
    }
    expect(siteverifyCalls).toBe(before); // refused before siteverify
    // The keep-alive (an HMAC check, no siteverify) still works; other networks are unaffected.
    const keep = await human(`/api/paste/${id}/human`, ip, { 'x-secbin-human': grant });
    expect(keep.status).toBe(200);
    expect((await human(`/api/paste/${id}/human`, freshIp(), { 'x-secbin-turnstile': token('share-open') })).status).toBe(200);
    // The owner can lift it like any Guard block.
    expect((await fetchJson('/api/private/admin/guard/unblock', { method: 'POST', cookie: oc, body: { scope: 'captcha-verify', key: `${ip}/32` } })).status).toBe(200);
    expect((await human(`/api/paste/${id}/human`, ip, { 'x-secbin-turnstile': token('share-open') })).status).toBe(200);
  });
});

// ── F4: nothing about an id before the check ───────────────────────────────
describe('a missing or ended share answers exactly as a protected one without a grant (F4)', () => {
  const MSG_BODY = { error: 'captcha_required', message: MSG };
  it('unknown ids of every kind, and ended shares: 403 captcha_required on head, open, "delete now" and chunks; with a grant the true answer', async () => {
    const u = await makeUser('cap-f4');
    await enableDrive(u.id);
    await driveLimits(u.id, { shareCaptcha: 'allow', openerDelete: true });
    const protectedNote = await note({ cookie: u.cookie }, { captcha: true });
    const ended = await note({ cookie: u.cookie }, { views: 1, captcha: false });
    const eip = freshIp();
    expect((await openIt(ended, eip)).status).toBe(200); // its only view: now ended
    const fakeFrag = b64urlFromBytes(randomBytes(32));
    const fake = (id) => ({ id, adata: protectedNote.adata, fragment: fakeFrag, password: '', drive: false });
    const cases = [
      fake(`k${b64urlFromBytes(randomBytes(16))}`),
      fake(`b${b64urlFromBytes(randomBytes(16))}`),
      fake(`f${b64urlFromBytes(randomBytes(16))}`),
      ended,
    ];
    const ref = async (fn) => { const r = await fn(); return [r.status, await r.json()]; };
    const ip = freshIp();
    const protectedHead = await ref(() => head(protectedNote, ip));
    expect(protectedHead).toEqual([403, MSG_BODY]);
    for (const s of cases) {
      const ip2 = freshIp();
      expect(await ref(() => head(s, ip2)), s.id).toEqual(protectedHead);
      expect(await ref(() => openIt(s, ip2)), s.id).toEqual(protectedHead);
      expect(await ref(() => expireIt(s, ip2)), s.id).toEqual(protectedHead);
      if (s.id[0] === 'f') expect(await ref(() => chunk(s, 'G'.repeat(43), ip2)), s.id).toEqual(protectedHead);
      // With a grant (after the check): the real answer.
      const g = await grantFor(s.id, ip2);
      expect([404, 410]).toContain((await head(s, ip2, g)).status);
    }
    // An unprotected live share still needs nothing (it is open by design).
    const plain = await note({ cookie: u.cookie }, { captcha: false });
    expect((await head(plain, freshIp())).status).toBe(200);
  });

  it('unknown ids are still counted as invalid requests (the Guard sees guessing as before)', async () => {
    const ip = freshIp();
    const invalid = async () => (await (await fetchJson('/api/private/admin/guard', { cookie: oc })).json()).tracking.find((t) => t.scope === 'invalid' && t.key === `${ip}/32`)?.count ?? 0;
    for (let i = 0; i < 3; i++) {
      const res = await ts(`/api/paste/k${b64urlFromBytes(randomBytes(16))}`, { ip });
      expect(await errorOf(res)).toBe('captcha_required');
    }
    expect(await invalid()).toBe(3);
  });
});

// ── the pages ──────────────────────────────────────────────────────────────
describe('the pages: strict where the key is, the Turnstile CSP only on the check page', () => {
  const nav = { 'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate', 'sec-fetch-site': 'none' };
  const back = { ...nav, 'sec-fetch-site': 'same-origin' }; // the check page's return navigation
  /**
   * The page key in a page → [content, n, key], or null when the page has none (an empty or no
   * "secbin-page-key" meta). The HTML is parsed (the runtime's HTMLRewriter), the attribute read as a value.
   */
  const keyOf = async (html) => {
    let content = null;
    await new globalThis.HTMLRewriter().on('meta[name="secbin-page-key"]', { element(el) { content = el.getAttribute('content'); } })
      .transform(new Response(html)).text();
    if (!content) return null;
    const [n, key, extra] = content.split('.');
    expect([n.length, key && key.length, extra]).toEqual([22, 43, undefined]); // a nonce of 16 and a key of 32 random bytes
    return [content, n, key];
  };
  /** The response's Set-Cookie headers, one string each (a response may clear several). */
  const setCookies = (res) => (typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : (res.headers.get('set-cookie') ? [res.headers.get('set-cookie')] : []));
  const cookieOf = (res) => { const all = setCookies(res); return all.length ? all[0] : null; };
  /** A Set-Cookie header parsed (never matched as a pattern): { name, value, attrs } with lower-case attribute names. */
  const parseSetCookie = (header) => {
    const [pair, ...rest] = String(header).split(';').map((x) => x.trim());
    const i = pair.indexOf('=');
    const attrs = {};
    for (const a of rest) {
      const j = a.indexOf('=');
      attrs[(j < 0 ? a : a.slice(0, j)).toLowerCase()] = j < 0 ? true : a.slice(j + 1);
    }
    return { name: pair.slice(0, i), value: pair.slice(i + 1), attrs };
  };
  const PREFIX = '__Secure-secbin_pk_';
  /** A page key cookie for `path`: named by its nonce, exactly these attributes (Max-Age 900 when set, 0 when cleared) → { n, value }. */
  const expectPageKeyCookie = (header, path, maxAge) => {
    const c = parseSetCookie(header);
    expect(c.name.startsWith(PREFIX)).toBe(true);
    expect(c.attrs).toEqual({ path, httponly: true, secure: true, samesite: 'Strict', 'max-age': String(maxAge) });
    return { n: c.name.slice(PREFIX.length), value: c.value };
  };
  /** A cookie jar for one path: applies a response's Set-Cookie headers → the Cookie header to send next. */
  const jar = () => {
    const m = new Map();
    return {
      apply(res) { for (const h of setCookies(res)) { const c = parseSetCookie(h); if (c.attrs['max-age'] === '0') m.delete(c.name); else m.set(c.name, c.value); } },
      header() { return [...m].map(([k, v]) => `${k}=${v}`).join('; '); },
      names() { return [...m.keys()]; },
    };
  };
  let paths;
  beforeAll(async () => {
    const u = await makeUser('cap-pages');
    await driveLimits(u.id, { shareCaptcha: 'require' });
    const s = await note({ cookie: u.cookie });
    const r = await receiver('cap-pages-rev');
    const link = await newReverse(r.cookie); // Default role: required
    paths = [`/p/${s.id}`, `/r/${link.id}`];
  });

  it('/p/<id> and /r/<id>: the strict CSP, COOP same-origin, COEP, never framed; a random page key, in the page and in an HttpOnly cookie for its path', async () => {
    for (const path of paths) {
      const page = await ts(path, { headers: nav });
      expect(page.status).toBe(200);
      expect(page.headers.get('content-security-policy')).toBe(CSP);
      expect(CSP).toContain("frame-ancestors 'none'");
      expect(CSP).toContain("worker-src 'self'"); // the app's own service worker still registers from normal pages
      expect(page.headers.get('x-frame-options')).toBe('DENY');
      expect(page.headers.get('cross-origin-opener-policy')).toBe('same-origin');
      expect(page.headers.get('cross-origin-embedder-policy')).toBe('require-corp');
      expect(page.headers.get('cache-control')).toBe('no-store');
      const html = await page.text();
      expect(html).not.toContain('challenges.cloudflare.com');
      const k = await keyOf(html);
      expect(k).not.toBeNull();
      const c = expectPageKeyCookie(cookieOf(page), path, 900);
      // The same key, held by the browser under its own nonce's name (value: key.issued).
      expect(c.n).toBe(k[1]);
      expect(c.value.split('.')[0]).toBe(k[2]);
      expect(c.value.split('.')[1]).toMatch(/^\d+$/);
      // Random: another navigation, another nonce and key (never derived from the id or the nonce).
      const k2 = await keyOf(await (await ts(path, { headers: back })).text());
      expect(k2[1]).not.toBe(k[1]);
      expect(k2[2]).not.toBe(k[2]);
    }
  });

  it('PoC F1: the return (?n=) gives the key only to the browser holding its cookie — forged navigation headers without it get none', async () => {
    for (const path of paths) {
      const first = await ts(path, { headers: nav });
      const [, n, key] = await keyOf(await first.text());
      const cookie = cookieOf(first).split(';')[0];
      // An outside client (curl) sends the Fetch Metadata of a navigation, but has no cookie: no key, nothing set.
      for (const headers of [nav, back, { ...back, cookie: `${PREFIX}${n}=` }, { ...back, cookie: `${PREFIX}${n}=${'A'.repeat(43)}x.1` }, { ...back, cookie: `__Secure-secbin_pk=${n}.${key}` }]) {
        const res = await ts(`${path}?n=${n}`, { headers });
        expect(await keyOf(await res.text())).toBeNull();
        expect(cookieOf(res)).toBeNull();
      }
      // A cookie for another nonce (another round trip, another tab): no key.
      const other = await ts(path, { headers: nav });
      await other.text();
      const otherCookie = cookieOf(other).split(';')[0];
      const mismatch = await ts(`${path}?n=${n}`, { headers: { ...back, cookie: otherCookie } });
      expect(await keyOf(await mismatch.text())).toBeNull();
      // The browser's own return: the key, and the cookie cleared in the same response.
      const ok = await ts(`${path}?n=${n}`, { headers: { ...back, cookie } });
      expect((await keyOf(await ok.text())).slice(1)).toEqual([n, key]);
      expect(expectPageKeyCookie(cookieOf(ok), path, 0)).toEqual({ n, value: '' });
    }
  });

  it('PoC F1: fetch() from a page (even with the cookie), a cross-site navigation, a frame or a HEAD gets no key and sets no cookie', async () => {
    for (const path of paths) {
      const first = await ts(path, { headers: nav });
      const [, n] = await keyOf(await first.text());
      const cookie = cookieOf(first).split(';')[0];
      const tries = [
        { 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-origin', cookie },
        { 'sec-fetch-dest': 'empty', 'sec-fetch-mode': 'same-origin', 'sec-fetch-site': 'same-origin', cookie },
        { 'sec-fetch-dest': 'document', 'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-origin', cookie },
        { 'sec-fetch-dest': 'iframe', 'sec-fetch-mode': 'navigate', 'sec-fetch-site': 'same-origin', cookie },
        { 'sec-fetch-dest': 'embed', 'sec-fetch-mode': 'navigate', 'sec-fetch-site': 'same-origin', cookie },
        { ...nav, 'sec-fetch-site': 'cross-site', cookie },
        { ...nav, 'sec-fetch-site': 'same-site', cookie },
        { cookie },
      ];
      for (const headers of tries) {
        for (const q of [`?n=${n}`, '']) {
          const res = await ts(`${path}${q}`, { headers });
          expect(await keyOf(await res.text()), JSON.stringify(headers)).toBeNull();
          expect(cookieOf(res), JSON.stringify(headers)).toBeNull();
        }
      }
      const head = await ts(path, { method: 'HEAD', headers: nav });
      expect(cookieOf(head)).toBeNull();
      // None of those used the cookie up: the real return still works once.
      const ok = await ts(`${path}?n=${n}`, { headers: { ...back, cookie } });
      expect((await keyOf(await ok.text()))[1]).toBe(n);
    }
  });

  it('the page key is single use: after the return that cleared it, a replayed cookie is the only way back, and no key is issued on a return', async () => {
    for (const path of paths) {
      const first = await ts(path, { headers: nav });
      const [, n] = await keyOf(await first.text());
      const cookie = cookieOf(first).split(';')[0];
      const ok = await ts(`${path}?n=${n}`, { headers: { ...back, cookie } });
      expect((await keyOf(await ok.text()))[1]).toBe(n);
      // The browser now holds no cookie for the path: the same return again gets nothing, and mints nothing.
      const again = await ts(`${path}?n=${n}`, { headers: back });
      expect(await keyOf(await again.text())).toBeNull();
      expect(cookieOf(again)).toBeNull();
    }
  });

  it('N6: two tabs of one share each keep their own page key (one cookie per round trip); both returns work, once each', async () => {
    for (const path of paths) {
      const j = jar();
      const tab1 = await ts(path, { headers: nav });
      const [, n1, k1] = await keyOf(await tab1.text());
      j.apply(tab1);
      const tab2 = await ts(path, { headers: { ...nav, cookie: j.header() } }); // the second tab, while the first is at its check
      const [, n2, k2] = await keyOf(await tab2.text());
      j.apply(tab2);
      expect(j.names().sort()).toEqual([`${PREFIX}${n1}`, `${PREFIX}${n2}`].sort());
      const back1 = await ts(`${path}?n=${n1}`, { headers: { ...back, cookie: j.header() } });
      expect((await keyOf(await back1.text())).slice(1)).toEqual([n1, k1]);
      j.apply(back1);
      expect(j.names()).toEqual([`${PREFIX}${n2}`]); // only its own cookie went
      const back2 = await ts(`${path}?n=${n2}`, { headers: { ...back, cookie: j.header() } });
      expect((await keyOf(await back2.text())).slice(1)).toEqual([n2, k2]);
      j.apply(back2);
      expect(j.names()).toEqual([]);
    }
  });

  it('N6: at most 4 page key cookies per share path — a new one clears the oldest', async () => {
    const path = paths[0];
    const j = jar();
    const issued = [];
    vi.useFakeTimers({ toFake: ['Date'] });
    const t0 = Date.now();
    for (let i = 0; i < 7; i++) {
      vi.setSystemTime(t0 + i * 1000); // distinct issue times
      const res = await ts(path, { headers: { ...nav, cookie: j.header() } });
      issued.push((await keyOf(await res.text()))[1]);
      j.apply(res);
      expect(j.names().length).toBeLessThanOrEqual(4);
    }
    expect(j.names().sort()).toEqual(issued.slice(-4).map((n) => `${PREFIX}${n}`).sort()); // the newest four
  });

  it('the check page: the Turnstile CSP with worker-src \'none\', COOP same-origin-allow-popups, no COEP, never a key; for any well-formed id (it says nothing about the share)', async () => {
    const plain = await note({ cookie: oc });
    const unknown = `k${b64urlFromBytes(randomBytes(16))}`;
    for (const path of [...paths, `/p/${plain.id}`, `/p/${unknown}`]) {
      const check = await ts(`${path}?check`, { headers: nav, ip: freshIp() });
      expect(check.status, path).toBe(200);
      const csp = check.headers.get('content-security-policy');
      expect(csp).toBe(TURNSTILE_CSP.replace("worker-src 'self'", "worker-src 'none'"));
      expect(csp.split('; ')).toContain("worker-src 'none'");
      expect(csp.split('; ')).toContain("frame-ancestors 'none'");
      expect(check.headers.get('cross-origin-opener-policy')).toBe('same-origin-allow-popups');
      expect(check.headers.get('cross-origin-embedder-policy')).toBeNull();
      expect(check.headers.get('cache-control')).toBe('no-store');
      expect(cookieOf(check)).toBeNull();
      const ch = await check.text();
      expect(ch).toContain('/js/check.js');
      expect(ch).not.toMatch(/\/js\/(view|reverse|pwa)\.js/);
      expect(await keyOf(ch)).toBeNull();
    }
    // Login and Account keep their own Turnstile CSP (workers allowed there, as before).
    const login = await ts('/dashboard/login/', { headers: nav });
    await login.text();
    expect(login.headers.get('content-security-policy')).toBe(TURNSTILE_CSP);
    // Without Turnstile keys, or for a malformed id: back to the page (no third-party script anywhere).
    for (const path of paths) {
      const off = await SELF.fetch(`${ORIGIN}${path}?check`, { redirect: 'manual' });
      expect(off.status).toBe(302);
      expect(off.headers.get('location')).toBe(path);
    }
    const bad = await ts('/p/nope?check');
    expect([bad.status, bad.headers.get('location')]).toEqual([302, '/p/nope']);
    for (const p of ['/check', '/check/', '/check/index.html']) {
      const res = await ts(p);
      expect(res.status, p).toBe(404);
      expect(res.headers.get('content-security-policy')).toBe(API_CSP); // plain text: sandboxed, no script at all
      await res.text();
    }
  });

  it('F3: the check page is behind the Guard\'s block and a per-network rate limit (an unknown id is served the same: no share lookup)', async () => {
    const ip = freshIp();
    let status;
    for (let i = 0; i < 60; i++) {
      const res = await ts(`${paths[0]}?check`, { ip });
      await res.text();
      status = res.status;
      if (status !== 200) break;
    }
    expect(status).toBe(200); // 60 in the window are served
    const over = await ts(`${paths[0]}?check`, { ip });
    expect([over.status, over.headers.get('retry-after')]).toEqual([429, '600']);
    expect(over.headers.get('content-security-policy')).toBe(API_CSP); // no Turnstile script (no script at all) on the refusal
    expect(await over.text()).not.toContain('secbin-page-key');
    // Another network is not affected; the owner can lift the limit (a Guard scope like the others).
    expect((await ts(`${paths[1]}?check`, { ip: freshIp() })).status).toBe(200);
    expect((await fetchJson('/api/private/admin/guard/unblock', { method: 'POST', cookie: oc, body: { scope: 'captcha-page', key: `${ip}/32` } })).status).toBe(200);
    expect((await ts(`${paths[0]}?check`, { ip })).status).toBe(200);
    // A network blocked for invalid requests gets no check page at all.
    const blocked = freshIp();
    expect((await fetchJson('/api/private/admin/guard/block', { method: 'POST', cookie: oc, body: { scope: 'invalid', key: `${blocked}/32`, seconds: 600 } })).status).toBe(200);
    const res = await ts(`${paths[1]}?check`, { ip: blocked });
    expect(res.status).toBe(429);
    expect(res.headers.get('content-security-policy')).toBe(API_CSP);
    await res.text();
    expect((await fetchJson('/api/private/admin/guard/unblock', { method: 'POST', cookie: oc, body: { scope: 'invalid', key: `${blocked}/32` } })).status).toBe(200);
  });
});

// ── N2: isolation headers on every Worker response ────────────────────────
describe('every Worker response carries the isolation headers (N2)', () => {
  const baseline = (res, what) => {
    expect(res.headers.get('cross-origin-opener-policy'), what).toMatch(/^same-origin(-allow-popups)?$/);
    expect(res.headers.get('cross-origin-resource-policy'), what).toBe('same-origin');
    expect(res.headers.get('x-frame-options'), what).toBe('DENY');
    expect(res.headers.get('x-content-type-options'), what).toBe('nosniff');
    expect(res.headers.get('referrer-policy'), what).toBe('no-referrer');
    expect(res.headers.get('content-security-policy'), what).toBeTruthy();
  };
  it('API answers, errors, chunks and redirects: COOP/CORP same-origin, XFO DENY and default-src \'none\'; frame-ancestors \'none\'; sandbox — pages keep their own CSP', async () => {
    expect(API_CSP).toBe("default-src 'none'; frame-ancestors 'none'; sandbox");
    const u = await makeUser('cap-n2');
    const plainFile = await fileShare({ cookie: u.cookie }, { captcha: false });
    const ip = freshIp();
    const o = await openIt(plainFile, ip);
    const dl = (await o.clone().json()).grant;
    const unknown = `k${b64urlFromBytes(randomBytes(16))}`;
    const cases = [
      ['config (200 JSON)', await ts('/api/config')],
      ['unknown API route (404)', await ts('/api/nope')],
      ['method not allowed (405)', await ts('/api/config', { method: 'PUT' })],
      ['a CAPTCHA refusal (403)', await ts(`/api/paste/${unknown}`, { ip: freshIp() })],
      ['missing intent (400)', await ts(`/api/paste/${unknown}/human`, { method: 'POST', ip: freshIp() })],
      ['an open (200 JSON)', o],
      ['a chunk (octet-stream)', await chunk(plainFile, dl, ip)],
      ['a redirect (302)', await SELF.fetch(`${ORIGIN}/p/${unknown}?check`, { redirect: 'manual' })],
      ['a private route without a session (401)', await fetchJson('/api/private/me')],
    ];
    for (const [what, res] of cases) {
      baseline(res, what);
      const type = res.headers.get('content-type') || '';
      if (!/text\/html/.test(type)) expect(res.headers.get('content-security-policy'), what).toBe(API_CSP);
      await res.arrayBuffer();
    }
    // Pages keep theirs: the strict page, and the check page with its own COOP.
    const page = await ts(`/p/${unknown}`, { headers: { 'sec-fetch-dest': 'document', 'sec-fetch-mode': 'navigate', 'sec-fetch-site': 'none' } });
    baseline(page, 'page');
    expect(page.headers.get('content-security-policy')).toBe(CSP);
    expect(page.headers.get('cross-origin-opener-policy')).toBe('same-origin');
    await page.text();
    const check = await ts(`/p/${unknown}?check`, { ip: freshIp() });
    baseline(check, 'check page');
    expect(check.headers.get('cross-origin-opener-policy')).toBe('same-origin-allow-popups');
    expect(check.headers.get('content-security-policy')).toBe(TURNSTILE_CSP.replace("worker-src 'self'", "worker-src 'none'"));
    await check.text();
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
