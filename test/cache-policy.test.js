// cache-policy.test.js — Workers Caching (wrangler.toml [cache]) sits in front
// of the Worker and would store any response without Cache-Control
// heuristically, cookie-authenticated GETs included. Every response the Worker
// returns — success and error, anonymous and signed in, 404 / 405 / thrown
// errors, API-key calls (no cookie at all) and the Account page's changes
// with Turnstile on — must carry an explicit Cache-Control and
// `Cloudflare-CDN-Cache-Control: no-store` (nothing is stored at the edge),
// and every private, session or secret-bearing response must be `no-store`.
// The only exceptions are the public home page (the asset server's own
// browser caching, for the offline shell) and the anonymous tracker
// (`private`, so the browser keeps its ETag copy); both stay out of the edge.
import { env, SELF, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import worker from '../src/index.js';
import { withCachePolicy, EDGE_CACHE_CONTROL } from '../src/lib/http.js';
import { invalidateGuardCaches } from '../src/lib/guard.js';
import { setSiteverify } from '../src/lib/turnstile.js';
import { layout, buildManifest, importFileKey, encryptChunk, readStreamChunk } from '../public/js/files.js';
import { encryptPaste } from '../public/js/crypto.js';
import { utf8 } from '../public/js/bytes.js';
import { ORIGIN, owner, makeUser, fetchJson, createNote, proofHeaders, freshIp, intent, proofFor, USER_PW, salt16 } from './helpers.js';
import { SoftAuthenticator } from './soft-authenticator.js';
import { enc, enableDrive, someBytes } from './drive-helpers.js';
import { driveChunkSize } from '../src/drive-do.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';

let oc, user;
beforeAll(async () => {
  oc = await owner();
  user = await makeUser('cache-walker');
});

// Every response walked, with what it must carry: 'no-store' (the default for
// anything private, per-session or secret-bearing), or one of the two named
// exceptions.
const seen = [];
function record(label, res, expect_ = 'no-store') {
  seen.push({ label, status: res.status, cc: res.headers.get('cache-control'), edge: res.headers.get(EDGE_CACHE_CONTROL), expect: expect_ });
  return res;
}
const get = (path, opts = {}) => fetchJson(path, opts);
const raw = (path, init = {}) => SELF.fetch(`${ORIGIN}${path}`, { redirect: 'manual', ...init });

async function direct(path, envPatch, init = {}) {
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(`${ORIGIN}${path}`, init), { ...env, ...envPatch }, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

// The Worker with Turnstile on (SELF runs without it), for the Account page's
// human checks; a fake siteverify accepts each "ok:<action>#n" token once.
const TS_ENV = { TURNSTILE_SITEKEY: '0x4AAAAAAAtestsitekey', TURNSTILE_SECRET: '0x4AAAAAAAtestsecretvalue' };
function tsFetch(path, { method = 'GET', body, cookie, headers = {}, token } = {}) {
  const h = { 'cf-connecting-ip': freshIp(), ...headers };
  if (body !== undefined) h['content-type'] = 'application/json';
  if (cookie) h.cookie = cookie;
  if (token) h['x-secbin-turnstile'] = token;
  return direct(path, TS_ENV, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
}
function fakeSiteverify({ down = false } = {}) {
  const used = new Set();
  return setSiteverify(async (form) => {
    if (down) throw new Error('network');
    const t = form.get('response');
    const m = /^ok:([^#]+)/.exec(t);
    if (!m || used.has(t)) return Response.json({ success: false, 'error-codes': ['invalid-input-response'] });
    used.add(t);
    return Response.json({ success: true, hostname: new URL(ORIGIN).hostname, action: m[1] });
  });
}

async function uploadFile(cookie) {
  const bytes = utf8('cache policy file');
  const l = layout([{ path: 'a.txt', type: 'text/plain', size: bytes.length, mtime: 0 }], []);
  const manifest = buildManifest({ entries: l.entries, total: l.total });
  const init = await fetchJson('/api/private/file', { method: 'POST', cookie, body: { views: null, expire: '1h', padded: l.padded, files: 1, maxFile: bytes.length } });
  record('POST /api/private/file (init)', init);
  const { id, uploadtoken, chunks } = await init.json();
  const key = await importFileKey(manifest.fk);
  const sources = [{ off: 0, size: bytes.length, read: async (a, b) => bytes.slice(a, b) }];
  for (let i = 0; i < chunks; i++) {
    const ct = await encryptChunk(key, i, chunks, await readStreamChunk(sources, i, l.total));
    record(`PUT chunk ${i}`, await raw(`/api/private/file/${id}/chunk/${i}`, { method: 'PUT', headers: { cookie, 'content-type': 'application/octet-stream', 'x-upload-token': uploadtoken }, body: ct }));
  }
  const { body, fragment } = await encryptPaste({ text: JSON.stringify(manifest), fmt: 'files', expire: '1h' });
  record('POST finalize', await fetchJson(`/api/private/file/${id}/finalize`, { method: 'POST', cookie, headers: { 'x-upload-token': uploadtoken }, body: { paste: body } }));
  return { id, fragment };
}

describe('cache policy (Workers Caching)', () => {
  it('every walked route carries an explicit Cache-Control and never reaches the edge cache', { timeout: 120000 }, async () => {
    const ip = freshIp();

    // ── the home page and the signed-in app ──────────────────────────────
    record('GET /', await raw('/'), 'home');
    record('GET /index.html', await raw('/index.html'), 'home');
    record('HEAD /', await raw('/', { method: 'HEAD' }), 'home');
    record('GET / (signed in → redirect)', await raw('/', { headers: { cookie: user.cookie } }));
    record('GET / (stale cookie)', await raw('/', { headers: { cookie: '__Host-secbin_sess=garbage' } }), 'home');
    record('GET /dashboard (anon → login)', await raw('/dashboard'));
    record('GET /dashboard/ (anon → login)', await raw('/dashboard/'));
    record('GET /dashboard/login/', await raw('/dashboard/login/'));
    record('GET /dashboard/login/ (signed in → redirect)', await raw('/dashboard/login/', { headers: { cookie: user.cookie } }));
    record('GET /dashboard/setup/', await raw('/dashboard/setup/'));
    record('GET /dashboard/ (user)', await raw('/dashboard/', { headers: { cookie: user.cookie } }));
    record('GET /dashboard/shares/ (user)', await raw('/dashboard/shares/', { headers: { cookie: user.cookie } }));
    record('GET /dashboard/admin/ (user → redirect)', await raw('/dashboard/admin/', { headers: { cookie: user.cookie } }));
    record('GET /dashboard/admin/ (owner)', await raw('/dashboard/admin/', { headers: { cookie: oc } }));
    record('GET /dashboard/nope (owner, SPA fallback)', await raw('/dashboard/nope', { headers: { cookie: oc } }));
    record('HEAD /dashboard/ (owner)', await raw('/dashboard/', { method: 'HEAD', headers: { cookie: oc } }));

    // ── /api/config, unknown routes, 404 / 405 ───────────────────────────
    record('GET /api/config', await get('/api/config'));
    record('GET /api/config (signed in)', await get('/api/config', { cookie: oc }));
    record('POST /api/config (405)', await get('/api/config', { method: 'POST', body: {} }));
    record('GET /api/nope (404)', await get('/api/nope'));
    record('GET /api/auth/nope (404)', await get('/api/auth/nope'));
    record('GET /api/private/nope (owner, 404)', await get('/api/private/nope', { cookie: oc }));
    record('POST /api/paste (410)', await get('/api/paste', { method: 'POST', body: {} }));

    // ── auth ─────────────────────────────────────────────────────────────
    record('GET /api/auth/session (anon)', await get('/api/auth/session'));
    record('GET /api/auth/session (user)', await get('/api/auth/session', { cookie: user.cookie }));
    record('GET /api/auth/setup', await get('/api/auth/setup'));
    record('POST /api/auth/prelogin', await get('/api/auth/prelogin', { method: 'POST', body: { username: 'cache-walker' }, ip }));
    record('POST /api/auth/login (wrong)', await get('/api/auth/login', { method: 'POST', body: { username: 'cache-walker', proof: 'x' }, ip }));
    record('POST /api/auth/login (bad JSON type)', await raw('/api/auth/login', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'x' }));
    record('GET /api/auth/login (405)', await get('/api/auth/login'));

    // ── the account API ──────────────────────────────────────────────────
    record('GET /api/private/me (anon, 401)', await get('/api/private/me'));
    record('GET /api/private/me (user)', await get('/api/private/me', { cookie: user.cookie }));
    record('GET /api/private/me (bearer garbage)', await get('/api/private/me', { headers: { authorization: 'Bearer sb_garbage' } }));
    record('GET /api/private/policy (user)', await get('/api/private/policy', { cookie: user.cookie }));
    record('GET /api/private/shares (user)', await get('/api/private/shares', { cookie: user.cookie }));
    record('GET /api/private/me/keys (user)', await get('/api/private/me/keys', { cookie: user.cookie }));
    record('GET /api/private/me/passkeys (user)', await get('/api/private/me/passkeys', { cookie: user.cookie }));
    record('GET /api/private/me/activity (user)', await get('/api/private/me/activity', { cookie: user.cookie }));
    record('PATCH /api/private/me (405)', await get('/api/private/me', { method: 'PATCH', cookie: user.cookie, body: {} }));
    record('GET /api/private/admin/overview (user, 403)', await get('/api/private/admin/overview', { cookie: user.cookie }));
    record('GET /api/private/admin/overview (owner)', await get('/api/private/admin/overview', { cookie: oc }));
    record('GET /api/private/admin/users (owner)', await get('/api/private/admin/users', { cookie: oc }));
    record('GET /api/private/admin/users/<id> (owner)', await get(`/api/private/admin/users/${user.id}`, { cookie: oc }));
    record('GET /api/private/admin/roles (owner)', await get('/api/private/admin/roles', { cookie: oc }));
    record('GET /api/private/admin/shares (owner)', await get('/api/private/admin/shares', { cookie: oc }));
    record('GET /api/private/admin/audit (owner)', await get('/api/private/admin/audit', { cookie: oc }));
    record('GET /api/private/admin/ip-rules (owner)', await get('/api/private/admin/ip-rules', { cookie: oc }));
    record('GET /api/private/admin/turnstile (owner)', await get('/api/private/admin/turnstile', { cookie: oc }));
    record('GET /api/private/admin/public (owner)', await get('/api/private/admin/public', { cookie: oc }));
    record('GET /api/private/admin/settings (owner, 405)', await get('/api/private/admin/settings', { cookie: oc }));
    record('GET /api/private/admin/nope (owner, 404)', await get('/api/private/admin/nope', { cookie: oc }));

    // ── notes: create, head, open, burn, delete ──────────────────────────
    const note = await createNote(user.cookie, {}, {});
    record('POST /api/private/paste', note.res);
    const head = await get(`/api/paste/${note.id}`, { ip });
    record('GET /api/paste/<id> (head)', head);
    const { headers } = await proofHeaders((await head.json()).adata, note.fragment);
    record('POST /api/paste/<id>/open', await get(`/api/paste/${note.id}/open`, { method: 'POST', headers, ip }));
    record('GET /api/paste/<id>/open (405)', await get(`/api/paste/${note.id}/open`, { ip }));
    record('PUT /api/paste/<id> (405)', await get(`/api/paste/${note.id}`, { method: 'PUT', body: {}, ip }));
    record('POST /api/paste/<id>/open (no proofs)', await get(`/api/paste/${note.id}/open`, { method: 'POST', ip }));
    record('GET /api/paste/<unknown> (404)', await get('/api/paste/kAAAAAAAAAAAAAAAAAAAAAA', { ip: freshIp() }));
    record('GET /api/paste/<cross-site> (403)', await get(`/api/paste/${note.id}`, { headers: { 'sec-fetch-site': 'cross-site' }, ip }));
    const burn = await createNote(user.cookie, { bar: true, views: 1 }, {});
    const bh = await get(`/api/paste/${burn.id}`, { ip });
    record('GET /api/paste/<burn> (head)', bh);
    const bp = await proofHeaders((await bh.json()).adata, burn.fragment);
    record('POST /api/paste/<burn>/open', await get(`/api/paste/${burn.id}/open`, { method: 'POST', headers: bp.headers, ip }));
    record('POST /api/paste/<burn>/open (spent, 410)', await get(`/api/paste/${burn.id}/open`, { method: 'POST', headers: bp.headers, ip }));
    record('DELETE /api/paste/<id> (by token)', await get(`/api/paste/${note.id}`, { method: 'DELETE', headers: { 'x-delete-token': note.deletetoken }, ip }));

    // ── files: head, open, chunk download (ciphertext), bad grant ─────────
    const file = await uploadFile(user.cookie);
    const fh = await get(`/api/file/${file.id}`, { ip });
    record('GET /api/file/<id> (head)', fh);
    const fp = await proofHeaders((await fh.json()).adata, file.fragment);
    const open = await get(`/api/file/${file.id}/open`, { method: 'POST', headers: fp.headers, ip });
    record('POST /api/file/<id>/open (grant)', open);
    const { grant } = await open.json();
    record('GET /api/file/<id>/chunk/0', await raw(`/api/file/${file.id}/chunk/0`, { headers: { 'x-download-grant': grant, 'cf-connecting-ip': ip } }));
    record('HEAD /api/file/<id>/chunk/0 (405)', await raw(`/api/file/${file.id}/chunk/0`, { method: 'HEAD', headers: { 'x-download-grant': grant, 'cf-connecting-ip': ip } }));
    record('GET /api/file/<id>/chunk/9 (no such chunk)', await raw(`/api/file/${file.id}/chunk/9`, { headers: { 'x-download-grant': grant, 'cf-connecting-ip': ip } }));
    record('GET /api/file/<id>/chunk/0 (bad grant)', await raw(`/api/file/${file.id}/chunk/0`, { headers: { 'x-download-grant': 'x', 'cf-connecting-ip': freshIp() } }));

    // ── anonymous sharing: profile and the tracker ───────────────────────
    record('GET /api/public/profile (off)', await get('/api/public/profile'));
    record('GET /api/public/t (off, 403)', await get('/api/public/t', { ip }));
    await get('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'public.enabled': true, 'public.tracking': 'tracker' } });
    invalidateGuardCaches();
    record('GET /api/public/profile (on)', await get('/api/public/profile'));
    const t = await get('/api/public/t', { ip });
    record('GET /api/public/t (new tracker)', t, 'tracker');
    const aid = (t.headers.get('set-cookie') || '').match(/__Host-secbin_aid=([A-Za-z0-9_-]{32})/)[1];
    const again = await get('/api/public/t', { ip, headers: { cookie: `__Host-secbin_aid=${aid}`, 'if-none-match': `"${aid}"` } });
    expect(again.status).toBe(304);
    record('GET /api/public/t (304)', again, 'tracker');
    record('POST /api/public/t (405)', await get('/api/public/t', { method: 'POST', body: {}, ip }));
    record('POST /api/public/paste (no tracker, 428)', await get('/api/public/paste', { method: 'POST', body: {}, ip }));
    record('GET /api/public/nope (404)', await get('/api/public/nope', { ip }));
    await get('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'public.enabled': false } });
    invalidateGuardCaches();

    // ── API keys (scopes): creation, "read" and "manage" on My shares ───
    // A key-authenticated GET carries no cookie, so nothing in the request
    // would stop a shared cache from keying it by URL alone.
    const api = await makeUser('cache-api');
    const bearer = (k) => ({ authorization: `Bearer ${k}` });
    expect((await get('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: api.id, channel: 'all', patch: { apiEnabled: true } } })).status).toBe(200);
    const mkKey = (name, scopes) => get('/api/private/me/keys', { method: 'POST', cookie: api.cookie, body: { name, scopes, current: proofFor(USER_PW) } });
    const full = record('POST /api/private/me/keys (session, 201)', await mkKey('all', ['notes', 'files', 'policy', 'read', 'manage']));
    const all = (await full.json()).key;
    const notesKey = (await (await mkKey('notes', ['notes'])).json()).key;
    const listed = record('GET /api/private/me/keys (with keys, 200)', await get('/api/private/me/keys', { cookie: api.cookie }));
    const notesId = (await listed.json()).keys.find((k) => k.name === 'notes').id;
    record('PATCH /api/private/me/keys/<id> (scopes, 200)', await get(`/api/private/me/keys/${notesId}`, { method: 'PATCH', cookie: api.cookie, body: { scopes: ['notes', 'read'], current: proofFor(USER_PW) } }));
    record('PATCH /api/private/admin/users/<id>/keys/<id> (owner, 200)', await get(`/api/private/admin/users/${api.id}/keys/${notesId}`, { method: 'PATCH', cookie: oc, body: { scopes: ['notes'] } }));
    record('POST /api/private/admin/users/<id>/keys (owner, 201)', await get(`/api/private/admin/users/${api.id}/keys`, { method: 'POST', cookie: oc, body: { name: 'by-owner', scopes: ['read'] } }));
    record('GET /api/private/admin/users/<id>/keys (owner, 405)', await get(`/api/private/admin/users/${api.id}/keys`, { cookie: oc }));
    const { body: pasteBody } = await encryptPaste({ text: 'by key', expire: '1h' });
    const byKey = record('POST /api/private/paste (key, 201)', await get('/api/private/paste', { method: 'POST', headers: bearer(all), body: { paste: pasteBody } }));
    const kid = (await byKey.json()).id;
    record('POST /api/private/paste (notes-only key, 201)', await get('/api/private/paste', { method: 'POST', headers: bearer(notesKey), body: { paste: pasteBody } }));
    record('POST /api/private/file (key, 201)', await get('/api/private/file', { method: 'POST', headers: bearer(all), body: { views: 1, expire: '1h', padded: 65536, files: 1, maxFile: 10 } }));
    record('GET /api/private/policy (key, 200)', await get('/api/private/policy', { headers: bearer(all) }));
    record('GET /api/private/policy (key without "policy", 403)', await get('/api/private/policy', { headers: bearer(notesKey) }));
    record('GET /api/private/shares (key: read, 200)', await get('/api/private/shares', { headers: bearer(all) }));
    record('GET /api/private/shares?status=active (key: read, 200)', await get('/api/private/shares?status=active', { headers: bearer(all) }));
    record('GET /api/private/shares (key without "read", 403)', await get('/api/private/shares', { headers: bearer(notesKey) }));
    record('GET /api/private/shares/<id> (key: read, 200)', await get(`/api/private/shares/${kid}`, { headers: bearer(all) }));
    record('GET /api/private/shares/<id> (session, 200)', await get(`/api/private/shares/${kid}`, { cookie: api.cookie }));
    record('GET /api/private/shares/<id> (key without "read", 403)', await get(`/api/private/shares/${kid}`, { headers: bearer(notesKey) }));
    record('GET /api/private/shares/<unknown> (key, 404)', await get('/api/private/shares/kAAAAAAAAAAAAAAAAAAAAAA', { headers: bearer(all) }));
    record('GET /api/private/shares/<bad id> (key, 404)', await get('/api/private/shares/nope', { headers: bearer(all) }));
    record('GET /api/private/shares/<other user\'s> (key, 404)', await get(`/api/private/shares/${burn.id}`, { headers: bearer(all) }));
    record('GET /api/private/shares/<id>/opens (key: read, 200)', await get(`/api/private/shares/${kid}/opens`, { headers: bearer(all) }));
    record('GET /api/private/shares/<id>/opens (session, 200)', await get(`/api/private/shares/${kid}/opens`, { cookie: api.cookie }));
    record('POST /api/private/shares/<id>/opens (key, 403)', await get(`/api/private/shares/${kid}/opens`, { method: 'POST', headers: { ...bearer(notesKey), ...intent } }));
    record('PATCH /api/private/shares/<id> (key: manage, 200)', await get(`/api/private/shares/${kid}`, { method: 'PATCH', headers: bearer(all), body: { label: 'by key' } }));
    record('PATCH /api/private/shares/<id> (session, 200)', await get(`/api/private/shares/${kid}`, { method: 'PATCH', cookie: api.cookie, body: { label: 'by session' } }));
    record('PATCH /api/private/shares/<id> (key without "manage", 403)', await get(`/api/private/shares/${kid}`, { method: 'PATCH', headers: bearer(notesKey), body: { label: 'x' } }));
    record('PUT /api/private/shares/<id> (key: manage, 405)', await get(`/api/private/shares/${kid}`, { method: 'PUT', headers: bearer(all), body: {} }));
    record('GET /api/private/shares/<id>/revoke (key: read, 405)', await get(`/api/private/shares/${kid}/revoke`, { headers: bearer(all) }));
    record('POST /api/private/shares/<id>/revoke (key, no intent, 400)', await get(`/api/private/shares/${kid}/revoke`, { method: 'POST', headers: bearer(all) }));
    record('POST /api/private/shares/<id>/revoke (key: manage, 200)', await get(`/api/private/shares/${kid}/revoke`, { method: 'POST', headers: { ...bearer(all), ...intent } }));
    record('GET /api/private/shares/<revoked> (key: read, 200)', await get(`/api/private/shares/${kid}`, { headers: bearer(all) }));
    record('PATCH /api/private/shares/<revoked> (key: manage, label, 200)', await get(`/api/private/shares/${kid}`, { method: 'PATCH', headers: bearer(all), body: { label: 'late' } }));
    record('PATCH /api/private/shares/<revoked> (key: manage, extend, 409)', await get(`/api/private/shares/${kid}`, { method: 'PATCH', headers: bearer(all), body: { expires: Math.floor(Date.now() / 1000) + 7200 } }));
    const sessNote = await createNote(api.cookie, {}, {});
    record('POST /api/private/shares/<id>/revoke (session, 200)', await get(`/api/private/shares/${sessNote.id}/revoke`, { method: 'POST', cookie: api.cookie, headers: intent }));
    record('GET /api/private/me (key, 403)', await get('/api/private/me', { headers: bearer(all) }));
    record('GET /api/private/me/keys (key, 403)', await get('/api/private/me/keys', { headers: bearer(all) }));

    // ── the Account page's human checks (Turnstile on) ───────────────────
    const acct = await makeUser('cache-account');
    let n = 0;
    const once = (action) => `ok:${action}#${++n}`;
    const pw = { current: proofFor(USER_PW) };
    const restore = fakeSiteverify();
    try {
      const ts = (method, path, body, token) => tsFetch(path, { method, body, cookie: acct.cookie, token, headers: method === 'DELETE' ? intent : {} });
      record('GET /api/config (Turnstile on, 200)', await tsFetch('/api/config'));
      record('GET /dashboard/account/ (Turnstile on, 200)', await tsFetch('/dashboard/account/', { cookie: acct.cookie }));
      record('GET /dashboard/login/ (Turnstile on, 200)', await tsFetch('/dashboard/login/'));
      record('POST /api/private/me/username (no token, 403)', await ts('POST', '/api/private/me/username', { username: 'cache-account-2', ...pw }));
      record('POST /api/private/me/username (password token, 403)', await ts('POST', '/api/private/me/username', { username: 'cache-account-2', ...pw }, once('password')));
      record('POST /api/private/me/username (account token, 200)', await ts('POST', '/api/private/me/username', { username: 'cache-account-2', ...pw }, once('account')));
      record('POST /api/private/me/username (wrong password, 403)', await ts('POST', '/api/private/me/username', { username: 'cache-account-3', current: proofFor('wrong-password-000') }, once('account')));
      await get('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: acct.id, channel: 'all', patch: { apiEnabled: true } } });
      record('POST /api/private/me/keys (no token, 403)', await ts('POST', '/api/private/me/keys', { name: 'k', ...pw }));
      const made = record('POST /api/private/me/keys (account token, 201)', await ts('POST', '/api/private/me/keys', { name: 'k', ...pw }, once('account')));
      const { id: keyId } = await made.json();
      record('PATCH /api/private/me/keys/<id> (account token, 200)', await ts('PATCH', `/api/private/me/keys/${keyId}`, { name: 'k2', scopes: ['notes'], ...pw }, once('account')));
      record('DELETE /api/private/me/keys/<id> (no token, 403)', await ts('DELETE', `/api/private/me/keys/${keyId}`, pw));
      record('DELETE /api/private/me/keys/<id> (account token, 200)', await ts('DELETE', `/api/private/me/keys/${keyId}`, pw, once('account')));
      const auth = new SoftAuthenticator();
      const o = record('POST /api/private/me/passkeys/options (Turnstile on, 200)', await ts('POST', '/api/private/me/passkeys/options', {}));
      const { challengeId, publicKey } = await o.json();
      const credential = await auth.create(publicKey, ORIGIN);
      record('POST /api/private/me/passkeys (no token, 403)', await ts('POST', '/api/private/me/passkeys', { challengeId, credential, name: 'Laptop', ...pw }));
      record('POST /api/private/me/passkeys (account token, 201)', await ts('POST', '/api/private/me/passkeys', { challengeId, credential, name: 'Laptop', ...pw }, once('account')));
      record('POST /api/private/me/second-factor (account token, 200)', await ts('POST', '/api/private/me/second-factor', { on: true, ...pw }, once('account')));
      record('POST /api/private/me/second-factor (off, account token, 200)', await ts('POST', '/api/private/me/second-factor', { on: false, ...pw }, once('account')));
      record('POST /api/private/me/recovery-codes (no token, 403)', await ts('POST', '/api/private/me/recovery-codes', pw));
      record('POST /api/private/me/recovery-codes (account token, 200)', await ts('POST', '/api/private/me/recovery-codes', pw, once('account')));
      record('POST /api/private/me/reauth (Turnstile on, 200)', await ts('POST', '/api/private/me/reauth', {}));
      record('POST /api/private/me/passkeys/<id>/remove (account token, 200)', await ts('POST', `/api/private/me/passkeys/${auth.id}/remove`, pw, once('account')));
      record('GET /api/private/me/passkeys (Turnstile on, 200)', await ts('GET', '/api/private/me/passkeys'));
      record('GET /api/private/me/keys (Turnstile on, 200)', await ts('GET', '/api/private/me/keys'));
      record('POST /api/private/me/password (account token, 403)', await ts('POST', '/api/private/me/password', { ...pw }, once('account')));
      fakeSiteverify({ down: true });
      record('POST /api/private/me/username (siteverify down, 503)', await ts('POST', '/api/private/me/username', { username: 'cache-account-4', ...pw }, once('account')));
    } finally {
      setSiteverify(restore);
    }

    // ── the Drive (docs/DRIVE.md §6): the page, keys, tree, files, shares,
    // the owner's escrow routes and the impersonation escrow route ────────
    const dv = await makeUser('cache-drive');
    const noDrive = await makeUser('cache-nodrive');
    await enableDrive(dv.id);
    const dc = dv.cookie;
    const wrapData = () => `1.${b64urlFromBytes(randomBytes(12))}.${b64urlFromBytes(randomBytes(48))}`;
    const escData = () => `1.${b64urlFromBytes(randomBytes(65))}.${b64urlFromBytes(randomBytes(16))}.${b64urlFromBytes(randomBytes(12))}.${b64urlFromBytes(randomBytes(48))}`;
    const nid = () => b64urlFromBytes(randomBytes(16));
    record('GET /dashboard/drive/ (user)', await raw('/dashboard/drive/', { headers: { cookie: dc } }));
    record('GET /api/private/drive (no Drive, 200)', await get('/api/private/drive', { cookie: noDrive.cookie }));
    record('POST /api/private/drive/folders (no Drive, 403)', await get('/api/private/drive/folders', { method: 'POST', cookie: noDrive.cookie, body: {} }));
    record('GET /api/private/drive (user, 200)', await get('/api/private/drive', { cookie: dc }));
    record('GET /api/private/drive (key, 403)', await get('/api/private/drive', { headers: { authorization: `Bearer ${all}` } }));
    record('PUT /api/private/drive/keys (first set-up, 200)', await get('/api/private/drive/keys', { method: 'PUT', cookie: dc, headers: intent, body: { driveSalt: salt16(), set: [{ kind: 'pw', ref: 'pw', data: wrapData() }, { kind: 'escrow', ref: 'escrow', data: escData() }] } }));
    record('PUT /api/private/drive/keys (replace without step-up, 400)', await get('/api/private/drive/keys', { method: 'PUT', cookie: dc, headers: intent, body: { set: [{ kind: 'pw', ref: 'pw', data: wrapData() }] } }));
    record('PUT /api/private/drive/keys (step-up, 200)', await get('/api/private/drive/keys', { method: 'PUT', cookie: dc, headers: intent, body: { set: [{ kind: 'pw', ref: 'pw', data: wrapData() }], current: proofFor(USER_PW) } }));
    record('GET /api/private/drive/keys (405)', await get('/api/private/drive/keys', { cookie: dc }));
    const folderId = nid();
    record('POST /api/private/drive/folders (201)', await get('/api/private/drive/folders', { method: 'POST', cookie: dc, body: { id: folderId, parent: 'root', name: enc() } }));
    const fileId = nid();
    const created = record('POST /api/private/drive/files (201)', await get('/api/private/drive/files', { method: 'POST', cookie: dc, body: { id: fileId, parent: folderId, name: enc(), meta: enc(), size: 40, fk: enc(32) } }));
    const { uploadToken } = await created.json();
    record('GET /api/private/drive/files/<id>/chunk/0 (pending, 404)', await raw(`/api/private/drive/files/${fileId}/chunk/0`, { headers: { cookie: dc } }));
    record('POST /api/private/drive/files/<id>/finalize (incomplete, 409)', await get(`/api/private/drive/files/${fileId}/finalize`, { method: 'POST', cookie: dc, headers: { 'x-upload-token': uploadToken } }));
    record('PUT /api/private/drive/files/<id>/chunk/0 (200)', await raw(`/api/private/drive/files/${fileId}/chunk/0`, { method: 'PUT', headers: { cookie: dc, 'content-type': 'application/octet-stream', 'x-upload-token': uploadToken }, body: someBytes(driveChunkSize(40, 0)) }));
    record('PUT /api/private/drive/files/<id>/chunk/0 (wrong token, 403)', await raw(`/api/private/drive/files/${fileId}/chunk/0`, { method: 'PUT', headers: { cookie: dc, 'content-type': 'application/octet-stream', 'x-upload-token': 'A'.repeat(43) }, body: someBytes(driveChunkSize(40, 0)) }));
    record('POST /api/private/drive/files/<id>/finalize (200)', await get(`/api/private/drive/files/${fileId}/finalize`, { method: 'POST', cookie: dc, headers: { 'x-upload-token': uploadToken } }));
    record('GET /api/private/drive/files/<id>/chunk/0 (200)', await raw(`/api/private/drive/files/${fileId}/chunk/0`, { headers: { cookie: dc } }));
    record('GET /api/private/drive/files/<id>/chunk/9 (404)', await raw(`/api/private/drive/files/${fileId}/chunk/9`, { headers: { cookie: dc } }));
    record('GET /api/private/drive/nodes/root (200)', await get('/api/private/drive/nodes/root', { cookie: dc }));
    record('GET /api/private/drive/nodes/<unknown> (404)', await get(`/api/private/drive/nodes/${nid()}`, { cookie: dc }));
    record('PATCH /api/private/drive/nodes/<id> (200)', await get(`/api/private/drive/nodes/${fileId}`, { method: 'PATCH', cookie: dc, headers: intent, body: { name: enc() } }));
    const manifest = { v: 3, kind: 'refs', entries: [{ path: 'a', size: 40, type: 'application/octet-stream', mtime: 0, ref: 0, fk: b64urlFromBytes(randomBytes(32)) }], dirs: [] };
    const sealed = await encryptPaste({ text: JSON.stringify(manifest), fmt: 'files', bar: false, expire: '1h' });
    const ds = record('POST /api/private/drive/shares (201)', await get('/api/private/drive/shares', { method: 'POST', cookie: dc, body: { nodes: [fileId], views: null, expire: '1h', paste: sealed.body } }));
    const { id: driveShare } = await ds.json();
    record('GET /api/private/drive/nodes/<id>/shares (200)', await get(`/api/private/drive/nodes/${folderId}/shares`, { cookie: dc }));
    const dh = await get(`/api/file/${driveShare}`, { ip });
    record('GET /api/file/<drive share> (head)', dh);
    const dp = await proofHeaders((await dh.json()).adata, sealed.fragment);
    const dopen = record('POST /api/file/<drive share>/open (grant)', await get(`/api/file/${driveShare}/open`, { method: 'POST', headers: dp.headers, ip }));
    const { grant: dgrant } = await dopen.json();
    record('GET /api/file/<drive share>/chunk/0/0', await raw(`/api/file/${driveShare}/chunk/0/0`, { headers: { 'x-download-grant': dgrant, 'cf-connecting-ip': ip } }));
    record('POST /api/private/drive/escrow (not impersonating, 403)', await get('/api/private/drive/escrow', { method: 'POST', cookie: dc, body: {} }));
    record('POST /api/private/admin/drive/escrow/<id> (owner, 200)', await get(`/api/private/admin/drive/escrow/${dv.id}`, { method: 'POST', cookie: oc, headers: intent, body: { reason: 'cache walk' } }));
    record('PUT /api/private/admin/drive/keys/<id> (owner, 200)', await get(`/api/private/admin/drive/keys/${dv.id}`, { method: 'PUT', cookie: oc, headers: intent, body: { driveSalt: salt16(), set: [{ kind: 'pw', ref: 'pw', data: wrapData() }] } }));
    const imp = await get(`/api/private/admin/users/${dv.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent });
    const ic = (imp.headers.get('set-cookie') || '').split(';')[0];
    record('GET /api/private/drive (impersonating, 200)', await get('/api/private/drive', { cookie: ic }));
    record('POST /api/private/drive/escrow (impersonating, 200)', await get('/api/private/drive/escrow', { method: 'POST', cookie: ic, body: {} }));
    record('PUT /api/private/drive/keys (impersonating, 403)', await get('/api/private/drive/keys', { method: 'PUT', cookie: ic, headers: intent, body: { remove: [{ kind: 'pw', ref: 'pw' }] } }));
    record('GET /api/private/drive/nodes/root (impersonating, 200)', await get('/api/private/drive/nodes/root', { cookie: ic }));
    record('DELETE /api/private/drive/nodes/<id> (200)', await get(`/api/private/drive/nodes/${folderId}`, { method: 'DELETE', cookie: dc, headers: intent }));

    // ── a blocked network, errors and exceptions ─────────────────────────
    record('POST /api/auth/logout (user)', await get('/api/auth/logout', { method: 'POST', cookie: user.cookie, headers: intent }));
    const boom = () => { throw new Error('boom'); };
    const res500 = await direct('/api/private/me', { DIRECTORY: { idFromName: boom, get: boom, idFromString: boom, newUniqueId: boom } }, { headers: { cookie: oc } });
    expect(res500.status).toBe(500);
    record('GET /api/private/me (thrown error, 500)', res500);
    const post500 = await direct('/api/auth/prelogin', { DIRECTORY: { idFromName: boom, get: boom, idFromString: boom, newUniqueId: boom } }, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"username":"x"}' });
    expect(post500.status).toBe(500);
    record('POST /api/auth/prelogin (thrown error, 500)', post500);
    const home500 = await direct('/', { ASSETS: { fetch: boom } });
    expect(home500.status).toBe(500);
    record('GET / (assets throw, 500)', home500);
    const dash500 = await direct('/dashboard/login/', { ASSETS: { fetch: boom } });
    expect(dash500.status).toBe(500);
    record('GET /dashboard/login/ (assets throw, 500)', dash500);
    const r503 = await direct('/api/paste/kAAAAAAAAAAAAAAAAAAAAAA', { PASTES: undefined });
    expect(r503.status).toBe(503);
    record('GET /api/paste/<id> (binding missing, 503)', r503);
    const noAssets = await direct('/', { ASSETS: undefined });
    expect(noAssets.status).toBe(404);
    record('GET / (no ASSETS binding, 404)', noAssets);

    // ── the verdict ──────────────────────────────────────────────────────
    expect(seen.length).toBeGreaterThan(140);
    for (const r of seen) {
      const at = `${r.label} → ${r.status}`;
      // A label naming a status ("… (405)", "… 500)") walked what it says.
      const want = r.label.match(/\b([1-5]\d\d)\)$/);
      if (want) expect(r.status, at).toBe(Number(want[1]));
      expect(r.cc, at).toBeTruthy();
      expect(r.edge, at).toBe('no-store');
      if (r.expect === 'no-store') expect(r.cc, at).toBe('no-store');
      else if (r.expect === 'tracker') expect(r.cc, at).toMatch(/(^|,\s*)private(,|$)/);
      else {
        // The home page: never marked shareable beyond what the asset
        // server sends for a static page, and never cacheable at the edge.
        expect([200, 307], at).toContain(r.status);
        expect(r.cc, at).not.toMatch(/s-maxage|immutable/);
      }
    }
  });

  it('withCachePolicy fills in no-store, keeps an explicit policy and copies immutable responses', async () => {
    const bare = withCachePolicy(new Response('x', { status: 404 }));
    expect(bare.headers.get('cache-control')).toBe('no-store');
    expect(bare.headers.get(EDGE_CACHE_CONTROL)).toBe('no-store');
    const kept = withCachePolicy(new Response('x', { headers: { 'cache-control': 'private, no-cache' } }));
    expect(kept.headers.get('cache-control')).toBe('private, no-cache');
    expect(kept.headers.get(EDGE_CACHE_CONTROL)).toBe('no-store');
    // A response straight from fetch() has immutable headers.
    const frozen = Response.redirect('https://secbin.test/x', 302);
    const out = withCachePolicy(frozen);
    expect(out.status).toBe(302);
    expect(out.headers.get('location')).toBe('https://secbin.test/x');
    expect(out.headers.get('cache-control')).toBe('no-store');
    expect(out.headers.get(EDGE_CACHE_CONTROL)).toBe('no-store');
  });
});
