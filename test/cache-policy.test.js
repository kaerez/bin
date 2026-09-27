// cache-policy.test.js — Workers Caching (wrangler.toml [cache]) sits in front
// of the Worker and would store any response without Cache-Control
// heuristically, cookie-authenticated GETs included. Every response the Worker
// returns — success and error, anonymous and signed in, 404 / 405 / thrown
// errors — must carry an explicit Cache-Control and
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
import { layout, buildManifest, importFileKey, encryptChunk, readStreamChunk } from '../public/js/files.js';
import { encryptPaste } from '../public/js/crypto.js';
import { utf8 } from '../public/js/bytes.js';
import { ORIGIN, owner, makeUser, fetchJson, createNote, proofHeaders, freshIp, intent } from './helpers.js';

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
  it('every walked route carries an explicit Cache-Control and never reaches the edge cache', async () => {
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
    expect(seen.length).toBeGreaterThan(80);
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
