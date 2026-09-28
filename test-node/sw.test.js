// sw.test.js — the service worker's caching rules (public/sw.js). The worker is
// a classic script, so it is evaluated in a vm context with a stub `self`; its
// top-level functions (requestPolicy, isCacheableResponse, cacheKey) and its
// fetch handler are then exercised directly. The invariant under test: nothing
// under /api/ or /p/, nothing with a query string, nothing cross-origin and no
// non-GET request is ever intercepted — so it can never be served from, or
// written to, the cache.
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { readFileSync } from 'node:fs';
import { createHash, webcrypto } from 'node:crypto';
import vm from 'node:vm';
import { generatedBlock, buildManifest } from '../tools/sw-manifest.mjs';
import { SECURITY_HEADERS } from '../src/lib/http.js';

const ORIGIN = 'https://bin.example';
const src = readFileSync(new URL('../public/sw.js', import.meta.url), 'utf8');

let ctx;
const listeners = {};
beforeAll(() => {
  ctx = {
    URL, Headers, Request, Response, Promise, crypto: webcrypto, btoa,
    self: {
      location: new URL(`${ORIGIN}/sw.js`),
      addEventListener: (type, fn) => { listeners[type] = fn; },
      skipWaiting: async () => {},
      clients: { claim: async () => {} },
    },
    caches: { open: async () => { throw new Error('cache must not be touched'); } },
    fetch: async () => { throw new Error('network must not be touched'); },
  };
  vm.createContext(ctx);
  vm.runInContext(src, ctx, { filename: 'public/sw.js' });
});

const req = (path, { method = 'GET', mode = 'no-cors', headers = {} } = {}) => ({
  url: path.startsWith('http') ? path : ORIGIN + path,
  method,
  mode,
  headers: new Headers(headers),
});

/** Dispatch a fetch event; returns true when the worker called respondWith(). */
function intercepts(request) {
  let responded = false;
  listeners.fetch({ request, respondWith: () => { responded = true; } });
  return responded;
}

describe('service worker request policy', () => {
  it('registers install, activate and fetch handlers', () => {
    expect(Object.keys(listeners).sort()).toEqual(['activate', 'fetch', 'install']);
  });

  it('never handles /api/* (any method, any shape)', () => {
    for (const p of ['/api', '/api/', '/api/config', '/api/paste/abc', '/api/file/x/chunk/0', '/api/private/shares', '/api/auth/session']) {
      for (const mode of ['cors', 'same-origin', 'no-cors', 'navigate']) {
        expect(ctx.requestPolicy(req(p, { mode }), ORIGIN)).toBeNull();
        expect(intercepts(req(p, { mode }))).toBe(false);
      }
    }
  });

  it('never handles /p/* share pages, even as navigations', () => {
    for (const p of ['/p', '/p/', '/p/bAbCdEfGhIjKlMnOpQrStUv', '/p/bAbCdEfGhIjKlMnOpQrStUv/', '/p/x#key-material']) {
      expect(ctx.requestPolicy(req(p, { mode: 'navigate' }), ORIGIN)).toBeNull();
      expect(ctx.requestPolicy(req(p), ORIGIN)).toBeNull();
      expect(intercepts(req(p, { mode: 'navigate' }))).toBe(false);
    }
  });

  it('never handles /r/* reverse-share upload pages, even as navigations', () => {
    for (const p of ['/r', '/r/', '/r/rAbCdEfGhIjKlMnOpQrStUv', '/r/rAbCdEfGhIjKlMnOpQrStUv/', '/r/x#key-material']) {
      expect(ctx.requestPolicy(req(p, { mode: 'navigate' }), ORIGIN)).toBeNull();
      expect(ctx.requestPolicy(req(p), ORIGIN)).toBeNull();
      expect(intercepts(req(p, { mode: 'navigate' }))).toBe(false);
    }
  });

  it('never handles URLs with a query string', () => {
    for (const p of ['/?token=secret', '/js/view.js?v=1', '/css/styles.css?x', '/dashboard/login/?disabled=1', '/img/icon-192.png?']) {
      expect(ctx.requestPolicy(req(p, { mode: p.startsWith('/?') ? 'navigate' : 'no-cors' }), ORIGIN)).toBeNull();
    }
  });

  it('never handles other origins, non-GET, Range requests or dot/encoded segments', () => {
    expect(ctx.requestPolicy(req('https://evil.example/js/view.js'), ORIGIN)).toBeNull();
    expect(ctx.requestPolicy(req('http://bin.example/js/view.js'), ORIGIN)).toBeNull();
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH', 'HEAD']) expect(ctx.requestPolicy(req('/js/view.js', { method }), ORIGIN)).toBeNull();
    expect(ctx.requestPolicy(req('/img/icon-192.png', { headers: { range: 'bytes=0-10' } }), ORIGIN)).toBeNull();
    expect(ctx.requestPolicy(req('/js/%2e%2e/api/config'), ORIGIN)).toBeNull();
    expect(ctx.requestPolicy(req('/js/..%2fapi/config'), ORIGIN)).toBeNull();
  });

  it('does not cache dashboard pages or unknown paths', () => {
    for (const p of ['/dashboard', '/dashboard/', '/dashboard/login/', '/dashboard/admin/', '/dashboard/drive/', '/robots.txt', '/opengraph.png', '/sw.js']) {
      expect(ctx.requestPolicy(req(p, { mode: 'navigate' }), ORIGIN)).toBeNull();
    }
    expect(ctx.requestPolicy(req('/dashboard/js/create.js'), ORIGIN)).toBeNull();
    expect(ctx.requestPolicy(req('/dashboard/js/drive-app.js'), ORIGIN)).toBeNull();
  });

  it('handles same-origin static assets and the landing shell', () => {
    for (const p of ['/css/styles.css', '/js/view.js', '/js/vendor/pdf.min.mjs', '/fonts/geist-400.woff2', '/img/icon-512.png', '/manifest.webmanifest', '/favicon.ico']) {
      expect(ctx.requestPolicy(req(p), ORIGIN)).toBe('static');
    }
    expect(ctx.requestPolicy(req('/', { mode: 'navigate' }), ORIGIN)).toBe('shell');
    // A share id never reaches the shell: /p/<id> is excluded above.
  });
});

describe('service worker response rules', () => {
  const res = (status = 200, { type = 'basic', redirected = false, cc = '' } = {}) => ({
    status, ok: status >= 200 && status < 300, type, redirected, headers: new Headers(cc ? { 'cache-control': cc } : {}),
  });

  it('stores only plain same-origin 200s that allow storage', () => {
    expect(ctx.isCacheableResponse(res())).toBe(true);
    expect(ctx.isCacheableResponse(res(200, { cc: 'public, max-age=0, must-revalidate' }))).toBe(true);
    expect(ctx.isCacheableResponse(res(206))).toBe(false);
    expect(ctx.isCacheableResponse(res(302))).toBe(false);
    expect(ctx.isCacheableResponse(res(404))).toBe(false);
    expect(ctx.isCacheableResponse(res(200, { type: 'opaque' }))).toBe(false);
    expect(ctx.isCacheableResponse(res(200, { type: 'cors' }))).toBe(false);
    expect(ctx.isCacheableResponse(res(0, { type: 'opaqueredirect' }))).toBe(false);
    expect(ctx.isCacheableResponse(res(200, { redirected: true }))).toBe(false);
    expect(ctx.isCacheableResponse(res(200, { cc: 'no-store' }))).toBe(false);
    expect(ctx.isCacheableResponse(res(200, { cc: 'private, max-age=60' }))).toBe(false);
    expect(ctx.isCacheableResponse(null)).toBe(false);
  });

  it('keys the cache by origin + path only', () => {
    expect(ctx.cacheKey(req('/css/styles.css#frag'))).toBe(`${ORIGIN}/css/styles.css`);
  });

  it('uses a versioned cache and deletes only older secbin caches on activate', async () => {
    const version = /const VERSION = '([^']+)';/.exec(src)?.[1];
    expect(version).toBeTruthy();
    const current = `secbin-static-${version}`;
    const deleted = [];
    const saved = ctx.caches;
    ctx.caches = { keys: async () => ['secbin-static-old', current, 'other-app'], delete: async (n) => { deleted.push(n); return true; } };
    let done;
    listeners.activate({ waitUntil: (p) => { done = p; } });
    await done;
    ctx.caches = saved;
    expect(deleted).toEqual(['secbin-static-old']);
  });
});

// ── the integrity manifest (security re-audit N3) ──────────────────────────
describe('service worker: cached copies are served only when they are this build\'s assets', () => {
  const sha = (text) => createHash('sha256').update(text).digest('base64');
  const REAL = '/js/view.js';
  const realBody = readFileSync(new URL('../public/js/view.js', import.meta.url));
  /** A Cache Storage stub: one cache, a Map of key → Response. */
  function cacheStorage(entries = {}) {
    const m = new Map(Object.entries(entries));
    const deleted = [];
    const cache = {
      match: async (k) => (m.has(k) ? m.get(k).clone() : undefined),
      put: async (k, r) => { m.set(k, r); },
      delete: async (k) => { deleted.push(k); return m.delete(k); },
    };
    return { store: { open: async () => cache, keys: async () => [] }, m, deleted };
  }
  const saved = {};
  beforeAll(() => { saved.caches = ctx.caches; saved.fetch = ctx.fetch; });
  afterEach(() => { ctx.caches = saved.caches; ctx.fetch = saved.fetch; });
  const offline = async () => { throw new TypeError('Failed to fetch'); };

  it('the manifest in sw.js is current (tools/sw-manifest.mjs), covers the landing page and every static asset, and carries the security headers', () => {
    expect(src).toContain(generatedBlock());
    const m = buildManifest();
    expect(m['/']).toBe(sha(readFileSync(new URL('../public/index.html', import.meta.url))));
    expect(m[REAL]).toBe(sha(realBody));
    expect(Object.keys(m).every((p) => p === '/' || p === '/manifest.webmanifest' || p === '/favicon.ico' || /^\/(css|fonts|img|js)\//.test(p))).toBe(true);
    expect(Object.keys(m)).not.toContain('/sw.js');
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) expect(src).toContain(`${JSON.stringify(k)}: ${JSON.stringify(v)}`);
  });

  it('PoC N3: a poisoned cache entry (a script of this origin wrote it) is never served offline; it is deleted and the request fails', async () => {
    for (const [path, body, headers] of [
      [REAL, 'alert(document.cookie)', { 'content-type': 'text/javascript' }],
      ['/', '<!doctype html><script>steal()</script>', { 'content-type': 'text/html' }], // no CSP of its own
      [REAL, `${realBody.toString('utf8')}\n;steal()`, { 'content-type': 'text/javascript' }], // the real file, appended to
    ]) {
      const c = cacheStorage({ [`${ORIGIN}${path}`]: new Response(body, { headers }) });
      ctx.caches = c.store;
      ctx.fetch = offline;
      await expect(ctx.networkFirst(req(path, { mode: path === '/' ? 'navigate' : 'no-cors' }))).rejects.toThrow('Failed to fetch');
      expect(c.deleted).toEqual([`${ORIGIN}${path}`]);
    }
  });

  it('a verified copy is served offline, rebuilt with this build\'s content type and security headers (never the stored ones)', async () => {
    const c = cacheStorage({ [`${ORIGIN}${REAL}`]: new Response(realBody, { headers: { 'content-type': 'text/html', 'content-security-policy': "script-src 'unsafe-inline'" } }) });
    ctx.caches = c.store;
    ctx.fetch = offline;
    const res = await ctx.networkFirst(req(REAL));
    expect(res.status).toBe(200);
    expect(Buffer.from(await res.arrayBuffer()).equals(realBody)).toBe(true);
    expect(res.headers.get('content-type')).toBe('text/javascript; charset=utf-8');
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) expect(res.headers.get(k)).toBe(v);
  });

  it('a network body that is not this build\'s is not stored; this build\'s is, with rebuilt headers; a path outside the manifest is never cached', async () => {
    const pending = [];
    const waitUntil = (p) => pending.push(p);
    let c = cacheStorage();
    ctx.caches = c.store;
    ctx.fetch = async () => new Response('tampered in transit', { status: 200, headers: { 'content-type': 'text/javascript' } });
    // A fetched same-origin response is 'basic' in a browser; Node's Response says 'default'.
    const typeDesc = Object.getOwnPropertyDescriptor(Response.prototype, 'type');
    Object.defineProperty(Response.prototype, 'type', { configurable: true, get() { return 'basic'; } });
    try {
      await ctx.networkFirst(req(REAL), waitUntil);
      await Promise.all(pending.splice(0));
      expect(c.m.size).toBe(0);
      ctx.fetch = async () => new Response(realBody, { status: 200, headers: { 'content-type': 'text/javascript' } });
      await ctx.networkFirst(req(REAL), waitUntil);
      await Promise.all(pending.splice(0));
      expect([...c.m.keys()]).toEqual([`${ORIGIN}${REAL}`]);
      expect(c.m.get(`${ORIGIN}${REAL}`).headers.get('content-security-policy')).toBe(SECURITY_HEADERS['content-security-policy']);
      // Not in the manifest: fetched, never stored, never served from cache.
      c = cacheStorage({ [`${ORIGIN}/js/not-a-real-file.js`]: new Response('x') });
      ctx.caches = c.store;
      ctx.fetch = async () => new Response('x', { status: 200 });
      await ctx.networkFirst(req('/js/not-a-real-file.js'), waitUntil);
      await Promise.all(pending.splice(0));
      expect([...c.m.keys()]).toEqual([`${ORIGIN}/js/not-a-real-file.js`]); // untouched, not re-stored
      ctx.fetch = offline;
      await expect(ctx.networkFirst(req('/js/not-a-real-file.js'))).rejects.toThrow('Failed to fetch');
    } finally {
      Object.defineProperty(Response.prototype, 'type', typeDesc);
    }
  });
});
