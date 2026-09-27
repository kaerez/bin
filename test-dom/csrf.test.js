// csrf.test.js (DOM) — public/js/api.js and CSRF tokens: every signed-in
// state-changing request carries the token read from its cookie at that
// moment (never a copy from page load); a 403 csrf_mismatch triggers exactly
// one /api/private/me refresh and one retry; a second refusal becomes the
// "session changed" message; a signed-out session gets the normal 401. And
// the dashboard chrome (nav.js) re-checks the session when the page comes
// back from the back-forward cache. The network is a stand-in.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const TOKEN_A = 'A'.repeat(43);
const TOKEN_B = 'B'.repeat(43);
const TOKEN_C = 'C'.repeat(43);

let jar = '';
Object.defineProperty(document, 'cookie', { configurable: true, get: () => jar, set: () => {} });

let calls;
let handler;
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const mismatch = () => json(403, { error: 'csrf_mismatch', message: 'This request could not be verified for your session. Reload the page and try again.' });
const profile = (over = {}) => ({ user: { id: 'u1', username: 'alice', role: 'owner' }, impersonatedBy: null, csrf: TOKEN_B, ...over });

beforeEach(() => {
  calls = [];
  jar = `other=1; __Host-secbin_csrf=${TOKEN_A}; theme=dark`;
  vi.stubGlobal('fetch', vi.fn(async (path, init = {}) => {
    const headers = Object.fromEntries(Object.entries(init.headers || {}).map(([k, v]) => [k.toLowerCase(), v]));
    calls.push({ path, method: init.method || 'GET', headers, body: init.body });
    return handler(path, init, headers);
  }));
});
afterEach(() => { vi.unstubAllGlobals(); });

const api = await import('../public/js/api.js');
const tokenOf = (c) => c.headers['x-secbin-csrf'];

describe('the token is read per request', () => {
  it('from the cookie as it is at the moment of each request', async () => {
    handler = () => json(200, { ok: true });
    await api.admin.settings({ csrfTokens: true });
    expect(tokenOf(calls[0])).toBe(TOKEN_A);
    // Another tab signed in again (or impersonation started): the cookie changed.
    jar = `__Host-secbin_csrf=${TOKEN_C}`;
    await api.updateShare('kAAAAAAAAAAAAAAAAAAAAAA', { label: 'x' });
    expect(tokenOf(calls[1])).toBe(TOKEN_C);
    await api.revokeShare('kAAAAAAAAAAAAAAAAAAAAAA');
    expect(tokenOf(calls[2])).toBe(TOKEN_C);
    expect(calls[2].headers['x-secbin-intent']).toBe('1');
    await api.logout();
    expect(tokenOf(calls[3])).toBe(TOKEN_C);
    expect(api.csrfToken()).toBe(TOKEN_C);
  });

  it('only where the server checks it: never on reads or on the anonymous routes', async () => {
    handler = () => json(200, { ok: true, id: 'x', deletetoken: 'y' });
    await api.listShares();
    await api.openShare('paste', 'kAAAAAAAAAAAAAAAAAAAAAA', { linkProof: 'l', keyProof: 'k' });
    await api.deleteShare('paste', 'kAAAAAAAAAAAAAAAAAAAAAA', 'tok');
    await api.login('alice', 'proof');
    await api.publicApi.createNote({});
    expect(calls.map(tokenOf)).toEqual([undefined, undefined, undefined, undefined, undefined]);
  });

  it('no cookie (or a malformed one): no header, and the server decides', async () => {
    handler = () => json(200, { ok: true });
    jar = '';
    await api.admin.settings({});
    jar = '__Host-secbin_csrf=<script>';
    await api.admin.settings({});
    expect(calls.map(tokenOf)).toEqual([undefined, undefined]);
  });

  it('chunk uploads carry it too', async () => {
    handler = () => json(200, { ok: true });
    await api.uploadChunk('fAAAAAAAAAAAAAAAAAAAAAA', 0, new Uint8Array(4), 'U'.repeat(43));
    expect(calls[0]).toMatchObject({ method: 'PUT', path: '/api/private/file/fAAAAAAAAAAAAAAAAAAAAAA/chunk/0' });
    expect(tokenOf(calls[0])).toBe(TOKEN_A);
    expect(calls[0].headers['content-type']).toBe('application/octet-stream');
  });
});

describe('a refused token: one refresh, one retry', () => {
  it('fetches /api/private/me once, retries once with its token, and succeeds', async () => {
    let attempts = 0;
    handler = (path) => {
      if (path === '/api/private/me') { jar = `__Host-secbin_csrf=${TOKEN_B}`; return json(200, profile()); }
      attempts += 1;
      return attempts === 1 ? mismatch() : json(201, { ok: true, id: 'r1' });
    };
    const r = await api.admin.createRole({ name: 'ops' });
    expect(r).toEqual({ ok: true, id: 'r1' });
    expect(calls.map((c) => `${c.method} ${c.path}`)).toEqual(['POST /api/private/admin/roles', 'GET /api/private/me', 'POST /api/private/admin/roles']);
    expect(calls.map(tokenOf)).toEqual([TOKEN_A, undefined, TOKEN_B]);
    // The same body both times.
    expect(calls[2].body).toBe(calls[0].body);
  });

  it('uses the token /me returns even when the cookie cannot be read', async () => {
    let attempts = 0;
    handler = (path) => {
      if (path === '/api/private/me') return json(200, profile({ csrf: TOKEN_C }));
      attempts += 1;
      return attempts === 1 ? mismatch() : json(200, { ok: true });
    };
    await api.admin.unlock('AAAAAAAAAAAAAAAA');
    expect(tokenOf(calls[2])).toBe(TOKEN_C);
  });

  it('a second refusal shows “Your session changed in another tab; reload the page.”', async () => {
    handler = (path) => (path === '/api/private/me' ? json(200, profile()) : mismatch());
    const e = await api.changeUsername('bob', { current: 'p' }).catch((x) => x);
    expect(e).toBeInstanceOf(api.ApiError);
    expect(e.message).toBe('Your session changed in another tab; reload the page.');
    expect(e.message).toBe(api.SESSION_CHANGED);
    expect(e).toMatchObject({ status: 403, code: 'csrf_mismatch' });
    // Exactly one refresh and one retry: no loop.
    expect(calls.map((c) => c.path)).toEqual(['/api/private/me/username', '/api/private/me', '/api/private/me/username']);
    // What the pages show for it (common.js friendlyError) is that message.
    const { friendlyError } = await import('../public/js/common.js');
    expect(friendlyError(e)).toBe(api.SESSION_CHANGED);
  });

  it('a signed-out session gets the normal 401, not a CSRF error', async () => {
    handler = (path) => (path === '/api/private/me' ? json(401, { error: 'unauthenticated', message: 'Please log in.' }) : mismatch());
    const e = await api.createNote({}, '').catch((x) => x);
    expect(e).toMatchObject({ status: 401, code: 'unauthenticated' });
    expect(calls).toHaveLength(2); // no retry without a session
  });

  it('other 403s are not retried', async () => {
    handler = () => json(403, { error: 'forbidden', message: 'Owner only.' });
    const e = await api.admin.settings({}).catch((x) => x);
    expect(e).toMatchObject({ status: 403, code: 'forbidden', message: 'Owner only.' });
    expect(calls).toHaveLength(1);
  });
});

describe('back-forward cache (nav.js)', () => {
  it('a restored page re-checks the session and reloads when it is someone else’s', async () => {
    let who = profile();
    handler = (path) => (path === '/api/private/me' ? json(200, who) : json(200, { ok: true }));
    const reload = vi.fn();
    const loc = window.location;
    Object.defineProperty(window, 'location', { configurable: true, value: { ...loc, pathname: '/dashboard/', href: 'https://secbin.test/dashboard/', reload, replace: vi.fn() } });
    try {
      const nav = await import('../public/dashboard/js/nav.js');
      await nav.ready;
      const pageshow = (persisted) => { const ev = new Event('pageshow'); Object.defineProperty(ev, 'persisted', { value: persisted }); window.dispatchEvent(ev); };
      const settle = () => new Promise((r) => setTimeout(r, 0));
      const before = calls.length;
      pageshow(false); // an ordinary load: nothing to do
      await settle();
      expect(calls.length).toBe(before);
      pageshow(true); // same session: nothing to reload; the next request reads the current token anyway
      await settle(); await settle();
      expect(calls.length).toBe(before + 1);
      expect(reload).not.toHaveBeenCalled();
      who = profile({ impersonatedBy: 'boss' }); // impersonation started in another tab
      pageshow(true);
      await settle(); await settle();
      expect(reload).toHaveBeenCalledTimes(1);
    } finally {
      Object.defineProperty(window, 'location', { configurable: true, value: loc });
    }
  });
});
