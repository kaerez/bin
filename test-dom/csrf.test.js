// csrf.test.js (DOM) — public/js/api.js and CSRF tokens. A signed-in page acts
// for the session it was loaded for: it sends that session's token (recorded
// from /api/private/me), never whatever the shared cookie holds now. A 403
// csrf_mismatch triggers exactly one /api/private/me refresh; the change is
// retried once only when the browser is still signed in as the page's own user
// in the same impersonation state. Anyone else, or a second refusal, becomes
// the "session changed" message with a Reload button, and the page stops
// acting for any session. A signed-out session gets the normal 401. The
// dashboard chrome (nav.js) records the session at load, re-checks it when the
// page comes back from the back-forward cache, and signs out through the same
// path. The network is a stand-in.
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
const bob = (over = {}) => profile({ user: { id: 'u2', username: 'bob', role: 'user' }, csrf: TOKEN_C, ...over });

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
const trail = () => calls.map((c) => `${c.method} ${c.path}`);

describe('the page’s token', () => {
  beforeEach(() => { api.bindSession(profile()); });

  it('is the one of the session the page was loaded for, not whatever the cookie holds now', async () => {
    handler = () => json(200, { ok: true });
    await api.admin.settings({ csrfTokens: true });
    expect(tokenOf(calls[0])).toBe(TOKEN_B); // from the profile, not the cookie (TOKEN_A)
    // Another tab signed in as someone else: the shared cookie changed.
    jar = `__Host-secbin_csrf=${TOKEN_C}`;
    await api.updateShare('kAAAAAAAAAAAAAAAAAAAAAA', { label: 'x' });
    await api.revokeShare('kAAAAAAAAAAAAAAAAAAAAAA');
    await api.logout();
    expect(calls.slice(1).map(tokenOf)).toEqual([TOKEN_B, TOKEN_B, TOKEN_B]);
    expect(calls[2].headers['x-secbin-intent']).toBe('1');
    expect(api.csrfToken()).toBe(TOKEN_C); // the cookie itself is read as it is
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

  it('a profile without a (well-formed) token: no header, and the server decides', async () => {
    handler = () => json(200, { ok: true });
    api.bindSession(profile({ csrf: undefined }));
    await api.admin.settings({});
    api.bindSession(profile({ csrf: '<script>' }));
    await api.admin.settings({});
    expect(calls.map(tokenOf)).toEqual([undefined, undefined]);
  });

  it('chunk uploads carry it too', async () => {
    handler = () => json(200, { ok: true });
    await api.uploadChunk('fAAAAAAAAAAAAAAAAAAAAAA', 0, new Uint8Array(4), 'U'.repeat(43));
    expect(calls[0]).toMatchObject({ method: 'PUT', path: '/api/private/file/fAAAAAAAAAAAAAAAAAAAAAA/chunk/0' });
    expect(tokenOf(calls[0])).toBe(TOKEN_B);
    expect(calls[0].headers['content-type']).toBe('application/octet-stream');
  });
});

describe('a page that recorded no session', () => {
  it('records the current one from /api/private/me before its first change', async () => {
    vi.resetModules();
    const fresh = await import('../public/js/api.js');
    handler = (path) => (path === '/api/private/me' ? json(200, profile({ csrf: TOKEN_C })) : json(200, { ok: true }));
    await fresh.admin.settings({});
    await fresh.admin.settings({});
    expect(trail()).toEqual(['GET /api/private/me', 'PATCH /api/private/admin/settings', 'PATCH /api/private/admin/settings']);
    expect(calls.map(tokenOf)).toEqual([undefined, TOKEN_C, TOKEN_C]);
  });

  it('signed out: the normal 401, and the change is not sent', async () => {
    vi.resetModules();
    const fresh = await import('../public/js/api.js');
    handler = (path) => (path === '/api/private/me' ? json(401, { error: 'unauthenticated', message: 'Please log in.' }) : json(200, { ok: true }));
    const e = await fresh.createNote({}, '').catch((x) => x);
    expect(e).toMatchObject({ status: 401, code: 'unauthenticated' });
    expect(trail()).toEqual(['GET /api/private/me']);
  });
});

describe('a refused token: one refresh, then a retry only for the same session holder', () => {
  let changed;
  beforeEach(() => {
    api.bindSession(profile());
    changed = vi.fn();
    api.onSessionChanged(changed);
  });

  it('the same user again (a new session, e.g. signed out and in elsewhere): one /me, one retry with its token, and it keeps that token', async () => {
    let attempts = 0;
    handler = (path) => {
      if (path === '/api/private/me') return json(200, profile({ csrf: TOKEN_C }));
      attempts += 1;
      return attempts === 1 ? mismatch() : json(201, { ok: true, id: 'r1' });
    };
    jar = ''; // the cookie cannot be read: /me's body is enough
    const r = await api.admin.createRole({ name: 'ops' });
    expect(r).toEqual({ ok: true, id: 'r1' });
    expect(trail()).toEqual(['POST /api/private/admin/roles', 'GET /api/private/me', 'POST /api/private/admin/roles']);
    expect(calls.map(tokenOf)).toEqual([TOKEN_B, undefined, TOKEN_C]);
    expect(calls[2].body).toBe(calls[0].body); // the same body both times
    await api.admin.unlock('AAAAAAAAAAAAAAAA');
    expect(tokenOf(calls[3])).toBe(TOKEN_C); // the page now acts for the new session
    expect(changed).not.toHaveBeenCalled();
  });

  it('another user now (audit L2: a page loaded for frank never acts on grace’s session): no retry, “session changed”, and the page stops', async () => {
    handler = (path) => (path === '/api/private/me' ? json(200, bob()) : mismatch());
    const e = await api.createNote({}, 'written on alice’s page').catch((x) => x);
    expect(api.isSessionChanged(e)).toBe(true);
    expect(e).toMatchObject({ status: 403, code: 'csrf_mismatch', message: api.SESSION_CHANGED });
    expect(trail()).toEqual(['POST /api/private/paste', 'GET /api/private/me']); // not retried
    expect(changed).toHaveBeenCalledTimes(1);
    // From now on nothing is sent for this page: bob's account is never touched.
    handler = () => json(200, { ok: true });
    for (const act of [() => api.updateShare('kAAAAAAAAAAAAAAAAAAAAAA', { label: 'x' }), () => api.admin.settings({}), () => api.logout()]) {
      expect(api.isSessionChanged(await act().catch((x) => x))).toBe(true);
    }
    expect(calls).toHaveLength(2);
    expect(changed).toHaveBeenCalledTimes(1); // said once
  });

  it('impersonation started in another tab (same browser, now “alice acting as bob”): no retry', async () => {
    handler = (path) => (path === '/api/private/me' ? json(200, bob({ impersonatedBy: 'alice' })) : mismatch());
    expect(api.isSessionChanged(await api.admin.settings({}).catch((x) => x))).toBe(true);
    expect(calls).toHaveLength(2);
  });

  it('impersonation ended in another tab (a page loaded while acting as bob): no retry', async () => {
    api.bindSession(bob({ impersonatedBy: 'alice' }));
    handler = (path) => (path === '/api/private/me' ? json(200, profile()) : mismatch());
    expect(api.isSessionChanged(await api.updateShare('kAAAAAAAAAAAAAAAAAAAAAA', { label: 'x' }).catch((x) => x))).toBe(true);
    expect(calls).toHaveLength(2);
  });

  it('a second refusal shows “Your session changed in another tab; reload the page.”', async () => {
    handler = (path) => (path === '/api/private/me' ? json(200, profile()) : mismatch());
    const e = await api.changeUsername('bob', { current: 'p' }).catch((x) => x);
    expect(e).toBeInstanceOf(api.ApiError);
    expect(e.message).toBe('Your session changed in another tab; reload the page.');
    expect(e.message).toBe(api.SESSION_CHANGED);
    expect(e).toMatchObject({ status: 403, code: 'csrf_mismatch' });
    // Exactly one refresh and one retry: no loop.
    expect(trail().map((x) => x.split(' ')[1])).toEqual(['/api/private/me/username', '/api/private/me', '/api/private/me/username']);
    // What the pages show for it (common.js friendlyError) is that message.
    const { friendlyError } = await import('../public/js/common.js');
    expect(friendlyError(e)).toBe(api.SESSION_CHANGED);
    expect(changed).toHaveBeenCalledTimes(1);
  });

  it('a signed-out session gets the normal 401, not a CSRF error', async () => {
    handler = (path) => (path === '/api/private/me' ? json(401, { error: 'unauthenticated', message: 'Please log in.' }) : mismatch());
    const e = await api.createNote({}, '').catch((x) => x);
    expect(e).toMatchObject({ status: 401, code: 'unauthenticated' });
    expect(calls).toHaveLength(2); // no retry without a session
    expect(changed).not.toHaveBeenCalled();
  });

  it('other 403s are not retried', async () => {
    handler = () => json(403, { error: 'forbidden', message: 'Owner only.' });
    const e = await api.admin.settings({}).catch((x) => x);
    expect(e).toMatchObject({ status: 403, code: 'forbidden', message: 'Owner only.' });
    expect(calls).toHaveLength(1);
  });
});

// ── nav.js ─────────────────────────────────────────────────────────────────
function chrome() {
  document.body.replaceChildren();
  const el = (tag, attrs = {}, ...kids) => { const x = document.createElement(tag); for (const [k, v] of Object.entries(attrs)) x.setAttribute(k, v); x.append(...kids); return x; };
  const nav = el('nav', { id: 'dash-nav', hidden: '' }, el('a', { href: '/dashboard/', 'data-nav': '' }, 'Create'), el('a', { id: 'nav-admin', href: '/dashboard/admin/' }, 'Admin'), el('button', { id: 'nav-logout', type: 'button' }, 'Log out'));
  const imp = el('div', { id: 'imp-banner', class: 'imp-banner', hidden: '' }, el('span', { id: 'imp-text' }), el('button', { id: 'imp-return', type: 'button' }, 'Return to admin'));
  document.body.append(imp, nav, el('div', { id: 'toast' }));
}
const loc = window.location;
let reload;
let replace;
function stubLocation() {
  reload = vi.fn();
  replace = vi.fn();
  Object.defineProperty(window, 'location', { configurable: true, value: { ...loc, pathname: '/dashboard/', href: 'https://secbin.test/dashboard/', reload, replace } });
}
const settle = async () => { for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0)); };

describe('the dashboard chrome (nav.js)', () => {
  afterEach(() => { Object.defineProperty(window, 'location', { configurable: true, value: loc }); });

  it('a page restored from the back-forward cache re-checks the session and reloads when it is someone else’s', async () => {
    let who = profile();
    handler = (path) => (path === '/api/private/me' ? json(200, who) : json(200, { ok: true }));
    stubLocation();
    chrome();
    vi.resetModules();
    const nav = await import('../public/dashboard/js/nav.js');
    await nav.ready;
    const pageshow = (persisted) => { const ev = new Event('pageshow'); Object.defineProperty(ev, 'persisted', { value: persisted }); window.dispatchEvent(ev); };
    const before = calls.length;
    pageshow(false); // an ordinary load: nothing to do
    await settle();
    expect(calls.length).toBe(before);
    pageshow(true); // same session: nothing to reload
    await settle();
    expect(calls.length).toBe(before + 1);
    expect(reload).not.toHaveBeenCalled();
    who = profile({ impersonatedBy: 'boss' }); // impersonation started in another tab
    pageshow(true);
    await settle();
    expect(reload).toHaveBeenCalledTimes(1);
  });

  /** A fresh dashboard page (new module instances) loaded for `who`. */
  async function load(who = profile()) {
    handler = (path) => (path === '/api/private/me' ? json(200, who) : json(200, { ok: true }));
    stubLocation();
    chrome();
    vi.resetModules();
    const nav = await import('../public/dashboard/js/nav.js');
    const fresh = await import('../public/js/api.js');
    await nav.ready;
    calls.length = 0;
    return { nav, api: fresh };
  }

  it('records the session the page was loaded for: its changes carry that session’s token', async () => {
    const { api: a } = await load(profile({ csrf: TOKEN_B }));
    jar = `__Host-secbin_csrf=${TOKEN_C}`; // the cookie is someone else's now
    await a.admin.settings({});
    expect(tokenOf(calls[0])).toBe(TOKEN_B);
  });

  it('when the browser is now signed in as someone else: “session changed” with a Reload button, and nothing is changed', async () => {
    const { api: a } = await load(profile({ impersonatedBy: 'boss' }));
    document.getElementById('imp-banner').hidden = false;
    handler = (path) => (path === '/api/private/me' ? json(200, bob()) : mismatch());
    expect(a.isSessionChanged(await a.createNote({}, '').catch((x) => x))).toBe(true);
    expect(trail()).toEqual(['POST /api/private/paste', 'GET /api/private/me']);
    const banner = document.getElementById('session-changed');
    expect(banner).not.toBeNull();
    expect(banner.getAttribute('role')).toBe('alert');
    expect(banner.textContent).toContain('Your session changed in another tab; reload the page.');
    expect(document.getElementById('imp-banner').hidden).toBe(true); // it described the old session
    const btn = document.getElementById('session-reload');
    expect(btn.textContent).toBe('Reload');
    expect(document.activeElement).toBe(btn);
    btn.click();
    expect(reload).toHaveBeenCalledTimes(1);
    // A second refusal elsewhere does not add a second banner.
    await a.admin.settings({}).catch(() => {});
    expect(document.querySelectorAll('#session-changed')).toHaveLength(1);
  });

  it('log out (audit I1): a stale token of the same user goes through the refresh and retry, then to the login page', async () => {
    await load();
    let attempts = 0;
    handler = (path) => {
      if (path === '/api/private/me') return json(200, profile({ csrf: TOKEN_C }));
      attempts += 1;
      return attempts === 1 ? mismatch() : json(200, { ok: true });
    };
    document.getElementById('nav-logout').click();
    await settle();
    expect(trail()).toEqual(['POST /api/auth/logout', 'GET /api/private/me', 'POST /api/auth/logout']);
    expect(calls.map(tokenOf)).toEqual([TOKEN_B, undefined, TOKEN_C]);
    expect(replace).toHaveBeenCalledWith('/dashboard/login/');
  });

  it('log out when the browser is now someone else’s: that session is not ended, the page says so and stops acting', async () => {
    const { api: a } = await load();
    handler = (path) => (path === '/api/private/me' ? json(200, bob()) : mismatch());
    document.getElementById('nav-logout').click();
    await settle();
    expect(trail()).toEqual(['POST /api/auth/logout', 'GET /api/private/me']); // no second logout: bob stays signed in
    expect(replace).not.toHaveBeenCalled();
    expect(document.getElementById('session-changed')).not.toBeNull();
    // Local state cleared: this page acts for no session any more.
    expect(a.isSessionChanged(await a.admin.settings({}).catch((x) => x))).toBe(true);
    expect(calls).toHaveLength(2);
  });

  it('log out that fails for another reason (the network): the error is shown, not swallowed, and it can be tried again', async () => {
    await load();
    handler = () => { throw new TypeError('Failed to fetch'); };
    document.getElementById('nav-logout').click();
    await settle();
    expect(document.getElementById('toast').textContent).toBe('Could not reach the server — check your connection and try again.');
    expect(replace).not.toHaveBeenCalled();
    handler = () => json(200, { ok: true });
    document.getElementById('nav-logout').click();
    await settle();
    expect(tokenOf(calls.at(-1))).toBe(TOKEN_B);
    expect(replace).toHaveBeenCalledWith('/dashboard/login/');
  });

  it('log out of a session that had already ended (401): to the login page', async () => {
    await load();
    handler = () => json(401, { error: 'unauthenticated', message: 'Please log in.' });
    document.getElementById('nav-logout').click();
    await settle();
    expect(replace).toHaveBeenCalledWith('/dashboard/login/');
  });
});
