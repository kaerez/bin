// csrf.test.js — CSRF tokens (src/lib/csrf.js), a second check on top of
// SameSite=Strict cookies, the Sec-Fetch-Site check and the JSON / intent
// requirement. Every cookie-authenticated state-changing request must echo the
// session's token in X-Secbin-CSRF: a missing, wrong, other-session or
// old-session-version token is refused with 403 csrf_mismatch before anything
// changes. API keys and the anonymous routes need none. The token is bound to
// the session (the same for every request of it) and changes with it. The
// owner can turn the check off (Admin → Settings, `csrfTokens`); the other
// guards stay.
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import worker from '../src/index.js';
import { csrfTokensMatch, CSRF_COOKIE } from '../src/lib/csrf.js';
import { setSiteverify } from '../src/lib/turnstile.js';
import { encryptPaste } from '../public/js/crypto.js';
import {
  ORIGIN, owner, makeUser, login, fetchJson, cookieOf, csrfFor, createNote, proofHeaders, freshIp, intent, proofFor, USER_PW, salt16,
} from './helpers.js';

let oc;
beforeAll(async () => { oc = await owner(); });

const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const errorOf = async (r) => (await r.json()).error;
/** A request as the page would send it, but with `token` (or none) instead of the session's own. */
const send = (method, path, { cookie = oc, token, body, headers = {}, ip = freshIp() } = {}) =>
  fetchJson(path, { method, cookie, body, ip, csrf: false, headers: { ...(token ? { 'x-secbin-csrf': token } : {}), ...headers } });
const setCookies = (res) => res.headers.getSetCookie();
const csrfCookieOf = (res) => setCookies(res).find((c) => c.startsWith(`${CSRF_COOKIE}=`)) ?? null;
const tokenOf = (res) => /^__Host-secbin_csrf=([^;]*)/.exec(csrfCookieOf(res) ?? '')?.[1] ?? null;
const settings = (patch, cookie = oc) => fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie, body: patch });
const myShares = async (cookie) => (await (await fetchJson('/api/private/shares', { cookie })).json()).total;
const loginRes = (username, password) => fetchJson('/api/auth/login', { method: 'POST', body: { username, proof: proofFor(password) }, ip: freshIp() });

describe('the token and its cookie', () => {
  it('comes with every new session: a readable __Host- cookie next to the HttpOnly session cookie', async () => {
    const u = await makeUser('csrf-cookie');
    const r = await loginRes('csrf-cookie', USER_PW);
    expect(r.status).toBe(200);
    const [sess, csrf] = setCookies(r);
    expect(sess).toMatch(/^__Host-secbin_sess=[^;]+; Path=\/; HttpOnly; Secure; SameSite=Strict; Max-Age=\d+$/);
    expect(csrf).toMatch(/^__Host-secbin_csrf=[A-Za-z0-9_-]{43}; Path=\/; Secure; SameSite=Strict; Max-Age=\d+$/);
    expect(csrf).not.toMatch(/HttpOnly|Domain=/i);
    // The same for every request of the session: /me returns it and re-sets its cookie.
    const cookie = cookieOf(r);
    const me1 = await fetchJson('/api/private/me', { cookie });
    const t = (await me1.json()).csrf;
    expect(t).toBe(tokenOf(r));
    expect(tokenOf(me1)).toBe(t);
    expect((await (await fetchJson('/api/private/me', { cookie })).json()).csrf).toBe(t);
    // So does every signed-in page load (a reload always has the current token).
    const page = await fetchJson('/dashboard/', { cookie });
    expect(page.status).toBe(200);
    expect(tokenOf(page)).toBe(t);
    // Another session of the same account has another token.
    expect(await csrfFor(u.cookie)).not.toBe(t);
  });

  it('changes after sign-in and sign-out, and the sign-out clears its cookie', async () => {
    await makeUser('csrf-cycle');
    const first = await loginRes('csrf-cycle', USER_PW);
    const c1 = cookieOf(first);
    const t1 = tokenOf(first);
    const out = await fetchJson('/api/auth/logout', { method: 'POST', cookie: c1, headers: intent });
    expect(out.status).toBe(200);
    expect(setCookies(out)).toEqual(expect.arrayContaining([
      expect.stringMatching(/^__Host-secbin_sess=; .*Max-Age=0$/),
      expect.stringMatching(/^__Host-secbin_csrf=; Path=\/; Secure; SameSite=Strict; Max-Age=0$/),
    ]));
    const second = await loginRes('csrf-cycle', USER_PW);
    const t2 = tokenOf(second);
    expect(TOKEN_RE.test(t1) && TOKEN_RE.test(t2)).toBe(true);
    expect(t2).not.toBe(t1);
    // The old token does not work for the new session.
    const r = await send('POST', '/api/private/paste', { cookie: cookieOf(second), token: t1, body: { paste: (await encryptPaste({ text: 'x' })).body } });
    expect(r.status).toBe(403);
    expect(await errorOf(r)).toBe('csrf_mismatch');
  });

  it('changes when impersonation starts and when it ends', async () => {
    const u = await makeUser('csrf-imp');
    const own = await csrfFor(oc);
    const imp = await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent });
    expect(imp.status).toBe(200);
    const ic = cookieOf(imp);
    const impToken = tokenOf(imp);
    expect(impToken).not.toBe(own);
    // A tab still holding the owner's token is refused (api.js then refreshes and retries).
    const stale = await send('POST', '/api/private/admin/unimpersonate', { cookie: ic, token: own, headers: intent });
    expect(await errorOf(stale)).toBe('csrf_mismatch');
    const back = await send('POST', '/api/private/admin/unimpersonate', { cookie: ic, token: impToken, headers: intent });
    expect(back.status).toBe(200);
    const after = tokenOf(back);
    expect(after).not.toBe(impToken);
    expect(after).not.toBe(own); // a new session of the owner's
  });
});

describe('refused without the session’s token (403 csrf_mismatch, nothing changes)', () => {
  it('missing, wrong, another session’s and an old session version’s token', async () => {
    const u = await makeUser('csrf-bad');
    const other = await login('csrf-bad', USER_PW); // a second session of the same account
    const note = async () => ({ paste: (await encryptPaste({ text: 'x' })).body });
    const before = await myShares(u.cookie);
    for (const token of [undefined, 'A'.repeat(43), 'short', `${await csrfFor(u.cookie)}x`, await csrfFor(other), await csrfFor(oc)]) {
      const r = await send('POST', '/api/private/paste', { cookie: u.cookie, token, body: await note() });
      expect(r.status).toBe(403);
      const b = await r.json();
      expect(b.error).toBe('csrf_mismatch');
      // Never the token in the message.
      expect(JSON.stringify(b)).not.toContain(await csrfFor(u.cookie));
    }
    expect(await myShares(u.cookie)).toBe(before);

    // Old session version: the password change bumps it and re-issues this
    // device's session; the token from before no longer matches.
    const oldToken = await csrfFor(u.cookie);
    const pw = await fetchJson('/api/private/me/password', { method: 'POST', cookie: u.cookie, body: { current: proofFor(USER_PW), salt: salt16(), t: 3, proof: proofFor('csrf-new-password-1') } });
    expect(pw.status).toBe(200);
    const fresh = cookieOf(pw);
    expect(tokenOf(pw)).not.toBe(oldToken);
    const r = await send('POST', '/api/private/paste', { cookie: fresh, token: oldToken, body: await note() });
    expect(await errorOf(r)).toBe('csrf_mismatch');
    expect(await myShares(fresh)).toBe(before);
    // The right token works.
    const ok = await send('POST', '/api/private/paste', { cookie: fresh, token: tokenOf(pw), body: await note() });
    expect(ok.status).toBe(201);
    expect(await myShares(fresh)).toBe(before + 1);
  });

  it('no change happens on a refused request (account, shares, admin, sign-out)', async () => {
    const u = await makeUser('csrf-nochange');
    const n = await createNote(u.cookie, {}, { label: 'keep' });
    expect(n.res.status).toBe(201);
    const wrong = await csrfFor(oc);
    // Username
    expect(await errorOf(await send('POST', '/api/private/me/username', { cookie: u.cookie, token: wrong, body: { username: 'csrf-renamed', current: proofFor(USER_PW) } }))).toBe('csrf_mismatch');
    expect((await (await fetchJson('/api/private/me', { cookie: u.cookie })).json()).user.username).toBe('csrf-nochange');
    // Share label and revoke
    expect(await errorOf(await send('PATCH', `/api/private/shares/${n.id}`, { cookie: u.cookie, token: wrong, body: { label: 'changed' } }))).toBe('csrf_mismatch');
    expect(await errorOf(await send('POST', `/api/private/shares/${n.id}/revoke`, { cookie: u.cookie, token: wrong, headers: intent }))).toBe('csrf_mismatch');
    const share = (await (await fetchJson(`/api/private/shares/${n.id}`, { cookie: u.cookie })).json()).share;
    expect(share).toMatchObject({ label: 'keep', status: 'active' });
    // Admin: create a user, change a setting, delete a user
    const users = async () => (await (await fetchJson('/api/private/admin/users', { cookie: oc })).json()).users.length;
    const count = await users();
    expect(await errorOf(await send('POST', '/api/private/admin/users', { token: 'B'.repeat(43), body: { username: 'csrf-ghost', salt: salt16(), t: 3, proof: proofFor('ghost-password-12') } }))).toBe('csrf_mismatch');
    expect(await errorOf(await send('DELETE', `/api/private/admin/users/${u.id}`, { headers: intent }))).toBe('csrf_mismatch');
    expect(await users()).toBe(count);
    const max = (await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json()).settings['guard.login.max'];
    expect(await errorOf(await send('PATCH', '/api/private/admin/settings', { body: { 'guard.login.max': max + 1 } }))).toBe('csrf_mismatch');
    expect((await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json()).settings['guard.login.max']).toBe(max);
    // Sign-out: the session stays valid.
    const out = await send('POST', '/api/auth/logout', { cookie: u.cookie, headers: intent });
    expect(await errorOf(out)).toBe('csrf_mismatch');
    expect(setCookies(out)).toEqual([]);
    expect((await fetchJson('/api/private/me', { cookie: u.cookie })).status).toBe(200);
  });

  it('covers every cookie-authenticated state-changing route', async () => {
    const id = 'AAAAAAAAAAAAAAAA';
    const share = 'kAAAAAAAAAAAAAAAAAAAAAA';
    const file = 'fAAAAAAAAAAAAAAAAAAAAAA';
    const json = (method, path) => ({ method, path, body: {} });
    const act = (method, path) => ({ method, path, headers: intent });
    const routes = [
      json('POST', '/api/private/paste'), json('POST', '/api/private/file'),
      { method: 'PUT', path: `/api/private/file/${file}/chunk/0`, raw: true },
      json('POST', `/api/private/file/${file}/finalize`),
      json('PATCH', `/api/private/shares/${share}`), act('POST', `/api/private/shares/${share}/revoke`),
      json('POST', '/api/private/me/password'), json('POST', '/api/private/me/username'), json('POST', '/api/private/me/reauth'),
      json('POST', '/api/private/me/keys'), json('PATCH', `/api/private/me/keys/${id}`), act('DELETE', `/api/private/me/keys/${id}`),
      json('POST', '/api/private/me/passkeys/options'), json('POST', '/api/private/me/passkeys'), json('POST', `/api/private/me/passkeys/${id}/remove`),
      json('POST', '/api/private/me/recovery-codes'), json('POST', '/api/private/me/second-factor'),
      act('POST', '/api/private/admin/unimpersonate'),
      json('PATCH', `/api/private/admin/shares/${share}`), act('POST', `/api/private/admin/shares/${share}/revoke`), json('POST', `/api/private/admin/shares/${share}/lock`),
      json('POST', '/api/private/admin/export'), json('POST', '/api/private/admin/import'),
      json('POST', '/api/private/admin/public/trackers/AAAAAAAAAAAA'),
      json('PATCH', '/api/private/admin/settings'), json('PUT', '/api/private/admin/turnstile'), json('PATCH', '/api/private/admin/limits'),
      json('PUT', '/api/private/admin/quotas'), json('PUT', '/api/private/admin/viewer-rules'),
      json('POST', '/api/private/admin/roles'), json('PATCH', `/api/private/admin/roles/${id}`), act('DELETE', `/api/private/admin/roles/${id}`),
      json('POST', '/api/private/admin/users'), json('PATCH', `/api/private/admin/users/${id}`), act('DELETE', `/api/private/admin/users/${id}`),
      json('POST', `/api/private/admin/users/${id}/password`), act('POST', `/api/private/admin/users/${id}/unlock`),
      act('POST', `/api/private/admin/users/${id}/passkeys`), json('PUT', `/api/private/admin/users/${id}/role`),
      act('POST', `/api/private/admin/users/${id}/impersonate`), json('POST', `/api/private/admin/users/${id}/keys`),
      json('PATCH', `/api/private/admin/users/${id}/keys/${id}`), act('DELETE', `/api/private/admin/users/${id}/keys/${id}`),
      json('POST', '/api/private/admin/logs/clear'), json('POST', '/api/private/admin/ip-rules'), act('DELETE', `/api/private/admin/ip-rules/${id}`),
      json('POST', '/api/private/admin/guard/unblock'), json('POST', '/api/private/admin/guard/block'),
      act('POST', '/api/auth/logout'),
    ];
    for (const r of routes) {
      const res = r.raw
        ? await fetchJson(r.path, { method: r.method, cookie: oc, csrf: false, headers: { 'content-type': 'application/octet-stream', 'x-upload-token': 'A'.repeat(43) } })
        : await send(r.method, r.path, { body: r.body, headers: r.headers });
      expect(`${r.method} ${r.path} → ${res.status} ${await errorOf(res)}`).toBe(`${r.method} ${r.path} → 403 csrf_mismatch`);
    }
    expect((await fetchJson('/api/private/me', { cookie: oc })).status).toBe(200); // the logout above was refused too
    // A simple request (a form-style text/plain body, no custom header) skips the
    // token check and is refused by each route's own guard, with its usual error.
    for (const r of routes) {
      const res = await fetchJson(r.path, { method: r.method, cookie: oc, csrf: false, ip: freshIp(), headers: { 'content-type': 'text/plain' } });
      const code = await errorOf(res);
      expect(`${r.method} ${r.path} → ${res.status >= 400 && res.status < 500 && code !== 'csrf_mismatch'}`).toBe(`${r.method} ${r.path} → true`);
      // The shape guards; finalize checks its X-Upload-Token (itself a custom
      // header) first, and a few admin routes look up the (made-up) id first.
      expect(['unsupported_media_type', 'missing_intent', 'bad_token', 'not_found']).toContain(code);
    }
    expect((await fetchJson('/api/private/me', { cookie: oc })).status).toBe(200);
  });
});

describe('after the existing guards, which keep their errors', () => {
  it('cross-site first, then the request shape, then the token', async () => {
    const body = { paste: (await encryptPaste({ text: 'x' })).body };
    const cross = await send('POST', '/api/private/paste', { body, headers: { 'sec-fetch-site': 'cross-site' } });
    expect(await errorOf(cross)).toBe('cross_site');
    const sameSite = await send('POST', '/api/private/paste', { body, headers: { 'sec-fetch-site': 'same-site' } });
    expect(await errorOf(sameSite)).toBe('cross_site');
    const plain = await fetchJson('/api/private/paste', { method: 'POST', cookie: oc, csrf: false, headers: { 'content-type': 'text/plain' } });
    expect(plain.status).toBe(415);
    const noIntent = await send('DELETE', '/api/private/admin/users/AAAAAAAAAAAAAAAA');
    expect(await errorOf(noIntent)).toBe('missing_intent');
    const noIntentLogout = await send('POST', '/api/auth/logout');
    expect(await errorOf(noIntentLogout)).toBe('missing_intent');
    // Safe methods need no token.
    expect((await send('GET', '/api/private/shares')).status).toBe(200);
  });

  it('a signed-out session gets the normal 401, not a CSRF error', async () => {
    const r = await send('POST', '/api/private/paste', { cookie: '__Host-secbin_sess=garbage', body: {} });
    expect(r.status).toBe(401);
    expect(await errorOf(r)).toBe('unauthenticated');
    const u = await makeUser('csrf-gone');
    const token = await csrfFor(u.cookie);
    await fetchJson('/api/auth/logout', { method: 'POST', cookie: u.cookie, headers: intent });
    const after = await send('POST', '/api/private/paste', { cookie: u.cookie, token, body: {} });
    expect(await errorOf(after)).toBe('unauthenticated');
    // Signing out an ended session is not refused either.
    expect((await send('POST', '/api/auth/logout', { cookie: u.cookie, headers: intent })).status).toBe(200);
  });

  it('comes before the human check, so a refused request can be retried with the same Turnstile token', async () => {
    const u = await makeUser('csrf-turnstile');
    const TS_ENV = { ...env, TURNSTILE_SITEKEY: '0x4AAAAAAAtestsitekey', TURNSTILE_SECRET: '0x4AAAAAAAtestsecretvalue' };
    const seen = new Set();
    const restore = setSiteverify(async (form) => {
      const t = form.get('response');
      if (seen.has(t)) return Response.json({ success: false, 'error-codes': ['timeout-or-duplicate'] });
      seen.add(t);
      return Response.json({ success: true, hostname: new URL(ORIGIN).hostname, action: 'account' });
    });
    try {
      const call = async (token) => {
        const ctx = createExecutionContext();
        const headers = { cookie: u.cookie, 'content-type': 'application/json', 'x-secbin-turnstile': 'ok:account#1', 'cf-connecting-ip': freshIp(), ...(token ? { 'x-secbin-csrf': token } : {}) };
        const res = await worker.fetch(new Request(`${ORIGIN}/api/private/me/username`, { method: 'POST', headers, body: JSON.stringify({ username: 'csrf-turnstile-2', current: proofFor(USER_PW) }) }), TS_ENV, ctx);
        await waitOnExecutionContext(ctx);
        return res;
      };
      expect(await errorOf(await call(null))).toBe('csrf_mismatch');
      expect(seen.size).toBe(0); // the human-check token was not spent
      const ok = await call(await csrfFor(u.cookie));
      expect(ok.status).toBe(200);
    } finally {
      setSiteverify(restore);
    }
  });
});

describe('exempt: API keys and the anonymous routes', () => {
  it('API-key (Bearer) requests need no token', async () => {
    const u = await makeUser('csrf-key');
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch: { apiEnabled: true } } });
    const k = await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { name: 'cli', current: proofFor(USER_PW), scopes: ['notes', 'read', 'manage'] } });
    expect(k.status).toBe(201);
    const auth = { authorization: `Bearer ${(await k.json()).key}` };
    const { body } = await encryptPaste({ text: 'from the CLI' });
    const made = await fetchJson('/api/private/paste', { method: 'POST', headers: auth, body: { paste: body } });
    expect(made.status).toBe(201);
    const { id } = await made.json();
    expect((await fetchJson(`/api/private/shares/${id}`, { method: 'PATCH', headers: auth, body: { label: 'via key' } })).status).toBe(200);
    expect((await fetchJson(`/api/private/shares/${id}/revoke`, { method: 'POST', headers: { ...auth, ...intent } })).status).toBe(200);
  });

  it('anonymous routes keep their own guards and need no token, even with a session cookie present', async () => {
    // Login, prelogin, setup status: no session yet.
    expect((await fetchJson('/api/auth/prelogin', { method: 'POST', body: { username: 'owner' }, ip: freshIp() })).status).toBe(200);
    expect((await loginRes('owner', 'owner-password')).status).toBe(200);
    expect((await fetchJson('/api/auth/setup')).status).toBe(200);
    // Opening and deleting a share by its capabilities.
    const n = await createNote(oc, {}, {});
    const head = await (await fetchJson(`/api/paste/${n.id}`)).json();
    const { headers } = await proofHeaders(head.adata, n.fragment);
    expect((await fetchJson(`/api/paste/${n.id}/open`, { method: 'POST', cookie: oc, csrf: false, headers })).status).toBe(200);
    expect((await fetchJson(`/api/paste/${n.id}`, { method: 'DELETE', cookie: oc, csrf: false, headers: { 'x-delete-token': n.deletetoken } })).status).toBe(200);
    // Anonymous creation (when the owner enables it).
    expect((await settings({ 'public.enabled': true, 'public.tracking': 'ip' })).status).toBe(200);
    try {
      const { body } = await encryptPaste({ text: 'anonymous', bar: true, views: 1, expire: '1h' });
      const r = await fetchJson('/api/public/paste', { method: 'POST', cookie: oc, csrf: false, ip: freshIp(), body: { paste: body } });
      expect(r.status).toBe(201);
      // Its existing guard still applies.
      const x = await fetchJson('/api/public/paste', { method: 'POST', ip: freshIp(), body: { paste: body }, headers: { 'sec-fetch-site': 'cross-site' } });
      expect(await errorOf(x)).toBe('cross_site');
    } finally {
      await settings({ 'public.enabled': false, 'public.tracking': 'tracker' });
    }
  });
});

describe('timing-safe comparison', () => {
  it('compares with crypto.subtle.timingSafeEqual and rejects anything but the exact token', async () => {
    const t = 'A'.repeat(43);
    expect(csrfTokensMatch(t, t)).toBe(true);
    expect(csrfTokensMatch(`${'A'.repeat(42)}B`, t)).toBe(false);
    expect(csrfTokensMatch('A'.repeat(44), t)).toBe(false);
    expect(csrfTokensMatch('', t)).toBe(false);
    expect(csrfTokensMatch(undefined, t)).toBe(false);
    expect(csrfTokensMatch(t, null)).toBe(false);
    const spy = vi.spyOn(crypto.subtle, 'timingSafeEqual');
    try {
      csrfTokensMatch(`${'A'.repeat(42)}B`, t);
      csrfTokensMatch('short', t); // a wrong length still runs one comparison
      expect(spy).toHaveBeenCalledTimes(2);
      // …and so does the check on a real request.
      spy.mockClear();
      const ctx = createExecutionContext();
      const res = await worker.fetch(new Request(`${ORIGIN}/api/private/admin/settings`, { method: 'PATCH', headers: { cookie: oc, 'content-type': 'application/json', 'x-secbin-csrf': 'C'.repeat(43) }, body: '{}' }), env, ctx);
      await waitOnExecutionContext(ctx);
      expect(await errorOf(res)).toBe('csrf_mismatch');
      expect(spy).toHaveBeenCalled();
    } finally {
      spy.mockRestore();
    }
  });
});

describe('the csrfTokens setting (Admin → Settings)', () => {
  it('is on by default; off, a request without a token succeeds and every other guard still refuses', async () => {
    const ov = await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json();
    expect(ov.settings.csrfTokens).toBe(true);
    expect(ov.defaults.settings.csrfTokens).toBe(true);
    const u = await makeUser('csrf-off');
    const note = async () => ({ paste: (await encryptPaste({ text: 'x' })).body });
    expect(await errorOf(await send('POST', '/api/private/paste', { cookie: u.cookie, body: await note() }))).toBe('csrf_mismatch');
    expect((await settings({ csrfTokens: false })).status).toBe(200);
    try {
      // Effective at once (read with the session, no cache).
      expect((await send('POST', '/api/private/paste', { cookie: u.cookie, body: await note() })).status).toBe(201);
      // A header the client keeps sending is ignored, even a wrong one.
      expect((await send('POST', '/api/private/paste', { cookie: u.cookie, token: 'D'.repeat(43), body: await note() })).status).toBe(201);
      expect(await errorOf(await send('POST', '/api/private/paste', { cookie: u.cookie, body: await note(), headers: { 'sec-fetch-site': 'cross-site' } }))).toBe('cross_site');
      expect(await errorOf(await send('POST', '/api/private/paste', { cookie: u.cookie, body: await note(), headers: { 'sec-fetch-site': 'same-site' } }))).toBe('cross_site');
      expect((await fetchJson('/api/private/paste', { method: 'POST', cookie: u.cookie, csrf: false, headers: { 'content-type': 'text/plain' } })).status).toBe(415);
      expect(await errorOf(await send('POST', `/api/private/shares/kAAAAAAAAAAAAAAAAAAAAAA/revoke`, { cookie: u.cookie }))).toBe('missing_intent');
      expect(await errorOf(await send('DELETE', '/api/private/admin/users/AAAAAAAAAAAAAAAA'))).toBe('missing_intent');
      // The cookie is still issued, so turning it back on needs nothing from open pages but the one retry.
      const r = await loginRes('csrf-off', USER_PW);
      expect(TOKEN_RE.test(tokenOf(r))).toBe(true);
    } finally {
      // Turning it back on needs a token again (it is off right now, so this passes either way).
      expect((await settings({ csrfTokens: true })).status).toBe(200);
    }
    expect(await errorOf(await send('POST', '/api/private/paste', { cookie: u.cookie, body: await note() }))).toBe('csrf_mismatch');
  });

  it('only the owner changes it, and every change is in the admin audit as settings.csrf', async () => {
    const u = await makeUser('csrf-notowner');
    const r = await settings({ csrfTokens: false }, u.cookie);
    expect(r.status).toBe(403);
    expect((await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json()).settings.csrfTokens).toBe(true);
    // An impersonating owner cannot either.
    const imp = cookieOf(await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
    expect(await errorOf(await settings({ csrfTokens: false }, imp))).toBe('impersonating');
    await fetchJson('/api/private/admin/unimpersonate', { method: 'POST', cookie: imp, headers: intent });
    // Not a boolean → refused.
    expect(await errorOf(await settings({ csrfTokens: 'no' }))).toBe('invalid_setting');

    expect((await settings({ csrfTokens: false })).status).toBe(200);
    expect((await settings({ csrfTokens: true })).status).toBe(200);
    const rows = (await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json()).rows.filter((x) => x.action === 'settings.csrf');
    expect(rows.slice(0, 2).map((x) => x.detail)).toEqual(['from=false to=true', 'from=true to=false']);
    expect(rows.every((x) => x.subject_id === null)).toBe(true);
    // Saving the same value again logs nothing new under settings.csrf.
    await settings({ csrfTokens: true });
    expect((await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json()).rows.filter((x) => x.action === 'settings.csrf')).toHaveLength(rows.length);
  });

  it('travels in the export’s settings part, is restored on import, and the preview flags turning it off', async () => {
    const CURRENT = proofFor('owner-password');
    const exp = async () => (await (await fetchJson('/api/private/admin/export', { method: 'POST', cookie: oc, body: { current: CURRENT, system: { settings: true } } })).json()).document;
    const imp = (document, dryRun) => fetchJson('/api/private/admin/import', { method: 'POST', cookie: oc, body: { current: CURRENT, document, decisions: { system: { settings: true }, users: {} }, dryRun } });
    expect((await settings({ csrfTokens: false })).status).toBe(200);
    const offDoc = await exp();
    expect(offDoc.system.settings.csrfTokens).toBe(false);
    expect((await settings({ csrfTokens: true })).status).toBe(200);
    const onDoc = await exp();
    expect(onDoc.system.settings.csrfTokens).toBe(true);

    // Preview: turning it off is called out; nothing changes yet.
    const preview = await (await imp(offDoc, true)).json();
    expect(preview.plan.warnings).toEqual(expect.arrayContaining([expect.stringMatching(/csrfTokens: true → false/)]));
    expect(preview.plan.system.settings).toEqual(expect.arrayContaining([{ key: 'csrfTokens', from: true, to: false }]));
    expect((await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json()).settings.csrfTokens).toBe(true);
    // Applied: restored, and audited.
    expect((await imp(offDoc, false)).status).toBe(200);
    expect((await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json()).settings.csrfTokens).toBe(false);
    const audit = (await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json()).rows;
    expect(audit.some((x) => x.action === 'settings.csrf' && x.detail === 'import: from=true to=false')).toBe(true);
    // Turning it back on is not flagged.
    const back = await (await imp(onDoc, true)).json();
    expect(back.plan.warnings.some((w) => /csrfTokens/.test(w))).toBe(false);
    expect((await imp(onDoc, false)).status).toBe(200);
    expect((await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json()).settings.csrfTokens).toBe(true);
  });
});
