// turnstile.test.js — the Cloudflare Turnstile human check: off unless both
// TURNSTILE_SITEKEY and TURNSTILE_SECRET are set; when on, login, a signed-in
// password change and starting an anonymous share need a token that
// siteverify accepts for this hostname and this form's action. Admin password
// resets, file chunks/finalize and API keys never need one. Only the pages
// that show the widget get the relaxed CSP (and no COEP).
import { describe, it, expect, beforeAll, afterEach } from 'vitest';
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import worker from '../src/index.js';
import { setSiteverify, turnstileConfig } from '../src/lib/turnstile.js';
import { CSP } from '../src/lib/http.js';
import { owner, makeUser, fetchJson, freshIp, cookieOf, salt16, proofFor, ORIGIN } from './helpers.js';
import { encryptPaste } from '../public/js/crypto.js';
import { invalidateGuardCaches } from '../src/lib/guard.js';

const SITEKEY = '0x4AAAAAAAtestsitekey';
const TS_ENV = { ...env, TURNSTILE_SITEKEY: SITEKEY, TURNSTILE_SECRET: '0x4AAAAAAAtestsecretvalue' };
const HOST = new URL(ORIGIN).hostname;

/** The Worker with Turnstile configured (SELF runs without it). */
async function tsFetch(path, { method = 'GET', body, cookie, headers = {}, ip, token } = {}) {
  const h = { ...headers };
  if (body !== undefined) h['content-type'] = 'application/json';
  if (cookie) h.cookie = cookie;
  if (ip) h['cf-connecting-ip'] = ip;
  if (token) h['x-secbin-turnstile'] = token;
  const ctx = createExecutionContext();
  const res = await worker.fetch(new Request(`${ORIGIN}${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' }), TS_ENV, ctx);
  await waitOnExecutionContext(ctx);
  return res;
}

// A fake siteverify: tokens "ok:<action>[#n]" pass for that action on this host;
// each token is accepted once (as Cloudflare does).
let calls = [];
function fakeSiteverify({ host = HOST, testing = false, down = false } = {}) {
  const seen = new Set();
  return setSiteverify(async (form) => {
    calls.push(Object.fromEntries(form.entries()));
    if (down) throw new Error('network');
    const t = form.get('response');
    if (testing) return Response.json({ success: true, hostname: 'example.com', metadata: { result_with_testing_key: true } });
    if (seen.has(t)) return Response.json({ success: false, 'error-codes': ['timeout-or-duplicate'] });
    seen.add(t);
    const m = /^ok:([^#]+)/.exec(t);
    return Response.json(m ? { success: true, hostname: host, action: m[1] } : { success: false, 'error-codes': ['invalid-input-response'] });
  });
}
let restore;
beforeAll(async () => { await owner(); });
afterEach(() => { if (restore) setSiteverify(restore); restore = null; calls = []; });
const withFake = (o) => { const prev = fakeSiteverify(o); if (!restore) restore = prev; };

const loginBody = (u, pw) => ({ username: u, proof: proofFor(pw) });
const errorOf = async (r) => (await r.json()).error;

describe('configuration', () => {
  it('is off unless both keys are set and well-formed', () => {
    expect(turnstileConfig(env)).toBeNull();
    expect(turnstileConfig({ TURNSTILE_SITEKEY: SITEKEY })).toBeNull();
    expect(turnstileConfig({ TURNSTILE_SITEKEY: SITEKEY, TURNSTILE_SECRET: 'x' })).toBeNull();
    expect(turnstileConfig(TS_ENV)).toEqual({ sitekey: SITEKEY, secret: TS_ENV.TURNSTILE_SECRET });
  });

  it('/api/config publishes the site key only when on', async () => {
    expect((await (await fetchJson('/api/config')).json()).turnstile).toBeNull();
    expect((await (await tsFetch('/api/config')).json()).turnstile).toBe(SITEKEY);
  });

  it('without Turnstile, login needs no token', async () => {
    const r = await fetchJson('/api/auth/login', { method: 'POST', body: loginBody('owner', 'owner-password'), ip: freshIp() });
    expect(r.status).toBe(200);
  });
});

describe('login', () => {
  it('needs a token for the "login" action, used once, for this host', async () => {
    withFake();
    const ip = freshIp();
    const body = loginBody('owner', 'owner-password');
    expect(await errorOf(await tsFetch('/api/auth/login', { method: 'POST', body, ip }))).toBe('turnstile_required');
    expect(await errorOf(await tsFetch('/api/auth/login', { method: 'POST', body, ip, token: 'ok:password' }))).toBe('turnstile_failed');
    expect(await errorOf(await tsFetch('/api/auth/login', { method: 'POST', body, ip, token: 'garbage' }))).toBe('turnstile_failed');
    const ok = await tsFetch('/api/auth/login', { method: 'POST', body, ip, token: 'ok:login' });
    expect(ok.status).toBe(200);
    // The same token again: refused (single use).
    expect(await errorOf(await tsFetch('/api/auth/login', { method: 'POST', body, ip, token: 'ok:login' }))).toBe('turnstile_failed');
    // siteverify got the secret, the token and the client address.
    expect(calls.at(-1)).toMatchObject({ secret: TS_ENV.TURNSTILE_SECRET, response: 'ok:login', remoteip: ip });
  });

  it('refuses a token issued for another hostname', async () => {
    withFake({ host: 'evil.example' });
    const r = await tsFetch('/api/auth/login', { method: 'POST', body: loginBody('owner', 'owner-password'), ip: freshIp(), token: 'ok:login' });
    expect(await errorOf(r)).toBe('turnstile_failed');
  });

  it('checks the token before the password (a bot learns nothing)', async () => {
    withFake();
    const r = await tsFetch('/api/auth/login', { method: 'POST', body: loginBody('owner', 'wrong-password'), ip: freshIp() });
    expect(await errorOf(r)).toBe('turnstile_required');
  });

  it('fails closed when siteverify is unreachable', async () => {
    withFake({ down: true });
    const r = await tsFetch('/api/auth/login', { method: 'POST', body: loginBody('owner', 'owner-password'), ip: freshIp(), token: 'ok:login' });
    expect(r.status).toBe(503);
    expect(await errorOf(r)).toBe('turnstile_unavailable');
  });

  it("accepts Cloudflare's testing-key results as they are", async () => {
    withFake({ testing: true });
    const r = await tsFetch('/api/auth/login', { method: 'POST', body: loginBody('owner', 'owner-password'), ip: freshIp(), token: 'XXXX.DUMMY.TOKEN.XXXX' });
    expect(r.status).toBe(200);
  });
});

describe('password changes', () => {
  it('a signed-in change needs a "password" token; an admin reset does not', async () => {
    withFake();
    const u = await makeUser('ts-pw', 'user-password-123');
    const change = (token, next) => tsFetch('/api/private/me/password', {
      method: 'POST', cookie: u.cookie, token, ip: freshIp(),
      body: { current: proofFor('user-password-123'), salt: salt16(), t: 3, proof: proofFor(next) },
    });
    expect(await errorOf(await change(undefined, 'user-password-456'))).toBe('turnstile_required');
    expect(await errorOf(await change('ok:login', 'user-password-456'))).toBe('turnstile_failed');
    const ok = await change('ok:password', 'user-password-456');
    expect(ok.status).toBe(200);

    const oc = cookieOf(await tsFetch('/api/auth/login', { method: 'POST', body: loginBody('owner', 'owner-password'), ip: freshIp(), token: 'ok:login#2' }));
    const reset = await tsFetch(`/api/private/admin/users/${u.id}/password`, { method: 'POST', cookie: oc, body: { salt: salt16(), t: 3, proof: proofFor('reset-by-admin-1') } });
    expect(reset.status).toBe(200);
  });
});

describe('anonymous shares', () => {
  it('starting one needs a "public-share" token; accounts and API keys do not', async () => {
    withFake();
    const oc = await owner();
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'public.enabled': true, 'public.tracking': 'ip' } });
    invalidateGuardCaches();
    const note = async (token) => tsFetch('/api/public/paste', { method: 'POST', ip: freshIp(), token, body: { paste: (await encryptPaste({ text: 'hi', bar: true, views: 1, expire: '1h' })).body } });
    expect(await errorOf(await note())).toBe('turnstile_required');
    expect(await errorOf(await note('ok:login'))).toBe('turnstile_failed');
    expect((await note('ok:public-share')).status).toBe(201);
    // A signed-in account creates without a check.
    const u = await makeUser('ts-share');
    const mine = await tsFetch('/api/private/paste', { method: 'POST', cookie: u.cookie, body: { paste: (await encryptPaste({ text: 'hi', bar: true, views: 1, expire: '1h' })).body } });
    expect(mine.status).toBe(201);
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'public.enabled': false } });
    invalidateGuardCaches();
  });
});

describe('headers', () => {
  const policyOf = async (path, cookie) => {
    const r = await tsFetch(path, { cookie });
    return { csp: r.headers.get('content-security-policy'), coep: r.headers.get('cross-origin-embedder-policy'), status: r.status };
  };

  it('login and account allow the widget; other pages stay strict', async () => {
    const login = await policyOf('/dashboard/login/');
    expect(login.status).toBe(200);
    expect(login.csp).toContain('script-src \'self\' \'wasm-unsafe-eval\' https://challenges.cloudflare.com');
    expect(login.csp).toContain('frame-src https://challenges.cloudflare.com');
    expect(login.csp).toContain("require-trusted-types-for 'script'");
    expect(login.coep).toBeNull();

    const oc = await owner();
    const account = await policyOf('/dashboard/account/', oc);
    expect(account.csp).toContain('frame-src https://challenges.cloudflare.com');
    for (const p of ['/dashboard/', '/dashboard/shares/', '/dashboard/setup/', '/p/bAAAAAAAAAAAAAAAAAAAAAA']) {
      const s = await policyOf(p, oc);
      expect(s.csp, p).toBe(CSP);
      expect(s.coep, p).toBe('require-corp');
    }
    // Without Turnstile, even login is strict.
    const plain = await fetchJson('/dashboard/login/');
    expect(plain.headers.get('content-security-policy')).toBe(CSP);
    expect(plain.headers.get('cross-origin-embedder-policy')).toBe('require-corp');
  });

  it('the home page stays cacheable (the offline shell), the app does not', async () => {
    const home = await tsFetch('/');
    expect(home.status).toBe(200);
    expect(home.headers.get('cache-control') || '').not.toContain('no-store');
    const login = await tsFetch('/dashboard/login/');
    expect(login.headers.get('cache-control')).toBe('no-store');
  });

  it('the home page allows it only while anonymous sharing is on', async () => {
    const oc = await owner();
    invalidateGuardCaches();
    expect((await policyOf('/')).csp).toBe(CSP);
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'public.enabled': true } });
    invalidateGuardCaches();
    const on = await policyOf('/');
    expect(on.csp).toContain('frame-src https://challenges.cloudflare.com');
    expect(on.coep).toBeNull();
    expect((await policyOf('/p/bAAAAAAAAAAAAAAAAAAAAAA')).csp).toBe(CSP);
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'public.enabled': false } });
    invalidateGuardCaches();
  });
});
