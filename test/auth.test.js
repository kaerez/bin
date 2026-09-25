// auth.test.js — owner setup / recovery, login, sessions (encrypted+signed
// JWT cookie: tamper, idle/absolute timeouts, revocation), CSRF guards, the
// /dashboard gate, API keys and graceful behaviour with missing env vars.
import { env, SELF } from 'cloudflare:test';
import { describe, it, expect, beforeAll, vi, afterEach } from 'vitest';
import { ORIGIN, AUTHN, owner, setOwnerCookie, login, makeUser, fetchJson, cookieOf, salt16, proofFor, intent, freshIp, createNote } from './helpers.js';
import worker from '../src/index.js';
import { sealToken, openToken } from '../src/lib/jwt.js';
import { sessionKeys, authnToken, bfpDisabled } from '../src/lib/config.js';

let oc;
beforeAll(async () => { oc = await owner(); });
afterEach(() => { vi.useRealTimers(); });

/** Call the Worker with a modified env (e.g. a missing secret). */
const callWith = (overrides, path, init = {}) => worker.fetch(new Request(`${ORIGIN}${path}`, init), { ...env, ...overrides }, { waitUntil() {} });

describe('setup and recovery', () => {
  it('the setup token is single-use; reuse is refused', async () => {
    const st = await (await fetchJson('/api/auth/setup')).json();
    expect(st.enabled).toBe(false); // consumed by owner()
    const r = await fetchJson('/api/auth/setup', { method: 'POST', body: { token: AUTHN, username: 'owner', salt: salt16(), t: 3, proof: proofFor('x') } });
    expect(r.status).toBe(410);
    expect((await r.json()).error).toBe('token_used');
  });

  it('a wrong token is 403; a NEW token recovers the owner (password reset, sessions revoked)', async () => {
    const ip = freshIp();
    const bad = await fetchJson('/api/auth/setup', { method: 'POST', ip, body: { token: 'nope-nope-nope-nope-nope-nope-nope-1', username: 'owner', salt: salt16(), t: 3, proof: proofFor('x') } });
    expect(bad.status).toBe(403);
    const NEW = 'a-brand-new-recovery-token-0123456789';
    const rec = await callWith({ AUTHN: NEW }, '/api/auth/setup', {
      method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': ip },
      body: JSON.stringify({ token: NEW, username: 'owner', salt: salt16(), t: 3, proof: proofFor('recovered-pass') }),
    });
    expect(rec.status).toBe(200);
    expect((await rec.json()).recovered).toBe(true);
    // Old session is gone; the new password works.
    expect((await fetchJson('/api/private/me', { cookie: oc })).status).toBe(401);
    oc = await login('owner', 'recovered-pass');
    setOwnerCookie(oc);
    expect((await fetchJson('/api/private/me', { cookie: oc })).status).toBe(200);
  });

  it('with AUTHN deleted/short, setup is cleanly disabled for any input', async () => {
    for (const AUTHN_ of [undefined, '', 'short']) {
      const g = await callWith({ AUTHN: AUTHN_ }, '/api/auth/setup');
      expect(await g.json()).toMatchObject({ enabled: false });
      const p = await callWith({ AUTHN: AUTHN_ }, '/api/auth/setup', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"token":"anything"}' });
      expect(p.status).toBe(404);
      const garbage = await callWith({ AUTHN: AUTHN_ }, '/api/auth/setup', { method: 'POST', body: 'not json at all' });
      expect(garbage.status).toBe(404);
    }
    expect(authnToken({})).toBeNull();
  });
});

describe('login and sessions', () => {
  it('wrong password → 401; prelogin never reveals whether a user exists', async () => {
    const ip = freshIp();
    const r = await fetchJson('/api/auth/login', { method: 'POST', ip, body: { username: 'owner', proof: proofFor('wrong') } });
    expect(r.status).toBe(401);
    const known = await (await fetchJson('/api/auth/prelogin', { method: 'POST', ip, body: { username: 'owner' } })).json();
    const unknown1 = await (await fetchJson('/api/auth/prelogin', { method: 'POST', ip, body: { username: 'nobody-here' } })).json();
    const unknown2 = await (await fetchJson('/api/auth/prelogin', { method: 'POST', ip, body: { username: 'nobody-here' } })).json();
    expect(Object.keys(known).sort()).toEqual(['salt', 't']);
    expect(unknown1).toEqual(unknown2); // stable fake salt
    expect(unknown1.salt).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it('the cookie is __Host-, HttpOnly, Secure, SameSite=Strict', async () => {
    const r = await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'owner', proof: proofFor('recovered-pass') } });
    const sc = r.headers.get('set-cookie');
    expect(sc).toMatch(/^__Host-secbin_sess=/);
    for (const attr of ['HttpOnly', 'Secure', 'SameSite=Strict', 'Path=/']) expect(sc).toContain(attr);
  });

  it('tampered, re-signed-with-wrong-key or alg-confused tokens are rejected', async () => {
    const keys = sessionKeys(env);
    const tok = oc.split('=')[1];
    const flipped = tok.slice(0, -3) + (tok.at(-3) === 'A' ? 'B' : 'A') + tok.slice(-2);
    expect((await fetchJson('/api/private/me', { cookie: `__Host-secbin_sess=${flipped}` })).status).toBe(401);
    const other = { sig: new Uint8Array(32).fill(9), enc: keys.enc };
    const claims = await openToken(keys, tok);
    expect(claims).toBeTruthy();
    const forged = await sealToken(other, claims);
    expect((await fetchJson('/api/private/me', { cookie: `__Host-secbin_sess=${forged}` })).status).toBe(401);
    const none = `${btoa('{"alg":"none"}').replace(/=/g, '')}..AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA`;
    expect(await openToken(keys, none)).toBeNull();
  });

  it('idle and absolute timeouts are enforced from admin settings', async () => {
    const r = await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'session.idleSec': 600, 'session.absSec': 3600 } });
    expect(r.status).toBe(200);
    const c = await login('owner', 'recovered-pass');
    vi.useFakeTimers({ now: Date.now() + 601 * 1000, toFake: ['Date'] });
    expect((await fetchJson('/api/private/me', { cookie: c })).status).toBe(401);
    vi.useRealTimers();
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'session.idleSec': 43200, 'session.absSec': 604800 } });
  });

  it('logout revokes the session server-side', async () => {
    const c = await login('owner', 'recovered-pass');
    expect((await fetchJson('/api/auth/logout', { method: 'POST', cookie: c })).status).toBe(400); // missing intent header
    const out = await fetchJson('/api/auth/logout', { method: 'POST', cookie: c, headers: intent });
    expect(out.status).toBe(200);
    expect(out.headers.get('set-cookie')).toContain('Max-Age=0');
    expect((await fetchJson('/api/private/me', { cookie: c })).status).toBe(401);
  });

  it('without SIG/ENC, login answers 503 and public viewing still works', async () => {
    const n = await createNote(oc, { text: 'public still works' });
    for (const o of [{ SIG: undefined }, { ENC: '' }, { SIG: env.ENC }, { SIG: 'zz' }]) {
      const r = await callWith(o, '/api/auth/login', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"username":"owner","proof":"x"}' });
      expect(r.status).toBe(503);
      expect((await r.json()).error).toBe('server_not_configured');
      const h = await callWith(o, `/api/paste/${n.id}`);
      expect(h.status).toBe(200);
    }
  });
});

describe('/dashboard gate', () => {
  it('redirects anonymous visitors to login, serves login/setup, adds security headers', async () => {
    const r = await SELF.fetch(`${ORIGIN}/dashboard/`, { redirect: 'manual' });
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/dashboard/login/');
    const l = await SELF.fetch(`${ORIGIN}/dashboard/login/`, { redirect: 'manual' });
    expect(l.status).toBe(200);
    expect(l.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
    const s = await SELF.fetch(`${ORIGIN}/dashboard/setup/`, { redirect: 'manual' });
    expect(s.status).toBe(200);
    const authed = await SELF.fetch(`${ORIGIN}/dashboard/`, { headers: { cookie: oc }, redirect: 'manual' });
    expect(authed.status).toBe(200);
    expect(authed.headers.get('cache-control')).toBe('no-store');
  });

  it('keeps non-owners out of /dashboard/admin', async () => {
    const u = await makeUser('gate-user');
    const r = await SELF.fetch(`${ORIGIN}/dashboard/admin/`, { headers: { cookie: u.cookie }, redirect: 'manual' });
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/dashboard/');
  });
});

describe('API keys', () => {
  it('need admin permission, authenticate creation only, and die when API access is revoked', async () => {
    const u = await makeUser('api-user');
    expect((await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { name: 'cli' } })).status).toBe(403);
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch: { apiEnabled: true, apiMaxKeys: 1 } } });
    const k = await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { name: 'cli' } });
    expect(k.status).toBe(201);
    const { key } = await k.json();
    expect(key).toMatch(/^sbk_/);
    expect((await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { name: 'second' } })).status).toBe(409);
    const bearer = { authorization: `Bearer ${key}` };
    const n = await createNote(null, { text: 'via api' }, { headers: bearer });
    expect(n.res.status).toBe(201);
    expect((await fetchJson('/api/private/me', { headers: bearer })).status).toBe(403); // not for account endpoints
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch: { apiEnabled: false } } });
    expect((await createNote(null, { text: 'again' }, { headers: bearer })).res.status).toBe(401);
  });
});

describe('config parsing never throws', () => {
  it('handles odd DISABLE_BFP values', () => {
    expect(bfpDisabled({})).toEqual({ all: false, setup: false });
    expect(bfpDisabled({ DISABLE_BFP: ' TRUE ' })).toEqual({ all: true, setup: true });
    expect(bfpDisabled({ DISABLE_BFP_SETUP: 'True' })).toEqual({ all: false, setup: true });
    expect(bfpDisabled({ DISABLE_BFP: 'yes', DISABLE_BFP_SETUP: '1' })).toEqual({ all: false, setup: false });
    expect(sessionKeys({ SIG: null, ENC: 42 })).toBeNull();
  });
  it('cookie helper roundtrip', async () => {
    const r = await fetchJson('/api/auth/session', { cookie: oc });
    expect((await r.json()).authenticated).toBe(true);
    expect(cookieOf(r) === null || cookieOf(r).startsWith('__Host-')).toBe(true);
  });
});
