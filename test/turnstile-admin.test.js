// turnstile-admin.test.js — Turnstile keys set in the admin panel: the owner
// sets them with a confirmation; the secret is never returned; they switch
// the human check on (when the deployment sets no keys) and off again; the
// deployment's own keys win. Also: limits that mean nothing for the public
// account cannot be set for it.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import worker from '../src/index.js';
import { setSiteverify, invalidateTurnstileCache } from '../src/lib/turnstile.js';
import { owner, makeUser, fetchJson, freshIp, proofFor, USER_PW, ORIGIN } from './helpers.js';

const SITEKEY = '0x4AAAAAAAadminsitekey';
const SECRET = '0x4AAAAAAAadminsecretvalue';
const put = (body, cookie) => fetchJson('/api/private/admin/turnstile', { method: 'PUT', body, cookie, ip: freshIp() });
const status = (cookie) => fetchJson('/api/private/admin/turnstile', { cookie });
const errorOf = async (r) => (await r.json()).error;
const login = (username, password, token) => fetchJson('/api/auth/login', { method: 'POST', body: { username, proof: proofFor(password) }, ip: freshIp(), headers: token ? { 'x-secbin-turnstile': token } : {} });

let oc;
let restore;
beforeAll(async () => {
  oc = await owner();
  restore = setSiteverify(async (form) => Response.json(form.get('secret') === SECRET && form.get('response') === 'good'
    ? { success: true, hostname: new URL(ORIGIN).hostname, action: 'login' } : { success: false }));
});
afterAll(() => setSiteverify(restore));

describe('Turnstile keys from the admin panel', () => {
  it('needs the owner and a confirmation, validates, and never returns the secret', async () => {
    const u = await makeUser('ts-admin-user');
    expect((await put({ sitekey: SITEKEY, secret: SECRET, current: proofFor(USER_PW) }, u.cookie)).status).toBe(403);
    expect(await errorOf(await put({ sitekey: SITEKEY, secret: SECRET }, oc))).toBe('reauth_required');
    expect(await errorOf(await put({ sitekey: SITEKEY, secret: SECRET, current: proofFor('wrong-password-00') }, oc))).toBe('wrong_password');
    expect(await errorOf(await put({ sitekey: 'bad key!', secret: SECRET, current: proofFor('owner-password') }, oc))).toBe('invalid_sitekey');
    expect(await errorOf(await put({ sitekey: SITEKEY, current: proofFor('owner-password') }, oc))).toBe('invalid_secret'); // none saved yet
    expect(await (await status(oc)).json()).toMatchObject({ sitekey: null, secretSet: false, active: null, deployment: false });
  });

  it('switches the human check on and off; the site key can change alone', async () => {
    expect((await login('owner', 'owner-password')).status).toBe(200);
    const r = await put({ sitekey: SITEKEY, secret: SECRET, current: proofFor('owner-password') }, oc);
    expect(await r.json()).toMatchObject({ ok: true, sitekey: SITEKEY, secretSet: true });
    const st = await (await status(oc)).json();
    expect(st).toMatchObject({ sitekey: SITEKEY, secretSet: true, active: 'admin' });
    expect(JSON.stringify(st)).not.toContain(SECRET);
    // Login now needs a token; the public config offers the site key.
    expect(await errorOf(await login('owner', 'owner-password'))).toBe('turnstile_required');
    expect((await login('owner', 'owner-password', 'good')).status).toBe(200);
    expect((await (await fetchJson('/api/config')).json()).turnstile).toBe(SITEKEY);
    // A new site key alone keeps the saved secret.
    expect((await put({ sitekey: '0x4AAAAAAAothersitekey', current: proofFor('owner-password') }, oc)).status).toBe(200);
    expect((await login('owner', 'owner-password', 'good')).status).toBe(200);
    // The audit log names the site key, never the secret.
    const audit = await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json();
    const rows = audit.rows.filter((a) => a.action.startsWith('turnstile.'));
    expect(rows.length).toBeGreaterThan(0);
    expect(JSON.stringify(rows)).not.toContain(SECRET);
    // Off again.
    expect((await put({ clear: true, current: proofFor('owner-password') }, oc)).status).toBe(200);
    expect((await login('owner', 'owner-password')).status).toBe(200);
    expect((await (await fetchJson('/api/config')).json()).turnstile).toBeNull();
  });

  it("the deployment's keys win and cannot be changed here", async () => {
    await put({ sitekey: SITEKEY, secret: SECRET, current: proofFor('owner-password') }, oc);
    const TS_ENV = { ...env, TURNSTILE_SITEKEY: '0x4AAAAAAAdeploysitekey', TURNSTILE_SECRET: '0x4AAAAAAAdeploysecretval' };
    const ctx = createExecutionContext();
    const res = await worker.fetch(new Request(`${ORIGIN}/api/private/admin/turnstile`, { headers: { cookie: oc } }), TS_ENV, ctx);
    await waitOnExecutionContext(ctx);
    expect(await res.json()).toMatchObject({ active: 'env', deployment: true });
    const c2 = createExecutionContext();
    const cfg = await worker.fetch(new Request(`${ORIGIN}/api/config`), TS_ENV, c2);
    await waitOnExecutionContext(c2);
    expect((await cfg.json()).turnstile).toBe('0x4AAAAAAAdeploysitekey');
    await put({ clear: true, current: proofFor('owner-password') }, oc);
    invalidateTurnstileCache();
  });
});

describe('the public account', () => {
  it('refuses limits that do not apply to it; inheriting them is fine', async () => {
    const set = (patch) => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: 'public-user-0000', channel: 'all', patch } });
    for (const k of ['apiEnabled', 'receiptIp', 'logMaxEntries', 'pwMinLength', 'passkeys']) {
      const v = k === 'passkeys' ? 'any' : k === 'logMaxEntries' || k === 'pwMinLength' ? 20 : true;
      const r = await set({ [k]: v });
      expect(r.status, k).toBe(400);
      expect((await r.json()).message, k).toMatch(/does not apply to the public account/);
      expect((await set({ [k]: 'inherit' })).status, k).toBe(200);
    }
    expect((await set({ maxViews: 5 })).status).toBe(200);
  });
});
