// audit-auth.test.js — regression tests for the authentication findings of
// the security audit of main (a707905):
//   F-1  impersonation never extends the owner's session: each switch keeps
//        the sign-in's absolute timeout and revokes the session it replaces;
//   F-2  the owner's own username changes only on Account (with the step-up);
//   F-3  the prelogin fake salt, the anonymous tracker's tag and the public
//        quota subjects each use a key of their own (HKDF), so a fake salt
//        cannot be turned into a tracker id the server accepts;
//   F-4  admin changes that weaken a security control need the owner's
//        password or a passkey; tightening needs nothing.
// Synthetic accounts and data only.
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { runInDurableObject } from 'cloudflare:test';
import { owner, makeUser, login, fetchJson, cookieOf, csrfFor, freshIp, intent, proofFor, OWNER_STEP, ORIGIN } from './helpers.js';
import { SoftAuthenticator } from './soft-authenticator.js';
import { dirStub } from './reverse-helpers.js';
import { weakenedSettings, weakenedLimits, settingsWithDefaults, resolveLimits } from '../src/lib/settings.js';
import { b64urlFromBytes, bytesFromB64url, utf8 } from '../public/js/bytes.js';
import { encryptPaste } from '../public/js/crypto.js';

let oc;
let ownerId;
beforeAll(async () => {
  oc = await owner();
  ownerId = (await (await fetchJson('/api/private/me', { cookie: oc })).json()).user.id;
});
afterEach(() => { vi.useRealTimers(); });

const errorOf = async (r) => (await r.clone().json()).error;
const me = async (cookie) => fetchJson('/api/private/me', { cookie, alias: false });
// These send exactly the confirmation given (`step: false`: none added by the helpers).
const settings = (patch, step = {}, cookie = oc) => fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie, body: { ...patch, ...step }, step: false });
const limits = (scope, patch, step = {}, channel = 'all') => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope, channel, patch, ...step }, step: false });
const ipRule = (cidr, action, step = {}) => fetchJson('/api/private/admin/ip-rules', { method: 'POST', cookie: oc, body: { cidr, action, note: 'audit-auth', ...step }, step: false });
const overview = async () => (await fetchJson('/api/private/admin/overview', { cookie: oc })).json();
/** Start impersonating `uid` with `cookie` (the replaced cookie is sent as it is) → the impersonation cookie. */
const impersonate = async (cookie, uid) => {
  const r = await fetchJson(`/api/private/admin/users/${uid}/impersonate`, { method: 'POST', cookie, headers: intent, alias: false });
  expect(r.status).toBe(200);
  return cookieOf(r);
};
const unimpersonate = async (cookie) => {
  const r = await fetchJson('/api/private/admin/unimpersonate', { method: 'POST', cookie, headers: intent, alias: false });
  expect(r.status).toBe(200);
  return cookieOf(r);
};
/** A weakening change is refused without the step-up, naming what it weakens. */
const needsStepUp = async (r, weakens) => {
  expect([r.status, await errorOf(r)]).toEqual([400, 'reauth_required']);
  expect((await r.json()).weakens).toEqual(weakens);
};

describe('F-1: impersonation keeps the absolute timeout and revokes the replaced session', () => {
  it('each switch revokes the session it replaces; the new one ends when the sign-in does; the page binding changes', async () => {
    const u = await makeUser('aa-imp-target');
    const start = await login('owner', 'owner-password', freshIp());
    const endsAt = (await (await me(start)).json()).session.endsAt;
    const ic = await impersonate(start, u.id);
    expect((await me(start)).status).toBe(401); // the owner's session it replaced
    const asUser = await (await me(ic)).json();
    expect(asUser).toMatchObject({ user: { id: u.id }, impersonatedBy: 'owner' });
    expect(asUser.session.endsAt).toBe(endsAt);
    const back = await unimpersonate(ic);
    expect((await me(ic)).status).toBe(401); // the impersonation session
    const mine = await (await me(back)).json();
    expect(mine.user.id).toBe(ownerId);
    expect(mine.session.endsAt).toBe(endsAt);
    // A new session each time: its CSRF token differs, so pages loaded before say "session changed".
    expect(new Set([await csrfFor(start), await csrfFor(ic), await csrfFor(back)]).size).toBe(3);
  });

  it('cycling every 100 s against a 300 s absolute timeout is refused at 300 s', async () => {
    const u = await makeUser('aa-imp-cycle');
    expect((await settings({ 'session.idleSec': 300, 'session.absSec': 300 })).status).toBe(200); // tightening: no step-up
    const t0 = Date.now();
    vi.useFakeTimers({ now: t0, toFake: ['Date'] });
    const ip = freshIp();
    let cycled = await login('owner', 'owner-password', ip);
    const control = await login('owner', 'owner-password', ip);
    const iat = Math.floor(t0 / 1000);
    for (let i = 1; i <= 2; i++) {
      vi.setSystemTime(t0 + i * 100_000);
      cycled = await unimpersonate(await impersonate(cycled, u.id));
      const s = (await (await me(cycled)).json()).session;
      expect(s.endsAt).toBe(iat + 300); // not moved by the cycle
      expect((await me(control)).status).toBe(200);
    }
    vi.setSystemTime(t0 + 301_000);
    expect((await me(control)).status).toBe(401);
    expect((await me(cycled)).status).toBe(401);
    const again = await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: cycled, headers: intent, alias: false });
    expect(again.status).toBe(401);
    vi.useRealTimers();
    // Back to the defaults: longer sessions weaken the timeout, so they need the step-up.
    const fresh = await login('owner', 'owner-password', freshIp());
    await needsStepUp(await settings({ 'session.idleSec': 43200, 'session.absSec': 604800 }, {}, fresh), ['session.idleSec', 'session.absSec']);
    expect((await settings({ 'session.idleSec': 43200, 'session.absSec': 604800 }, OWNER_STEP, fresh)).status).toBe(200);
  });
});

describe('F-2: the owner\'s own username', () => {
  it('is never changed through Admin → Users (use Account, with the step-up); other users are renamed there as before', async () => {
    const r = await fetchJson(`/api/private/admin/users/${ownerId}`, { method: 'PATCH', cookie: oc, body: { username: 'aa-owner-renamed' } });
    expect([r.status, await errorOf(r)]).toEqual([403, 'use_account_page']);
    const both = await fetchJson(`/api/private/admin/users/${ownerId}`, { method: 'PATCH', cookie: oc, body: { username: 'aa-owner-renamed', disabled: false } });
    expect(await errorOf(both)).toBe('use_account_page');
    expect((await (await me(oc)).json()).user.username).toBe('owner');
    const v = await makeUser('aa-rename-me');
    const ok = await fetchJson(`/api/private/admin/users/${v.id}`, { method: 'PATCH', cookie: oc, body: { username: 'aa-renamed' } });
    expect([ok.status, (await ok.json()).user.username]).toEqual([200, 'aa-renamed']);
    // Account: the password (or a passkey) is needed.
    const acct = (body) => fetchJson('/api/private/me/username', { method: 'POST', cookie: oc, body, ip: freshIp() });
    expect(await errorOf(await acct({ username: 'aa-owner-renamed' }))).toBe('reauth_required');
    expect((await acct({ username: 'aa-owner-renamed', ...OWNER_STEP })).status).toBe(200);
    expect((await acct({ username: 'owner', ...OWNER_STEP })).status).toBe(200);
  });
});

describe('F-3: separate keys for the prelogin fake salt, the tracker tag and the public subjects', () => {
  const prelogin = async (username, ip = freshIp()) => (await fetchJson('/api/auth/prelogin', { method: 'POST', ip, body: { username } })).json();
  const secret = () => runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec("SELECT v FROM meta WHERE k = 'secret'").one().v);
  const hmac = async (key, msg) => new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8(msg)));
  const rawKey = async (sec) => crypto.subtle.importKey('raw', utf8(sec), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const derived = async (sec, info) => crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: utf8(info) },
    await crypto.subtle.importKey('raw', utf8(sec), 'HKDF', false, ['deriveKey']), { name: 'HMAC', hash: 'SHA-256', length: 256 }, false, ['sign']);
  const tracker = async (ip, value) => {
    const r = await fetchJson('/api/public/t', { ip, headers: value ? { cookie: `__Host-secbin_aid=${value}`, 'x-secbin-aid-copies': `ls=${value};idb=${value}` } : {} });
    return r.json();
  };

  it('the fake salt is stable per name (any case), shaped like a real salt, and keyed for this use alone', async () => {
    const real = await prelogin('owner');
    const a = await prelogin('aa-nobody');
    expect(await prelogin('aa-nobody')).toEqual(a);
    expect(await prelogin('AA-NOBODY')).toEqual(a);
    expect((await prelogin('aa-somebody-else')).salt).not.toBe(a.salt);
    for (const x of [real, a]) expect(x.salt).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(Object.keys(a).sort()).toEqual(Object.keys(real).sort());
    expect(a.t).toBe(real.t);
    const sec = await secret();
    // HMAC under the key derived for the fake salt, never under the Directory's secret itself.
    expect(a.salt).toBe(b64urlFromBytes((await hmac(await derived(sec, 'secbin-directory/prelogin-salt/v1'), 'aa-nobody')).subarray(0, 16)));
    expect(a.salt).not.toBe(b64urlFromBytes((await hmac(await rawKey(sec), 'aa-nobody')).subarray(0, 16)));
  });

  it('a tracker id forged from a prelogin salt is not accepted (the audit\'s PoC); server-issued ids still are', async () => {
    expect((await settings({ 'public.enabled': true, 'public.tracking': 'tracker' }, OWNER_STEP)).status).toBe(200);
    try {
      // A body whose base64url has no upper-case letter (prelogin lower-cases the name), issued a minute ago.
      const lead = bytesFromB64url('a'.repeat(16));
      let body = null;
      for (let t = Math.floor(Date.now() / 1000) - 60; !body; t--) {
        const b = new Uint8Array(16);
        b.set(lead, 0);
        new DataView(b.buffer).setUint32(12, t);
        const s = b64urlFromBytes(b);
        if (s === s.toLowerCase()) body = s;
      }
      const pre = await prelogin(`secbin-public/tid:${body}`);
      const forged = b64urlFromBytes(new Uint8Array([...bytesFromB64url(body), ...bytesFromB64url(pre.salt).subarray(0, 8)]));
      const ip = freshIp();
      const got = await tracker(ip, forged);
      expect(got.status).toBe('new');
      expect(got.aid).not.toBe(forged);
      // Nothing is created under it; under the id the server issued, it is.
      const create = async (aid) => fetchJson('/api/public/paste', { method: 'POST', ip, headers: { cookie: `__Host-secbin_aid=${aid}`, 'x-secbin-aid': aid },
        body: { paste: (await encryptPaste({ text: 'aa synthetic', bar: true, views: 1, expire: '1h' })).body } });
      const refused = await create(forged);
      expect([refused.status, await errorOf(refused)]).toEqual([428, 'tracker_required']);
      expect((await create(got.aid)).status).toBe(201);
      // The id the server issued is kept, and its tag is the tracker key's alone.
      expect(await tracker(freshIp(), got.aid)).toMatchObject({ aid: got.aid, status: 'ok' });
      const b = bytesFromB64url(got.aid);
      const sec = await secret();
      const msg = `secbin-public/tid:${b64urlFromBytes(b.subarray(0, 16))}`;
      expect(b64urlFromBytes(b.subarray(16))).toBe(b64urlFromBytes((await hmac(await derived(sec, 'secbin-directory/tracker-tag/v1'), msg)).subarray(0, 8)));
      // A fake salt never starts with a valid tag.
      const salt = bytesFromB64url((await prelogin(msg.toLowerCase())).salt);
      expect(b64urlFromBytes(salt.subarray(0, 8))).not.toBe(b64urlFromBytes(b.subarray(16)));
    } finally {
      await settings({ 'public.enabled': false });
    }
  });
});

describe('F-4: weakening a security control needs the owner\'s password or a passkey', () => {
  it('settings: CSRF tokens off, looser lockout, brute-force and rate limits, longer sessions, less log kept', async () => {
    const cases = [
      [{ csrfTokens: false }, ['csrfTokens'], { csrfTokens: true }],
      [{ 'lockout.max': 11 }, ['lockout.max'], { 'lockout.max': 10 }],
      [{ 'lockout.windowSec': 60 }, ['lockout.windowSec'], { 'lockout.windowSec': 600 }],
      [{ 'lockout.lockSec': 60 }, ['lockout.lockSec'], { 'lockout.lockSec': 900 }],
      [{ 'guard.login.max': 20 }, ['guard.login.max'], { 'guard.login.max': 10 }],
      [{ 'guard.invalid.windowSec': 60 }, ['guard.invalid.windowSec'], { 'guard.invalid.windowSec': 600 }],
      [{ 'guard.setup.blockSec': 60 }, ['guard.setup.blockSec'], { 'guard.setup.blockSec': 3600 }],
      [{ 'guard.v6Prefix': 128 }, ['guard.v6Prefix'], { 'guard.v6Prefix': 64 }],
      [{ 'session.absSec': 8 * 86400 }, ['session.absSec'], { 'session.absSec': 7 * 86400 }],
      [{ 'public.newTrackersPerIp': 50 }, ['public.newTrackersPerIp'], { 'public.newTrackersPerIp': 5 }],
      [{ 'public.newTrackersWindowSec': 3600 }, ['public.newTrackersWindowSec'], { 'public.newTrackersWindowSec': 86400 }],
      [{ 'log.maxAgeSec': 30 * 86400 }, ['log.maxAgeSec'], { 'log.maxAgeSec': 365 * 86400 }],
      [{ 'log.maxEntries': 1000 }, ['log.maxEntries'], { 'log.maxEntries': 500000 }],
      [{ 'log.ownerMaxAgeSec': 30 * 86400 }, ['log.ownerMaxAgeSec'], { 'log.ownerMaxAgeSec': null }],
    ];
    for (const [weak, keys, back] of cases) {
      const before = (await overview()).settings;
      await needsStepUp(await settings(weak), keys);
      expect((await overview()).settings).toEqual(before); // nothing changed
      const wrong = await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, ip: freshIp(), body: { ...weak, current: proofFor('not-the-owner-password') } });
      expect([wrong.status, await errorOf(wrong)]).toEqual([403, 'wrong_password']);
      expect((await settings(weak, OWNER_STEP)).status).toBe(200);
      // The other way (tightening, or back to the default here) needs nothing.
      expect((await settings(back)).status, JSON.stringify(back)).toBe(200);
      expect((await overview()).settings).toEqual(before);
    }
    // Several at once: all are named; unrelated or tightening keys in the same patch are fine.
    await needsStepUp(await settings({ csrfTokens: false, 'lockout.max': 20, 'lockout.lockSec': 3600, 'files.pendingSec': 7200 }), ['csrfTokens', 'lockout.max']);
    expect((await settings({ 'lockout.max': 5, 'lockout.lockSec': 3600, 'files.pendingSec': 7200, 'a11y.contact': 'aa@example.test' })).status).toBe(200);
    expect((await settings({ 'lockout.max': 10, 'lockout.lockSec': 900, 'files.pendingSec': 3600 }, OWNER_STEP)).status).toBe(200);
  }, 60_000);

  it('settings: a passkey confirms too', async () => {
    const auth = new SoftAuthenticator();
    const post = (path, body) => fetchJson(path, { method: 'POST', cookie: oc, body });
    const o = await (await post('/api/private/me/passkeys/options', {})).json();
    expect((await post('/api/private/me/passkeys', { challengeId: o.challengeId, credential: await auth.create(o.publicKey, ORIGIN), name: 'aa-key', ...OWNER_STEP })).status).toBe(201);
    const reauth = async (tamper = false) => {
      const c = await (await post('/api/private/me/reauth', {})).json();
      return { reauth: { challengeId: c.challengeId, credential: await auth.get(c.publicKey, ORIGIN, { tamper }) } };
    };
    expect(await errorOf(await settings({ 'lockout.max': 12 }, await reauth(true)))).toBe('reauth_failed');
    expect((await settings({ 'lockout.max': 12 }, await reauth())).status).toBe(200);
    expect((await settings({ 'lockout.max': 10 })).status).toBe(200);
  });

  it('IP rules: every allow rule (the whole Internet included); block rules need nothing', async () => {
    for (const cidr of ['0.0.0.0/0', '::/0', '203.0.113.7']) await needsStepUp(await ipRule(cidr, 'allow'), ['ipRule.allow']);
    expect((await (await fetchJson('/api/private/admin/ip-rules', { cookie: oc })).json()).rules.filter((r) => r.action === 'allow')).toEqual([]);
    const added = await ipRule('0.0.0.0/0', 'allow', OWNER_STEP);
    expect(added.status).toBe(201);
    const block = await ipRule('198.51.100.0/24', 'block');
    expect(block.status).toBe(201);
    for (const id of [(await added.json()).id, (await block.json()).id]) {
      expect((await fetchJson(`/api/private/admin/ip-rules/${id}`, { method: 'DELETE', cookie: oc, headers: intent })).status).toBe(200);
    }
  });

  it('roles: looser passkeys, password policy, sessions or log retention; the API channel and tightening need nothing', async () => {
    // Default role (every option has a value).
    await needsStepUp(await limits('global', { passkeys: 'off' }), ['passkeys']);
    expect((await limits('global', { passkeys: 'second' })).status).toBe(200); // stronger
    await needsStepUp(await limits('global', { passkeys: 'any' }), ['passkeys']);
    expect((await limits('global', { passkeys: 'any' }, OWNER_STEP)).status).toBe(200);
    await needsStepUp(await limits('global', { pwMinLength: 8 }), ['pwMinLength']);
    expect((await limits('global', { pwMinLength: 14, pwDigit: true })).status).toBe(200);
    await needsStepUp(await limits('global', { pwDigit: false }), ['pwDigit']);
    await needsStepUp(await limits('global', { sessionAbsSec: 30 * 86400 }), ['sessionAbsSec']); // longer than the server-wide 7 days
    expect((await limits('global', { sessionAbsSec: 86400 })).status).toBe(200);
    await needsStepUp(await limits('global', { sessionAbsSec: null }), ['sessionAbsSec']); // back to the server-wide 7 days
    await needsStepUp(await limits('global', { logMaxAgeSec: 30 * 86400 }), ['logMaxAgeSec']); // null: only the global limit
    expect((await limits('global', { pwMinLength: 12, pwDigit: false, sessionAbsSec: null }, OWNER_STEP)).status).toBe(200);
    // A custom role: its own value, or "inherit" from a looser Default.
    const role = await (await fetchJson('/api/private/admin/roles', { method: 'POST', cookie: oc, body: { name: 'aa-strict' } })).json();
    const scope = `role:${role.id}`;
    expect((await limits(scope, { pwMinLength: 20, passkeys: 'second' })).status).toBe(200);
    await needsStepUp(await limits(scope, { logMaxEntries: 100 }), ['logMaxEntries']); // keeps less than Default (everything)
    expect((await limits(scope, { logMaxEntries: 100 }, OWNER_STEP)).status).toBe(200);
    await needsStepUp(await limits(scope, { pwMinLength: 'inherit' }), ['pwMinLength']);
    await needsStepUp(await limits(scope, { passkeys: 'inherit', logMaxEntries: 'inherit', pwMinLength: 24 }), ['passkeys']);
    expect((await limits(scope, { logMaxEntries: 'inherit', maxViews: 3 })).status).toBe(200);
    // The API channel only narrows, and holds none of these options.
    expect((await limits(scope, { maxViews: 1 }, {}, 'api')).status).toBe(200);
    expect((await fetchJson(`/api/private/admin/roles/${role.id}`, { method: 'DELETE', cookie: oc, headers: intent })).status).toBe(200);
    const d = (await overview()).limits.all;
    expect([d.passkeys, d.pwMinLength, d.pwDigit, d.sessionAbsSec]).toEqual(['any', 12, false, null]);
  });

  it('roles: widening what shares, links and API keys may be (CAPTCHA, passwords, expiry, views, types, links, API)', async () => {
    const role = await (await fetchJson('/api/private/admin/roles', { method: 'POST', cookie: oc, body: { name: 'aa-wide' } })).json();
    const scope = `role:${role.id}`;
    // Tighter than Default first: needs nothing.
    const tight = { shareCaptcha: 'require', shareCaptchaDefault: 'on', reverseCaptcha: 'require', reverseCaptchaDefault: 'on', reversePassword: 'require', reversePasswordDefault: 'on',
      allowUnlimitedViews: false, reverseAllowUnlimitedViews: false, maxExpireSec: 3600, maxViews: 5, reverseMaxExpireSec: 3600, reverseMaxViews: 5,
      fileTypeMode: 'allow', fileTypeRules: ['ext:pdf'], urlRules: ['scheme:https://'], files: false, reverseFiles: false };
    expect((await limits(scope, tight)).status).toBe(200);
    const cases = [
      [{ shareCaptcha: 'allow' }, ['shareCaptcha']], [{ shareCaptcha: 'off' }, ['shareCaptcha']], [{ shareCaptcha: 'inherit' }, ['shareCaptcha']],
      [{ shareCaptchaDefault: 'off' }, ['shareCaptchaDefault']],
      [{ reverseCaptcha: 'allow' }, ['reverseCaptcha']], [{ reverseCaptchaDefault: 'off' }, ['reverseCaptchaDefault']],
      [{ reversePassword: 'off' }, ['reversePassword']], [{ reversePasswordDefault: 'off' }, ['reversePasswordDefault']],
      [{ reverseNoExpiry: true }, ['reverseNoExpiry']],
      [{ allowUnlimitedViews: true }, ['allowUnlimitedViews']], [{ reverseAllowUnlimitedViews: true }, ['reverseAllowUnlimitedViews']],
      [{ maxExpireSec: 7200 }, ['maxExpireSec']], [{ maxExpireSec: null }, ['maxExpireSec']], [{ maxViews: 'inherit' }, ['maxViews']],
      [{ maxViews: 6 }, ['maxViews']], [{ reverseMaxExpireSec: null }, ['reverseMaxExpireSec']], [{ reverseMaxViews: 50 }, ['reverseMaxViews']],
      [{ url: true }, ['url']], [{ secret: true }, ['secret']], [{ apiEnabled: true }, ['apiEnabled']],
      // Receive links that may take links or credentials (off in the Default role).
      [{ reverseUrl: true }, ['reverseUrl']], [{ reverseSecret: true }, ['reverseSecret']],
      // Files (outgoing file and Drive shares, and Receive links that take files), off in this role first.
      [{ files: true }, ['files']], [{ files: 'inherit' }, ['files']], [{ reverseFiles: true }, ['reverseFiles']], [{ reverseFiles: 'inherit' }, ['reverseFiles']],
      [{ fileTypeMode: 'block' }, ['fileTypeMode']], [{ fileTypeMode: 'any' }, ['fileTypeMode']],
      [{ fileTypeRules: ['ext:pdf', 'ext:exe'] }, ['fileTypeRules']], // more allowed types
      [{ urlRules: ['scheme:https://', 'scheme:tel:'] }, ['urlRules']],
      [{ url: true, maxViews: 3, maxExpireSec: 600 }, ['url']], // tightening keys alongside are not named
    ];
    for (const [patch, keys] of cases) await needsStepUp(await limits(scope, patch), keys);
    // The other way needs nothing.
    for (const patch of [{ maxViews: 3, maxExpireSec: 600, reverseMaxViews: 1 }, { fileTypeRules: [] }, { urlRules: ['scheme:https://'] }, { reverseUrl: false, reverseSecret: false, reverseText: false }]) {
      expect((await limits(scope, patch)).status, JSON.stringify(patch)).toBe(200);
    }
    // A block list: removing a rule lets more through.
    expect((await limits(scope, { fileTypeMode: 'block', fileTypeRules: ['ext:exe', 'ext:js'] }, OWNER_STEP)).status).toBe(200);
    await needsStepUp(await limits(scope, { fileTypeRules: ['ext:exe'] }), ['fileTypeRules']);
    expect((await limits(scope, { fileTypeRules: ['ext:exe', 'ext:js', 'ext:bat'] })).status).toBe(200);
    // With the step-up, all at once.
    expect((await limits(scope, { url: true, apiEnabled: true, maxViews: null }, OWNER_STEP)).status).toBe(200);
    // The API channel, compared on what it resolves to: lifting an API restriction widens the API.
    expect((await limits(scope, { url: false, maxViews: 2 }, {}, 'api')).status).toBe(200);
    await needsStepUp(await limits(scope, { url: 'inherit' }, {}, 'api'), ['url']);
    await needsStepUp(await limits(scope, { maxViews: 'inherit' }, {}, 'api'), ['maxViews']);
    expect((await limits(scope, { maxViews: 1 }, {}, 'api')).status).toBe(200);
    expect((await fetchJson(`/api/private/admin/roles/${role.id}`, { method: 'DELETE', cookie: oc, headers: intent })).status).toBe(200);
    // The public account: what anonymous senders may do.
    await needsStepUp(await limits('public-user-0000', { url: true }), ['url']);
    await needsStepUp(await limits('public-user-0000', { maxViews: 20 }), ['maxViews']);
    expect((await limits('public-user-0000', { maxViews: 5 })).status).toBe(200);
    expect((await limits('public-user-0000', { maxViews: 10 }, OWNER_STEP)).status).toBe(200);
  }, 60_000);

  it('settings: turning anonymous sharing on; the Turnstile keys were already confirmed on every change', async () => {
    await needsStepUp(await settings({ 'public.enabled': true }), ['public.enabled']);
    expect((await settings({ 'public.enabled': true }, OWNER_STEP)).status).toBe(200);
    expect((await settings({ 'public.enabled': false })).status).toBe(200);
    const ts = (body) => fetchJson('/api/private/admin/turnstile', { method: 'PUT', cookie: oc, body });
    expect(await errorOf(await ts({ clear: true }))).toBe('reauth_required');
    expect(await errorOf(await ts({ sitekey: '1x00000000000000000000AA', secret: '1x0000000000000000000000000000000AA' }))).toBe('reauth_required');
  });

  it('the owner acting as a user cannot reach these routes at all', async () => {
    const u = await makeUser('aa-imp-admin');
    const ic = cookieOf(await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
    expect(await errorOf(await settings({ csrfTokens: false }, OWNER_STEP, ic))).toBe('impersonating');
    await fetchJson('/api/private/admin/unimpersonate', { method: 'POST', cookie: ic, headers: intent });
  });

  it('what counts as weakening (settings.js)', () => {
    const s = settingsWithDefaults({});
    expect(weakenedSettings(s, { ...s })).toEqual([]);
    expect(weakenedSettings(s, { ...s, csrfTokens: false, 'guard.v6Prefix': 48, 'lockout.max': 3, 'session.idleSec': 3600 })).toEqual(['csrfTokens']);
    expect(weakenedSettings({ ...s, csrfTokens: false }, s)).toEqual([]);
    expect(weakenedSettings({ ...s, 'log.ownerMaxEntries': 5000 }, { ...s, 'log.ownerMaxEntries': null })).toEqual([]);
    expect(weakenedSettings({ ...s, 'log.ownerMaxEntries': 5000 }, { ...s, 'log.ownerMaxEntries': 4000 })).toEqual(['log.ownerMaxEntries']);
    const d = resolveLimits({}, {});
    expect(weakenedLimits(d, { ...d, passkeysMax: 1, apiEnabled: false, maxViews: 1, maxExpireSec: 3600, url: false }, s)).toEqual([]);
    expect(weakenedLimits({ ...d, passkeys: 'second' }, { ...d, passkeys: 'off' }, s)).toEqual(['passkeys']);
    expect(weakenedLimits({ ...d, sessionIdleSec: 600 }, { ...d, sessionIdleSec: null }, s)).toEqual(['sessionIdleSec']);
    expect(weakenedLimits({ ...d, sessionIdleSec: null }, { ...d, sessionIdleSec: s['session.idleSec'] }, s)).toEqual([]);
    // File types: read with the mode; a mode change is the mode's own entry.
    const allow = { ...d, fileTypeMode: 'allow', fileTypeRules: ['ext:pdf'] };
    expect(weakenedLimits(allow, { ...allow, fileTypeRules: [] }, s)).toEqual([]);
    expect(weakenedLimits(allow, { ...allow, fileTypeRules: ['ext:pdf', 'ext:png'] }, s)).toEqual(['fileTypeRules']);
    expect(weakenedLimits(allow, { ...allow, fileTypeMode: 'block', fileTypeRules: [] }, s)).toEqual(['fileTypeMode']);
    const block = { ...d, fileTypeMode: 'block', fileTypeRules: ['ext:exe', 'ext:js'] };
    expect(weakenedLimits(block, { ...block, fileTypeRules: ['ext:js'] }, s)).toEqual(['fileTypeRules']);
    expect(weakenedLimits(block, { ...block, fileTypeMode: 'allow' }, s)).toEqual([]);
    expect(weakenedLimits({ ...d, urlRules: ['scheme:https://'] }, { ...d, urlRules: ['scheme:http://'] }, s)).toEqual(['urlRules']);
    expect(weakenedLimits({ ...d, urlRules: ['scheme:https://', 'scheme:http://'] }, { ...d, urlRules: ['scheme:https://'] }, s)).toEqual([]);
    // Receive links: allowing links or credentials weakens (false → true); turning them off does not.
    expect([d.reverseUrl, d.reverseSecret]).toEqual([false, false]);
    expect(weakenedLimits(d, { ...d, reverseUrl: true, reverseSecret: true }, s)).toEqual(['reverseUrl', 'reverseSecret']);
    expect(weakenedLimits({ ...d, reverseUrl: true, reverseSecret: true }, d, s)).toEqual([]);
    // Files too (RT2-3): on is weakening, off is not.
    expect([d.files, d.reverseFiles]).toEqual([true, true]);
    expect(weakenedLimits({ ...d, files: false, reverseFiles: false }, d, s)).toEqual(['files', 'reverseFiles']);
    expect(weakenedLimits(d, { ...d, files: false, reverseFiles: false }, s)).toEqual([]);
  });
});
