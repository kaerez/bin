// passkeys.test.js — WebAuthn passkeys and recovery codes, driven by a real
// software authenticator (test/soft-authenticator.js):
//   - registration needs the current password; the first passkey comes with
//     20 one-time recovery codes;
//   - sign-in with a passkey alone (usernameless), or password + passkey /
//     recovery code as a second step, as the "passkeys" limit allows;
//   - every WebAuthn check: challenge single use, origin, RP ID, user
//     verification, signature, counter;
//   - the admin can remove a user's passkeys; the owner is exempt from the
//     global limit.
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, freshIp, cookieOf, proofFor, ORIGIN, intent } from './helpers.js';
import { SoftAuthenticator } from './soft-authenticator.js';
import { cborDecode, derToRawP256, parseAuthData } from '../src/lib/webauthn.js';
import { normalizeRecoveryCode } from '../src/directory-do.js';

const PW = 'user-password-123';
const CODE_RE = /^[0-9A-HJKMNP-TV-Z]{4}(-[0-9A-HJKMNP-TV-Z]{4}){3}$/;
let oc;
beforeAll(async () => { oc = await owner(); });

const post = (path, body, cookie, ip = freshIp()) => fetchJson(path, { method: 'POST', body, cookie, ip });
const limits = (uid, patch) => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: uid, channel: 'all', patch } });

/** Register a passkey for `cookie` → { res, body, auth }. */
async function register(cookie, { auth = new SoftAuthenticator(), password = PW, name = 'Laptop', knobs = {} } = {}) {
  const o = await (await post('/api/private/me/passkeys/options', {}, cookie)).json();
  const credential = await auth.create(o.publicKey, knobs.origin ?? ORIGIN, knobs);
  const res = await post('/api/private/me/passkeys', { challengeId: o.challengeId, credential, name, current: proofFor(password) }, cookie);
  return { res, body: await res.json(), auth, options: o };
}

/** Usernameless sign-in with `auth`. */
async function passkeyLogin(auth, knobs = {}) {
  const o = await (await post('/api/auth/passkey/options', {})).json();
  const credential = await auth.get(o.publicKey, knobs.origin ?? ORIGIN, knobs);
  return post('/api/auth/passkey/login', { challengeId: o.challengeId, credential });
}

const passwordLogin = (username, password = PW) => post('/api/auth/login', { username, proof: proofFor(password) });
const errorOf = async (r) => (await r.json()).error;

describe('the WebAuthn parser', () => {
  it('rejects malformed CBOR and DER', () => {
    expect(() => cborDecode(new Uint8Array([0xa1, 0x01]))).toThrow(); // truncated map
    expect(() => cborDecode(new Uint8Array([0x01, 0x02]))).toThrow(); // trailing bytes
    expect(() => cborDecode(new Uint8Array([0x9f]))).toThrow(); // indefinite length
    expect(() => cborDecode(new Uint8Array(Array(40).fill(0x81)))).toThrow(); // too deep
    expect(() => derToRawP256(new Uint8Array([0x30, 0x02, 0x02, 0x00]))).toThrow();
    expect(() => parseAuthData(new Uint8Array(10))).toThrow();
  });

  it('normalizes recovery codes forgivingly', () => {
    expect(normalizeRecoveryCode('abcd-efgh-jkmn-pqrs')).toBe('ABCDEFGHJKMNPQRS');
    expect(normalizeRecoveryCode(' 0o1i-L234 5678 9ABC ')).toBe('0011123456789ABC');
    expect(normalizeRecoveryCode('ABCD-EFGH-JKMN-PQRU')).toBeNull(); // U is not in the alphabet
    expect(normalizeRecoveryCode('short')).toBeNull();
  });
});

describe('registration', () => {
  it('needs the current password and returns 20 recovery codes once', async () => {
    const u = await makeUser('pk-reg');
    const wrong = await register(u.cookie, { password: 'not-my-password-1' });
    expect(wrong.res.status).toBe(403);
    expect(wrong.body.error).toBe('wrong_password');
    const { res, body, options } = await register(u.cookie);
    expect(res.status).toBe(201);
    expect(body.codes).toHaveLength(20);
    for (const c of body.codes) expect(c).toMatch(CODE_RE);
    expect(new Set(body.codes).size).toBe(20);
    // Discoverable, user-verified, no attestation.
    expect(options.publicKey.authenticatorSelection).toMatchObject({ residentKey: 'required', userVerification: 'required' });
    expect(options.publicKey.attestation).toBe('none');
    expect(options.publicKey.rp.id).toBe('secbin.test');
    // A second passkey: no new codes, and the first is excluded.
    const second = await register(u.cookie, { name: 'Phone' });
    expect(second.res.status).toBe(201);
    expect(second.body.codes).toBeNull();
    expect(second.options.publicKey.excludeCredentials).toHaveLength(1);
    const st = await (await fetchJson('/api/private/me/passkeys', { cookie: u.cookie })).json();
    expect(st.passkeys.map((p) => p.name)).toEqual(['Laptop', 'Phone']);
    expect(st.recoveryLeft).toBe(20);
    expect(st.mode).toBe('any');
  });

  it('refuses a reused challenge, another origin, another RP and no user verification', async () => {
    const u = await makeUser('pk-bad-reg');
    const auth = new SoftAuthenticator();
    const o = await (await post('/api/private/me/passkeys/options', {}, u.cookie)).json();
    const cred = await auth.create(o.publicKey, ORIGIN);
    expect((await post('/api/private/me/passkeys', { challengeId: o.challengeId, credential: cred, name: 'k', current: proofFor(PW) }, u.cookie)).status).toBe(201);
    const again = await post('/api/private/me/passkeys', { challengeId: o.challengeId, credential: cred, name: 'k', current: proofFor(PW) }, u.cookie);
    expect(await errorOf(again)).toBe('challenge_expired');
    for (const knobs of [{ origin: 'https://evil.example' }, { rpId: 'evil.example' }, { uv: false }, { type: 'webauthn.get' }]) {
      const r = await register(u.cookie, { knobs });
      expect(r.body.error, JSON.stringify(knobs)).toBe('invalid_passkey');
    }
  });

  it('works with EdDSA and RS256 keys too', async () => {
    for (const alg of [-8, -257]) {
      const u = await makeUser(`pk-alg${-alg}`);
      const { res, auth } = await register(u.cookie, { auth: new SoftAuthenticator({ alg }) });
      expect(res.status, String(alg)).toBe(201);
      expect((await passkeyLogin(auth)).status, String(alg)).toBe(200);
    }
  });

  it('is refused while impersonating', async () => {
    const u = await makeUser('pk-imp');
    const imp = await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent });
    const r = await post('/api/private/me/passkeys/options', {}, cookieOf(imp));
    expect(await errorOf(r)).toBe('impersonating');
  });
});

describe('sign-in with a passkey alone', () => {
  it('signs in without a username and the session works', async () => {
    const u = await makeUser('pk-login');
    const { auth } = await register(u.cookie);
    const r = await passkeyLogin(auth);
    expect(r.status).toBe(200);
    expect((await r.json()).user.username).toBe('pk-login');
    const me = await (await fetchJson('/api/private/me', { cookie: cookieOf(r) })).json();
    expect(me.user.id).toBe(u.id);
    expect(me.passkeys).toMatchObject({ mode: 'any', count: 1, required: false, recoveryLeft: 20 });
  });

  it('refuses replays, bad signatures, other origins, no UV and unknown passkeys', async () => {
    const u = await makeUser('pk-bad-login');
    const { auth } = await register(u.cookie);
    const o = await (await post('/api/auth/passkey/options', {})).json();
    const cred = await auth.get(o.publicKey, ORIGIN);
    expect((await post('/api/auth/passkey/login', { challengeId: o.challengeId, credential: cred })).status).toBe(200);
    expect(await errorOf(await post('/api/auth/passkey/login', { challengeId: o.challengeId, credential: cred }))).toBe('challenge_expired');
    for (const knobs of [{ tamper: true }, { origin: 'https://evil.example' }, { rpId: 'evil.example' }, { uv: false }]) {
      expect(await errorOf(await passkeyLogin(auth, knobs)), JSON.stringify(knobs)).toBe('invalid_passkey');
    }
    const stranger = new SoftAuthenticator();
    await stranger.create({ rp: { id: 'secbin.test' }, user: { id: 'x' }, challenge: 'x' }, ORIGIN);
    expect(await errorOf(await passkeyLogin(stranger))).toBe('invalid_passkey');
  });

  it('refuses a signature counter that goes backwards (cloned authenticator)', async () => {
    const u = await makeUser('pk-counter');
    const { auth } = await register(u.cookie, { auth: new SoftAuthenticator({ counter: true }) });
    expect((await passkeyLogin(auth)).status).toBe(200);
    expect((await passkeyLogin(auth)).status).toBe(200);
    expect(await errorOf(await passkeyLogin(auth, { count: 1 }))).toBe('invalid_passkey');
  });

  it('refuses a disabled account', async () => {
    const u = await makeUser('pk-disabled');
    const { auth } = await register(u.cookie);
    await fetchJson(`/api/private/admin/users/${u.id}`, { method: 'PATCH', cookie: oc, body: { disabled: true } });
    expect(await errorOf(await passkeyLogin(auth))).toBe('account_disabled');
  });
});

describe('recovery codes', () => {
  it('sign in alone once each (mode "any"), and can be regenerated', async () => {
    const u = await makeUser('pk-codes');
    const { body } = await register(u.cookie);
    const [c1, c2] = body.codes;
    const r = await post('/api/auth/recovery', { username: 'pk-codes', code: c1.toLowerCase() });
    expect(r.status).toBe(200);
    expect((await r.json()).recoveryLeft).toBe(19);
    expect(await errorOf(await post('/api/auth/recovery', { username: 'pk-codes', code: c1 }))).toBe('invalid_login');
    expect(await errorOf(await post('/api/auth/recovery', { username: 'pk-codes', code: 'ZZZZ-ZZZZ-ZZZZ-ZZZZ' }))).toBe('invalid_login');
    const regen = await post('/api/private/me/recovery-codes', { current: proofFor(PW) }, u.cookie);
    const fresh = (await regen.json()).codes;
    expect(fresh).toHaveLength(20);
    expect(await errorOf(await post('/api/auth/recovery', { username: 'pk-codes', code: c2 }))).toBe('invalid_login'); // old set revoked
    expect((await post('/api/auth/recovery', { username: 'pk-codes', code: fresh[0] })).status).toBe(200);
  });

  it('go away with the last passkey', async () => {
    const u = await makeUser('pk-remove');
    const { body, auth } = await register(u.cookie);
    const wrong = await post(`/api/private/me/passkeys/${auth.id}/remove`, { current: proofFor('nope-nope-nope-1') }, u.cookie);
    expect(await errorOf(wrong)).toBe('wrong_password');
    expect((await post(`/api/private/me/passkeys/${auth.id}/remove`, { current: proofFor(PW) }, u.cookie)).status).toBe(200);
    const st = await (await fetchJson('/api/private/me/passkeys', { cookie: u.cookie })).json();
    expect(st).toMatchObject({ passkeys: [], recoveryLeft: 0, mfa: false });
    expect(await errorOf(await post('/api/auth/recovery', { username: 'pk-remove', code: body.codes[0] }))).toBe('invalid_login');
    expect(await errorOf(await passkeyLogin(auth))).toBe('invalid_passkey');
  });
});

describe('passkey as a second factor', () => {
  it('when the user turns it on, a password login needs the passkey or a code', async () => {
    const u = await makeUser('pk-2fa');
    const { auth, body } = await register(u.cookie);
    expect((await post('/api/private/me/second-factor', { on: true, current: proofFor(PW) }, u.cookie)).status).toBe(200);
    const step1 = await passwordLogin('pk-2fa');
    expect(step1.status).toBe(200);
    expect(step1.headers.get('set-cookie')).toBeNull(); // no session yet
    const { secondFactor } = await step1.json();
    expect(secondFactor.publicKey.allowCredentials.map((c) => c.id)).toEqual([auth.id]);
    const cred = await auth.get(secondFactor.publicKey, ORIGIN);
    const step2 = await post('/api/auth/second-factor', { challengeId: secondFactor.challengeId, credential: cred });
    expect(step2.status).toBe(200);
    expect(cookieOf(step2)).toBeTruthy();
    expect(await step2.clone().json()).not.toHaveProperty('recoveryLeft'); // no code was spent
    // The challenge is spent.
    expect(await errorOf(await post('/api/auth/second-factor', { challengeId: secondFactor.challengeId, credential: cred }))).toBe('challenge_expired');

    // A recovery code instead of the passkey (a wrong one first).
    const again = (await (await passwordLogin('pk-2fa')).json()).secondFactor;
    expect(await errorOf(await post('/api/auth/second-factor', { challengeId: again.challengeId, code: 'ZZZZ-ZZZZ-ZZZZ-ZZZZ' }))).toBe('invalid_second_factor');
    const ok = await post('/api/auth/second-factor', { challengeId: again.challengeId, code: body.codes[3] });
    expect(ok.status).toBe(200);
    expect((await ok.json()).recoveryLeft).toBe(19);
  });

  it('allows a few tries per password step', async () => {
    const u = await makeUser('pk-tries');
    await register(u.cookie);
    await post('/api/private/me/second-factor', { on: true, current: proofFor(PW) }, u.cookie);
    const { secondFactor } = await (await passwordLogin('pk-tries')).json();
    const codes = [];
    for (let i = 0; i < 6; i++) codes.push(await errorOf(await post('/api/auth/second-factor', { challengeId: secondFactor.challengeId, code: 'ZZZZ-ZZZZ-ZZZZ-ZZZZ' })));
    expect(codes.slice(0, 5)).toEqual(Array(5).fill('invalid_second_factor'));
    expect(codes[5]).toBe('challenge_expired');
  });

  it('mode "second": no passkey-only or code-only sign-in, and the second factor is always on', async () => {
    const u = await makeUser('pk-mode2');
    const { auth, body } = await register(u.cookie);
    expect((await limits(u.id, { passkeys: 'second' })).status).toBe(200);
    expect(await errorOf(await passkeyLogin(auth))).toBe('password_first');
    expect(await errorOf(await post('/api/auth/recovery', { username: 'pk-mode2', code: body.codes[0] }))).toBe('password_first');
    const { secondFactor } = await (await passwordLogin('pk-mode2')).json();
    expect(secondFactor).toBeTruthy();
    // The code refused above was not spent.
    expect((await post('/api/auth/second-factor', { challengeId: secondFactor.challengeId, code: body.codes[0] })).status).toBe(200);
    const off = await post('/api/private/me/second-factor', { on: false, current: proofFor(PW) }, u.cookie);
    expect(await errorOf(off)).toBe('second_factor_required');
  });

  it('mode "off": no registration, and passwords work alone again', async () => {
    const u = await makeUser('pk-mode-off');
    const { auth } = await register(u.cookie);
    await post('/api/private/me/second-factor', { on: true, current: proofFor(PW) }, u.cookie);
    await limits(u.id, { passkeys: 'off' });
    expect(await errorOf(await post('/api/private/me/passkeys/options', {}, u.cookie))).toBe('passkeys_disabled');
    expect(await errorOf(await passkeyLogin(auth))).toBe('passkeys_disabled');
    const r = await passwordLogin('pk-mode-off');
    expect(cookieOf(r)).toBeTruthy();
  });
});

describe('administration', () => {
  it('the admin removes a user\'s passkeys and codes', async () => {
    const u = await makeUser('pk-admin');
    const { auth } = await register(u.cookie);
    const d = await (await fetchJson(`/api/private/admin/users/${u.id}`, { cookie: oc })).json();
    expect(d.passkeys).toMatchObject({ count: 1, recoveryLeft: 20 });
    const r = await fetchJson(`/api/private/admin/users/${u.id}/passkeys`, { method: 'POST', cookie: oc, headers: intent });
    expect((await r.json()).removed).toBe(1);
    expect(await errorOf(await passkeyLogin(auth))).toBe('invalid_passkey');
  });

  it('a global "off" never applies to the owner', async () => {
    expect((await limits('', { passkeys: 'off' })).status).toBe(200);
    const u = await makeUser('pk-global-off');
    expect(await errorOf(await post('/api/private/me/passkeys/options', {}, u.cookie))).toBe('passkeys_disabled');
    const o = await register(oc, { password: 'owner-password' });
    expect(o.res.status).toBe(201);
    await limits('', { passkeys: 'any' });
  });
});
