// step-up.test.js — "confirm it's you" for changes to one's own account:
// the current password or a fresh passkey assertion, for a password change,
// passkey changes, API keys (create / change / revoke) and the username. The
// owner acts on other users' keys and passkeys without it, and on their own
// account with it.
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, freshIp, proofFor, USER_PW, intent, ORIGIN, login } from './helpers.js';
import { SoftAuthenticator } from './soft-authenticator.js';

let oc;
beforeAll(async () => { oc = await owner(); });

const call = (method, path, body, cookie) => fetchJson(path, { method, body, cookie, ip: freshIp(), headers: method === 'DELETE' ? intent : undefined });
const post = (path, body, cookie) => call('POST', path, body, cookie);
const errorOf = async (r) => (await r.json()).error;
const pw = (password = USER_PW) => ({ current: proofFor(password) });
const allowApi = (uid) => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: uid, channel: 'all', patch: { apiEnabled: true, apiMaxKeys: null } } });

async function withPasskey(cookie) {
  const auth = new SoftAuthenticator();
  const o = await (await post('/api/private/me/passkeys/options', {}, cookie)).json();
  const credential = await auth.create(o.publicKey, ORIGIN);
  const res = await post('/api/private/me/passkeys', { challengeId: o.challengeId, credential, name: 'Laptop', ...pw() }, cookie);
  expect(res.status).toBe(201);
  return auth;
}

/** A passkey confirmation for `cookie` → { reauth }. */
async function passkeyProof(cookie, auth) {
  const o = await (await post('/api/private/me/reauth', {}, cookie)).json();
  return { reauth: { challengeId: o.challengeId, credential: await auth.get(o.publicKey, ORIGIN) } };
}

describe('confirming changes to one\'s own account', () => {
  it('API keys: create, change and revoke need the password or a passkey', async () => {
    const u = await makeUser('su-keys');
    await allowApi(u.id);
    expect(await errorOf(await post('/api/private/me/keys', { name: 'k' }, u.cookie))).toBe('reauth_required');
    expect(await errorOf(await post('/api/private/me/keys', { name: 'k', ...pw('wrong-password-000') }, u.cookie))).toBe('wrong_password');
    const made = await post('/api/private/me/keys', { name: 'k', ...pw() }, u.cookie);
    expect(made.status).toBe(201);
    const { id } = await made.json();
    const auth = await withPasskey(u.cookie);
    // Change: rename and narrow the scopes, confirmed with a passkey.
    expect(await errorOf(await call('PATCH', `/api/private/me/keys/${id}`, { name: 'renamed' }, u.cookie))).toBe('reauth_required');
    const ch = await call('PATCH', `/api/private/me/keys/${id}`, { name: 'renamed', scopes: ['notes'], ...(await passkeyProof(u.cookie, auth)) }, u.cookie);
    expect(ch.status).toBe(200);
    const { keys } = await (await fetchJson('/api/private/me/keys', { cookie: u.cookie })).json();
    expect(keys[0]).toMatchObject({ name: 'renamed', scopes: ['notes'] });
    expect(await errorOf(await call('PATCH', `/api/private/me/keys/${id}`, { scopes: ['nope'], ...pw() }, u.cookie))).toBe('invalid_scopes');
    // Revoke.
    expect(await errorOf(await call('DELETE', `/api/private/me/keys/${id}`, {}, u.cookie))).toBe('reauth_required');
    expect((await call('DELETE', `/api/private/me/keys/${id}`, pw(), u.cookie)).status).toBe(200);
    expect((await (await fetchJson('/api/private/me/keys', { cookie: u.cookie })).json()).keys).toEqual([]);
  });

  it('a passkey confirmation works once, for its own account only', async () => {
    const a = await makeUser('su-once-a');
    const b = await makeUser('su-once-b');
    await allowApi(a.id);
    await allowApi(b.id);
    const authA = await withPasskey(a.cookie);
    await withPasskey(b.cookie);
    const proof = await passkeyProof(a.cookie, authA);
    expect((await post('/api/private/me/keys', { name: 'one', ...proof }, a.cookie)).status).toBe(201);
    expect(await errorOf(await post('/api/private/me/keys', { name: 'two', ...proof }, a.cookie))).toBe('reauth_failed');
    // A's challenge answered by A's passkey, presented on B's account.
    expect(await errorOf(await post('/api/private/me/keys', { name: 'x', ...(await passkeyProof(a.cookie, authA)) }, b.cookie))).toBe('reauth_failed');
    // B's challenge answered with A's passkey.
    const o = await (await post('/api/private/me/reauth', {}, b.cookie)).json();
    const credential = await authA.get({ ...o.publicKey, allowCredentials: [] }, ORIGIN);
    expect(await errorOf(await post('/api/private/me/keys', { name: 'x', reauth: { challengeId: o.challengeId, credential } }, b.cookie))).toBe('reauth_failed');
  });

  it('without a passkey, only the password confirms', async () => {
    const u = await makeUser('su-nopk');
    expect(await errorOf(await post('/api/private/me/reauth', {}, u.cookie))).toBe('no_passkeys');
  });

  it('the password changes with a passkey instead of the current password', async () => {
    const u = await makeUser('su-pw');
    const auth = await withPasskey(u.cookie);
    const r = await post('/api/private/me/password', { salt: 'AAAAAAAAAAAAAAAAAAAAAA', t: 3, proof: proofFor('another-password-1'), ...(await passkeyProof(u.cookie, auth)) }, u.cookie);
    expect(r.status).toBe(200);
    expect(await login('su-pw', 'another-password-1')).toBeTruthy();
  });

  it('the username changes with the password; taken names are refused', async () => {
    const u = await makeUser('su-name');
    await makeUser('su-taken');
    expect(await errorOf(await post('/api/private/me/username', { username: 'su-renamed' }, u.cookie))).toBe('reauth_required');
    expect(await errorOf(await post('/api/private/me/username', { username: 'SU-TAKEN', ...pw() }, u.cookie))).toBe('username_taken');
    expect(await errorOf(await post('/api/private/me/username', { username: 'x', ...pw() }, u.cookie))).toBe('invalid_username');
    const r = await post('/api/private/me/username', { username: 'su-renamed', ...pw() }, u.cookie);
    expect(await r.json()).toMatchObject({ ok: true, username: 'su-renamed' });
    // The session carries on; the new name signs in, the old one does not.
    expect((await (await fetchJson('/api/private/me', { cookie: u.cookie })).json()).user.username).toBe('su-renamed');
    expect(await login('su-renamed', USER_PW)).toBeTruthy();
    expect((await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'su-name', proof: proofFor(USER_PW) }, ip: freshIp() })).status).toBe(401);
  });

  it('failed confirmations add up to signing the account out everywhere', async () => {
    const u = await makeUser('su-revoke');
    await allowApi(u.id);
    let last;
    for (let i = 0; i < 10 && last !== 'session_revoked'; i++) last = await errorOf(await post('/api/private/me/keys', { name: 'k', ...pw('wrong-password-000') }, u.cookie));
    expect(last).toBe('session_revoked');
    expect((await fetchJson('/api/private/me', { cookie: u.cookie })).status).toBe(401);
  });
});

describe('the owner, for other users', () => {
  it('creates, changes and revokes a user\'s API keys without confirming', async () => {
    const u = await makeUser('su-admin-keys');
    await allowApi(u.id);
    const made = await post(`/api/private/admin/users/${u.id}/keys`, { name: 'for-cli', scopes: ['files'] }, oc);
    expect(made.status).toBe(201);
    const { id, key } = await made.json();
    expect(key).toMatch(/^sbk_/);
    expect((await call('PATCH', `/api/private/admin/users/${u.id}/keys/${id}`, { name: 'cli-2' }, oc)).status).toBe(200);
    const { keys } = await (await fetchJson('/api/private/me/keys', { cookie: u.cookie })).json();
    expect(keys[0]).toMatchObject({ name: 'cli-2', scopes: ['files'] });
    expect((await call('DELETE', `/api/private/admin/users/${u.id}/keys/${id}`, {}, oc)).status).toBe(200);
    const audit = await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json();
    expect(audit.rows.find((r) => r.action === 'apikey.created' && r.subject === 'su-admin-keys').actor).toBe('owner');
  });

  it('on the owner\'s own account, the admin routes need the confirmation too', async () => {
    const { users } = await (await fetchJson('/api/private/admin/users', { cookie: oc })).json();
    const me = users.find((x) => x.role === 'owner');
    expect(await errorOf(await post(`/api/private/admin/users/${me.id}/keys`, { name: 'mine' }, oc))).toBe('reauth_required');
    const r = await post(`/api/private/admin/users/${me.id}/keys`, { name: 'mine', current: proofFor('owner-password') }, oc);
    expect(r.status).toBe(201);
    const { id } = await r.json();
    expect(await errorOf(await call('DELETE', `/api/private/admin/users/${me.id}/keys/${id}`, {}, oc))).toBe('reauth_required');
    expect((await call('DELETE', `/api/private/admin/users/${me.id}/keys/${id}`, { current: proofFor('owner-password') }, oc)).status).toBe(200);
  });

  it('other actions do not take a key id', async () => {
    const u = await makeUser('su-route');
    expect((await post(`/api/private/admin/users/${u.id}/password/AAAAAAAAAAAAAAAA`, {}, oc)).status).toBe(404);
  });
});
