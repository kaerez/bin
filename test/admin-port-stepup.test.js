// admin-port-stepup.test.js — Admin → Import / export: the account and
// system export and import (secbin-export/v1) are confirmed like every other
// step-up (src/routes/stepup.js, src/routes/drive.js stepUp): the owner's
// password (`current`) or a fresh passkey assertion (`reauth`, from POST
// /api/private/me/reauth). A wrong password or a failed passkey counts like
// a failed confirmation (the account's lockout, and the network's login
// failures); the import's preview and its apply both need it; the owner
// acting as a user cannot reach either route. The same holds for clearing
// logs (POST /api/private/admin/logs/clear).
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, proofFor, freshIp, intent, cookieOf, login, setOwnerCookie, ORIGIN } from './helpers.js';
import { SoftAuthenticator } from './soft-authenticator.js';

const OWNER_PW = 'owner-password';
let oc;
let auth;
const post = (path, body, { cookie = oc, ip } = {}) => fetchJson(path, { method: 'POST', cookie, body, ip });
const errorOf = async (r) => (await r.json()).error;

/** A passkey confirmation for the owner → { reauth }; `tamper` breaks its signature. */
async function passkeyProof({ tamper = false, cookie = oc } = {}) {
  const o = await (await post('/api/private/me/reauth', {}, { cookie })).json();
  return { reauth: { challengeId: o.challengeId, credential: await auth.get(o.publicKey, ORIGIN, { tamper }) } };
}
const exportSettings = (step, opts) => post('/api/private/admin/export', { ...step, system: { settings: true } }, opts);
const importSettings = (document, step, dryRun, opts) => post('/api/private/admin/import', { ...step, document, decisions: { system: { settings: true }, users: {} }, dryRun }, opts);

beforeAll(async () => {
  oc = await owner();
  auth = new SoftAuthenticator();
  const o = await (await post('/api/private/me/passkeys/options', {})).json();
  const credential = await auth.create(o.publicKey, ORIGIN);
  const r = await post('/api/private/me/passkeys', { challengeId: o.challengeId, credential, name: 'Owner laptop', current: proofFor(OWNER_PW) });
  expect(r.status).toBe(201);
});

describe('the account and system export', () => {
  it('takes a passkey instead of the password; a passkey confirmation works once', async () => {
    const proof = await passkeyProof();
    const r = await exportSettings(proof);
    expect(r.status).toBe(200);
    expect((await r.json()).document).toMatchObject({ format: 'secbin-export/v1', system: { settings: expect.any(Object) } });
    // The same assertion again: its challenge is used up.
    expect(await errorOf(await exportSettings(proof))).toBe('reauth_failed');
    // The password still works; neither: refused.
    expect((await exportSettings({ current: proofFor(OWNER_PW) })).status).toBe(200);
    const none = await exportSettings({});
    expect([none.status, await errorOf(none)]).toEqual([400, 'reauth_required']);
  });

  it('refuses a passkey that does not verify, and a challenge that was never issued', async () => {
    const bad = await exportSettings(await passkeyProof({ tamper: true }));
    expect([bad.status, await errorOf(bad)]).toEqual([403, 'reauth_failed']);
    const { reauth } = await passkeyProof();
    const forged = await exportSettings({ reauth: { ...reauth, challengeId: 'not-a-challenge' } });
    expect([forged.status, await errorOf(forged)]).toEqual([403, 'reauth_failed']);
    const malformed = await exportSettings({ reauth: { challengeId: 1, credential: 'x' } });
    expect([malformed.status, await errorOf(malformed)]).toEqual([400, 'reauth_required']);
  });
});

describe('the account and system import', () => {
  it('the preview and the apply each take a passkey (or the password), and refuse an invalid one', async () => {
    const doc = (await (await exportSettings({ current: proofFor(OWNER_PW) })).json()).document;
    const preview = await importSettings(doc, await passkeyProof(), true);
    expect(preview.status, await preview.clone().text()).toBe(200);
    expect(await preview.json()).toMatchObject({ ok: true, applied: false });
    expect(await errorOf(await importSettings(doc, await passkeyProof({ tamper: true }), true))).toBe('reauth_failed');
    expect(await errorOf(await importSettings(doc, await passkeyProof({ tamper: true }), false))).toBe('reauth_failed');
    expect(await errorOf(await importSettings(doc, {}, false))).toBe('reauth_required');
    const applied = await importSettings(doc, await passkeyProof(), false);
    expect(applied.status).toBe(200);
    expect(await applied.json()).toMatchObject({ ok: true, applied: true });
    expect((await importSettings(doc, { current: proofFor(OWNER_PW) }, true)).status).toBe(200);
  });

  it('the owner acting as a user reaches neither route, whatever the confirmation', async () => {
    const u = await makeUser('port-imp');
    const imp = cookieOf(await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
    const doc = (await (await exportSettings({ current: proofFor(OWNER_PW) })).json()).document;
    for (const r of [await exportSettings({ current: proofFor(OWNER_PW) }, { cookie: imp }), await importSettings(doc, { current: proofFor(OWNER_PW) }, true, { cookie: imp })]) {
      expect([r.status, await errorOf(r)]).toEqual([403, 'impersonating']);
    }
    // A user's own session: not the owner.
    expect((await exportSettings({ current: proofFor('user-password-123') }, { cookie: u.cookie })).status).toBe(403);
  });
});

describe('clearing logs', () => {
  const clearLogs = (step, body = { scope: 'all', before: 1 }, opts) => post('/api/private/admin/logs/clear', { ...step, ...body }, opts);
  it('takes a passkey instead of the password, and refuses one that does not verify', async () => {
    const ok = await clearLogs(await passkeyProof());
    expect(ok.status, await ok.clone().text()).toBe(200);
    expect(await ok.json()).toMatchObject({ ok: true, deleted: 0 });
    const bad = await clearLogs(await passkeyProof({ tamper: true }));
    expect([bad.status, await errorOf(bad)]).toEqual([403, 'reauth_failed']);
    const none = await clearLogs({});
    expect([none.status, await errorOf(none)]).toEqual([400, 'reauth_required']);
    expect((await clearLogs({ current: proofFor(OWNER_PW) })).status).toBe(200);
    expect(await errorOf(await clearLogs({ current: proofFor('not-the-password') }))).toBe('wrong_password');
  });

  it('a failed passkey counts against the network; the owner acting as a user cannot clear logs', async () => {
    const ip = freshIp();
    expect(await errorOf(await clearLogs(await passkeyProof({ tamper: true }), undefined, { ip }))).toBe('reauth_failed');
    const { tracking } = await (await fetchJson('/api/private/admin/guard', { cookie: oc })).json();
    expect(tracking.find((t) => t.key === `${ip}/32` && t.scope === 'login')).toMatchObject({ count: 1 });
    expect((await exportSettings(await passkeyProof())).status).toBe(200); // a good confirmation clears the account's count
    const u = await makeUser('port-logs-imp');
    const imp = cookieOf(await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
    const r = await clearLogs({ current: proofFor(OWNER_PW) }, undefined, { cookie: imp });
    expect([r.status, await errorOf(r)]).toEqual([403, 'impersonating']);
  });
});

describe('failed confirmations', () => {
  it('a wrong password and a failed passkey count against the network and the account, up to signing it out everywhere', async () => {
    const ip = freshIp();
    const wrong = await exportSettings({ current: proofFor('not-the-password') }, { ip });
    expect([wrong.status, await errorOf(wrong)]).toEqual([403, 'wrong_password']);
    expect(await errorOf(await exportSettings(await passkeyProof({ tamper: true }), { ip }))).toBe('reauth_failed');
    // The network's login failures (as a wrong password at login).
    const { tracking } = await (await fetchJson('/api/private/admin/guard', { cookie: oc })).json();
    expect(tracking.find((t) => t.key === `${ip}/32` && t.scope === 'login')).toMatchObject({ count: 2 });
    // A good confirmation clears the account's count; then only failed passkeys, up to the lockout.
    expect((await exportSettings(await passkeyProof())).status).toBe(200);
    let last;
    let n = 0;
    while (last !== 'session_revoked' && n < 12) {
      last = await errorOf(await importSettings({}, await passkeyProof({ tamper: true }), true, { ip: freshIp() }));
      n++;
    }
    expect(last).toBe('session_revoked');
    expect(n).toBe(10); // lockout.max (the default)
    expect((await fetchJson('/api/private/me', { cookie: oc })).status).toBe(401);
    oc = await login('owner', OWNER_PW);
    setOwnerCookie(oc);
  });
});
