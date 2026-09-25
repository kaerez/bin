// hardening.test.js — regression tests for the security-hardening pass:
// disabled accounts are refused everywhere (even with a still-valid session or
// API key), missing bindings answer a clean 503, same-site requests cannot
// change state, a wrong current password counts toward lockout, account
// passwords use the default time cost, and share-list totals honor filters.
import { env, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import worker from '../src/index.js';
import { ORIGIN, owner, makeUser, fetchJson, createNote, freshIp, intent, salt16, proofFor, login } from './helpers.js';

let oc;
beforeAll(async () => { oc = await owner(); });

const patchUser = (id, body) => fetchJson(`/api/private/admin/users/${id}`, { method: 'PATCH', cookie: oc, body });

describe('disabled accounts', () => {
  it('are refused on every route, with a session or an API key, until re-enabled', async () => {
    const u = await makeUser('disabled-matrix');
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: u.id, channel: 'all', patch: { apiEnabled: true } } });
    const k = await (await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { name: 'cli' } })).json();
    const note = await createNote(u.cookie, {}, { label: 'mine' });
    expect(note.res.status).toBe(201);

    expect((await patchUser(u.id, { disabled: true })).status).toBe(200);

    const bearer = { authorization: `Bearer ${k.key}` };
    const calls = [
      ['GET', '/api/private/me'],
      ['GET', '/api/private/me/keys'],
      ['GET', '/api/private/me/activity'],
      ['GET', '/api/private/shares'],
      ['PATCH', `/api/private/shares/${note.id}`, { label: 'renamed' }],
      ['POST', `/api/private/shares/${note.id}/revoke`, undefined, intent],
      ['POST', '/api/private/paste', { paste: note.body }],
    ];
    for (const [method, path, body, headers] of calls) {
      const r = await fetchJson(path, { method, cookie: u.cookie, body, headers });
      expect([path, r.status]).toEqual([path, 403]);
      const j = await r.json();
      expect(j.error).toBe('account_disabled');
      expect(r.headers.get('set-cookie')).toMatch(/__Host-secbin_sess=;.*Max-Age=0/);
    }
    // API key: refused with the same explicit reason.
    const viaKey = await fetchJson('/api/private/paste', { method: 'POST', headers: bearer, body: { paste: note.body } });
    expect(viaKey.status).toBe(403);
    expect((await viaKey.json()).error).toBe('account_disabled');
    // The dashboard sends the browser to login with the reason and clears the cookie.
    const dash = await fetchJson('/dashboard/', { cookie: u.cookie });
    expect(dash.status).toBe(302);
    expect(dash.headers.get('location')).toBe('/dashboard/login/?disabled=1');
    expect(dash.headers.get('set-cookie')).toMatch(/Max-Age=0/);
    // The share itself was not touched.
    const list = await (await fetchJson('/api/private/shares', { cookie: oc })).json();
    expect(list.rows.some((r) => r.id === note.id)).toBe(false); // owner's list is scoped to the owner

    // Re-enabling does not resurrect the old session (the session version moved on).
    await patchUser(u.id, { disabled: false });
    expect((await fetchJson('/api/private/me', { cookie: u.cookie })).status).toBe(401);
    // …but the API key works again (keys are not tied to sessions).
    expect((await fetchJson('/api/private/paste', { method: 'POST', headers: bearer, body: { paste: (await createNote(null, {}, {})).body } })).status).not.toBe(403);
  });
});

describe('missing bindings', () => {
  async function call(path, envPatch, init = {}) {
    const ctx = createExecutionContext();
    const res = await worker.fetch(new Request(`${ORIGIN}${path}`, init), { ...env, ...envPatch }, ctx);
    await waitOnExecutionContext(ctx);
    return res;
  }

  it('answer a clean 503 naming the binding, never a 500', async () => {
    // (The bare session probe and the logged-out dashboard redirect need no
    // storage at all, so they are not in this list.)
    for (const [name, path, init] of [['DIRECTORY', '/api/auth/prelogin', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"username":"x"}' }], ['PASTES', '/api/paste/kAAAAAAAAAAAAAAAAAAAAAA'], ['BURN', '/api/paste/bAAAAAAAAAAAAAAAAAAAAAA'], ['FILESHARE', '/api/file/fAAAAAAAAAAAAAAAAAAAAAA']]) {
      for (const value of [undefined, null, 'oops', 42, {}]) {
        const r = await call(path, { [name]: value }, init ? { ...init } : {});
        expect([name, value, r.status]).toEqual([name, value, 503]);
        const j = await r.json();
        expect(j.error).toBe('not_configured');
        expect(JSON.stringify(j)).not.toContain(name); // the binding name stays in the logs
      }
    }
  });

  it('keep public pages served when storage is missing', async () => {
    const r = await call('/', { DIRECTORY: undefined, PASTES: undefined, FILES: undefined });
    expect(r.status).toBe(200);
  });

  it('tolerate garbage environment variables', async () => {
    for (const bad of [{ DISABLE_BFP: 'maybe' }, { DISABLE_BFP: 1 }, { DISABLE_BFP: {} }, { DISABLE_BFP_SETUP: [] }, { SIG: 12, ENC: null }, { AUTHN: { x: 1 } }]) {
      const r = await call('/api/auth/session', bad);
      expect(r.status).toBeLessThan(500);
    }
  });
});

describe('CSRF', () => {
  it('refuses same-site and cross-site state changes, allows same-origin and header-less clients', async () => {
    for (const site of ['same-site', 'cross-site']) {
      const r = await fetchJson('/api/private/paste', { method: 'POST', cookie: oc, headers: { 'sec-fetch-site': site }, body: { paste: {} } });
      expect(r.status).toBe(403);
      expect((await r.json()).error).toBe('cross_site');
    }
    const ok = await createNote(oc, {}, { headers: { 'sec-fetch-site': 'same-origin' } });
    expect(ok.res.status).toBe(201);
  });
});

describe('password change', () => {
  it('ends every session after repeated wrong current passwords, without locking the account', async () => {
    const u = await makeUser('pw-guesser', 'right-password-123');
    // A fresh IP per attempt isolates the per-account rule from the per-IP guard.
    const attempt = (cookie) => fetchJson('/api/private/me/password', {
      method: 'POST', cookie, ip: freshIp(), body: { current: proofFor('wrong-guess-xyz'), salt: salt16(), t: 3, proof: proofFor('new-password-123') },
    });
    const statuses = [];
    let last;
    for (let i = 0; i < 10; i++) { last = await attempt(u.cookie); statuses.push(last.status); }
    expect(statuses.slice(0, 9)).toEqual(Array(9).fill(403));
    expect(statuses[9]).toBe(401); // default: 10 wrong attempts in 10 minutes
    expect((await last.json()).error).toBe('session_revoked');
    expect(last.headers.get('set-cookie')).toMatch(/Max-Age=0/);
    // The stolen session is dead…
    expect((await fetchJson('/api/private/me', { cookie: u.cookie })).status).toBe(401);
    // …but the account is not locked: the real owner can log in and change the password.
    const again = await login('pw-guesser', 'right-password-123', freshIp());
    const ok = await fetchJson('/api/private/me/password', {
      method: 'POST', cookie: again, ip: freshIp(), body: { current: proofFor('right-password-123'), salt: salt16(), t: 3, proof: proofFor('new-password-123') },
    });
    expect(ok.status).toBe(200);
  });

  it('a login lockout never blocks a password change', async () => {
    const u = await makeUser('locked-changer', 'right-password-456');
    for (let i = 0; i < 10; i++) {
      await fetchJson('/api/auth/login', { method: 'POST', ip: freshIp(), body: { username: 'locked-changer', proof: proofFor('attacker-guess') } });
    }
    expect((await fetchJson('/api/auth/login', { method: 'POST', ip: freshIp(), body: { username: 'locked-changer', proof: proofFor('right-password-456') } })).status).toBe(423);
    const r = await fetchJson('/api/private/me/password', {
      method: 'POST', cookie: u.cookie, ip: freshIp(), body: { current: proofFor('right-password-456'), salt: salt16(), t: 3, proof: proofFor('new-password-456') },
    });
    expect(r.status).toBe(200);
  });

  it('impersonating a user who is then disabled ends the session without "account disabled"', async () => {
    const u = await makeUser('imp-then-disabled');
    const imp = await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent });
    const cookie = imp.headers.get('set-cookie').split(';')[0];
    await patchUser(u.id, { disabled: true });
    const r = await fetchJson('/api/private/me', { cookie });
    expect(r.status).toBe(401);
    expect((await r.json()).error).toBe('unauthenticated');
  });

  it('requires the default Argon2id time cost for every account password', async () => {
    const r = await fetchJson('/api/private/admin/users', { method: 'POST', cookie: oc, body: { username: 'odd-cost', salt: salt16(), t: 5, proof: proofFor('odd-cost-password') } });
    expect(r.status).toBe(400);
    expect((await r.json()).message).toMatch(/time cost must be 3/);
  });

  it('prelogin answers the same time cost for real and unknown users', async () => {
    await makeUser('real-person');
    const real = await (await fetchJson('/api/auth/prelogin', { method: 'POST', body: { username: 'real-person' } })).json();
    const ghost = await (await fetchJson('/api/auth/prelogin', { method: 'POST', body: { username: 'no-such-person' } })).json();
    expect(real.t).toBe(ghost.t);
  });
});

describe('share list', () => {
  it('reports totals that honor the search and status filters', async () => {
    const u = await makeUser('lister');
    await createNote(u.cookie, {}, { label: 'alpha one' });
    await createNote(u.cookie, {}, { label: 'alpha two' });
    await createNote(u.cookie, {}, { label: 'beta' });
    const all = await (await fetchJson('/api/private/shares', { cookie: u.cookie })).json();
    expect(all.total).toBe(3);
    const alpha = await (await fetchJson('/api/private/shares?q=alpha', { cookie: u.cookie })).json();
    expect(alpha.rows).toHaveLength(2);
    expect(alpha.total).toBe(2);
    await login('lister', 'user-password-123');
  });
});
