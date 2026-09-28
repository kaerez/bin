// csrf.test.js — CSRF tokens (src/lib/csrf.js), a second check on top of
// SameSite=Strict cookies, the Sec-Fetch-Site check and the JSON / intent
// requirement. Every cookie-authenticated state-changing request must echo the
// session's token in X-Secbin-CSRF: a missing, wrong, other-session or
// old-session-version token is refused with 403 csrf_mismatch before anything
// changes. API keys and the anonymous routes need none. The token is bound to
// the session (the same for every request of it) and changes with it. The
// owner can turn the check off (Admin → Settings, `csrfTokens`); the other
// guards stay.
import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import { env, SELF, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import worker from '../src/index.js';
import { csrfTokensMatch, CSRF_COOKIE } from '../src/lib/csrf.js';
import { setSiteverify } from '../src/lib/turnstile.js';
import { encryptPaste } from '../public/js/crypto.js';
import {
  ORIGIN, owner, makeUser, login, fetchJson, cookieOf, csrfFor, createNote, proofHeaders, freshIp, intent, proofFor, USER_PW, salt16,
} from './helpers.js';
import { driveLimits, sealed } from './drive-helpers.js';
import { receiver, newReverse, received, sealLinkPriv } from './reverse-helpers.js';
import { linkProof, sealUpload, newNodeId as newReverseNode } from '../public/js/reversekeys.js';
import { randomBytes, utf8, b64urlFromBytes } from '../public/js/bytes.js';
import { CHUNK, encryptChunk, importFileKey } from '../public/js/files.js';
import driveSrc from '../src/routes/drive.js?raw';
import adminSrc from '../src/routes/admin.js?raw';
import reverseSrc from '../src/routes/reverse.js?raw';
import keysSrc from '../src/routes/keys.js?raw';

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

// ── the Drive's routes (src/routes/drive.js, and the owner's in admin.js) ──
// Every cookie-authenticated change under /api/private/drive and
// /api/private/admin/drive, with the method and shape the browser uses
// (public/js/api.js `drive`): a JSON body, the intent header, or (the chunk
// upload) a raw application/octet-stream body with the upload token.
const DRIVE_ID = 'AAAAAAAAAAAAAAAAAAAAAA';
const DRIVE_USER = 'uAAAAAAAAAAAAAAA';
const dj = (method, path) => ({ method, path, body: {}, headers: intent });
const da = (method, path) => ({ method, path, headers: intent });
const DRIVE_ROUTES = [
  dj('POST', '/api/private/drive/keys'), // the session's KEKs: it may make the salt, and is audited for the owner acting as the user
  dj('POST', '/api/private/drive/kit'), dj('POST', '/api/private/drive/kit/verify'), dj('POST', '/api/private/drive/kit/restore'), dj('PUT', '/api/private/drive/kit/items'),
  dj('PUT', '/api/private/drive/migrate'), dj('POST', '/api/private/drive/migrate/finish'),
  dj('POST', '/api/private/drive/folders'), dj('POST', '/api/private/drive/files'),
  { method: 'PUT', path: `/api/private/drive/files/${DRIVE_ID}/chunk/0`, raw: true },
  { method: 'POST', path: `/api/private/drive/files/${DRIVE_ID}/finalize`, headers: { ...intent, 'x-upload-token': 'A'.repeat(43) } },
  dj('PATCH', `/api/private/drive/nodes/${DRIVE_ID}`), da('DELETE', `/api/private/drive/nodes/${DRIVE_ID}`),
  dj('POST', '/api/private/drive/shares'),
  dj('PUT', `/api/private/admin/drive/migrate/${DRIVE_USER}`), dj('POST', `/api/private/admin/drive/migrate/${DRIVE_USER}/finish`),
  dj('POST', `/api/private/admin/drive/migrate/${DRIVE_USER}/escrow`),
];
/**
 * Every Drive path the routers name, one concrete path each (the reads too:
 * a state-changing method on them must be refused for its token as well).
 */
const DRIVE_PATHS = [
  '/api/private/drive', '/api/private/drive/keys', '/api/private/drive/kit', '/api/private/drive/kit/verify', '/api/private/drive/kit/restore',
  '/api/private/drive/kit/items', '/api/private/drive/migrate', '/api/private/drive/migrate/items', '/api/private/drive/migrate/finish',
  '/api/private/drive/folders', '/api/private/drive/files', `/api/private/drive/files/${DRIVE_ID}/chunk/0`,
  `/api/private/drive/files/${DRIVE_ID}/finalize`, `/api/private/drive/nodes/${DRIVE_ID}`, `/api/private/drive/nodes/${DRIVE_ID}/shares`,
  '/api/private/drive/shares', '/api/private/admin/drive/migration', `/api/private/admin/drive/migrate/${DRIVE_USER}`,
  `/api/private/admin/drive/migrate/${DRIVE_USER}/items`, `/api/private/admin/drive/migrate/${DRIVE_USER}/finish`,
  `/api/private/admin/drive/migrate/${DRIVE_USER}/escrow`,
];
/** The Drive paths that only read (GET): every other one takes a change the sweep sends. */
const DRIVE_READS = [
  '/api/private/drive', `/api/private/drive/nodes/${DRIVE_ID}/shares`, '/api/private/drive/migrate/items',
  '/api/private/admin/drive/migration', `/api/private/admin/drive/migrate/${DRIVE_USER}/items`,
];

// ── the Drive keyring (src/routes/keys.js: Admin → Security → Keys) ──
// The owner's key actions, with the method and shape the browser uses (public/js/api.js `keysApi`).
const KEYS_MEK = 'mAAAAAAAAAAA';
const KEYS_ROUTES = [
  dj('POST', '/api/private/admin/keys/candidate'), dj('POST', '/api/private/admin/keys/subs'),
  dj('PATCH', `/api/private/admin/keys/subs/${KEYS_MEK}`), dj('DELETE', `/api/private/admin/keys/subs/${KEYS_MEK}`),
  dj('POST', `/api/private/admin/keys/subs/${KEYS_MEK}/current`), dj('POST', `/api/private/admin/keys/subs/${KEYS_MEK}/show`),
  dj('POST', '/api/private/admin/keys/root'), dj('POST', '/api/private/admin/keys/root/show'),
  dj('POST', '/api/private/admin/keys/jobs'), dj('DELETE', '/api/private/admin/keys/jobs'), dj('POST', '/api/private/admin/keys/jobs/step'),
  dj('POST', '/api/private/admin/keys/kit'), dj('POST', '/api/private/admin/keys/verify'), dj('POST', '/api/private/admin/keys/restore'),
  dj('POST', '/api/private/admin/keys/export'), dj('POST', '/api/private/admin/keys/import'),
  dj('POST', `/api/private/admin/keys/users/${DRIVE_USER}/view`),
];
const KEYS_PATHS = [
  '/api/private/admin/keys', '/api/private/admin/keys/usage', '/api/private/admin/keys/candidate', '/api/private/admin/keys/subs',
  `/api/private/admin/keys/subs/${KEYS_MEK}`, `/api/private/admin/keys/subs/${KEYS_MEK}/current`, `/api/private/admin/keys/subs/${KEYS_MEK}/show`,
  '/api/private/admin/keys/root', '/api/private/admin/keys/root/show', '/api/private/admin/keys/jobs', '/api/private/admin/keys/jobs/step',
  '/api/private/admin/keys/kit', '/api/private/admin/keys/verify', '/api/private/admin/keys/restore', '/api/private/admin/keys/export',
  '/api/private/admin/keys/import', `/api/private/admin/keys/users/${DRIVE_USER}/view`,
];
const KEYS_READS = ['/api/private/admin/keys', '/api/private/admin/keys/usage'];

// ── reverse shares (src/routes/reverse.js, docs/REVERSE.md) ──
// The user's routes are cookie-authenticated (reached through the Drive router,
// or My shares / Admin → Shares for extend, revoke and lock) and must pass the
// CSRF check. The anonymous uploader's routes (/api/reverse/<id>/…) carry no
// user session and are exempt; they keep their own guards.
const REV_ID = 'rAAAAAAAAAAAAAAAAAAAAAA';
const REVERSE_ROUTES = [
  dj('POST', '/api/private/drive/reverse'), // create a link
  dj('POST', `/api/private/drive/received/${DRIVE_ID}`), // take a received file in
  dj('POST', `/api/private/drive/received/${DRIVE_ID}/failed`), // mark it failed
  da('DELETE', `/api/private/drive/received/${DRIVE_ID}/failed`), // retry it
];
/**
 * Every cookie-authenticated path reverse.js (and the Drive router's dispatch
 * to it) names, one concrete path each, with the methods it allows, in the
 * order handleReverseOwner answers them (its methodNotAllowed calls).
 */
const REVERSE_METHODS = {
  '/api/private/drive/reverse': 'GET, POST',
  '/api/private/drive/received': 'GET',
  [`/api/private/drive/received/${DRIVE_ID}/failed`]: 'POST, DELETE',
  [`/api/private/drive/received/${DRIVE_ID}`]: 'POST',
};
const REVERSE_PATHS = Object.keys(REVERSE_METHODS);
/** A reverse link's changes through the shares routes (src/routes/private.js, admin.js): extend, revoke, lock. */
const REVERSE_SHARE_ROUTES = [
  dj('PATCH', `/api/private/shares/${REV_ID}`), da('POST', `/api/private/shares/${REV_ID}/revoke`),
  dj('PATCH', `/api/private/admin/shares/${REV_ID}`), da('POST', `/api/private/admin/shares/${REV_ID}/revoke`), dj('POST', `/api/private/admin/shares/${REV_ID}/lock`),
];
/** The anonymous uploader's actions (the /api/reverse/<id>/… router): exempt, by design. */
const REVERSE_ANON_ACTIONS = ['open', 'begin', 'files', 'done'];

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

  it('covers every cookie-authenticated state-changing route', { timeout: 60000 }, async () => { // a sweep, like the ones below
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
      ...DRIVE_ROUTES, ...KEYS_ROUTES,
      ...REVERSE_ROUTES, ...REVERSE_SHARE_ROUTES,
      act('POST', '/api/auth/logout'),
    ];
    for (const r of routes) {
      const res = r.raw
        ? await fetchJson(r.path, { method: r.method, cookie: oc, csrf: false, headers: { 'content-type': 'application/octet-stream', 'x-upload-token': 'A'.repeat(43) } })
        : await send(r.method, r.path, { body: r.body, headers: r.headers });
      expect(`${r.method} ${r.path} → ${res.status} ${await errorOf(res)}`).toBe(`${r.method} ${r.path} → 403 csrf_mismatch`);
    }
    expect((await fetchJson('/api/private/me', { cookie: oc })).status).toBe(200); // the logout above was refused too
    // A simple request (a form-style text/plain body, no custom header) is
    // refused for its shape before anything else, on every route: 415 (a
    // DELETE, and logout, for the missing intent header).
    for (const r of routes) {
      const res = await fetchJson(r.path, { method: r.method, cookie: oc, csrf: false, ip: freshIp(), headers: { 'content-type': 'text/plain' } });
      const want = r.method === 'DELETE' || r.path === '/api/auth/logout' ? '400 missing_intent' : '415 unsupported_media_type';
      expect(`${r.method} ${r.path} → ${res.status} ${await errorOf(res)}`).toBe(`${r.method} ${r.path} → ${want}`);
    }
    expect((await fetchJson('/api/private/me', { cookie: oc })).status).toBe(200);
  });

  it('the sweep names every Drive route the routers have (src/routes/drive.js, admin.js)', () => {
    const paths = new Set();
    const patterns = [];
    for (const src of [driveSrc, adminSrc]) {
      for (const [, lit] of src.matchAll(/'(\/api\/private\/(?:admin\/)?drive[^']*)'/g)) paths.add(lit);
      for (const [, re] of src.matchAll(/\.match\(\/(\^\\\/api\\\/private\\\/(?:admin\\\/)?drive.*?\$)\/\)/g)) patterns.push(new RegExp(re));
    }
    expect(paths.size).toBeGreaterThan(10);
    expect(patterns.length).toBe(3); // files/…/chunk|finalize, nodes/…(/shares), admin/drive/migrate/<uid>(/escrow|/items|/finish)
    // The Drive router also dispatches the reverse-share paths (to reverse.js): the reverse sweep names those.
    const known = [...DRIVE_PATHS, ...REVERSE_PATHS];
    for (const lit of paths) {
      const covered = lit.endsWith('/') ? known.some((x) => x.startsWith(lit)) : known.includes(lit);
      expect(covered, lit).toBe(true);
    }
    for (const re of patterns) expect(DRIVE_PATHS.some((x) => re.test(x)), String(re)).toBe(true);
    // Every change the sweep sends is on one of those paths, and every path
    // that takes a change is in the sweep.
    for (const r of DRIVE_ROUTES) expect(DRIVE_PATHS, r.path).toContain(r.path);
    for (const x of DRIVE_PATHS) if (!DRIVE_READS.includes(x)) expect(DRIVE_ROUTES.some((r) => r.path === x), x).toBe(true);
  });

  it('the sweep names every keyring route (src/routes/keys.js)', () => {
    const lits = new Set([...keysSrc.matchAll(/'(\/api\/private\/admin\/keys[^']*)'/g)].map((m) => m[1]));
    const pats = [...keysSrc.matchAll(/\.match\(\/(\^\\\/api\\\/private\\\/admin\\\/keys.*?\$)\/\)/g)].map((m) => new RegExp(m[1]));
    expect(lits.size).toBeGreaterThan(10);
    expect(pats.length).toBe(2); // subs/<id>(/current|/show), users/<uid>/view
    for (const lit of lits) expect(KEYS_PATHS, lit).toContain(lit);
    for (const re of pats) expect(KEYS_PATHS.some((x) => re.test(x)), String(re)).toBe(true);
    for (const r of KEYS_ROUTES) expect(KEYS_PATHS, r.path).toContain(r.path);
    for (const x of KEYS_PATHS) if (!KEYS_READS.includes(x)) expect(KEYS_ROUTES.some((r) => r.path === x), x).toBe(true);
    // The admin router hands /api/private/admin/keys… to keys.js.
    expect(adminSrc).toMatch(/'\/api\/private\/admin\/keys'/);
  });

  it('every state-changing method on every Drive and keyring path is refused for its token before routing (no 404 / 405 / 403 of the route first)', { timeout: 60000 }, async () => {
    for (const path of [...DRIVE_PATHS, ...KEYS_PATHS, '/api/private/drive/no-such-route', `/api/private/admin/drive/other/${DRIVE_USER}`, '/api/private/admin/keys/no-such-route']) {
      for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
        const res = await send(method, path, { body: {}, headers: intent });
        expect(`${method} ${path} → ${res.status} ${await errorOf(res)}`).toBe(`${method} ${path} → 403 csrf_mismatch`);
      }
    }
    // A user without the Drive, and while impersonating: the token first too.
    const u = await makeUser('csrf-drive-none');
    for (const r of [...DRIVE_ROUTES, ...KEYS_ROUTES]) {
      const res = r.raw
        ? await fetchJson(r.path, { method: r.method, cookie: u.cookie, csrf: false, headers: { 'content-type': 'application/octet-stream', 'x-upload-token': 'A'.repeat(43) } })
        : await send(r.method, r.path, { cookie: u.cookie, body: r.body, headers: r.headers });
      expect(`${r.method} ${r.path} → ${res.status} ${await errorOf(res)}`).toBe(`${r.method} ${r.path} → 403 csrf_mismatch`);
    }
  });

  it('the Drive: with the token, the same requests reach the routes (and change something only then)', async () => {
    const u = await makeUser('csrf-drive-ok');
    await driveLimits(u.id, { driveEnabled: true });
    const token = await csrfFor(u.cookie);
    const fs = await sealed(u.cookie); // sealed under the user's current KEK, as the page does
    const folder = { parent: 'root', name: fs.name, ks: fs.ks, mek: fs.mek };
    // Refused without the token: no folder.
    expect(await errorOf(await send('POST', '/api/private/drive/folders', { cookie: u.cookie, body: folder }))).toBe('csrf_mismatch');
    const children = async () => (await (await fetchJson('/api/private/drive/nodes/root', { cookie: u.cookie })).json()).children?.length ?? 0;
    const before = await children();
    // With the token it is created.
    const ok = await send('POST', '/api/private/drive/folders', { cookie: u.cookie, token, body: folder });
    expect(ok.status).toBe(201);
    expect(await children()).toBe(before + 1);
    // A raw chunk: the chunk rule satisfies the shape check; the token is still needed.
    const chunk = (t) => fetchJson(`/api/private/drive/files/${DRIVE_ID}/chunk/0`, { method: 'PUT', cookie: u.cookie, csrf: false, headers: { 'content-type': 'application/octet-stream', 'x-upload-token': 'A'.repeat(43), ...(t ? { 'x-secbin-csrf': t } : {}) } });
    expect(await errorOf(await chunk(null))).toBe('csrf_mismatch');
    expect([403, 404, 410]).toContain((await chunk(token)).status); // past the CSRF check: the route's own answer (no such upload)
    expect(await errorOf(await chunk(token))).not.toBe('csrf_mismatch');
    // Finalize has no body: the intent header is its shape.
    const fin = (headers) => fetchJson(`/api/private/drive/files/${DRIVE_ID}/finalize`, { method: 'POST', cookie: u.cookie, headers: { 'x-upload-token': 'A'.repeat(43), ...headers } });
    expect(await errorOf(await fin({}))).toBe('missing_intent');
    expect(await errorOf(await fin(intent))).not.toBe('csrf_mismatch');
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

// Regressions for the security audit of this change (kaerez/bin#63): each
// fails on the code before the fixes.
describe('audit L1: no request of the wrong shape gets past the CSRF check or spends a human-check token', () => {
  const TS_ENV = { ...env, TURNSTILE_SITEKEY: '0x4AAAAAAAtestsitekey', TURNSTILE_SECRET: '0x4AAAAAAAtestsecretvalue' };
  const KEY = 'AAAAAAAAAAAAAAAA';
  // The Turnstile-gated routes. `human`: the change carries a human-check token.
  const ACCOUNT = [
    ['POST', '/api/private/me/password'], ['POST', '/api/private/me/username'],
    ['POST', '/api/private/me/keys'], ['PATCH', `/api/private/me/keys/${KEY}`], ['DELETE', `/api/private/me/keys/${KEY}`],
    ['POST', '/api/private/me/passkeys'], ['POST', `/api/private/me/passkeys/${KEY}/remove`],
    ['POST', '/api/private/me/recovery-codes'], ['POST', '/api/private/me/second-factor'],
  ];
  let spent;
  let restore;
  beforeAll(() => {
    // Any token is refused, and every siteverify call is counted: a call means a token was spent.
    restore = setSiteverify(async () => { spent += 1; return Response.json({ success: false, 'error-codes': ['invalid-input-response'] }); });
  });
  afterAll(() => setSiteverify(restore));
  beforeEach(() => { spent = 0; });
  const human = (method, path, { cookie, headers = {}, body } = {}) => {
    const ctx = createExecutionContext();
    const h = { 'cf-connecting-ip': freshIp(), 'x-secbin-turnstile': 'synthetic-turnstile-token', ...(cookie ? { cookie } : {}), ...headers };
    return worker.fetch(new Request(`${ORIGIN}${path}`, { method, headers: h, body }), TS_ENV, ctx).then(async (res) => { await waitOnExecutionContext(ctx); return res; });
  };
  const outcome = async (res) => `${res.status} ${await errorOf(res)}`;

  it('without the token, the JSON type or the intent header (poc3): 415 / missing_intent, and siteverify is never called', async () => {
    const u = await makeUser('csrf-l1-shape');
    for (const [method, path] of ACCOUNT) {
      const plain = await human(method, path, { cookie: u.cookie, headers: { 'content-type': 'text/plain' }, body: '{}' });
      expect(`${method} ${path} → ${await outcome(plain)}`).toBe(`${method} ${path} → ${method === 'DELETE' ? '400 missing_intent' : '415 unsupported_media_type'}`);
      const bare = await human(method, path, { cookie: u.cookie });
      expect(`${method} ${path} → ${await outcome(bare)}`).toBe(`${method} ${path} → 400 missing_intent`);
    }
    expect(spent).toBe(0);
    // Cross-site is still refused first.
    expect(await outcome(await human('POST', '/api/private/me/password', { cookie: u.cookie, headers: { 'content-type': 'text/plain', 'sec-fetch-site': 'cross-site' }, body: '{}' }))).toBe('403 cross_site');
    // …and a correctly shaped request without the token is csrf_mismatch, still before the human check.
    expect(await outcome(await human('POST', '/api/private/me/username', { cookie: u.cookie, headers: { 'content-type': 'application/json' }, body: '{}' }))).toBe('403 csrf_mismatch');
    expect(spent).toBe(0);
  });

  it('with the token and the intent header but a body that is not JSON: 415 before the human check', async () => {
    const u = await makeUser('csrf-l1-body');
    const token = await csrfFor(u.cookie);
    for (const [method, path] of ACCOUNT) {
      const res = await human(method, path, { cookie: u.cookie, headers: { ...intent, 'x-secbin-csrf': token, 'content-type': 'text/plain' }, body: '{}' });
      expect(`${method} ${path} → ${await outcome(res)}`).toBe(`${method} ${path} → 415 unsupported_media_type`);
    }
    expect(spent).toBe(0);
    // The body checks come first; a well-formed request still meets the human check.
    expect(await outcome(await human('POST', '/api/private/me/username', { cookie: u.cookie, headers: { 'x-secbin-csrf': token, 'content-type': 'application/json' }, body: '{}' }))).toBe('403 turnstile_failed');
    expect(spent).toBe(1);
  });

  it('with the csrfTokens setting off too', async () => {
    const u = await makeUser('csrf-l1-off');
    expect((await settings({ csrfTokens: false })).status).toBe(200);
    try {
      for (const [method, path] of ACCOUNT) {
        const res = await human(method, path, { cookie: u.cookie, headers: { 'content-type': 'text/plain' }, body: '{}' });
        expect(`${method} ${path} → ${await outcome(res)}`).toBe(`${method} ${path} → ${method === 'DELETE' ? '400 missing_intent' : '415 unsupported_media_type'}`);
      }
      expect(spent).toBe(0);
    } finally {
      expect((await settings({ csrfTokens: true })).status).toBe(200);
    }
  });

  it('the anonymous routes with a human check read their body first too (sign-in, recovery, passkey sign-in, public shares)', async () => {
    for (const path of ['/api/auth/login', '/api/auth/recovery', '/api/auth/passkey/login']) {
      expect(`${path} → ${await outcome(await human('POST', path, { headers: { 'content-type': 'text/plain' }, body: '{}' }))}`).toBe(`${path} → 415 unsupported_media_type`);
    }
    expect((await settings({ 'public.enabled': true, 'public.tracking': 'ip' })).status).toBe(200);
    try {
      for (const path of ['/api/public/paste', '/api/public/file']) {
        expect(`${path} → ${await outcome(await human('POST', path, { headers: { 'content-type': 'text/plain' }, body: '{}' }))}`).toBe(`${path} → 415 unsupported_media_type`);
      }
    } finally {
      await settings({ 'public.enabled': false, 'public.tracking': 'tracker' });
    }
    expect(spent).toBe(0);
  });
});

describe('audit I3: the token cookie never outlives the session cookie', () => {
  const maxAge = (c) => Number(/Max-Age=(\d+)/.exec(c ?? '')?.[1]);
  it('on a dashboard load and on /api/private/me, its lifetime is what the session cookie has left (the idle window), not the absolute expiry', async () => {
    await makeUser('csrf-i3');
    const r = await loginRes('csrf-i3', USER_PW);
    const sess = maxAge(setCookies(r).find((c) => c.startsWith('__Host-secbin_sess=')));
    const idle = (await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json()).settings['session.idleSec'];
    expect(sess).toBe(idle); // 12 hours by default; the absolute expiry is 7 days
    const cookie = cookieOf(r);
    for (const path of ['/dashboard/', '/api/private/me']) {
      const t = maxAge(csrfCookieOf(await fetchJson(path, { cookie })));
      expect(`${path}: ${t <= sess && t >= sess - 5}`).toBe(`${path}: true`);
    }
  });
});

describe('audit I5: POST /api/auth/passkey/options has the same guards as the other auth routes', () => {
  const options = (headers, body) => SELF.fetch(`${ORIGIN}/api/auth/passkey/options`, { method: 'POST', headers: { 'cf-connecting-ip': freshIp(), ...headers }, body });
  it('refuses a simple cross-site POST and a body that is not JSON; a same-origin JSON request gets its challenge', async () => {
    const cross = await options({ 'content-type': 'text/plain', 'sec-fetch-site': 'cross-site' }, 'x');
    expect(`${cross.status} ${await errorOf(cross)}`).toBe('403 cross_site');
    const sameSite = await options({ 'content-type': 'application/json', 'sec-fetch-site': 'same-site' }, '{}');
    expect(`${sameSite.status} ${await errorOf(sameSite)}`).toBe('403 cross_site');
    const plain = await options({ 'content-type': 'text/plain' }, 'x');
    expect(`${plain.status} ${await errorOf(plain)}`).toBe('415 unsupported_media_type');
    const ok = await options({ 'content-type': 'application/json', 'sec-fetch-site': 'same-origin' }, '{}');
    expect(ok.status).toBe(200);
    expect(typeof (await ok.json()).challengeId).toBe('string');
  });
});

// ── reverse shares (src/routes/reverse.js; docs/REVERSE.md, SECURITY.md "CSRF") ──
describe('reverse shares: the user’s routes need the token; the anonymous uploader’s are exempt', () => {
  it('the sweep names every cookie-authenticated route reverse.js has, and its anonymous router has only the exempt actions', () => {
    const lits = [...new Set([...reverseSrc.matchAll(/'(\/api\/[^']*)'/g)].map((m) => m[1]))];
    const pats = [...reverseSrc.matchAll(/\.match\(\/(\^\\\/api\\\/.*?\$)\/\)/g)].map((m) => m[1]);
    expect(lits.length).toBeGreaterThanOrEqual(2); // /api/private/drive/reverse, /api/private/drive/received
    expect(pats.length).toBe(2); // received/<id>(/failed), and the anonymous /api/reverse/<id>/…
    // Every route is either the user's (cookie-authenticated, /api/private/) or
    // the anonymous uploader's (/api/reverse/): a route under any other prefix
    // must be classified here first.
    for (const x of [...lits, ...pats]) expect(/^\^?\\?\/api\\?\/(private|reverse)\\?\//.test(x), x).toBe(true);
    const privLits = lits.filter((x) => x.startsWith('/api/private/'));
    const privPats = pats.filter((x) => x.startsWith('^\\/api\\/private\\/')).map((x) => new RegExp(x));
    for (const lit of privLits) expect(REVERSE_PATHS, lit).toContain(lit);
    for (const re of privPats) expect(REVERSE_PATHS.some((x) => re.test(x)), String(re)).toBe(true);
    for (const r of REVERSE_ROUTES) expect(REVERSE_PATHS, r.path).toContain(r.path);
    // Each route's methods, as the user's handler allows them: a new route or
    // method there changes this list, and every state-changing one must be in
    // the sweep.
    const owner = reverseSrc.slice(0, reverseSrc.indexOf('export async function handleReversePublic'));
    expect([...owner.matchAll(/methodNotAllowed\('([^']+)'\)/g)].map((m) => m[1])).toEqual(Object.values(REVERSE_METHODS));
    for (const [path, allowed] of Object.entries(REVERSE_METHODS)) {
      for (const method of allowed.split(', ').filter((x) => x !== 'GET')) {
        expect(REVERSE_ROUTES.some((r) => r.path === path && r.method === method), `${method} ${path}`).toBe(true);
      }
    }
    // The anonymous router: exactly the exempt actions (a new one must be added here, deliberately).
    const anon = pats.filter((x) => x.startsWith('^\\/api\\/reverse\\/'));
    expect(anon).toHaveLength(1);
    const actions = /\\\/\(([a-z|]+)\)/.exec(anon[0])?.[1].split('|').sort();
    expect(actions).toEqual([...REVERSE_ANON_ACTIONS].sort());
  });

  it('every state-changing method on every reverse path is refused for its token before routing (the owner, a user without the Drive, a user with reverse shares)', { timeout: 60000 }, async () => {
    const none = await makeUser('csrf-rev-none');
    const rec = await receiver('csrf-rev-sweep');
    for (const cookie of [oc, none.cookie, rec.cookie]) {
      for (const path of REVERSE_PATHS) {
        for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
          const res = await send(method, path, { cookie, body: {}, headers: intent });
          expect(`${method} ${path} → ${res.status} ${await errorOf(res)}`).toBe(`${method} ${path} → 403 csrf_mismatch`);
        }
      }
      for (const r of [...REVERSE_ROUTES, ...REVERSE_SHARE_ROUTES]) {
        const res = await send(r.method, r.path, { cookie, body: r.body, headers: r.headers });
        expect(`${r.method} ${r.path} → ${res.status} ${await errorOf(res)}`).toBe(`${r.method} ${r.path} → 403 csrf_mismatch`);
        // A simple (form-style) request is refused for its shape first.
        const plain = await fetchJson(r.path, { method: r.method, cookie, csrf: false, ip: freshIp(), headers: { 'content-type': 'text/plain' } });
        const want = r.method === 'DELETE' ? '400 missing_intent' : '415 unsupported_media_type';
        expect(`${r.method} ${r.path} → ${plain.status} ${await errorOf(plain)}`).toBe(`${r.method} ${r.path} → ${want}`);
      }
    }
  });

  it('create, extend, revoke, take in, mark failed and retry: refused without the token (nothing changes), done with it; the uploader needs none, even with a session cookie present', { timeout: 60000 }, async () => {
    const u = await makeUser('csrf-rev-flow');
    const rec = await receiver('csrf-rev-flow-r');
    const token = await csrfFor(rec.cookie);
    const links = async () => (await (await fetchJson('/api/private/drive/reverse', { cookie: rec.cookie })).json()).reverse;

    // Create: as the page does (fetchJson sends the session's token), 201.
    const before = (await links()).length;
    const link = await newReverse(rec.cookie);
    expect(link.res.status).toBe(201);
    expect((await links()).length).toBe(before + 1);
    // Another link's body without the token (or with a wrong one, or another
    // account's): refused, nothing is claimed or created; with it, 201.
    const againId = `r${b64urlFromBytes(randomBytes(16))}`;
    const again = { ...link.body, id: againId, ...(await sealLinkPriv(rec.cookie, againId, link.privateKey)) }; // the private key is bound to the link id
    for (const t of [undefined, 'A'.repeat(43), await csrfFor(u.cookie)]) {
      const r = await send('POST', '/api/private/drive/reverse', { cookie: rec.cookie, token: t, body: again, headers: intent });
      expect(`${r.status} ${await errorOf(r)}`).toBe('403 csrf_mismatch');
    }
    expect((await links()).length).toBe(before + 1);
    const ok = await send('POST', '/api/private/drive/reverse', { cookie: rec.cookie, token, body: again, headers: intent });
    expect(ok.status).toBe(201);
    expect((await links()).length).toBe(before + 2);

    // Extend and revoke (My shares): refused without the token.
    const expiresOf = async (id) => (await (await fetchJson(`/api/private/shares/${id}`, { cookie: rec.cookie })).json()).share;
    const was = await expiresOf(again.id);
    const later = was.expires + 3600;
    expect(await errorOf(await send('PATCH', `/api/private/shares/${again.id}`, { cookie: rec.cookie, body: { expires: later } }))).toBe('csrf_mismatch');
    expect(await errorOf(await send('POST', `/api/private/shares/${again.id}/revoke`, { cookie: rec.cookie, headers: intent }))).toBe('csrf_mismatch');
    expect(await expiresOf(again.id)).toMatchObject({ expires: was.expires, status: 'active' });
    expect((await send('PATCH', `/api/private/shares/${again.id}`, { cookie: rec.cookie, token, body: { expires: later } })).status).toBe(200);
    expect((await send('POST', `/api/private/shares/${again.id}/revoke`, { cookie: rec.cookie, token, headers: intent })).status).toBe(200);
    expect(await expiresOf(again.id)).toMatchObject({ expires: later, status: 'revoked' });

    // The uploader (anonymous): with the user's session cookie in the browser
    // and no token (or a wrong one), every call works; the anonymous guards
    // (cross-site, intent header, link proof) still apply.
    const ip = freshIp();
    const anon = (path, { method = 'POST', headers = {}, body, csrf } = {}) => fetchJson(`/api/reverse/${link.id}${path}`, {
      method, body, ip, cookie: rec.cookie, csrf: false, headers: { ...intent, ...(csrf ? { 'x-secbin-csrf': csrf } : {}), ...headers },
    });
    const lp = await linkProof(link.pub);
    expect(`${(await anon('/open', { headers: { 'x-link-proof': lp, 'sec-fetch-site': 'cross-site' } })).status}`).toBe('403');
    expect(await errorOf(await fetchJson(`/api/reverse/${link.id}/open`, { method: 'POST', ip, cookie: rec.cookie, csrf: false, headers: { 'x-link-proof': lp } }))).toBe('missing_intent');
    expect(await errorOf(await anon('/open', { headers: { 'x-link-proof': b64urlFromBytes(randomBytes(32)) } }))).toBe('bad_link');
    expect((await anon('/open', { headers: { 'x-link-proof': lp } })).status).toBe(200);
    const b = await anon('/begin', { headers: { 'x-link-proof': lp }, csrf: 'A'.repeat(43) });
    expect(b.status).toBe(200);
    const { grant } = await b.json();
    const reserveOne = async (bytes) => {
      const node = newReverseNode();
      const fk = randomBytes(32);
      const sealed = await sealUpload(link.pub, link.id, node, fk, { path: 'a.txt', type: 'text/plain', mtime: 1700000000000, size: bytes.length });
      const r = await anon('/files', { headers: { 'x-reverse-grant': grant }, body: { id: node, ...sealed, size: bytes.length } });
      expect(r.status).toBe(201);
      return { node, fk, ...(await r.json()) };
    };
    const bytes = utf8('hello from the uploader');
    const f = await reserveOne(bytes);
    const key = await importFileKey(b64urlFromBytes(f.fk));
    for (let i = 0; i < f.chunks; i++) {
      const ct = await encryptChunk(key, i, f.chunks, bytes.slice(i * CHUNK, (i + 1) * CHUNK));
      const pr = await SELF.fetch(`${ORIGIN}/api/reverse/${link.id}/files/${f.node}/chunk/${i}`, {
        method: 'PUT', body: ct, headers: { cookie: rec.cookie, 'content-type': 'application/octet-stream', 'x-upload-token': f.uploadToken, 'cf-connecting-ip': ip },
      });
      expect(pr.status).toBe(200);
    }
    expect((await anon(`/files/${f.node}/finalize`, { headers: { 'x-reverse-grant': grant, 'x-upload-token': f.uploadToken } })).status).toBe(200);
    const g = await reserveOne(utf8('cancelled'));
    expect((await anon(`/files/${g.node}`, { method: 'DELETE', headers: { 'x-reverse-grant': grant, 'x-upload-token': g.uploadToken } })).status).toBe(200);
    expect((await anon('/done', { headers: { 'x-reverse-grant': grant } })).status).toBe(200);

    // Take in, mark failed, retry: refused without the token (the item stays where it was), done with it.
    const queued = async () => (await received(rec.cookie)).items.map((i) => i.id);
    expect(await queued()).toEqual([f.node]);
    const tf = await sealed(rec.cookie, 'file'); // sealed under the receiver's current KEK, as the page does
    const takeIn = { parent: 'root', name: tf.name, meta: tf.meta, dek: tf.dek, ks: tf.ks, mek: tf.mek };
    expect(await errorOf(await send('POST', `/api/private/drive/received/${f.node}`, { cookie: rec.cookie, body: takeIn, headers: intent }))).toBe('csrf_mismatch');
    expect(await errorOf(await send('POST', `/api/private/drive/received/${f.node}/failed`, { cookie: rec.cookie, body: { reason: 'unreadable' }, headers: intent }))).toBe('csrf_mismatch');
    expect(await queued()).toEqual([f.node]);
    const failedList = async () => (await (await fetchJson('/api/private/drive/received?failed=1', { cookie: rec.cookie })).json()).items.map((i) => i.id);
    expect((await send('POST', `/api/private/drive/received/${f.node}/failed`, { cookie: rec.cookie, token, body: {}, headers: intent })).status).toBe(200);
    expect(await failedList()).toEqual([f.node]);
    expect(await errorOf(await send('DELETE', `/api/private/drive/received/${f.node}/failed`, { cookie: rec.cookie, headers: intent }))).toBe('csrf_mismatch');
    expect(await failedList()).toEqual([f.node]);
    expect((await send('DELETE', `/api/private/drive/received/${f.node}/failed`, { cookie: rec.cookie, token, headers: intent })).status).toBe(200);
    expect(await queued()).toEqual([f.node]);
    expect((await send('POST', `/api/private/drive/received/${f.node}`, { cookie: rec.cookie, token, body: takeIn, headers: intent })).status).toBe(200);
    expect(await queued()).toEqual([]);
  });
});
