// helpers.js — shared fixtures for the workerd suites: an owner account created
// through the real setup flow, cookie-carrying request helpers, and note/file
// builders using the real client crypto (Argon2id is replaced by a stand-in —
// workerd cannot compile WebAssembly at runtime, and the server never runs it).
import { env, SELF } from 'cloudflare:test';
import { encryptPaste, deriveAccess, setPasswordStretcher, hkdf32 } from '../public/js/crypto.js';
import { b64urlFromBytes, randomBytes, utf8 } from '../public/js/bytes.js';
import { CSRF_COOKIE } from '../src/lib/csrf.js';

export const ORIGIN = 'https://secbin.test';
export const AUTHN = env.AUTHN;

// Deterministic stand-in for Argon2id in workerd (NOT a KDF — tests only).
setPasswordStretcher(async (pw, salt) => hkdf32(pw, salt, utf8('test-stretch')));

export const salt16 = () => b64urlFromBytes(randomBytes(16));
/** A fake client-side Argon2id output for `password` (the server never sees the password). */
export const proofFor = (password) => b64urlFromBytes(new Uint8Array(32).map((_, i) => (password.charCodeAt(i % password.length) + i) & 0xff));

let ipCounter = 1;
/** A fresh client IP per test file/area so Guard state never bleeds between tests. */
export const freshIp = () => `198.51.100.${(ipCounter++ % 250) + 1}`;

// Accounts have no settings of their own: roles replace them. Tests that set a
// limit, quota or viewer rule "for a user" give that user a role of their own
// ("user <id>") and set it there, which is what an admin would do.
const ROLE_SCOPED = /^\/api\/private\/admin\/(limits|quotas|viewer-rules)$/;
const userRoles = new Map();
async function roleForUser(uid, cookie) {
  if (userRoles.has(uid)) return userRoles.get(uid);
  const name = `user ${uid}`;
  const call = async (p, init) => SELF.fetch(`${ORIGIN}${p}`, { ...init, headers: { 'content-type': 'application/json', cookie, 'x-secbin-intent': '1', ...(await csrfHeaders(cookie)) }, redirect: 'manual' });
  let r = await call('/api/private/admin/roles', { method: 'POST', body: JSON.stringify({ name }) });
  let id = r.status === 201 ? (await r.json()).id : null;
  if (!id) id = (await (await call('/api/private/admin/roles', { method: 'GET' })).json()).roles.find((x) => x.name === name)?.id;
  r = await call(`/api/private/admin/users/${uid}/role`, { method: 'PUT', body: JSON.stringify({ roleId: id }) });
  if (r.status !== 200) throw new Error(`role for ${uid}: ${r.status} ${await r.text()}`);
  userRoles.set(uid, id);
  return id;
}

// CSRF tokens (src/lib/csrf.js): like the browser client (public/js/api.js),
// a signed-in state-changing request carries the session's token. The helpers
// take it from the response that set the session cookie (cookieOf), or else
// from GET /api/private/me, once per cookie, and send it unless the test
// passes `csrf: false` or sets X-Secbin-CSRF itself.
export const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const csrfCache = new Map();
/** The session's CSRF token for `cookie` (null when the session is not valid). */
export async function csrfFor(cookie, ip) {
  if (!cookie) return null;
  if (csrfCache.has(cookie)) return csrfCache.get(cookie);
  const r = await SELF.fetch(`${ORIGIN}/api/private/me`, { headers: { cookie, ...(ip ? { 'cf-connecting-ip': ip } : {}) }, redirect: 'manual' });
  const token = r.status === 200 ? (await r.json()).csrf ?? null : null;
  if (token) csrfCache.set(cookie, token);
  return token;
}
/** { 'x-secbin-csrf': token } for `cookie`, or {}. */
export async function csrfHeaders(cookie, ip) {
  const t = await csrfFor(cookie, ip);
  return t ? { 'x-secbin-csrf': t } : {};
}

export async function fetchJson(path, { method = 'GET', body, cookie, headers = {}, ip, csrf = true } = {}) {
  if (ROLE_SCOPED.test(path) && body && typeof body.scope === 'string' && /^[A-Za-z0-9_-]{16}$/.test(body.scope) && body.scope !== 'public-user-0000') {
    body = { ...body, scope: `role:${await roleForUser(body.scope, cookie)}` };
  }
  const h = { ...headers };
  if (csrf && cookie && STATE_CHANGING.has(method) && !Object.keys(h).some((k) => k.toLowerCase() === 'x-secbin-csrf')) Object.assign(h, await csrfHeaders(cookie, ip));
  if (body !== undefined) h['content-type'] = 'application/json';
  if (cookie) h.cookie = cookie;
  if (ip) h['cf-connecting-ip'] = ip;
  return SELF.fetch(`${ORIGIN}${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
}

/**
 * The session cookie a response sets (`name=value`), or null. A response that
 * starts a session also sets its CSRF token cookie (src/lib/csrf.js); that
 * token is recorded for the session cookie, as the browser has it from the
 * same response, so the helpers need no GET /api/private/me for it.
 */
export const cookieOf = (res) => {
  const all = res.headers.getSetCookie().map((c) => c.split(';')[0]);
  const cookie = all[0] ?? null;
  const t = all.find((c) => c.startsWith(`${CSRF_COOKIE}=`))?.slice(CSRF_COOKIE.length + 1);
  if (cookie && /^__Host-secbin_sess=./.test(cookie) && /^[A-Za-z0-9_-]{43}$/.test(t || '')) csrfCache.set(cookie, t);
  return cookie;
};

let ownerCookie = null;
/** Create (once per file) and log in the owner. */
export async function owner() {
  if (ownerCookie) return ownerCookie;
  const st = await (await fetchJson('/api/auth/setup')).json();
  if (st.enabled) {
    const r = await fetchJson('/api/auth/setup', { method: 'POST', body: { token: AUTHN, username: 'owner', salt: salt16(), t: 3, proof: proofFor('owner-password') } });
    if (r.status !== 200) throw new Error(`setup failed ${r.status} ${await r.text()}`);
  }
  ownerCookie = await login('owner', 'owner-password');
  return ownerCookie;
}

/** Replace the cached owner cookie (after a recovery/password change in a test). */
export function setOwnerCookie(c) { ownerCookie = c; }

export async function login(username, password, ip) {
  const r = await fetchJson('/api/auth/login', { method: 'POST', body: { username, proof: proofFor(password) }, ip });
  if (r.status !== 200) throw new Error(`login failed ${r.status} ${await r.text()}`);
  return cookieOf(r);
}

/** Owner creates a user; returns { id, cookie }. */
export const USER_PW = 'user-password-123';
export async function makeUser(username, password = USER_PW) {
  const oc = await owner();
  const r = await fetchJson('/api/private/admin/users', { method: 'POST', cookie: oc, body: { username, salt: salt16(), t: 3, proof: proofFor(password) } });
  if (r.status !== 201) throw new Error(`create user failed ${r.status} ${await r.text()}`);
  const { user } = await r.json();
  return { id: user.id, cookie: await login(username, password) };
}

export const intent = { 'x-secbin-intent': '1' };

/** Encrypt + create a note as `cookie`. Returns { id, deletetoken, fragment, body, res }. */
export async function createNote(cookie, opts = {}, { label, headers } = {}) {
  const { body, fragment } = await encryptPaste({ text: 'hello', ...opts });
  const res = await fetchJson('/api/private/paste', { method: 'POST', cookie, body: { paste: body, label }, headers });
  const data = res.status === 201 ? await res.json() : null;
  return { ...(data || {}), fragment, body, res, password: opts.password || '' };
}

/** Proof headers for opening a share. */
export async function proofHeaders(adata, fragment, password = '') {
  const a = await deriveAccess({ adata, fragment, password });
  return { access: a, headers: { 'x-link-proof': a.linkProof, 'x-key-proof': a.keyProof } };
}

export async function openNote(id, fragment, password = '', { ip, tamper } = {}) {
  const head = await (await fetchJson(`/api/paste/${id}`, { ip })).json();
  const { access, headers } = await proofHeaders(head.adata, tamper ? b64urlFromBytes(randomBytes(32)) : fragment, password);
  const res = await fetchJson(`/api/paste/${id}/open`, { method: 'POST', headers, ip });
  return { res, access, head };
}
