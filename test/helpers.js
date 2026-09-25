// helpers.js — shared fixtures for the workerd suites: an owner account created
// through the real setup flow, cookie-carrying request helpers, and note/file
// builders using the real client crypto (Argon2id is replaced by a stand-in —
// workerd cannot compile WebAssembly at runtime, and the server never runs it).
import { env, SELF } from 'cloudflare:test';
import { encryptPaste, deriveAccess, setPasswordStretcher, hkdf32 } from '../public/js/crypto.js';
import { b64urlFromBytes, randomBytes, utf8 } from '../public/js/bytes.js';

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

export function fetchJson(path, { method = 'GET', body, cookie, headers = {}, ip } = {}) {
  const h = { ...headers };
  if (body !== undefined) h['content-type'] = 'application/json';
  if (cookie) h.cookie = cookie;
  if (ip) h['cf-connecting-ip'] = ip;
  return SELF.fetch(`${ORIGIN}${path}`, { method, headers: h, body: body === undefined ? undefined : JSON.stringify(body), redirect: 'manual' });
}

export const cookieOf = (res) => {
  const sc = res.headers.get('set-cookie');
  return sc ? sc.split(';')[0] : null;
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
export async function makeUser(username, password = 'user-password-123') {
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
