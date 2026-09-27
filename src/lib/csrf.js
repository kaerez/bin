// csrf.js — CSRF tokens, a second line of defence on top of SameSite=Strict
// cookies, the Sec-Fetch-Site check and the JSON / X-Secbin-Intent requirement
// (SECURITY.md §6 "CSRF").
//
// The token is stateless and bound to the session:
//   HMAC-SHA256(K, "secbin-csrf/v1:" + sid + ":" + ver), base64url
// where K = HMAC-SHA256(SIG, "secbin-csrf-key/v1") is a subkey of the session
// signing secret used for nothing else, `sid` is the session id and `ver` the
// session version it is bound to (the owner's while impersonating). It is the
// same for every tab and request of a session and changes only with the
// session: sign-in, sign-out, a session-version bump, impersonation start/end.
//
// The browser gets it in a readable cookie (not HttpOnly, so page script can
// copy it into the X-Secbin-CSRF header) whenever the session cookie is set or
// refreshed, on every signed-in dashboard page load, and in GET
// /api/private/me (body and cookie). Only cookie-authenticated state-
// changing requests are checked (authenticate() in auth.js, and logout); API
// keys carry no cookies, and anonymous routes have no session.
//
// Never log the token or put it in an error message.

import { sessionKeys } from './config.js';
import { HttpError } from './http.js';
import { b64urlFromBytes, utf8 } from '../../public/js/bytes.js';

export const CSRF_COOKIE = '__Host-secbin_csrf';
export const CSRF_HEADER = 'x-secbin-csrf';
const LABEL = 'secbin-csrf/v1:';
const KEY_LABEL = 'secbin-csrf-key/v1';
/** 32-byte HMAC, base64url without padding. */
const TOKEN_LEN = 43;

const keyCache = new WeakMap();

async function csrfKey(keys) {
  let k = keyCache.get(keys);
  if (!k) {
    const sig = await crypto.subtle.importKey('raw', keys.sig, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sub = new Uint8Array(await crypto.subtle.sign('HMAC', sig, utf8(KEY_LABEL)));
    k = await crypto.subtle.importKey('raw', sub, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    keyCache.set(keys, k);
  }
  return k;
}

/** The token for a session's claims ({ sid, ver }), or null when SIG/ENC are unset. */
export async function csrfTokenFor(env, claims) {
  const keys = sessionKeys(env);
  if (!keys || !claims || typeof claims.sid !== 'string' || !Number.isInteger(claims.ver)) return null;
  const mac = await crypto.subtle.sign('HMAC', await csrfKey(keys), utf8(`${LABEL}${claims.sid}:${claims.ver}`));
  return b64urlFromBytes(new Uint8Array(mac));
}

/** The readable token cookie: __Host- (Secure, Path=/, no Domain), SameSite=Strict, not HttpOnly. */
export function csrfCookie(token, maxAgeSec) {
  return `${CSRF_COOKIE}=${token}; Path=/; Secure; SameSite=Strict; Max-Age=${Math.max(0, Math.floor(maxAgeSec))}`;
}

export const clearCsrfCookie = () => `${CSRF_COOKIE}=; Path=/; Secure; SameSite=Strict; Max-Age=0`;

/**
 * The cookie for a session's claims, or null. `maxAgeSec`: what the session
 * cookie has left (readSession's `maxAgeSec`), so that the token cookie never
 * outlives it.
 */
export async function csrfCookieFor(env, claims, maxAgeSec) {
  const token = await csrfTokenFor(env, claims);
  return token ? csrfCookie(token, Number.isFinite(maxAgeSec) ? maxAgeSec : 0) : null;
}

/**
 * Timing-safe comparison of a presented token with the expected one. The
 * length is not secret (every token is 43 characters); a wrong length still
 * runs one full comparison. Uses workerd's crypto.subtle.timingSafeEqual.
 */
export function csrfTokensMatch(presented, expected) {
  if (typeof expected !== 'string' || expected.length !== TOKEN_LEN) return false;
  const e = utf8(expected);
  const ok = typeof presented === 'string' && presented.length === TOKEN_LEN;
  const p = ok ? utf8(presented) : e;
  const same = timingSafeEqual(p, e);
  return ok && same;
}

function timingSafeEqual(a, b) {
  if (a.byteLength !== b.byteLength) return false;
  if (typeof crypto.subtle.timingSafeEqual === 'function') return crypto.subtle.timingSafeEqual(a, b);
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export const csrfMismatch = () => new HttpError(403, 'csrf_mismatch', 'This request could not be verified for your session. Reload the page and try again.');

/** Refuse (403 csrf_mismatch) unless X-Secbin-CSRF carries this session's token. */
export async function assertCsrf(request, env, claims) {
  const expected = await csrfTokenFor(env, claims);
  if (!csrfTokensMatch(request.headers.get(CSRF_HEADER) || '', expected)) throw csrfMismatch();
}
