// auth.js — request authentication for the Worker: the encrypted+signed
// session cookie (JWT, see jwt.js) and API keys (Bearer sbk_…).
//
// The token carries { sid, uid, act?, ver, iat, lat, exp }. It is checked for
// integrity (SIG/ENC), then against current state in the Directory (session
// revoked? user disabled? session version bumped by a password change/reset?),
// then against the admin-configured idle and absolute timeouts. Activity slides
// the idle window by re-issuing the cookie at most once a minute.
//
// Every time the session cookie is set or refreshed, the session's CSRF token
// cookie (csrf.js) goes with it, and cookie-authenticated state-changing
// requests must echo the token in X-Secbin-CSRF (unless the owner turned
// `csrfTokens` off in Admin → Settings).

import { sessionKeys } from './config.js';
import { sealToken, openToken } from './jwt.js';
import { getCookie, sessionCookie, clearCookie, HttpError, assertNotCrossSite, hasStateChangeShape } from './http.js';
import { csrfTokenFor, csrfCookie, clearCsrfCookie, assertCsrf } from './csrf.js';
import { genSessionId, hashToken } from './ids.js';
import { directory } from './guard.js';

export const SESSION_COOKIE = '__Host-secbin_sess';
const SLIDE_SEC = 60;
const now = () => Math.floor(Date.now() / 1000);

export function unconfigured() {
  return new HttpError(503, 'server_not_configured', 'Server not configured: set the SIG and ENC secrets (64 hex characters each).');
}

/** The session cookie and its CSRF token cookie, with the same lifetime. */
async function sessionCookies(env, keys, claims, maxAgeSec) {
  const cookies = [sessionCookie(SESSION_COOKIE, await sealToken(keys, claims), maxAgeSec)];
  const csrf = await csrfTokenFor(env, claims);
  if (csrf) cookies.push(csrfCookie(csrf, maxAgeSec));
  return cookies;
}

/**
 * Mint the Set-Cookie values for a new session of `uid` (optionally
 * impersonated by `act`): the session cookie, then its CSRF token cookie.
 */
export async function issueSession(env, { uid, act = null, ver, settings, sid = genSessionId(), iat = now() }) {
  const keys = sessionKeys(env);
  if (!keys) throw unconfigured();
  const t = now();
  const exp = iat + settings.absSec;
  const claims = { sid, uid, ver, iat, lat: t, exp };
  if (act) claims.act = act;
  return { cookie: await sessionCookies(env, keys, claims, Math.min(exp - t, settings.idleSec)), claims };
}

/** Set-Cookie values that sign the browser out: the session and its CSRF token. */
export const logoutCookie = () => [clearCookie(SESSION_COOKIE), clearCsrfCookie()];

/** A disabled account: refused everywhere, even with a still-valid session or key. */
export const accountDisabled = (headers) => new HttpError(403, 'account_disabled', 'This account is disabled. Contact the administrator.', undefined, headers);

/**
 * Resolve the session on a request. Returns
 *   { ok: true, user, actor, claims, csrf, setCookie? }  or
 *   { ok: false, reason: 'none' | 'unconfigured' | 'invalid' | 'disabled' }.
 * `csrf` is the `csrfTokens` setting (read by the Directory with the session,
 * so it costs no extra round trip); `setCookie` is an array of Set-Cookie
 * values (the refreshed session cookie and its CSRF token cookie).
 */
export async function readSession(request, env) {
  const token = getCookie(request, SESSION_COOKIE);
  if (!token) return { ok: false, reason: 'none' };
  const keys = sessionKeys(env);
  if (!keys) return { ok: false, reason: 'unconfigured' };
  const c = await openToken(keys, token);
  const t = now();
  if (!c || typeof c.sid !== 'string' || typeof c.uid !== 'string' || !Number.isInteger(c.ver)
      || !Number.isInteger(c.iat) || !Number.isInteger(c.lat) || !Number.isInteger(c.exp)
      || (c.act !== undefined && typeof c.act !== 'string') || t >= c.exp) {
    return { ok: false, reason: 'invalid' };
  }
  const res = await directory(env).resolveSession({ sid: c.sid, uid: c.uid, act: c.act ?? null, ver: c.ver });
  if (!res) return { ok: false, reason: 'invalid' };
  if (res.disabled) return { ok: false, reason: 'disabled' };
  const { idleSec, absSec } = res.settings;
  if (t - c.lat > idleSec || t - c.iat > absSec) return { ok: false, reason: 'invalid' };
  let setCookie;
  if (t - c.lat >= SLIDE_SEC) {
    const next = { ...c, lat: t, exp: Math.min(c.exp, c.iat + absSec) };
    setCookie = await sessionCookies(env, keys, next, Math.min(next.exp - t, idleSec));
  }
  // Fail closed: only an explicit `false` turns the token check off.
  return { ok: true, user: res.user, actor: res.actor, claims: c, csrf: res.csrf !== false, setCookie };
}

const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * The CSRF token check for a cookie-authenticated request (`s`: a resolved
 * session). Only state-changing methods, and only while the `csrfTokens`
 * setting is on. It runs after the existing guards, whose errors stay as they
 * were: the Sec-Fetch-Site check first, then the request shape (a request
 * without a JSON body, a chunk or X-Secbin-Intent is left to the route's own
 * guard, which refuses it). It runs before anything that changes state or
 * spends a single-use token (Turnstile), so a refused request can be retried.
 */
export async function checkCsrf(request, env, s) {
  if (!STATE_CHANGING.has(request.method) || !s.csrf) return;
  assertNotCrossSite(request);
  if (!hasStateChangeShape(request)) return;
  await assertCsrf(request, env, s.claims);
}

/**
 * Authenticate a /api/private request. Sessions work everywhere; API keys only
 * where `allowApiKey` is set, and only when the key holds `scope` (see
 * API_SCOPES in settings.js). Returns { user, actor, channel: 'all'|'api',
 * claims?, setCookie?, keyId? } or throws HttpError.
 */
export async function authenticate(request, env, { allowApiKey = false, scope = null } = {}) {
  const authz = request.headers.get('authorization') || '';
  if (authz) {
    const m = /^Bearer (sbk_[A-Za-z0-9_-]{43})$/.exec(authz.trim());
    if (!m) throw new HttpError(401, 'invalid_api_key', 'Invalid API key.');
    if (!allowApiKey) throw new HttpError(403, 'api_key_not_allowed', 'API keys cannot be used here (only to create shares, read the policy, and read or manage the key user’s own shares).');
    const res = await directory(env).authKey(await hashToken(m[1]));
    if (res?.disabled) throw accountDisabled();
    if (!res) throw new HttpError(401, 'invalid_api_key', 'Invalid, expired or disabled API key.');
    // Each key does only what it was created for (least privilege).
    if (scope && !(res.scopes || []).includes(scope)) {
      throw new HttpError(403, 'scope_denied', `This API key does not have the "${scope}" scope.`);
    }
    // No CSRF token: the key travels in the Authorization header, which a
    // browser never attaches on its own (cookies play no part here), so a
    // forged cross-site request cannot carry it.
    return { user: res.user, actor: null, channel: 'api', scopes: res.scopes, keyId: res.keyId };
  }
  const s = await readSession(request, env);
  if (!s.ok) {
    if (s.reason === 'unconfigured') throw unconfigured();
    if (s.reason === 'disabled') throw accountDisabled({ 'set-cookie': logoutCookie() });
    throw new HttpError(401, 'unauthenticated', 'Please log in.');
  }
  await checkCsrf(request, env, s);
  return { user: s.user, actor: s.actor, claims: s.claims, setCookie: s.setCookie, channel: 'all' };
}

/** The actor recorded for an action: the user, or { id: owner, imp: true } while impersonating. */
export const actorId = (a) => (a.actor ? { id: a.actor.id, imp: true } : a.user.id);
