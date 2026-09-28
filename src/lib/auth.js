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
import { getCookie, sessionCookie, clearCookie, HttpError, assertNotCrossSite, assertStateChangeShape } from './http.js';
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
 * A session that replaces another one of the same sign-in (impersonation
 * starting or ending) passes that session's `iat` and its `exp` as
 * `notAfter`: the absolute timeout keeps counting from the sign-in and the
 * new session never ends later than the one it replaces.
 */
export async function issueSession(env, { uid, act = null, ver, settings, sid = genSessionId(), iat = now(), notAfter = Infinity }) {
  const keys = sessionKeys(env);
  if (!keys) throw unconfigured();
  const t = now();
  const exp = Math.min(iat + settings.absSec, notAfter);
  const claims = { sid, uid, ver, iat, lat: t, exp };
  if (act) claims.act = act;
  return { cookie: await sessionCookies(env, keys, claims, Math.min(exp - t, settings.idleSec)), claims };
}

/** Set-Cookie values that sign the browser out: the session and its CSRF token. */
export const logoutCookie = () => [clearCookie(SESSION_COOKIE), clearCsrfCookie()];

/** A disabled account: refused everywhere, even with a still-valid session or key. */
export const accountDisabled = (headers) => new HttpError(403, 'account_disabled', 'This account is disabled. Contact the administrator.', undefined, headers);

/**
 * When a session ends (Unix seconds), for the browser's warning before it
 * does (WCAG 2.2.1): `idleEndsAt` without further activity (each request
 * slides it, at most once a minute), `endsAt` at the latest (the absolute
 * timeout; it cannot be extended). `idleSec` is the inactivity allowance.
 * `now` is the server's time: the page measures its clock against it, so a
 * browser clock that is off does not move the warning.
 */
export function sessionTimes(c, { idleSec, absSec, t = now() }) {
  const endsAt = Math.min(c.exp, c.iat + absSec);
  return { idleSec, idleEndsAt: Math.min(c.lat + idleSec, endsAt), endsAt, slideSec: SLIDE_SEC, now: t };
}

/**
 * Resolve the session on a request. Returns
 *   { ok: true, user, actor, claims, csrf, maxAgeSec, session, setCookie? }  or
 *   { ok: false, reason: 'none' | 'unconfigured' | 'invalid' | 'disabled' }.
 * `csrf` is the `csrfTokens` setting (read by the Directory with the session,
 * so it costs no extra round trip); `maxAgeSec` is how long the session
 * cookie has left (the idle window from the last activity, capped by the
 * absolute expiry), the lifetime of a CSRF token cookie (re)set on its own;
 * `setCookie` is an array of Set-Cookie values (the refreshed session cookie
 * and its CSRF token cookie).
 * `session` is when the session ends (sessionTimes), for the page's warning.
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
  let claims = c;
  if (t - c.lat >= SLIDE_SEC) {
    claims = { ...c, lat: t, exp: Math.min(c.exp, c.iat + absSec) };
    setCookie = await sessionCookies(env, keys, claims, Math.min(claims.exp - t, idleSec));
  }
  const maxAgeSec = Math.min(claims.exp, claims.lat + idleSec, claims.iat + absSec) - t;
  // Fail closed: only an explicit `false` turns the token check off.
  return { ok: true, user: res.user, actor: res.actor, claims: c, csrf: res.csrf !== false, maxAgeSec, setCookie, session: sessionTimes(claims, { idleSec, absSec, t }) };
}

const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * The CSRF checks for a cookie-authenticated state-changing request (`s`: a
 * resolved session), in this order, before anything else happens (no state
 * change, no failure counted, no human-check token spent), so a refused
 * request can be retried as it is:
 *   1. the Sec-Fetch-Site check (403 cross_site);
 *   2. the request shape: a JSON body, a chunk or X-Secbin-Intent, and the
 *      intent header on a DELETE (415 unsupported_media_type, 400
 *      missing_intent; assertStateChangeShape in http.js);
 *   3. the session's CSRF token, while the `csrfTokens` setting is on (403
 *      csrf_mismatch).
 * 1 and 2 are the existing guards; they apply with the setting off too.
 */
export async function checkCsrf(request, env, s) {
  if (!STATE_CHANGING.has(request.method)) return;
  assertNotCrossSite(request);
  assertStateChangeShape(request);
  if (s.csrf) await assertCsrf(request, env, s.claims);
}

/**
 * Authenticate a /api/private request. Sessions work everywhere; API keys only
 * where `allowApiKey` is set, and only when the key holds `scope` (see
 * API_SCOPES in settings.js). Returns { user, actor, channel: 'all'|'api',
 * claims?, maxAgeSec?, setCookie?, keyId? } or throws HttpError.
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
  return { user: s.user, actor: s.actor, claims: s.claims, maxAgeSec: s.maxAgeSec, setCookie: s.setCookie, session: s.session, channel: 'all' };
}

/** The actor recorded for an action: the user, or { id: owner, imp: true } while impersonating. */
export const actorId = (a) => (a.actor ? { id: a.actor.id, imp: true } : a.user.id);
