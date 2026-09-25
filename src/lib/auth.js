// auth.js — request authentication for the Worker: the encrypted+signed
// session cookie (JWT, see jwt.js) and API keys (Bearer sbk_…).
//
// The token carries { sid, uid, act?, ver, iat, lat, exp }. It is checked for
// integrity (SIG/ENC), then against current state in the Directory (session
// revoked? user disabled? session version bumped by a password change/reset?),
// then against the admin-configured idle and absolute timeouts. Activity slides
// the idle window by re-issuing the cookie at most once a minute.

import { sessionKeys } from './config.js';
import { sealToken, openToken } from './jwt.js';
import { getCookie, sessionCookie, clearCookie, HttpError } from './http.js';
import { genSessionId, hashToken } from './ids.js';
import { directory } from './guard.js';

export const SESSION_COOKIE = '__Host-secbin_sess';
const SLIDE_SEC = 60;
const now = () => Math.floor(Date.now() / 1000);

export function unconfigured() {
  return new HttpError(503, 'server_not_configured', 'Server not configured: set the SIG and ENC secrets (64 hex characters each).');
}

/** Mint a session cookie header value for `uid` (optionally impersonated by `act`). */
export async function issueSession(env, { uid, act = null, ver, settings, sid = genSessionId(), iat = now() }) {
  const keys = sessionKeys(env);
  if (!keys) throw unconfigured();
  const t = now();
  const exp = iat + settings.absSec;
  const claims = { sid, uid, ver, iat, lat: t, exp };
  if (act) claims.act = act;
  const token = await sealToken(keys, claims);
  return { cookie: sessionCookie(SESSION_COOKIE, token, Math.min(exp - t, settings.idleSec)), claims };
}

export const logoutCookie = () => clearCookie(SESSION_COOKIE);

/**
 * Resolve the session on a request. Returns
 *   { ok: true, user, actor, claims, setCookie? }  or
 *   { ok: false, reason: 'none' | 'unconfigured' | 'invalid' }.
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
  const { idleSec, absSec } = res.settings;
  if (t - c.lat > idleSec || t - c.iat > absSec) return { ok: false, reason: 'invalid' };
  let setCookie;
  if (t - c.lat >= SLIDE_SEC) {
    const next = { ...c, lat: t, exp: Math.min(c.exp, c.iat + absSec) };
    setCookie = sessionCookie(SESSION_COOKIE, await sealToken(keys, next), Math.min(next.exp - t, idleSec));
  }
  return { ok: true, user: res.user, actor: res.actor, claims: c, setCookie };
}

/**
 * Authenticate a /api/private request. Sessions work everywhere; API keys only
 * where `allowApiKey` is set (share creation). Returns
 * { user, actor, channel: 'all'|'api', claims?, setCookie? } or throws HttpError.
 */
export async function authenticate(request, env, { allowApiKey = false } = {}) {
  const authz = request.headers.get('authorization') || '';
  if (authz) {
    const m = /^Bearer (sbk_[A-Za-z0-9_-]{43})$/.exec(authz.trim());
    if (!m) throw new HttpError(401, 'invalid_api_key', 'Invalid API key.');
    if (!allowApiKey) throw new HttpError(403, 'api_key_not_allowed', 'API keys can only be used to create shares.');
    const res = await directory(env).authKey(await hashToken(m[1]));
    if (!res) throw new HttpError(401, 'invalid_api_key', 'Invalid, expired or disabled API key.');
    return { user: res.user, actor: null, channel: 'api' };
  }
  const s = await readSession(request, env);
  if (!s.ok) {
    if (s.reason === 'unconfigured') throw unconfigured();
    throw new HttpError(401, 'unauthenticated', 'Please log in.');
  }
  return { user: s.user, actor: s.actor, claims: s.claims, setCookie: s.setCookie, channel: 'all' };
}

/** The id recorded as the actor of an action (the owner while impersonating). */
export const actorId = (a) => (a.actor ? a.actor.id : a.user.id);
