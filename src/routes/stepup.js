// stepup.js — "confirm it's you" for changes to one's own account: the
// current password (a proof, as at login) or a fresh passkey assertion for a
// "reauth" challenge (POST /api/private/me/reauth). The Directory checks it;
// these helpers read it from a request body and handle a failed attempt.

import { HttpError, appendCookies } from '../lib/http.js';
import { logoutCookie } from '../lib/auth.js';
import { recordFailure } from '../lib/guard.js';
import { verifierFrom } from './auth.js';

/**
 * The confirmation in `body`: `{ current }` (password proof) or
 * `{ reauth: { challengeId, credential } }`. Throws 400 when neither is there.
 */
export async function stepUpFrom(body, url) {
  const base = { origin: url.origin, rpId: url.hostname };
  if (body && body.current !== undefined && body.current !== null && body.current !== '') {
    const current = await verifierFrom(body.current);
    if (!current) throw new HttpError(400, 'invalid_credential', 'Invalid password proof.');
    return { ...base, current };
  }
  if (body && body.reauth && typeof body.reauth === 'object'
      && typeof body.reauth.challengeId === 'string' && body.reauth.credential && typeof body.reauth.credential === 'object') {
    return { ...base, reauth: { challengeId: body.reauth.challengeId, credential: body.reauth.credential } };
  }
  throw new HttpError(400, 'reauth_required', 'Confirm with your password or a passkey.');
}

const COUNTED = new Set(['wrong_password', 'reauth_failed', 'session_revoked']);

/**
 * After a Directory refusal: failed confirmations also count against the
 * caller's network (so a thief's IP is blocked from logging in again), and a
 * revoked session clears the cookie.
 */
export async function afterRefusal(env, g, r, res) {
  if (COUNTED.has(r.error)) await recordFailure(env, g, 'login');
  if (r.error === 'session_revoked') appendCookies(res, logoutCookie());
  return res;
}
