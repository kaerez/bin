// auth.js (routes) — /api/auth/*: session probe, owner setup/recovery,
// prelogin (salt lookup), login and logout. Passwords never reach the server:
// the browser sends d = Argon2id(password, salt); the server stores and compares
// SHA-256("secbin-auth/v2" ‖ d) only.

import { json, err, readJsonBody, assertIntent, methodNotAllowed } from '../lib/http.js';
import { authnToken, sessionKeys } from '../lib/config.js';
import { readSession, issueSession, logoutCookie, unconfigured } from '../lib/auth.js';
import { ipContext, isBlocked, recordFailure, directory } from '../lib/guard.js';
import { sha256Hex, utf8, bytesFromB64url, timingSafeEqualHex } from '../../public/js/bytes.js';
import { requireTurnstile, TURNSTILE_ACTIONS } from '../lib/turnstile.js';
import { requestOptions } from '../lib/webauthn.js';

const AUTH_LABEL = utf8('secbin-auth/v2');

/** d (base64url, 32 bytes) → stored verifier hex, or null if malformed. */
export async function verifierFrom(dB64) {
  let d;
  try { d = bytesFromB64url(dB64); } catch { return null; }
  if (d.length !== 32) return null;
  const buf = new Uint8Array(AUTH_LABEL.length + 32);
  buf.set(AUTH_LABEL);
  buf.set(d, AUTH_LABEL.length);
  return sha256Hex(buf);
}

const blockedErr = (b) => err(429, 'blocked', 'Too many attempts from your network. Try again later.', b.until ? { until: b.until } : undefined);

/** A Directory login result → the session cookie, or the error (failures count against the IP). */
async function signedIn(env, g, res) {
  if (!res.ok) {
    if (res.status === 401) {
      const r = await recordFailure(env, g, 'login');
      if (r.newlyBlocked) return blockedErr(r);
    }
    return err(res.status, res.error, res.message, res.until ? { until: res.until } : undefined);
  }
  const { cookie } = await issueSession(env, { uid: res.user.id, ver: res.user.ver, settings: res.settings });
  const out = { ok: true, user: { id: res.user.id, username: res.user.username, role: res.user.role } };
  if (typeof res.recoveryLeft === 'number') out.recoveryLeft = res.recoveryLeft;
  return json(out, 200, { 'set-cookie': cookie });
}

export async function handleAuth(request, env, url) {
  const p = url.pathname;

  if (p === '/api/auth/session') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    const configured = !!sessionKeys(env);
    const s = await readSession(request, env);
    const headers = s.ok && s.setCookie ? { 'set-cookie': s.setCookie } : undefined;
    return json({
      configured,
      authenticated: s.ok,
      user: s.ok ? { id: s.user.id, username: s.user.username, role: s.user.role } : null,
      impersonatedBy: s.ok && s.actor ? s.actor.username : null,
    }, 200, headers);
  }

  if (p === '/api/auth/setup') {
    const token = authnToken(env);
    const authnHash = token ? await sha256Hex(utf8(token)) : null;
    if (request.method === 'GET') {
      if (!authnHash) return json({ enabled: false, configured: !!sessionKeys(env) });
      const st = await directory(env).setupStatus(authnHash);
      return json({ enabled: st.enabled, ownerExists: st.enabled ? st.ownerExists : undefined, configured: !!sessionKeys(env) });
    }
    if (request.method !== 'POST') return methodNotAllowed('GET, POST');
    // Setup disabled (AUTHN unset/deleted/too short): reject everything, cleanly.
    if (!authnHash) return err(404, 'setup_disabled', 'Setup is disabled.');
    const g = await ipContext(env, request);
    const b = await isBlocked(env, g, 'setup');
    if (b.blocked) return blockedErr(b);
    const body = await readJsonBody(request);
    const presented = typeof body.token === 'string' ? body.token.trim() : '';
    const presentedHash = await sha256Hex(utf8(presented));
    if (!timingSafeEqualHex(presentedHash, authnHash)) {
      const r = await recordFailure(env, g, 'setup');
      return r.newlyBlocked ? blockedErr(r) : err(403, 'bad_token', 'The setup token is incorrect.');
    }
    const verifier = await verifierFrom(body.proof);
    if (!verifier) return err(400, 'invalid_credential', 'Invalid password proof.');
    const res = await directory(env).setup({ authnHash, username: body.username, salt: body.salt, t: body.t, verifier });
    if (!res.ok) return err(res.status, res.error, res.message);
    return json({ ok: true, recovered: res.recovered });
  }

  if (p === '/api/auth/prelogin') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const g = await ipContext(env, request);
    const b = await isBlocked(env, g, 'login');
    if (b.blocked) return blockedErr(b);
    const body = await readJsonBody(request);
    if (typeof body.username !== 'string' || body.username.length > 64) return err(400, 'invalid_username', 'Enter your username.');
    return json(await directory(env).prelogin(body.username));
  }

  if (p === '/api/auth/login') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    if (!sessionKeys(env)) return unconfigured().toResponse();
    const g = await ipContext(env, request);
    const b = await isBlocked(env, g, 'login');
    if (b.blocked) return blockedErr(b);
    // The human check comes before the password is looked at.
    await requireTurnstile(env, request, TURNSTILE_ACTIONS.login);
    const body = await readJsonBody(request);
    const verifier = await verifierFrom(body.proof);
    const res = await directory(env).login({ username: body.username, verifier: verifier ?? '', lockoutOff: g.off.all });
    if (res.ok && res.secondFactor) {
      // Right password; the account also needs a passkey (or recovery code).
      const f = res.secondFactor;
      return json({ ok: true, secondFactor: { challengeId: f.challengeId, publicKey: requestOptions(f, url.hostname), recoveryLeft: f.recoveryLeft } });
    }
    return signedIn(env, g, res);
  }

  // ── passkeys: sign in alone, or as the second step of a password login ──
  if (p === '/api/auth/passkey/options') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const g = await ipContext(env, request);
    const b = await isBlocked(env, g, 'login');
    if (b.blocked) return blockedErr(b);
    const r = await directory(env).passkeyLoginOptions();
    return json({ challengeId: r.challengeId, publicKey: requestOptions(r, url.hostname) });
  }
  if (p === '/api/auth/passkey/login' || p === '/api/auth/recovery' || p === '/api/auth/second-factor') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    if (!sessionKeys(env)) return unconfigured().toResponse();
    const g = await ipContext(env, request);
    const b = await isBlocked(env, g, 'login');
    if (b.blocked) return blockedErr(b);
    // The second step rides on the password step's human check.
    if (p !== '/api/auth/second-factor') await requireTurnstile(env, request, TURNSTILE_ACTIONS.login);
    const body = await readJsonBody(request);
    const dir = directory(env);
    const origin = url.origin;
    const rpId = url.hostname;
    const res = p === '/api/auth/passkey/login'
      ? await dir.passkeyLogin({ challengeId: body.challengeId, credential: body.credential, origin, rpId })
      : p === '/api/auth/recovery'
        ? await dir.recoveryLogin({ username: body.username, code: body.code, lockoutOff: g.off.all })
        : await dir.secondFactor({ challengeId: body.challengeId, credential: body.credential, code: body.code, origin, rpId, lockoutOff: g.off.all });
    return signedIn(env, g, res);
  }

  if (p === '/api/auth/logout') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    assertIntent(request);
    const s = await readSession(request, env);
    if (s.ok) await directory(env).revokeSession(s.claims.sid, s.claims.exp, s.actor ? { id: s.actor.id, imp: true } : s.user.id, s.user.id);
    return json({ ok: true }, 200, { 'set-cookie': logoutCookie() });
  }

  return null;
}
