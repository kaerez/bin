// turnstile.js — Cloudflare Turnstile (a privacy-preserving human check) on
// the forms bots attack: login, anonymous share creation and every change a
// signed-in browser session makes to its own account (password, username,
// passkeys, recovery codes, sign-in steps and API keys). Off unless a site key and a secret key are both configured:
// as the deployment's TURNSTILE_SITEKEY and TURNSTILE_SECRET (preferred: a
// Worker secret), or else in the admin panel (Security → Human check), where
// the owner enters them. Admin password resets, the owner's changes to other
// accounts in the admin panel, owner setup and API-key calls never need it.
// The owner acting as a user ("Log in as") changes that account on its
// Account page, and passes the same human check there as anyone else.
//
// The browser sends the widget's token in X-Secbin-Turnstile. The server
// redeems it with Cloudflare's siteverify and accepts it only when it
//   - succeeded (siteverify also refuses a token seen before, so each token
//     works once — "timeout-or-duplicate"),
//   - was issued for this hostname, and
//   - was issued for this form's action (a login token cannot change a
//     password or create a share).
// Cloudflare's published testing keys carry no hostname or action; their
// results are accepted as they are (they always pass or always fail anyway).
// Tokens siteverify rejects are counted per network: after TURNSTILE_VERIFY.max
// in a window the network's tokens are refused without a call (the share grant
// routes count theirs under CAPTCHA_VERIFY instead: human.js verifyCaptcha).

import { assertNotCrossSite, HttpError } from './http.js';
import { directory, ipContext, isBlocked, rateLimit, TURNSTILE_VERIFY } from './guard.js';

export const TURNSTILE_ORIGIN = 'https://challenges.cloudflare.com';
const SITEVERIFY = `${TURNSTILE_ORIGIN}/turnstile/v0/siteverify`;
export const KEY_RE = /^[A-Za-z0-9_-]{10,100}$/;
const ADMIN_CACHE_MS = 30 * 1000;
const TOKEN_MAX = 2048; // Cloudflare's documented maximum
const VERIFY_TIMEOUT_MS = 10000;

/**
 * The form each token is issued for (the widget's `action`): `account` covers
 * every other change on the account page (username, passkeys, recovery codes,
 * sign-in steps, API keys); `reverse` is the anonymous reverse-share upload;
 * `share` opens a share that has the CAPTCHA (src/lib/human.js).
 */
export const TURNSTILE_ACTIONS = Object.freeze({ login: 'login', password: 'password', account: 'account', public: 'public-share', reverse: 'reverse-upload', share: 'share-open' });

/** { sitekey, secret } when both are set and well-formed, else null (Turnstile off). */
let warned = false;
export function turnstileConfig(env) {
  const sitekey = typeof env?.TURNSTILE_SITEKEY === 'string' ? env.TURNSTILE_SITEKEY.trim() : '';
  const secret = typeof env?.TURNSTILE_SECRET === 'string' ? env.TURNSTILE_SECRET.trim() : '';
  if (!KEY_RE.test(sitekey) || !KEY_RE.test(secret)) {
    // Half a configuration is a mistake, not a choice: say so (never the values).
    if ((sitekey || secret) && !warned) {
      warned = true;
      console.warn('Turnstile is OFF: TURNSTILE_SITEKEY and TURNSTILE_SECRET must both be set and well-formed');
    }
    return null;
  }
  return { sitekey, secret };
}

// Keys set in the admin panel, cached per isolate (another isolate sees a
// change within ADMIN_CACHE_MS).
let adminCache = { at: 0, keys: undefined };
/** Forget the cached admin-panel keys (after the owner changes them). */
export function invalidateTurnstileCache() { adminCache = { at: 0, keys: undefined }; }

/**
 * The keys in force: { sitekey, secret, source: 'env' | 'admin' }, or null
 * (Turnstile off). The deployment's keys win over the admin panel's.
 */
export async function turnstileKeys(env) {
  const fromEnv = turnstileConfig(env);
  if (fromEnv) return { ...fromEnv, source: 'env' };
  if (adminCache.keys === undefined || Date.now() - adminCache.at > ADMIN_CACHE_MS) {
    let keys;
    try { keys = await directory(env).turnstileKeys(); } catch { keys = adminCache.keys ?? null; }
    adminCache = { at: Date.now(), keys };
  }
  const k = adminCache.keys;
  return k && KEY_RE.test(k.sitekey) && KEY_RE.test(k.secret) ? { sitekey: k.sitekey, secret: k.secret, source: 'admin' } : null;
}

// Tests replace the network call; production always posts to siteverify.
let siteverify = (body) => fetch(SITEVERIFY, { method: 'POST', body, signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS) });
/** Test hook: swap the siteverify call (returns the previous one). */
export function setSiteverify(fn) { const prev = siteverify; siteverify = fn; return prev; }

/**
 * Throws HttpError unless the request carries a valid, unused token for
 * `action`. A no-op when Turnstile is not configured. Unless the caller
 * limits the calls itself (`limited: false`: verifyCaptcha's
 * "captcha-verify"), every token siteverify rejects counts towards the
 * network's "turnstile-verify" scope (TURNSTILE_VERIFY), and a network that
 * reached it gets `429 rate_limited` without a call until the block ends or
 * the owner lifts it. Accepted tokens are never counted: each one cost a
 * solved CAPTCHA, so sign-ins behind one busy address never use it up. A
 * cross-site request is refused first, so another site cannot count here.
 */
export async function requireTurnstile(env, request, action, { limited = true } = {}) {
  const cfg = await turnstileKeys(env);
  if (!cfg) return;
  const token = (request.headers.get('x-secbin-turnstile') || '').trim();
  if (!token) throw new HttpError(403, 'turnstile_required', 'Complete the CAPTCHA and try again.');
  if (token.length > TOKEN_MAX) throw failed();
  let g = null;
  if (limited) {
    assertNotCrossSite(request);
    g = await ipContext(env, request);
    const b = await isBlocked(env, g, 'turnstile-verify');
    if (b.blocked) throw tooMany(b.until);
  }
  // A rejected token is counted (after its verdict: siteverify has been asked).
  const rejected = async () => {
    if (g) await rateLimit(env, g, 'turnstile-verify', TURNSTILE_VERIFY);
    return failed();
  };
  const form = new FormData();
  form.append('secret', cfg.secret);
  form.append('response', token);
  const ip = request.headers.get('cf-connecting-ip');
  if (ip) form.append('remoteip', ip);
  let data;
  try {
    const res = await siteverify(form);
    data = await res.json();
  } catch {
    // Fail closed: without a verdict the request is not let through.
    throw new HttpError(503, 'turnstile_unavailable', 'The CAPTCHA could not be verified right now. Try again in a moment.');
  }
  if (!data || data.success !== true) throw await rejected();
  if (data.metadata?.result_with_testing_key === true) return;
  if (data.hostname !== new URL(request.url).hostname || data.action !== action) throw await rejected();
}

const tooMany = (until) => new HttpError(429, 'rate_limited', 'Too many failed CAPTCHA checks from your network. Try again later.',
  until ? { until } : undefined, { 'retry-after': String(TURNSTILE_VERIFY.blockSec) });

const failed = () => new HttpError(403, 'turnstile_failed', 'The CAPTCHA failed or expired. Try again.');
