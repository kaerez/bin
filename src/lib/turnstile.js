// turnstile.js — Cloudflare Turnstile (a privacy-preserving human check) on
// the forms bots attack: login, a signed-in password change and anonymous
// share creation. Off unless BOTH TURNSTILE_SITEKEY and TURNSTILE_SECRET are
// set; admin password resets and owner setup never need it.
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

import { HttpError } from './http.js';

export const TURNSTILE_ORIGIN = 'https://challenges.cloudflare.com';
const SITEVERIFY = `${TURNSTILE_ORIGIN}/turnstile/v0/siteverify`;
const KEY_RE = /^[A-Za-z0-9_-]{10,100}$/;
const TOKEN_MAX = 2048; // Cloudflare's documented maximum
const VERIFY_TIMEOUT_MS = 10000;

/** The form each token is issued for (the widget's `action`). */
export const TURNSTILE_ACTIONS = Object.freeze({ login: 'login', password: 'password', public: 'public-share' });

/** { sitekey, secret } when both are set and well-formed, else null (Turnstile off). */
export function turnstileConfig(env) {
  const sitekey = typeof env?.TURNSTILE_SITEKEY === 'string' ? env.TURNSTILE_SITEKEY.trim() : '';
  const secret = typeof env?.TURNSTILE_SECRET === 'string' ? env.TURNSTILE_SECRET.trim() : '';
  if (!KEY_RE.test(sitekey) || !KEY_RE.test(secret)) return null;
  return { sitekey, secret };
}

// Tests replace the network call; production always posts to siteverify.
let siteverify = (body) => fetch(SITEVERIFY, { method: 'POST', body, signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS) });
/** Test hook: swap the siteverify call (returns the previous one). */
export function setSiteverify(fn) { const prev = siteverify; siteverify = fn; return prev; }

/**
 * Throws HttpError unless the request carries a valid, unused token for
 * `action`. A no-op when Turnstile is not configured.
 */
export async function requireTurnstile(env, request, action) {
  const cfg = turnstileConfig(env);
  if (!cfg) return;
  const token = (request.headers.get('x-secbin-turnstile') || '').trim();
  if (!token) throw new HttpError(403, 'turnstile_required', 'Complete the human check and try again.');
  if (token.length > TOKEN_MAX) throw failed();
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
    throw new HttpError(503, 'turnstile_unavailable', 'The human check could not be verified right now. Try again in a moment.');
  }
  if (!data || data.success !== true) throw failed();
  if (data.metadata?.result_with_testing_key === true) return;
  if (data.hostname !== new URL(request.url).hostname || data.action !== action) throw failed();
}

const failed = () => new HttpError(403, 'turnstile_failed', 'The human check failed or expired. Try again.');
