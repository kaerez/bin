// index.js — secbin Worker entry.
//
// Routes:
//   /api/auth/*      login, logout, setup/recovery, session probe (public)
//   /api/private/*   everything that needs an account (session or API key)
//   /api/public/*    anonymous creation (the public account), when enabled
//   /api/paste/*, /api/file/*, /api/config   capability-gated public reads
//   /dashboard*      the signed-in app (login/setup pages are the exceptions)
//   everything else  Workers Static Assets (landing page + viewer)
//
// The server is deliberately dumb about content: it stores opaque ciphertext
// plus non-secret metadata and enforces accounts, limits, quotas, view counts,
// expiry and brute-force protection. It never sees a decryption key, a password,
// a file name or a file type. See SPEC.md §10 and SECURITY.md.

import { err, HttpError, withSecurityHeaders, withCachePolicy, redirect, appendCookies, SECURITY_HEADERS } from './lib/http.js';
import { csrfCookieFor } from './lib/csrf.js';
import { readSession, logoutCookie, SESSION_COOKIE } from './lib/auth.js';
import { ipContext, cachedSettings } from './lib/guard.js';
import { turnstileKeys } from './lib/turnstile.js';
import { BindingMissing } from './lib/config.js';
import { handleAuth } from './routes/auth.js';
import { handlePrivate } from './routes/private.js';
import { handlePublic } from './routes/public.js';
import { handlePublicApi } from './routes/publicapi.js';

export { BurnPaste } from './burn-do.js';
export { FileShare } from './fileshare-do.js';
export { Directory } from './directory-do.js';
export { Guard } from './guard-do.js';
export { Drive } from './drive-do.js';

const DASH_PUBLIC = /^\/dashboard\/(login|setup)(\/|\/index\.html)?$/;
const DASH_LOGIN = /^\/dashboard\/login(\/|\/index\.html)?$/;

// Pages with a Turnstile widget (see src/lib/turnstile.js): login, account
// (every change to one's own account) and the home page's public composer
// when it is enabled.
const TURNSTILE_DASH = /^\/dashboard\/(login|account)(\/|\/index\.html)?$/;
const HOME = /^\/(index\.html)?$/;
// The home page is public and browser-cached: look up a session only when a cookie is there.
const hasSessionCookie = (request) => (request.headers.get('cookie') || '').includes(`${SESSION_COOKIE}=`);

async function showsTurnstile(env, pathname) {
  if (!(await turnstileKeys(env))) return false;
  if (TURNSTILE_DASH.test(pathname)) return true;
  if (HOME.test(pathname)) {
    // The landing page must render even if settings are unreachable (strict headers then).
    try { return (await cachedSettings(env))['public.enabled'] === true; } catch { return false; }
  }
  return false;
}

// The signed-in app is never stored; the public landing page keeps the asset
// server's own caching headers for the browser, as when it was served straight
// from static assets (the service worker keeps it as the offline shell). Neither
// is ever stored in Cloudflare's cache (withCachePolicy, in the fetch handler):
// the home page varies with the session cookie (the signed-in redirect) and
// with the admin's Turnstile / anonymous-sharing settings (its headers).
async function serveAsset(env, request, url, { noStore = true } = {}) {
  if (!env.ASSETS) return new Response('Not found', { status: 404, headers: { ...SECURITY_HEADERS, 'cache-control': 'no-store' } });
  const turnstile = url ? await showsTurnstile(env, url.pathname) : false;
  return withSecurityHeaders(await env.ASSETS.fetch(request), { turnstile, noStore });
}

/**
 * Someone already signed in who opens the home page or the login page goes
 * straight to the dashboard. Only a valid session redirects; anything else
 * (no cookie, expired, disabled, unreachable) shows the page as usual.
 */
async function signedInRedirect(request, env) {
  if (request.method !== 'GET' && request.method !== 'HEAD') return null;
  try {
    const s = await readSession(request, env);
    if (!s.ok) return null;
    return appendCookies(redirect('/dashboard/'), s.setCookie);
  } catch {
    return null;
  }
}

async function handleDashboard(request, env, url) {
  if (DASH_LOGIN.test(url.pathname)) {
    const to = await signedInRedirect(request, env);
    if (to) return to;
  }
  if (DASH_PUBLIC.test(url.pathname)) return serveAsset(env, request, url);
  const s = await readSession(request, env);
  if (!s.ok) {
    if (s.reason !== 'disabled') return redirect('/dashboard/login/');
    return appendCookies(redirect('/dashboard/login/?disabled=1'), logoutCookie());
  }
  if (/^\/dashboard\/admin(\/|$)/.test(url.pathname) && (s.user.role !== 'owner' || s.actor)) return redirect('/dashboard/');
  const res = await serveAsset(env, request, url);
  // Every signed-in page load (re)sets the session's CSRF token cookie, so a
  // reload always leaves the page with the current token (src/lib/csrf.js),
  // with the lifetime the session cookie has left.
  return appendCookies(res, s.setCookie ?? await csrfCookieFor(env, s.claims, s.maxAgeSec));
}

async function route(request, env, url, ctx) {
  const { pathname } = url;
  const isApi = pathname.startsWith('/api/');
  const isDash = pathname === '/dashboard' || pathname.startsWith('/dashboard/');
  if (!isApi && !isDash) {
    if (HOME.test(pathname) && hasSessionCookie(request)) {
      const to = await signedInRedirect(request, env);
      if (to) return to;
    }
    return serveAsset(env, request, url, { noStore: false });
  }

  // Manual admin block rules apply to the whole API and app surface.
  const g = await ipContext(env, request);
  if (g.manual === 'block') return err(403, 'blocked', 'Access from your network is blocked.');

  if (isDash) return handleDashboard(request, env, url);
  if (pathname.startsWith('/api/auth/')) return (await handleAuth(request, env, url)) ?? err(404, 'not_found', 'Not found.');
  if (pathname.startsWith('/api/private/') || pathname === '/api/private') return handlePrivate(request, env, url, ctx);
  if (pathname.startsWith('/api/public/')) return handlePublicApi(request, env, url);
  return (await handlePublic(request, env, url)) ?? err(404, 'not_found', 'Not found.');
}

function errorResponse(e) {
  if (e instanceof HttpError) return e.toResponse();
  if (e instanceof BindingMissing) {
    console.error(`deployment error: the ${e.binding} binding is missing or invalid`);
    // The binding's name goes to the logs, not to the (possibly anonymous) caller.
    return err(503, 'not_configured', 'The server is not fully configured. Please contact the administrator.');
  }
  console.error('unhandled error', e && e.stack ? e.stack : e);
  return err(500, 'server_error', 'Something went wrong. Please try again.');
}

export default {
  async fetch(request, env, ctx) {
    let res;
    try {
      res = await route(request, env, new URL(request.url), ctx);
      if (!(res instanceof Response)) throw new Error('route returned no response');
    } catch (e) {
      res = errorResponse(e);
    }
    // Every response, error paths included, leaves with an explicit cache
    // policy: nothing the Worker returns is stored by Cloudflare's cache
    // (wrangler.toml [cache]); see withCachePolicy.
    return withCachePolicy(res);
  },
};
