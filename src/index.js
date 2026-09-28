// index.js — secbin Worker entry.
//
// Routes:
//   /api/auth/*      login, logout, setup/recovery, session probe (public)
//   /api/private/*   everything that needs an account (session or API key)
//   /api/public/*    anonymous creation (the public account), when enabled
//   /api/paste/*, /api/file/*, /api/config   capability-gated public reads
//   /api/reverse/*   anonymous uploads to a user's reverse share (docs/REVERSE.md)
//   /p/<id>          the recipient's page (the viewer; strict headers, a page key)
//   /r/<id>          the reverse-share uploader page (strict headers, a page key)
//   /p|r/<id>?check  the CAPTCHA page of a share that has one (Turnstile headers)
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
import { ipContext, cachedSettings, isBlocked, rateLimit, CAPTCHA_PAGE } from './lib/guard.js';
import { turnstileKeys } from './lib/turnstile.js';
import { newPageKey, pageKeysIn, pageKeyCookie, PAGE_KEYS_MAX } from './lib/human.js';
import { parseId } from './lib/ids.js';
import { BindingMissing } from './lib/config.js';
import { handleAuth } from './routes/auth.js';
import { handlePrivate } from './routes/private.js';
import { handlePublic } from './routes/public.js';
import { handlePublicApi } from './routes/publicapi.js';
import { handleReversePublic, REVERSE_ID_RE } from './routes/reverse.js';

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
// The reverse-share uploader page: /r/<id> (the key is in the #fragment).
const REVERSE_PAGE = /^\/r\/([^/]+)\/?$/;
// The recipient's page: /p/<id> (the viewer, public/index.html; the key is in the #fragment).
const SHARE_PAGE = /^\/p\/([^/]+)\/?$/;
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

const pageNotFound = () => withSecurityHeaders(new Response('Not found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8' } }));

/**
 * The CAPTCHA of a share that has one, without the link's key ever being
 * readable where Cloudflare's script runs (docs: SECURITY.md, "CAPTCHA on
 * shares"):
 *   • /p/<id> and /r/<id> — the recipient's page and the uploader's page —
 *     always get the strict CSP (COOP same-origin, COEP, frame-ancestors
 *     'none'). A strict navigation (Sec-Fetch-Dest: document, Sec-Fetch-Mode:
 *     navigate, Sec-Fetch-Site: none or same-origin) gets a new random page
 *     key: `n.key` in a meta tag and in an HttpOnly, Secure, SameSite=Strict
 *     cookie of its own (`__Secure-secbin_pk_<n>`, so each tab's round trip
 *     has one) scoped to the share's path, for 15 minutes, at most
 *     PAGE_KEYS_MAX per path (the oldest are cleared). When the share needs
 *     the CAPTCHA, the page seals the link's key (only that) with it in
 *     sessionStorage, takes it out of the address bar and goes to the check
 *     page.
 *   • /p/<id>?n=<n> — the return from the check: the key is written into the
 *     page again only when the navigation carries the cookie for that nonce,
 *     and the cookie is cleared in the same response (single use). No new key
 *     is issued there.
 *   • /p/<id>?check and /r/<id>?check — the check page (public/check/), for
 *     any well-formed id while the server has Turnstile keys (else a redirect
 *     back), so it says nothing about the share; behind the Guard's block and
 *     a per-network rate limit, with no share lookup. Only a same-origin (or
 *     'none') document navigation is counted and served; any other request
 *     (another site's <img> or <iframe>) is redirected back, uncounted. Its CSP adds Turnstile
 *     and forbids workers; COOP same-origin-allow-popups. It never gets a key.
 * Never stored. Any other /p/ or /r/ path is not found.
 */
async function sharePage(request, env, url, kind) {
  const m = url.pathname.match(kind === 'r' ? REVERSE_PAGE : SHARE_PAGE);
  let id = null;
  if (m) { try { id = decodeURIComponent(m[1]); } catch { id = null; } }
  const valid = id !== null && (kind === 'r' ? REVERSE_ID_RE.test(id) : !!parseId(id));
  if (request.method !== 'GET' && request.method !== 'HEAD') return pageNotFound();
  // The viewer shows a readable error for a malformed /p/ link, as before; /r/ answers 404.
  if (!m || (kind === 'r' && !valid)) return pageNotFound();
  if (!env.ASSETS) return new Response('Not found', { status: 404 });
  const asset = (path) => env.ASSETS.fetch(new Request(new URL(path, url), { method: request.method, headers: request.headers }));
  const home = `/${kind}/${m[1]}`;
  const h = (k) => request.headers.get(k) || '';
  if (url.searchParams.has('check')) {
    if (!valid || !(await turnstileKeys(env))) return withSecurityHeaders(redirect(home, 302));
    // Only this site's own document navigation (the viewer's location.replace, or a
    // typed / bookmarked address) is counted and served: another site's <img>,
    // <iframe> or fetch gets the redirect back, before the Guard is asked, so it
    // can never use up a network's budget of check pages.
    const site = h('sec-fetch-site');
    if (h('sec-fetch-dest') !== 'document' || (site !== 'same-origin' && site !== 'none')) return withSecurityHeaders(redirect(home, 302));
    const g = await ipContext(env, request);
    const b = await isBlocked(env, g, 'invalid');
    const rl = b.blocked ? { ok: false } : await rateLimit(env, g, 'captcha-page', CAPTCHA_PAGE);
    if (!rl.ok) {
      return withSecurityHeaders(new Response('Too many requests from your network. Try again later.', { status: 429, headers: { 'content-type': 'text/plain; charset=utf-8', 'retry-after': '600' } }));
    }
    return withSecurityHeaders(await asset('/check/'), { check: true });
  }
  const page = withSecurityHeaders(await asset(kind === 'r' ? '/r/' : '/'));
  const nav = h('sec-fetch-dest') === 'document' && h('sec-fetch-mode') === 'navigate'
    && (h('sec-fetch-site') === 'none' || h('sec-fetch-site') === 'same-origin');
  const Rewriter = globalThis.HTMLRewriter; // the Workers runtime's streaming HTML rewriter
  // The cookie's path must be the path the browser asked for, character for character.
  if (!valid || m[1] !== id || !nav || request.method !== 'GET' || !page.ok || typeof Rewriter !== 'function') return page;
  const cookiePath = `/${kind}/${id}`;
  const held = pageKeysIn(request); // this share path's page key cookies, one per round trip (tab)
  let pk;
  if (url.searchParams.has('n')) {
    // The return from the check page: only the key this browser holds for that nonce, once.
    const n = url.searchParams.get('n');
    const hit = held.find((c) => c.n === n);
    if (!hit) return page;
    pk = { n, key: hit.key };
    page.headers.append('set-cookie', pageKeyCookie(cookiePath, n, null));
  } else {
    pk = newPageKey();
    page.headers.append('set-cookie', pageKeyCookie(cookiePath, pk.n, pk));
    // At most PAGE_KEYS_MAX per share path: a new one clears the oldest beyond that.
    for (const old of held.sort((a, b) => b.t - a.t).slice(PAGE_KEYS_MAX - 1)) {
      page.headers.append('set-cookie', pageKeyCookie(cookiePath, old.n, null));
    }
  }
  // Set as an attribute value by the rewriter (it escapes it), never written as markup.
  return new Rewriter().on('meta[name="secbin-page-key"]', {
    element(el) { el.setAttribute('content', `${pk.n}.${pk.key}`); },
  }).transform(page);
}

async function route(request, env, url, ctx) {
  const { pathname } = url;
  if (pathname === '/r' || pathname.startsWith('/r/')) return sharePage(request, env, url, 'r');
  if (pathname.startsWith('/p/')) return sharePage(request, env, url, 'p');
  // The check page is served only as /p|r/<id>?check.
  if (pathname === '/check' || pathname.startsWith('/check/')) return pageNotFound();
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
  if (pathname.startsWith('/api/reverse/')) return handleReversePublic(request, env, url);
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
