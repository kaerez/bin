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

import { err, HttpError, withSecurityHeaders, withCachePolicy, redirect, SECURITY_HEADERS } from './lib/http.js';
import { readSession, logoutCookie, SESSION_COOKIE } from './lib/auth.js';
import { ipContext, cachedSettings, directory } from './lib/guard.js';
import { turnstileKeys } from './lib/turnstile.js';
import { pageKey, pageNonce, PAGE_NONCE_RE } from './lib/human.js';
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
    const res = redirect('/dashboard/');
    if (s.setCookie) res.headers.append('set-cookie', s.setCookie);
    return res;
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
    const res = redirect('/dashboard/login/?disabled=1');
    res.headers.append('set-cookie', logoutCookie());
    return res;
  }
  if (/^\/dashboard\/admin(\/|$)/.test(url.pathname) && (s.user.role !== 'owner' || s.actor)) return redirect('/dashboard/');
  const res = await serveAsset(env, request, url);
  if (s.setCookie) res.headers.append('set-cookie', s.setCookie);
  return res;
}

const pageNotFound = () => withSecurityHeaders(new Response('Not found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8' } }));

/**
 * The CAPTCHA of a share that has one, without the link's key ever being
 * readable where Cloudflare's script runs (docs: SECURITY.md, "CAPTCHA on
 * shares"):
 *   • /p/<id> and /r/<id> — the recipient's page and the uploader's page —
 *     always get the strict CSP. On a real navigation (Sec-Fetch-Dest:
 *     document, Sec-Fetch-Mode: navigate, which a script cannot send with
 *     fetch) the page also gets a page key: a meta tag with a nonce `n` and
 *     HMAC(SIG-derived key, kind ‖ id ‖ n). When the share needs the CAPTCHA,
 *     the page seals the link's key with it in sessionStorage, takes it out
 *     of the address bar and goes to the check page.
 *   • /p/<id>?check and /r/<id>?check — the check page (public/check/): the
 *     Turnstile CSP, only when the share has the CAPTCHA and the server has
 *     Turnstile keys (else a redirect back). It holds only the sealed key;
 *     after the check it returns to /p/<id>?n=<n>, whose navigation gets the
 *     page key for that nonce again, and that strict page opens the key.
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
  if (url.searchParams.has('check')) {
    const on = valid && !!(await turnstileKeys(env)) && (await directory(env).shareCaptcha(id));
    if (!on) return withSecurityHeaders(redirect(home, 302));
    return withSecurityHeaders(await asset('/check/'), { turnstile: true });
  }
  const page = withSecurityHeaders(await asset(kind === 'r' ? '/r/' : '/'));
  const nav = (request.headers.get('sec-fetch-dest') || '') === 'document' && (request.headers.get('sec-fetch-mode') || '') === 'navigate';
  const Rewriter = globalThis.HTMLRewriter; // the Workers runtime's streaming HTML rewriter
  if (!valid || !nav || request.method !== 'GET' || !page.ok || typeof Rewriter !== 'function') return page;
  const asked = url.searchParams.get('n');
  const n = asked && PAGE_NONCE_RE.test(asked) ? asked : pageNonce();
  const key = await pageKey(env, kind, id, n);
  return new Rewriter().on('head', {
    element(el) { el.append(`<meta name="secbin-page-key" content="${n}.${key}">`, { html: true }); },
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
