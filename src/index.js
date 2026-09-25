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

import { err, HttpError, withSecurityHeaders, redirect } from './lib/http.js';
import { readSession, logoutCookie } from './lib/auth.js';
import { ipContext } from './lib/guard.js';
import { BindingMissing } from './lib/config.js';
import { handleAuth } from './routes/auth.js';
import { handlePrivate } from './routes/private.js';
import { handlePublic } from './routes/public.js';
import { handlePublicApi } from './routes/publicapi.js';

export { BurnPaste } from './burn-do.js';
export { FileShare } from './fileshare-do.js';
export { Directory } from './directory-do.js';
export { Guard } from './guard-do.js';

const DASH_PUBLIC = /^\/dashboard\/(login|setup)(\/|\/index\.html)?$/;

async function serveAsset(env, request) {
  if (!env.ASSETS) return new Response('Not found', { status: 404 });
  return withSecurityHeaders(await env.ASSETS.fetch(request));
}

async function handleDashboard(request, env, url) {
  if (DASH_PUBLIC.test(url.pathname)) return serveAsset(env, request);
  const s = await readSession(request, env);
  if (!s.ok) {
    if (s.reason !== 'disabled') return redirect('/dashboard/login/');
    const res = redirect('/dashboard/login/?disabled=1');
    res.headers.append('set-cookie', logoutCookie());
    return res;
  }
  if (/^\/dashboard\/admin(\/|$)/.test(url.pathname) && (s.user.role !== 'owner' || s.actor)) return redirect('/dashboard/');
  const res = await serveAsset(env, request);
  if (s.setCookie) res.headers.append('set-cookie', s.setCookie);
  return res;
}

async function route(request, env, url, ctx) {
  const { pathname } = url;
  const isApi = pathname.startsWith('/api/');
  const isDash = pathname === '/dashboard' || pathname.startsWith('/dashboard/');
  if (!isApi && !isDash) return serveAsset(env, request);

  // Manual admin block rules apply to the whole API and app surface.
  const g = await ipContext(env, request);
  if (g.manual === 'block') return err(403, 'blocked', 'Access from your network is blocked.');

  if (isDash) return handleDashboard(request, env, url);
  if (pathname.startsWith('/api/auth/')) return (await handleAuth(request, env, url)) ?? err(404, 'not_found', 'Not found.');
  if (pathname.startsWith('/api/private/') || pathname === '/api/private') return handlePrivate(request, env, url, ctx);
  if (pathname.startsWith('/api/public/')) return handlePublicApi(request, env, url);
  return (await handlePublic(request, env, url)) ?? err(404, 'not_found', 'Not found.');
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    try {
      return await route(request, env, url, ctx);
    } catch (e) {
      if (e instanceof HttpError) return e.toResponse();
      if (e instanceof BindingMissing) {
        console.error(`deployment error: the ${e.binding} binding is missing or invalid`);
        // The binding's name goes to the logs, not to the (possibly anonymous) caller.
        return err(503, 'not_configured', 'The server is not fully configured. Please contact the administrator.');
      }
      console.error('unhandled error', e && e.stack ? e.stack : e);
      return err(500, 'server_error', 'Something went wrong. Please try again.');
    }
  },
};
