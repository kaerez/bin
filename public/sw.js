// sw.js — secbin's service worker (scope "/"). It exists to make the app
// installable and to keep the static shell available offline; it is NOT a
// content cache. The rules, in order (requestPolicy below is the single
// decision point, unit-tested in test-node/sw.test.js):
//
//   • Only same-origin GET requests without a query string are ever touched.
//     Everything else (other origins, POST/PUT/DELETE, anything with "?…",
//     Range requests) goes straight to the network — the worker does not even
//     call respondWith(), so it can never answer from cache.
//   • /api/* (share ciphertext, grants, accounts) and /p/* (the share viewer)
//     are never intercepted and never cached. A share's key lives in the URL
//     fragment, which is never part of a request, but even the viewer page for
//     a share id stays network-only so nothing about a share lands on disk.
//   • Static assets (/css, /js, /fonts, /img, the manifest, the favicon) are
//     network-first: always fetched fresh while online (a security app must
//     not run yesterday's code), with the last good copy used only when the
//     network fails.
//   • HTML is network-first too, and only the public landing page "/" may be
//     cached as the offline fallback. Dashboard pages are left alone.
//   • A response is stored only if it is a plain 200 from this origin, not a
//     redirect, and not marked no-store (the Worker marks everything it serves
//     itself — /dashboard*, the API — no-store).
//   • The cache name is versioned; activation deletes every older secbin cache
//     and claims open pages immediately (skipWaiting + clients.claim).
//
// Plain classic script (no modules, no importScripts) so it runs everywhere a
// service worker does; the CSP's worker-src 'self' and the Trusted Types policy
// in public/js/tt.js (which mints the '/sw.js' script URL) govern registration.

const VERSION = '3';
const CACHE_PREFIX = 'secbin-static-';
const CACHE = CACHE_PREFIX + VERSION;

// Same-origin static asset locations (path prefixes and exact files).
const STATIC_PREFIXES = ['/css/', '/js/', '/fonts/', '/img/'];
const STATIC_FILES = ['/manifest.webmanifest', '/favicon.ico'];
// The only HTML that may be served from cache when offline.
const SHELL_PAGES = ['/'];
// Never intercepted, never cached.
const NETWORK_ONLY_PREFIXES = ['/api/', '/p/'];

// Warmed on install (best effort) so the offline landing page has its assets.
const PRECACHE = [
  '/',
  '/css/styles.css',
  '/js/theme-init.js',
  '/js/a11y-init.js',
  '/js/a11y.js',
  '/js/theme.js',
  '/js/tt.js',
  '/js/pwa.js',
  '/js/install-banner.js',
  '/manifest.webmanifest',
  '/img/favicon.svg',
  '/img/icon-192.png',
];

/**
 * Decide how a request is handled: 'static' (network-first, cacheable asset),
 * 'shell' (network-first HTML with offline fallback), or null (not handled —
 * the browser fetches it from the network as if there were no worker).
 */
function requestPolicy(request, origin) {
  if (!request || request.method !== 'GET') return null;
  let url;
  try { url = new URL(request.url); } catch { return null; }
  if (url.origin !== origin) return null;
  // Query strings may carry anything (tokens, ids); such URLs are never stored.
  if (url.search || url.href.includes('?')) return null;
  const path = url.pathname;
  if (path === '/api' || path === '/p') return null;
  for (const p of NETWORK_ONLY_PREFIXES) if (path.startsWith(p)) return null;
  if (/%2e|%2f|%5c|\/\.\.?(\/|$)|\\/i.test(path)) return null; // no encoded or dot segments
  if (request.headers && typeof request.headers.has === 'function' && request.headers.has('range')) return null;
  if (request.mode === 'navigate') return SHELL_PAGES.includes(path) ? 'shell' : null;
  if (STATIC_FILES.includes(path)) return 'static';
  for (const p of STATIC_PREFIXES) if (path.startsWith(p)) return 'static';
  return null;
}

/** Only a plain, complete, same-origin 200 that doesn't forbid storage. */
function isCacheableResponse(response) {
  if (!response || response.status !== 200 || !response.ok) return false;
  if (response.type !== 'basic' || response.redirected) return false;
  const cc = (response.headers && response.headers.get('cache-control')) || '';
  if (/no-store|private/i.test(cc)) return false;
  return true;
}

/** Cache key: origin + path only (never a fragment or query). */
function cacheKey(request) {
  const url = new URL(request.url);
  return url.origin + url.pathname;
}

async function networkFirst(request) {
  const cache = await caches.open(CACHE);
  try {
    // Revalidate with the server every time: the browser's HTTP cache must
    // never hand back an older asset than the one the page expects.
    const response = await fetch(request, { cache: 'no-cache' });
    if (isCacheableResponse(response)) {
      await cache.put(cacheKey(request), response.clone()).catch(() => {});
    }
    return response;
  } catch (e) {
    const cached = await cache.match(cacheKey(request));
    if (cached) return cached;
    throw e;
  }
}

self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE);
    await Promise.allSettled(PRECACHE.map(async (path) => {
      const response = await fetch(path, { cache: 'reload', credentials: 'same-origin' });
      if (isCacheableResponse(response)) await cache.put(new URL(path, self.location.origin).href, response);
    }));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(names.filter((n) => n.startsWith(CACHE_PREFIX) && n !== CACHE).map((n) => caches.delete(n)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const policy = requestPolicy(event.request, self.location.origin);
  if (!policy) return; // not ours: straight to the network, never cached
  event.respondWith(networkFirst(event.request));
});
