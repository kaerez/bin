// pwa.js — loaded by every page: registers the service worker (public/sw.js)
// and starts the install banner (install-banner.js).
//
// The worker's script URL is minted by the page's single Trusted Types policy
// (tt.js allows exactly '/sw.js' besides /js/*), so registration works under
// `require-trusted-types-for 'script'`; `worker-src 'self'` covers the worker
// itself. Registration waits for `load` so it never competes with the page's
// own requests, and failures are non-fatal (the app works without it).
import { scriptURL } from './tt.js';
import { startInstallBanner } from './install-banner.js';

export async function registerServiceWorker(win = window) {
  const sw = win.navigator && win.navigator.serviceWorker;
  if (!sw || !win.isSecureContext) return null;
  try {
    return await sw.register(scriptURL('/sw.js'), { scope: '/', updateViaCache: 'none' });
  } catch (e) {
    console.warn('secbin: service worker registration failed', e && e.message ? e.message : e);
    return null;
  }
}

if (document.readyState === 'complete') registerServiceWorker();
else window.addEventListener('load', () => { registerServiceWorker(); }, { once: true });

startInstallBanner();
