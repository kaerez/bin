// turnstile.js — the Cloudflare Turnstile widget (a human check) on login, the
// account password form and the public composer, shown only when the server
// has it configured (/api/config → `turnstile`, the public site key). Each
// token works once: take() hands out the current one, and the next take()
// starts a fresh challenge. The server side is src/lib/turnstile.js.
//
// The widget stays invisible unless Cloudflare needs the visitor to interact
// ("interaction-only"); its script is the only third-party code secbin loads,
// and only on those pages (see the CSP in src/lib/http.js).

import { scriptURL, TURNSTILE_SCRIPT } from './tt.js';
import { fetchConfig } from './api.js';

const WAIT_MS = 120000;
const LOAD_FAILED = 'The human check (Cloudflare Turnstile) could not load. Check your connection or content blocker, then reload the page.';
const NOT_DONE = 'Complete the human check, then try again.';

let loader = null;
function loadScript() {
  if (globalThis.turnstile) return Promise.resolve(globalThis.turnstile);
  if (!loader) {
    loader = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.async = true;
      s.onload = () => (globalThis.turnstile ? resolve(globalThis.turnstile) : reject(new Error(LOAD_FAILED)));
      s.onerror = () => { loader = null; s.remove(); reject(new Error(LOAD_FAILED)); };
      s.src = scriptURL(TURNSTILE_SCRIPT);
      document.head.appendChild(s);
    });
  }
  return loader;
}

/** The site key, or null when this server has no human check. */
export async function turnstileSiteKey() {
  try {
    const c = await fetchConfig();
    return typeof c.turnstile === 'string' && c.turnstile ? c.turnstile : null;
  } catch {
    return null; // the server still decides; a refusal explains itself
  }
}

const OFF = Object.freeze({ active: false, take: async () => null });

/**
 * Mount the widget in `container` (a hidden element) for the form `action`.
 * Returns { active, take() } — take() resolves to a token, or to null when
 * the server has no human check; it throws with a readable message if the
 * check cannot be completed.
 */
export async function humanCheck(container, action) {
  const sitekey = container ? await turnstileSiteKey() : null;
  if (!sitekey) return OFF;
  container.hidden = false;
  let token = null;
  let used = false;
  let waiters = [];
  const settle = (fn) => { const w = waiters; waiters = []; for (const x of w) fn(x); };
  let ts;
  let id;
  let broken = null;
  try {
    ts = await loadScript();
    id = ts.render(container, {
      sitekey,
      action,
      theme: 'auto',
      size: 'flexible',
      appearance: 'interaction-only',
      'refresh-expired': 'auto',
      language: 'auto',
      callback: (t) => { token = t; used = false; settle((x) => x.resolve(t)); },
      'expired-callback': () => { token = null; },
      'error-callback': () => { token = null; },
    });
  } catch (e) {
    broken = e instanceof Error ? e : new Error(LOAD_FAILED);
  }
  return {
    active: true,
    async take() {
      if (broken) throw broken;
      if (used) { used = false; token = null; ts.reset(id); } // a token works once
      const t = token || await new Promise((resolve, reject) => {
        const w = { resolve, reject: () => reject(new Error(NOT_DONE)) };
        waiters.push(w);
        setTimeout(() => { if (waiters.includes(w)) { waiters = waiters.filter((x) => x !== w); w.reject(); } }, WAIT_MS);
      });
      used = true;
      return t;
    },
  };
}
