// turnstile.js — the Cloudflare Turnstile widget (a human check) on login, the
// account password form and the public composer, shown only when the server
// has it configured (/api/config → `turnstile`, the public site key). Each
// token works once: take() hands out the current one, and the next take()
// starts a fresh challenge. The server side is src/lib/turnstile.js.
//
// The widget is always shown ("always"), so the visitor sees the check pass
// before the protected button enables; its script is the only third-party code secbin loads,
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
const WAITING = 'Waiting for the human check…';
const BUTTON_DISABLED = Object.getOwnPropertyDescriptor(HTMLButtonElement.prototype, 'disabled');

/**
 * Keep `btn` disabled while `waiting()` is true, whatever the page does: the
 * page's own `btn.disabled = …` is remembered as its wish, and the button is
 * enabled only when the page wants it enabled and the check is not waiting.
 * Returns the function that re-applies the state.
 */
function gate(btn, waiting) {
  let want = BUTTON_DISABLED.get.call(btn);
  const title = btn.getAttribute('title');
  const apply = () => {
    const wait = waiting();
    BUTTON_DISABLED.set.call(btn, want || wait);
    if (wait) btn.setAttribute('title', WAITING);
    else if (title === null) btn.removeAttribute('title');
    else btn.setAttribute('title', title);
  };
  Object.defineProperty(btn, 'disabled', {
    configurable: true,
    get: () => BUTTON_DISABLED.get.call(btn),
    set: (v) => { want = !!v; apply(); },
  });
  apply();
  return apply;
}

/**
 * Mount the widget in `container` (a hidden element) for the form `action`.
 * Returns { active, take() } — take() resolves to a token, or to null when
 * the server has no human check; it throws with a readable message if the
 * check cannot be completed. The `gate` buttons stay disabled until the check
 * has a fresh token (again after each use), so nothing is sent before the
 * human check has passed; with no human check on the server they are left
 * alone.
 */
export async function humanCheck(container, action, { gate: buttons = [] } = {}) {
  let token = null;
  let state = 'pending'; // pending (site key unknown) | on | off
  let broken = null;
  const waiting = () => state === 'pending' || (state === 'on' && !token);
  const gates = buttons.filter(Boolean).map((b) => gate(b, waiting));
  const update = () => { for (const g of gates) g(); };
  const sitekey = container ? await turnstileSiteKey() : null;
  if (!sitekey) { state = 'off'; update(); return OFF; }
  state = 'on';
  update();
  container.hidden = false;
  let waiters = [];
  const settle = (fn) => { const w = waiters; waiters = []; for (const x of w) fn(x); };
  let ts;
  let id;
  try {
    ts = await loadScript();
    id = ts.render(container, {
      sitekey,
      action,
      theme: 'auto',
      size: 'flexible',
      appearance: 'always',
      'refresh-expired': 'auto',
      language: 'auto',
      callback: (t) => { token = t; update(); settle((x) => x.resolve(t)); },
      'expired-callback': () => { token = null; update(); },
      'error-callback': () => { token = null; update(); },
    });
  } catch (e) {
    broken = e instanceof Error ? e : new Error(LOAD_FAILED);
    // The buttons stay disabled: say why, where the widget would be.
    const note = document.createElement('p');
    note.className = 'msg error';
    note.setAttribute('role', 'alert');
    note.textContent = broken.message;
    container.replaceChildren(note);
  }
  return {
    active: true,
    async take() {
      if (broken) throw broken;
      const t = token || await new Promise((resolve, reject) => {
        const w = { resolve, reject: () => reject(new Error(NOT_DONE)) };
        waiters.push(w);
        setTimeout(() => { if (waiters.includes(w)) { waiters = waiters.filter((x) => x !== w); w.reject(); } }, WAIT_MS);
      });
      // A token works once: start the next check now (an issued token stays
      // valid), and keep the buttons disabled until it passes.
      token = null;
      update();
      ts.reset(id);
      return t;
    },
  };
}
