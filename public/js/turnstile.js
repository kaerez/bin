// turnstile.js — the Cloudflare Turnstile widget (a human check) on login, the
// account page (one widget per card) and the public composer, shown only when the server
// has it configured (/api/config → `turnstile`, the public site key). Each
// token works once: take() hands out the current one, and the next take()
// starts a fresh challenge. The server side is src/lib/turnstile.js.
//
// The widget is always shown ("always"), so the visitor sees the check pass
// before the protected button enables; its script is the only third-party code secbin loads,
// and only on those pages (see the CSP in src/lib/http.js).

import { scriptURL, TURNSTILE_SCRIPT } from './tt.js';
import { fetchConfig } from './api.js';
import { holdSessionKeys } from './drivekeys.js';

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
      // Third-party script from here on: the tab's Drive keys leave
      // sessionStorage for drivekeys.js's memory first (SECURITY.md, "Drive keys").
      holdSessionKeys();
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

const OFF = Object.freeze({ active: false, take: async () => null, gate: () => {} });
const WAITING = 'Waiting for the human check…';
let noteSeq = 0;

/** The native `disabled` accessor of a button, input, select or fieldset. */
function disabledOf(el) {
  for (let p = Object.getPrototypeOf(el); p; p = Object.getPrototypeOf(p)) {
    const d = Object.getOwnPropertyDescriptor(p, 'disabled');
    if (d && d.get && d.set) return d;
  }
  throw new TypeError('humanCheck can only gate form controls');
}

/**
 * Keep `btn` disabled while `waiting()` is true, whatever the page does: the
 * page's own `btn.disabled = …` is remembered as its wish, and the button is
 * enabled only when the page wants it enabled and the check is not waiting.
 * Returns the function that re-applies the state.
 */
function gate(btn, waiting) {
  const native = disabledOf(btn);
  let want = native.get.call(btn);
  const apply = () => native.set.call(btn, want || waiting());
  Object.defineProperty(btn, 'disabled', {
    configurable: true,
    get: () => native.get.call(btn),
    set: (v) => { want = !!v; apply(); },
  });
  apply();
  return apply;
}

/**
 * Mount the widget in `container` (a hidden element) for the form `action`.
 * Returns { active, take(), gate(btn) } — take() resolves to a token, or to
 * null when the server has no human check; it throws with a readable message
 * if the check cannot be completed. The `gate` buttons (any form control) stay
 * disabled until the check has a fresh token (again after each use), so
 * nothing is sent before the human check has passed; with no human check on
 * the server they are left alone. gate(btn) adds a control created later (a
 * table row's button) to the same gate; it is also on the returned promise,
 * so a page can gate new buttons at once, before the widget has loaded. One
 * widget can serve several buttons: each take() uses up the token and starts
 * a fresh check.
 */
export function humanCheck(container, action, { gate: buttons = [] } = {}) {
  let token = null;
  let state = 'pending'; // pending (site key unknown) | on | off
  let broken = null;
  const waiting = () => state === 'pending' || (state === 'on' && !token);
  const gated = buttons.filter(Boolean);
  const gates = gated.map((b) => gate(b, waiting));
  // The reason, shown under the first protected button while the check is
  // pending (only once the server is known to have one), and referenced by
  // every protected button for screen readers.
  let note = null;
  if (gated.length) {
    note = document.createElement('p');
    note.className = 'mono muted human-wait';
    note.id = `human-wait-${++noteSeq}`;
    note.setAttribute('role', 'status');
    note.textContent = WAITING;
    note.hidden = true;
    gated[0].insertAdjacentElement('afterend', note);
    for (const b of gated) b.setAttribute('aria-describedby', [b.getAttribute('aria-describedby'), note.id].filter(Boolean).join(' '));
  }
  const update = () => {
    for (const g of gates) g();
    if (note) note.hidden = !(state === 'on' && !token && !broken);
  };
  const addGate = (b) => {
    if (!b) return;
    gates.push(gate(b, waiting));
    if (note) b.setAttribute('aria-describedby', [b.getAttribute('aria-describedby'), note.id].filter(Boolean).join(' '));
  };
  const mounted = mount();
  return Object.assign(mounted, { gate: addGate });

  async function mount() {
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
      update();
      // The buttons stay disabled: say why, where the widget would be.
      const note = document.createElement('p');
      note.className = 'msg error';
      note.setAttribute('role', 'alert');
      note.textContent = broken.message;
      container.replaceChildren(note);
    }
    return {
      active: true,
      gate: addGate,
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
}
