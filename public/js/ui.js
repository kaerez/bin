// ui.js — small DOM helpers for the client. No innerHTML on user content.

export const $ = (sel, root = document) => root.querySelector(sel);

/** Show exactly one top-level view section (`<section id="view-…">`), hide the rest. */
export function showView(name) {
  let shown = null;
  for (const el of document.querySelectorAll('main section[id^="view-"]')) {
    el.hidden = el.id !== `view-${name}`;
    if (!el.hidden) shown = el;
  }
  // Keyboard/screen-reader users must not be left focused on a control that
  // just became hidden — move focus to the shown view (sections carry
  // tabindex="-1"). Repeated transitions to the same view (status updates)
  // keep focus where it is; controllers may then focus a specific field.
  if (shown && !shown.contains(document.activeElement)) shown.focus();
}

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), summary, [tabindex]:not([tabindex="-1"])';

/**
 * Keep keyboard focus through a re-render of `container` that may remove the
 * focused control (a table rebuilt after a delete, an editor re-opened after
 * a save). Call it before the re-render and the returned function after:
 * when focus was inside `container` and has been lost (to <body>), it goes to
 * the control with the same `data-focus-key` in the new DOM — or, key by key,
 * to the nearest enclosing key ("user:7:delete" → "user:7": the row) — and
 * failing that to `fallback` (default: `container`), made focusable with
 * tabindex="-1" if it is not already.
 *
 * `key` names the control explicitly, for callers whose control had already
 * lost focus before the re-render (Chromium blurs a button as soon as it is
 * disabled, e.g. while its action runs).
 */
export function keepFocus(container, { fallback = container, key: forced = null } = {}) {
  const before = document.activeElement;
  const had = !!forced || !!(container && before && before !== document.body && container.contains(before));
  const key = forced || (had ? before.closest('[data-focus-key]')?.dataset.focusKey : null);
  return () => {
    if (!had) return;
    const now = document.activeElement;
    if (now && now !== document.body && now !== document.documentElement && now.isConnected && !now.disabled) return;
    const scope = container.isConnected ? container : document;
    for (let k = key; k; k = k.includes(':') ? k.slice(0, k.lastIndexOf(':')) : null) {
      const el = [...scope.querySelectorAll('[data-focus-key]')].find((e) => e.dataset.focusKey === k);
      const target = el && (el.matches(FOCUSABLE) ? el : el.querySelector(FOCUSABLE));
      if (target && !target.disabled && target.getClientRects().length) { target.focus(); return; }
    }
    const f = typeof fallback === 'function' ? fallback() : fallback;
    if (!f || !f.isConnected) return;
    if (!f.matches(FOCUSABLE) && !f.hasAttribute('tabindex')) f.setAttribute('tabindex', '-1');
    f.focus();
  };
}

/**
 * Keyboard behaviour of an ARIA tablist (WAI-ARIA APG "Tabs"): one Tab stop —
 * the selected tab (roving tabindex) — and ←/→ (mirrored in RTL), Home and End
 * between the visible tabs. `automatic`: the focused tab is selected at once
 * (by clicking it); otherwise Enter / Space selects it (for panels that load).
 * Returns `sync`: call it after aria-selected changes to move the Tab stop.
 */
export function tablistKeys(list, { automatic = false } = {}) {
  const tabs = () => [...list.querySelectorAll('[role="tab"]')].filter((t) => !t.hidden);
  const sync = () => { for (const t of list.querySelectorAll('[role="tab"]')) t.tabIndex = t.getAttribute('aria-selected') === 'true' ? 0 : -1; };
  list.addEventListener('keydown', (e) => {
    if (e.altKey || e.ctrlKey || e.metaKey) return;
    const all = tabs();
    const i = all.indexOf(document.activeElement);
    if (i < 0) return;
    const rtl = getComputedStyle(list).direction === 'rtl';
    const to = { ArrowRight: rtl ? i - 1 : i + 1, ArrowLeft: rtl ? i + 1 : i - 1, Home: 0, End: all.length - 1 }[e.key];
    if (to === undefined) return;
    e.preventDefault();
    const t = all[(to + all.length) % all.length];
    t.focus();
    if (automatic) t.click();
  });
  sync();
  return sync;
}

/**
 * Transient bottom toast (role="status", so it is announced). Every save
 * confirms with one. `{ error: true }` styles it as a failure and keeps it up
 * longer.
 */
let toastTimer;
export function toast(message, { error = false } = {}) {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = message;
  t.classList.toggle('error', !!error);
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), error ? 6000 : 3500);
}

/** Copy text to the clipboard, with a legacy fallback. Returns a boolean. */
export async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* fall through */ }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.className = 'clipboard-stage';
  document.body.appendChild(ta);
  try {
    ta.select();
    return document.execCommand('copy');
  } catch {
    return false;
  } finally {
    // The staging textarea holds the paste URL (key fragment included) — it must
    // never be left in the DOM, even when select/execCommand throws.
    document.body.removeChild(ta);
  }
}

/** Flash a copy button into its "copied" state briefly. */
export function flashCopied(btn, label = 'copied') {
  if (!btn) return;
  const original = btn.dataset.label || btn.textContent;
  btn.dataset.label = original;
  btn.textContent = label;
  btn.classList.add('copied');
  setTimeout(() => {
    btn.textContent = btn.dataset.label;
    btn.classList.remove('copied');
  }, 1600);
}

/** Build a pill element (mono badge with a status dot). */
export function pill(text, kind) {
  const el = document.createElement('span');
  el.className = kind ? `pill ${kind}` : 'pill';
  el.textContent = text;
  return el;
}
