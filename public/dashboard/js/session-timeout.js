// session-timeout.js — warns before a signed-in session ends, and lets the
// person stay signed in (WCAG 2.2.1 Timing Adjustable, 2.2.6 Timeouts).
//
// The server ends a session after `idleSec` without a request (each request
// slides that window, at most once a minute) and at `endsAt` at the latest
// (/api/private/me → session; src/lib/auth.js). WARN_SEC before either, a
// dialog says so:
//   - inactivity: "Stay signed in" makes a request, which moves the end again,
//     as often as needed; Escape does the same;
//   - the absolute end cannot be moved: that dialog only says when it comes.
// When the time is up the dialog says so, and the page locks: it is hidden and
// inert behind the dialog, the tab's Drive keys are cleared (an open Drive
// closes: 'secbin:session-ended'), password fields are emptied and the toast is
// put away. Nothing changes page on its own (3.2.5): "Sign in again" opens the
// login page in a new tab, so what is typed here stays (2.2.5); coming back to
// this tab re-checks the session and, for the same user, unlocks the page. For
// anyone else (another account signed in meanwhile) the page stays locked and
// says that the session changed (api.js endPageSession), never taking over the
// other session.
//
// All times are the server's: the page measures its clock against the `now`
// the server sends with the session, so a browser clock that is off does not
// move the warning.

import { h, spellDuration as spell } from '../../js/common.js';
import { me, logout, onPrivateActivity, ApiError, isPageSession, endPageSession } from '../../js/api.js';
import { clearSessionKey } from '../../js/drivekeys.js';
import { dismissToast } from '../../js/ui.js';

export const WARN_SEC = 120;

const clock = (ms) => {
  const s = Math.max(0, Math.ceil(ms / 1000));
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, '0')}`;
};


/**
 * Watch the session described by `session` ({ idleSec, idleEndsAt, endsAt,
 * slideSec, now }, Unix seconds; `now` is the server's time when it answered).
 * Returns { stop, state } (state for tests). `now` (this browser's clock) and
 * `every` are injectable for tests.
 */
export function watchSession(session, { now = () => Date.now(), every = (fn, ms) => setInterval(fn, ms), clear = (t) => clearInterval(t), loginUrl = '/dashboard/login/' } = {}) {
  if (!session || !Number.isFinite(session.idleEndsAt) || !Number.isFinite(session.endsAt)) return { stop() {}, state: null };
  const st = {
    idleSec: session.idleSec,
    slideSec: Number.isFinite(session.slideSec) ? session.slideSec : 60,
    idleEndsAt: session.idleEndsAt * 1000,
    endsAt: session.endsAt * 1000,
    shown: null, // the open dialog: null | 'idle' | 'absolute' | 'expired'
    dismissedAbsolute: false,
    expired: false,
    locked: false, // the page is hidden and inert until the same user signs in again
    changed: false, // another account is signed in now: nothing more is watched
    skew: 0, // the server's clock minus this browser's, in ms
  };
  let dlg = null;
  let carried = null; // the opener, kept when one dialog replaces another
  let lockedEls = [];
  const measure = (s) => { if (s && Number.isFinite(s.now)) st.skew = s.now * 1000 - now(); };
  const serverNow = () => now() + st.skew;
  measure(session);

  const adopt = (s) => {
    if (!s || !Number.isFinite(s.idleEndsAt)) return;
    measure(s);
    if (s.endsAt * 1000 !== st.endsAt) st.dismissedAbsolute = false; // a new session
    st.idleSec = s.idleSec;
    st.idleEndsAt = s.idleEndsAt * 1000;
    st.endsAt = s.endsAt * 1000;
    st.expired = false;
  };

  /** The session is over: keep nothing usable on screen or in the tab (what was typed stays, hidden). */
  function lockPage() {
    if (st.locked) return;
    st.locked = true;
    clearSessionKey(); // the tab's Drive key slots, stored or held in memory
    dismissToast();
    for (const el of document.querySelectorAll('input[type="password"]')) el.value = '';
    // An open Drive closes itself (its key, names and dialogs): drive-app.js.
    window.dispatchEvent(new CustomEvent('secbin:session-ended'));
    lockedEls = [...document.body.children].filter((el) => el.tagName !== 'SCRIPT' && el.id !== 'toast' && !el.classList.contains('session-dialog'));
    for (const el of lockedEls) {
      el.dataset.sessionWasInert = el.inert ? '1' : '';
      el.inert = true;
      el.classList.add('session-locked');
    }
  }
  function unlockPage() {
    if (!st.locked) return;
    st.locked = false;
    for (const el of lockedEls) {
      el.classList.remove('session-locked');
      if (!el.dataset.sessionWasInert) el.inert = false;
      delete el.dataset.sessionWasInert;
    }
    lockedEls = [];
  }
  /** Another account is signed in in this browser now: the page stays locked and says so. */
  function sessionChanged() {
    st.changed = true;
    st.expired = true;
    close({ restore: false });
    lockPage();
    endPageSession(); // the "session changed" banner, with Reload (nav.js)
  }
  // A request at time t slid the window unless the last slide was under
  // slideSec ago: the end is at least t - slideSec + idleSec.
  const off = onPrivateActivity(() => {
    if (st.expired) return;
    const t = serverNow();
    st.idleEndsAt = Math.min(st.endsAt, Math.max(st.idleEndsAt, t + (st.idleSec - st.slideSec) * 1000));
    if (st.shown === 'idle' && st.idleEndsAt - t > WARN_SEC * 1000) close();
  });

  function tick() {
    if (st.changed) return;
    const t = serverNow();
    const left = Math.min(st.idleEndsAt, st.endsAt) - t;
    const absolute = st.endsAt <= st.idleEndsAt;
    if (left <= 0) {
      st.expired = true;
      if (st.shown !== 'expired') expire(absolute);
    } else if (left <= WARN_SEC * 1000) {
      if (absolute && !st.dismissedAbsolute && st.shown !== 'absolute') show('absolute');
      else if (!absolute && st.shown !== 'idle') show('idle');
    }
    if (dlg && dlg.timer) dlg.timer.textContent = clock(left);
  }

  function expire(absolute) {
    close({ restore: false });
    lockPage();
    show('expired', absolute);
  }

  async function stay() {
    if (!dlg) return;
    dlg.primary.disabled = true;
    try {
      const p = await me();
      if (!isPageSession(p)) { sessionChanged(); return; }
      adopt(p.session);
      close();
    } catch (e) {
      if (dlg) dlg.primary.disabled = false;
      if (e instanceof ApiError && e.status === 401) { st.expired = true; expire(false); }
    }
  }

  // Back in this tab after signing in elsewhere: the same user picks the page up again; anyone
  // else never does (the page stays locked and says the session changed).
  async function recheck() {
    if (!st.expired || st.changed || document.visibilityState === 'hidden') return;
    let p;
    try { p = await me(); } catch { return; /* still signed out */ }
    if (!isPageSession(p)) { sessionChanged(); return; }
    adopt(p.session);
    unlockPage();
    close();
  }
  document.addEventListener('visibilitychange', recheck);
  window.addEventListener('focus', recheck);

  const sendBtn = (label, on) => h('button.send', { type: 'button', on: { click: on } }, h('span.send-txt', { text: label }));

  function show(kind, absolute = false) {
    close({ restore: false });
    st.shown = kind;
    const id = 'session-dlg';
    const timer = h('span.mono', { role: 'timer', 'aria-live': 'off' });
    let title;
    let text;
    let primary;
    let secondary = null;
    if (kind === 'idle') {
      title = 'Are you still there?';
      text = [`For your security you are signed out after ${spell(st.idleSec)} without activity. Time left: `, timer, '.'];
      secondary = h('button.btn.modal-btn', { type: 'button', text: 'Log out', on: { click: async () => { try { await logout(); } catch { /* cleared anyway */ } location.assign(loginUrl); } } });
      primary = sendBtn('Stay signed in', stay);
    } else if (kind === 'absolute') {
      title = 'Your session ends soon';
      text = ['This session reaches its maximum length in ', timer, ' and cannot be extended. Finish or copy what you are working on, then sign in again.'];
      primary = sendBtn('OK', () => { st.dismissedAbsolute = true; close(); });
    } else {
      title = 'You have been signed out';
      text = [absolute ? 'This session reached its maximum length.' : `There was no activity for ${spell(st.idleSec)}.`,
        ' This page is hidden until you sign in again: sign in in a new tab, then come back to this tab and carry on. What you typed is kept, except passwords; an open Drive was closed.'];
      secondary = h('button.btn.modal-btn', { type: 'button', text: 'Log out', on: { click: async () => { try { await logout(); } catch { /* cleared anyway */ } location.assign(loginUrl); } } });
      primary = h('a.send', { href: loginUrl, target: '_blank', rel: 'noopener' }, h('span.send-txt', { text: 'Sign in again' }), h('span.sr-only', { text: ' (opens in a new tab)' }));
    }
    const box = h('div.modal', { role: 'alertdialog', 'aria-modal': 'true', 'aria-labelledby': `${id}-t`, 'aria-describedby': `${id}-s`, tabindex: '-1', id },
      h('h2.modal-title', { id: `${id}-t`, text: title }),
      h('p.modal-sub', { id: `${id}-s` }, ...text),
      h('div.modal-actions', {}, secondary, primary));
    const scrim = h('div.modal-scrim.session-dialog', {}, box);
    const opener = carried || document.activeElement;
    carried = null;
    const inerted = [...document.body.children].filter((el) => el.id !== 'toast' && el.tagName !== 'SCRIPT' && !el.inert);
    const onKey = (e) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        if (kind === 'idle') stay();
        else if (kind === 'absolute') { st.dismissedAbsolute = true; close(); }
        // Signed out: the dialog stays (the page behind it is locked); its buttons are the way on.
        return;
      }
      if (e.key !== 'Tab') return;
      const f = [...box.querySelectorAll('button, a[href]')].filter((el) => !el.disabled);
      if (!f.length) return;
      e.preventDefault();
      e.stopPropagation();
      const i = f.indexOf(document.activeElement);
      f[(i + (e.shiftKey ? -1 : 1) + f.length) % f.length].focus();
    };
    document.body.appendChild(scrim);
    for (const el of inerted) el.inert = true;
    // On window, capturing: before any other dialog's trap (a Drive dialog may be open underneath).
    window.addEventListener('keydown', onKey, true);
    dlg = { scrim, inerted, onKey, opener, timer: kind === 'expired' ? null : timer, primary };
    primary.focus();
    if (dlg.timer) dlg.timer.textContent = clock(Math.min(st.idleEndsAt, st.endsAt) - serverNow());
  }

  function close({ restore = true } = {}) {
    if (!dlg) return;
    const d = dlg;
    dlg = null;
    st.shown = null;
    d.scrim.remove();
    for (const el of d.inerted) el.inert = false;
    window.removeEventListener('keydown', d.onKey, true);
    if (!restore) carried = d.opener;
    else if (d.opener && d.opener.isConnected && typeof d.opener.focus === 'function') d.opener.focus();
  }

  const handle = every(tick, 1000);
  tick();
  return {
    state: st,
    tick,
    stop() { clear(handle); off(); close(); unlockPage(); document.removeEventListener('visibilitychange', recheck); window.removeEventListener('focus', recheck); },
  };
}
