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
// When the time is up the dialog says so. Nothing is lost and nothing changes
// page on its own (3.2.5): "Sign in again" opens the login page in a new tab,
// so what is typed here stays (2.2.5); coming back to this tab re-checks the
// session and carries on.

import { h, spellDuration as spell } from '../../js/common.js';
import { me, logout, onPrivateActivity, ApiError } from '../../js/api.js';

export const WARN_SEC = 120;

const clock = (ms) => {
  const s = Math.max(0, Math.ceil(ms / 1000));
  const m = Math.floor(s / 60);
  return `${m}:${String(s % 60).padStart(2, '0')}`;
};


/**
 * Watch the session described by `session` ({ idleSec, idleEndsAt, endsAt,
 * slideSec }, Unix seconds). Returns { stop, state } (state for tests).
 * `now` and `interval` are injectable for tests.
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
    dismissedExpired: false,
  };
  let dlg = null;
  let carried = null; // the opener, kept when one dialog replaces another

  const adopt = (s) => {
    if (!s || !Number.isFinite(s.idleEndsAt)) return;
    if (s.endsAt * 1000 !== st.endsAt) st.dismissedAbsolute = false; // a new session
    st.idleSec = s.idleSec;
    st.idleEndsAt = s.idleEndsAt * 1000;
    st.endsAt = s.endsAt * 1000;
    st.expired = false;
    st.dismissedExpired = false;
  };
  // A request at time t slid the window unless the last slide was under
  // slideSec ago: the end is at least t - slideSec + idleSec.
  const off = onPrivateActivity(() => {
    if (st.expired) return;
    const t = now();
    st.idleEndsAt = Math.min(st.endsAt, Math.max(st.idleEndsAt, t + (st.idleSec - st.slideSec) * 1000));
    if (st.shown === 'idle' && st.idleEndsAt - t > WARN_SEC * 1000) close();
  });

  function tick() {
    const t = now();
    const left = Math.min(st.idleEndsAt, st.endsAt) - t;
    const absolute = st.endsAt <= st.idleEndsAt;
    if (left <= 0) {
      st.expired = true;
      if (st.shown !== 'expired' && !st.dismissedExpired) show('expired', absolute);
    } else if (left <= WARN_SEC * 1000) {
      if (absolute && !st.dismissedAbsolute && st.shown !== 'absolute') show('absolute');
      else if (!absolute && st.shown !== 'idle') show('idle');
    }
    if (dlg && dlg.timer) dlg.timer.textContent = clock(left);
  }

  async function stay() {
    if (!dlg) return;
    dlg.primary.disabled = true;
    try {
      adopt((await me()).session);
      close();
    } catch (e) {
      if (dlg) dlg.primary.disabled = false;
      if (e instanceof ApiError && e.status === 401) { st.expired = true; show('expired', false); }
    }
  }

  // Back in this tab after signing in elsewhere: pick up the new session.
  async function recheck() {
    if (!st.expired || document.visibilityState === 'hidden') return;
    try {
      adopt((await me()).session);
      close();
    } catch { /* still signed out */ }
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
        ' What you typed on this page is still here: sign in again in a new tab, then come back to this tab and carry on.'];
      secondary = h('button.btn.modal-btn', { type: 'button', text: 'Close', on: { click: () => { st.dismissedExpired = true; close(); } } });
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
        else { if (kind === 'absolute') st.dismissedAbsolute = true; else st.dismissedExpired = true; close(); }
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
    if (dlg.timer) dlg.timer.textContent = clock(Math.min(st.idleEndsAt, st.endsAt) - now());
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
    stop() { clear(handle); off(); close(); document.removeEventListener('visibilitychange', recheck); window.removeEventListener('focus', recheck); },
  };
}
