// nav.js — shared dashboard chrome: loads the signed-in profile (/api/private/me)
// and records it as the session this page acts for (api.js bindSession), shows
// the nav (Drive only when the role allows it, Admin only for the owner), the
// impersonation banner with "Return to admin", log-out, the "session changed"
// banner, and the warning before the session times out (session-timeout.js).
// Every dashboard page awaits `ready`.

import { me, logout, admin, ApiError, bindSession, forgetSession, onSessionChanged, isSessionChanged, isPageSession, endPageSession, SESSION_CHANGED } from '../../js/api.js';
import { toast } from '../../js/ui.js';
import { friendlyError, h } from '../../js/common.js';
import { clearSessionKey, clearImpersonationKeys, purgeStaleSlots } from '../../js/drivekeys.js';
import { watchSession } from './session-timeout.js';

const $ = (s) => document.querySelector(s);

function toLogin(reason) {
  clearSessionKey(); // signed out: forget the tab's Drive keys (docs/DRIVE.md §3)
  location.replace(reason === 'account_disabled' ? '/dashboard/login/?disabled=1' : '/dashboard/login/');
}

export async function loadMe() {
  try {
    return await me();
  } catch (e) {
    if (e instanceof ApiError && (e.status === 401 || e.status === 503 || e.code === 'account_disabled')) { toLogin(e.code); return new Promise(() => {}); }
    throw e;
  }
}

/**
 * The browser is now signed in as someone else (another tab signed in, or
 * started or ended impersonation): this page no longer acts for anyone
 * (api.js). Say so, with a Reload button that loads the page for the current
 * session.
 */
export function showSessionChanged() {
  if (document.getElementById('session-changed')) return;
  const imp = $('#imp-banner');
  if (imp) imp.hidden = true; // it described the page's old session
  const reload = h('button.btn', { type: 'button', id: 'session-reload', text: 'Reload', on: { click: () => location.reload() } });
  document.body.prepend(h('div.imp-banner', { id: 'session-changed', role: 'alert' }, h('span', { text: SESSION_CHANGED }), reload));
  reload.focus();
}
onSessionChanged(showSessionChanged);

/** Whether the signed-in account's role has a Drive: `caps.driveEnabled` (docs/DRIVE.md §5, §8.1). */
export function driveAllowed(profile) {
  return !!(profile && profile.caps && profile.caps.driveEnabled === true);
}

export const ready = (async () => {
  const profile = await loadMe();
  bindSession(profile);
  // A warning before the session times out, with the option to stay signed in (WCAG 2.2.1).
  watchSession(profile.session);
  // Drive keys are never kept in the tab (each page asks the server): remove what a release before left there.
  purgeStaleSlots();
  const nav = $('#dash-nav');
  if (nav) {
    nav.hidden = false;
    const here = location.pathname.replace(/\/+$/, '/');
    for (const a of nav.querySelectorAll('a[data-nav]')) if (new URL(a.href).pathname === here) a.setAttribute('aria-current', 'page');
    const adminLink = $('#nav-admin');
    if (adminLink) adminLink.hidden = !(profile.user.role === 'owner' && !profile.impersonatedBy);
    const driveLink = $('#nav-drive');
    if (driveLink) driveLink.hidden = !driveAllowed(profile);
    // Signing out is a change like any other: it goes through the same token
    // refresh and retry (api.js), so it is refused when the browser is now
    // signed in as someone else (that session is not ended from this page).
    // Whatever the server says about the token, this page stops acting for
    // any session. Other failures (e.g. the network) are shown, and signing
    // out can be tried again.
    $('#nav-logout').onclick = async () => {
      try {
        await logout();
      } catch (e) {
        if (isSessionChanged(e)) return; // the banner (Reload) is up; forgotten already
        if (!(e instanceof ApiError && e.status === 401)) { toast(friendlyError(e), { error: true }); return; }
        // 401: the session had ended already.
      }
      forgetSession();
      toLogin();
    };
  }
  const banner = $('#imp-banner');
  if (banner && profile.impersonatedBy) {
    banner.hidden = false;
    $('#imp-text').textContent = `You (${profile.impersonatedBy}) are acting as ${profile.user.username}.`;
    $('#imp-return').onclick = async () => {
      try {
        await admin.unimpersonate();
        clearImpersonationKeys();
        location.href = '/dashboard/admin/';
      } catch (e) {
        toast(friendlyError(e), { error: true });
      }
    };
  }
  return profile;
})();

// Back-forward cache: a page can come back exactly as it was left, while the
// session may have changed meanwhile: back at the login page if it ended, a
// reload if it is now someone else's (another sign-in, impersonation started
// or ended). A new session of the same user needs nothing here: the page's
// first change is refused for its old token and retried with the new one
// (api.js).
addEventListener('pageshow', async (ev) => {
  if (!ev.persisted) return;
  let was;
  let now;
  try { was = await ready; now = await loadMe(); } catch { return; /* offline: the next request says so */ }
  if (now.user.id !== was.user.id || (now.impersonatedBy ?? null) !== (was.impersonatedBy ?? null)) location.reload();
});

// A tab shown again: if the browser is now signed in as someone else (another
// tab signed in, or started or ended impersonation), this page stops acting for
// anyone at once — the Drive drops its keys (api.js, `secbin:session-changed`)
// — without waiting for its next change. At most one check every few seconds.
let lastCheck = 0;
addEventListener('visibilitychange', async () => {
  if (document.visibilityState !== 'visible' || Date.now() - lastCheck < 5000) return;
  lastCheck = Date.now();
  let now;
  try { await ready; now = await me(); } catch { return; /* offline or signed out: the next request (or the session timeout) says so */ }
  if (!isPageSession(now)) endPageSession();
});
