// nav.js — shared dashboard chrome: loads the signed-in profile (/api/private/me),
// shows the nav (Admin only for the owner), the impersonation banner with
// "Return to admin", and log-out. Every dashboard page awaits `ready`.

import { me, logout, admin, ApiError } from '../../js/api.js';
import { toast } from '../../js/ui.js';
import { friendlyError } from '../../js/common.js';

const $ = (s) => document.querySelector(s);

function toLogin() {
  location.replace('/dashboard/login/');
}

export async function loadMe() {
  try {
    return await me();
  } catch (e) {
    if (e instanceof ApiError && (e.status === 401 || e.status === 503)) { toLogin(); return new Promise(() => {}); }
    throw e;
  }
}

export const ready = (async () => {
  const profile = await loadMe();
  const nav = $('#dash-nav');
  if (nav) {
    nav.hidden = false;
    const here = location.pathname.replace(/\/+$/, '/');
    for (const a of nav.querySelectorAll('a[data-nav]')) if (new URL(a.href).pathname === here) a.setAttribute('aria-current', 'page');
    const adminLink = $('#nav-admin');
    if (adminLink) adminLink.hidden = !(profile.user.role === 'owner' && !profile.impersonatedBy);
    $('#nav-logout').onclick = async () => {
      try { await logout(); } catch { /* the cookie is cleared regardless */ }
      toLogin();
    };
  }
  const banner = $('#imp-banner');
  if (banner && profile.impersonatedBy) {
    banner.hidden = false;
    $('#imp-text').textContent = `You (${profile.impersonatedBy}) are acting as ${profile.user.username}. Everything you do here is recorded in the audit log.`;
    $('#imp-return').onclick = async () => {
      try {
        await admin.unimpersonate();
        location.href = '/dashboard/admin/';
      } catch (e) {
        toast(friendlyError(e));
      }
    };
  }
  return profile;
})();
