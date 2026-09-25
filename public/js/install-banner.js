// install-banner.js — the "Install secbin" notification.
//
// Shown on every page, never inside the installed app:
//   • Chromium-family browsers fire `beforeinstallprompt` once the page is
//     installable; we hold the event and offer an Install button that calls
//     its prompt(). "Not now" / the close button dismiss it.
//   • iOS / iPadOS browsers have no install prompt API, so they get a short
//     instruction instead: "Tap Share, then Add to Home Screen".
//   • Hidden when running as an installed app (display-mode: standalone, or
//     iOS's navigator.standalone), after `appinstalled`, and for a year after
//     the user dismisses it — remembered in the first-party cookie
//     `secbin_pwa_dismiss=1` (no identifier, nothing else stored).
//
// Built with createElement/textContent only (no markup parsing), styled from
// public/css/styles.css (".pwa-banner"), so it is CSP- and Trusted-Types-clean.

export const DISMISS_COOKIE = 'secbin_pwa_dismiss';
const DISMISS_MAX_AGE = 31536000; // one year, in seconds
const SVG_NS = 'http://www.w3.org/2000/svg';

/** True when the page runs as an installed app (any platform). */
export function isStandalone(win = globalThis.window) {
  try {
    if (win.navigator && win.navigator.standalone === true) return true;
    if (typeof win.matchMedia === 'function') {
      for (const mode of ['standalone', 'minimal-ui', 'window-controls-overlay']) {
        if (win.matchMedia(`(display-mode: ${mode})`).matches) return true;
      }
    }
  } catch { /* no media queries — assume a browser tab */ }
  return false;
}

/** True when the dismissal cookie is present. */
export function isDismissed(doc = globalThis.document) {
  let jar = '';
  try { jar = String(doc.cookie || ''); } catch { return false; }
  return jar.split(';').some((c) => c.trim() === `${DISMISS_COOKIE}=1`);
}

/** The Set-Cookie-style string that records a dismissal (Secure on https only). */
export function dismissCookie(protocol = globalThis.location?.protocol) {
  const parts = [`${DISMISS_COOKIE}=1`, `Max-Age=${DISMISS_MAX_AGE}`, 'Path=/', 'SameSite=Lax'];
  if (protocol === 'https:') parts.push('Secure');
  return parts.join('; ');
}

export function rememberDismissal(doc = globalThis.document, protocol = globalThis.location?.protocol) {
  try { doc.cookie = dismissCookie(protocol); } catch { /* cookies disabled — hide for this page only */ }
}

/** iPhone / iPod / iPad, including iPadOS, which reports a desktop Mac UA but has touch. */
export function isIos(nav = globalThis.navigator) {
  const ua = String(nav?.userAgent || '');
  if (/\b(iPhone|iPad|iPod)\b/.test(ua)) return true;
  return /\bMacintosh\b/.test(ua) && Number(nav?.maxTouchPoints || 0) > 1;
}

/** Which iOS browser: 'safari' | 'chrome' | 'edge' | 'firefox' | 'other' (all are WebKit). */
export function iosBrowser(nav = globalThis.navigator) {
  const ua = String(nav?.userAgent || '');
  if (/\bCriOS\//.test(ua)) return 'chrome';
  if (/\bEdgiOS\//.test(ua)) return 'edge';
  if (/\bFxiOS\//.test(ua)) return 'firefox';
  if (/\b(OPiOS|OPT|DuckDuckGo|GSA|YaBrowser)\//.test(ua)) return 'other';
  return 'safari';
}

/** iPad (including iPadOS's desktop-class UA), as opposed to iPhone/iPod. */
function isIpad(nav) {
  const ua = String(nav?.userAgent || '');
  return /\biPad\b/.test(ua) || (/\bMacintosh\b/.test(ua) && Number(nav?.maxTouchPoints || 0) > 1);
}

/**
 * Where the floating banner sits: next to the control it talks about.
 *   • iPad (every browser) and Chrome / Edge on iPhone keep Share at the top
 *     of the window → 'top';
 *   • Safari and Firefox on iPhone keep it in the bottom toolbar, and the
 *     Chromium install prompt is a thumb-reach action → 'bottom'.
 */
export function bannerPlacement(nav = globalThis.navigator, mode = 'prompt') {
  if (mode !== 'ios') return 'bottom';
  if (isIpad(nav)) return 'top';
  const b = iosBrowser(nav);
  return b === 'chrome' || b === 'edge' ? 'top' : 'bottom';
}

function el(doc, tag, cls, text) {
  const e = doc.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

function svg(doc, tag, attrs, ...children) {
  const e = doc.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, String(v));
  for (const c of children) e.appendChild(c);
  return e;
}

/** iOS's Share glyph (a box with an up arrow), decorative. */
function shareIcon(doc) {
  return svg(doc, 'svg', { class: 'pwa-share-ico', width: '16', height: '16', viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.6',
    'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false' },
  svg(doc, 'path', { d: 'M12 3v12M8 7l4-4 4 4' }),
  svg(doc, 'path', { d: 'M8 10H6.5A1.5 1.5 0 0 0 5 11.5v8A1.5 1.5 0 0 0 6.5 21h11a1.5 1.5 0 0 0 1.5-1.5v-8A1.5 1.5 0 0 0 17.5 10H16' }));
}

function closeIcon(doc) {
  return svg(doc, 'svg', { class: 'pwa-close-ico', width: '18', height: '18', viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.6',
    'stroke-linecap': 'round', 'aria-hidden': 'true', focusable: 'false' },
  svg(doc, 'path', { d: 'M6 6l12 12M18 6L6 18' }));
}

/**
 * Build the banner element. mode: 'prompt' (Install + Not now) or 'ios'
 * (Add-to-Home-Screen instructions). Both have a close (dismiss) button.
 */
export function buildBanner(doc, { mode, onInstall, onDismiss, nav = globalThis.navigator }) {
  const root = el(doc, 'div', 'pwa-banner');
  root.id = 'pwa-banner';
  root.setAttribute('role', 'region');
  root.setAttribute('aria-label', 'Install secbin');
  root.dataset.mode = mode;
  root.dataset.pos = bannerPlacement(nav, mode);

  const icon = el(doc, 'img', 'pwa-banner-ico');
  icon.setAttribute('src', '/img/icon-192.png');
  icon.setAttribute('alt', '');
  icon.setAttribute('width', '40');
  icon.setAttribute('height', '40');

  const body = el(doc, 'div', 'pwa-banner-body');
  body.appendChild(el(doc, 'p', 'pwa-banner-title', 'Install secbin'));
  const text = el(doc, 'p', 'pwa-banner-text');
  text.id = 'pwa-banner-text';
  if (mode === 'ios') {
    const share = () => [el(doc, 'strong', '', 'Share'), shareIcon(doc)];
    const add = el(doc, 'strong', '', 'Add to Home Screen');
    const b = iosBrowser(nav);
    if (b === 'chrome' || b === 'edge') {
      text.append('Tap ', ...share(), ' in the address bar, then ', add, '.');
    } else if (b === 'safari' && !isIpad(nav)) {
      // iOS 26 moved Share into the "⋯" menu of the compact toolbar.
      text.append('Tap ', ...share(), ' (or ', el(doc, 'strong', '', '⋯'), ' then Share), then ', add, '.');
    } else if (b === 'safari') {
      text.append('Tap ', ...share(), ' at the top, then ', add, '.');
    } else {
      text.append('Open the browser menu, tap ', ...share(), ', then ', add, '.');
    }
  } else {
    text.textContent = 'Add it to your device for quick, full-screen access.';
  }
  body.appendChild(text);
  root.setAttribute('aria-describedby', text.id);

  const close = el(doc, 'button', 'pwa-close');
  close.type = 'button';
  close.setAttribute('aria-label', 'Dismiss install banner');
  close.appendChild(closeIcon(doc));
  close.addEventListener('click', () => onDismiss());

  root.append(icon, body);
  if (mode === 'prompt') {
    const actions = el(doc, 'div', 'pwa-banner-actions');
    const install = el(doc, 'button', 'btn pwa-install', 'Install');
    install.type = 'button';
    install.addEventListener('click', () => onInstall());
    const later = el(doc, 'button', 'btn pwa-later', 'Not now');
    later.type = 'button';
    later.addEventListener('click', () => onDismiss());
    actions.append(install, later);
    root.appendChild(actions);
  }
  root.appendChild(close);
  return root;
}

/**
 * Wire the banner into a page. Returns a small controller (for tests), or
 * null when running as an installed app — then nothing is attached at all.
 */
export function startInstallBanner({ window: win = globalThis.window, document: doc = win?.document, navigator: nav = win?.navigator } = {}) {
  if (!win || !doc || isStandalone(win) || (nav && nav.standalone === true)) return null;

  let deferred = null; // the held beforeinstallprompt event
  let banner = null;

  const hide = () => {
    if (!banner) return;
    banner.remove();
    banner = null;
    doc.documentElement?.classList.remove('pwa-banner-open', 'pwa-banner-top');
  };

  const dismiss = () => {
    rememberDismissal(doc, win.location?.protocol);
    hide();
  };

  const install = async () => {
    const e = deferred;
    deferred = null;
    hide();
    if (!e || typeof e.prompt !== 'function') return;
    try {
      await e.prompt(); // must run inside the click (user activation)
      const choice = await e.userChoice;
      // Declining the browser's own dialog counts as "not now" too.
      if (choice && choice.outcome === 'dismissed') rememberDismissal(doc, win.location?.protocol);
    } catch { /* prompt() already used or unavailable — nothing to do */ }
  };

  const show = (mode) => {
    if (isDismissed(doc) || isStandalone(win)) return;
    hide();
    banner = buildBanner(doc, { mode, onInstall: install, onDismiss: dismiss, nav });
    doc.body.appendChild(banner);
    // Room at the start or end of the page so the floating banner never hides content.
    doc.documentElement?.classList.add('pwa-banner-open');
    doc.documentElement?.classList.toggle('pwa-banner-top', banner.dataset.pos === 'top');
  };

  const onBeforeInstall = (e) => {
    // Hold the event so the browser's own mini-infobar doesn't compete with
    // (or override a dismissal of) this banner; the omnibox install icon stays.
    e.preventDefault();
    deferred = e;
    show('prompt');
  };
  const onInstalled = () => { deferred = null; hide(); };

  win.addEventListener('beforeinstallprompt', onBeforeInstall);
  win.addEventListener('appinstalled', onInstalled);

  let mq = null;
  const onModeChange = (e) => { if (e.matches) hide(); };
  try {
    mq = typeof win.matchMedia === 'function' ? win.matchMedia('(display-mode: standalone)') : null;
    mq?.addEventListener?.('change', onModeChange);
  } catch { mq = null; }

  if (isIos(nav) && !isDismissed(doc)) {
    if (doc.body) show('ios');
    else doc.addEventListener('DOMContentLoaded', () => show('ios'), { once: true });
  }

  return {
    get element() { return banner; },
    show,
    hide,
    destroy() {
      hide();
      win.removeEventListener('beforeinstallprompt', onBeforeInstall);
      win.removeEventListener('appinstalled', onInstalled);
      mq?.removeEventListener?.('change', onModeChange);
    },
  };
}
