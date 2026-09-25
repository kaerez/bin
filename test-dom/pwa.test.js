// pwa.test.js — the install banner (public/js/install-banner.js) and the PWA
// wiring of every page, under happy-dom:
//   • hidden in the installed app (display-mode: standalone / navigator.standalone);
//   • hidden once the secbin_pwa_dismiss cookie is set; dismissing sets it
//     (Secure only on https) and removes the banner;
//   • Chromium path: beforeinstallprompt → banner → Install calls prompt();
//   • iOS path (iPhone, and iPadOS's desktop UA + touch): Share → Add to Home
//     Screen instructions; appinstalled hides the banner;
//   • DOM-only construction (no inline handlers / styles / markup parsing);
//   • static checks: manifest fields + icon sizes, every page links the
//     manifest and loads /js/pwa.js.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  DISMISS_COOKIE, isStandalone, isDismissed, dismissCookie, isIos, iosBrowser, bannerPlacement, startInstallBanner, buildBanner,
} from '../public/js/install-banner.js';

const root = process.cwd();
const read = (p) => readFileSync(join(root, p), 'utf8');

const CHROME_UA = 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36';
const IPHONE_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1';
const IPHONE_CHROME_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/140.0.0.0 Mobile/15E148 Safari/604.1';
const IPHONE_FIREFOX_UA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/140.0 Mobile/15E148 Safari/605.1.15';
const IPADOS_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15';

/** A window stand-in: real events + document, controllable display-mode and navigator. */
function fakeWindow({ standalone = false, navigator = { userAgent: CHROME_UA, maxTouchPoints: 0 }, protocol = 'http:' } = {}) {
  const win = new EventTarget();
  const listeners = new Set();
  win.document = document;
  win.navigator = navigator;
  win.location = { protocol };
  win.matchMedia = (q) => ({
    matches: standalone && q === '(display-mode: standalone)',
    media: q,
    addEventListener: (_t, fn) => listeners.add(fn),
    removeEventListener: (_t, fn) => listeners.delete(fn),
  });
  win.setStandalone = (v) => { standalone = v; for (const fn of listeners) fn({ matches: v }); };
  return win;
}

/** A synthetic beforeinstallprompt with a recordable prompt(). */
function bipEvent(outcome = 'accepted') {
  const e = new Event('beforeinstallprompt', { cancelable: true });
  e.prompt = vi.fn(async () => {});
  e.userChoice = Promise.resolve({ outcome, platform: 'web' });
  return e;
}

const banner = () => document.getElementById('pwa-banner');
const clearCookie = () => { document.cookie = `${DISMISS_COOKIE}=; Max-Age=0; Path=/`; };

let ctl = null;
beforeEach(() => { clearCookie(); document.body.replaceChildren(); });
afterEach(() => { ctl?.destroy(); ctl = null; clearCookie(); });

describe('install banner — visibility rules', () => {
  it('detects the installed app', () => {
    expect(isStandalone(fakeWindow())).toBe(false);
    expect(isStandalone(fakeWindow({ standalone: true }))).toBe(true);
    expect(isStandalone(fakeWindow({ navigator: { userAgent: IPHONE_UA, standalone: true } }))).toBe(true);
  });

  it('attaches nothing in display-mode: standalone', () => {
    const win = fakeWindow({ standalone: true });
    ctl = startInstallBanner({ window: win });
    expect(ctl).toBeNull();
    const e = bipEvent();
    win.dispatchEvent(e);
    expect(e.defaultPrevented).toBe(false);
    expect(banner()).toBeNull();
  });

  it('attaches nothing in an iOS home-screen app (navigator.standalone)', () => {
    const win = fakeWindow({ navigator: { userAgent: IPHONE_UA, maxTouchPoints: 5, standalone: true } });
    ctl = startInstallBanner({ window: win });
    expect(ctl).toBeNull();
    expect(banner()).toBeNull();
  });

  it('stays hidden when the dismissal cookie is set', () => {
    document.cookie = `${DISMISS_COOKIE}=1; Path=/`;
    expect(isDismissed(document)).toBe(true);
    const win = fakeWindow();
    ctl = startInstallBanner({ window: win });
    win.dispatchEvent(bipEvent());
    expect(banner()).toBeNull();
  });

  it('ignores look-alike cookies', () => {
    document.cookie = `x${DISMISS_COOKIE}=1; Path=/`;
    document.cookie = `${DISMISS_COOKIE}x=1; Path=/`;
    expect(isDismissed(document)).toBe(false);
    document.cookie = `x${DISMISS_COOKIE}=; Max-Age=0; Path=/`;
    document.cookie = `${DISMISS_COOKIE}x=; Max-Age=0; Path=/`;
  });

  it('shows nothing on a desktop/Android browser until beforeinstallprompt', () => {
    const win = fakeWindow();
    ctl = startInstallBanner({ window: win });
    expect(banner()).toBeNull();
  });
});

describe('install banner — Chromium prompt path', () => {
  it('shows an accessible banner on beforeinstallprompt and holds the event', () => {
    const win = fakeWindow();
    ctl = startInstallBanner({ window: win });
    const e = bipEvent();
    win.dispatchEvent(e);
    expect(e.defaultPrevented).toBe(true);
    const b = banner();
    expect(b).not.toBeNull();
    expect(b.getAttribute('role')).toBe('region');
    expect(b.getAttribute('aria-label')).toBe('Install secbin');
    expect(b.dataset.mode).toBe('prompt');
    const buttons = [...b.querySelectorAll('button')];
    expect(buttons.map((x) => x.textContent.trim() || x.getAttribute('aria-label'))).toEqual(['Install', 'Not now', 'Dismiss install banner']);
    for (const x of buttons) expect(x.getAttribute('type')).toBe('button');
    expect(document.documentElement.classList.contains('pwa-banner-open')).toBe(true);
  });

  it('Install calls prompt() and hides the banner; a declined dialog is remembered', async () => {
    const win = fakeWindow();
    ctl = startInstallBanner({ window: win });
    const e = bipEvent('dismissed');
    win.dispatchEvent(e);
    banner().querySelector('.pwa-install').click();
    expect(e.prompt).toHaveBeenCalledTimes(1);
    expect(banner()).toBeNull();
    await e.userChoice;
    await new Promise((r) => setTimeout(r, 0));
    expect(isDismissed(document)).toBe(true);
  });

  it('an accepted install does not set the dismissal cookie', async () => {
    const win = fakeWindow();
    ctl = startInstallBanner({ window: win });
    const e = bipEvent('accepted');
    win.dispatchEvent(e);
    banner().querySelector('.pwa-install').click();
    await e.userChoice;
    await new Promise((r) => setTimeout(r, 0));
    expect(isDismissed(document)).toBe(false);
  });

  for (const which of ['.pwa-later', '.pwa-close']) {
    it(`${which === '.pwa-later' ? 'Not now' : 'the close button'} dismisses and sets the cookie`, () => {
      const win = fakeWindow();
      ctl = startInstallBanner({ window: win });
      win.dispatchEvent(bipEvent());
      banner().querySelector(which).click();
      expect(banner()).toBeNull();
      expect(document.documentElement.classList.contains('pwa-banner-open')).toBe(false);
      expect(isDismissed(document)).toBe(true);
      // A later prompt (e.g. next navigation) stays hidden.
      win.dispatchEvent(bipEvent());
      expect(banner()).toBeNull();
    });
  }

  it('appinstalled and a switch to standalone hide the banner', () => {
    const win = fakeWindow();
    ctl = startInstallBanner({ window: win });
    win.dispatchEvent(bipEvent());
    win.dispatchEvent(new Event('appinstalled'));
    expect(banner()).toBeNull();
    win.dispatchEvent(bipEvent());
    expect(banner()).not.toBeNull();
    win.setStandalone(true);
    expect(banner()).toBeNull();
  });
});

describe('install banner — dismissal cookie', () => {
  it('is a year-long, site-wide, Lax cookie; Secure only on https', () => {
    expect(dismissCookie('https:')).toBe(`${DISMISS_COOKIE}=1; Max-Age=31536000; Path=/; SameSite=Lax; Secure`);
    expect(dismissCookie('http:')).toBe(`${DISMISS_COOKIE}=1; Max-Age=31536000; Path=/; SameSite=Lax`);
  });

  it('writes the https form when the page is https', () => {
    const doc = { cookie: '', body: document.body, createElement: document.createElement.bind(document), createElementNS: document.createElementNS.bind(document), addEventListener() {} };
    const win = fakeWindow({ protocol: 'https:' });
    win.document = doc;
    ctl = startInstallBanner({ window: win, document: doc });
    win.dispatchEvent(bipEvent());
    banner().querySelector('.pwa-close').click();
    expect(doc.cookie).toBe(dismissCookie('https:'));
  });
});

describe('install banner — iOS instructions path', () => {
  it('recognises iPhone, iPad and iPadOS (Mac UA + touch), not desktop Safari', () => {
    expect(isIos({ userAgent: IPHONE_UA, maxTouchPoints: 5 })).toBe(true);
    expect(isIos({ userAgent: IPHONE_UA.replace('iPhone; CPU iPhone OS', 'iPad; CPU OS'), maxTouchPoints: 5 })).toBe(true);
    expect(isIos({ userAgent: IPADOS_UA, maxTouchPoints: 5 })).toBe(true);
    expect(isIos({ userAgent: IPADOS_UA, maxTouchPoints: 0 })).toBe(false);
    expect(isIos({ userAgent: CHROME_UA, maxTouchPoints: 5 })).toBe(false);
  });

  it('shows Add-to-Home-Screen instructions immediately, with only a dismiss button', () => {
    const win = fakeWindow({ navigator: { userAgent: IPADOS_UA, maxTouchPoints: 5 } });
    ctl = startInstallBanner({ window: win });
    const b = banner();
    expect(b).not.toBeNull();
    expect(b.dataset.mode).toBe('ios');
    expect(b.dataset.pos).toBe('top'); // iPad: Share is in the top toolbar
    expect(b.querySelector('.pwa-banner-text').textContent).toBe('Tap Share at the top, then Add to Home Screen.');
    expect(b.querySelector('.pwa-install')).toBeNull();
    expect([...b.querySelectorAll('button')].map((x) => x.getAttribute('aria-label'))).toEqual(['Dismiss install banner']);
    b.querySelector('.pwa-close').click();
    expect(banner()).toBeNull();
    expect(isDismissed(document)).toBe(true);
  });

  it('names the right control and sits next to it, per browser', () => {
    const cases = [
      [IPHONE_UA, 'safari', 'bottom', 'Tap Share (or ⋯ then Share), then Add to Home Screen.'],
      [IPHONE_CHROME_UA, 'chrome', 'top', 'Tap Share in the address bar, then Add to Home Screen.'],
      [IPHONE_FIREFOX_UA, 'firefox', 'bottom', 'Open the browser menu, tap Share, then Add to Home Screen.'],
    ];
    for (const [userAgent, browser, pos, text] of cases) {
      const nav = { userAgent, maxTouchPoints: 5 };
      expect(iosBrowser(nav)).toBe(browser);
      expect(bannerPlacement(nav, 'ios')).toBe(pos);
      const b = buildBanner(document, { mode: 'ios', nav, onInstall() {}, onDismiss() {} });
      expect(b.dataset.pos, userAgent).toBe(pos);
      expect(b.querySelector('.pwa-banner-text').textContent, userAgent).toBe(text);
    }
    // The Chromium install prompt is a bottom sheet everywhere.
    expect(bannerPlacement({ userAgent: CHROME_UA, maxTouchPoints: 5 }, 'prompt')).toBe('bottom');
  });

  it('marks the page for top placement so content is padded at the top, and clears it on dismiss', () => {
    ctl = startInstallBanner({ window: fakeWindow({ navigator: { userAgent: IPHONE_CHROME_UA, maxTouchPoints: 5 } }) });
    expect(document.documentElement.classList.contains('pwa-banner-top')).toBe(true);
    banner().querySelector('.pwa-close').click();
    expect(document.documentElement.classList.contains('pwa-banner-top')).toBe(false);
    expect(document.documentElement.classList.contains('pwa-banner-open')).toBe(false);
  });

  it('gives every icon an intrinsic size, so it stays small even without the stylesheet', () => {
    const b = buildBanner(document, { mode: 'ios', nav: { userAgent: IPHONE_UA, maxTouchPoints: 5 }, onInstall() {}, onDismiss() {} });
    for (const svg of b.querySelectorAll('svg')) {
      expect(Number(svg.getAttribute('width'))).toBeLessThanOrEqual(24);
      expect(Number(svg.getAttribute('height'))).toBeLessThanOrEqual(24);
    }
    expect(b.querySelector('img').getAttribute('width')).toBe('40');
  });

  it('respects a previous dismissal on iOS', () => {
    document.cookie = `${DISMISS_COOKIE}=1; Path=/`;
    ctl = startInstallBanner({ window: fakeWindow({ navigator: { userAgent: IPHONE_UA, maxTouchPoints: 5 } }) });
    expect(banner()).toBeNull();
  });
});

describe('install banner — DOM safety', () => {
  it('builds inert DOM: no inline handlers or styles, decorative SVGs hidden', () => {
    for (const mode of ['prompt', 'ios']) {
      const b = buildBanner(document, { mode, onInstall() {}, onDismiss() {} });
      for (const n of [b, ...b.querySelectorAll('*')]) {
        for (const a of n.getAttributeNames()) {
          expect(a.startsWith('on')).toBe(false);
          expect(a).not.toBe('style');
        }
      }
      for (const s of b.querySelectorAll('svg')) expect(s.getAttribute('aria-hidden')).toBe('true');
      expect(b.querySelector('img').getAttribute('alt')).toBe('');
    }
  });

  it('the banner modules never parse markup', () => {
    for (const f of ['public/js/install-banner.js', 'public/js/pwa.js']) {
      const src = read(f).replace(/^\s*\/\/.*$/gm, '');
      expect(src).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
    }
  });

  it('pwa.js registers the worker through the Trusted Types policy', () => {
    const src = read('public/js/pwa.js');
    expect(src).toMatch(/import \{ scriptURL \} from '\.\/tt\.js'/);
    expect(src).toMatch(/register\(scriptURL\('\/sw\.js'\), \{ scope: '\/'/);
  });
});

// ── static wiring ────────────────────────────────────────────────────────────

function pages(dir = 'public') {
  const out = [];
  for (const name of readdirSync(join(root, dir))) {
    const p = `${dir}/${name}`;
    if (statSync(join(root, p)).isDirectory()) { if (name !== 'js' && name !== 'vendor') out.push(...pages(p)); } else if (name === 'index.html') out.push(p);
  }
  return out;
}

function pngSize(path) {
  const b = readFileSync(join(root, path));
  expect(b.subarray(0, 8).toString('hex')).toBe('89504e470d0a1a0a');
  return [b.readUInt32BE(16), b.readUInt32BE(20)];
}

describe('PWA wiring', () => {
  it('the manifest is complete and matches the dark theme tokens', () => {
    const m = JSON.parse(read('public/manifest.webmanifest'));
    expect(m.name).toBe('secbin');
    expect(m.short_name).toBeTruthy();
    expect(m.start_url).toBe('/');
    expect(m.scope).toBe('/');
    expect(m.display).toBe('standalone');
    const css = read('public/css/styles.css');
    const paper = /html\.dark \{[^}]*--paper: (#[0-9a-f]{6})/.exec(css)[1];
    expect(m.theme_color).toBe(paper);
    expect(m.background_color).toBe(paper);
    const icons = Object.fromEntries(m.icons.map((i) => [`${i.sizes}:${i.purpose}`, i]));
    expect(Object.keys(icons).sort()).toEqual(['192x192:any', '512x512:any', '512x512:maskable']);
    for (const i of m.icons) {
      expect(i.type).toBe('image/png');
      const [w, h] = pngSize(`public${i.src}`);
      expect(`${w}x${h}`).toBe(i.sizes);
    }
  });

  it('every page links the manifest, the touch icon and theme color, and loads pwa.js', () => {
    const list = pages();
    expect(list.length).toBeGreaterThanOrEqual(7);
    for (const p of list) {
      const html = read(p);
      expect(html, p).toContain('<link rel="manifest" href="/manifest.webmanifest" />');
      expect(html, p).toContain('<link rel="apple-touch-icon" href="/img/apple-touch-icon.png" />');
      expect(html, p).toMatch(/<meta name="theme-color" content="#[0-9a-f]{6}" \/>/);
      expect(html, p).toContain('<script type="module" src="/js/pwa.js"></script>');
    }
  });
});
