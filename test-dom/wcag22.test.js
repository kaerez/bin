// wcag22.test.js (DOM) — the WCAG 2.2 audit's fixes (docs/WCAG22.md):
//   2.2.1 / 2.2.6  the warning before a session times out, with "Stay signed in";
//   2.2.2          the "Stop the countdown" switch;
//   2.4.11 / 12    fixed (and the sticky impersonation banner) never cover the focused control;
//   2.4.2          the title names the view; focus the person placed stays;
//   3.2.5          links that open a new tab say so;
//   3.3.2 / 2.5.3  every credential field on the static pages has a visible
//                  label that is its accessible name, and an autocomplete token (1.3.5);
//   3.3.8          the human check's note offers the contact (and a page's alternative);
//   1.4.3 / 1.4.6 / 1.4.11  every text colour ≥7:1 and field boundaries ≥3:1, both themes.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(import.meta.dirname, '..');
const pub = (p) => readFileSync(join(ROOT, 'public', p), 'utf8');
// A page's body, parsed, with its scripts and links removed (the head's stylesheet
// and scripts are not needed; the checks here read the body only).
const page = (p) => {
  const html = pub(p);
  const body = html.slice(html.indexOf('<body'), html.indexOf('</body>') + '</body>'.length);
  const doc = new DOMParser().parseFromString(`<!doctype html><html>${body}</html>`, 'text/html');
  for (const el of doc.querySelectorAll('script, link')) el.remove();
  return doc;
};

// ── api.js stand-in: me() / logout() and the activity hook ──────────────────
const api = vi.hoisted(() => ({ me: null, activity: new Set(), logouts: 0, config: { turnstile: null }, changed: 0 }));
vi.mock('../public/js/api.js', () => {
  class ApiError extends Error { constructor(m, status) { super(m); this.status = status; } }
  return {
    ApiError,
    me: async () => api.me(),
    logout: async () => { api.logouts += 1; },
    onPrivateActivity: (fn) => { api.activity.add(fn); return () => api.activity.delete(fn); },
    fetchConfig: async () => api.config,
    // The page acts for user u1 (a profile without a user is taken as u1).
    isPageSession: (p) => !!p && (p.user ? p.user.id : 'u1') === 'u1',
    endPageSession: () => { api.changed += 1; },
  };
});

const { watchSession, WARN_SEC } = await import('../public/dashboard/js/session-timeout.js');
const { countdownSwitch, showView } = await import('../public/js/ui.js');
globalThis.__SECBIN_A11Y_NO_AUTOMOUNT = true;
const { unobscure } = await import('../public/js/a11y.js');
const { humanCheck } = await import('../public/js/turnstile.js');
const { renderMarkdown } = await import('../public/js/markdown.js');

beforeEach(() => { document.body.replaceChildren(); document.documentElement.className = ''; });

// ── 2.2.1 / 2.2.6: session timeouts ──────────────────────────────────────────
describe('watchSession — a warning before the session ends', () => {
  let t;
  let ticks;
  let w;
  const start = (session) => {
    ticks = [];
    w = watchSession(session, { now: () => t, every: (fn) => { ticks.push(fn); return 1; }, clear: () => {} });
    return w;
  };
  const at = (sec) => { t = sec * 1000; for (const fn of ticks) fn(); };
  const dialog = () => document.querySelector('[role="alertdialog"]');
  afterEach(() => w && w.stop());

  it('warns WARN_SEC before the idle end, focused on "Stay signed in"; staying extends it', async () => {
    t = 0;
    document.body.appendChild(Object.assign(document.createElement('button'), { id: 'work', textContent: 'work' }));
    document.getElementById('work').focus();
    start({ idleSec: 600, idleEndsAt: 600, endsAt: 86400, slideSec: 60 });
    at(600 - WARN_SEC - 1);
    expect(dialog()).toBeNull();
    at(600 - WARN_SEC + 1);
    const d = dialog();
    expect(d).not.toBeNull();
    expect(d.getAttribute('aria-modal')).toBe('true');
    expect(document.getElementById(d.getAttribute('aria-labelledby')).textContent).toMatch(/still there/i);
    expect(document.getElementById(d.getAttribute('aria-describedby')).textContent).toMatch(/10 minutes without activity/);
    expect(document.activeElement.textContent).toBe('Stay signed in');
    // The rest of the page is inert while it is open.
    expect(document.getElementById('work').inert).toBe(true);
    api.me = async () => ({ session: { idleSec: 600, idleEndsAt: 1100, endsAt: 86400 } });
    document.activeElement.click();
    await vi.waitFor(() => expect(dialog()).toBeNull());
    expect(document.activeElement.id).toBe('work'); // focus back where it was
    expect(document.getElementById('work').inert).toBe(false);
    expect(w.state.idleEndsAt).toBe(1100 * 1000);
  });

  it('can be extended again and again (Escape stays signed in too)', async () => {
    t = 0;
    start({ idleSec: 300, idleEndsAt: 300, endsAt: 86400, slideSec: 60 });
    let end = 300;
    for (let i = 0; i < 12; i++) {
      at(end - 30);
      expect(dialog(), `round ${i}`).not.toBeNull();
      end += 300;
      const next = end;
      api.me = async () => ({ session: { idleSec: 300, idleEndsAt: next, endsAt: 86400 } });
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
      window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
      await vi.waitFor(() => expect(dialog()).toBeNull());
    }
  });

  it('activity (any signed-in request) moves the end without a dialog', () => {
    t = 0;
    start({ idleSec: 600, idleEndsAt: 600, endsAt: 86400, slideSec: 60 });
    at(400);
    for (const fn of api.activity) fn('/api/private/shares');
    at(600 - WARN_SEC + 5);
    expect(dialog()).toBeNull();
    expect(w.state.idleEndsAt).toBe((400 + 600 - 60) * 1000);
  });

  it('the absolute end cannot be extended: it only says when', () => {
    t = 0;
    start({ idleSec: 3600, idleEndsAt: 1000, endsAt: 1000, slideSec: 60 });
    at(1000 - 60);
    expect(dialog().textContent).toMatch(/maximum length/);
    expect([...dialog().querySelectorAll('button')].map((b) => b.textContent)).toEqual(['OK']);
  });

  it('when time is up, it says so and offers to sign in in a new tab: nothing navigates on its own', () => {
    t = 0;
    const href = location.href;
    start({ idleSec: 600, idleEndsAt: 600, endsAt: 86400, slideSec: 60 });
    at(601);
    const d = dialog();
    expect(d.textContent).toMatch(/signed out/);
    const a = d.querySelector('a');
    expect(a.getAttribute('target')).toBe('_blank');
    expect(a.textContent).toMatch(/opens in a new tab/);
    expect(location.href).toBe(href);
    // Its other way on is "Log out"; Escape does not put it away (the page behind it is locked).
    expect([...d.querySelectorAll('button')].map((x) => x.textContent)).toEqual(['Log out']);
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    at(700);
    expect(dialog()).not.toBeNull();
  });

  // Security audit F6 (PCI DSS 8.2.8): once the session has ended, nothing on the page stays usable
  // or readable until the same user signs in again; what was typed stays (hidden), passwords do not.
  const page = () => {
    const main = document.body.appendChild(Object.assign(document.createElement('main'), { id: 'main' }));
    const note = main.appendChild(Object.assign(document.createElement('textarea'), { id: 'note', value: 'my draft' }));
    const pw = main.appendChild(Object.assign(document.createElement('input'), { id: 'pw', type: 'password', value: 'secret-pw' }));
    const toastEl = document.body.appendChild(Object.assign(document.createElement('div'), { id: 'toast', className: 'show', textContent: 'Moved “salaries.xlsx”' }));
    return { main, note, pw, toastEl };
  };
  it('when time is up the page locks: hidden and inert, the tab\'s Drive keys cleared, passwords emptied, the toast put away; the Drive is told', async () => {
    const { saveSessionKey, loadSessionKey, saveImpersonationKey, loadImpersonationKey } = await import('../public/js/drivekeys.js');
    saveSessionKey(new Uint8Array(32).fill(7), 'u1');
    saveImpersonationKey(new Uint8Array(32).fill(8), 'u2');
    const { main, note, pw, toastEl } = page();
    let told = 0;
    const onEnded = () => { told += 1; };
    window.addEventListener('secbin:session-ended', onEnded);
    t = 0;
    start({ idleSec: 600, idleEndsAt: 600, endsAt: 86400, slideSec: 60 });
    at(601);
    window.removeEventListener('secbin:session-ended', onEnded);
    expect(told).toBe(1);
    expect(main.inert).toBe(true);
    expect(main.classList.contains('session-locked')).toBe(true);
    expect(loadSessionKey('u1')).toBeNull();
    expect(loadImpersonationKey('u2')).toBeNull();
    expect(pw.value).toBe('');
    expect(note.value).toBe('my draft'); // what was typed is kept, hidden
    expect(toastEl.classList.contains('show')).toBe(false);
    expect(toastEl.textContent).toBe('');
    expect(dialog().closest('.session-locked')).toBeNull();
  });

  it('back in the tab, signed in again as the same user: the page unlocks and carries on', async () => {
    const { main, note } = page();
    t = 0;
    start({ idleSec: 600, idleEndsAt: 600, endsAt: 86400, slideSec: 60 });
    at(601);
    api.me = async () => ({ user: { id: 'u1' }, session: { idleSec: 600, idleEndsAt: 2000, endsAt: 90000 } });
    window.dispatchEvent(new Event('focus'));
    await vi.waitFor(() => expect(dialog()).toBeNull());
    expect(main.inert).toBe(false);
    expect(main.classList.contains('session-locked')).toBe(false);
    expect(note.value).toBe('my draft');
    expect(w.state.expired).toBe(false);
  });

  // Security audit F5: another account signed in in the new tab never takes over this page.
  it('back in the tab, signed in as someone else: the page stays locked and says the session changed; nothing is adopted', async () => {
    const { main } = page();
    t = 0;
    api.changed = 0;
    start({ idleSec: 600, idleEndsAt: 600, endsAt: 86400, slideSec: 60 });
    at(601);
    api.me = async () => ({ user: { id: 'u2' }, session: { idleSec: 600, idleEndsAt: 5000, endsAt: 90000 } });
    window.dispatchEvent(new Event('focus'));
    await vi.waitFor(() => expect(api.changed).toBe(1));
    expect(dialog()).toBeNull(); // the "session changed" banner (nav.js) takes over
    expect(main.inert).toBe(true);
    expect(main.classList.contains('session-locked')).toBe(true);
    expect(w.state.idleEndsAt).toBe(600 * 1000); // not the other session's times
    at(5000);
    expect(dialog()).toBeNull(); // nothing more is watched
  });

  it('"Stay signed in" while someone else has signed in: the page locks and says the session changed', async () => {
    const { main } = page();
    t = 0;
    api.changed = 0;
    start({ idleSec: 600, idleEndsAt: 600, endsAt: 86400, slideSec: 60 });
    at(600 - WARN_SEC + 1);
    api.me = async () => ({ user: { id: 'u2' }, session: { idleSec: 600, idleEndsAt: 5000, endsAt: 90000 } });
    dialog().querySelector('.send').click();
    await vi.waitFor(() => expect(api.changed).toBe(1));
    expect(main.classList.contains('session-locked')).toBe(true);
    expect(w.state.idleEndsAt).toBe(600 * 1000);
  });

  // Security audit F4: the warning goes by the server's clock (the session's `now`), not this browser's.
  it('with this browser\'s clock 5 minutes behind the server\'s, the warning still comes WARN_SEC before the end', () => {
    t = -300 * 1000; // the browser says 5 minutes earlier than the server (whose now is 0)
    start({ idleSec: 600, idleEndsAt: 600, endsAt: 86400, slideSec: 60, now: 0 });
    at(600 - WARN_SEC - 300 - 1); // server time 600 - WARN_SEC - 1
    expect(dialog()).toBeNull();
    at(600 - WARN_SEC - 300 + 1); // server time 600 - WARN_SEC + 1
    expect(dialog()).not.toBeNull();
    expect(dialog().textContent).toMatch(/still there/i);
    at(601 - 300); // server time 601: signed out, not five minutes later
    expect(dialog().textContent).toMatch(/signed out/);
  });
});

// ── 2.2.2: stop a countdown ──────────────────────────────────────────────────
describe('countdownSwitch', () => {
  it('toggles aria-pressed and reports the state', () => {
    const seen = [];
    const s = countdownSwitch((stopped) => seen.push(stopped));
    expect(s.el.getAttribute('aria-pressed')).toBe('false');
    s.el.click();
    expect(s.el.getAttribute('aria-pressed')).toBe('true');
    expect(s.stopped()).toBe(true);
    s.el.click();
    expect(seen).toEqual([true, false]);
  });
  it('starts stopped when "Stop animations" is on', () => {
    document.documentElement.classList.add('a11y-no-anim');
    expect(countdownSwitch(() => {}).stopped()).toBe(true);
  });
});

// ── 2.4.11 / 2.4.12: focus not obscured ──────────────────────────────────────
describe('unobscure', () => {
  const box = (el, r) => { el.getBoundingClientRect = () => ({ ...r, width: r.right - r.left, height: r.bottom - r.top }); };
  it('scrolls a control out from under the fixed accessibility button', () => {
    Object.defineProperty(window, 'innerHeight', { value: 600, configurable: true });
    const btn = Object.assign(document.createElement('button'), { id: 'a11y-btn' });
    const field = document.createElement('input');
    document.body.append(btn, field);
    box(btn, { left: 16, right: 60, top: 540, bottom: 584 });
    box(field, { left: 20, right: 300, top: 550, bottom: 590 });
    const spy = vi.spyOn(window, 'scrollBy').mockImplementation(() => {});
    expect(unobscure(field)).toBe(590 - (540 - 8));
    expect(spy).toHaveBeenCalledWith(expect.objectContaining({ top: 590 - 532 }));
    // Beside it (no horizontal overlap): nothing to do.
    box(field, { left: 100, right: 300, top: 550, bottom: 590 });
    expect(unobscure(field)).toBe(0);
    spy.mockRestore();
  });
  it('scrolls a control out from under the impersonation banner (sticky at the top)', () => {
    Object.defineProperty(window, 'innerHeight', { value: 256, configurable: true });
    const banner = Object.assign(document.createElement('div'), { id: 'imp-banner', className: 'imp-banner' });
    const ret = document.createElement('button');
    banner.append(ret);
    const theme = document.createElement('button');
    document.body.append(banner, theme);
    box(banner, { left: 0, right: 320, top: 0, bottom: 90 });
    box(ret, { left: 100, right: 220, top: 40, bottom: 84 });
    box(theme, { left: 260, right: 304, top: 30, bottom: 74 }); // under the banner
    const spy = vi.spyOn(window, 'scrollBy').mockImplementation(() => {});
    expect(unobscure(theme)).toBe(30 - (90 + 8));
    // The banner's own button is never scrolled away from it.
    expect(unobscure(ret)).toBe(0);
    // Hidden (not acting as a user): nothing to do.
    banner.hidden = true;
    expect(unobscure(theme)).toBe(0);
    spy.mockRestore();
  });
  it('moves the toast to the top instead of scrolling', () => {
    const toast = Object.assign(document.createElement('div'), { id: 'toast', className: 'show' });
    const b = document.createElement('button');
    document.body.append(toast, b);
    box(toast, { left: 100, right: 400, top: 500, bottom: 540 });
    box(b, { left: 150, right: 250, top: 510, bottom: 530 });
    unobscure(b);
    expect(toast.classList.contains('toast-top')).toBe(true);
  });
  it('moves a toast at the top back to the bottom when focus goes under it, and puts it away when it covers focus at both edges', () => {
    Object.defineProperty(window, 'innerHeight', { value: 256, configurable: true });
    const toast = Object.assign(document.createElement('div'), { id: 'toast', className: 'show toast-top' });
    const b = document.createElement('button');
    document.body.append(toast, b);
    // Where the toast is depends on its class, as the CSS places it.
    toast.getBoundingClientRect = () => (toast.classList.contains('toast-top')
      ? { left: 20, right: 300, top: 16, bottom: 59, width: 280, height: 43 }
      : { left: 20, right: 300, top: 181, bottom: 224, width: 280, height: 43 });
    box(b, { left: 130, right: 240, top: 30, bottom: 74 }); // under the top toast
    const spy = vi.spyOn(window, 'scrollBy').mockImplementation(() => {});
    unobscure(b);
    expect(toast.classList.contains('toast-top')).toBe(false);
    expect(toast.classList.contains('show')).toBe(true);
    // A control that the toast covers at the bottom and at the top (a very short screen): it goes.
    box(b, { left: 130, right: 240, top: 20, bottom: 230 });
    unobscure(b);
    expect(toast.classList.contains('show')).toBe(false);
    spy.mockRestore();
  });
});

// ── 2.4.2 / 2.4.3: showView keeps the person's focus and names the view ──────
// Security audit F8: a toast may name decrypted items; it keeps no time limit (2.2.1) but goes,
// its text too, on the next key press or click, when the page is left and when its history moves.
describe('toast', () => {
  it('is put away with its text on the next click, on pagehide, popstate and hashchange', async () => {
    const { toast, dismissToast } = await import('../public/js/ui.js');
    const el = document.body.appendChild(Object.assign(document.createElement('div'), { id: 'toast' }));
    for (const ev of ['pagehide', 'popstate', 'hashchange']) {
      toast('Moved “salaries.xlsx”.');
      expect(el.classList.contains('show')).toBe(true);
      window.dispatchEvent(new Event(ev));
      expect(el.classList.contains('show'), ev).toBe(false);
      expect(el.textContent, ev).toBe('');
    }
    vi.useFakeTimers({ toFake: ['Date'] });
    try {
      toast('Saved as “plan.pdf”.');
      vi.setSystemTime(Date.now() + 2000); // past the grace for the key that caused it
      document.body.dispatchEvent(new MouseEvent('click', { bubbles: true }));
      expect(el.classList.contains('show')).toBe(false);
      expect(el.textContent).toBe('');
    } finally { vi.useRealTimers(); }
    toast('x');
    dismissToast();
    expect(el.textContent).toBe('');
  });
});

describe('showView', () => {
  it('leaves focus the person placed outside the views, and titles the page from data-title', () => {
    document.title = 'secbin · zero-knowledge sharing';
    const header = document.createElement('button');
    const main = document.createElement('main');
    for (const [id, title] of [['view-a', 'First view'], ['view-b', '']]) {
      const s = document.createElement('section');
      s.id = id; s.tabIndex = -1; s.hidden = true;
      if (title) s.dataset.title = title;
      main.appendChild(s);
    }
    document.body.append(header, main);
    header.focus();
    showView('a');
    expect(document.activeElement).toBe(header);
    expect(document.title).toBe('First view · secbin');
    showView('b');
    expect(document.title).toBe('secbin · zero-knowledge sharing');
  });
});

// ── 3.2.5: new tabs are announced ────────────────────────────────────────────
describe('links that open a new tab say so', () => {
  it('in shared Markdown', () => {
    const div = document.createElement('div');
    renderMarkdown(div, 'see [the docs](https://example.com)');
    const a = div.querySelector('a');
    expect(a.getAttribute('target')).toBe('_blank');
    expect(a.querySelector('.sr-only').textContent).toBe(' (opens in a new tab)');
  });
  it('in every page footer, which is the same on every page (3.2.3, 3.2.6)', () => {
    const pages = ['index.html', 'accessibility/index.html', 'r/index.html', 'check/index.html', 'dashboard/index.html',
      ...readdirSync(join(ROOT, 'public/dashboard'), { withFileTypes: true }).filter((d) => d.isDirectory() && existsSync(join(ROOT, 'public/dashboard', d.name, 'index.html'))).map((d) => `dashboard/${d.name}/index.html`)];
    const foots = new Set();
    for (const p of pages) {
      const doc = page(p);
      const links = [...doc.querySelectorAll('footer .foot-links a')];
      for (const a of links.filter((x) => x.target === '_blank')) expect(a.querySelector('.sr-only')?.textContent, p).toBe(' (opens in a new tab)');
      foots.add(links.map((a) => `${a.getAttribute('href')}|${a.textContent.trim()}`).join(' '));
      // The footer is the page's contentinfo landmark: a child of <body>, never inside <main> (1.3.1).
      const f = doc.querySelectorAll('footer');
      expect(f.length, p).toBe(1);
      expect(f[0].parentElement.tagName, p).toBe('BODY');
      expect(f[0].querySelector('[aria-label]:not(nav, [role])'), p).toBeNull(); // no name on a plain paragraph
    }
    expect(foots.size).toBe(1);
    expect([...foots][0]).toMatch(/\/accessibility\/\|Accessibility statement.*\/accessibility\/#glossary\|Glossary/);
  });
});

// ── 3.3.2 / 2.5.3 / 1.3.5 on the static pages ────────────────────────────────
describe('credential fields on the static pages', () => {
  const pages = ['index.html', 'dashboard/index.html', 'dashboard/login/index.html', 'dashboard/setup/index.html', 'dashboard/account/index.html'];
  for (const p of pages) {
    it(`${p}: each has a visible label that is its name, and an autocomplete token`, () => {
      const doc = page(p);
      const fields = [...doc.querySelectorAll('input[type="password"], input[autocomplete="one-time-code"], input[autocomplete="username"]')];
      expect(fields.length).toBeGreaterThan(0);
      for (const f of fields) {
        const label = doc.querySelector(`label[for="${f.id}"]`);
        expect(label, `${p} #${f.id}`).not.toBeNull();
        // The label names it: no aria-label overriding it with other words.
        const aria = f.getAttribute('aria-label');
        if (aria) expect(aria.toLowerCase(), `${p} #${f.id}`).toContain(label.textContent.trim().toLowerCase());
        expect(f.getAttribute('autocomplete'), `${p} #${f.id}`).toMatch(/^(current-password|new-password|username|one-time-code|off)$/);
        // Nothing stops pasting (3.3.8).
        expect(f.hasAttribute('onpaste') || f.hasAttribute('readonly'), `${p} #${f.id}`).toBe(false);
      }
    });
  }
  it('account passwords are for password managers: the right token, never "off"', () => {
    for (const p of ['dashboard/login/index.html', 'dashboard/setup/index.html', 'dashboard/account/index.html']) {
      const doc = page(p);
      for (const f of doc.querySelectorAll('input[type="password"]:not(#setup-token)')) expect(f.getAttribute('autocomplete'), `${p} #${f.id}`).toMatch(/^(current|new)-password$/);
    }
  });
  it('no code blocks paste anywhere in the browser modules', () => {
    for (const dir of ['public/js', 'public/dashboard/js']) {
      for (const f of readdirSync(join(ROOT, dir)).filter((x) => x.endsWith('.js'))) {
        expect(readFileSync(join(ROOT, dir, f), 'utf8'), `${dir}/${f}`).not.toMatch(/addEventListener\(\s*['"]paste['"]|onpaste/);
      }
    }
  });
});

// ── 4.1.3: status lines that are in the page before they speak ───────────────
describe('status lines in the page from the start', () => {
  it('the sign-in (and the Drive set-up or unlock after it) has one, outside both forms; the Drive page has "Opening your Drive…"', () => {
    const login = page('dashboard/login/index.html');
    const s = login.getElementById('login-status');
    expect(s.getAttribute('role')).toBe('status');
    expect(s.textContent).toBe('');
    expect(s.closest('form, [hidden]')).toBeNull();
    expect(readFileSync(join(ROOT, 'public/js/login.js'), 'utf8')).toMatch(/#login-status'\)\.textContent = on \? 'Signing in…'/);
    const drive = page('dashboard/drive/index.html');
    const d = drive.querySelector('#drive-root > p.msg[role="status"]');
    expect(d.textContent).toBe('Opening your Drive…');
  });
});

// ── 3.3.8: the human check offers a way on ───────────────────────────────────
describe('humanCheck help', () => {
  it('the waiting note offers the contact, and a page\'s own alternative when it has one', async () => {
    api.config = { turnstile: '0x4AAAAAAAsitekey' };
    globalThis.turnstile = { render: () => 'w1', reset() {} };
    const box = Object.assign(document.createElement('div'), { hidden: true });
    const btn = document.createElement('button');
    document.body.append(box, btn);
    const c = humanCheck(box, 'login', { gate: [btn] });
    await c;
    const note = document.querySelector('.human-wait');
    expect(note.textContent).toBe('Waiting for the CAPTCHA… If you cannot complete it, contact the administrator.');
    const btn2 = document.createElement('button');
    document.body.append(btn2);
    await humanCheck(Object.assign(document.createElement('div'), { hidden: true }), 'account', { gate: [btn2], alternative: 'Ask the owner to make the change for you.' });
    expect(btn2.nextElementSibling.textContent).toMatch(/Waiting for the CAPTCHA… Ask the owner to make the change for you\. If you cannot complete it/);
    expect(note.querySelector('a').getAttribute('href')).toBe('/accessibility/#st-contact');
    delete globalThis.turnstile;
    api.config = { turnstile: null };
  });
});

// ── 1.4.3 / 1.4.6 / 1.4.11: the palette ──────────────────────────────────────
// Contrast in every frame (WCAG 1.4.3 / 1.4.6): nothing with text is ever drawn part-way
// transparent or in a blend of the two themes. A control that becomes enabled (the CAPTCHA passed,
// files chosen) or a toast that appears is at full contrast at once: a transition on opacity from a
// disabled .45 (or a hidden 0) passed through low contrast (reproduced: 2.24:1 on "Send files" 40 ms
// after it was enabled, light theme). The same for entrances, dialogs, the countdown and the theme flip.
describe('no animation or transition passes through low contrast', () => {
  const css = readFileSync(join(ROOT, 'public/css/styles.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
  it('.cta, .send and #toast do not transition opacity', () => {
    for (const sel of ['.cta', '.send', '#toast']) {
      const rule = new RegExp(`(^|\\n)${sel.replace('.', '\\.')} \\{([^}]*)\\}`).exec(css);
      expect(rule, sel).not.toBeNull();
      const tr = /transition:\s*([^;]*)/.exec(rule[2]);
      expect(tr ? tr[1] : '', sel).not.toMatch(/opacity|\ball\b/);
    }
  });
  it('no @keyframes changes opacity, and no transition lists opacity or all', () => {
    const frames = [...css.matchAll(/@keyframes\s+([\w-]+)\s*\{((?:[^{}]*\{[^{}]*\})*[^{}]*)\}/g)];
    expect(frames.length).toBeGreaterThan(5);
    for (const [, name, body] of frames) expect(body, name).not.toMatch(/opacity/);
    for (const [decl] of css.matchAll(/transition:[^;}]*/g)) expect(decl).not.toMatch(/opacity|\ball\b/);
  });
  it('the theme flip: the wave has a hard edge (old or new palette, never a blend); the fallback does not interpolate colours', () => {
    const mask = /::view-transition-new\(root\)\s*\{[^}]*?\bmask-image:\s*linear-gradient\(([^;]*)\);/.exec(css);
    expect(mask).not.toBeNull();
    const stops = [...mask[1].matchAll(/(\d+)%/g)].map((m) => Number(m[1]));
    expect(stops.at(-1)).toBe(stops.at(-2)); // the transparent stop starts where the opaque one ends
    expect(css).not.toMatch(/html\.theming[^{]*\{[^}]*transition/);
  });
});

describe('palette', () => {
  const css = pub('css/styles.css');
  const block = (sel) => {
    const i = css.indexOf(`${sel} {`);
    return Object.fromEntries([...css.slice(i, css.indexOf('}', i)).matchAll(/--([a-z0-9-]+):\s*(#[0-9a-f]{6})/gi)].map((m) => [m[1], m[2]]));
  };
  const light = block(':root');
  const dark = { ...light, ...block('html.dark') };
  const lum = (hex) => [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((c) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4)).reduce((a, c, i) => a + c * [0.2126, 0.7152, 0.0722][i], 0);
  const ratio = (a, b) => { const x = lum(a); const y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
  for (const [name, t] of [['light', light], ['dark', dark]]) {
    it(`${name}: every text colour is ≥7:1 on every surface (AAA)`, () => {
      for (const fg of ['ink', 'ink-2', 'ink-3', 'accent', 'seal', 'ok', 'warn']) {
        for (const bg of ['paper', 'sheet', 'sheet-2']) expect(ratio(t[fg], t[bg]), `${fg} on ${bg}`).toBeGreaterThanOrEqual(7);
      }
      expect(ratio(t['accent-fg'], t['accent-fill']), 'button text').toBeGreaterThanOrEqual(7);
      expect(ratio('#ffffff', t['seal-fill']), 'error toast').toBeGreaterThanOrEqual(7);
    });
    it(`${name}: field boundaries and the focus ring are ≥3:1 (1.4.11, 2.4.13)`, () => {
      for (const bg of ['paper', 'sheet', 'sheet-2']) {
        expect(ratio(t.field, t[bg]), `field on ${bg}`).toBeGreaterThanOrEqual(3);
        expect(ratio(t.ring, t[bg]), `ring on ${bg}`).toBeGreaterThanOrEqual(3);
      }
    });
  }
});
