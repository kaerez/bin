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
// A page's markup without its <link>s and <script>s (parsing must not fetch them).
const page = (p) => new DOMParser().parseFromString(pub(p).replace(/<link\b[^>]*>/g, '').replace(/<script\b[\s\S]*?<\/script>/g, ''), 'text/html');

// ── api.js stand-in: me() / logout() and the activity hook ──────────────────
const api = vi.hoisted(() => ({ me: null, activity: new Set(), logouts: 0, config: { turnstile: null } }));
vi.mock('../public/js/api.js', () => {
  class ApiError extends Error { constructor(m, status) { super(m); this.status = status; } }
  return {
    ApiError,
    me: async () => api.me(),
    logout: async () => { api.logouts += 1; },
    onPrivateActivity: (fn) => { api.activity.add(fn); return () => api.activity.delete(fn); },
    fetchConfig: async () => api.config,
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
    // Closed, it stays closed (the page keeps what was typed).
    d.querySelector('button').click();
    at(700);
    expect(dialog()).toBeNull();
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
    const pages = ['index.html', 'accessibility/index.html', 'r/index.html', 'dashboard/index.html',
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
