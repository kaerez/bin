// a11y-widget.test.js — the accessibility preferences widget (public/js/a11y.js)
// and its head bootstrap (public/js/a11y-init.js): saved settings survive and
// malformed ones are ignored; both files use the same class map; the panel
// is keyboard-operable with switch semantics; every English string has a
// Hebrew one and the panel turns RTL; and every page carries the widget, a
// skip link and a main target.
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it, expect, beforeEach } from 'vitest';

globalThis.__SECBIN_A11Y_NO_AUTOMOUNT = true;
const { readSaved, apply, mount, STRINGS, FLAGS } = await import('../public/js/a11y.js');
const root = join(import.meta.dirname, '..');
const read = (p) => readFileSync(join(root, p), 'utf8');

const store = (v) => ({ getItem: () => v });

beforeEach(() => {
  document.body.replaceChildren();
  document.documentElement.className = '';
  try { localStorage.clear(); } catch { /* */ }
});

describe('settings', () => {
  it('ignores malformed storage and keeps only known values', () => {
    expect(readSaved(store('not json')).fontScale).toBe('md');
    expect(readSaved(store('[1,2]')).highContrast).toBe(false);
    const s = readSaved(store(JSON.stringify({ highContrast: true, fontScale: 'huge', lang: 'fr', evil: '<img>', markLinks: 'yes' })));
    expect(s).toMatchObject({ highContrast: true, fontScale: 'md', lang: null, markLinks: false });
    expect(s).not.toHaveProperty('evil');
    expect(readSaved({ getItem: () => { throw new Error('blocked'); } }).fontScale).toBe('md');
  });

  it('applies classes, one text size at a time', () => {
    apply({ highContrast: true, keyboardNav: true, fontScale: 'lg' });
    expect([...document.documentElement.classList].sort()).toEqual(['a11y-contrast', 'a11y-font-lg', 'a11y-keyboard']);
    apply({ fontScale: 'sm' });
    expect([...document.documentElement.classList]).toEqual(['a11y-font-sm']);
  });

  it('the head bootstrap uses the same class map and storage key', () => {
    const init = read('public/js/a11y-init.js');
    const widget = read('public/js/a11y.js');
    const pairs = [...init.matchAll(/(\w+): '(a11y-[a-z-]+)'/g)].map((m) => [m[1], m[2]]);
    expect(Object.fromEntries(pairs)).toEqual(FLAGS);
    expect(init).toContain("'a11y-font-lg'");
    expect(init).toContain("'a11y-font-sm'");
    expect(init).toContain("'secbin:a11y'");
    expect(widget).toContain("'secbin:a11y'");
  });
});

describe('the panel', () => {
  it('opens, moves focus in, toggles switches, and Escape returns focus', () => {
    const w = mount(document.body);
    expect(w.btn.getAttribute('aria-expanded')).toBe('false');
    expect(w.panel.hidden).toBe(true);
    w.btn.click();
    expect(w.panel.hidden).toBe(false);
    expect(w.panel.contains(document.activeElement)).toBe(true);
    const sw = w.panel.querySelector('[data-key="noAnimations"]');
    expect(sw.getAttribute('role')).toBe('switch');
    sw.click();
    expect(sw.getAttribute('aria-checked')).toBe('true');
    expect(document.documentElement.classList.contains('a11y-no-anim')).toBe(true);
    expect(JSON.parse(localStorage.getItem('secbin:a11y')).noAnimations).toBe(true);
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' }));
    expect(w.panel.hidden).toBe(true);
    expect(document.activeElement).toBe(w.btn);
  });

  it('switches to Hebrew: rtl, lang="he" and Hebrew labels', () => {
    const w = mount(document.body);
    w.btn.click();
    w.panel.querySelector('button[lang="he"]').click();
    expect(w.panel.getAttribute('dir')).toBe('rtl');
    expect(w.panel.getAttribute('lang')).toBe('he');
    expect(w.btn.getAttribute('aria-label')).toBe(STRINGS.he.open);
    expect(w.panel.querySelector('[data-key="highContrast"]').textContent).toContain(STRINGS.he.highContrast);
  });

  it('every English string has a Hebrew one', () => {
    expect(Object.keys(STRINGS.he).sort()).toEqual(Object.keys(STRINGS.en).sort());
    for (const v of Object.values(STRINGS.he)) expect(v).toMatch(/[֐-׿]/);
  });

  it('builds no markup from strings', () => {
    expect(read('public/js/a11y.js')).not.toMatch(/innerHTML|insertAdjacentHTML|outerHTML|document\.write/);
  });
});

describe('every page', () => {
  const pages = (dir = 'public') => readdirSync(join(root, dir)).flatMap((n) => {
    const p = `${dir}/${n}`;
    if (statSync(join(root, p)).isDirectory()) return n === 'js' || n === 'vendor' ? [] : pages(p);
    return n === 'index.html' ? [p] : [];
  });

  it('has a skip link to #main, the widget, the head bootstrap and the statement link', () => {
    const list = pages();
    expect(list).toContain('public/accessibility/index.html');
    for (const p of list) {
      const s = read(p);
      expect(s, p).toMatch(/<body>\s*<a class="skip-link" href="#main">/);
      expect(s, p).toMatch(/<main [^>]*id="main" tabindex="-1"/);
      expect(s, p).toContain('<script src="/js/a11y-init.js"></script>');
      expect(s, p).toContain('<script type="module" src="/js/a11y.js"></script>');
      expect(s, p).toContain('href="/accessibility/"');
    }
  });

  it('the statement is bilingual and claims only partial conformance', () => {
    const s = read('public/accessibility/index.html');
    expect(s).toMatch(/lang="he" dir="rtl"/);
    expect(s).toContain('partial conformance');
    expect(s).toContain('התאמה חלקית');
    expect(s).not.toMatch(/fully (conforms|compliant)|full conformance/i);
  });
});
