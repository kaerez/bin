// statement.test.js — the accessibility statement (#35): the structured model
// (public/js/a11ystatement.js) defaults to English only and claims only
// partial conformance; the renderer (public/js/statement.js) builds headings,
// lists, lang/dir and the admin's contact from text only — markup in the
// settings stays text — and a second language falls back to the main
// language's headings, marked with that language.
import { describe, it, expect, beforeEach } from 'vitest';

globalThis.__SECBIN_STATEMENT_NO_AUTOMOUNT = true;
const { renderStatement } = await import('../public/js/statement.js');
const { A11Y_DEFAULTS, A11Y_SETTINGS, STATEMENT_FIELDS, publicStatement, checkStatement, guessDir, A11Y_MAX_TOTAL } = await import('../public/js/a11ystatement.js');

let root;
beforeEach(() => {
  document.body.replaceChildren();
  root = document.createElement('div');
  root.id = 'statement';
  document.body.appendChild(root);
});
const render = (over = {}) => renderStatement(root, publicStatement({ ...A11Y_DEFAULTS, ...over }));
const texts = (sel, el = root) => [...el.querySelectorAll(sel)].map((e) => e.textContent);

describe('model', () => {
  it('defaults to one English statement claiming partial conformance', () => {
    const p = publicStatement(A11Y_DEFAULTS);
    expect(p.statements).toHaveLength(1);
    expect(p.statements[0]).toMatchObject({ lang: 'en', dir: 'ltr', title: 'Accessibility statement' });
    expect(p.statements[0].standard.join(' ')).toContain('partial conformance');
    expect(JSON.stringify(p)).not.toMatch(/fully (conforms|compliant)|full conformance/i);
    expect(JSON.stringify(p)).not.toMatch(/[֐-׿]/); // no Hebrew by default
    expect(p.statements[0].done).toHaveLength(8);
    expect(p.statements[0].limits).toHaveLength(4);
    expect(A11Y_DEFAULTS['a11y.alt.lang']).toBe('');
    expect({ contact: p.contact, coordinator: p.coordinator }).toEqual({ contact: '', coordinator: '' });
  });

  it('every main-language field has a default within its limits; second-language fields start empty', () => {
    for (const [k, f] of Object.entries(STATEMENT_FIELDS)) {
      const d = A11Y_SETTINGS[`a11y.${k}`].def;
      expect(d.length, k).toBeGreaterThan(0);
      expect(d.length, k).toBeLessThanOrEqual(f.max);
      if (f.items) expect(d.split('\n').every((x) => x.length <= f.itemMax), k).toBe(true);
      expect(A11Y_SETTINGS[`a11y.alt.${k}`].def, k).toBe('');
      expect(A11Y_SETTINGS[`a11y.alt.${k}`].required, k).toBeUndefined();
    }
  });

  it('checks the fields together', () => {
    expect(checkStatement(A11Y_DEFAULTS)).toBeNull();
    expect(checkStatement({ ...A11Y_DEFAULTS, 'a11y.alt.lang': 'he' })).toMatch(/needs a title/);
    expect(checkStatement({ ...A11Y_DEFAULTS, 'a11y.alt.lang': 'EN', 'a11y.alt.title': 'x' })).toMatch(/differ/);
    expect(checkStatement({ ...A11Y_DEFAULTS, 'a11y.alt.lang': 'he', 'a11y.alt.title': 'הצהרת נגישות' })).toBeNull();
    expect(checkStatement({ ...A11Y_DEFAULTS, 'a11y.alt.done': 'x'.repeat(A11Y_MAX_TOTAL) })).toMatch(/at most/);
  });

  it('guesses the direction of a language', () => {
    for (const l of ['he', 'ar', 'fa-IR', 'ur']) expect(guessDir(l), l).toBe('rtl');
    for (const l of ['en', 'fr', 'ru', 'zh-Hant']) expect(guessDir(l), l).toBe('ltr');
  });
});

describe('renderer', () => {
  it('renders the default: landmarks, headings, lists, date, fallback contact', () => {
    expect(render()).toBe(true);
    expect(root.dataset.ready).toBe('true');
    const arts = root.querySelectorAll('article');
    expect(arts).toHaveLength(1);
    expect(arts[0].getAttribute('lang')).toBe('en');
    expect(arts[0].getAttribute('dir')).toBe('ltr');
    expect(arts[0].getAttribute('aria-labelledby')).toBe('st-title');
    expect(texts('h1')).toEqual(['Accessibility statement']);
    expect(texts('h2')).toEqual(['Our commitment', 'Standard and status', 'What we have done', 'Known limitations', 'Report a problem or ask for an adjustment']);
    expect(root.querySelectorAll('ul.statement-list')).toHaveLength(2);
    expect(root.querySelectorAll('ul.statement-list li')).toHaveLength(12);
    const t = root.querySelector('time');
    expect(t.getAttribute('datetime')).toBe('2026-09-25');
    expect(t.parentElement.textContent).toMatch(/^Last technical review: .*2026\. This was an automated/);
    expect(root.querySelector('#st-contact').textContent).toBe('Contact the administrator of this site.');
    expect(root.querySelector('#st-coord')).toBeNull();
    expect(root.querySelector('.eyebrow')).toBeNull(); // one language: no language switch
    expect(document.title).toBe('Accessibility statement · secbin');
  });

  it('keeps markup in the settings as text (no elements are created from it)', () => {
    const evil = '<img src=x onerror=alert(1)><script>alert(2)</script>';
    render({ 'a11y.title': evil, 'a11y.commitment': evil, 'a11y.done': `${evil}\nsecond`, 'a11y.contact': evil, 'a11y.coordinator': evil });
    expect(root.querySelector('img, script')).toBeNull();
    expect(root.querySelector('h1').textContent).toBe(evil);
    expect(root.querySelector('#st-contact').textContent).toBe(evil);
    expect(root.querySelector('#st-coord .statement-contact').textContent).toBe(evil);
    expect(texts('ul li').slice(0, 2)).toEqual([evil, 'second']);
  });

  it('one paragraph per line, empty sections left out, no date without one', () => {
    render({ 'a11y.commitment': 'one\ntwo', 'a11y.limits': '', 'a11y.reviewed': '', 'a11y.reviewNote': '' });
    const commit = root.querySelectorAll('section')[0];
    expect(texts('p', commit)).toEqual(['one', 'two']);
    expect(texts('h2')).not.toContain('Known limitations');
    expect(root.querySelector('time')).toBeNull();
  });

  it('a second language gets its own article, lang and dir, with a link to it', () => {
    render({
      'a11y.contact': 'access@example.test', 'a11y.coordinator': 'Dana',
      'a11y.alt.lang': 'he', 'a11y.alt.dir': 'rtl', 'a11y.alt.title': 'הצהרת נגישות',
      'a11y.alt.commitmentHeading': 'מחויבות', 'a11y.alt.commitment': 'טקסט', 'a11y.alt.done': 'א\nב',
    });
    const [en, he] = root.querySelectorAll('article');
    expect(he.getAttribute('lang')).toBe('he');
    expect(he.getAttribute('dir')).toBe('rtl');
    expect(he.id).toBe('st-alt');
    expect(he.getAttribute('aria-labelledby')).toBe('st-title-alt');
    expect(he.querySelector('h1').id).toBe('st-title-alt');
    const link = en.querySelector('.eyebrow a');
    expect(link.getAttribute('href')).toBe('#st-alt');
    expect(link.getAttribute('lang')).toBe('he');
    // Shared details appear in both languages.
    expect(he.querySelector('#st-contact-alt').textContent).toBe('access@example.test');
    expect(he.querySelector('#st-coord-alt .statement-contact').textContent).toBe('Dana');
    // Its own heading where set; the main language's (marked en/ltr) where not.
    const h2 = [...he.querySelectorAll('h2')];
    expect(h2[0].textContent).toBe('מחויבות');
    expect(h2[0].querySelector('span')).toBeNull();
    const done = h2.find((x) => x.textContent === 'What we have done');
    expect(done.querySelector('span').getAttribute('lang')).toBe('en');
    expect(done.querySelector('span').getAttribute('dir')).toBe('ltr');
    expect(texts('li', he)).toEqual(['א', 'ב']);
    // No duplicate ids across the two articles.
    const ids = [...root.querySelectorAll('[id]')].map((e) => e.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('ignores malformed data', () => {
    expect(renderStatement(root, null)).toBe(false);
    expect(renderStatement(root, { statements: [] })).toBe(false);
    expect(renderStatement(root, { statements: [{ lang: 'en', dir: 'sideways', title: 'T', done: 'not-a-list', limits: [1, 'ok'] }], reviewed: '<b>' })).toBe(true);
    expect(root.querySelector('article').getAttribute('dir')).toBe('ltr');
    expect(texts('li')).toEqual(['ok']);
    expect(root.querySelector('time')).toBeNull();
  });
});
