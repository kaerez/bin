// a11y.js — the accessibility preferences widget (English / עברית): a fixed
// button that opens a panel of switches — keyboard focus highlight, stop
// animations, high contrast, text size, readable font, mark headings, mark
// links — saved in localStorage and applied as classes on <html>
// (public/js/a11y-init.js applies them before paint on the next load).
//
// A comfort tool, not a compliance measure: the pages themselves are built
// to WCAG 2.2 AA (see /accessibility/). Built with DOM calls only (no markup
// strings), so it runs under the site's CSP and Trusted Types.

const KEY = 'secbin:a11y';
export const FLAGS = {
  keyboardNav: 'a11y-keyboard', noAnimations: 'a11y-no-anim', highContrast: 'a11y-contrast',
  readableFont: 'a11y-readable', markHeadings: 'a11y-headings', markLinks: 'a11y-links',
};
const FONT = { sm: 'a11y-font-sm', md: '', lg: 'a11y-font-lg' };
const DEFAULTS = Object.freeze({
  keyboardNav: false, noAnimations: false, highContrast: false, readableFont: false,
  markHeadings: false, markLinks: false, fontScale: 'md', lang: null,
});

export const STRINGS = {
  en: {
    open: 'Accessibility settings', title: 'Accessibility settings', close: 'Close',
    keyboardNav: 'Highlight keyboard focus', noAnimations: 'Stop animations', highContrast: 'High contrast',
    readableFont: 'Readable font', markHeadings: 'Mark headings', markLinks: 'Mark links and buttons',
    text: 'Text size', sm: 'Smaller', md: 'Default', lg: 'Larger',
    reset: 'Reset all', statement: 'Accessibility statement', language: 'Language',
    note: 'These settings are saved in this browser only.',
  },
  he: {
    open: 'הגדרות נגישות', title: 'הגדרות נגישות', close: 'סגירה',
    keyboardNav: 'הדגשת פוקוס מקלדת', noAnimations: 'עצירת אנימציות', highContrast: 'ניגודיות גבוהה',
    readableFont: 'גופן קריא', markHeadings: 'סימון כותרות', markLinks: 'סימון קישורים וכפתורים',
    text: 'גודל טקסט', sm: 'קטן', md: 'רגיל', lg: 'גדול',
    reset: 'איפוס הכול', statement: 'הצהרת נגישות', language: 'שפה',
    note: 'ההגדרות נשמרות בדפדפן זה בלבד.',
  },
};

/** Saved settings merged over the defaults (anything malformed is ignored). */
export function readSaved(storage = globalThis.localStorage) {
  let saved = null;
  try { saved = JSON.parse(storage.getItem(KEY) || 'null'); } catch { /* blocked or corrupt */ }
  const out = { ...DEFAULTS };
  if (!saved || typeof saved !== 'object' || Array.isArray(saved)) return out;
  for (const k of Object.keys(FLAGS)) if (typeof saved[k] === 'boolean') out[k] = saved[k];
  if (saved.fontScale in FONT) out.fontScale = saved.fontScale;
  if (saved.lang === 'en' || saved.lang === 'he') out.lang = saved.lang;
  return out;
}

/** Put the settings on <html> (the same classes a11y-init.js sets). */
export function apply(settings, html = document.documentElement) {
  for (const [k, cls] of Object.entries(FLAGS)) html.classList.toggle(cls, !!settings[k]);
  html.classList.remove('a11y-font-sm', 'a11y-font-lg');
  if (FONT[settings.fontScale]) html.classList.add(FONT[settings.fontScale]);
}

const langOf = (s) => s.lang || (/^he\b/i.test(navigator.language || '') ? 'he' : 'en');

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'text') e.textContent = v;
    else e.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of kids) if (c) e.appendChild(c);
  return e;
}

const SVG = 'http://www.w3.org/2000/svg';
function icon() {
  const s = document.createElementNS(SVG, 'svg');
  for (const [k, v] of Object.entries({ viewBox: '0 0 24 24', width: '24', height: '24', fill: 'none', stroke: 'currentColor', 'stroke-width': '1.75', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', focusable: 'false' })) s.setAttribute(k, v);
  const add = (tag, a) => { const n = document.createElementNS(SVG, tag); for (const [k, v] of Object.entries(a)) n.setAttribute(k, v); s.appendChild(n); };
  add('circle', { cx: '12', cy: '4.5', r: '1.75' });
  add('path', { d: 'M5 8.5l7 1.5 7-1.5M12 10v4.5M12 14.5l-3 6M12 14.5l3 6' });
  return s;
}

export function mount(root = document.body) {
  if (!root || document.getElementById('a11y-btn')) return null;
  let settings = readSaved();
  let open = false;
  const save = () => {
    apply(settings);
    try { localStorage.setItem(KEY, JSON.stringify(settings)); } catch { /* blocked: this page only */ }
  };

  const btn = el('button', { type: 'button', id: 'a11y-btn', class: 'a11y-btn', 'aria-expanded': 'false', 'aria-controls': 'a11y-panel' });
  btn.appendChild(icon());
  const panel = el('div', { id: 'a11y-panel', class: 'a11y-panel', role: 'region', 'aria-labelledby': 'a11y-title', hidden: true });

  function render() {
    const lang = langOf(settings);
    const t = STRINGS[lang];
    btn.setAttribute('aria-label', t.open);
    btn.setAttribute('title', t.open);
    panel.setAttribute('lang', lang);
    panel.setAttribute('dir', lang === 'he' ? 'rtl' : 'ltr');
    panel.replaceChildren();
    const close = el('button', { type: 'button', class: 'a11y-close', 'aria-label': t.close, text: '×' });
    close.addEventListener('click', () => toggle(false));
    panel.appendChild(el('div', { class: 'a11y-head' }, el('h2', { id: 'a11y-title', class: 'a11y-title', text: t.title }), close));

    const langs = el('div', { class: 'a11y-seg', role: 'group', 'aria-label': t.language });
    for (const [code, name] of [['en', 'English'], ['he', 'עברית']]) {
      const b = el('button', { type: 'button', lang: code, 'aria-pressed': String(lang === code), text: name });
      b.addEventListener('click', () => { settings = { ...settings, lang: code }; save(); render(); panel.querySelector(`.a11y-seg button[lang="${code}"]`)?.focus(); });
      langs.appendChild(b);
    }
    panel.appendChild(langs);

    for (const k of Object.keys(FLAGS)) {
      const sw = el('button', { type: 'button', role: 'switch', class: 'a11y-switch', 'aria-checked': String(!!settings[k]), 'data-key': k },
        el('span', { text: t[k] }), el('span', { class: 'a11y-track', 'aria-hidden': 'true' }, el('span', { class: 'a11y-thumb' })));
      sw.addEventListener('click', () => {
        settings = { ...settings, [k]: !settings[k] };
        sw.setAttribute('aria-checked', String(settings[k]));
        save();
      });
      panel.appendChild(sw);
    }

    const sizes = el('div', { class: 'a11y-seg', role: 'group', 'aria-label': t.text });
    for (const f of ['sm', 'md', 'lg']) {
      const b = el('button', { type: 'button', 'aria-pressed': String(settings.fontScale === f), 'data-font': f, text: t[f] });
      b.addEventListener('click', () => {
        settings = { ...settings, fontScale: f };
        save();
        for (const x of sizes.children) x.setAttribute('aria-pressed', String(x.dataset.font === f));
      });
      sizes.appendChild(b);
    }
    panel.appendChild(el('p', { class: 'a11y-label', text: t.text }));
    panel.appendChild(sizes);

    const reset = el('button', { type: 'button', class: 'btn', text: t.reset });
    reset.addEventListener('click', () => { settings = { ...DEFAULTS, lang: settings.lang }; save(); render(); panel.querySelector('button')?.focus(); });
    panel.appendChild(el('div', { class: 'a11y-foot' }, reset, el('a', { href: '/accessibility/', text: t.statement })));
    panel.appendChild(el('p', { class: 'a11y-note', text: t.note }));
  }

  function toggle(want, { focusButton = true } = {}) {
    open = want;
    panel.hidden = !open;
    btn.setAttribute('aria-expanded', String(open));
    if (open) panel.querySelector('button')?.focus();
    else if (focusButton) btn.focus();
  }
  btn.addEventListener('click', () => toggle(!open));
  document.addEventListener('keydown', (e) => { if (open && e.key === 'Escape') { e.preventDefault(); toggle(false); } });
  document.addEventListener('mousedown', (e) => {
    if (open && !panel.contains(e.target) && !btn.contains(e.target)) toggle(false, { focusButton: panel.contains(document.activeElement) });
  });

  render();
  root.appendChild(btn);
  root.appendChild(panel);
  return { btn, panel, toggle, get settings() { return settings; } };
}

if (typeof document !== 'undefined' && document.body && !globalThis.__SECBIN_A11Y_NO_AUTOMOUNT) mount();
