// a11ystatement.js — the accessibility statement as structured, admin-editable
// text (Admin → Settings → Accessibility): the fields, their limits, the
// English default, and the pure transform from settings to what /api/config
// serves and /accessibility/ renders. Plain text only: nothing here is ever
// parsed as HTML (the page builds its DOM with textContent). Shared by the
// Worker (src/lib/settings.js validates with these specs) and the browser.

/** Longest list (done / limitations) and the cap on the whole statement, in characters. */
export const A11Y_MAX_ITEMS = 30;
export const A11Y_MAX_TOTAL = 32000;
export const A11Y_DIRS = ['ltr', 'rtl'];

const line = (max, def, label) => ({ max, oneLine: true, required: true, def, label });
const paras = (max, def, label) => ({ max, paragraphs: true, def, label });
const list = (def, label) => ({ max: 8000, items: A11Y_MAX_ITEMS, itemMax: 500, def: def.join('\n'), label });

/**
 * The text of one language block, in page order. `required` fields cannot be
 * empty in the main language; in the second language an empty heading shows
 * the main language's (marked with its lang), so only the title is needed.
 */
export const STATEMENT_FIELDS = {
  title: line(120, 'Accessibility statement', 'Title'),
  commitmentHeading: line(120, 'Our commitment', 'Commitment: heading'),
  commitment: paras(2000, 'secbin should be usable by everyone, including people with disabilities. We build the pages themselves to be accessible, and keep improving them.', 'Commitment'),
  standardHeading: line(120, 'Standard and status', 'Standard and status: heading'),
  standard: paras(2000, 'We target WCAG 2.2 level AA. Content that meets WCAG 2.2 AA also meets WCAG 2.0 AA, on which the Israeli standard IS 5568 (level AA) is based. The current status is partial conformance: see the known limitations below.', 'Standard and status'),
  reviewLabel: line(120, 'Last technical review', 'Review: label before the date'),
  reviewNote: paras(2000, 'This was an automated WCAG 2.2 A/AA scan (axe-core) of every page and state, in both themes, at desktop and phone widths. In Chromium, automated checks also covered the accessibility tree that the browser passes to screen readers (names, roles and states, landmarks, headings, live regions, dialogs and form errors), keyboard-only use with a visible focus, Windows High Contrast (forced colours), reflow at 320 px, reduced motion and right-to-left text.', 'Review: how it was done'),
  doneHeading: line(120, 'What we have done', 'What we have done: heading'),
  done: list([
    'A “Skip to main content” link, landmarks and a heading structure on every page.',
    'Everything works with a keyboard alone, with a visible focus indicator, also in Windows High Contrast (forced colours).',
    'Every form field has a label; errors are given in text and announced to screen readers.',
    'Colour contrast meets AA in both the light and the dark theme; information is never carried by colour alone.',
    'Animations stop when your system asks for reduced motion, or when you turn on “Stop animations” in the accessibility settings.',
    'Pages reflow down to 320 px wide and at 200% zoom; touch targets are at least 24 px.',
    'No time limits, except the expiry a sender chooses for a share.',
    'In addition, an accessibility settings button (bottom corner of every page): high contrast, larger or smaller text, readable font, stop animations, keyboard focus highlight, and marking of headings and links. It is a convenience, not a substitute for the above.',
  ], 'What we have done'),
  limitsHeading: line(120, 'Known limitations', 'Known limitations: heading'),
  limits: list([
    'Files and notes are made by their senders; we cannot make a shared document (for example a PDF) accessible. You can always download it and open it in your own reader.',
    'The in-browser preview of PDFs and some other file types may not expose the document’s structure to screen readers. Download the file instead.',
    'When this server uses the Cloudflare Turnstile human check (a third-party component), it may occasionally ask you to confirm. If you cannot complete it, contact us.',
  ], 'Known limitations'),
  reportHeading: line(120, 'Report a problem or ask for an adjustment', 'Report a problem: heading'),
  report: paras(1000, 'If something here is not accessible to you, or you need an adjustment, tell us:', 'Report a problem: introduction'),
  noContact: line(500, 'Contact the administrator of this site.', 'Shown when no contact is set'),
  coordinatorHeading: line(120, 'Accessibility coordinator', 'Coordinator: heading'),
};

export const MAIN = 'a11y.';
export const ALT = 'a11y.alt.';

/**
 * The settings (src/lib/settings.js SETTINGS entries) behind the statement.
 * The contact and coordinator are shared by both languages; so is the review
 * date. The second language is off while its code is empty.
 */
export const A11Y_SETTINGS = {
  // How to report a problem, and the coordinator (only where the law requires one).
  'a11y.contact':     { type: 'text', max: 500, def: '' },
  'a11y.coordinator': { type: 'text', max: 500, def: '' },
  'a11y.reviewed':    { type: 'date', def: '2026-09-25' },
  'a11y.lang':        { type: 'lang', def: 'en' },
  'a11y.dir':         { type: 'enum', values: A11Y_DIRS, def: 'ltr' },
  ...Object.fromEntries(Object.entries(STATEMENT_FIELDS).map(([k, { label: _label, ...f }]) => [`${MAIN}${k}`, { type: 'text', ...f }])),
  'a11y.alt.lang':    { type: 'lang', optional: true, def: '' },
  'a11y.alt.dir':     { type: 'enum', values: A11Y_DIRS, def: 'ltr' },
  ...Object.fromEntries(Object.entries(STATEMENT_FIELDS).map(([k, { label: _label, required: _required, ...f }]) => [`${ALT}${k}`, { type: 'text', ...f, def: '' }])),
};

export const A11Y_KEYS = Object.keys(A11Y_SETTINGS);
export const A11Y_DEFAULTS = Object.freeze(Object.fromEntries(A11Y_KEYS.map((k) => [k, A11Y_SETTINGS[k].def])));

/** Non-empty trimmed lines (paragraphs or list items). */
export const splitLines = (v) => String(v ?? '').split('\n').map((x) => x.trim()).filter(Boolean);

/** Right-to-left scripts, as a hint for the admin UI (the admin can override). */
export function guessDir(lang) {
  try {
    const loc = new Intl.Locale(lang);
    const info = typeof loc.getTextInfo === 'function' ? loc.getTextInfo() : loc.textInfo;
    if (info && info.direction) return info.direction === 'rtl' ? 'rtl' : 'ltr';
  } catch { /* fall through */ }
  return /^(ar|arc|ckb|dv|fa|he|iw|ks|ku-arab|ps|sd|syr|ug|ur|yi)(-|$)/i.test(String(lang)) ? 'rtl' : 'ltr';
}

/**
 * Rules across fields, on the merged settings: returns an error message or
 * null. A second language needs a title and a code other than the main one;
 * the whole statement stays under A11Y_MAX_TOTAL characters.
 */
export function checkStatement(s) {
  const alt = s['a11y.alt.lang'];
  if (alt) {
    if (String(alt).toLowerCase() === String(s['a11y.lang']).toLowerCase()) return 'The second language must differ from the main one.';
    if (!s['a11y.alt.title']) return 'The second language needs a title.';
  }
  const total = A11Y_KEYS.reduce((n, k) => n + String(s[k] ?? '').length, 0);
  if (total > A11Y_MAX_TOTAL) return `The accessibility statement is at most ${A11Y_MAX_TOTAL} characters in all (it is ${total}).`;
  return null;
}

/** What /api/config serves: the shared details and one block per language (main first). */
export function publicStatement(s) {
  const block = (prefix, lang, dir) => {
    const b = { lang, dir };
    for (const [k, f] of Object.entries(STATEMENT_FIELDS)) {
      const v = String(s[`${prefix}${k}`] ?? '');
      b[k] = f.items || f.paragraphs ? splitLines(v) : v;
    }
    return b;
  };
  const statements = [block(MAIN, s['a11y.lang'] || 'en', s['a11y.dir'] || 'ltr')];
  if (s['a11y.alt.lang']) statements.push(block(ALT, s['a11y.alt.lang'], s['a11y.alt.dir'] || 'ltr'));
  return { contact: s['a11y.contact'] || '', coordinator: s['a11y.coordinator'] || '', reviewed: s['a11y.reviewed'] || '', statements };
}
