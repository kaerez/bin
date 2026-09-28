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
  standard: paras(2000, 'WCAG 2.2 level AA is our minimum, and we meet level AAA wherever we can. Content that meets WCAG 2.2 AA also meets WCAG 2.1 AA and 2.0 AA.\nAt our last technical review, the pages of this site met every WCAG 2.2 level A and AA success criterion, and most level AAA criteria. That review was done in one browser engine; testing by people with screen readers and other assistive technology is still to come, and content that users share and the optional CAPTCHA (a third-party component) are outside it: see the known limitations below.', 'Standard and status'),
  reviewLabel: line(120, 'Last technical review', 'Review: label before the date'),
  reviewNote: paras(2000, 'Every WCAG 2.2 success criterion was checked, at levels A, AA and AAA, on every page and state, in both themes, at desktop and phone widths: with automated scans (axe-core, including the AAA contrast rules), with measurements of reflow at 320 px and 400% zoom, text spacing, target sizes and focus hidden behind fixed elements, and by reading the code. In Chromium, automated checks also covered the accessibility tree that the browser passes to screen readers (names, roles and states, landmarks, headings, live regions, dialogs and form errors), keyboard-only use with a visible focus, Windows High Contrast (forced colours), reduced motion and right-to-left text.', 'Review: how it was done'),
  doneHeading: line(120, 'What we have done', 'What we have done: heading'),
  done: list([
    'A “Skip to main content” link, landmarks and a heading structure on every page.',
    'Everything works with a keyboard alone, with a visible focus indicator, also in Windows High Contrast (forced colours).',
    'Every form field has a visible label; errors are given in text and announced to screen readers.',
    'Text contrast is at least 7:1 (level AAA) in both the light and the dark theme; information is never carried by colour alone.',
    'Animations stop when your system asks for reduced motion, or when you turn on “Stop animations” in the accessibility settings.',
    'Pages reflow down to 320 px wide and at 400% zoom; touch targets are at least 24 px, or 44 px with “Large buttons and links”.',
    'Nothing ends your work without warning: before your session times out, or a download window closes, you are warned and can extend it. Countdowns can be stopped. A share’s own expiry is the sender’s choice.',
    'A passkey signs you in without a password; passwords and codes can be pasted and filled in by password managers.',
    'A glossary explains the technical words and abbreviations, and a site map lists every page (both below).',
    'In addition, an accessibility settings button (bottom corner of every page): high contrast, larger or smaller text, readable font, text spacing, large buttons and links, stop animations, keyboard focus highlight, and marking of headings and links. It is a convenience, not a substitute for the above.',
  ], 'What we have done'),
  limitsHeading: line(120, 'Known limitations', 'Known limitations: heading'),
  limits: list([
    'Files and notes are made by their senders; we cannot make a shared document (for example a PDF) accessible. You can always download it and open it in your own reader.',
    'The in-browser preview of a PDF gives the text of each page, but not the document’s structure (headings, tables, reading order). Download the file to read it in your own reader.',
    'When this server uses the Cloudflare Turnstile CAPTCHA (a third-party component), it may occasionally ask you to confirm (a box to tick, no puzzle). If you cannot complete it, contact us: the note under the button links to how.',
    'We have not yet tested with screen readers, voice control and other assistive technology, or in browsers other than Chromium. Please tell us about anything that does not work for you.',
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
  'a11y.reviewed':    { type: 'date', def: '2026-09-27' },
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
