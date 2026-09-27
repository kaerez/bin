// statement.js — /accessibility/: renders the accessibility statement the
// admin edits under Admin → Settings → Accessibility (served by /api/config),
// one article per language with its own lang and dir. DOM construction only
// (textContent via h()); the text is never parsed as HTML. Without the config
// (offline, an error) the built-in English default is shown.

import { fetchConfig } from './api.js';
import { h, clear } from './common.js';
import { A11Y_DEFAULTS, STATEMENT_FIELDS, A11Y_DIRS, publicStatement } from './a11ystatement.js';

const langName = (lang) => {
  try { return new Intl.DisplayNames([lang], { type: 'language' }).of(lang) || lang; } catch { return lang; }
};

const formatDay = (iso, lang) => {
  try {
    return new Intl.DateTimeFormat(lang, { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' }).format(new Date(`${iso}T00:00:00Z`));
  } catch { return iso; }
};

/**
 * One language's article. `main` is the first block: an empty heading in a
 * second language shows the main language's, marked with that language.
 */
function article(b, main, data, i, count) {
  const sfx = i ? '-alt' : '';
  const word = (key) => (b[key] || b === main ? b[key] : h('span', { lang: main.lang, dir: main.dir, text: main[key] }));
  const heading = (key) => h('h2.section-title', {}, word(key));
  const paras = (list) => list.map((t) => h('p', { text: t }));
  const section = (key, ...body) => h('section', {}, heading(key), ...body);
  const items = (list) => h('ul.statement-list', {}, ...list.map((t) => h('li', { text: t })));

  const parts = [];
  if (!i && count > 1) {
    const other = data.statements[1];
    parts.push(h('p.eyebrow', {}, langName(b.lang), ' · ', h('a', { href: '#st-alt', lang: other.lang, dir: other.dir, text: langName(other.lang) })));
  }
  parts.push(h('h1.title', { id: `st-title${sfx}`, text: b.title || main.title }));
  if (b.commitment.length) parts.push(section('commitmentHeading', ...paras(b.commitment)));
  const [note, ...more] = b.reviewNote;
  const review = data.reviewed
    ? h('p', {}, word('reviewLabel'), ': ', h('time', { datetime: data.reviewed, text: formatDay(data.reviewed, b.lang) }), '.', note ? ` ${note}` : '')
    : note ? h('p', { text: note }) : null;
  if (b.standard.length || review) parts.push(section('standardHeading', ...paras(b.standard), review, ...paras(more)));
  if (b.done.length) parts.push(section('doneHeading', items(b.done)));
  if (b.limits.length) parts.push(section('limitsHeading', items(b.limits)));
  const coord = data.coordinator
    ? h('div', { id: `st-coord${sfx}` }, h('h3.field-label', {}, word('coordinatorHeading')), h('p.statement-contact', { text: data.coordinator }))
    : null;
  parts.push(section('reportHeading', ...paras(b.report),
    h('p.statement-contact', { id: `st-contact${sfx}` }, data.contact || word('noContact')), coord));
  return h(`article.statement.stack.reveal.d${i + 1}`, { lang: b.lang, dir: b.dir, id: i ? 'st-alt' : null, 'aria-labelledby': `st-title${sfx}` }, ...parts);
}

/** Replace `root`'s content with the statement (the /api/config `accessibility` object). */
export function renderStatement(root, data) {
  // Coerce to the shape the renderer expects: strings, and arrays of strings.
  const str = (v) => (typeof v === 'string' ? v : '');
  const block = (b) => {
    const out = { lang: str(b?.lang) || 'en', dir: A11Y_DIRS.includes(b?.dir) ? b.dir : 'ltr' };
    for (const [k, f] of Object.entries(STATEMENT_FIELDS)) {
      out[k] = f.items || f.paragraphs ? (Array.isArray(b?.[k]) ? b[k].map(str).filter(Boolean) : []) : str(b?.[k]);
    }
    return out;
  };
  const list = Array.isArray(data?.statements) ? data.statements.slice(0, 2).map(block) : [];
  if (!list.length) return false;
  const d = { contact: str(data.contact), coordinator: str(data.coordinator), reviewed: /^\d{4}-\d{2}-\d{2}$/.test(str(data.reviewed)) ? data.reviewed : '', statements: list };
  clear(root);
  list.forEach((b, i) => root.appendChild(article(b, list[0], d, i, list.length)));
  if (list[0].title) document.title = `${list[0].title} · secbin`;
  root.dataset.ready = 'true';
  return true;
}

if (!globalThis.__SECBIN_STATEMENT_NO_AUTOMOUNT) {
  (async () => {
    const root = document.getElementById('statement');
    if (!root) return;
    let a = null;
    try { a = (await fetchConfig()).accessibility; } catch { /* the default below */ }
    if (!renderStatement(root, a)) renderStatement(root, publicStatement(A11Y_DEFAULTS));
  })();
}
