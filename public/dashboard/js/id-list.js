// id-list.js — user id lists in Admin → Import / export, shared by the
// account export and import (admin-portable.js) and the Drive keys export
// (admin-keysport.js). An id list is a plain text file of user ids, one per
// line (a JSON array is taken too when uploaded): user ids only, never keys,
// passwords or other credentials, so choosing or saving one changes nothing
// by itself. `idPicker` gives rows that each have a checkbox a search (by user
// name or id), Select all / Deselect all of the rows shown, a count, an
// uploaded id list and a download of the chosen ids. DOM through h() only
// (strict CSP).

import { h, showMsg } from '../../js/common.js';
import { field, fileInput, liveMsg, saveText } from './kit-ui.js';

export const UID_RE = /^[A-Za-z0-9_-]{16}$/;
const MAX_LIST = 1024 * 1024;
export const UPLOAD_LABEL = 'Choose from an id list (user ids only: one per line, or a JSON array)';

/** Ids from an uploaded list: one per line, or a JSON array (anything else ignored). */
export function parseIds(text, re = UID_RE) {
  let list;
  try { list = JSON.parse(text); } catch { list = String(text).split(/[\s,;]+/); }
  if (!Array.isArray(list)) list = [];
  return [...new Set(list.map((x) => String(x).trim()).filter((x) => re.test(x)))];
}

/** Save user ids as a plain text list, one per line. */
export function saveIds(ids) {
  saveText(`${ids.join('\n')}\n`, `secbin-user-ids-${location.hostname}-${new Date().toISOString().slice(0, 10)}.txt`, 'text/plain');
}

/**
 * An id list's upload field: `apply(ids)` (a Set of the valid user ids in the
 * file) does the choosing and returns what to say, in a status line that is
 * in the page from the start. → { input, el (the labelled field), live }.
 */
export function idListUpload(id, apply, label = UPLOAD_LABEL) {
  const input = fileInput(id);
  input.accept = '.txt,.json,text/plain,application/json';
  const { msg, live } = liveMsg(`${id}-msg`);
  input.addEventListener('change', async () => {
    const f = input.files && input.files[0];
    if (!f) return;
    if (f.size > MAX_LIST) { input.value = ''; return showMsg(msg, 'That list is too large (max 1 MiB).'); }
    let text;
    try { text = await f.text(); } catch { input.value = ''; return showMsg(msg, 'That list cannot be read.'); }
    input.value = '';
    showMsg(msg, apply(new Set(parseIds(text))), false);
  });
  return { input, el: field(label, input), live };
}

const idsWord = (n) => `${n} id${n === 1 ? '' : 's'}`;

/**
 * The picker's tools for `rows` ([{ id, name, box, el }]: `box` the row's
 * checkbox, `el` the row, hidden when the search leaves it out). Select all /
 * Deselect all act on the rows shown; an uploaded list chooses exactly the rows
 * whose ids it holds (shown or not). `labels`: { selectAll, deselectAll }
 * (the buttons' names), `download` (the download button's text), `hint` (what
 * the downloaded list is). → { top (search, Select all, Deselect all, count),
 * bottom (the id list: upload, download, hint, status line), chosen(), sync() }.
 */
export function idPicker(rows, { prefix, labels, download, hint }) {
  const search = h('input.input', { type: 'search', id: `${prefix}-search`, placeholder: 'Search by user name or id', maxlength: '64', autocomplete: 'off', spellcheck: 'false' });
  const count = h('span.mono.muted', { id: `${prefix}-count`, role: 'status' });
  const chosen = () => rows.filter((r) => r.box.checked);
  const sync = () => { count.textContent = `${chosen().length} of ${rows.length} chosen`; };
  for (const r of rows) r.box.addEventListener('change', sync);
  search.addEventListener('input', () => {
    const q = search.value.trim().toLowerCase();
    for (const r of rows) r.el.hidden = !!q && !r.name.toLowerCase().includes(q) && !String(r.id ?? '').toLowerCase().includes(q);
  });
  // A change event per box changed, so whatever listens to the boxes (a count, a preview) hears it.
  const tick = (r, on) => {
    if (r.box.disabled || r.box.checked === on) return;
    r.box.checked = on;
    r.box.dispatchEvent(new Event('change', { bubbles: true }));
  };
  const set = (on) => () => { for (const r of rows) if (!r.el.hidden) tick(r, on); sync(); };
  const upload = idListUpload(`${prefix}-ids-file`, (ids) => {
    let hit = 0;
    for (const r of rows) { const on = !!r.id && ids.has(r.id); tick(r, on); if (on) hit++; }
    sync();
    return `${hit} of ${idsWord(ids.size)} in the list are accounts here and are now chosen${ids.size > hit ? '; the others are not on this server' : ''}.`;
  });
  const down = h('button.btn.mini', { type: 'button', id: `${prefix}-ids-save`, text: download, on: { click: () => saveIds(chosen().map((r) => r.id).filter(Boolean)) } });
  sync();
  return {
    chosen,
    sync,
    top: h('div.toolbar', {}, field('Find users', search),
      h('button.btn.mini', { type: 'button', text: 'Select all', 'aria-label': labels.selectAll, on: { click: set(true) } }),
      h('button.btn.mini', { type: 'button', text: 'Deselect all', 'aria-label': labels.deselectAll, on: { click: set(false) } }), count),
    bottom: h('div.stack', {}, h('div.toolbar', {}, upload.el, down), h('p.type-hint', { text: hint }), upload.live),
  };
}
