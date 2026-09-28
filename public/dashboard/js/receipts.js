// receipts.js — read receipts for a share: every open, newest first. The
// sender sees the time of each open and only the details the administrator
// lets the account see (the server leaves the rest out); the admin sees all.
// Rendered with textContent only (the values come from openers' requests).
// A Receive link's receipts are its upload sessions (a view: one session
// started), shown with the same details.

import { h, formatDate, friendlyError } from '../../js/common.js';

const COLUMNS = [
  [null, 'Opened at', (r) => formatDate(r.ts)],
  ['receiptIp', 'Address', (r) => r.ip || '—'],
  ['receiptLocation', 'Location', (r) => [r.city, r.region, r.country].filter(Boolean).join(', ') || '—'],
  ['receiptBrowser', 'Browser', (r) => [r.browser, r.browser_ver].filter(Boolean).join(' ') || '—'],
  ['receiptOs', 'System', (r) => r.os || '—'],
  ['receiptLanguages', 'Languages', (r) => r.langs || '—'],
];

/**
 * A button showing how many times the share was opened; clicking it toggles a
 * row under `tr` (spanning `colspan` columns) with the list from `load()`.
 * `receive`: a Receive link, whose receipts are its upload sessions.
 */
export function opensButton(share, load, colspan, tr, { receive = false } = {}) {
  const n = share.opens ?? 0;
  const text = receive ? `${n} upload session${n === 1 ? '' : 's'}` : `${n} open${n === 1 ? '' : 's'}`;
  const btn = h('button.btn', { type: 'button', text, 'aria-expanded': 'false' });
  btn.onclick = async () => {
    const next = tr.nextElementSibling;
    if (next && next.classList.contains('opens-row')) { next.remove(); btn.setAttribute('aria-expanded', 'false'); return; }
    const box = h('div.opens-box', {}, h('p.mono.muted', { text: 'Loading…' }));
    tr.after(h('tr.opens-row', {}, h('td.cell-full', { colspan: String(colspan) }, box)));
    btn.setAttribute('aria-expanded', 'true');
    try {
      const d = await load();
      box.replaceChildren(opensTable(d, receive));
    } catch (e) {
      box.replaceChildren(h('p.msg.error', { text: friendlyError(e) }));
    }
  };
  return btn;
}

function opensTable(d, receive = false) {
  if (!d.rows.length) return h('p.mono.muted', { text: receive ? 'No upload session started yet.' : 'Not opened yet.' });
  const cols = COLUMNS.filter(([f]) => f === null || d.fields.includes(f)).map((c) => (c[0] === null && receive ? [null, 'Started at', c[2]] : c));
  const body = h('tbody', {}, ...d.rows.map((r) => h('tr', {}, ...cols.map(([, label, get]) => h('td.mono', { dataset: { label }, text: get(r) })))));
  const note = d.total > d.rows.length ? [h('p.mono.muted', { text: `Showing the latest ${d.rows.length} of ${d.total}.` })] : [];
  const hidden = COLUMNS.filter(([f]) => f !== null && !d.fields.includes(f)).length;
  if (hidden) {
    note.push(h('p.mono.muted', { text: receive
      ? 'Only the time of each upload session is shown for your account; the administrator decides which other details you may see.'
      : 'Only the time of each open is shown for your account; the administrator decides which other details senders may see.' }));
  }
  return h('div', {}, h('div.table-wrap', {}, h('table.table', { 'aria-label': receive ? 'Upload sessions of this link' : 'Opens of this share' },
    h('thead', {}, h('tr', {}, ...cols.map(([, label]) => h('th', { text: label })))), body)), ...note);
}
