// admin-shares.js — the admin "Shares" tab: every user's shares with filters
// (users, type, status, label, lock, created and expiry date/time ranges or a
// single day), and the same controls a sender has (label, more views, longer
// expiry, revoke) plus lock/unlock. A locked share is frozen for its sender:
// they cannot edit, revoke or delete it with its token — only the admin can.
// Direct admin changes are recorded in the audit log, not in the user's own
// activity (unlike impersonation, which acts as the user).

import { admin } from '../../js/api.js';
import { h, clear, showMsg, armConfirm, formatDate, formatCoarse, friendlyError, DURATION_UNITS, unitSeconds, unencryptedHint } from '../../js/common.js';
import { toast } from '../../js/ui.js';

const PAGE = 50;
const now = () => Math.floor(Date.now() / 1000);

/** A datetime-local value (local time) → unix seconds, or null. */
export function localToUnix(value) {
  if (!value) return null;
  const t = new Date(value).getTime();
  return Number.isFinite(t) ? Math.floor(t / 1000) : null;
}

/** A date (YYYY-MM-DD, local) → [start, end] unix seconds of that local day. */
export function dayRange(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value || '')) return [null, null];
  const [y, m, d] = value.split('-').map(Number);
  const start = new Date(y, m - 1, d, 0, 0, 0).getTime();
  const end = new Date(y, m - 1, d, 23, 59, 59).getTime();
  return [Math.floor(start / 1000), Math.floor(end / 1000)];
}

/** Build the query string for GET /api/private/admin/shares from the filter state. */
export function filterQuery(f, offset = 0) {
  const qs = new URLSearchParams();
  if (f.users.length) qs.set('users', f.users.join(','));
  for (const k of ['kind', 'status', 'q']) if (f[k]) qs.set(k, f[k]);
  if (f.locked === 'true' || f.locked === 'false') qs.set('locked', f.locked);
  const range = (name, day, from, to) => {
    let [a, b] = day ? dayRange(day) : [null, null];
    if (!day) { a = localToUnix(from); b = localToUnix(to); }
    if (a !== null) qs.set(`${name}From`, String(a));
    if (b !== null) qs.set(`${name}To`, String(b));
  };
  range('created', f.createdDay, f.createdFrom, f.createdTo);
  range('expires', f.expiresDay, f.expiresFrom, f.expiresTo);
  qs.set('limit', String(PAGE));
  qs.set('offset', String(offset));
  return qs;
}

export async function renderShares(p) {
  clear(p);
  const users = (await admin.users().catch(() => ({ users: [] }))).users || [];
  const f = { users: [], kind: '', status: '', q: '', locked: '', createdDay: '', createdFrom: '', createdTo: '', expiresDay: '', expiresFrom: '', expiresTo: '' };
  let offset = 0;
  let rows = [];
  let total = 0;

  const userSel = h('select.input.multi', { multiple: true, size: String(Math.min(6, Math.max(3, users.length))), 'aria-label': 'Users (none selected = all)' },
    ...users.map((u) => h('option', { value: u.id, text: u.username })));
  const kind = h('select.input', { 'aria-label': 'Type' }, h('option', { value: '', text: 'any type' }), h('option', { value: 'text', text: 'notes' }), h('option', { value: 'files', text: 'files' }));
  const status = h('select.input', { 'aria-label': 'Status' }, h('option', { value: '', text: 'any status' }),
    ...['active', 'revoked', 'expired', 'consumed', 'deleted', 'ended'].map((s) => h('option', { value: s, text: s })));
  const locked = h('select.input', { 'aria-label': 'Lock' }, h('option', { value: '', text: 'locked or not' }), h('option', { value: 'true', text: 'locked only' }), h('option', { value: 'false', text: 'unlocked only' }));
  const q = h('input.input', { type: 'search', placeholder: 'Search labels', 'aria-label': 'Search labels', maxlength: '100' });
  const dt = (label) => h('input.input', { type: 'datetime-local', 'aria-label': label });
  const day = (label) => h('input.input', { type: 'date', 'aria-label': label });
  const cDay = day('Created on day'); const cFrom = dt('Created from'); const cTo = dt('Created until');
  const eDay = day('Expires on day'); const eFrom = dt('Expires from'); const eTo = dt('Expires until');
  const apply = h('button.btn', { type: 'button', text: 'Apply filters' });
  const reset = h('button.btn', { type: 'button', text: 'Reset' });
  const summary = h('p.mono.muted', { 'aria-live': 'polite' });
  const msg = h('p.msg', { hidden: true });
  const body = h('tbody');
  const more = h('button.btn', { type: 'button', text: 'Load more', hidden: true });

  p.appendChild(h('div.card.stack', {},
    h('h2.section-title', { text: 'All shares' }),
    h('p.subtitle', { text: 'Every user\'s shares. Locking freezes a share for its sender (no edits, no revoke, no delete token) — only you can change it. Your changes here appear in the audit log, not in the user\'s own activity.' }),
    h('div.filters', {},
      h('label.field', {}, h('span.field-label', { text: 'Users' }), userSel),
      h('div.stack', {},
        h('div.toolbar', {}, kind, status, locked),
        q,
        h('fieldset.range', {}, h('legend', { text: 'Created' }), h('div.toolbar', {}, h('span.field-label', { text: 'on' }), cDay, h('span.field-label', { text: 'or from' }), cFrom, h('span.field-label', { text: 'to' }), cTo)),
        h('fieldset.range', {}, h('legend', { text: 'Expires' }), h('div.toolbar', {}, h('span.field-label', { text: 'on' }), eDay, h('span.field-label', { text: 'or from' }), eFrom, h('span.field-label', { text: 'to' }), eTo)),
        h('div.btn-row', {}, apply, reset))),
    summary, msg,
    h('div.table-wrap', {}, h('table.table', {},
      h('thead', {}, h('tr', {}, ...['User', 'Label', 'Type', 'Created', 'Expires', 'Views', 'Status', ''].map((c) => h('th', { text: c })))),
      body)),
    more));

  const read = () => {
    f.users = [...userSel.selectedOptions].map((o) => o.value);
    Object.assign(f, {
      kind: kind.value, status: status.value, locked: locked.value, q: q.value.trim(),
      createdDay: cDay.value, createdFrom: cFrom.value, createdTo: cTo.value,
      expiresDay: eDay.value, expiresFrom: eFrom.value, expiresTo: eTo.value,
    });
  };

  async function load(fresh) {
    if (fresh) { offset = 0; rows = []; }
    try {
      const r = await admin.shares(filterQuery(f, offset));
      rows = rows.concat(r.rows);
      total = r.total;
      offset = rows.length;
      more.hidden = rows.length >= total;
      summary.textContent = `${total} share${total === 1 ? '' : 's'} match${rows.length < total ? ` — showing ${rows.length}` : ''}.`;
      render();
      showMsg(msg, rows.length ? '' : 'No shares match these filters.', false);
    } catch (e) {
      showMsg(msg, friendlyError(e));
    }
  }

  function render() {
    clear(body);
    for (const r of rows) body.appendChild(rowFor(r));
  }

  function rowFor(r) {
    const active = r.status === 'active';
    const views = r.views_total === null || r.views_total === undefined ? 'unlimited' : `${r.left ?? '—'} left of ${r.views_total}`;
    const expires = r.expires ? (active && r.expires > now() ? `in ${formatCoarse(r.expires - now())}` : formatDate(r.expires)) : '—';
    const hintId = `adm-label-hint-${r.id}`;
    const labelIn = h('input.input.label-in', { value: r.label || '', maxlength: '100', 'aria-label': `Label of ${r.id}`, placeholder: '(no label)', 'aria-describedby': hintId });
    labelIn.addEventListener('change', async () => {
      try { await admin.updateShare(r.id, { label: labelIn.value }); r.label = labelIn.value; toast('label saved'); } catch (e) { toast(friendlyError(e)); labelIn.value = r.label || ''; }
    });
    const actions = h('div.btn-row.row-actions');
    const lockBtn = h('button.btn', { type: 'button', text: r.locked ? 'Unlock' : 'Lock' });
    lockBtn.onclick = async () => {
      lockBtn.disabled = true;
      try { const res = await admin.lockShare(r.id, !r.locked); r.locked = res.locked ? 1 : 0; toast(r.locked ? 'locked' : 'unlocked'); render(); } catch (e) { lockBtn.disabled = false; toast(friendlyError(e)); }
    };
    actions.appendChild(lockBtn);
    const tr = h('tr', { dataset: { status: r.status } });
    if (active) {
      actions.appendChild(h('button.btn', { type: 'button', text: 'Extend', on: { click: () => openExtend(r, tr) } }));
      const rv = h('button.btn.danger', { type: 'button', text: 'Revoke' });
      armConfirm(rv, 'Revoke now — irreversible', async () => {
        rv.disabled = true;
        try { await admin.revokeShare(r.id); r.status = 'revoked'; render(); toast('revoked'); } catch (e) { rv.disabled = false; toast(friendlyError(e)); }
      });
      actions.appendChild(rv);
    }
    const statusCell = h('td', { dataset: { label: 'Status' } }, h(`span.pill.${active ? 'ok' : 'bad'}`, { text: r.status }));
    if (r.locked) statusCell.appendChild(h('span.pill.warn', { text: 'locked', title: r.locked_by ? `locked by ${r.locked_by}${r.locked_at ? ` on ${formatDate(r.locked_at)}` : ''}` : 'locked' }));
    tr.append(
      h('td.mono', { dataset: { label: 'User' }, text: r.username || '(deleted user)' }),
      h('td', { dataset: { label: 'Label' } }, labelIn, unencryptedHint(hintId)),
      h('td.mono', { dataset: { label: 'Type' }, text: r.kind === 'files' ? 'files' : 'note' }),
      h('td.mono', { dataset: { label: 'Created' }, text: formatDate(r.created) }),
      h('td.mono', { dataset: { label: 'Expires' }, text: expires }),
      h('td.mono', { dataset: { label: 'Views' }, text: views }),
      statusCell,
      h('td', { dataset: { label: 'Actions' } }, actions));
    return tr;
  }

  function openExtend(r, tr) {
    const existing = tr.nextElementSibling;
    if (existing && existing.classList.contains('extend-row')) { existing.remove(); return; }
    const views = h('input.input.opt-num', { type: 'number', min: String((r.views_total ?? 0) + 1), max: '100000', placeholder: 'total views', 'aria-label': 'New total views' });
    const unlimited = h('label.inline', {}, h('input', { type: 'checkbox', disabled: r.views_total === null }), ' unlimited');
    const n = h('input.input.opt-num', { type: 'number', min: '1', value: '1', 'aria-label': 'Extend by' });
    const unit = h('select.input', { 'aria-label': 'Unit' }, ...DURATION_UNITS.filter(([u]) => u !== 's').map(([u, w]) => h('option', { value: u, text: w, selected: u === 'd' })));
    const emsg = h('p.msg.error', { hidden: true });
    const save = h('button.btn', { type: 'button', text: 'Apply' });
    save.onclick = async () => {
      const patch = {};
      if (unlimited.querySelector('input').checked) patch.views = null;
      else if (views.value) patch.views = Number(views.value);
      const add = Number(n.value) * unitSeconds(unit.value);
      if (add > 0) patch.expires = Math.max(r.expires || now(), now()) + add;
      if (!Object.keys(patch).length) return showMsg(emsg, 'Nothing to change.');
      save.disabled = true;
      try { await admin.updateShare(r.id, patch); toast('updated'); load(true); } catch (e) { save.disabled = false; showMsg(emsg, friendlyError(e)); }
    };
    const row = h('tr.extend-row', {}, h('td', { colspan: '8' },
      h('div.extend-box', {},
        r.kind === 'text' && r.views_total === null ? null : h('div.toolbar', {}, h('span.field-label', { text: 'Views (new total)' }), views, unlimited),
        h('div.toolbar', {}, h('span.field-label', { text: 'Extend expiry by' }), n, unit),
        h('p.mono.muted', { text: 'Admin changes are not bound by the user\'s limits (up to 100000 views and 365 days). Views and expiry can only increase.' }),
        h('div.btn-row', {}, save), emsg)));
    tr.after(row);
  }

  apply.onclick = () => { read(); load(true); };
  reset.onclick = () => {
    for (const o of userSel.options) o.selected = false;
    for (const el of [kind, status, locked]) el.value = '';
    for (const el of [q, cDay, cFrom, cTo, eDay, eFrom, eTo]) el.value = '';
    read();
    load(true);
  };
  q.addEventListener('keydown', (e) => { if (e.key === 'Enter') { read(); load(true); } });
  more.onclick = () => load(false);
  read();
  await load(true);
}
