// shares.js — "My shares": list what I sent (label, type, lifetime, views),
// raise views / extend expiry within my limits, rename labels, revoke now.
// A share the administrator has locked is shown frozen: no control changes it.

import { listShares, updateShare, revokeShare } from '../../js/api.js';
import { h, clear, showMsg, armConfirm, formatDate, formatCoarse, friendlyError, DURATION_UNITS, unitSeconds, unencryptedHint } from '../../js/common.js';
import { toast } from '../../js/ui.js';
import { ready } from './nav.js';

const $ = (s) => document.querySelector(s);
let profile;
let offset = 0;
let rows = [];

(async () => {
  profile = await ready;
  let t = null;
  $('#shares-q').addEventListener('input', () => { clearTimeout(t); t = setTimeout(reload, 250); });
  $('#shares-status').addEventListener('change', reload);
  $('#shares-more').onclick = () => load(false);
  reload();
})();

function reload() {
  offset = 0;
  rows = [];
  load(true);
}

async function load(fresh) {
  const msg = $('#shares-msg');
  try {
    const qs = new URLSearchParams({ q: $('#shares-q').value.trim(), status: $('#shares-status').value, offset: String(offset) });
    const r = await listShares(`?${qs}`);
    rows = fresh ? r.rows : rows.concat(r.rows);
    offset = rows.length;
    $('#shares-more').hidden = r.rows.length < 50;
    render();
    showMsg(msg, rows.length ? '' : 'Nothing here yet.', false);
  } catch (e) {
    showMsg(msg, friendlyError(e));
  }
}

const now = () => Math.floor(Date.now() / 1000);

function render() {
  const body = clear($('#shares-body'));
  for (const [i, r] of rows.entries()) {
    const active = r.status === 'active';
    const views = r.views_total === null || r.views_total === undefined
      ? 'unlimited'
      : `${r.left ?? '—'} left of ${r.views_total}`;
    const expires = r.expires ? (active && r.expires > now() ? `in ${formatCoarse(r.expires - now())}` : formatDate(r.expires)) : '—';
    const locked = !!r.locked;
    const labelIn = h('input.input.label-in', { value: r.label || '', maxlength: '100', 'aria-label': 'Label', placeholder: '(no label)', disabled: locked });
    // Shown under the field while it is being edited (see .label-cell in styles.css);
    // aria-describedby announces it on focus either way.
    const labelHint = unencryptedHint(`share-label-hint-${i}`, labelIn);
    labelIn.addEventListener('change', async () => {
      try { await updateShare(r.id, { label: labelIn.value }); r.label = labelIn.value; toast('label saved'); } catch (e) { toast(friendlyError(e)); labelIn.value = r.label || ''; }
    });
    const actions = h('div.btn-row.row-actions');
    if (active && locked) {
      actions.appendChild(h('span.mono.muted', { text: 'Locked by the administrator — it cannot be changed or revoked.' }));
    } else if (active) {
      actions.appendChild(h('button.btn', { type: 'button', text: 'Extend', on: { click: () => openExtend(r, tr) } }));
      const rv = h('button.btn.danger', { type: 'button', text: 'Revoke' });
      armConfirm(rv, 'Revoke now — irreversible', async () => {
        rv.disabled = true;
        try { await revokeShare(r.id); r.status = 'revoked'; render(); toast('revoked'); } catch (e) { rv.disabled = false; toast(friendlyError(e)); }
      });
      actions.appendChild(rv);
    }
    // data-label = the column name, shown per cell in the stacked (<640px) layout.
    const tr = h('tr', { dataset: { status: r.status } },
      h('td', { dataset: { label: 'Label' } }, h('div.label-cell', {}, labelIn, labelHint)),
      h('td.mono', { dataset: { label: 'Type' }, text: r.kind === 'files' ? 'files' : 'note' }),
      h('td.mono', { dataset: { label: 'Created' }, text: formatDate(r.created) }),
      h('td.mono', { dataset: { label: 'Expires' }, text: expires }),
      h('td.mono', { dataset: { label: 'Views' }, text: views }),
      h('td', { dataset: { label: 'Status' } }, h(`span.pill.${active ? 'ok' : 'bad'}`, { text: r.status }),
        locked ? h('span.pill.warn', { text: 'locked', title: 'Locked by the administrator' }) : null),
      h('td.cell-actions', {}, actions));
    body.appendChild(tr);
  }
}

function openExtend(r, tr) {
  const L = profile.limits;
  const existing = tr.nextElementSibling;
  if (existing && existing.classList.contains('extend-row')) { existing.remove(); return; }
  const views = h('input.input.opt-num', { type: 'number', min: String((r.views_total ?? 0) + 1), max: String(L.maxViews ?? 100000), placeholder: 'total views', 'aria-label': 'New total views' });
  const unlimited = h('label.inline', {}, h('input', { type: 'checkbox', disabled: !L.allowUnlimitedViews || r.views_total === null }), ' unlimited');
  const n = h('input.input.opt-num', { type: 'number', min: '1', value: '1', 'aria-label': 'Extend by' });
  const unit = h('select.input', { 'aria-label': 'Unit' }, ...DURATION_UNITS.filter(([u]) => u !== 's').map(([u, w]) => h('option', { value: u, text: w, selected: u === 'd' })));
  const msg = h('p.msg.error', { hidden: true });
  const save = h('button.btn', { type: 'button', text: 'Apply' });
  save.onclick = async () => {
    const patch = {};
    if (unlimited.querySelector('input').checked) patch.views = null;
    else if (views.value) patch.views = Number(views.value);
    const add = Number(n.value) * unitSeconds(unit.value);
    if (add > 0) patch.expires = Math.max(r.expires || now(), now()) + add;
    if (!Object.keys(patch).length) return showMsg(msg, 'Nothing to change.');
    save.disabled = true;
    try {
      await updateShare(r.id, patch);
      toast('updated');
      reload();
    } catch (e) {
      save.disabled = false;
      showMsg(msg, friendlyError(e));
    }
  };
  const limitsText = `Your limits: ${L.maxViews === null ? 'any number of views' : `up to ${L.maxViews} views`}, `
    + `${L.maxExpireSec === null ? 'expiry up to 365 days' : `expiry up to ${formatCoarse(L.maxExpireSec)} from now`}.`;
  const row = h('tr.extend-row', {}, h('td.cell-full', { colspan: '7' },
    h('div.extend-box', {},
      r.kind === 'text' && (r.views_total === null) ? null : h('div.toolbar', {}, h('span.field-label', { text: 'Views (new total)' }), views, unlimited),
      h('div.toolbar', {}, h('span.field-label', { text: 'Extend expiry by' }), n, unit),
      h('p.mono.muted', { text: limitsText }),
      h('div.btn-row', {}, save), msg)));
  tr.after(row);
}
