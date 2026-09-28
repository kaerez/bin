// shares.js — "My shares": list what I sent (label, type, lifetime, views),
// raise views / extend expiry within my limits, rename labels, revoke now;
// a "Receive" link (reverse share) has an Edit instead (reverse-edit.js: its
// expiry or none, views, limits, CAPTCHA, password and note, as the role
// allows). A share the administrator has locked is shown frozen: no control
// changes it.

import { listShares, updateShare, revokeShare, shareOpens, drive as driveApi } from '../../js/api.js';
import { opensButton } from './receipts.js';
import { h, clear, showMsg, armConfirm, formatDate, formatCoarse, friendlyError, DURATION_UNITS, unitSeconds, unencryptedHint, KIND_NAMES, viewsText, expiresText } from '../../js/common.js';
import { toast, keepFocus } from '../../js/ui.js';
import { ready } from './nav.js';
import { reverseEditForm, saveReverseEdit } from './reverse-edit.js';

const $ = (s) => document.querySelector(s);
let profile;
let offset = 0;
let rows = [];

(async () => {
  profile = await ready;
  let t = null;
  $('#shares-q').addEventListener('input', () => { clearTimeout(t); t = setTimeout(reload, 250); });
  $('#shares-status').addEventListener('change', reload);
  $('#shares-expiry').addEventListener('change', reload);
  $('#shares-more').onclick = () => load(false);
  reload();
})();

/** `focusKey`: the control to put focus back on after the re-render (see render). */
function reload(focusKey = null) {
  offset = 0;
  rows = [];
  load(true, typeof focusKey === 'string' ? focusKey : null);
}

async function load(fresh, focusKey = null) {
  const msg = $('#shares-msg');
  try {
    const qs = new URLSearchParams({ q: $('#shares-q').value.trim(), status: $('#shares-status').value, expiry: $('#shares-expiry').value, offset: String(offset) });
    const r = await listShares(`?${qs}`);
    rows = fresh ? r.rows : rows.concat(r.rows);
    offset = rows.length;
    $('#shares-more').hidden = r.rows.length < 50;
    render(focusKey);
    showMsg(msg, rows.length ? '' : 'Nothing here yet.', false);
  } catch (e) {
    showMsg(msg, friendlyError(e));
  }
}

const now = () => Math.floor(Date.now() / 1000);

/** `focusKey`: where focus goes if the re-render loses it (see keepFocus). */
function render(focusKey = null) {
  // A revoke or an update re-renders the rows: keep focus in the same row.
  const refocus = keepFocus($('#shares-body'), { fallback: $('#view-shares .title'), key: focusKey });
  const body = clear($('#shares-body'));
  for (const [i, r] of rows.entries()) {
    const active = r.status === 'active';
    const views = viewsText(r);
    const expires = expiresText(r, now());
    const locked = !!r.locked;
    const labelIn = h('input.input.label-in', { value: r.label || '', maxlength: '100', 'aria-label': 'Label', placeholder: '(no label)', disabled: locked, dataset: { focusKey: `share:${r.id}:label` } });
    // Shown under the field while it is being edited (see .label-cell in styles.css);
    // aria-describedby announces it on focus either way.
    const labelHint = unencryptedHint(`share-label-hint-${i}`, labelIn);
    labelIn.addEventListener('change', async () => {
      try { await updateShare(r.id, { label: labelIn.value }); r.label = labelIn.value; toast('Label saved.'); } catch (e) { toast(friendlyError(e), { error: true }); labelIn.value = r.label || ''; }
    });
    const actions = h('div.btn-row.row-actions');
    if (active && locked) {
      actions.appendChild(h('span.mono.muted', { text: 'Locked by the administrator — it cannot be changed or revoked.' }));
    } else if (active) {
      // A Receive link: Edit (everything the role lets the user change after making it; reverseEdit off: only the label).
      if (r.kind === 'reverse') {
        if (profile.limits?.reverseEdit !== false) actions.appendChild(h('button.btn', { type: 'button', text: 'Edit', 'aria-label': `Edit ${r.label || 'this upload link'}`, dataset: { focusKey: `share:${r.id}:extend` }, on: { click: () => openReverseEdit(r, tr) } }));
      } else actions.appendChild(h('button.btn', { type: 'button', text: 'Extend', dataset: { focusKey: `share:${r.id}:extend` }, on: { click: () => openExtend(r, tr) } }));
      const rv = h('button.btn.danger', { type: 'button', text: 'Revoke', dataset: { focusKey: `share:${r.id}:revoke` } });
      armConfirm(rv, 'Revoke now — irreversible', async () => {
        rv.disabled = true;
        try { await revokeShare(r.id); r.status = 'revoked'; render(`share:${r.id}:revoke`); toast('Share revoked.'); } catch (e) { rv.disabled = false; rv.focus(); toast(friendlyError(e), { error: true }); }
      });
      actions.appendChild(rv);
    }
    // data-label = the column name, shown per cell in the stacked (<640px) layout.
    const tr = h('tr', { dataset: { status: r.status, focusKey: `share:${r.id}` } },
      h('td', { dataset: { label: 'Label' } }, h('div.label-cell', {}, labelIn, labelHint)),
      h('td.mono', { dataset: { label: 'Type' }, text: KIND_NAMES[r.kind] || 'note' }),
      h('td.mono', { dataset: { label: 'Created' }, text: formatDate(r.created) }),
      h('td.mono', { dataset: { label: 'Expires' }, text: expires }),
      h('td.mono', { dataset: { label: 'Views' }, text: views }),
      h('td', { dataset: { label: 'Opened' } }),
      h('td', { dataset: { label: 'Status' } }, h(`span.pill.${active ? 'ok' : 'bad'}`, { text: r.status }),
        locked ? h('span.pill.warn', { text: 'locked', title: 'Locked by the administrator' }) : null,
        r.captcha ? h('span.pill.captcha-badge', { text: 'CAPTCHA', title: r.kind === 'reverse' ? 'Senders complete a CAPTCHA before uploading' : 'Recipients complete a CAPTCHA before opening' }) : null,
        r.paused ? h('span.pill.warn', { text: 'paused', title: 'Paused when the Drive was started over in the previous release: it does not accept files' }) : null),
      h('td.cell-actions', {}, actions));
    tr.querySelector('td[data-label="Opened"]').appendChild(opensButton(r, () => shareOpens(r.id), 8, tr));
    body.appendChild(tr);
  }
  refocus();
}

let client = null;
/** The Drive client (for a note or a password: sealed with the link's key), opened once, on first need. */
async function driveClient() {
  if (!client) {
    const m = await import('../../js/driveclient.js');
    client = await m.openDrive({ user: { id: profile.user.id, role: profile.user.role, impersonating: !!profile.impersonatedBy } });
  }
  return client;
}

/** A Receive link's Edit row (reverse-edit.js), under its row; again closes it. */
async function openReverseEdit(r, tr) {
  const existing = tr.nextElementSibling;
  if (existing && existing.classList.contains('extend-row')) { existing.remove(); return; }
  const status = h('p.msg', { role: 'status', text: 'Loading this link’s options…' });
  const cell = h('td.cell-full', { colspan: '8' }, h('div.extend-box', {}, status));
  const row = h('tr.extend-row', { dataset: { focusKey: `share:${r.id}:extend` } }, cell);
  tr.after(row);
  let cur;
  try {
    cur = ((await driveApi.reverse()).reverse || []).find((x) => x.id === r.id);
    if (!cur) throw new Error('This link is no longer in your Drive.');
  } catch (e) {
    status.textContent = `Its options could not be loaded: ${friendlyError(e)}`;
    status.classList.add('error');
    return;
  }
  const form = reverseEditForm(cur, profile);
  const msg = h('p.msg.error', { role: 'alert', hidden: true });
  const save = h('button.btn', { type: 'button', text: 'Save changes' });
  save.onclick = async () => {
    msg.hidden = true;
    const o = form.read();
    if (o.error) {
      showMsg(msg, o.error);
      const f = o.field && form.field(o.field);
      if (f) f.focus();
      return;
    }
    save.disabled = true;
    try {
      await saveReverseEdit(r.id, o.patch, { updateShare, driveClient });
      form.clearSecrets();
      toast('Upload link updated.');
      reload(`share:${r.id}:extend`);
    } catch (e) {
      save.disabled = false;
      showMsg(msg, friendlyError(e));
      toast(friendlyError(e), { error: true });
    }
  };
  const cancel = h('button.btn', { type: 'button', text: 'Cancel', on: { click: () => { row.remove(); tr.querySelector('[data-focus-key$=":extend"]')?.focus(); } } });
  cell.firstChild.replaceChildren(
    h('h2.field-label', { text: `Edit ${r.label ? `“${r.label}”` : 'this upload link'}` }),
    form.el,
    h('p.mono.muted', { text: 'The password and the note are encrypted in this browser with the link’s key; the server never sees them. Files already received stay in your Drive.' }),
    h('div.btn-row', {}, save, cancel), msg);
  form.focus();
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
      toast('Share updated.');
      // Apply was disabled while saving (so focus has already left it): back to this share's Extend.
      reload(`share:${r.id}:extend`);
    } catch (e) {
      save.disabled = false;
      showMsg(msg, friendlyError(e));
      toast(friendlyError(e), { error: true });
    }
  };
  const limitsText = `Your limits: ${L.maxViews === null ? 'any number of views' : `up to ${L.maxViews} views`}, `
    + `${L.maxExpireSec === null ? 'expiry up to 365 days' : `expiry up to ${formatCoarse(L.maxExpireSec)} from now`}.`;
  const row = h('tr.extend-row', { dataset: { focusKey: `share:${r.id}:extend` } }, h('td.cell-full', { colspan: '8' },
    h('div.extend-box', {},
      r.kind !== 'files' && r.kind !== 'drive' && r.views_total === null ? null : h('div.toolbar', {}, h('span.field-label', { text: 'Views (new total)' }), views, unlimited),
      h('div.toolbar', {}, h('span.field-label', { text: 'Extend expiry by' }), n, unit),
      h('p.mono.muted', { text: limitsText }),
      h('div.btn-row', {}, save), msg)));
  tr.after(row);
}
