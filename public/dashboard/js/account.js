// account.js — my limits and quotas, change password (current required;
// stretched locally), API keys (if allowed), and my activity log.

import '../../js/kdf-progress.js';
import { changePassword, listKeys, createKey, revokeKey, myActivity, ApiError } from '../../js/api.js';
import { stretch, newCredential, checkNewPassword } from '../../js/pwauth.js';
import { prelogin } from '../../js/api.js';
import { h, clear, showMsg, armConfirm, wirePeek, formatDate, formatBytes, formatCoarse, friendlyError } from '../../js/common.js';
import { copyText, flashCopied } from '../../js/ui.js';
import { ready } from './nav.js';

const $ = (s) => document.querySelector(s);
let profile;
let lastActivity = null;

(async () => {
  profile = await ready;
  $('#acct-sub').textContent = `Signed in as ${profile.user.username}${profile.user.role === 'owner' ? ' (owner)' : ''}.`;
  renderLimits();
  wirePassword();
  wireKeys();
  loadActivity(true);
  $('#activity-more').onclick = () => loadActivity(false);
})();

function renderLimits() {
  const L = profile.limits;
  const dl = clear($('#acct-limits'));
  const row = (k, v) => { dl.appendChild(h('dt', { text: k })); dl.appendChild(h('dd.mono', { text: v })); };
  const lim = (v, fmt = String) => (v === null ? 'no limit' : fmt(v));
  row('Notes', L.text ? 'allowed' : 'not allowed');
  row('File sharing', L.files ? 'allowed' : 'not allowed');
  row('Max views', lim(L.maxViews));
  row('Unlimited views', L.allowUnlimitedViews ? 'allowed' : 'not allowed');
  row('Max expiry', lim(L.maxExpireSec, formatCoarse));
  row('Max share size', formatBytes(profile.caps.maxShareBytes));
  row('Max file size', lim(L.maxFileBytes, formatBytes));
  row('Max files per share', lim(L.maxFilesPerShare));
  row('In-browser viewer', profile.viewer.enabled ? 'available' : 'off');
  row('API keys', profile.apiKeys.enabled ? `up to ${profile.apiKeys.max}` : 'not allowed');
  const q = clear($('#acct-quotas'));
  if (profile.quotas.length) {
    q.appendChild(h('h3.field-label', { text: 'Quotas' }));
    for (const x of profile.quotas) {
      const what = x.kind === 'all' ? 'shares' : x.kind === 'text' ? 'notes' : 'file shares';
      q.appendChild(h('p.mono', { text: `${x.used} / ${x.max} ${what} per ${x.n}${x.unit}${x.channel === 'api' ? ' (API)' : ''}` }));
    }
  }
}

function wirePassword() {
  wirePeek(['#pw-current', '#pw-current-peek']);
  wirePeek(['#pw-new', '#pw-new-peek'], ['#pw-new2', '#pw-new2-peek']);
  const form = $('#pw-form');
  if (profile.impersonatedBy) {
    form.hidden = true;
    return;
  }
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = $('#pw-msg');
    const btn = $('#pw-btn');
    const bad = checkNewPassword($('#pw-new').value, $('#pw-new2').value);
    if (!$('#pw-current').value) return showMsg(msg, 'Enter your current password.');
    if (bad) return showMsg(msg, bad);
    btn.disabled = true;
    btn.textContent = 'Changing…';
    try {
      const { salt, t } = await prelogin(profile.user.username);
      const current = await stretch($('#pw-current').value, salt, t);
      const cred = await newCredential($('#pw-new').value);
      await changePassword({ current, ...cred });
      form.reset();
      showMsg(msg, 'Password changed. Your other sessions were signed out.', false);
    } catch (err) {
      showMsg(msg, err instanceof ApiError && err.code === 'wrong_password' ? 'The current password is incorrect.' : friendlyError(err));
    } finally {
      btn.disabled = false;
      btn.textContent = 'Change password';
    }
  });
}

function wireKeys() {
  const card = $('#keys-card');
  if (!profile.apiKeys.enabled) {
    $('#keys-sub').textContent = 'API keys are not enabled for your account. Ask the administrator if you need CLI access.';
    $('#key-form').hidden = true;
    return renderKeys();
  }
  if (profile.impersonatedBy) $('#key-form').hidden = true;
  $('#key-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = $('#keys-msg');
    try {
      const life = $('#key-life').value;
      const r = await createKey($('#key-name').value.trim(), life ? Number(life) : null);
      $('#key-new').hidden = false;
      $('#key-new-note').hidden = false;
      $('#key-new-val').textContent = r.key;
      $('#key-copy').onclick = async () => flashCopied($('#key-copy'), (await copyText(r.key)) ? 'copied' : 'failed');
      $('#key-name').value = '';
      msg.hidden = true;
      renderKeys();
    } catch (err) {
      showMsg(msg, friendlyError(err));
    }
  });
  void card;
  renderKeys();
}

async function renderKeys() {
  const body = clear($('#keys-body'));
  try {
    const { keys } = await listKeys();
    for (const k of keys) {
      const rv = h('button.btn.danger', { type: 'button', text: 'Revoke' });
      armConfirm(rv, 'Revoke?', async () => {
        try { await revokeKey(k.id); renderKeys(); } catch (e) { showMsg($('#keys-msg'), friendlyError(e)); }
      });
      body.appendChild(h('tr', {}, h('td', { dataset: { label: 'Name' }, text: k.name }), h('td.mono', { dataset: { label: 'Created' }, text: formatDate(k.created) }),
        h('td.mono', { dataset: { label: 'Last used' }, text: formatDate(k.last_used) }),
        h('td.mono', { dataset: { label: 'Expires' }, text: k.expires ? formatDate(k.expires) : 'never' }), h('td.cell-actions', {}, rv)));
    }
  } catch (e) {
    showMsg($('#keys-msg'), friendlyError(e));
  }
}

async function loadActivity(fresh) {
  const body = $('#activity-body');
  if (fresh) { clear(body); lastActivity = null; }
  try {
    const { rows } = await myActivity(lastActivity);
    for (const r of rows) body.appendChild(h('tr', {}, h('td.mono', { dataset: { label: 'When' }, text: formatDate(r.ts) }),
      h('td.mono', { dataset: { label: 'Action' }, text: r.action }), h('td', { dataset: { label: 'Details' }, text: r.detail })));
    if (rows.length) lastActivity = rows[rows.length - 1].id;
    $('#activity-more').hidden = rows.length < 50;
  } catch { /* non-fatal */ }
}
