// account.js — my limits and quotas, username, password, passkeys and
// recovery codes, API keys (if allowed), and my activity log. Every change
// is confirmed with the password (stretched locally) or, for an account with
// a passkey, a fresh passkey check; the password is asked again every time.

import '../../js/kdf-progress.js';
import { changePassword, listKeys, createKey, updateKey, revokeKey, myActivity, ApiError, myPasskeys, passkeyRegisterOptions, addPasskey, removePasskey, regenerateRecoveryCodes, setSecondFactor, changeUsername } from '../../js/api.js';
import { passkeysSupported, createPasskey } from '../../js/passkeys.js';
import { confirmStep as confirmWith, confirmLabel } from './confirm.js';
import { newCredential, checkNewPassword, checkOwnerPassword, describePolicy } from '../../js/pwauth.js';
import { h, clear, showMsg, armConfirm, wirePeek, formatDate, formatBytes, formatCoarse, friendlyError } from '../../js/common.js';
import { copyText, flashCopied, toast, keepFocus } from '../../js/ui.js';
import { ready } from './nav.js';
import { humanCheck } from '../../js/turnstile.js';

const $ = (s) => document.querySelector(s);
let profile;
let lastActivity = null;
let hasPasskey = false; // kept current by renderPasskeys()

const CONFIRM_FIELDS = [['#name-current', 'Your password'], ['#pw-current', 'Current password'],
  ['#passkey-current', 'Your password (asked again for every change)'], ['#key-current', 'Your password (asked again for every change)']];

/** Labels say that an empty password field means "use a passkey". */
function labelConfirmFields() {
  const alt = hasPasskey && passkeysSupported();
  for (const [sel, text] of CONFIRM_FIELDS) {
    const label = $(`${sel}-label`);
    if (label) label.textContent = confirmLabel(text, alt);
  }
}

/** The confirmation for one change (see confirm.js). */
const confirmStep = (input) => confirmWith(input, profile.user.username, hasPasskey);

const refusal = (e) => (e instanceof ApiError && e.code === 'wrong_password' ? 'The password is incorrect.'
  : e instanceof ApiError && e.code === 'reauth_failed' ? 'The passkey could not be verified.' : friendlyError(e));

(async () => {
  profile = await ready;
  renderSub();
  renderLimits();
  wireUsername();
  wirePassword();
  wirePasskeys();
  wireKeys();
  loadActivity(true);
  $('#activity-more').onclick = () => loadActivity(false);
})();

function renderSub() {
  $('#acct-sub').textContent = `Signed in as ${profile.user.username}${profile.user.role === 'owner' ? ' (owner)' : ''}.`;
}

function wireUsername() {
  const form = $('#name-form');
  if (profile.impersonatedBy) { form.hidden = true; return; }
  $('#name-new').value = profile.user.username;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = $('#name-msg');
    const btn = $('#name-btn');
    const name = $('#name-new').value.trim();
    if (!name) return showMsg(msg, 'Enter the new username.');
    btn.disabled = true;
    try {
      const r = await changeUsername(name, await confirmStep($('#name-current')));
      profile.user.username = r.username;
      renderSub();
      showMsg(msg, `Your username is now ${r.username}. Use it the next time you sign in.`, false);
      toast('Username changed.');
    } catch (err) {
      const text = err instanceof ApiError && err.code === 'username_taken' ? 'That username is taken.' : refusal(err);
      showMsg(msg, text);
      toast(text, { error: true });
    } finally {
      btn.disabled = false;
    }
  });
}

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
  // The policy the administrator set for this account (checked here only:
  // the server never sees the password).
  // The owner sets their own password freely; everyone else follows the policy.
  const policy = profile.user.role === 'owner' ? null : profile.passwordPolicy;
  $('#pw-new-label').textContent = 'New password';
  $('#pw-policy').textContent = policy ? describePolicy(policy) : 'As the owner, you choose any password.';
  if (profile.impersonatedBy) {
    form.hidden = true;
    return;
  }
  const check = humanCheck($('#pw-turnstile'), 'password', { gate: [$('#pw-btn')] });
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = $('#pw-msg');
    const btn = $('#pw-btn');
    const bad = policy ? checkNewPassword($('#pw-new').value, $('#pw-new2').value, policy) : checkOwnerPassword($('#pw-new').value, $('#pw-new2').value);
    if (bad) return showMsg(msg, bad);
    btn.disabled = true;
    btn.textContent = 'Changing…';
    try {
      const step = await confirmStep($('#pw-current'));
      const token = await (await check).take();
      const cred = await newCredential($('#pw-new').value);
      const r = await changePassword({ ...step, ...cred }, token);
      form.reset();
      // Passkeys and recovery codes are not tied to the password.
      const still = r.passkeys ? ` Your ${r.passkeys} passkey${r.passkeys === 1 ? '' : 's'} and ${r.recoveryLeft} recovery code${r.recoveryLeft === 1 ? '' : 's'} still work: if someone else may have had access, remove any passkey you do not recognise and create new recovery codes below.` : '';
      showMsg(msg, `Password changed. Your other sessions were signed out.${still}`, false);
      toast('Password changed. Your other sessions were signed out.');
    } catch (err) {
      const text = refusal(err);
      showMsg(msg, text);
      toast(text, { error: true });
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
  if (profile.impersonatedBy) { $('#key-form').hidden = true; $('#key-confirm').hidden = true; }
  $('#key-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = $('#keys-msg');
    try {
      const life = $('#key-life').value;
      const scopes = [...document.querySelectorAll('input[name="key-scope"]:checked')].map((c) => c.value);
      if (!scopes.length) { showMsg(msg, 'Choose at least one thing the key may do.'); return; }
      const r = await createKey($('#key-name').value.trim(), life ? Number(life) : null, scopes, await confirmStep($('#key-current')));
      $('#key-new').hidden = false;
      $('#key-new-note').hidden = false;
      $('#key-new-val').textContent = r.key;
      $('#key-copy').onclick = async () => flashCopied($('#key-copy'), (await copyText(r.key)) ? 'copied' : 'failed');
      $('#key-name').value = '';
      msg.hidden = true;
      toast('API key created. Copy it now: it is shown only once.');
      renderKeys();
    } catch (err) {
      showMsg(msg, refusal(err));
      toast(refusal(err), { error: true });
    }
  });
  // A copy-pasteable example with this server's address (no key in it).
  $('#api-example-policy').textContent = `curl -H "Authorization: Bearer $SECBIN_API_KEY" ${location.origin}/api/private/policy`;
  void card;
  renderKeys();
}

const KEY_SCOPES = [['notes', 'create notes'], ['files', 'upload files'], ['policy', 'read my policy']];

async function keyChange(fn, done) {
  const msg = $('#keys-msg');
  try {
    await fn(await confirmStep($('#key-current')));
    msg.hidden = true;
    toast(done);
    renderKeys();
  } catch (e) {
    showMsg(msg, refusal(e));
    toast(refusal(e), { error: true });
  }
}

/** An inline editor under a key's row: its name and scopes. */
function editKeyRow(k, tr) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains('key-edit-row')) { next.remove(); return; }
  const name = h('input.input', { value: k.name, maxlength: '100', 'aria-label': 'Key name' });
  const boxes = KEY_SCOPES.map(([v, t]) => h('input', { type: 'checkbox', value: v, checked: (k.scopes || []).includes(v), 'aria-label': t }));
  const save = h('button.btn', { type: 'button', text: 'Save' });
  save.onclick = () => {
    const scopes = boxes.filter((b) => b.checked).map((b) => b.value);
    if (!scopes.length) return showMsg($('#keys-msg'), 'Choose at least one thing the key may do.');
    return keyChange((step) => updateKey(k.id, { name: name.value.trim(), scopes }, step), 'API key updated.');
  };
  tr.after(h('tr.key-edit-row', { dataset: { focusKey: `key:${k.id}:edit` } }, h('td.cell-full', { colspan: '6' }, h('div.toolbar', {}, name,
    h('fieldset.key-scopes', { 'aria-label': 'What the key may do' }, ...boxes.map((b, i) => h('label.inline', {}, b, ` ${KEY_SCOPES[i][1]}`))), save))));
}

async function renderKeys() {
  // A revoke or an edit re-renders the table: focus goes back to the key's
  // row, or to the card's heading when the row is gone.
  const refocus = keepFocus($('#keys-body'), { fallback: $('#keys-card .section-title') });
  const body = clear($('#keys-body'));
  try {
    const { keys } = await listKeys();
    for (const k of keys) {
      const actions = h('div.btn-row.row-actions');
      const tr = h('tr', { dataset: { focusKey: `key:${k.id}` } }, h('td', { dataset: { label: 'Name' }, text: k.name }), h('td.mono', { dataset: { label: 'Created' }, text: formatDate(k.created) }),
        h('td.mono', { dataset: { label: 'Last used' }, text: formatDate(k.last_used) }),
        h('td.mono', { dataset: { label: 'Expires' }, text: k.expires ? formatDate(k.expires) : 'never' }),
        h('td.mono', { dataset: { label: 'Scopes' }, text: (k.scopes || []).join(', ') || '—' }), h('td.cell-actions', {}, actions));
      if (!profile.impersonatedBy) {
        actions.appendChild(h('button.btn', { type: 'button', text: 'Edit', dataset: { focusKey: `key:${k.id}:edit` }, on: { click: () => editKeyRow(k, tr) } }));
        const rv = h('button.btn.danger', { type: 'button', text: 'Revoke', dataset: { focusKey: `key:${k.id}:revoke` } });
        armConfirm(rv, 'Revoke?', () => keyChange((step) => revokeKey(k.id, step), 'API key revoked.'));
        actions.appendChild(rv);
      }
      body.appendChild(tr);
    }
  } catch (e) {
    showMsg($('#keys-msg'), friendlyError(e));
  }
  refocus();
}

// ── passkeys and recovery codes ────────────────────────────────────────────
const MODE_TEXT = {
  any: 'Sign in with your password or a passkey, or require both. A recovery code always signs you in on its own.',
  second: 'The administrator allows passkeys only as a second step: once you add one, you sign in with your password and a passkey. A recovery code always signs you in on its own.',
};


function showCodes(codes) {
  const list = clear($('#recovery-list'));
  for (const c of codes) list.appendChild(h('li', { text: c }));
  $('#recovery-new').hidden = false;
  const text = `secbin recovery codes for ${profile.user.username} (${location.host})\nEach works once in place of a passkey.\n\n${codes.join('\n')}\n`;
  $('#recovery-copy').onclick = async () => { await copyText(codes.join('\n')); toast('Recovery codes copied.'); };
  $('#recovery-download').onclick = () => {
    const url = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    const a = h('a', { href: url, download: `secbin-recovery-codes-${profile.user.username}.txt` });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  $('#recovery-new').scrollIntoView({ block: 'nearest' });
}

async function passkeyAction(fn, done) {
  const msg = $('#passkeys-msg');
  msg.hidden = true;
  try {
    const r = await fn(await confirmStep($('#passkey-current')));
    if (done) done(r);
    await renderPasskeys();
  } catch (e) {
    const text = refusal(e);
    showMsg(msg, text);
    toast(text, { error: true });
  }
}

async function renderPasskeys() {
  const refocus = keepFocus($('#passkeys-body'), { fallback: $('#passkeys-card .section-title') });
  const body = clear($('#passkeys-body'));
  let st;
  try { st = await myPasskeys(); } catch (e) { showMsg($('#passkeys-msg'), friendlyError(e)); refocus(); return; }
  for (const p of st.passkeys) {
    const rm = h('button.btn.danger', { type: 'button', text: 'Remove' });
    armConfirm(rm, st.passkeys.length === 1 ? 'Remove (and its recovery codes)?' : 'Remove?', () => passkeyAction(
      (step) => removePasskey(p.id, step), () => toast('Passkey removed.'),
    ));
    body.appendChild(h('tr', {}, h('td', { dataset: { label: 'Name' }, text: p.name }), h('td.mono', { dataset: { label: 'Added' }, text: formatDate(p.created) }),
      h('td.mono', { dataset: { label: 'Last used' }, text: formatDate(p.lastUsed) }), h('td.mono', { dataset: { label: 'Synced' }, text: p.synced ? 'yes' : 'this device only' }),
      h('td.cell-actions', {}, rm)));
  }
  if (!st.passkeys.length) body.appendChild(h('tr', {}, h('td.muted', { colspan: '5', text: 'No passkeys yet.' })));
  const has = st.passkeys.length > 0;
  hasPasskey = has && st.mode !== 'off';
  labelConfirmFields();
  $('#passkeys-sub').textContent = MODE_TEXT[st.mode] || $('#passkeys-sub').textContent;
  // The choice is offered in mode "any"; it needs a passkey to turn on.
  $('#mfa-row').hidden = st.mode !== 'any' || !!profile.impersonatedBy;
  $('#mfa-on').disabled = !has;
  $(st.mfa ? '#mfa-on' : '#mfa-off').checked = true;
  $('#recovery-status').textContent = has
    ? `${st.recoveryLeft} of 20 recovery codes left.${st.required ? ' You sign in with your password and a passkey (or a code).' : ''}`
    : 'Adding your first passkey gives you 20 one-time recovery codes.';
  $('#recovery-regen').hidden = !has;
  $('#passkey-add').disabled = st.passkeys.length >= st.max;
  refocus();
}

function wirePasskeys() {
  const card = $('#passkeys-card');
  const mode = profile.passkeys?.mode || 'off';
  if (mode === 'off') {
    $('#passkeys-sub').textContent = 'Passkeys are not enabled for your account.';
    $('#passkeys-actions').hidden = true;
    return renderPasskeys();
  }
  const left = new URLSearchParams(location.search).get('recovery');
  if (left !== null && /^\d+$/.test(left)) {
    showMsg($('#recovery-used'), `You signed in with a recovery code; ${left} left. If you lost your passkey, remove it and add a new one, or create new codes.`, false);
  }
  if (profile.impersonatedBy) { $('#passkeys-actions').hidden = true; return renderPasskeys(); }
  if (!passkeysSupported()) {
    $('#passkey-form').hidden = true;
    card.querySelector('#passkeys-sub').textContent += ' This browser cannot create passkeys.';
  }
  $('#passkey-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const name = $('#passkey-name').value.trim() || 'Passkey';
    passkeyAction(async (step) => {
      const o = await passkeyRegisterOptions();
      const credential = await createPasskey(o.publicKey);
      return addPasskey({ challengeId: o.challengeId, credential, name, ...step });
    }, (r) => {
      $('#passkey-name').value = '';
      toast('Passkey added.');
      if (r.codes) showCodes(r.codes);
    });
  });
  for (const radio of ['#mfa-off', '#mfa-on']) {
    $(radio).addEventListener('change', (e) => {
      if (!e.target.checked) return;
      const on = e.target.value === 'on';
      passkeyAction((step) => setSecondFactor(on, step), () => toast(on ? 'You now sign in with your password and a passkey.' : 'Your password or a passkey signs you in again.'))
        .finally(() => renderPasskeys());
    });
  }
  armConfirm($('#recovery-regen'), 'Replace all codes?', () => passkeyAction(
    (step) => regenerateRecoveryCodes(step), (r) => { toast('New recovery codes created; the old ones no longer work.'); showCodes(r.codes); },
  ));
  return renderPasskeys();
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
