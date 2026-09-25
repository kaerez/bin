// account.js — my limits and quotas, change password (current required;
// stretched locally), passkeys and recovery codes, API keys (if allowed), and
// my activity log.

import '../../js/kdf-progress.js';
import { changePassword, listKeys, createKey, revokeKey, myActivity, ApiError, myPasskeys, passkeyRegisterOptions, addPasskey, removePasskey, regenerateRecoveryCodes, setSecondFactor } from '../../js/api.js';
import { passkeysSupported, createPasskey } from '../../js/passkeys.js';
import { stretch, newCredential, checkNewPassword, describePolicy } from '../../js/pwauth.js';
import { prelogin } from '../../js/api.js';
import { h, clear, showMsg, armConfirm, wirePeek, formatDate, formatBytes, formatCoarse, friendlyError } from '../../js/common.js';
import { copyText, flashCopied, toast } from '../../js/ui.js';
import { ready } from './nav.js';
import { humanCheck } from '../../js/turnstile.js';

const $ = (s) => document.querySelector(s);
let profile;
let lastActivity = null;

(async () => {
  profile = await ready;
  $('#acct-sub').textContent = `Signed in as ${profile.user.username}${profile.user.role === 'owner' ? ' (owner)' : ''}.`;
  renderLimits();
  wirePassword();
  wirePasskeys();
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
  // The policy the administrator set for this account (checked here only:
  // the server never sees the password).
  const rule = describePolicy(profile.passwordPolicy);
  $('#pw-new-label').textContent = 'New password';
  $('#pw-policy').textContent = rule;
  if (profile.impersonatedBy) {
    form.hidden = true;
    return;
  }
  const check = humanCheck($('#pw-turnstile'), 'password');
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = $('#pw-msg');
    const btn = $('#pw-btn');
    const bad = checkNewPassword($('#pw-new').value, $('#pw-new2').value, profile.passwordPolicy);
    if (!$('#pw-current').value) return showMsg(msg, 'Enter your current password.');
    if (bad) return showMsg(msg, bad);
    btn.disabled = true;
    btn.textContent = 'Changing…';
    try {
      const token = await (await check).take();
      const { salt, t } = await prelogin(profile.user.username);
      const current = await stretch($('#pw-current').value, salt, t);
      const cred = await newCredential($('#pw-new').value);
      await changePassword({ current, ...cred }, token);
      form.reset();
      showMsg(msg, 'Password changed. Your other sessions were signed out.', false);
      toast('Password changed. Your other sessions were signed out.');
    } catch (err) {
      const text = err instanceof ApiError && err.code === 'wrong_password' ? 'The current password is incorrect.' : friendlyError(err);
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
  if (profile.impersonatedBy) $('#key-form').hidden = true;
  $('#key-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const msg = $('#keys-msg');
    try {
      const life = $('#key-life').value;
      const scopes = [...document.querySelectorAll('input[name="key-scope"]:checked')].map((c) => c.value);
      if (!scopes.length) { showMsg(msg, 'Choose at least one thing the key may do.'); return; }
      const r = await createKey($('#key-name').value.trim(), life ? Number(life) : null, scopes);
      $('#key-new').hidden = false;
      $('#key-new-note').hidden = false;
      $('#key-new-val').textContent = r.key;
      $('#key-copy').onclick = async () => flashCopied($('#key-copy'), (await copyText(r.key)) ? 'copied' : 'failed');
      $('#key-name').value = '';
      msg.hidden = true;
      toast('API key created. Copy it now: it is shown only once.');
      renderKeys();
    } catch (err) {
      showMsg(msg, friendlyError(err));
      toast(friendlyError(err), { error: true });
    }
  });
  // A copy-pasteable example with this server's address (no key in it).
  $('#api-example-policy').textContent = `curl -H "Authorization: Bearer $SECBIN_API_KEY" ${location.origin}/api/private/policy`;
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
        try { await revokeKey(k.id); toast('API key revoked.'); renderKeys(); } catch (e) { showMsg($('#keys-msg'), friendlyError(e)); toast(friendlyError(e), { error: true }); }
      });
      body.appendChild(h('tr', {}, h('td', { dataset: { label: 'Name' }, text: k.name }), h('td.mono', { dataset: { label: 'Created' }, text: formatDate(k.created) }),
        h('td.mono', { dataset: { label: 'Last used' }, text: formatDate(k.last_used) }),
        h('td.mono', { dataset: { label: 'Expires' }, text: k.expires ? formatDate(k.expires) : 'never' }),
        h('td.mono', { dataset: { label: 'Scopes' }, text: (k.scopes || []).join(', ') || '—' }), h('td.cell-actions', {}, rv)));
    }
  } catch (e) {
    showMsg($('#keys-msg'), friendlyError(e));
  }
}

// ── passkeys and recovery codes ────────────────────────────────────────────
const MODE_TEXT = {
  any: 'Sign in with a passkey alone, or require it after your password.',
  second: 'The administrator allows passkeys only as a second step: once you add one, every password login asks for it.',
};

/** The current password as a proof (the server checks it for every change here). */
async function currentProof() {
  const pw = $('#passkey-current').value;
  if (!pw) throw new Error('Enter your current password first.');
  const { salt, t } = await prelogin(profile.user.username);
  return stretch(pw, salt, t);
}

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
    const r = await fn(await currentProof());
    if (done) done(r);
    await renderPasskeys();
  } catch (e) {
    const text = e instanceof ApiError && e.code === 'wrong_password' ? 'The current password is incorrect.' : friendlyError(e);
    showMsg(msg, text);
    toast(text, { error: true });
  }
}

async function renderPasskeys() {
  const body = clear($('#passkeys-body'));
  let st;
  try { st = await myPasskeys(); } catch (e) { showMsg($('#passkeys-msg'), friendlyError(e)); return; }
  for (const p of st.passkeys) {
    const rm = h('button.btn.danger', { type: 'button', text: 'Remove' });
    armConfirm(rm, st.passkeys.length === 1 ? 'Remove (and its recovery codes)?' : 'Remove?', () => passkeyAction(
      (current) => removePasskey(p.id, current), () => toast('Passkey removed.'),
    ));
    body.appendChild(h('tr', {}, h('td', { dataset: { label: 'Name' }, text: p.name }), h('td.mono', { dataset: { label: 'Added' }, text: formatDate(p.created) }),
      h('td.mono', { dataset: { label: 'Last used' }, text: formatDate(p.lastUsed) }), h('td.mono', { dataset: { label: 'Synced' }, text: p.synced ? 'yes' : 'this device only' }),
      h('td.cell-actions', {}, rm)));
  }
  if (!st.passkeys.length) body.appendChild(h('tr', {}, h('td.muted', { colspan: '5', text: 'No passkeys yet.' })));
  const has = st.passkeys.length > 0;
  $('#passkeys-sub').textContent = MODE_TEXT[st.mode] || $('#passkeys-sub').textContent;
  $('#mfa-row').hidden = st.mode !== 'any' || !has;
  $('#mfa-toggle').checked = st.mfa;
  $('#recovery-status').textContent = has
    ? `${st.recoveryLeft} of 20 recovery codes left.${st.required ? ' Password logins ask for a passkey or a code.' : ''}`
    : 'Adding your first passkey gives you 20 one-time recovery codes.';
  $('#recovery-regen').hidden = !has;
  $('#passkey-add').disabled = st.passkeys.length >= st.max;
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
    passkeyAction(async (current) => {
      const o = await passkeyRegisterOptions();
      const credential = await createPasskey(o.publicKey);
      return addPasskey({ challengeId: o.challengeId, credential, name, current });
    }, (r) => {
      $('#passkey-name').value = '';
      toast('Passkey added.');
      if (r.codes) showCodes(r.codes);
    });
  });
  $('#mfa-toggle').addEventListener('change', (e) => {
    const on = e.target.checked;
    passkeyAction((current) => setSecondFactor(on, current), () => toast(on ? 'Password logins now also need a passkey.' : 'A password alone signs you in again.'))
      .finally(() => renderPasskeys());
  });
  armConfirm($('#recovery-regen'), 'Replace all codes?', () => passkeyAction(
    (current) => regenerateRecoveryCodes(current), (r) => { toast('New recovery codes created; the old ones no longer work.'); showCodes(r.codes); },
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
