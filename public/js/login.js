// login.js — /dashboard/login: look up the account's salt, stretch the password
// with Argon2id locally, send only the result. Also: sign in with a passkey
// alone, with a recovery code, or confirm a password login with a passkey /
// recovery code when the account needs a second factor.

import './kdf-progress.js';
import { login, session, ApiError, passkeyLoginOptions, passkeyLogin, recoveryLogin, secondFactor } from './api.js';
import { loginProof } from './pwauth.js';
import { showMsg, markInvalid, wirePeek, friendlyError } from './common.js';
import { humanCheck } from './turnstile.js';
import { passkeysSupported, usePasskeyPrf } from './passkeys.js';
import { DRIVE_PRF_SALT } from './drivekeys.js';
import { unlockAtSignIn } from './driveclient.js';

const $ = (s) => document.querySelector(s);

if (new URLSearchParams(location.search).get('disabled') === '1') {
  showMsg($('#login-msg'), 'Your account has been disabled. Contact the administrator.');
}

(async () => {
  try {
    const s = await session();
    if (s.authenticated) { location.replace('/dashboard/'); return; }
    if (!s.configured) showMsg($('#login-msg'), 'Server not configured: the SIG and ENC secrets must be set before anyone can log in.');
  } catch { /* offline */ }
})();

wirePeek(['#login-pass', '#login-pass-peek']);
// Sign-in buttons stay disabled until the human check (when on) has passed.
// Its note offers the contact for anyone who cannot complete it (turnstile.js).
const check = humanCheck($('#login-turnstile'), 'login', { gate: [$('#login-btn'), $('#passkey-btn')] });

/**
 * Signed in: unlock the Drive for this tab with what was used (the password,
 * a passkey's PRF output, a recovery code — docs/DRIVE.md §3; never blocks the
 * sign-in: the Drive page asks when this fails), then to the dashboard, or to
 * Account when a recovery code was spent.
 */
async function done(r, creds = {}) {
  if (r && r.user && typeof r.user.id === 'string') await unlockAtSignIn({ user: r.user, ...creds });
  $('#login-pass').value = '';
  if (r && typeof r.recoveryLeft === 'number') location.replace(`/dashboard/account/?recovery=${r.recoveryLeft}`);
  else location.replace('/dashboard/');
}

/** Mark the fields a message is about (and only those) invalid, described by it. */
function flag(msg, ...fields) {
  for (const f of document.querySelectorAll('#login-user, #login-pass, #login-code, #second-code')) markInvalid(f, msg, false);
  for (const f of fields) markInvalid(f, msg);
}

function failure(msg, err, fields = []) {
  // "Wrong username or password / recovery code" is about both fields.
  flag(msg, ...(err instanceof ApiError && ['invalid_login', 'invalid_second_factor'].includes(err.code) ? fields : []));
  if (err instanceof ApiError && err.code === 'account_locked') {
    showMsg(msg, `This account is temporarily locked${err.extra.until ? ` until ${new Date(err.extra.until * 1000).toLocaleTimeString()}` : ''}.`);
  } else {
    showMsg(msg, friendlyError(err));
  }
}

// ── recovery-code mode (instead of the password) ───────────────────────────
let recoveryMode = false;
$('#recovery-toggle').addEventListener('click', () => {
  recoveryMode = !recoveryMode;
  $('#login-pass-block').hidden = recoveryMode;
  $('#login-code-block').hidden = !recoveryMode;
  $('#recovery-toggle').textContent = recoveryMode ? 'Use my password instead' : 'Use a recovery code instead';
  $('#login-btn').textContent = recoveryMode ? 'Log in with the code' : 'Log in';
  (recoveryMode ? $('#login-code') : $('#login-pass')).focus();
});

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('#login-btn');
  const msg = $('#login-msg');
  const label = btn.textContent;
  const username = $('#login-user').value.trim();
  const password = $('#login-pass').value;
  const code = $('#login-code').value.trim();
  const secret = recoveryMode ? $('#login-code') : $('#login-pass');
  if (!username || (recoveryMode ? !code : !password)) {
    showMsg(msg, recoveryMode ? 'Enter your username and a recovery code.' : 'Enter your username and password.');
    const missing = [!username && $('#login-user'), !secret.value.trim() && secret].filter(Boolean);
    flag(msg, ...missing);
    missing[0].focus();
    return;
  }
  btn.disabled = true;
  btn.textContent = 'Signing in…';
  msg.hidden = true;
  flag(msg);
  try {
    const token = await (await check).take();
    if (recoveryMode) { await done(await recoveryLogin(username, code, token), { code }); return; }
    const r = await login(username, await loginProof(username, password), token);
    if (r.secondFactor) { startSecond(r.secondFactor, password); return; }
    await done(r, { password });
  } catch (err) {
    failure(msg, err, [$('#login-user'), secret]);
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
});

// ── a passkey alone ────────────────────────────────────────────────────────
if (passkeysSupported()) {
  const pk = $('#passkey-btn');
  pk.hidden = false;
  pk.addEventListener('click', async () => {
    const msg = $('#login-msg');
    pk.disabled = true;
    msg.hidden = true;
    try {
      const token = await (await check).take();
      const o = await passkeyLoginOptions();
      const { credential, prf } = await usePasskeyPrf(o.publicKey, DRIVE_PRF_SALT);
      await done(await passkeyLogin(o.challengeId, credential, token), prf ? { prfOutput: prf, credentialId: credential.rawId } : {});
    } catch (err) {
      failure(msg, err);
    } finally {
      pk.disabled = false;
    }
  });
}

// ── second step: the password was right; now a passkey or recovery code ───
let pending = null;
let pendingPassword = ''; // kept (in memory only) to unlock the Drive once signed in
function startSecond(sf, password) {
  pending = sf;
  pendingPassword = password;
  $('#login-form').hidden = true;
  $('#second-form').hidden = false;
  $('#second-msg').hidden = true;
  $('#second-passkey').hidden = !passkeysSupported();
  (passkeysSupported() ? $('#second-passkey') : $('#second-code')).focus();
}
function startOver(text) {
  pending = null;
  pendingPassword = '';
  $('#second-form').hidden = true;
  $('#login-form').hidden = false;
  $('#login-pass').value = '';
  $('#login-pass').focus();
  if (text) showMsg($('#login-msg'), text);
}
async function second(body, btn, creds = {}) {
  const msg = $('#second-msg');
  btn.disabled = true;
  msg.hidden = true;
  try {
    const r = await secondFactor({ challengeId: pending.challengeId, ...body });
    const password = pendingPassword;
    pendingPassword = '';
    await done(r, { password, ...(body.code ? { code: body.code } : {}), ...creds });
  } catch (err) {
    if (err instanceof ApiError && err.code === 'challenge_expired') startOver(err.message);
    else failure(msg, err, body.code ? [$('#second-code')] : []);
  } finally {
    btn.disabled = false;
  }
}
$('#second-passkey').addEventListener('click', async () => {
  const btn = $('#second-passkey');
  try {
    const { credential, prf } = await usePasskeyPrf(pending.publicKey, DRIVE_PRF_SALT);
    await second({ credential }, btn, prf ? { prfOutput: prf, credentialId: credential.rawId } : {});
  } catch (err) {
    showMsg($('#second-msg'), friendlyError(err));
  }
});
$('#second-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const code = $('#second-code').value.trim();
  if (!code) { showMsg($('#second-msg'), 'Enter a recovery code, or use your passkey.'); flag($('#second-msg'), $('#second-code')); $('#second-code').focus(); return; }
  second({ code }, $('#second-code-btn'));
});
$('#second-back').addEventListener('click', () => startOver());
