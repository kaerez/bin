// login.js — /dashboard/login: look up the account's salt, stretch the password
// with Argon2id locally, send only the result. Also: sign in with a passkey
// alone, with a recovery code, or confirm a password login with a passkey /
// recovery code when the account needs a second factor.

import './kdf-progress.js';
import { login, session, ApiError, passkeyLoginOptions, passkeyLogin, recoveryLogin, secondFactor } from './api.js';
import { loginProof } from './pwauth.js';
import { showMsg, wirePeek, friendlyError } from './common.js';
import { humanCheck } from './turnstile.js';
import { passkeysSupported, usePasskey } from './passkeys.js';

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
const check = humanCheck($('#login-turnstile'), 'login');

/** Signed in: to the dashboard, or to Account when a recovery code was spent. */
function done(r) {
  $('#login-pass').value = '';
  if (r && typeof r.recoveryLeft === 'number') location.replace(`/dashboard/account/?recovery=${r.recoveryLeft}`);
  else location.replace('/dashboard/');
}

function failure(msg, err) {
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
  $('#recovery-toggle').setAttribute('aria-pressed', String(recoveryMode));
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
  if (!username || (recoveryMode ? !code : !password)) {
    showMsg(msg, recoveryMode ? 'Enter your username and a recovery code.' : 'Enter your username and password.');
    return;
  }
  btn.disabled = true;
  btn.textContent = 'Signing in…';
  msg.hidden = true;
  try {
    const token = await (await check).take();
    if (recoveryMode) { done(await recoveryLogin(username, code, token)); return; }
    const r = await login(username, await loginProof(username, password), token);
    if (r.secondFactor) { startSecond(r.secondFactor); return; }
    done(r);
  } catch (err) {
    failure(msg, err);
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
      done(await passkeyLogin(o.challengeId, await usePasskey(o.publicKey), token));
    } catch (err) {
      failure(msg, err);
    } finally {
      pk.disabled = false;
    }
  });
}

// ── second step: the password was right; now a passkey or recovery code ───
let pending = null;
function startSecond(sf) {
  pending = sf;
  $('#login-form').hidden = true;
  $('#second-form').hidden = false;
  $('#second-msg').hidden = true;
  $('#second-passkey').hidden = !passkeysSupported();
  (passkeysSupported() ? $('#second-passkey') : $('#second-code')).focus();
}
function startOver(text) {
  pending = null;
  $('#second-form').hidden = true;
  $('#login-form').hidden = false;
  $('#login-pass').value = '';
  $('#login-pass').focus();
  if (text) showMsg($('#login-msg'), text);
}
async function second(body, btn) {
  const msg = $('#second-msg');
  btn.disabled = true;
  msg.hidden = true;
  try {
    done(await secondFactor({ challengeId: pending.challengeId, ...body }));
  } catch (err) {
    if (err instanceof ApiError && err.code === 'challenge_expired') startOver(err.message);
    else failure(msg, err);
  } finally {
    btn.disabled = false;
  }
}
$('#second-passkey').addEventListener('click', async () => {
  const btn = $('#second-passkey');
  try {
    const credential = await usePasskey(pending.publicKey);
    await second({ credential }, btn);
  } catch (err) {
    showMsg($('#second-msg'), friendlyError(err));
  }
});
$('#second-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const code = $('#second-code').value.trim();
  if (!code) { showMsg($('#second-msg'), 'Enter a recovery code, or use your passkey.'); return; }
  second({ code }, $('#second-code-btn'));
});
$('#second-back').addEventListener('click', () => startOver());
