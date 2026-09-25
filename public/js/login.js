// login.js — /dashboard/login: look up the account's salt, stretch the password
// with Argon2id locally, send only the result.

import { login, session, ApiError } from './api.js';
import { loginProof } from './pwauth.js';
import { showMsg, wirePeek, friendlyError } from './common.js';

const $ = (s) => document.querySelector(s);

(async () => {
  try {
    const s = await session();
    if (s.authenticated) { location.replace('/dashboard/'); return; }
    if (!s.configured) showMsg($('#login-msg'), 'Server not configured: the SIG and ENC secrets must be set before anyone can log in.');
  } catch { /* offline */ }
})();

wirePeek(['#login-pass', '#login-pass-peek']);

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = $('#login-btn');
  const msg = $('#login-msg');
  const username = $('#login-user').value.trim();
  const password = $('#login-pass').value;
  if (!username || !password) { showMsg(msg, 'Enter your username and password.'); return; }
  btn.disabled = true;
  btn.textContent = 'Signing in…';
  msg.hidden = true;
  try {
    await login(username, await loginProof(username, password));
    $('#login-pass').value = '';
    location.replace('/dashboard/');
  } catch (err) {
    btn.disabled = false;
    btn.textContent = 'Log in';
    if (err instanceof ApiError && err.code === 'account_locked') {
      showMsg(msg, `This account is temporarily locked${err.extra.until ? ` until ${new Date(err.extra.until * 1000).toLocaleTimeString()}` : ''}.`);
    } else {
      showMsg(msg, friendlyError(err));
    }
  }
});
