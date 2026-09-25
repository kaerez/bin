// setup.js — /dashboard/setup: owner creation / recovery with the one-time
// AUTHN token, plus a local secret generator for AUTHN / SIG / ENC. Generated
// values never leave this page; the owner password is stretched locally.

import { setupStatus, setup } from './api.js';
import { newCredential, checkNewPassword, randomHex } from './pwauth.js';
import { showMsg, wirePeek, friendlyError } from './common.js';
import { copyText, flashCopied } from './ui.js';

const $ = (s) => document.querySelector(s);

function generate() {
  $('#gen-authn').textContent = randomHex(32);
  $('#gen-sig').textContent = randomHex(32);
  $('#gen-enc').textContent = randomHex(32);
}
generate();
$('#gen-again').onclick = generate;
for (const b of document.querySelectorAll('[data-copy]')) {
  b.onclick = async () => flashCopied(b, (await copyText(document.getElementById(b.dataset.copy).textContent)) ? 'copied' : 'failed');
}

wirePeek(['#setup-token', '#setup-token-peek']);
wirePeek(['#setup-pass', '#setup-pass-peek'], ['#setup-pass2', '#setup-pass2-peek']);

(async () => {
  let st = { enabled: false, configured: true };
  try { st = await setupStatus(); } catch { /* treat as disabled */ }
  $('#setup-unconfigured').hidden = st.configured !== false;
  if (!st.enabled) { $('#setup-disabled').hidden = false; return; }
  $('#setup-form').hidden = false;
  if (st.ownerExists) $('#setup-btn').textContent = 'Recover owner account';
})();

$('#setup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const msg = $('#setup-msg');
  const btn = $('#setup-btn');
  const token = $('#setup-token').value.trim();
  const username = $('#setup-user').value.trim();
  const pw = $('#setup-pass').value;
  const bad = checkNewPassword(pw, $('#setup-pass2').value);
  if (!token) return showMsg(msg, 'Enter the setup token.');
  if (!username) return showMsg(msg, 'Choose an owner username.');
  if (bad) return showMsg(msg, bad);
  btn.disabled = true;
  const label = btn.textContent;
  btn.textContent = 'Working…';
  try {
    const cred = await newCredential(pw);
    const r = await setup({ token, username, ...cred });
    $('#setup-form').reset();
    showMsg(msg, `${r.recovered ? 'Owner account recovered' : 'Owner account created'}. Now delete the AUTHN secret, then log in.`, false);
    btn.hidden = true;
    setTimeout(() => location.replace('/dashboard/login/'), 2500);
  } catch (err) {
    btn.disabled = false;
    btn.textContent = label;
    showMsg(msg, friendlyError(err));
  }
});
