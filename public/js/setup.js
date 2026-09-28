// setup.js — /dashboard/setup: owner creation / recovery with the one-time
// AUTHN token, plus a local secret generator for AUTHN / SIG / ENC. Generated
// values never leave this page; the owner password is stretched locally.

import './kdf-progress.js';
import { setupStatus, setup } from './api.js';
import { newCredential, checkOwnerPassword, randomHex } from './pwauth.js';
import { showMsg, markInvalid, wirePeek, friendlyError } from './common.js';
import { parseManualKey } from './drivekeys.js';
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
  if (st.ownerExists) {
    $('#setup-btn').textContent = 'Recover owner account';
    // The keyring stays as it is on a recovery.
    $('#setup-keys').hidden = true;
    $('#setup-keys-kept').hidden = false;
  }
})();

// The Drive keys (docs/DRIVE.md §3): generated on the server, or entered here.
const manualKeys = () => !$('#setup-keys').hidden && $('#setup-keys-manual').checked;
for (const r of document.querySelectorAll('input[name="setup-keys-mode"]')) {
  r.addEventListener('change', () => { $('#setup-keys-fields').hidden = !manualKeys(); });
}

$('#setup-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const msg = $('#setup-msg');
  const btn = $('#setup-btn');
  const token = $('#setup-token').value.trim();
  const username = $('#setup-user').value.trim();
  const pw = $('#setup-pass').value;
  const bad = checkOwnerPassword(pw, $('#setup-pass2').value); // the owner chooses freely
  // A problem with a field: the message is tied to it (aria-invalid + aria-describedby) and focus goes there.
  const fields = ['#setup-token', '#setup-user', '#setup-pass', '#setup-pass2'].map((s) => $(s));
  for (const f of fields) markInvalid(f, msg, false);
  const fail = (field, text) => { showMsg(msg, text); markInvalid(field, msg); field.focus(); };
  if (!token) return fail(fields[0], 'Enter the setup token.');
  if (!username) return fail(fields[1], 'Choose an owner username.');
  if (bad) return fail(/match/i.test(bad) ? fields[3] : fields[2], bad);
  let keys;
  if (manualKeys()) {
    const [root, sub] = ['#setup-root', '#setup-sub'].map((s) => $(s));
    for (const f of [root, sub]) markInvalid(f, msg, false);
    try { parseManualKey(root.value); } catch (e2) { return fail(root, `Root MEK: ${e2.message}`); }
    try { parseManualKey(sub.value); } catch (e2) { return fail(sub, `Sub-MEK: ${e2.message}`); }
    keys = { mode: 'manual', root: root.value.trim(), sub: sub.value.trim() };
  }
  btn.disabled = true;
  const label = btn.textContent;
  btn.textContent = 'Working…';
  try {
    const cred = await newCredential(pw);
    const r = await setup({ token, username, ...cred, ...(keys ? { keys } : {}) });
    $('#setup-form').reset();
    $('#setup-keys-fields').hidden = true;
    const kit = r.keys === 'created' ? ' The Drive keys were created: after you log in, download the key kit (Admin → Security → Keys) and store it offline.'
      : r.keys === 'later' ? ' The Drive keys are made the first time a Drive is used.' : '';
    showMsg(msg, `${r.recovered ? 'Owner account recovered' : 'Owner account created'}.${kit} Now delete the AUTHN secret, then log in.`, false);
    btn.hidden = true;
    setTimeout(() => location.replace('/dashboard/login/'), r.keys === 'created' ? 6000 : 2500);
  } catch (err) {
    btn.disabled = false;
    btn.textContent = label;
    showMsg(msg, friendlyError(err));
  }
});
