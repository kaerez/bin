// setup.js — /dashboard/setup: owner creation / recovery with the one-time
// AUTHN token, plus a local secret generator for AUTHN / SIG / ENC. Generated
// values never leave this page; the owner password is stretched locally.
// The Drive keys (docs/DRIVE.md §3, "Set-up"): the server proposes a root MEK
// and a first sub-MEK for the setup token's holder, shown here masked until
// Show (keychoice.js, as Admin → Security → Keys shows a generated key), with
// "Use these", "Generate again" and "Enter manually"; nothing is stored until
// the owner is created with the pair chosen (or the keys entered by hand).

import './kdf-progress.js';
import { setupStatus, setup, setupCandidate } from './api.js';
import { newCredential, checkOwnerPassword, randomHex } from './pwauth.js';
import { showMsg, markInvalid, wirePeek, friendlyError } from './common.js';
import { parseManualKey } from './drivekeys.js';
import { copyText, flashCopied } from './ui.js';
import { candidateView, fpText } from './keychoice.js';

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

// The Drive keys (docs/DRIVE.md §3): a pair the server proposes and the owner chooses, or entered here.
const manualKeys = () => !$('#setup-keys').hidden && $('#setup-keys-manual').checked;
const keysMode = () => { $('#setup-keys-fields').hidden = !manualKeys(); $('#setup-keys-gen-box').hidden = manualKeys(); };
for (const r of document.querySelectorAll('input[name="setup-keys-mode"]')) r.addEventListener('change', keysMode);

// The proposed pair ({ root, sub, expires }: ids, keys and fingerprints) and whether it is chosen.
let proposal = null;
let chosen = false;
function showProposal() {
  const box = $('#setup-keys-cand');
  box.replaceChildren(...(proposal ? [
    candidateView({ id: 'setup-cand-root', label: 'root MEK', cand: proposal.root, masked: true }),
    candidateView({ id: 'setup-cand-sub', label: 'first sub-MEK', cand: proposal.sub, masked: true }),
  ] : []));
  box.hidden = !proposal;
  $('#setup-keys-choice').hidden = !proposal;
  $('#setup-keys-gen').hidden = !!proposal;
  $('#setup-keys-use').hidden = chosen;
  $('#setup-keys-chosen').textContent = proposal && chosen
    ? `These keys will be used (root MEK ${fpText(proposal.root.fp)}, sub-MEK ${fpText(proposal.sub.fp)}). Copy them to a secrets manager if you want a copy now; after you log in, download the key kit.`
    : '';
}
async function propose() {
  const msg = $('#setup-msg');
  const tokenIn = $('#setup-token');
  markInvalid(tokenIn, msg, false);
  const token = tokenIn.value.trim();
  if (!token) { showMsg(msg, 'Enter the setup token first: the server proposes the keys only to its holder.'); markInvalid(tokenIn, msg); tokenIn.focus(); return; }
  const btns = ['#setup-keys-gen', '#setup-keys-again'].map((q) => $(q));
  for (const b of btns) b.disabled = true;
  try {
    proposal = await setupCandidate(token);
    chosen = false;
    msg.hidden = true;
    showProposal();
    $('#setup-cand-root-show').focus();
  } catch (e) {
    showMsg(msg, friendlyError(e));
  } finally {
    for (const b of btns) b.disabled = false;
  }
}
$('#setup-keys-gen').addEventListener('click', propose);
$('#setup-keys-again').addEventListener('click', propose);
$('#setup-keys-use').addEventListener('click', () => { chosen = true; showProposal(); $('#setup-keys-again').focus(); });
$('#setup-keys-to-manual').addEventListener('click', () => { $('#setup-keys-manual').checked = true; keysMode(); $('#setup-root').focus(); });

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
  } else if (!$('#setup-keys').hidden) {
    // The keys the server proposed, once the owner chose them ("Use these").
    if (!proposal || !chosen) {
      showMsg(msg, proposal ? 'Choose “Use these” for the proposed Drive keys, generate them again, or enter them manually.' : 'Generate the Drive keys and choose “Use these”, or enter them manually.');
      (proposal ? $('#setup-keys-use') : $('#setup-keys-gen')).focus();
      return;
    }
    keys = { mode: 'generated', root: proposal.root.id, sub: proposal.sub.id };
  }
  btn.disabled = true;
  const label = btn.textContent;
  btn.textContent = 'Working…';
  try {
    const cred = await newCredential(pw);
    const r = await setup({ token, username, ...cred, ...(keys ? { keys } : {}) });
    $('#setup-form').reset();
    $('#setup-keys-fields').hidden = true;
    proposal = null;
    chosen = false;
    showProposal();
    const kit = r.keys === 'created' ? ' The Drive keys were created: after you log in, download the key kit (Admin → Security → Keys) and store it offline.'
      : r.keys === 'later' ? ' The Drive keys are made the first time a Drive is used.' : '';
    showMsg(msg, `${r.recovered ? 'Owner account recovered' : 'Owner account created'}.${kit} Now delete the AUTHN secret, then log in.`, false);
    btn.hidden = true;
    setTimeout(() => location.replace('/dashboard/login/'), r.keys === 'created' ? 6000 : 2500);
  } catch (err) {
    btn.disabled = false;
    btn.textContent = label;
    showMsg(msg, friendlyError(err));
    // The proposal is gone (10 minutes, or a newer one): the owner generates the keys again.
    if (err && err.code === 'candidate_expired') { proposal = null; chosen = false; showProposal(); }
  }
});
