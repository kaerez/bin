// userkit.js — Account → Drive personal kit (docs/DRIVE.md §3.1): the same
// for every user, the owner included. Download (with the step-up), Verify (a
// kit file the user selects, read-only, with a date picker for the sub-MEK in
// effect on a day) and Restore. The kit is sealed and opened only in this
// browser (public/js/driveclient.js, public/js/drivekit.js); its file is
// never sent, only check values (Verify) and, for Restore, what the server
// lost (the user salt, and items re-sealed under the current key).

import { h, showMsg, friendlyError } from '../../js/common.js';
import { toast } from '../../js/ui.js';
import {
  field, secret, fileInput, datePicker, passphrasePair, saveText, takeFile, verifyResults, throttleWait, kitFailed, kitSucceeded, kitFailure, holdOff,
} from './kit-ui.js';

export const USER_KIT_ANCHOR = 'drive-kit';
const userOf = (profile) => ({ id: profile.user.id, role: profile.user.role, impersonating: !!profile.impersonatedBy });

const INTRO = 'A file you keep offline with what opens your Drive: your account id and username, your user salt, and the key (KEK) the server makes for your account from each of its Drive keys that your files use. It is sealed with a passphrase in this browser and never sent back. With a copy of your stored files, it opens your Drive files and your upload links (Receive files) without the server; on this server, it puts back your salt and your files if the server lost one of its keys. Anyone with the kit, its passphrase and a copy of your stored files can read your Drive: store it offline.';

/** Download: a new kit each time (the server records it); `confirm(input)` → the step-up. */
function download({ profile, drive, confirm }) {
  const user = userOf(profile);
  const pp = passphrasePair('ukit', 'your Drive');
  const mine = secret('ukit-confirm', 'current-password');
  const go = h('button.btn', { type: 'button', id: 'ukit-download', text: 'Download personal kit' });
  const msg = h('p.msg', { id: 'ukit-download-msg', role: 'status', hidden: true });
  go.addEventListener('click', async () => {
    if (pp.pass1.value !== pp.pass2.value) return showMsg(msg, 'The two passphrases differ.');
    go.disabled = true;
    showMsg(msg, 'Making the kit…', false);
    try {
      const step = await confirm(mine);
      const r = await drive.buildPersonalKit({ user, passphrase: pp.pass1.value, step });
      saveText(r.text, `secbin-personal-kit-${profile.user.username}-${location.hostname}-${new Date().toISOString().slice(0, 10)}.json`);
      const empty = pp.pass1.value === '';
      pp.pass1.value = pp.pass2.value = '';
      pp.sync();
      showMsg(msg, `Personal kit downloaded, with ${r.keks} key${r.keks === 1 ? '' : 's'}. ${empty ? 'It has no passphrase: anyone with the file and your stored files can read your Drive. ' : ''}Store it offline, then verify the saved file. Download a fresh one after the administrator adds a Drive key.`, false);
      toast('Personal kit downloaded.');
    } catch (e) {
      showMsg(msg, friendlyError(e));
    } finally {
      go.disabled = false;
    }
  });
  return h('fieldset.range', { id: 'ukit-download-set' }, h('legend', { text: 'Download' }),
    h('p.type-hint', { text: 'Each download is a new file with the keys your Drive uses now. Your password (or a passkey) confirms it is you.' }),
    pp.el, field('Your password (or leave it empty to confirm with a passkey)', mine), h('div.btn-row', {}, go), msg);
}

/** Verify: a read-only check of a kit file the user selects, and which key is in effect on a chosen day. */
function verify({ profile, drive }) {
  const user = userOf(profile);
  const file = fileInput('ukit-verify-file');
  const pass = secret('ukit-verify-pass', 'off');
  const day = datePicker('ukit-verify-date');
  const go = h('button.btn', { type: 'button', id: 'ukit-verify', text: 'Verify kit', disabled: true, 'aria-describedby': 'ukit-verify-hint' });
  const hint = h('p.type-hint', { id: 'ukit-verify-hint', text: 'Choose the kit file you saved. Nothing is changed and the file is not uploaded: the server compares check values and answers match or no match. The date (today by default; a future date too) shows which Drive key is in effect then and whether the kit holds it.' });
  const msg = h('p.msg', { id: 'ukit-verify-msg', role: 'status', hidden: true });
  const out = h('div', { id: 'ukit-verify-out' });
  const sync = () => { go.disabled = !file.files || !file.files.length; };
  file.addEventListener('change', sync);
  go.addEventListener('click', async () => {
    if (!file.files || !file.files.length) { sync(); return showMsg(msg, 'Choose the kit file first.'); }
    if (throttleWait()) return holdOff(go, msg, sync);
    go.disabled = true;
    out.replaceChildren();
    showMsg(msg, 'Checking the kit…', false);
    const date = day.seconds();
    const { text, passphrase } = await takeFile(file, pass, sync);
    try {
      const res = await drive.verifyPersonalKit({ user, text, passphrase, date });
      if (res.verdict === 'failed') kitFailed(); else kitSucceeded();
      msg.hidden = true;
      out.replaceChildren(verifyResults(res, 'ukit-verify'));
      out.querySelector('#ukit-verify-verdict').focus();
    } catch (e) {
      showMsg(msg, friendlyError(e));
    } finally {
      sync();
    }
  });
  return h('fieldset.range', { id: 'ukit-verify-set' }, h('legend', { text: 'Verify' }),
    field('Kit file to verify', file), field('Its passphrase', pass), field('The Drive key in effect on', day.el), hint, h('div.btn-row', {}, go), msg, out);
}

/** Restore: the user salt when the server has none, and files sealed under a key the server lost. */
function restore({ profile, drive, confirm }) {
  const user = userOf(profile);
  const file = fileInput('ukit-restore-file');
  const pass = secret('ukit-restore-pass', 'off');
  const mine = secret('ukit-restore-confirm', 'current-password');
  const go = h('button.btn', { type: 'button', id: 'ukit-restore', text: 'Restore from kit', disabled: true, 'aria-describedby': 'ukit-restore-hint' });
  const hint = h('p.type-hint', { id: 'ukit-restore-hint', text: 'Only what the server lost comes back: your salt if it has none, and files sealed under a key it no longer has (opened here with the kit and sealed again under the current key). Nothing that works is replaced.' });
  const msg = h('p.msg', { id: 'ukit-restore-msg', role: 'status', hidden: true });
  const sync = () => { go.disabled = !file.files || !file.files.length; };
  file.addEventListener('change', sync);
  go.addEventListener('click', async () => {
    if (!file.files || !file.files.length) { sync(); return showMsg(msg, 'Choose the kit file first.'); }
    if (throttleWait()) return holdOff(go, msg, sync);
    go.disabled = true;
    showMsg(msg, 'Opening the kit and restoring…', false);
    try {
      const step = await confirm(mine);
      const { text, passphrase } = await takeFile(file, pass, sync);
      const r = await drive.restorePersonalKit({ user, text, passphrase, step, onProgress: (n) => showMsg(msg, `Restoring… ${n} item${n === 1 ? '' : 's'} sealed again`, false) });
      kitSucceeded();
      const salt = { restored: 'your user salt was put back', same: 'your user salt was already there', kept: 'your user salt on the server was kept (it is not the kit’s)', wrong: 'the kit’s salt does not open your files, so it was not used', absent: '' }[r.salt] || '';
      showMsg(msg, `Restore done: ${[salt, r.items || r.links ? `${r.items} item${r.items === 1 ? '' : 's'} and ${r.links} upload link${r.links === 1 ? '' : 's'} sealed again under the current key` : 'nothing else was missing'].filter(Boolean).join('; ')}.${r.left.length ? ` The kit has no key for ${r.left.length} of the lost Drive keys: the administrator’s key kit may.` : ''}`, false);
      toast('Restored from the personal kit.');
    } catch (e) {
      if (kitFailure(e)) kitFailed();
      showMsg(msg, friendlyError(e));
    } finally {
      sync();
    }
  });
  return h('fieldset.range', { id: 'ukit-restore-set' }, h('legend', { text: 'Restore' }),
    field('Kit file to restore from', file), field('Its passphrase', pass), field('Your password (or leave it empty to confirm with a passkey)', mine), hint, h('div.btn-row', {}, go), msg);
}

/**
 * The personal kit card. `confirm(input)` → the step-up ({ current } |
 * { reauth }) for Download and Restore. Not while the owner acts as the user
 * (a note says so): the owner's key kit covers every Drive.
 */
export function personalKitCard({ profile, drive, confirm }) {
  const title = h('h2.section-title', { id: 'ukit-title', text: 'Drive personal kit' });
  if (profile.impersonatedBy) {
    return h('div.card.stack', { id: USER_KIT_ANCHOR, tabindex: '-1', 'aria-labelledby': 'ukit-title' }, title,
      h('p.subtitle', { text: 'A personal kit is the user’s own: they download it from their Account page. As the administrator, your key kit (Admin → Security → Keys) covers every Drive.' }));
  }
  return h('div.card.stack', { id: USER_KIT_ANCHOR, tabindex: '-1', 'aria-labelledby': 'ukit-title' }, title,
    h('p.subtitle', { text: INTRO }),
    download({ profile, drive, confirm }), verify({ profile, drive }), restore({ profile, drive, confirm }));
}
