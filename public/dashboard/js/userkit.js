// userkit.js — Account → Drive personal kit (docs/DRIVE.md §3.1): the same
// for every user, the owner included. The key version now and its date, the
// last download (and a calm notice when the keys changed since), Download
// (with the step-up) and Verify (a kit file the user selects, read-only, with
// a date picker for the sub-MEK in effect on a day). With the CAPTCHA on, the
// card has its widget like every other Account card: Download and Verify stay
// disabled until it has passed, and each request spends one token. There is
// no restore here: only the owner restores from a personal kit (Admin →
// Security → Keys), so no user can change what opens a Drive. The kit is
// sealed and opened only in this browser (public/js/driveclient.js,
// public/js/drivekit.js); its file is never sent, only check values (Verify).

import { h, showMsg, friendlyError, formatDate } from '../../js/common.js';
import { toast } from '../../js/ui.js';
import { humanCheck } from '../../js/turnstile.js';
import {
  field, secret, fileInput, datePicker, passphrasePair, saveText, takeFile, verifyResults, throttleWait, kitFailed, kitSucceeded, holdOff, liveMsg, versionText,
} from './kit-ui.js';

export const USER_KIT_ANCHOR = 'drive-kit';
const userOf = (profile) => ({ id: profile.user.id, role: profile.user.role, impersonating: !!profile.impersonatedBy });

const INTRO = 'A file you keep offline with what opens your Drive: your account id and username, your user salt, and the key (KEK) the server makes for your account from each of its Drive keys that your files use. It is sealed with a passphrase in this browser and never sent back. With a copy of your stored files, it opens your Drive files and your upload links (Receive) without the server. If this server loses one of its Drive keys, the administrator can use it. Anyone with the kit, its passphrase and a copy of your stored files can read your Drive: store it offline.';

/** The notice when the keys changed after the last download (vague on purpose: no key detail). */
export const STALE_TEXT = 'Your Drive’s keys were updated. Download a new personal kit and keep it safe.';

/**
 * The kit's state: the keys' version and date, the last download, and the
 * notice when that kit is out of date → { el, set(status) } (`status`: the
 * server's { version, versionAt, last, stale }, or null while it loads).
 */
function statusView() {
  const version = h('dd', { id: 'ukit-version', text: '…' });
  const last = h('dd', { id: 'ukit-last', text: '…' });
  const notice = h('div.kit-notice', { id: 'ukit-stale', role: 'note', hidden: true }, h('p.msg.warn', { text: STALE_TEXT }));
  const el = h('div.stack', { id: 'ukit-status' },
    h('dl.kv', {}, h('dt', { text: 'Current keys' }), version, h('dt', { text: 'Last downloaded' }), last), notice);
  const set = (st) => {
    if (!st) return;
    version.textContent = versionText(st.version, st.versionAt);
    last.textContent = st.last ? `${formatDate(st.last.at)} (version ${st.last.version})` : 'Never: download one and keep it safe.';
    notice.hidden = !st.stale;
  };
  return { el, set };
}

/**
 * Download: a new kit each time (the server records it); `confirm(input)` →
 * the step-up; `human()` → the CAPTCHA token (or null); `done(status)`: the
 * kit's state after it.
 */
function download({ profile, drive, confirm, human, done }) {
  const user = userOf(profile);
  const pp = passphrasePair('ukit', 'your Drive');
  const mine = secret('ukit-confirm', 'current-password');
  const go = h('button.btn', { type: 'button', id: 'ukit-download', text: 'Download personal kit' });
  const { msg, live } = liveMsg('ukit-download-msg');
  go.addEventListener('click', async () => {
    if (pp.pass1.value !== pp.pass2.value) return showMsg(msg, 'The two passphrases differ.');
    go.disabled = true;
    showMsg(msg, 'Making the kit…', false);
    try {
      const step = await confirm(mine);
      const r = await drive.buildPersonalKit({ user, passphrase: pp.pass1.value, step, human });
      saveText(r.text, `secbin-personal-kit-${profile.user.username}-${location.hostname}-${new Date().toISOString().slice(0, 10)}.json`);
      const empty = pp.pass1.value === '';
      pp.pass1.value = pp.pass2.value = '';
      pp.sync();
      showMsg(msg, `Personal kit downloaded, with ${r.keks} key${r.keks === 1 ? '' : 's'}${Number.isSafeInteger(r.keyVersion) ? ` (key version ${r.keyVersion})` : ''}. ${empty ? 'It has no passphrase: anyone with the file and your stored files can read your Drive. ' : ''}Store it offline, then verify the saved file. When the Drive’s keys are updated, this page and the Drive page say so: then download a new one.`, false);
      toast('Personal kit downloaded.');
      if (r.status) done(r.status);
    } catch (e) {
      showMsg(msg, friendlyError(e));
    } finally {
      go.disabled = false;
    }
  });
  return h('fieldset.range', { id: 'ukit-download-set' }, h('legend', { text: 'Download' }),
    h('p.type-hint', { text: 'Each download is a new file with the keys your Drive uses now. Your password (or a passkey) confirms it is you.' }),
    pp.el, field('Your password (or leave it empty to confirm with a passkey)', mine), h('div.btn-row', {}, go), live);
}

/** Verify: a read-only check of a kit file the user selects, and which key is in effect on a chosen day (`human()`: the CAPTCHA token). */
function verify({ profile, drive, human }) {
  const user = userOf(profile);
  const file = fileInput('ukit-verify-file');
  const pass = secret('ukit-verify-pass', 'off');
  const day = datePicker('ukit-verify-date');
  const go = h('button.btn', { type: 'button', id: 'ukit-verify', text: 'Verify kit', disabled: true, 'aria-describedby': 'ukit-verify-hint' });
  const hint = h('p.type-hint', { id: 'ukit-verify-hint', text: 'Choose the kit file you saved. Nothing is changed and the file is not uploaded: the server compares check values and answers match or no match. The date (today by default; a future date too) shows which Drive key is in effect then and whether the kit holds it.' });
  const { msg, live } = liveMsg('ukit-verify-msg');
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
      const res = await drive.verifyPersonalKit({ user, text, passphrase, date, human });
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
    field('Kit file to verify', file), field('Its passphrase', pass), field('The Drive key in effect on', day.el), hint, h('div.btn-row', {}, go), live, out);
}

/**
 * The personal kit card: the keys' version, the last download, Download and
 * Verify. `confirm(input)` → the step-up ({ current } | { reauth }) for
 * Download; `onStatus(status)`: the kit's state, when it is known and after
 * each download (the Account page's own notice follows it). Not while the
 * owner acts as the user (a note says so, and nothing is asked of the
 * server, so the user's notice stays theirs): the owner's key kit covers
 * every Drive.
 */
export function personalKitCard({ profile, drive, confirm, onStatus = () => {} }) {
  const title = h('h2.section-title', { id: 'ukit-title', text: 'Drive personal kit' });
  if (profile.impersonatedBy) {
    return h('div.card.stack', { id: USER_KIT_ANCHOR, tabindex: '-1', 'aria-labelledby': 'ukit-title' }, title,
      h('p.subtitle', { text: 'A personal kit is the user’s own: they download it from their Account page. As the administrator, your key kit (Admin → Security → Keys) covers every Drive.' }));
  }
  const status = statusView();
  const set = (st) => { status.set(st); onStatus(st); };
  // One CAPTCHA for the card (as each Account card has): it gates both buttons.
  const box = h('div.turnstile', { id: 'ukit-turnstile', hidden: true });
  let check = null;
  const human = async () => (check ? (await check).take() : null);
  const dl = download({ profile, drive, confirm, human, done: set });
  const vf = verify({ profile, drive, human });
  const card = h('div.card.stack', { id: USER_KIT_ANCHOR, tabindex: '-1', 'aria-labelledby': 'ukit-title' }, title,
    h('p.subtitle', { text: INTRO }), status.el, box, dl, vf);
  check = humanCheck(box, 'account', { gate: [dl.querySelector('#ukit-download'), vf.querySelector('#ukit-verify')] });
  if (drive.personalKitStatus) {
    drive.personalKitStatus().then(set).catch(() => {
      status.el.querySelector('#ukit-version').textContent = 'Unavailable right now.';
      status.el.querySelector('#ukit-last').textContent = 'Unavailable right now.';
    });
  }
  return card;
}
