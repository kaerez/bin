// reverse-edit.js — the options of a "Receive" link (a reverse share,
// docs/REVERSE.md §5, §8) as the user changes them after making it: My
// shares' Edit (the Drive's Receive dialog uses the pure helpers for a new
// link). Its expiry (extend it, give it one, or none), views, limits,
// CAPTCHA, the uploader password and the note, each shown as the role allows
// (profile.limits); the server checks every value again.
//
// The password and the note are sealed in this browser with the link's key
// (driveclient.js updateReverse), which the Drive's keys open: the Drive
// client is loaded only when one of them changes. Neither is sent in clear,
// but like the uploads to the link they are not end-to-end: the server holds
// the keys that open the link's key. A change that weakens the link (its
// password removed or changed, the CAPTCHA off, no expiry, unlimited views)
// asks for the account password or a passkey, as making a link does (not
// while the owner acts as the user). DOM through h() only (strict CSP,
// Trusted Types).

import { h, formatBytes, formatCoarse, DURATION_UNITS, unitSeconds } from '../../js/common.js';
import { MAX_VIEWS, MAX_TTL } from '../../js/format.js';
import { normalizeRules } from '../../js/filepolicy.js';
import { captchaChoice } from '../../js/captcha.js';
import { confirmStep, confirmLabel, canUsePasskey } from './confirm.js';

const MiB = 1024 * 1024;
const MAX_FILES = 10000;
let seq = 0;

/**
 * A reverse link's views as typed → { views } (null: unlimited) or { error,
 * field: 'views' }. `L`: reverseMaxViews, reverseAllowUnlimitedViews; `min`:
 * the views already used (a link's views are never set below them).
 */
export function reverseViews({ views, unlimited }, L = {}, min = 1) {
  if (unlimited) {
    if (L.reverseAllowUnlimitedViews === false) return { error: 'Unlimited views are not allowed for your account’s upload links.', field: 'views' };
    return { views: null };
  }
  const max = L.reverseMaxViews ?? MAX_VIEWS;
  const lo = Math.max(1, min);
  const vRaw = String(views ?? '').trim();
  if (!/^[1-9][0-9]{0,5}$/.test(vRaw) || Number(vRaw) > max || Number(vRaw) < lo) {
    return { error: `Views must be a whole number from ${lo.toLocaleString('en-US')} to ${max.toLocaleString('en-US')}${L.reverseAllowUnlimitedViews === false ? '' : ', or unlimited (∞)'}.`, field: 'views' };
  }
  return { views: Number(vRaw) };
}

/**
 * The uploader-password box from the role (reversePassword): "allow" shows it
 * pre-set from reversePasswordDefault, "require" ticked and disabled, "off"
 * hides it → { show, checked, disabled, mode }. The server decides.
 */
export function reversePasswordChoice(L = {}) {
  const mode = L.reversePassword ?? 'allow';
  if (mode === 'require') return { show: true, checked: true, disabled: true, mode };
  if (mode === 'off') return { show: false, checked: false, disabled: true, mode };
  return { show: true, checked: L.reversePasswordDefault === 'on', disabled: false, mode };
}

/** A size typed in MB ('' = no limit) → bytes, null, or undefined when invalid. */
export function mbToBytes(raw) {
  const v = String(raw ?? '').trim();
  if (!v) return null;
  if (!/^\d{1,9}(\.\d{1,3})?$/.test(v) || Number(v) <= 0) return undefined;
  return Math.max(1, Math.round(Number(v) * MiB));
}
const mbText = (b) => (b === null || b === undefined ? '' : String(Math.round((b / MiB) * 1000) / 1000));
const sameTypes = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null);

/**
 * What the Edit form asks for, from its values and the link as it is (`cur`:
 * the Drive's row — expires (null: none), views, used, maxFiles, maxBytes,
 * maxFileBytes, types, captcha, password, note) → { patch } (only what
 * changed; `note` / `password` / `removePassword` as driveclient.js
 * updateReverse takes them) or { error, field }.
 */
export function reverseEditPatch(v, cur, L = {}, now = Math.floor(Date.now() / 1000)) {
  const patch = {};
  // Expiry: as regular shares, only extended — or given one (a link with none), or none (where allowed).
  if (v.expiry === 'extend') {
    const n = String(v.n ?? '').trim();
    if (!/^[1-9][0-9]{0,6}$/.test(n)) return { error: 'Enter a whole number of minutes, hours or days.', field: 'expire' };
    const add = Number(n) * unitSeconds(v.unit);
    const base = cur.expires === null ? now : Math.max(cur.expires, now);
    const at = base + add;
    if (at > now + MAX_TTL) return { error: 'An upload link can expire at most 365 days from now.', field: 'expire' };
    const maxSec = L.reverseMaxExpireSec;
    if (maxSec !== null && maxSec !== undefined && at - now > maxSec) return { error: `Your account allows upload links to accept files for at most ${formatCoarse(maxSec)} from now.`, field: 'expire' };
    patch.expires = at;
  } else if (v.expiry === 'none') {
    if (!L.reverseNoExpiry) return { error: 'Your account does not allow upload links without an expiry.', field: 'expire' };
    if (cur.expires !== null) patch.expires = null;
  }
  const views = reverseViews({ views: v.views, unlimited: v.unlimited }, L, cur.used ?? 0);
  if (views.error) return views;
  if (views.views !== (cur.views ?? null)) patch.views = views.views;
  // Limits.
  const fRaw = String(v.maxFiles ?? '').trim();
  let maxFiles = null;
  if (fRaw) {
    if (!/^[1-9][0-9]{0,4}$/.test(fRaw) || Number(fRaw) > MAX_FILES) return { error: 'Files must be a whole number from 1 to 10,000, or empty for no limit.', field: 'files' };
    maxFiles = Number(fRaw);
  }
  if (maxFiles !== (cur.maxFiles ?? null)) patch.maxFiles = maxFiles;
  const roleMax = L.reverseMaxBytes ?? null;
  const maxBytes = mbToBytes(v.maxMb);
  if (maxBytes === undefined) return { error: 'The total size must be a number of MB, or empty.', field: 'bytes' };
  if (roleMax !== null && maxBytes !== null && maxBytes > roleMax) return { error: `Your account allows at most ${formatBytes(roleMax)} per link.`, field: 'bytes' };
  // Both sides as they apply: "none" is the role's limit, when it has one.
  if ((maxBytes ?? roleMax) !== (cur.maxBytes ?? roleMax)) patch.maxBytes = maxBytes;
  const fileBytes = mbToBytes(v.fileMb);
  if (fileBytes === undefined) return { error: 'The file size must be a number of MB, or empty.', field: 'file' };
  if (fileBytes !== (cur.maxFileBytes ?? null)) patch.maxFileBytes = fileBytes;
  let types = null;
  if (v.typeMode === 'allow' || v.typeMode === 'block') {
    let rules;
    try { rules = normalizeRules(String(v.typeRules ?? '').split(/[\n,]+/).map((x) => x.trim()).filter(Boolean)); } catch (e) { return { error: e.message, field: 'types' }; }
    if (!rules.length) return { error: 'List at least one file type (for example ext:pdf), or accept any type.', field: 'types' };
    types = { mode: v.typeMode, rules };
  }
  if (!sameTypes(types, cur.types)) patch.types = types;
  if (typeof v.captcha === 'boolean' && v.captcha !== !!cur.captcha) patch.captcha = v.captcha;
  // The password: kept, changed (or added) — typed twice —, or removed.
  if (v.password === 'change') {
    if (!v.pw1) return { error: 'Enter the new password, or keep the current one.', field: 'pw' };
    if (v.pw1 !== v.pw2) return { error: 'Passwords do not match — repeat the same password in both fields.', field: 'pw2' };
    patch.password = v.pw1;
  } else if (v.password === 'remove') {
    if (L.reversePassword === 'require') return { error: 'Your role requires a password on every upload link.', field: 'pw' };
    patch.removePassword = true;
  }
  if (v.note === 'change') {
    const text = String(v.noteText ?? '').trim();
    if (!text) return { error: 'Write the new note, or keep the current one.', field: 'note' };
    patch.note = text;
  } else if (v.note === 'remove') patch.note = '';
  if (!Object.keys(patch).length) return { error: 'Nothing to change.', field: null };
  return { patch };
}

/**
 * Whether `patch` (from reverseEditPatch) weakens link `cur`: its password
 * removed or changed, its CAPTCHA turned off, no expiry, unlimited views.
 * Such a change needs the account password or a passkey (the server decides:
 * src/routes/reverse.js weakening).
 */
export function weakensLink(patch, cur) {
  if (!patch) return false;
  return (patch.expires === null && cur.expires !== null)
    || (patch.views === null && cur.views !== null && cur.views !== undefined)
    || ((typeof patch.password === 'string' || patch.removePassword === true) && !!cur.password)
    || (patch.captcha === false && !!cur.captcha);
}

/** A radio group in a fieldset: choices [[value, text, hidden?]] → { el, value(), radios }. */
function choiceGroup(legend, name, choices, current) {
  const shown = choices.filter((c) => !c[2]);
  const radios = shown.map(([value]) => h('input', { type: 'radio', name, value, checked: value === current }));
  const el = h('fieldset.rev-edit-group', {}, h('legend.field-label', { text: legend }),
    ...radios.map((r, i) => h('label.radio-opt', {}, r, h('span', { text: shown[i][1] }))));
  return { el, radios, value: () => radios.find((r) => r.checked)?.value ?? current };
}

/**
 * The Edit form for reverse share `cur` (the Drive's row, as GET
 * /api/private/drive/reverse lists it): → { el, focus(), read() → the
 * reverseEditPatch result, stepUp(patch) → the confirmation to send }.
 * `profile`: /api/private/me (its limits and the CAPTCHA's state; the owner
 * acting as the user confirms nothing). `confirm(input)`: a stand-in for
 * confirm.js confirmStep (tests). Every control has a visible label; the
 * error line is an alert, the note under each group says what it does.
 */
export function reverseEditForm(cur, profile, { confirm = null, passkey = null, impersonating: acting = null } = {}) {
  const n = ++seq;
  const id = (x) => `rev-edit-${n}-${x}`;
  const L = (profile && profile.limits) || {};
  const now = Math.floor(Date.now() / 1000);
  // Expiry.
  const expN = h('input.input.opt-num', { id: id('expire'), type: 'number', min: '1', step: '1', value: '7', inputmode: 'numeric' });
  const expU = h('select.input.opt-sel', { id: id('unit'), 'aria-label': `${cur.expires === null ? 'Expire in' : 'Extend by'}: unit` },
    ...DURATION_UNITS.filter(([u]) => u !== 's').map(([u, w]) => h('option', { value: u, text: w, selected: u === 'd' })));
  expU.value = 'd';
  const nowText = cur.expires === null ? 'It has no expiry now.' : `It expires in ${formatCoarse(Math.max(0, cur.expires - now))} now.`;
  const expiry = choiceGroup(`Expiry — ${nowText}`, id('expiry'), [
    ['keep', 'Keep it'],
    ['extend', cur.expires === null ? 'Give it an expiry' : 'Extend it'],
    ['none', 'No expiry (it accepts files until you revoke it)', !L.reverseNoExpiry || cur.expires === null],
  ], 'keep');
  const expBox = h('div.opt', { role: 'group', 'aria-labelledby': id('expire-l'), hidden: true },
    h('label.opt-label', { id: id('expire-l'), for: id('expire'), text: cur.expires === null ? 'Expire in' : 'Extend by' }), expN, expU);
  const syncExp = () => { expBox.hidden = expiry.value() !== 'extend'; };
  for (const r of expiry.radios) r.addEventListener('change', syncExp);
  // Views.
  const used = cur.used ?? 0;
  const unlimitedOk = L.reverseAllowUnlimitedViews !== false;
  const isUnlimited = cur.views === null || cur.views === undefined;
  const viewsIn = h('input.input.opt-num', { id: id('views'), type: 'number', min: String(Math.max(1, used)), max: String(L.reverseMaxViews ?? MAX_VIEWS), step: '1',
    value: String(isUnlimited ? Math.max(1, used + 1) : cur.views), inputmode: 'numeric', disabled: isUnlimited, 'aria-describedby': id('views-hint') });
  const inf = h('button.opt-toggle', { type: 'button', id: id('unlimited'), 'aria-pressed': String(isUnlimited), 'aria-label': 'Unlimited views', title: 'Unlimited views', text: '∞', disabled: !unlimitedOk && !isUnlimited });
  inf.addEventListener('click', () => { const on = inf.getAttribute('aria-pressed') !== 'true'; inf.setAttribute('aria-pressed', String(on)); viewsIn.disabled = on; if (!on) viewsIn.focus(); });
  const viewsBox = h('div.opt', { role: 'group', 'aria-labelledby': id('views-l') }, h('label.opt-label', { id: id('views-l'), for: id('views'), text: 'Views (new total)' }), viewsIn, inf);
  const viewsHint = h('p.type-hint', { id: id('views-hint'), text: `${used} used so far: a view is one visit that started sending files. Views can be raised or lowered, never below those used.` });
  // Limits.
  const labelled = (text, input) => h('div.dfield', {}, h('label.field-label', { for: input.id, text }), input);
  const files = h('input.input', { id: id('files'), type: 'number', min: '1', max: String(MAX_FILES), step: '1', inputmode: 'numeric', placeholder: 'no limit', value: cur.maxFiles ? String(cur.maxFiles) : '' });
  const roleMax = L.reverseMaxBytes ?? null;
  const maxMb = h('input.input', { id: id('bytes'), inputmode: 'decimal', placeholder: roleMax ? `up to ${formatBytes(roleMax)}` : 'no limit', value: mbText(cur.maxBytes) });
  const fileMb = h('input.input', { id: id('filesize'), inputmode: 'decimal', placeholder: 'no limit', value: mbText(cur.maxFileBytes) });
  const typeMode = h('select.input', { id: id('types') },
    h('option', { value: 'any', text: 'any type' }), h('option', { value: 'allow', text: 'only the listed types' }), h('option', { value: 'block', text: 'all but the listed types' }));
  typeMode.value = cur.types ? cur.types.mode : 'any';
  const typeRules = h('textarea.input.rules-in', { id: id('rules'), rows: '2', placeholder: 'ext:pdf\next:docx\nmime:image/*' });
  typeRules.value = cur.types ? cur.types.rules.join('\n') : '';
  const typeBox = labelled('The file types (one per line: ext:pdf, mime:image/*)', typeRules);
  typeBox.hidden = typeMode.value === 'any';
  typeMode.addEventListener('change', () => { typeBox.hidden = typeMode.value === 'any'; });
  // The CAPTCHA, as the role says (shown while it can be chosen, or while this link has it).
  const cc = captchaChoice(profile, 'reverse');
  const capIn = h('input', { type: 'checkbox', id: id('captcha'), checked: !!cur.captcha, disabled: cc.mode === 'require' || (cc.mode === 'off' && !cur.captcha), 'aria-describedby': id('captcha-hint') });
  const capBox = cc.mode === 'off' && !cur.captcha ? null : h('div.captcha-opt', {},
    h('label.inline', {}, capIn, ' Require CAPTCHA to send files'),
    h('p.type-hint', { id: id('captcha-hint'), text: cc.mode === 'require' ? 'Your role requires it on every link.' : cc.mode === 'off' ? 'Your role no longer allows it: it can only be turned off.' : 'Senders complete a CAPTCHA before they can upload.' }));
  // The password.
  const pc = reversePasswordChoice(L);
  const password = choiceGroup(`Uploader password — ${cur.password ? 'it has one now' : 'it has none now'} (it only lets uploaders in; you never need it)`, id('pw-mode'), [
    ['keep', cur.password ? 'Keep it' : 'Keep it without one'],
    ['change', cur.password ? 'Change it' : 'Add one', pc.mode === 'off'],
    ['remove', 'Remove it', !cur.password || pc.mode === 'require'],
  ], 'keep');
  const pw1 = h('input.input', { id: id('pw'), type: 'password', autocomplete: 'new-password', maxlength: '128', 'data-lpignore': 'true', 'data-1p-ignore': true });
  const pw2 = h('input.input', { id: id('pw2'), type: 'password', autocomplete: 'new-password', maxlength: '128', 'data-lpignore': 'true', 'data-1p-ignore': true });
  const pwBox = h('div.drive-share-pw', { hidden: true }, labelled('New password', pw1), labelled('Repeat the new password', pw2));
  for (const r of password.radios) r.addEventListener('change', () => { pwBox.hidden = password.value() !== 'change'; });
  const pwEl = password.radios.length > 1 ? password.el : null;
  // The note.
  const note = choiceGroup(`Note to the people who upload — ${cur.note ? 'it has one now' : 'it has none now'} (encrypted to the link; like the Drive, not end-to-end)`, id('note-mode'), [
    ['keep', cur.note ? 'Keep it' : 'Keep it without one'],
    ['change', cur.note ? 'Replace it' : 'Add one'],
    ['remove', 'Remove it', !cur.note],
  ], 'keep');
  const noteIn = h('textarea.input', { id: id('note'), maxlength: '1000', rows: '3' });
  const noteBox = h('div', { hidden: true }, labelled('The new note', noteIn));
  for (const r of note.radios) r.addEventListener('change', () => { noteBox.hidden = note.value() !== 'change'; });

  // "Confirm it's you": shown only while the change weakens the link (and never while the owner acts as the user).
  const impersonating = acting ?? !!(profile && (profile.impersonatedBy || profile.user?.impersonating));
  const confirmIn = h('input.input', { id: id('confirm'), type: 'password', autocomplete: 'current-password', maxlength: '1024', spellcheck: 'false', 'aria-describedby': id('confirm-hint') });
  const confirmText = h('label.field-label', { for: id('confirm'), text: 'Your account password (to confirm it is you)' });
  let withPasskey = passkey === true;
  if (!impersonating && passkey === null) canUsePasskey().then((ok) => { withPasskey = !!ok; confirmText.textContent = confirmLabel('Your account password (to confirm it is you)', withPasskey); }).catch(() => {});
  const confirmBox = h('div.dfield', { hidden: true }, confirmText, confirmIn,
    h('p.type-hint', { id: id('confirm-hint'), text: 'This change removes a protection of the link (its password, its CAPTCHA, its expiry or its views limit), so it needs your password or a passkey, as making a link does.' }));

  const el = h('div.rev-edit.stack', {},
    expiry.el, expBox,
    h('div.toolbar', {}, viewsBox), viewsHint,
    h('div.drive-reverse-grid', {}, labelled('Most files (empty: no limit)', files), labelled('Most in total, MB (empty: no limit)', maxMb), labelled('Largest file, MB (empty: no limit)', fileMb)),
    labelled('File types', typeMode), typeBox,
    capBox,
    pwEl, pwBox,
    note.el, noteBox,
    confirmBox);
  const fields = { expire: expN, views: viewsIn.disabled ? inf : viewsIn, files, bytes: maxMb, file: fileMb, types: typeRules, pw: pw1, pw2, note: noteIn, confirm: confirmIn };
  const read = () => reverseEditPatch({
    expiry: expiry.value(), n: expN.value, unit: expU.value,
    views: viewsIn.value, unlimited: inf.getAttribute('aria-pressed') === 'true',
    maxFiles: files.value, maxMb: maxMb.value, fileMb: fileMb.value, typeMode: typeMode.value, typeRules: typeRules.value,
    captcha: capBox ? capIn.checked : undefined,
    password: password.value(), pw1: pw1.value, pw2: pw2.value,
    note: note.value(), noteText: noteIn.value,
  }, cur, L);
  const needsStepUp = (patch) => !impersonating && weakensLink(patch, cur);
  const sync = () => { confirmBox.hidden = !needsStepUp(read().patch); };
  el.addEventListener('change', sync);
  el.addEventListener('input', (e) => { if (e.target !== confirmIn) sync(); });
  el.addEventListener('click', (e) => { if (e.target === inf) sync(); });
  return {
    el,
    focus: () => expiry.radios[0].focus(),
    field: (k) => (k === 'views' ? (viewsIn.disabled ? inf : viewsIn) : fields[k] || null),
    read,
    needsStepUp,
    /** The confirmation `patch` needs: {} when it weakens nothing, else { current } or { reauth } (throws with a reason). */
    stepUp: async (patch) => {
      if (!needsStepUp(patch)) return {};
      confirmBox.hidden = false;
      return (confirm || ((input) => confirmStep(input, profile?.user?.username, withPasskey)))(confirmIn);
    },
    clearSecrets: () => { pw1.value = pw2.value = confirmIn.value = ''; },
  };
}

/**
 * Save a patch from reverseEditPatch: through the Drive client when the
 * password or the note changes (they are sealed with the link's key), else
 * as is. `deps`: { updateShare(id, body), driveClient() → a DriveClient }.
 */
export async function saveReverseEdit(id, patch, deps) {
  if (patch.password !== undefined || patch.note !== undefined) {
    const client = await deps.driveClient();
    return client.updateReverse(id, patch);
  }
  const { removePassword, ...rest } = patch;
  return deps.updateShare(id, removePassword ? { ...rest, password: null } : rest);
}

