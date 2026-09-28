// kit-ui.js — the pieces both Drive kits share (docs/DRIVE.md §3.1): the
// personal kit on Account (userkit.js) and the key kit in Admin → Security →
// Keys (admin-keys.js). A kit is sealed and opened only in this browser; its
// FILE is never sent (Verify and Restore read the file the person selects,
// never a copy kept by the page, and clear it and its passphrase once done).
// Failed openings are throttled here: two free tries, then 5 s, 10 s, 20 s…
// up to a minute (Argon2id is slow as well); the throttle lives in this
// page's memory only.

import { h, showMsg } from '../../js/common.js';

export const SHORT_PASSPHRASE = 12;

// ── throttle ────────────────────────────────────────────────────────────────
const throttle = { fails: 0, until: 0 };
/** Seconds to wait before the next attempt (0: go ahead). */
export const throttleWait = () => Math.max(0, Math.ceil((throttle.until - Date.now()) / 1000));
export function kitFailed() {
  throttle.fails += 1;
  if (throttle.fails >= 3) throttle.until = Date.now() + Math.min(60, 5 * 2 ** (throttle.fails - 3)) * 1000;
}
export const kitSucceeded = () => { throttle.fails = 0; throttle.until = 0; };
/** Tests only. */
export const resetThrottle = kitSucceeded;
/** Whether an error is the kit's (a wrong passphrase, another account's kit, not a kit): counted by the throttle. */
export const kitFailure = (e) => !!e && e.name === 'DriveKitError' && ['auth', 'format', 'kind', 'owner', 'payload'].includes(e.check);
export function holdOff(btn, msg, sync) {
  showMsg(msg, `Too many failed attempts: try again in ${throttleWait()} seconds.`);
  btn.disabled = true;
  setTimeout(() => { sync(); msg.hidden = true; }, throttleWait() * 1000);
}

/**
 * A form's message inside a status line that is in the page from the start
 * (WCAG 4.1.3: a live region that appears together with its text is often not
 * read) → { msg (the message: showMsg / hidden), live (what goes in the page) }.
 */
export function liveMsg(id = null) {
  const msg = h('p.msg', { id, hidden: true });
  return { msg, live: h('div.kit-live', { role: 'status' }, msg) };
}

// ── fields ──────────────────────────────────────────────────────────────────
export const field = (label, control, hint = null) => h('label.field', {}, h('span.field-label', { text: label }), control, hint);
export const secret = (id, autocomplete) => h('input.input', { id, type: 'password', autocomplete, maxlength: '1024', spellcheck: 'false' });
export const fileInput = (id) => h('input.input', { id, type: 'file', accept: '.json,application/json' });

/** A date picker (the day, local time) with today as its default → { el, seconds() } (noon of the chosen day, in seconds). */
export function datePicker(id) {
  const today = new Date();
  const pad = (n) => String(n).padStart(2, '0');
  const el = h('input.input', { id, type: 'date', value: `${today.getFullYear()}-${pad(today.getMonth() + 1)}-${pad(today.getDate())}` });
  return {
    el,
    seconds() {
      const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(el.value || '');
      if (!m) return Math.floor(Date.now() / 1000);
      const d = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 12, 0, 0);
      // Today: now, so that a key that starts later today is not taken for in effect.
      const sameDay = d.toDateString() === new Date().toDateString();
      return Math.floor((sameDay ? Date.now() : d.getTime()) / 1000);
    },
  };
}

/**
 * Two passphrase fields and the warning under them (empty or short): the
 * passphrase is optional, with no minimum, per the rules. `what`: what the
 * kit opens (for the warning).
 */
export function passphrasePair(prefix, what) {
  const pass1 = secret(`${prefix}-pass`, 'new-password');
  const pass2 = secret(`${prefix}-pass2`, 'new-password');
  const weak = h('p.type-hint.warn', { id: `${prefix}-pass-warn`, role: 'note' });
  const sync = () => {
    const n = [...pass1.value].length;
    weak.hidden = n >= SHORT_PASSPHRASE;
    // The warning describes the passphrase field while it shows (and only then: WCAG 1.3.1).
    if (weak.hidden) pass1.removeAttribute('aria-describedby'); else pass1.setAttribute('aria-describedby', weak.id);
    weak.textContent = n === 0
      ? `No passphrase: the kit is still encrypted, but with a key anyone can derive. It opens ${what}: store it offline.`
      : `A short passphrase (under ${SHORT_PASSPHRASE} characters) is easy to guess offline. The kit opens ${what}: store it offline.`;
  };
  pass1.addEventListener('input', sync);
  sync();
  return { pass1, pass2, weak, sync, el: h('div.stack', {}, h('div.toolbar', {}, field('Kit passphrase (optional)', pass1), field('Repeat the kit passphrase', pass2)), weak) };
}

export function saveText(text, name) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const a = h('a', { href: url, download: name, hidden: true });
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** Read the selected file (never a copy kept by this page), then clear the input and the passphrase. */
export async function takeFile(input, passInput, sync = () => {}) {
  const file = input.files && input.files[0];
  const passphrase = passInput.value;
  passInput.value = '';
  input.value = '';
  sync();
  return { text: file ? await file.text() : null, passphrase };
}

/** "Pass" / "Warning" / "Fail" / "Not applicable": the status in words, not only in colour. */
const STATUS = { pass: 'Pass', warn: 'Warning', fail: 'Fail', skip: 'Not applicable' };

const KIT_VERDICTS = { complete: 'Complete: this kit covers everything in use', failed: 'This kit cannot be used', incomplete: 'Incomplete: see below' };

/**
 * A kit check's result list (`res`: { verdict, checks: [{ id, status, label,
 * detail }], summary?, fixes? }); `verdicts`: the heading for each verdict
 * (a kit's by default).
 */
export function verifyResults(res, id = 'kit-verify', verdicts = KIT_VERDICTS) {
  const verdict = verdicts[res.verdict] ?? verdicts.incomplete;
  return h('section.kit-results', { id: `${id}-results`, 'aria-labelledby': `${id}-verdict` },
    h('h3.section-title', { id: `${id}-verdict`, tabindex: '-1', dataset: { verdict: res.verdict }, text: verdict }),
    res.summary ? h('p', { id: `${id}-summary`, text: res.summary }) : null,
    h('ul.kit-checks', {}, ...res.checks.map((c) => h('li', { dataset: { check: c.id, status: c.status } },
      h(`strong.kit-${c.status}`, { text: `${STATUS[c.status] || c.status}: ` }), `${c.label}. `, h('span.muted', { text: c.detail || '' })))),
    res.fixes && res.fixes.length ? h('ul.plan-list', { 'aria-label': 'What to do' }, ...res.fixes.map((f) => h('li', { text: f }))) : null);
}
