// keychoice.js — a key the server generated, shown for the owner to choose
// (docs/DRIVE.md §3, §3.2): the same pieces on Admin → Security → Keys ("Use
// this key" / "Generate another" / "Enter manually", admin-keys.js) and on the
// set-up page ("Use these" / "Generate again" / "Enter manually", setup.js).
// The key is a candidate the server keeps for 10 minutes and uses only when
// it is chosen; nothing here stores it. DOM through h() only (strict CSP).

import { h } from './common.js';
import { copyText, flashCopied } from './ui.js';

/** A key's fingerprint as the pages show it (xxxx-xxxx-xxx). */
export const fpText = (fp) => (typeof fp === 'string' && fp.length >= 8 ? `${fp.slice(0, 4)}-${fp.slice(4, 8)}-${fp.slice(8)}` : '—');

/** The out-of-band help for a key entered by hand. */
export const MANUAL_KEY_HELP = 'Generate a key out of band and paste it here (base64 or hex, exactly 32 bytes), for example: openssl rand -base64 32 — or in PowerShell: [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) (not Get-Random, which is not a secure generator) — or from a hardware security module or secrets manager. Keep a copy in a secrets manager.';

const MASK = '••••••••••••••••••••••••••••••••';

/**
 * One generated key: its fingerprint, its value (`masked`: hidden until
 * "Show", and hidden again with "Hide") and a copy button. `cand`: { key,
 * fp }; `label`: what it is ("root MEK", "generated key"); `id`: the
 * element's id (its parts get `${id}-value`, `${id}-show`).
 */
export function candidateView({ id, label, cand, masked = false }) {
  const val = h('code.mono.key-value', { id: `${id}-value`, text: masked ? MASK : cand.key });
  const hiddenNote = masked ? h('span.sr-only', { id: `${id}-hidden`, text: `The ${label} is hidden.` }) : null;
  const copy = h('button.copy-btn', { type: 'button', text: 'copy', 'aria-label': `Copy the ${label}` });
  copy.addEventListener('click', async () => flashCopied(copy, (await copyText(cand.key)) ? 'copied' : 'failed'));
  let show = null;
  if (masked) {
    show = h('button.btn.mini', { type: 'button', id: `${id}-show`, text: 'Show', 'aria-label': `Show the ${label}`, 'aria-controls': val.id });
    show.addEventListener('click', () => {
      const open = val.textContent === MASK;
      val.textContent = open ? cand.key : MASK;
      hiddenNote.hidden = open;
      show.textContent = open ? 'Hide' : 'Show';
      show.setAttribute('aria-label', `${open ? 'Hide' : 'Show'} the ${label}`);
    });
  }
  return h('div.stack.key-candidate', { id, dataset: { fp: cand.fp } },
    h('p', {}, `${label[0].toUpperCase()}${label.slice(1)} (fingerprint `, h('span.mono', { text: fpText(cand.fp) }), '):'),
    val, hiddenNote, h('div.btn-row', {}, show, copy));
}
