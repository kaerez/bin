// keychoice.js — a key the server generated, shown for the owner to choose
// (docs/DRIVE.md §3, §3.2): the same pieces on Admin → Security → Keys ("Use
// this key" / "Generate another" / "Enter manually", admin-keys.js) and on the
// set-up page ("Use these" / "Generate again" / "Enter manually", setup.js).
// The key is a candidate the server keeps for 10 minutes and uses only when
// it is chosen; nothing here stores it. DOM through h() only (strict CSP).

import { h } from './common.js';
import { copyText, flashCopied, toast } from './ui.js';

/** A key's fingerprint as the pages show it (xxxx-xxxx-xxx). */
export const fpText = (fp) => (typeof fp === 'string' && fp.length >= 8 ? `${fp.slice(0, 4)}-${fp.slice(4, 8)}-${fp.slice(8)}` : '—');

/** The out-of-band help for a key entered by hand. */
export const MANUAL_KEY_HELP = 'Generate a key out of band and paste it here (base64 or hex, exactly 32 bytes), for example: openssl rand -base64 32 — or in PowerShell: [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32)) (not Get-Random, which is not a secure generator) — or from a hardware security module or secrets manager. Keep a copy in a secrets manager.';

const MASK = '••••••••••••••••••••••••••••••••';
export const CLEAR_MS = 60000;

/**
 * Whether this page may read the clipboard: the clear below checks that the
 * clipboard still holds the key before it empties it, so that nothing else
 * the person copied is wiped. The site's Permissions-Policy denies
 * clipboard-read (src/lib/http.js), so this is false there, and the page says
 * so instead of promising a clear.
 */
function canReadClipboard() {
  try {
    const fp = document.featurePolicy || document.permissionsPolicy;
    if (fp && typeof fp.allowsFeature === 'function') return fp.allowsFeature('clipboard-read');
    return !!(navigator.clipboard && typeof navigator.clipboard.readText === 'function');
  } catch {
    return false;
  }
}

/**
 * After CLEAR_MS, empty the clipboard — only while this page has focus and
 * the clipboard still holds `key` (read back to check). Best effort: any
 * failure (no permission, no focus, the browser refusing) leaves it as it is.
 */
function clearLater(key) {
  setTimeout(async () => {
    try {
      if (!document.hasFocus()) return;
      if ((await navigator.clipboard.readText()) !== key) return;
      await navigator.clipboard.writeText('');
    } catch { /* left as it is */ }
  }, CLEAR_MS);
}

/** Copy a key: the copy button's state, and a toast saying whether the clipboard will be cleared. */
export async function copyKey(btn, key) {
  const ok = await copyText(key);
  flashCopied(btn, ok ? 'copied' : 'failed');
  if (!ok) return false;
  if (canReadClipboard()) {
    clearLater(key);
    toast('Copied. Clipboard clears in 60 s.');
  } else {
    toast('Copied. This page cannot clear the clipboard: clear it (and any clipboard history) once the key is stored.');
  }
  return true;
}

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
  copy.addEventListener('click', () => copyKey(copy, cand.key));
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
