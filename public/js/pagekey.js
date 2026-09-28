// pagekey.js — keeping a share link's key (the #fragment) out of the page that
// runs Cloudflare's Turnstile script, for shares that have the CAPTCHA (the
// shareCaptcha / reverseCaptcha role options; SECURITY.md, "CAPTCHA on
// shares").
//
// The recipient's page (/p/<id>) and the uploader's page (/r/<id>) always run
// under the strict CSP, where no third-party script can load. When the server
// answers `captcha_required`, the page:
//   1. takes the key out of the address bar (history.replaceState);
//   2. seals it — with this tab's Drive keys, which leave sessionStorage too —
//      under the page key the Worker put in this document (a meta tag
//      "secbin-page-key": a nonce n and a key bound to the share and n, given
//      only on a real navigation, never to fetch()), and keeps only
//      { n, iv, ct } in sessionStorage (this tab only);
//   3. goes to the check page (<page>?check), which runs the Turnstile widget
//      and holds nothing it could open;
// and the check page, once the CAPTCHA passed, stores the grant and returns
// to <page>?n=<n>: a new strict document whose navigation carries the page key
// for n again, which opens the sealed key, removes it from sessionStorage,
// puts the key back in the address bar and opens the share.
//
// Without sessionStorage, or without a page key (a browser that does not send
// Fetch Metadata), a protected share is not opened (fail closed).

import { b64urlFromBytes, bytesFromB64url, utf8, fromUtf8 } from './bytes.js';

const RECORD = (kind, id) => `secbin_pk:${kind}:${id}`;
const GRANT = (kind, id) => `secbin_hg:${kind}:${id}`;
const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;
const KEY_RE = /^[A-Za-z0-9_-]{43}$/;
// The tab's Drive keys (public/js/drivekeys.js): they must not be readable where the check page runs.
export const DRIVE_SLOTS = ['secbin_dk', 'secbin_dk_uid', 'secbin_dk_imp', 'secbin_dk_imp_uid'];

/** This tab's sessionStorage if it works (write, read, remove), else null. */
export function tabStorage(win = globalThis) {
  try {
    const s = win.sessionStorage;
    if (!s) return null;
    const probe = 'secbin_probe';
    s.setItem(probe, '1');
    const ok = s.getItem(probe) === '1';
    s.removeItem(probe);
    return ok ? s : null;
  } catch {
    return null;
  }
}

/**
 * The page key the Worker put in this document → { n, key } (and the tag is
 * removed), or null when there is none.
 */
export function readPageKey(doc = globalThis.document) {
  const el = doc && doc.querySelector('meta[name="secbin-page-key"]');
  if (!el) return null;
  const [n, key] = String(el.getAttribute('content') || '').split('.');
  el.remove();
  return NONCE_RE.test(n) && KEY_RE.test(key) ? { n, key } : null;
}

const aad = (kind, id, n) => utf8(`secbin-page/v1\n${kind}\n${id}\n${n}\n`);
const aesKey = (key, use) => crypto.subtle.importKey('raw', bytesFromB64url(key), { name: 'AES-GCM' }, false, [use]);

/**
 * Seal `fragment` (and the tab's Drive keys, which are removed from storage)
 * under the page key and keep the sealed record in `storage`.
 */
export async function stashKey({ kind, id, fragment, pageKey, storage }) {
  const drive = {};
  for (const k of DRIVE_SLOTS) {
    const v = storage.getItem(k);
    if (v !== null) drive[k] = v;
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(kind, id, pageKey.n) },
    await aesKey(pageKey.key, 'encrypt'), utf8(JSON.stringify({ k: fragment, d: drive }))));
  storage.setItem(RECORD(kind, id), JSON.stringify({ n: pageKey.n, iv: b64urlFromBytes(iv), ct: b64urlFromBytes(ct) }));
  for (const k of DRIVE_SLOTS) storage.removeItem(k);
}

/** The nonce of the sealed record for this share (the check page returns to ?n=<n>), or null. */
export function stashedNonce({ kind, id, storage }) {
  try {
    const r = JSON.parse(storage.getItem(RECORD(kind, id)) || 'null');
    return r && NONCE_RE.test(r.n) ? r.n : null;
  } catch {
    return null;
  }
}

/**
 * Open the sealed record with the page key (it must be for the same nonce),
 * remove it, put the Drive keys back → the fragment, or null.
 */
export async function takeKey({ kind, id, pageKey, storage }) {
  const raw = storage.getItem(RECORD(kind, id));
  storage.removeItem(RECORD(kind, id));
  if (!raw || !pageKey) return null;
  try {
    const r = JSON.parse(raw);
    if (!r || r.n !== pageKey.n) return null;
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytesFromB64url(r.iv), additionalData: aad(kind, id, r.n) },
      await aesKey(pageKey.key, 'decrypt'), bytesFromB64url(r.ct));
    const v = JSON.parse(fromUtf8(new Uint8Array(pt)));
    if (!v || typeof v.k !== 'string' || !v.k) return null;
    for (const [k, val] of Object.entries(v.d || {})) if (DRIVE_SLOTS.includes(k) && typeof val === 'string') storage.setItem(k, val);
    return v.k;
  } catch {
    return null;
  }
}

/** Forget the sealed record (it is of no use once the key is known again). */
export function dropKey({ kind, id, storage }) {
  try { storage.removeItem(RECORD(kind, id)); } catch { /* storage refused */ }
}

/** The CAPTCHA grant kept for this share in this tab. */
export function loadGrant({ kind, id, storage }) {
  try { return storage ? storage.getItem(GRANT(kind, id)) : null; } catch { return null; }
}
export function saveGrant({ kind, id, storage, grant }) {
  try { if (grant) storage.setItem(GRANT(kind, id), grant); else storage.removeItem(GRANT(kind, id)); } catch { /* storage refused */ }
}

/**
 * Leave for the check page: the key out of the address bar at once, then
 * sealed, then the check page (replacing this history entry). Resolves to
 * 'no_storage' | 'no_page_key' when that is impossible (nothing is kept
 * then, and the page says why); otherwise the page is being left.
 */
export async function goToCheck({ kind, id, fragment, pageKey, storage, win = globalThis }) {
  const path = win.location.pathname;
  win.history.replaceState(null, '', path);
  if (!storage) return 'no_storage';
  if (!pageKey) return 'no_page_key';
  await stashKey({ kind, id, fragment, pageKey, storage });
  win.location.replace(`${path}?check`);
  return 'leaving';
}

/** A readable reason for `goToCheck`'s refusals. */
export const CHECK_REFUSED = {
  no_storage: 'This share requires a CAPTCHA, and this browser does not let the page keep the link for this tab while you complete it (site storage is off, or this is a restricted window). Allow site storage for this site, or open the link in another browser.',
  no_page_key: 'This share requires a CAPTCHA, which this browser cannot complete safely here (it does not send the headers the page needs). Update the browser, or open the link in another one.',
};
