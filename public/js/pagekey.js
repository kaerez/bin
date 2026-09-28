// pagekey.js — keeping a share link's key (the #fragment) out of the page that
// runs Cloudflare's Turnstile script, for shares that have the CAPTCHA (the
// shareCaptcha / reverseCaptcha role options; SECURITY.md, "CAPTCHA on
// shares").
//
// The recipient's page (/p/<id>) and the uploader's page (/r/<id>) always run
// under the strict CSP, where no third-party script can load. When the server
// answers `captcha_required`, the page:
//   1. takes the key out of the address bar (history.replaceState);
//   2. removes this tab's Drive keys from sessionStorage (they never go
//      through the check: the Drive asks to be unlocked again afterwards);
//   3. seals the link's key — only that — under the page key the Worker put
//      in this document (a meta tag "secbin-page-key": a nonce n and 32
//      random bytes, also held by the browser in an HttpOnly cookie for this
//      share's path, 15 minutes), and keeps only { n, iv, ct } in
//      sessionStorage (this tab only);
//   4. goes to the check page (<page>?check), which runs the Turnstile widget
//      and holds nothing it could open;
// and the check page, once the CAPTCHA passed, stores the grant and returns
// to <page>?n=<n>: a new strict document, which the Worker gives the page key
// again only because the navigation carries that cookie (then cleared: one
// use). It opens the sealed key, removes it from sessionStorage, puts the key
// back in the address bar and opens the share.
//
// A page that has no fresh page key (it was opened from another site, whose
// navigation gets none, or its key was used on a return) first reloads itself
// once, as its own same-origin navigation (<page>?pk#<key>), to get one.
// Without sessionStorage, or still without a page key, a protected share is
// not opened (fail closed).

import { b64urlFromBytes, bytesFromB64url, utf8, fromUtf8 } from './bytes.js';

const RECORD = (kind, id) => `secbin_pk:${kind}:${id}`;
const GRANT = (kind, id) => `secbin_hg:${kind}:${id}`;
const NONCE_RE = /^[A-Za-z0-9_-]{22}$/;
const KEY_RE = /^[A-Za-z0-9_-]{43}$/;
// The tab's Drive keys (public/js/drivekeys.js: secbin_dk, secbin_dk_uid,
// secbin_dk_imp, secbin_dk_imp_uid, and any later slot of that family): they
// must never be readable where the check page runs.
const DRIVE_PREFIX = 'secbin_dk';

/** Remove every Drive key slot of this tab from `storage`. */
export function dropDriveKeys(storage) {
  const names = [];
  for (let i = 0; i < storage.length; i++) {
    const k = storage.key(i);
    if (k !== null && k.startsWith(DRIVE_PREFIX)) names.push(k);
  }
  for (const k of names) storage.removeItem(k);
}

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
 * Seal `fragment` — and nothing else — under the page key and keep the sealed
 * record in `storage`. The tab's Drive keys are removed first.
 */
export async function stashKey({ kind, id, fragment, pageKey, storage }) {
  dropDriveKeys(storage);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(kind, id, pageKey.n) },
    await aesKey(pageKey.key, 'encrypt'), utf8(JSON.stringify({ k: fragment }))));
  storage.setItem(RECORD(kind, id), JSON.stringify({ n: pageKey.n, iv: b64urlFromBytes(iv), ct: b64urlFromBytes(ct) }));
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
 * remove it → the fragment, or null. The page key is spent: a later check
 * from this document gets a fresh one (goToCheck).
 */
export async function takeKey({ kind, id, pageKey, storage }) {
  const raw = storage.getItem(RECORD(kind, id));
  storage.removeItem(RECORD(kind, id));
  if (!raw || !pageKey) return null;
  pageKey.spent = true;
  try {
    const r = JSON.parse(raw);
    if (!r || r.n !== pageKey.n) return null;
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytesFromB64url(r.iv), additionalData: aad(kind, id, r.n) },
      await aesKey(pageKey.key, 'decrypt'), bytesFromB64url(r.ct));
    const v = JSON.parse(fromUtf8(new Uint8Array(pt)));
    return v && typeof v.k === 'string' && v.k ? v.k : null;
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
 * This document was the page's own reload for a page key (<page>?pk): take
 * `pk` out of the address (the key stays after "#") → true, else false.
 */
export function keyReload(win = globalThis) {
  const q = new URLSearchParams(win.location.search || '');
  if (!q.has('pk')) return false;
  q.delete('pk');
  const rest = q.toString();
  win.history.replaceState(null, '', `${win.location.pathname}${rest ? `?${rest}` : ''}${win.location.hash || ''}`);
  return true;
}
let reloadedForKey = typeof location !== 'undefined' && typeof history !== 'undefined' ? keyReload() : false;

/**
 * Leave for the check page: the Drive keys and the link's key out of the
 * tab, the link's key sealed, then the check page (replacing this history
 * entry). Without a fresh page key the page first reloads itself once
 * (<page>?pk#<key>, a same-origin navigation the Worker gives a new key).
 * Resolves to 'no_storage' | 'no_page_key' when it is impossible (nothing is
 * kept then, and the page says why); otherwise the page is being left.
 */
export async function goToCheck({ kind, id, fragment, pageKey, storage, win = globalThis, reloaded = reloadedForKey }) {
  const path = win.location.pathname;
  if (storage) dropDriveKeys(storage);
  if (storage && (!pageKey || pageKey.spent) && !reloaded) {
    reloadedForKey = true;
    win.location.replace(`${path}?pk#${fragment}`);
    return 'leaving';
  }
  win.history.replaceState(null, '', path);
  if (!storage) return 'no_storage';
  if (!pageKey || pageKey.spent) return 'no_page_key';
  await stashKey({ kind, id, fragment, pageKey, storage });
  pageKey.spent = true;
  win.location.replace(`${path}?check`);
  return 'leaving';
}

/** A readable reason for `goToCheck`'s refusals. */
export const CHECK_REFUSED = {
  no_storage: 'This share requires a CAPTCHA, and this browser does not let the page keep the link for this tab while you complete it (site storage is off, or this is a restricted window). Allow site storage for this site, or open the link in another browser.',
  no_page_key: 'This share requires a CAPTCHA, which this browser cannot complete safely here (it does not send the headers the page needs). Update the browser, or open the link in another one.',
};
