// mek.js — the Worker's side of the Drive key model v2 (docs/DRIVE.md §3):
// the user's KEKs (derived by the Directory from the root MEK, the sub-MEKs
// and the user salt), and opening, checking and re-sealing what the Drive
// stores under them. Everything opened here stays in this request's memory:
// a DEK or a name is unwrapped only to be checked or re-sealed, never stored
// or logged in the clear.

import { HttpError } from './http.js';
import { directory } from './guard.js';
import {
  keyBytes, openDek, sealDek, openName, sealName, openLinkKey, sealLinkKey, sealAtRest, openAtRest, isAtRest, newSalt, newKey,
} from '../../public/js/drivekeys.js';
import { b64urlFromBytes } from '../../public/js/bytes.js';

/** The fields the field layer seals for a user (sealAtRest), each with its own key. */
export const AT_REST_FIELDS = ['linkKey', 'received'];

/**
 * The user's KEKs → { userId, salt, current, changing, keks: Map(mekId → {
 * kek, kekOld, fp, from, until }), missing, broken, version (the keyring's
 * version, docs/DRIVE.md §3.1) }. `meks`: the sub-MEKs
 * wanted (the current one always comes too), or `all`. HttpError when the
 * Directory has no salt or no root for them.
 */
export async function userKeys(env, uid, { meks = [], all = false, createSalt = false } = {}) {
  const r = await directory(env).driveKeys(uid, { meks, all, createSalt });
  if (!r.ok) throw new HttpError(r.status, r.error, r.message);
  const keks = new Map();
  for (const k of r.keys) keks.set(k.mekId, { kek: keyBytes(k.kek), kekOld: k.kekOld ? keyBytes(k.kekOld) : null, fp: k.fp, from: k.from, until: k.until });
  return { userId: r.userId, salt: r.salt, current: r.current, changing: r.changing, keks, missing: r.missing, broken: r.broken, version: r.version };
}

/** The KEKs an item sealed under `mekId` may open with: under the root now, then (during a root change) the previous one. */
export function keksOf(keys, mekId) {
  const k = keys.keks.get(mekId);
  if (!k) return [];
  return k.kekOld ? [k.kek, k.kekOld] : [k.kek];
}

/** The current sub-MEK's KEK and fingerprint → { mek, mfp, kek }. */
export function currentKek(keys) {
  const k = keys.current ? keys.keks.get(keys.current) : null;
  if (!k) throw new HttpError(503, 'keys_missing', 'The current Drive key is not available: the administrator checks Admin → Security → Keys.');
  return { mek: keys.current, mfp: k.fp, kek: k.kek };
}

const parsed = (v) => (typeof v === 'string' ? JSON.parse(v) : v);

/**
 * Open an item's sealed fields ({ kind, ks, mek, name, meta, dek }) with
 * `keks` → { kek (the one that opened its name), name, meta, dek } (bytes;
 * meta null when there is none, dek for files only). Each field may open
 * under a different one of `keks` (during a root change an item can hold a
 * name sealed under the new root and a DEK still under the old one); with one
 * KEK, every field must open under it. Throws when a field opens under none.
 */
export async function openItem(uid, keks, item) {
  const at = { userId: uid, mekId: item.mek, salt: item.ks };
  const first = async (fn) => {
    let last;
    for (const kek of keks) {
      try { return { kek, v: await fn(kek) }; } catch (e) { last = e; }
    }
    throw last || new Error('no key');
  };
  const name = await first((kek) => openName(kek, at, 'name', parsed(item.name)));
  let meta = null;
  try {
    meta = item.meta ? (await first((kek) => openName(kek, at, 'meta', parsed(item.meta)))).v : null;
    const dek = item.kind === 'file' ? (await first((kek) => openDek(kek, at, parsed(item.dek)))).v : null;
    return { kek: name.kek, name: name.v, meta, dek };
  } catch (e) {
    name.v.fill(0);
    if (meta) meta.fill(0);
    throw e;
  }
}

/**
 * Seal an item's fields under a KEK with a fresh salt → { ks, mek, mfp,
 * name, meta, dek } as stored JSON text (meta / dek null when absent).
 */
export async function sealItem(uid, { kek, mek, mfp }, { name, meta = null, dek = null }) {
  const ks = newSalt();
  const at = { userId: uid, mekId: mek, salt: ks };
  return {
    ks, mek, mfp,
    name: JSON.stringify(await sealName(kek, at, 'name', name)),
    meta: meta ? JSON.stringify(await sealName(kek, at, 'meta', meta)) : null,
    dek: dek ? JSON.stringify(await sealDek(kek, at, dek)) : null,
  };
}

/**
 * Check what a browser sealed for a new (or taken-in) item: it must open
 * under the current sub-MEK's KEK (so the server can re-seal it later), with
 * a 32-byte DEK for a file. The opened values are dropped at once.
 * `inspect(name, meta)` (optional) sees the opened name and metadata bytes
 * first, in memory only (the role's file-type rules: src/lib/drivepolicy.js);
 * they are zeroed after it, whatever it does.
 */
export async function checkNewItem(uid, keys, item, inspect = null) {
  if (item.mek !== keys.current) throw new HttpError(409, 'mek_not_current', 'The Drive key changed: reload the page to use the current one.');
  const { kek } = currentKek(keys);
  let r;
  try { r = await openItem(uid, [kek], item); } catch { throw new HttpError(400, 'bad_seal', 'The item is not sealed under your current Drive key.'); }
  try {
    if (inspect) inspect(r.name, r.meta);
  } finally {
    r.name.fill(0);
    if (r.meta) r.meta.fill(0);
    if (r.dek) r.dek.fill(0);
  }
  return keys.keks.get(keys.current).fp;
}

/**
 * Check an item's new name or metadata, sealed under its own mek and salt (a
 * rename): only under the KEK of the root MEK now. One sealed under the
 * previous root (a page that fetched its keys before a root change) is
 * refused with `409 stale_keys`, so the browser fetches its keys and seals
 * again: nothing new is ever stored under a root that is going.
 */
export async function checkField(uid, keys, { mek, ks }, field, value) {
  const k = keys.keks.get(mek);
  const at = { userId: uid, mekId: mek, salt: ks };
  if (k) {
    try { (await openName(k.kek, at, field, value)).fill(0); return; } catch { /* not under the root now */ }
    if (k.kekOld) {
      let old = false;
      try { (await openName(k.kekOld, at, field, value)).fill(0); old = true; } catch { /* not under the previous root either */ }
      if (old) throw new HttpError(409, 'stale_keys', 'The Drive keys changed: reload the page to use the current ones.');
    }
  }
  throw new HttpError(400, 'bad_seal', 'The name is not sealed under this item’s key.');
}

/** A link key sealed by the browser under the current KEK: it must open. */
export async function checkLinkKey(uid, keys, linkId, mek, sealed) {
  if (mek !== keys.current) throw new HttpError(409, 'mek_not_current', 'The Drive key changed: reload the page to use the current one.');
  try { (await openLinkKey(currentKek(keys).kek, { userId: uid, mekId: mek, linkId }, sealed)).fill(0); } catch {
    throw new HttpError(400, 'bad_seal', 'The link key is not sealed under your current Drive key.');
  }
}

/** Open a link key with the KEKs of its mek → PKCS#8 bytes (or throws). */
export async function openLink(uid, keys, linkId, mek, sealed) {
  let last;
  for (const kek of keksOf(keys, mek)) {
    try { return { kek, pkcs8: await openLinkKey(kek, { userId: uid, mekId: mek, linkId }, sealed) }; } catch (e) { last = e; }
  }
  throw last || new Error('no key');
}

/** A link key re-sealed under another KEK → { iv, ct }. */
export async function resealLink(uid, { kek, mek }, linkId, pkcs8) {
  return sealLinkKey(kek, { userId: uid, mekId: mek, linkId }, pkcs8);
}

// ── the field layer ─────────────────────────────────────────────────────────

/** The user's field keys → { cur: { field: bytes }, old: { … } | null }. */
export async function fieldKeys(env, uid) {
  const r = await directory(env).fieldKeys(uid, AT_REST_FIELDS);
  if (!r.ok) throw new HttpError(r.status, r.error, r.message);
  const conv = (o) => (o ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k, keyBytes(v)])) : null);
  return { cur: conv(r.cur), old: conv(r.old) };
}

/** Seal `text` at rest for the user (field `field`, bound to `ref`). */
export function toRest(fk, uid, field, ref, text) {
  return sealAtRest(fk.cur[field], { userId: uid, field, ref }, text);
}

/**
 * A value stored at rest back as text: opened with the field key (the one
 * now, then the previous one during a root change). A value stored before
 * the field layer (plain JSON text) comes back as it is.
 */
export async function fromRest(fk, uid, field, ref, value) {
  if (!isAtRest(value)) return value;
  for (const set of [fk.cur, fk.old]) {
    if (!set) continue;
    try { return await openAtRest(set[field], { userId: uid, field, ref }, value); } catch { /* the next one */ }
  }
  throw new HttpError(500, 'unreadable', 'A stored value does not open with this account’s field key.');
}

export { newKey, b64urlFromBytes };
