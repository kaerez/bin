// drivekeys.js — the Drive key model v2 (docs/DRIVE.md §3), shared by the
// Worker (it derives and re-seals) and the browser (it seals new items and
// opens them). Every key is 32 bytes; every seal is AES-256-GCM.
//
//   root MEK   random, one per instance, stored in the Directory;
//   sub-MEK    random, sealed under the root MEK (sealSubMek), each with
//              from / until dates, one current;
//   user salt  random, one per user, created with the user, never changed;
//   KEK        HKDF(ikm = root MEK ‖ sub-MEK, salt = user salt,
//              info "secbin-kek/v1\n<userId>") — one per user per sub-MEK,
//              derived by the server and handed to the user's session;
//   DEK        random per file; it encrypts the content (files.js
//              encryptChunk) and is sealed under
//              HKDF(ikm = KEK, salt = the per-DEK salt, info "secbin-dek/v1"),
//              AAD "secbin-dek/v1\n<userId>\n<mekId>" (no item id);
//   names      an item's name and metadata, sealed under
//              HKDF(ikm = KEK, salt = the item's salt, info "secbin-names/v1"),
//              AAD "secbin-names/v1\n<userId>\n<mekId>\n<field>";
//   link key   a reverse share's private key, sealed under
//              HKDF(ikm = KEK, salt = "", info "secbin-reverse-link/v1"),
//              AAD "secbin-reverse-link/v1\n<userId>\n<mekId>\n<linkId>";
//   user key   (the field layer) HKDF(ikm = root MEK, salt = user salt,
//              info "secbin-user/v1\n<userId>"); field keys
//              HKDF(user key, "", "secbin-atrest/v1\n<field>") seal what the
//              server keeps at rest for the user (sealAtRest).
//
// An item's DEK and names share one mekId and one random 32-byte salt (the
// "per-DEK salt"; folders have one too, for their names). No item id is bound
// into a key or an AAD (docs/DRIVE.md §9 says what that means).
//
// The tab's copy of the keys the server handed out (the KEKs) lives in
// sessionStorage until sign-out or the tab closes, as the Drive key did.

import { randomBytes, utf8, b64urlFromBytes, bytesFromB64url, timingSafeEqualHex } from './bytes.js';
import { hkdf32, DecryptError } from './crypto.js';

export const KEY_BYTES = 32;
export const SALT_BYTES = 32;
/** A sub-MEK's id: "m" + 8 random bytes, base64url. */
export const MEK_ID_RE = /^m[A-Za-z0-9_-]{11}$/;
/** A 32-byte value, base64url (keys, salts, KEKs). */
export const KEY_RE = /^[A-Za-z0-9_-]{43}$/;
const EMPTY = new Uint8Array(0);

export const newMekId = () => `m${b64urlFromBytes(randomBytes(8))}`;
/** A new random key (root MEK, sub-MEK, DEK) or salt: 32 bytes. */
export const newKey = () => randomBytes(KEY_BYTES);
export const newSalt = () => b64urlFromBytes(randomBytes(SALT_BYTES));

const isKey = (k) => k instanceof Uint8Array && k.length === KEY_BYTES;
function need(k, what = 'key') {
  if (!isKey(k)) throw new TypeError(`invalid ${what}`);
  return k;
}
/** A base64url 32-byte value → bytes; TypeError otherwise. */
export function keyBytes(v, what = 'key') {
  if (v instanceof Uint8Array) return need(v, what);
  if (typeof v !== 'string' || !KEY_RE.test(v)) throw new TypeError(`invalid ${what}`);
  return need(bytesFromB64url(v), what);
}

async function aesKey(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function seal(key, ad, bytes) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: ad, tagLength: 128 }, key, bytes));
  return { iv: b64urlFromBytes(iv), ct: b64urlFromBytes(ct) };
}
async function open(key, ad, sealed) {
  let iv;
  let ct;
  try {
    const s = typeof sealed === 'string' ? JSON.parse(sealed) : sealed;
    iv = bytesFromB64url(s.iv);
    ct = bytesFromB64url(s.ct);
  } catch {
    throw new DecryptError('invalid sealed value');
  }
  if (iv.length !== 12 || ct.length < 16) throw new DecryptError('invalid sealed value');
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: ad, tagLength: 128 }, key, ct));
  } catch {
    throw new DecryptError();
  }
}
async function hmac(key, text) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, utf8(text)));
}
const toBytes = (v) => (typeof v === 'string' ? utf8(v) : v);

// ── derivations ────────────────────────────────────────────────────────────

/** KEK = HKDF(root MEK ‖ sub-MEK, user salt, "secbin-kek/v1\n<userId>") → 32 bytes. */
export async function deriveKek(root, sub, userSalt, userId) {
  need(root, 'root MEK');
  need(sub, 'sub-MEK');
  if (typeof userId !== 'string' || !userId) throw new TypeError('user id required');
  const ikm = new Uint8Array(KEY_BYTES * 2);
  ikm.set(root, 0);
  ikm.set(sub, KEY_BYTES);
  try {
    return await hkdf32(ikm, keyBytes(userSalt, 'user salt'), utf8(`secbin-kek/v1\n${userId}`));
  } finally {
    ikm.fill(0);
  }
}

/** The field layer's user key: HKDF(root MEK, user salt, "secbin-user/v1\n<userId>"). */
export async function deriveUserKey(root, userSalt, userId) {
  need(root, 'root MEK');
  if (typeof userId !== 'string' || !userId) throw new TypeError('user id required');
  return hkdf32(root, keyBytes(userSalt, 'user salt'), utf8(`secbin-user/v1\n${userId}`));
}

/** A field key of the field layer: HKDF(user key, "", "secbin-atrest/v1\n<field>"). */
export async function deriveFieldKey(userKey, field) {
  return hkdf32(need(userKey, 'user key'), EMPTY, utf8(`secbin-atrest/v1\n${field}`));
}

/** A key's fingerprint: the first 8 bytes of HMAC(key, "secbin-mek-fp/v1"), base64url (11 characters). Reveals nothing about the key. */
export async function keyFingerprint(key) {
  return b64urlFromBytes((await hmac(need(key), 'secbin-mek-fp/v1')).subarray(0, 8));
}

/**
 * Check values for a kit's Verify (the server compares them with its own in
 * constant time and answers match or no match only): HMAC(key, label).
 */
export const CHECK_LABELS = Object.freeze({ kek: 'secbin-kek-check/v1', mek: 'secbin-mek-check/v1' });
export async function keyCheckValue(key, kind = 'kek') {
  if (!CHECK_LABELS[kind]) throw new TypeError('unknown check');
  return b64urlFromBytes(await hmac(need(key), CHECK_LABELS[kind]));
}
/** A user salt's check value: HMAC(salt, "secbin-salt-check/v1\n<userId>"). */
export async function saltCheckValue(salt, userId) {
  return b64urlFromBytes(await hmac(keyBytes(salt, 'user salt'), `secbin-salt-check/v1\n${userId}`));
}
/** Constant-time comparison of two check values (base64url strings). */
export const sameCheck = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && a.length > 0 && timingSafeEqualHex(a, b);

// ── DEKs, names and link keys (sealed under a KEK) ─────────────────────────

const dekAad = (userId, mekId) => utf8(`secbin-dek/v1\n${userId}\n${mekId}`);
const namesAad = (userId, mekId, field) => utf8(`secbin-names/v1\n${userId}\n${mekId}\n${field}`);
const linkAad = (userId, mekId, linkId) => utf8(`secbin-reverse-link/v1\n${userId}\n${mekId}\n${linkId}`);
const where = ({ userId, mekId } = {}) => {
  if (typeof userId !== 'string' || !userId || typeof mekId !== 'string' || !MEK_ID_RE.test(mekId)) throw new TypeError('user id and mek id required');
};

async function dekKey(kek, salt) {
  return aesKey(await hkdf32(need(kek, 'KEK'), keyBytes(salt, 'salt'), utf8('secbin-dek/v1')));
}
async function namesKey(kek, salt) {
  return aesKey(await hkdf32(need(kek, 'KEK'), keyBytes(salt, 'salt'), utf8('secbin-names/v1')));
}

/** Seal a DEK (32 bytes) under `kek` with the item's salt → { iv, ct }. */
export async function sealDek(kek, { userId, mekId, salt }, dek) {
  where({ userId, mekId });
  return seal(await dekKey(kek, salt), dekAad(userId, mekId), need(dek, 'DEK'));
}

/** The DEK back → 32 bytes; DecryptError under another KEK, salt, user or mekId. */
export async function openDek(kek, { userId, mekId, salt }, sealed) {
  where({ userId, mekId });
  const dek = await open(await dekKey(kek, salt), dekAad(userId, mekId), sealed);
  if (!isKey(dek)) throw new DecryptError('invalid DEK');
  return dek;
}

/** Seal an item's `field` ('name' | 'meta') → { iv, ct }. */
export async function sealName(kek, { userId, mekId, salt }, field, value) {
  where({ userId, mekId });
  return seal(await namesKey(kek, salt), namesAad(userId, mekId, field), toBytes(value));
}

/** An item's `field` back → bytes; DecryptError when it does not open. */
export async function openName(kek, { userId, mekId, salt }, field, sealed) {
  where({ userId, mekId });
  return open(await namesKey(kek, salt), namesAad(userId, mekId, field), sealed);
}

async function linkKey(kek) {
  return aesKey(await hkdf32(need(kek, 'KEK'), EMPTY, utf8('secbin-reverse-link/v1')));
}

/** A reverse share's private key (PKCS#8 bytes) sealed under HKDF(KEK, "reverse-link") → { iv, ct }. */
export async function sealLinkKey(kek, { userId, mekId, linkId }, pkcs8) {
  where({ userId, mekId });
  return seal(await linkKey(kek), linkAad(userId, mekId, linkId), pkcs8);
}

export async function openLinkKey(kek, { userId, mekId, linkId }, sealed) {
  where({ userId, mekId });
  return open(await linkKey(kek), linkAad(userId, mekId, linkId), sealed);
}

// ── the keyring's own seals (the Worker / Directory only) ──────────────────

async function subSealKey(root) {
  return aesKey(await hkdf32(need(root, 'root MEK'), EMPTY, utf8('secbin-mek-seal/v1')));
}

/** A sub-MEK sealed under the root MEK → "m1.<iv>.<ct>". */
export async function sealSubMek(root, id, sub) {
  const s = await seal(await subSealKey(root), utf8(`secbin-mek/v1\n${id}`), need(sub, 'sub-MEK'));
  return `m1.${s.iv}.${s.ct}`;
}

/** A sub-MEK back → 32 bytes; DecryptError under another root or id. */
export async function openSubMek(root, id, data) {
  const p = typeof data === 'string' ? data.split('.') : [];
  if (p.length !== 3 || p[0] !== 'm1') throw new DecryptError('invalid sealed sub-MEK');
  const sub = await open(await subSealKey(root), utf8(`secbin-mek/v1\n${id}`), { iv: p[1], ct: p[2] });
  if (!isKey(sub)) throw new DecryptError('invalid sub-MEK');
  return sub;
}

/** Whether a stored value is sealed at rest (the field layer): "a1.<iv>.<ct>". */
export const isAtRest = (v) => typeof v === 'string' && /^a1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$/.test(v);

/** Seal `text` at rest with a field key → "a1.<iv>.<ct>"; AAD binds the user, the field and `ref`. */
export async function sealAtRest(fieldKey, { userId, field, ref }, text) {
  const s = await seal(await aesKey(need(fieldKey, 'field key')), utf8(`secbin-atrest/v1\n${userId}\n${field}\n${ref}`), utf8(text));
  return `a1.${s.iv}.${s.ct}`;
}

/** The text back; DecryptError under another key, user, field or ref. */
export async function openAtRest(fieldKey, { userId, field, ref }, value) {
  if (!isAtRest(value)) throw new DecryptError('not sealed at rest');
  const p = value.split('.');
  return new TextDecoder().decode(await open(await aesKey(need(fieldKey, 'field key')), utf8(`secbin-atrest/v1\n${userId}\n${field}\n${ref}`), { iv: p[1], ct: p[2] }));
}

// ── the sub-MEK timeline ───────────────────────────────────────────────────
// Each sub-MEK is in effect from `from` until `until` (null: open-ended).
// Where two overlap, the later `from` wins. There is always exactly one
// open-ended sub-MEK, one in effect now (the current one: new items use it),
// and no gap from now on. Reads never depend on dates: each item names the
// sub-MEK it is sealed under.

/** The sub-MEK in effect at time `t` (seconds) among `list` [{ id, from, until, created }], or null. */
export function effectiveAt(list, t) {
  let best = null;
  for (const m of Array.isArray(list) ? list : []) {
    if (!(m.from <= t && (m.until === null || m.until === undefined || t < m.until))) continue;
    if (!best || m.from > best.from || (m.from === best.from && (m.created > best.created || (m.created === best.created && m.id > best.id)))) best = m;
  }
  return best;
}

/** 'current' | 'scheduled' | 'retired' | 'overlapped' (in effect by its dates, but a later one wins) for `m` at `now`. */
export function mekStatus(list, m, now) {
  const cur = effectiveAt(list, now);
  if (cur && cur.id === m.id) return 'current';
  if (m.from > now) return 'scheduled';
  if (m.until !== null && m.until !== undefined && m.until <= now) return 'retired';
  return 'overlapped';
}

/**
 * Whether `list` is a valid timeline at `now` → null, or what is wrong:
 * dates in order, exactly one open-ended sub-MEK, one in effect now, and no
 * gap from now on.
 */
export function checkTimeline(list, now) {
  if (!Array.isArray(list) || !list.length) return 'There must be at least one sub-MEK.';
  for (const m of list) {
    if (!Number.isSafeInteger(m.from) || m.from < 0) return 'Every sub-MEK needs a start date.';
    if (m.until !== null && (!Number.isSafeInteger(m.until) || m.until < m.from)) return 'A sub-MEK cannot end before it starts.';
  }
  if (list.filter((m) => m.until === null).length !== 1) return 'Exactly one sub-MEK must be open-ended (no end date).';
  if (!effectiveAt(list, now)) return 'One sub-MEK must be in effect now.';
  for (const m of list) {
    // A gap can only open where an interval ends.
    if (m.until !== null && m.until > now && !effectiveAt(list, m.until)) {
      return 'There would be a gap after a sub-MEK ends: another must start by then.';
    }
  }
  return null;
}

// ── a key entered by hand (Admin → Security → Keys, set-up) ────────────────

/**
 * A key typed or pasted by the owner: 32 bytes as base64, base64url or hex
 * (spaces ignored) → bytes. Refused when it is not exactly 32 bytes or all
 * its bytes are the same (e.g. all zero).
 */
export function parseManualKey(text) {
  const t = String(text ?? '').replace(/\s+/g, '');
  let b = null;
  if (/^[0-9a-fA-F]{64}$/.test(t)) {
    b = new Uint8Array(32);
    for (let i = 0; i < 32; i++) b[i] = parseInt(t.slice(i * 2, i * 2 + 2), 16);
  } else if (/^[A-Za-z0-9+/_-]{43}=?$/.test(t)) {
    try { b = bytesFromB64url(t.replace(/=$/, '').replace(/\+/g, '-').replace(/\//g, '_')); } catch { b = null; }
  }
  if (!b || b.length !== KEY_BYTES) throw new TypeError('A key is exactly 32 bytes, as base64 (44 characters) or hex (64 characters).');
  if (b.every((x) => x === b[0])) throw new TypeError('That key has all its bytes the same: generate a random one.');
  return b;
}

// ── what the tab keeps ─────────────────────────────────────────────────────
// The KEKs are never written to browser storage: each page asks the server
// for them (POST /api/private/drive/keys, cheap: the server derives them) and
// keeps them in its own memory (the DriveClient), gone when the page is left.
// A value found in storage is never used as a key, so a key planted there by
// any same-origin script is ignored. The one Drive key in sessionStorage is
// the old DK of the release before (drivev1.js, only while a Drive waits for
// its upgrade: the sign-in page opens it, the Drive page uses it), and it is
// checked against the server's key check value before any use
// (driveupgrade.js). Every other slot a release before used ("secbin_kek",
// "secbin_kek_imp", "secbin_dk_imp", "secbin_dk_imp_uid") is removed
// (purgeStaleSlots, at every Drive open and dashboard load).

const LEGACY = ['secbin_dk', 'secbin_dk_uid'];
const STALE = ['secbin_kek', 'secbin_kek_imp', 'secbin_dk_imp', 'secbin_dk_imp_uid'];
const ALL = [...LEGACY, ...STALE];

function storage() {
  try { return typeof sessionStorage === 'undefined' ? null : sessionStorage; } catch { return null; }
}

/** While set (holdSessionKeys), the tab's slots live only in this module's memory, never in sessionStorage. */
let held = null;

/** Read a raw slot (this module's memory while held). */
export function readSlot(k) {
  if (held) return held[k] ?? null;
  try { return storage()?.getItem(k) ?? null; } catch { return null; }
}
/** Write (or, with null, remove) a raw slot. */
export function writeSlot(k, v) {
  if (held) { held[k] = v; return true; }
  const s = storage();
  if (!s) return false;
  try {
    if (v === null || v === undefined) s.removeItem(k); else s.setItem(k, v);
    return true;
  } catch {
    return false;
  }
}

/** Remove the slots no release uses any more (the KEK slots, the old impersonation DK). */
export function purgeStaleSlots() {
  for (const k of STALE) writeSlot(k, null);
}
/** The owner stopped acting as a user: nothing of theirs is kept (the KEKs were only in the page's memory). */
export const clearImpersonationKeys = purgeStaleSlots;
/** Forget every Drive key this tab holds (sign-out, the sign-in page). */
export function clearSessionKey() {
  for (const k of ALL) writeSlot(k, null);
}

/**
 * Called right before third-party script (the Turnstile widget on login,
 * Account and the public composer; public/js/turnstile.js) is added to the
 * page: the old DK of the release before (the one Drive key in
 * sessionStorage, above) moves out of sessionStorage into this module's
 * memory, where other script on the page cannot read it, and is gone when
 * the page is left. releaseSessionKeys() writes it back (the sign-in does, as
 * it leaves the page). SECURITY.md, "Drive keys, in the tab".
 */
export function holdSessionKeys() {
  if (held) return;
  const s = storage();
  const next = Object.fromEntries(ALL.map((k) => [k, null]));
  if (s) {
    for (const k of ALL) {
      try { next[k] = s.getItem(k); s.removeItem(k); } catch { /* storage refused */ }
    }
  }
  held = next;
}

export function releaseSessionKeys() {
  if (!held) return;
  const h = held;
  held = null;
  for (const [k, v] of Object.entries(h)) writeSlot(k, v);
}
