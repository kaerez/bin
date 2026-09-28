// records.js — sign-in and viewer records sealed at rest (SECURITY.md,
// "Records at rest"): the read receipts' opener details, the sign-in entries
// of the activity log and the addresses the Guard tracks. Shared by the
// Directory (it holds the keys) and the Worker (it seals the Guard's addresses
// with the key the Directory hands it). Every key is 32 bytes; every seal is
// AES-256-GCM with a random 96-bit IV.
//
// Synchronous (node:crypto, the `nodejs_compat` flag): a record is sealed in
// the very statement that writes it, inside the caller's transaction, so no
// row is ever written first and sealed later (Web Crypto is asynchronous, and
// the activity log is written from synchronous code).
//
//   record key  HKDF(ikm = root MEK, salt = "", info "secbin-records/v1"),
//               one per root MEK; its id (`kid`, stored with every sealed row)
//               is the root's fingerprint. Not the KEK derivation: no sub-MEK,
//               no user salt.
//   table key   HKDF(ikm = record key, salt = "", info
//               "secbin-records/table/v1\n<table>"): one per table, so the key
//               the Worker holds for the Guard opens nothing else.
//   value       "r1.<iv>.<ct>", AAD "secbin-records/v1\n<table>\n<column>\n
//               <row nonce>\n<the row's owner columns, JSON>": a ciphertext
//               moved to another row, column or table, or its row moved to
//               another share, account or action, does not open. The row nonce
//               is random, chosen before the row is written.
//   wrap key    HKDF(ikm = root MEK, salt = "", info "secbin-records/wrap/v1"):
//               seals the record keys of earlier roots ("k1.<iv>.<ct>", AAD
//               "secbin-records/wrap/v1\n<kid>") so that rows sealed before a
//               root change stay readable after the old root is gone.
//
// Equality lookups (the per-address throttles) use a keyed HMAC of the value
// instead of the value; those keys come from the Directory's own secret (its
// KEY_INFO), never from the root MEK, so that they survive a root change and
// work before there is a keyring.

import { createCipheriv, createDecipheriv, createHmac, hkdfSync, randomBytes } from 'node:crypto';
import { b64urlFromBytes, bytesFromB64url, utf8 } from '../../public/js/bytes.js';
import { DecryptError } from '../../public/js/crypto.js';

export const RECORD_INFO = 'secbin-records/v1';
const TABLE_INFO = 'secbin-records/table/v1';
const WRAP_INFO = 'secbin-records/wrap/v1';
/** A sealed value ("r1.<iv>.<ct>"; the ciphertext holds at least the 16-byte tag). */
const SEALED_RE = /^r1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$/;
const WRAPPED_RE = /^k1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}$/;
/** A key id: a root MEK fingerprint (keyFingerprint: 11 base64url characters). */
export const KID_RE = /^[A-Za-z0-9_-]{1,64}$/;
/** The tables whose rows are sealed (the AAD's and the table key's name). */
export const RECORD_TABLES = Object.freeze(['opens', 'activity', 'guard']);

const need = (k, what) => {
  if (!(k instanceof Uint8Array) || k.length !== 32) throw new TypeError(`invalid ${what}`);
  return k;
};
const hkdf = (ikm, info) => new Uint8Array(hkdfSync('sha256', ikm, new Uint8Array(0), utf8(info), 32));

/** A row's nonce (16 random bytes, base64url), chosen before the row is written. */
export const recordNonce = () => b64urlFromBytes(new Uint8Array(randomBytes(16)));

/**
 * The AAD of one value: `where` = { table, col, rn (the row nonce), bind (the
 * row's owner columns, in a fixed order per table; null stays null) }.
 */
function valueAad({ table, col, rn, bind = [] }) {
  if (!RECORD_TABLES.includes(table) || typeof col !== 'string' || !col || typeof rn !== 'string' || !rn || !Array.isArray(bind)) {
    throw new TypeError('table, column, row nonce and owner columns required');
  }
  return utf8(`${RECORD_INFO}\n${table}\n${col}\n${rn}\n${JSON.stringify(bind.map((v) => (v === undefined ? null : v)))}`);
}

// update() is called only with bytes: workerd's GCM fails final() after an empty update().
function sealWith(key, ad, bytes, prefix) {
  const iv = new Uint8Array(randomBytes(12));
  const c = createCipheriv('aes-256-gcm', key, iv);
  c.setAAD(ad);
  const body = bytes.length ? c.update(bytes) : new Uint8Array(0);
  const ct = new Uint8Array([...body, ...c.final(), ...c.getAuthTag()]);
  return `${prefix}.${b64urlFromBytes(iv)}.${b64urlFromBytes(ct)}`;
}
function openWith(key, ad, value, re) {
  if (typeof value !== 'string' || !re.test(value)) throw new DecryptError('not a sealed record');
  const [, ivText, ctText] = value.split('.');
  const iv = bytesFromB64url(ivText);
  const all = bytesFromB64url(ctText);
  try {
    const d = createDecipheriv('aes-256-gcm', key, iv);
    d.setAAD(ad);
    d.setAuthTag(all.subarray(all.length - 16));
    const ct = all.subarray(0, all.length - 16);
    return new Uint8Array([...(ct.length ? d.update(ct) : []), ...d.final()]);
  } catch {
    throw new DecryptError();
  }
}

/** The record key of a root MEK (32 bytes). */
export function deriveRecordKey(root) {
  return hkdf(need(root, 'root MEK'), RECORD_INFO);
}

/** One table's key under a record key (32 bytes; the Worker's copy for the Guard). */
export function tableKey(recordKey, table) {
  if (!RECORD_TABLES.includes(table)) throw new TypeError('unknown table');
  return hkdf(need(recordKey, 'record key'), `${TABLE_INFO}\n${table}`);
}

/** Whether a stored value is sealed ("r1.<iv>.<ct>"). */
export const isSealedRecord = (v) => typeof v === 'string' && SEALED_RE.test(v);

/** Seal one value of one row: `key` is the table key; `where` as valueAad. */
export function sealRecord(key, where, text) {
  return sealWith(need(key, 'table key'), valueAad(where), utf8(String(text ?? '')), 'r1');
}

/** The text back; DecryptError under another key, table, column, row nonce or owner columns. */
export function openRecord(key, where, value) {
  return new TextDecoder().decode(openWith(need(key, 'table key'), valueAad(where), value, SEALED_RE));
}

const wrapKey = (root) => hkdf(need(root, 'root MEK'), WRAP_INFO);

/** An earlier root's record key, sealed under the root MEK `root` → "k1.<iv>.<ct>". */
export function wrapRecordKey(root, kid, recordKey) {
  if (!KID_RE.test(kid ?? '')) throw new TypeError('invalid key id');
  return sealWith(wrapKey(root), utf8(`${WRAP_INFO}\n${kid}`), need(recordKey, 'record key'), 'k1');
}

/** The record key back → 32 bytes; DecryptError under another root or id. */
export function unwrapRecordKey(root, kid, wrapped) {
  const k = openWith(wrapKey(root), utf8(`${WRAP_INFO}\n${kid}`), wrapped, WRAPPED_RE);
  if (k.length !== 32) throw new DecryptError('invalid record key');
  return k;
}

/**
 * The Guard's lookup key for a network (its tracking key: an address or an
 * IPv6 prefix): "h:" + 18 bytes of HMAC(tag key, "secbin-guard/v1\n<key>"),
 * base64url. `tagKey`: 32 bytes (Directory.guardKeys).
 */
export function guardTag(tagKey, trackingKey) {
  const mac = createHmac('sha256', need(tagKey, 'tag key')).update(utf8(`secbin-guard/v1\n${trackingKey}`)).digest();
  return `h:${b64urlFromBytes(new Uint8Array(mac).subarray(0, 18))}`;
}
/** A Guard row's key is a tag (else it is a network key from before the tags). */
export const isGuardTag = (k) => typeof k === 'string' && /^h:[A-Za-z0-9_-]{24}$/.test(k);
/**
 * Where a Guard row's address is sealed: its key (a tag, random-looking and
 * fixed for the network) is the row nonce and its scope the owner column.
 * Tracking and blocks share it (a row moves from one to the other).
 */
export const guardWhere = (scope, key) => ({ table: 'guard', col: 'addr', rn: key, bind: [scope] });
