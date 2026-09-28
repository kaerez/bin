// reversekeys.js — the keys of reverse shares ("Receive", docs/REVERSE.md
// §3), shared by the anonymous uploader's page and the user's Drive client.
//
// Each reverse share has its own ECDH P-256 key pair, made in the user's
// browser. The raw public key is the link's #fragment; the private key is
// stored on the server sealed under HKDF(the user's KEK, "reverse-link")
// (drivekeys.js sealLinkKey, docs/DRIVE.md §3). The uploader encrypts
// each file exactly like a Drive file (a random file key fk), its relative
// path and metadata with a random metadata key mk, and wraps fk ‖ mk to the
// public key (ECDH with an ephemeral key → HKDF → AES-GCM). The server stores
// that ciphertext; it can open it with the link's private key, which it can
// unseal (the KEK is server-derived: SECURITY.md, "Drive keys"). A copy of R2
// or of the Drive object alone cannot. The optional password only gates the uploader:
// the server keeps the SHA-256 of an Argon2id-derived proof bound to the
// public key, which it never sees.

import { randomBytes, utf8, fromUtf8, b64urlFromBytes, bytesFromB64url } from './bytes.js';
import { hkdf32, proofHash, DecryptError } from './crypto.js';
import { ARGON2 } from './format.js';

const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
const EMPTY = new Uint8Array(0);
const VERSION = '1';
const info = (s) => utf8(`secbin-reverse/v1 ${s}`);
const aad = (field, ...ids) => utf8(`secbin-reverse/v1\n${field}\n${ids.map((x) => `${x}\n`).join('')}`);

/** Reverse share ids: "r" + 16 random bytes (base64url), chosen by the user's browser. */
export const REVERSE_ID_RE = /^r[A-Za-z0-9_-]{22}$/;
/** The link's fragment: the raw (uncompressed, 65-byte) public key, base64url. */
export const FRAGMENT_RE = /^[A-Za-z0-9_-]{87}$/;
/** Longest relative path an uploader may send (UTF-8 bytes). */
export const MAX_PATH_BYTES = 1024;
/** Longest note to the uploader (UTF-8 bytes; a longer one is cut at a character boundary). */
export const MAX_NOTE = 1000;

/** `text` cut to at most `max` UTF-8 bytes, never inside a character. */
function cutUtf8(text, max) {
  let out = '';
  let n = 0;
  for (const ch of String(text ?? '')) {
    const b = utf8(ch).length;
    if (n + b > max) break;
    out += ch;
    n += b;
  }
  return out;
}

export const newReverseId = () => `r${b64urlFromBytes(randomBytes(16))}`;
export const newNodeId = () => b64urlFromBytes(randomBytes(16));

async function aesKey(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}
async function seal(key, ad, bytes) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: ad, tagLength: 128 }, key, bytes));
  return { iv, ct };
}
async function open(key, ad, iv, ct) {
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: ad, tagLength: 128 }, key, ct));
  } catch {
    throw new DecryptError();
  }
}
const sealed = (v) => {
  let s;
  try { s = typeof v === 'string' ? JSON.parse(v) : v; } catch { throw new DecryptError('invalid sealed field'); }
  if (!s || typeof s.iv !== 'string' || typeof s.ct !== 'string') throw new DecryptError('invalid sealed field');
  let iv, ct;
  try { iv = bytesFromB64url(s.iv); ct = bytesFromB64url(s.ct); } catch { throw new DecryptError('invalid sealed field'); }
  if (iv.length !== 12) throw new DecryptError('invalid sealed field');
  return { iv, ct };
};
const out = ({ iv, ct }) => ({ iv: b64urlFromBytes(iv), ct: b64urlFromBytes(ct) });

// ── the link key pair (the user's browser) ─────────────────────────────────

/** A new link key pair → { pub: Uint8Array(65), privateKey (extractable, to be sealed) }. */
export async function createReverseKey() {
  const kp = await crypto.subtle.generateKey(ECDH, true, ['deriveBits']);
  return { pub: new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey)), privateKey: kp.privateKey };
}

/** The fragment of the link for a raw public key. */
export const fragmentOf = (pub) => b64urlFromBytes(pub);

/** The raw public key from a link fragment, or null when it is not one. */
export function pubFromFragment(fragment) {
  const f = String(fragment ?? '').replace(/^#/, '');
  if (!FRAGMENT_RE.test(f)) return null;
  let b;
  try { b = bytesFromB64url(f); } catch { return null; }
  return b.length === 65 && b[0] === 4 ? b : null;
}

/**
 * A link's private key (PKCS#8 bytes, opened by the Drive client) → {
 * privateKey (for ECDH), pub (raw, to show the link again) }; DecryptError
 * when the bytes are not such a key. The bytes are overwritten.
 */
export async function pubOfPrivate(pkcs8) {
  let jwk;
  try {
    // Imported once as extractable only to read its public point, then again for use.
    jwk = await crypto.subtle.exportKey('jwk', await crypto.subtle.importKey('pkcs8', pkcs8, ECDH, true, ['deriveBits']));
  } catch {
    throw new DecryptError('invalid reverse key');
  }
  const x = bytesFromB64url(jwk.x);
  const y = bytesFromB64url(jwk.y);
  const pub = new Uint8Array(65);
  pub[0] = 4;
  pub.set(x, 1);
  pub.set(y, 33);
  const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, ECDH, false, ['deriveBits']);
  pkcs8.fill(0);
  return { privateKey, pub };
}

// ── what the server keeps of the link and the password ─────────────────────

/** The uploader's link proof (X-Link-Proof), base64url of 32 bytes. */
export async function linkProof(pub) {
  return b64urlFromBytes(await hkdf32(pub, EMPTY, info('link-proof')));
}

/** The link proof's hash: the only form the server stores (`lh`). */
export async function linkHash(pub) {
  return proofHash(await linkProof(pub));
}

// Argon2id through kdf.js (WebAssembly), loaded only when a password is used.
// Tests may swap it (workerd cannot compile WebAssembly; the server never runs it).
let stretch = async (pw, salt, t) => {
  const { argon2idRaw } = await import('./kdf.js');
  return argon2idRaw(pw, salt, { t });
};
/** Tests only: replace Argon2id → (pwBytes, salt, t) → Promise<Uint8Array(32)>. */
export function setReverseStretcher(fn) { stretch = fn; }

/** The password proof (X-Key-Proof): Argon2id → HKDF bound to the link's public key. */
export async function passwordProof(password, saltB64, t, pub) {
  if (typeof password !== 'string' || !password) throw new TypeError('password required');
  if (!Number.isInteger(t) || t < ARGON2.tMin || t > ARGON2.tMax) throw new TypeError('invalid cost');
  let salt;
  try { salt = bytesFromB64url(saltB64); } catch { throw new TypeError('invalid salt'); }
  if (salt.length !== 16) throw new TypeError('invalid salt');
  const raw = await stretch(utf8(password.normalize('NFC')), salt, t);
  return b64urlFromBytes(await hkdf32(raw, pub, info('pw-proof')));
}

/** A new password gate → { salt, t, ph } (what the server stores). */
export async function passwordGate(password, pub, t = ARGON2.tDefault) {
  const salt = b64urlFromBytes(randomBytes(16));
  return { salt, t, ph: await proofHash(await passwordProof(password, salt, t, pub)) };
}

// ── the note to the uploader (readable by link holders only) ───────────────

async function noteKey(pub) {
  return aesKey(await hkdf32(pub, EMPTY, info('note')));
}

export async function sealNote(pub, id, text) {
  const t = cutUtf8(text, MAX_NOTE);
  return out(await seal(await noteKey(pub), aad('note', id), utf8(t)));
}

export async function openNote(pub, id, value) {
  const { iv, ct } = sealed(value);
  return fromUtf8(await open(await noteKey(pub), aad('note', id), iv, ct));
}

// ── one uploaded file (the uploader's browser) ─────────────────────────────

/**
 * Seal an upload's path and metadata with a fresh metadata key and wrap the
 * file key with it to the link's public key → { name, meta, wrap }.
 * `fk` is the file's 32-byte key (chunks: encryptChunk, as Drive files).
 */
export async function sealUpload(pub, id, nodeId, fk, { path, type, mtime, size }) {
  if (!(fk instanceof Uint8Array) || fk.length !== 32) throw new TypeError('invalid file key');
  if (utf8(path).length > MAX_PATH_BYTES) throw new TypeError('path too long');
  const mk = randomBytes(32);
  const mkKey = await aesKey(mk);
  const name = out(await seal(mkKey, aad('name', nodeId), utf8(path)));
  const meta = out(await seal(mkKey, aad('meta', nodeId), utf8(JSON.stringify({ type, mtime, size }))));
  const linkPub = await crypto.subtle.importKey('raw', pub, ECDH, false, []);
  const eph = await crypto.subtle.generateKey(ECDH, true, ['deriveBits']);
  const epk = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: linkPub }, eph.privateKey, 256));
  const kek = await aesKey(await hkdf32(shared, epk, info('kek')));
  const both = new Uint8Array(64);
  both.set(fk, 0);
  both.set(mk, 32);
  const w = await seal(kek, aad('wrap', id, nodeId), both);
  return { name, meta, wrap: [VERSION, b64urlFromBytes(epk), b64urlFromBytes(w.iv), b64urlFromBytes(w.ct)].join('.') };
}

// ── the user's side: open a received file ──────────────────────────────────

/**
 * Open a received item ({ id, name, meta, fk: { kind: 'rs', data } }) of
 * reverse share `rid` with its private key → { fk (32 bytes), path, type,
 * mtime, size }. DecryptError when anything does not open.
 */
export async function openUpload(privateKey, rid, item) {
  const data = item && item.fk && item.fk.kind === 'rs' ? item.fk.data : null;
  const parts = typeof data === 'string' ? data.split('.') : [];
  if (parts.length !== 4 || parts[0] !== VERSION) throw new DecryptError('invalid wrap');
  let epk, iv, ct;
  try { [epk, iv, ct] = parts.slice(1).map((p) => bytesFromB64url(p)); } catch { throw new DecryptError('invalid wrap'); }
  if (epk.length !== 65 || iv.length !== 12) throw new DecryptError('invalid wrap');
  let ephPub;
  try { ephPub = await crypto.subtle.importKey('raw', epk, ECDH, false, []); } catch { throw new DecryptError('invalid wrap'); }
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: ephPub }, privateKey, 256));
  const kek = await aesKey(await hkdf32(shared, epk, info('kek')));
  const both = await open(kek, aad('wrap', rid, item.id), iv, ct);
  if (both.length !== 64) throw new DecryptError('invalid wrap');
  const mkKey = await aesKey(both.slice(32));
  const n = sealed(item.name);
  const path = fromUtf8(await open(mkKey, aad('name', item.id), n.iv, n.ct));
  const m = sealed(item.meta);
  let meta;
  try { meta = JSON.parse(fromUtf8(await open(mkKey, aad('meta', item.id), m.iv, m.ct))); } catch (e) { throw e instanceof DecryptError ? e : new DecryptError('invalid metadata'); }
  if (!meta || typeof meta !== 'object') throw new DecryptError('invalid metadata');
  return { fk: both.slice(0, 32), path, type: typeof meta.type === 'string' ? meta.type : '', mtime: Number.isSafeInteger(meta.mtime) && meta.mtime >= 0 ? meta.mtime : 0, size: meta.size };
}
