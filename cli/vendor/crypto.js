// crypto.js — secbin zero-knowledge crypto protocol v2 (Web Crypto + Argon2id).
//
// Implements SPEC.md: a per-paste random 256-bit CEK encrypts the content with
// AES-256-GCM; the CEK is wrapped by a KEK derived from the URL-fragment secret F
// (HKDF) combined with an optional Argon2id-stretched password; a canonical AAD
// binds all security-relevant metadata to both GCM operations. Two access proofs
// derived from F and from the KEK let the server check "right link" and "right
// password" before it releases ciphertext or spends a view — it stores only their
// SHA-256 and never learns F, the password or the KEK.
//
// Runs unchanged in the browser, the CLI (Node) and the workerd test runtime. All
// randomness comes from crypto.getRandomValues (via bytes.js).

import { randomBytes, utf8, fromUtf8, b64urlFromBytes, bytesFromB64url } from './bytes.js';
import { buildAAD, validatePaste, ARGON2 } from './format.js';

const KEK_INFO = utf8('secbin/v2 kek');
const LINK_PROOF_INFO = utf8('secbin/v2 link-proof');
const KEY_PROOF_INFO = utf8('secbin/v2 key-proof');
const EMPTY = new Uint8Array(0);
export const MAX_PLAINTEXT = 1 << 20; // 1 MiB — cap before compression and on decompression

/** Raised when a paste needs a password the caller didn't supply. */
export class PasswordRequired extends Error {
  constructor() { super('password required'); this.name = 'PasswordRequired'; }
}
/** Raised when decryption/authentication fails (wrong key/password or tampering). */
export class DecryptError extends Error {
  constructor(message = 'decryption failed') { super(message); this.name = 'DecryptError'; }
}

// ── password stretching (injectable) ─────────────────────────────────────────
// Argon2id runs through WebAssembly, which workerd refuses to compile at runtime;
// the Worker never needs it, and the workerd test-suite injects a stand-in so it
// can exercise password-protected records. Browsers and the CLI use kdf.js.
let stretcher = null;
/** Override the password stretcher: (pwBytes, salt, t) → Promise<Uint8Array(32)>. Tests only. */
export function setPasswordStretcher(fn) { stretcher = fn; }

async function stretchPassword(password, salt, t) {
  const pw = utf8(password.normalize('NFC')); // same key for NFC/NFD input (SPEC §2)
  if (stretcher) return stretcher(pw, salt, t);
  const { argon2idRaw } = await import('./kdf.js');
  return argon2idRaw(pw, salt, { t });
}

// ── low-level primitives (exported for test vectors) ─────────────────────────

async function importAesKey(rawBytes) {
  return crypto.subtle.importKey('raw', rawBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function aesGcmEncrypt(key, iv, plaintext, aad) {
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, plaintext);
  return new Uint8Array(ct);
}

export async function aesGcmDecrypt(key, iv, ciphertext, aad) {
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, ciphertext);
    return new Uint8Array(pt);
  } catch {
    throw new DecryptError();
  }
}

/** HKDF-SHA256(ikm, salt, info) → 32 bytes. */
export async function hkdf32(ikm, salt, info) {
  const key = await crypto.subtle.importKey('raw', ikm, { name: 'HKDF' }, false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, 256));
}

/**
 * Key schedule (SPEC.md §2) from the fragment secret F and the stretched
 * password bytes `pwIkm` (empty without a password):
 *   KEK        = HKDF(ikm=F,   salt=pwIkm, info="secbin/v2 kek")
 *   linkProof  = HKDF(ikm=F,   salt="",    info="secbin/v2 link-proof")
 *   keyProof   = HKDF(ikm=KEK, salt="",    info="secbin/v2 key-proof")
 */
export async function keySchedule(F, pwIkm) {
  const kekBits = await hkdf32(F, pwIkm, KEK_INFO);
  const linkProof = await hkdf32(F, EMPTY, LINK_PROOF_INFO);
  const keyProof = await hkdf32(kekBits, EMPTY, KEY_PROOF_INFO);
  return { kek: await importAesKey(kekBits), linkProof, keyProof };
}

/** base64url(SHA-256(proof bytes)) — the only form of a proof the server stores. */
export async function proofHash(proofB64) {
  const d = await crypto.subtle.digest('SHA-256', bytesFromB64url(proofB64));
  return b64urlFromBytes(new Uint8Array(d));
}

// ── gzip via native streams, with a hard decompression cap ───────────────────

function hasCompression() {
  return typeof CompressionStream !== 'undefined' && typeof DecompressionStream !== 'undefined';
}

async function readAll(readable, maxOut = Infinity) {
  const reader = readable.getReader();
  reader.closed.catch(() => {});
  const chunks = [];
  let total = 0;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > maxOut) {
      await reader.cancel().catch(() => {});
      throw new DecryptError('decompressed data too large');
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

export async function gzip(bytes) {
  const stream = new CompressionStream('gzip');
  const writer = stream.writable.getWriter();
  writer.write(bytes);
  writer.close();
  return readAll(stream.readable);
}

/**
 * Gunzip with a hard output cap (gzip-bomb defense): aborts as soon as the
 * cumulative decompressed size exceeds `maxOut`. Throws on malformed input.
 */
export async function gunzip(bytes, maxOut = MAX_PLAINTEXT) {
  const stream = new DecompressionStream('gzip');
  const writer = stream.writable.getWriter();
  // Malformed input rejects the writable side in parallel with the readable
  // side; the read loop reports it, so silence the duplicate signals.
  writer.write(bytes).catch(() => {});
  writer.close().catch(() => {});
  writer.closed.catch(() => {});
  try {
    return await readAll(stream.readable, maxOut);
  } catch (e) {
    if (e instanceof DecryptError) throw e;
    throw new DecryptError('malformed compressed data');
  }
}

// ── high-level API ───────────────────────────────────────────────────────────

/**
 * Encrypt a paste. Returns { body, fragment } where `body` is the format-v2
 * create object (paste + `acc` proof hashes) and `fragment` is the base64url
 * URL-fragment secret F — which MUST stay client-side.
 */
export async function encryptPaste({
  text, password = '', fmt = 'plaintext', bar = false, expire = '24h', views, t = ARGON2.tDefault, deletable = false,
}) {
  const data = utf8(text);
  if (data.length > MAX_PLAINTEXT) throw new Error('paste too large');

  let comp = 'none';
  let payload = data;
  if (hasCompression()) {
    const gz = await gzip(data);
    if (gz.length < data.length) { comp = 'gzip'; payload = gz; }
  }

  const CEK = randomBytes(32);
  const F = randomBytes(32);
  const ivc = randomBytes(12);
  const ivw = randomBytes(12);

  const usePassword = password.length > 0;
  const salt = usePassword ? randomBytes(16) : EMPTY;

  const adata = {
    alg: 'A256GCM',
    kdf: usePassword ? 'argon2id-hkdf' : 'hkdf',
    iter: usePassword ? t : 0,
    comp,
    fmt,
    bar,
    ivc: b64urlFromBytes(ivc),
    ivw: b64urlFromBytes(ivw),
    skdf: usePassword ? b64urlFromBytes(salt) : '',
  };
  const aad = buildAAD(adata);

  const pwIkm = usePassword ? await stretchPassword(password, salt, t) : EMPTY;
  const { kek, linkProof, keyProof } = await keySchedule(F, pwIkm);
  const wk = await aesGcmEncrypt(kek, ivw, CEK, aad);
  const ct = await aesGcmEncrypt(await importAesKey(CEK), ivc, payload, aad);

  const body = {
    v: 2,
    ct: b64urlFromBytes(ct),
    wk: b64urlFromBytes(wk),
    adata,
    // `views` (view limit) is only meaningful for bar pastes; format.js rejects it otherwise.
    meta: { expire, ...(views === undefined ? {} : { views }), ...(deletable ? { deletable: true } : {}) },
    acc: {
      lh: await proofHash(b64urlFromBytes(linkProof)),
      kh: await proofHash(b64urlFromBytes(keyProof)),
    },
  };
  return { body, fragment: b64urlFromBytes(F) };
}

/**
 * Derive the reader's access material from a head's `adata`, the fragment and
 * an optional password: { kek, linkProof, keyProof } (proofs as base64url, to
 * send in X-Link-Proof / X-Key-Proof). Needs no ciphertext and makes no request.
 * Throws PasswordRequired when a password is needed but absent, DecryptError on
 * a malformed fragment.
 */
export async function deriveAccess({ adata, fragment, password = '' }) {
  let F;
  try {
    F = bytesFromB64url(fragment);
  } catch {
    throw new DecryptError('invalid key');
  }
  if (F.length !== 32) throw new DecryptError('invalid key');

  const usePassword = adata.kdf === 'argon2id-hkdf';
  if (usePassword && password.length === 0) throw new PasswordRequired();
  let pwIkm = EMPTY;
  if (usePassword) {
    let salt;
    try { salt = bytesFromB64url(adata.skdf); } catch { throw new DecryptError('invalid paste'); }
    pwIkm = await stretchPassword(password, salt, adata.iter);
  }
  const { kek, linkProof, keyProof } = await keySchedule(F, pwIkm);
  return { kek, linkProof: b64urlFromBytes(linkProof), keyProof: b64urlFromBytes(keyProof) };
}

/** Unwrap the CEK from `wk` with an already-derived KEK. */
export async function unwrapCek({ adata, wk, kek }) {
  let ivw, wkBytes;
  try {
    ivw = bytesFromB64url(adata.ivw);
    wkBytes = bytesFromB64url(wk);
  } catch {
    throw new DecryptError('invalid paste');
  }
  return importAesKey(await aesGcmDecrypt(kek, ivw, wkBytes, buildAAD(adata)));
}

/** Decrypt the content with an unwrapped CEK. Returns { text, fmt, bar }. */
export async function decryptContent({ adata, ct, cek }) {
  let ctBytes, ivc;
  try {
    ctBytes = bytesFromB64url(ct);
    ivc = bytesFromB64url(adata.ivc);
  } catch {
    throw new DecryptError('invalid ciphertext');
  }
  const payload = await aesGcmDecrypt(cek, ivc, ctBytes, buildAAD(adata));
  const plainBytes = adata.comp === 'gzip' ? await gunzip(payload, MAX_PLAINTEXT) : payload;
  let text;
  try {
    text = fromUtf8(plainBytes);
  } catch {
    throw new DecryptError('invalid text encoding');
  }
  return { text, fmt: adata.fmt, bar: adata.bar };
}

/**
 * Decrypt a paste released by an open (`{v, ct, wk, adata, meta}`) with the
 * access material from deriveAccess(). Validates the shape first (fail closed).
 */
export async function openPaste({ paste, access }) {
  const clean = validatePaste(paste);
  const cek = await unwrapCek({ adata: clean.adata, wk: clean.wk, kek: access.kek });
  return decryptContent({ adata: clean.adata, ct: clean.ct, cek });
}
