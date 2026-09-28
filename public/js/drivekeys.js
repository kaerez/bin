// drivekeys.js — the Drive's keys, in the browser only (docs/DRIVE.md §3).
//
// DK, the Drive key, is 32 random bytes per user. Two AES-256-GCM sub-keys come
// from it by HKDF-SHA-256: "names" seals node names and metadata, "files" seals
// each file's own key (fk). The server stores DK only as wraps it cannot open:
//   pw       — Argon2id(NFC(password), driveSalt, 64 MiB, t=3, p=1) → HKDF → AES-GCM;
//   recovery — HKDF over a recovery code's normalised text, one wrap per code;
//   passkey  — HKDF over the WebAuthn PRF output for DRIVE_PRF_SALT;
//   escrow   — ECDH P-256 (ephemeral × the owner's escrow key) → HKDF.
// The owner also has an ECDSA P-256 signing key: it signs the escrow public
// key, so users' browsers accept a new escrow key only when the signing key
// they pinned endorses it.
// Every sealed value carries AAD "secbin-drive/v1\n<field>\n<nodeId>\n" so the
// server cannot move a value to another node, field or wrap.
//
// Formats. A sealed field is { iv, ct } (base64url; 12-byte IV). A wrap's `data`
// (and the owner's sealed escrow key) is an opaque string of base64url segments
// joined by ".": "1.<iv>.<ct>", or for escrow "1.<epk>.<kid>.<iv>.<ct>" where epk
// is the ephemeral public key (raw, 65 bytes) and kid identifies the owner's key.

import { randomBytes, utf8, b64urlFromBytes, bytesFromB64url, sha256Hex } from './bytes.js';
import { hkdf32, DecryptError } from './crypto.js';

const EMPTY = new Uint8Array(0);
const VERSION = '1';
const DK_BYTES = 32;
const SALT_BYTES = 16;
/** The Drive's own Argon2id cost (fixed: never taken from the server). */
export const DRIVE_ARGON2 = Object.freeze({ mKiB: 65536, t: 3, p: 1 });
const SESSION_KEY = 'secbin_dk';
const SESSION_UID = 'secbin_dk_uid';
// The Drive of the user the owner acts as: a separate slot, so it never
// overwrites the owner's own key (cleared when the impersonation ends).
const IMP_KEY = 'secbin_dk_imp';
const IMP_UID = 'secbin_dk_imp_uid';

/** SHA-256("secbin-drive/v1 prf"): the fixed PRF input for passkey wraps (a test checks it). */
export const DRIVE_PRF_SALT = new Uint8Array([
  0x7c, 0x53, 0xc3, 0x1c, 0xb5, 0xb3, 0xcc, 0x57, 0xbd, 0x63, 0x2e, 0xda, 0x13, 0x81, 0x08, 0xe6,
  0x8c, 0x8e, 0x04, 0xd2, 0x1b, 0x3c, 0x8a, 0x5f, 0x30, 0x04, 0x60, 0x70, 0xa4, 0x6c, 0xb3, 0x19,
]);

const info = (s) => utf8(`secbin-drive/v1 ${s}`);
const aad = (field, nodeId) => utf8(`secbin-drive/v1\n${field}\n${nodeId}\n`);
const isDk = (dk) => dk instanceof Uint8Array && dk.length === DK_BYTES;

async function aesKey(raw, usages = ['encrypt', 'decrypt']) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, usages);
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

// ── DK and its sub-keys ────────────────────────────────────────────────────

/** A new Drive key: 32 random bytes. */
export function createDriveKey() {
  return randomBytes(DK_BYTES);
}

/**
 * The Drive key's check value: HMAC-SHA-256 under DK's "files" sub-key (its
 * raw HKDF output) of "secbin-drive/v1 kcv", base64url. The server keeps it
 * from the first set-up and accepts a new password wrap only with the same
 * value, so a wrap of another key is refused; it reveals nothing about DK.
 */
export async function keyCheckValue(dk) {
  if (!isDk(dk)) throw new TypeError('invalid Drive key');
  const raw = await hkdf32(dk, EMPTY, info('files'));
  const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64urlFromBytes(new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8('secbin-drive/v1 kcv'))));
}

/** { names, files }: the two AES-256-GCM sub-keys (HKDF, salt empty). */
export async function deriveSubkeys(dk) {
  if (!isDk(dk)) throw new TypeError('invalid Drive key');
  const [names, files] = await Promise.all([hkdf32(dk, EMPTY, info('names')), hkdf32(dk, EMPTY, info('files'))]);
  return { names: await aesKey(names), files: await aesKey(files) };
}

/** Seal `value` (bytes or a string) for `field` of node `nodeId` → { iv, ct } (base64url). */
export async function sealField(key, field, nodeId, value) {
  const bytes = typeof value === 'string' ? utf8(value) : value;
  if (!(bytes instanceof Uint8Array)) throw new TypeError('bytes or string expected');
  const { iv, ct } = await seal(key, aad(field, nodeId), bytes);
  return { iv: b64urlFromBytes(iv), ct: b64urlFromBytes(ct) };
}

/** Open a sealed field → Uint8Array; DecryptError when it is not this node's `field`. */
export async function openField(key, field, nodeId, sealed) {
  let iv, ct;
  try {
    const s = typeof sealed === 'string' ? JSON.parse(sealed) : sealed;
    iv = bytesFromB64url(s.iv);
    ct = bytesFromB64url(s.ct);
  } catch {
    throw new DecryptError('invalid sealed field');
  }
  if (iv.length !== 12) throw new DecryptError('invalid sealed field');
  return open(key, aad(field, nodeId), iv, ct);
}

// ── wraps ──────────────────────────────────────────────────────────────────

const wrapAad = (kind, ref) => aad(`wrap:${kind}`, ref);

async function kekFrom(ikm, label, salt = EMPTY) {
  return aesKey(await hkdf32(ikm, salt, info(label)));
}

async function wrapWith(kek, kind, ref, dk) {
  if (!isDk(dk)) throw new TypeError('invalid Drive key');
  const { iv, ct } = await seal(kek, wrapAad(kind, ref), dk);
  return { kind, ref, data: [VERSION, b64urlFromBytes(iv), b64urlFromBytes(ct)].join('.') };
}

/** Parse "1.<seg>…" into byte segments; null when malformed. */
function segments(data, count) {
  if (typeof data !== 'string' || data.length > 4096) return null;
  const parts = data.split('.');
  if (parts.length !== count + 1 || parts[0] !== VERSION) return null;
  try { return parts.slice(1).map((p) => bytesFromB64url(p)); } catch { return null; }
}

/** DK from a symmetric wrap, or null (wrong key, other wrap, malformed). */
async function unwrapWith(kek, w) {
  const seg = segments(w && w.data, 2);
  if (!seg || seg[0].length !== 12) return null;
  try {
    const dk = await open(kek, wrapAad(w.kind, w.ref), seg[0], seg[1]);
    return isDk(dk) ? dk : null;
  } catch {
    return null;
  }
}

const listOf = (wraps, kind) => (Array.isArray(wraps) ? wraps.filter((w) => w && w.kind === kind && typeof w.ref === 'string') : []);

async function passwordKek(password, salt) {
  if (typeof password !== 'string' || !password) throw new TypeError('password required');
  const { argon2idRaw } = await import('./kdf.js'); // loaded only when a password is used
  const raw = await argon2idRaw(utf8(password.normalize('NFC')), salt, { t: DRIVE_ARGON2.t, mKiB: DRIVE_ARGON2.mKiB, p: DRIVE_ARGON2.p });
  return kekFrom(raw, 'kek-pw');
}

/** A new `pw` wrap under a fresh 16-byte driveSalt → { driveSalt, wrap }. */
export async function wrapPassword(dk, password) {
  const salt = randomBytes(SALT_BYTES);
  const kek = await passwordKek(password, salt);
  return { driveSalt: b64urlFromBytes(salt), wrap: await wrapWith(kek, 'pw', 'pw', dk) };
}

/** DK from the `pw` wrap, or null. */
export async function unlockWithPassword(password, driveSalt, wraps) {
  const pw = listOf(wraps, 'pw');
  if (!pw.length || typeof password !== 'string' || !password) return null;
  let salt;
  try { salt = bytesFromB64url(driveSalt); } catch { return null; }
  if (salt.length !== SALT_BYTES) return null;
  const kek = await passwordKek(password, salt);
  for (const w of pw) {
    const dk = await unwrapWith(kek, w);
    if (dk) return dk;
  }
  return null;
}

/**
 * A recovery code as the server reads it (src/directory-do.js): case, dashes
 * and spaces ignored, O → 0, I/L → 1; 16 Crockford base32 characters, or null.
 */
export function normalizeRecoveryCode(code) {
  if (typeof code !== 'string' || code.length > 64) return null;
  const v = code.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  return /^[0-9A-HJKMNP-TV-Z]{16}$/.test(v) ? v : null;
}

/** The server's id for a recovery code: hex SHA-256("secbin-recovery/v1:" ‖ normalised code). */
export async function recoveryRef(code) {
  const norm = normalizeRecoveryCode(code);
  return norm ? sha256Hex(utf8(`secbin-recovery/v1:${norm}`)) : null;
}

async function recoveryKek(code) {
  const norm = normalizeRecoveryCode(code);
  if (!norm) return null;
  return kekFrom(utf8(norm), 'kek-recovery');
}

/** A `recovery` wrap for one code; `ref` defaults to the code's server-side hash. */
export async function wrapRecovery(dk, code, ref) {
  const kek = await recoveryKek(code);
  if (!kek) throw new TypeError('invalid recovery code');
  return wrapWith(kek, 'recovery', typeof ref === 'string' && ref ? ref : await recoveryRef(code), dk);
}

/** DK from the wrap of this recovery code, or null. */
export async function unlockWithRecovery(code, wraps) {
  const kek = await recoveryKek(code);
  if (!kek) return null;
  const ref = await recoveryRef(code);
  const all = listOf(wraps, 'recovery');
  // The code's own wrap first; the others only when refs are not hashes.
  for (const w of [...all.filter((x) => x.ref === ref), ...all.filter((x) => x.ref !== ref)]) {
    const dk = await unwrapWith(kek, w);
    if (dk) return dk;
  }
  return null;
}

function prfBytes(prfOutput) {
  const b = prfOutput instanceof ArrayBuffer ? new Uint8Array(prfOutput)
    : ArrayBuffer.isView(prfOutput) ? new Uint8Array(prfOutput.buffer, prfOutput.byteOffset, prfOutput.byteLength) : null;
  if (!b || b.length < 32) throw new TypeError('invalid PRF output');
  return b;
}

/** A `passkey` wrap from the PRF output for DRIVE_PRF_SALT; ref = the credential id. */
export async function wrapPrf(dk, prfOutput, credentialId) {
  if (typeof credentialId !== 'string' || !credentialId) throw new TypeError('credential id required');
  return wrapWith(await kekFrom(prfBytes(prfOutput), 'kek-prf'), 'passkey', credentialId, dk);
}

/** DK from this passkey's wrap, or null. */
export async function unlockWithPrf(prfOutput, credentialId, wraps) {
  let kek;
  try { kek = await kekFrom(prfBytes(prfOutput), 'kek-prf'); } catch { return null; }
  for (const w of listOf(wraps, 'passkey').filter((x) => x.ref === credentialId)) {
    const dk = await unwrapWith(kek, w);
    if (dk) return dk;
  }
  return null;
}

// ── owner escrow ───────────────────────────────────────────────────────────

const ECDH = { name: 'ECDH', namedCurve: 'P-256' };

/** A public JWK reduced to the fields that matter. */
function cleanJwk(j) {
  if (!j || j.kty !== 'EC' || j.crv !== 'P-256' || typeof j.x !== 'string' || typeof j.y !== 'string') throw new TypeError('invalid escrow public key');
  return { kty: 'EC', crv: 'P-256', x: j.x, y: j.y };
}

/** kid: the first 16 bytes of SHA-256 over the raw public point, base64url. */
async function keyId(rawPub) {
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', rawPub));
  return b64urlFromBytes(d.subarray(0, 16));
}

/** The owner's escrow key pair: { publicJwk, privateKey } (the private key is extractable, to be sealed). */
export async function createEscrowKeyPair() {
  const kp = await crypto.subtle.generateKey(ECDH, true, ['deriveBits']);
  return { publicJwk: cleanJwk(await crypto.subtle.exportKey('jwk', kp.publicKey)), privateKey: kp.privateKey };
}

/** The escrow private key (PKCS#8) sealed under the owner's DK → data string. */
export async function sealEscrowPriv(dk, privateKey) {
  const { files } = await deriveSubkeys(dk);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
  const { iv, ct } = await seal(files, aad('escrowPriv', 'drive'), pkcs8);
  return [VERSION, b64urlFromBytes(iv), b64urlFromBytes(ct)].join('.');
}

/** The escrow private key back (non-extractable) → CryptoKey; DecryptError on a wrong DK. */
export async function openEscrowPriv(dk, data) {
  const seg = segments(data, 2);
  if (!seg || seg[0].length !== 12) throw new DecryptError('invalid escrow key');
  const { files } = await deriveSubkeys(dk);
  const pkcs8 = await open(files, aad('escrowPriv', 'drive'), seg[0], seg[1]);
  try {
    return await crypto.subtle.importKey('pkcs8', pkcs8, ECDH, false, ['deriveBits']);
  } catch {
    throw new DecryptError('invalid escrow key');
  }
}

/**
 * The escrow private key back with its public key → { privateKey, publicJwk }:
 * the public key is derived from the private one, so the owner's browser can
 * check that the escrow public key the server hands to every Drive is this
 * key's (docs/DRIVE.md §3). DecryptError on a wrong DK.
 */
export async function openEscrowKeyPair(dk, data) {
  const seg = segments(data, 2);
  if (!seg || seg[0].length !== 12) throw new DecryptError('invalid escrow key');
  const { files } = await deriveSubkeys(dk);
  const pkcs8 = await open(files, aad('escrowPriv', 'drive'), seg[0], seg[1]);
  try {
    const full = await crypto.subtle.exportKey('jwk', await crypto.subtle.importKey('pkcs8', pkcs8, ECDH, true, ['deriveBits']));
    return { privateKey: await crypto.subtle.importKey('pkcs8', pkcs8, ECDH, false, ['deriveBits']), publicJwk: cleanJwk(full) };
  } catch {
    throw new DecryptError('invalid escrow key');
  }
}

/** Whether two escrow public JWKs are the same key. */
export function sameEscrowKey(a, b) {
  try {
    const x = cleanJwk(a);
    const y = cleanJwk(b);
    return x.x === y.x && x.y === y.y;
  } catch {
    return false;
  }
}

/**
 * What this Drive trusts, sealed under DK (field `escrowPin`, node "drive"):
 * `{ escrow, sign }` — the kid of the escrow key its escrow wrap is for, and
 * the kid of the owner's signing key (null when there was none), plus the
 * owner-reset `epoch` it has seen. A user's browser pins them at the Drive's first
 * set-up and re-wraps to another escrow key only when the pinned signing key
 * signed it (or when the user accepts it, or once for an owner reset:
 * driveclient.js resetApplies).
 */
export async function sealEscrowPin(dk, pin) {
  const { names } = await deriveSubkeys(dk);
  const v = typeof pin === 'string' ? { escrow: pin, sign: null } : { escrow: String(pin.escrow), sign: pin.sign ? String(pin.sign) : null };
  // The owner reset this pin has seen (docs/DRIVE.md §3), when there was one.
  if (pin && Number.isSafeInteger(pin.epoch) && pin.epoch > 0) v.epoch = pin.epoch;
  return sealField(names, 'escrowPin', 'drive', JSON.stringify(v));
}

/** The pin `{ escrow, sign, epoch? }`, or null (none; or it does not open with this DK — altered). */
export async function openEscrowPin(dk, sealed) {
  if (!sealed) return null;
  try {
    const { names } = await deriveSubkeys(dk);
    const text = new TextDecoder().decode(await openField(names, 'escrowPin', 'drive', sealed));
    const v = JSON.parse(text);
    if (!v || typeof v.escrow !== 'string') return null;
    const pin = { escrow: v.escrow, sign: typeof v.sign === 'string' ? v.sign : null };
    if (Number.isSafeInteger(v.epoch) && v.epoch > 0) pin.epoch = v.epoch;
    return pin;
  } catch {
    return null;
  }
}

// ── the owner's signing key (endorses the escrow public key) ──────────────

const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' };
const SIGN = { name: 'ECDSA', hash: 'SHA-256' };
const endorsement = (jwk) => utf8(`secbin-drive/v1 escrow-endorse\n${jwk.x}\n${jwk.y}`);

/** The owner's signing key pair: { publicJwk, privateKey } (extractable, to be sealed). */
export async function createSigningKeyPair() {
  const kp = await crypto.subtle.generateKey(ECDSA, true, ['sign', 'verify']);
  return { publicJwk: cleanJwk(await crypto.subtle.exportKey('jwk', kp.publicKey)), privateKey: kp.privateKey };
}

/** The signing private key (PKCS#8) sealed under the owner's DK → data string (field `escrowSign`). */
export async function sealSigningKey(dk, privateKey) {
  const { files } = await deriveSubkeys(dk);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
  const { iv, ct } = await seal(files, aad('escrowSign', 'drive'), pkcs8);
  return [VERSION, b64urlFromBytes(iv), b64urlFromBytes(ct)].join('.');
}

/** The signing key back → { privateKey, publicJwk }; DecryptError on a wrong DK. */
export async function openSigningKey(dk, data) {
  const seg = segments(data, 2);
  if (!seg || seg[0].length !== 12) throw new DecryptError('invalid signing key');
  const { files } = await deriveSubkeys(dk);
  const pkcs8 = await open(files, aad('escrowSign', 'drive'), seg[0], seg[1]);
  try {
    const full = await crypto.subtle.exportKey('jwk', await crypto.subtle.importKey('pkcs8', pkcs8, ECDSA, true, ['sign']));
    return { privateKey: await crypto.subtle.importKey('pkcs8', pkcs8, ECDSA, false, ['sign']), publicJwk: cleanJwk(full) };
  } catch {
    throw new DecryptError('invalid signing key');
  }
}

/** The signing key's signature over an escrow public key (raw r ‖ s, base64url). */
export async function endorseEscrowKey(signPrivateKey, escrowJwk) {
  return b64urlFromBytes(new Uint8Array(await crypto.subtle.sign(SIGN, signPrivateKey, endorsement(cleanJwk(escrowJwk)))));
}

/** Whether `sig` is `signJwk`'s signature over `escrowJwk`. */
export async function escrowKeyEndorsed(signJwk, escrowJwk, sig) {
  try {
    const key = await crypto.subtle.importKey('jwk', cleanJwk(signJwk), ECDSA, false, ['verify']);
    return await crypto.subtle.verify(SIGN, key, bytesFromB64url(sig), endorsement(cleanJwk(escrowJwk)));
  } catch {
    return false;
  }
}

// ── raw private keys, for the owner recovery kit (docs/DRIVE.md §3) ──────
// The kit carries the escrow and signing private keys as PKCS#8, so that it
// can put back a sealed copy the owner's Drive has lost.

const PKCS8_FIELD = { escrow: 'escrowPriv', sign: 'escrowSign' };

/** A sealed escrow (`kind` 'escrow') or signing ('sign') private key → its PKCS#8 bytes; DecryptError on a wrong DK. */
export async function openPrivateKeyBytes(dk, kind, data) {
  const seg = segments(data, 2);
  if (!seg || seg[0].length !== 12 || !PKCS8_FIELD[kind]) throw new DecryptError('invalid sealed key');
  const { files } = await deriveSubkeys(dk);
  return open(files, aad(PKCS8_FIELD[kind], 'drive'), seg[0], seg[1]);
}

/** PKCS#8 bytes sealed under DK as the Drive stores them (`escrowPriv` / `escrowSignPriv`). */
export async function sealPrivateKeyBytes(dk, kind, pkcs8) {
  if (!PKCS8_FIELD[kind] || !(pkcs8 instanceof Uint8Array)) throw new TypeError('invalid key');
  const { files } = await deriveSubkeys(dk);
  const { iv, ct } = await seal(files, aad(PKCS8_FIELD[kind], 'drive'), pkcs8);
  return [VERSION, b64urlFromBytes(iv), b64urlFromBytes(ct)].join('.');
}

/**
 * PKCS#8 bytes of an escrow ('escrow', ECDH) or signing ('sign', ECDSA) key →
 * { privateKey (non-extractable), publicJwk (derived from it), kid };
 * DecryptError when they are not such a key.
 */
export async function privateKeyFromBytes(kind, pkcs8) {
  const alg = kind === 'escrow' ? ECDH : kind === 'sign' ? ECDSA : null;
  const usages = kind === 'escrow' ? ['deriveBits'] : ['sign'];
  try {
    const full = await crypto.subtle.exportKey('jwk', await crypto.subtle.importKey('pkcs8', pkcs8, alg, true, usages));
    const publicJwk = cleanJwk(full);
    const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, alg, false, usages);
    return { privateKey, publicJwk, kid: kind === 'escrow' ? await escrowKeyId(publicJwk) : await signingKeyId(publicJwk) };
  } catch {
    throw new DecryptError('invalid private key');
  }
}

/** The kid of a signing public JWK (as escrowKeyId). */
export async function signingKeyId(publicJwk) {
  const pub = await crypto.subtle.importKey('jwk', cleanJwk(publicJwk), ECDSA, true, ['verify']);
  return keyId(new Uint8Array(await crypto.subtle.exportKey('raw', pub)));
}

async function escrowKek(privateKey, publicKey, epkRaw) {
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: publicKey }, privateKey, 256));
  return kekFrom(shared, 'kek-escrow', epkRaw);
}

/** The kid of an escrow public JWK (to tell whether an escrow wrap is for the current key). */
export async function escrowKeyId(publicJwk) {
  const pub = await crypto.subtle.importKey('jwk', cleanJwk(publicJwk), ECDH, true, []);
  return keyId(new Uint8Array(await crypto.subtle.exportKey('raw', pub)));
}

/** The kid an escrow wrap was made for, or null. */
export function escrowWrapKeyId(wrap) {
  const parts = wrap && typeof wrap.data === 'string' ? wrap.data.split('.') : [];
  return parts.length === 5 && parts[0] === VERSION ? parts[2] : null;
}

/** An `escrow` wrap of DK for the owner's escrow public key (ref "escrow"). */
export async function wrapEscrow(dk, publicJwk) {
  if (!isDk(dk)) throw new TypeError('invalid Drive key');
  const ownerPub = await crypto.subtle.importKey('jwk', cleanJwk(publicJwk), ECDH, true, []);
  const kid = await keyId(new Uint8Array(await crypto.subtle.exportKey('raw', ownerPub)));
  const eph = await crypto.subtle.generateKey(ECDH, true, ['deriveBits']);
  const epk = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const kek = await escrowKek(eph.privateKey, ownerPub, epk);
  const { iv, ct } = await seal(kek, wrapAad('escrow', `escrow:${kid}`), dk);
  return { kind: 'escrow', ref: 'escrow', data: [VERSION, b64urlFromBytes(epk), kid, b64urlFromBytes(iv), b64urlFromBytes(ct)].join('.') };
}

/** DK from an escrow wrap with the owner's escrow private key, or null. */
export async function unlockWithEscrow(privateKey, wrap) {
  const parts = wrap && typeof wrap.data === 'string' ? wrap.data.split('.') : [];
  if (wrap?.kind !== 'escrow' || parts.length !== 5 || parts[0] !== VERSION) return null;
  try {
    const epk = bytesFromB64url(parts[1]);
    const iv = bytesFromB64url(parts[3]);
    const ct = bytesFromB64url(parts[4]);
    if (epk.length !== 65 || iv.length !== 12) return null;
    const ephPub = await crypto.subtle.importKey('raw', epk, ECDH, false, []);
    const kek = await escrowKek(privateKey, ephPub, epk);
    const dk = await open(kek, wrapAad('escrow', `escrow:${parts[2]}`), iv, ct);
    return isDk(dk) ? dk : null;
  } catch {
    return null;
  }
}

// ── the tab's copy of DK ───────────────────────────────────────────────────

function storage() {
  try { return typeof sessionStorage === 'undefined' ? null : sessionStorage; } catch { return null; }
}

/**
 * While `held` is set (see holdSessionKeys), the tab's keys live only in this
 * module's memory, never in sessionStorage.
 */
let held = null;

function put(slot, uidSlot, dk, userId) {
  if (!isDk(dk)) return false;
  if (held) {
    held[slot] = b64urlFromBytes(dk);
    held[uidSlot] = typeof userId === 'string' && userId ? userId : null;
    return true;
  }
  const s = storage();
  if (!s) return false;
  try {
    s.setItem(slot, b64urlFromBytes(dk));
    if (typeof userId === 'string' && userId) s.setItem(uidSlot, userId);
    else s.removeItem(uidSlot);
    return true;
  } catch {
    return false;
  }
}

function get(slot, uidSlot, userId, strict) {
  let v;
  let owner;
  if (held) {
    v = held[slot];
    owner = held[uidSlot];
  } else {
    const s = storage();
    if (!s) return null;
    try { v = s.getItem(slot); owner = s.getItem(uidSlot); } catch { return null; }
  }
  if (!v) return null;
  if ((strict || (typeof userId === 'string' && userId)) && owner !== userId) return null;
  try {
    const dk = bytesFromB64url(v);
    return isDk(dk) ? dk : null;
  } catch {
    return null;
  }
}

function drop(...slots) {
  if (held) { for (const k of slots) held[k] = null; return; }
  const s = storage();
  if (!s) return;
  for (const k of slots) { try { s.removeItem(k); } catch { /* storage refused */ } }
}

/**
 * Keep DK for this tab (sessionStorage "secbin_dk", base64url) until sign-out
 * or the tab closes. `userId` (optional) is kept next to it so another
 * account's page (e.g. while impersonating) never picks it up.
 */
export function saveSessionKey(dk, userId) {
  return put(SESSION_KEY, SESSION_UID, dk, userId);
}

/** This tab's DK, or null (none, malformed, or kept for another user). */
export function loadSessionKey(userId) {
  return get(SESSION_KEY, SESSION_UID, userId, false);
}

/** The account whose DK this tab holds (the owner's, while impersonating), or null. */
export function sessionKeyUser() {
  if (held) return held[SESSION_KEY] ? held[SESSION_UID] || null : null;
  const s = storage();
  try { return s && s.getItem(SESSION_KEY) ? s.getItem(SESSION_UID) : null; } catch { return null; }
}

/** Forget this tab's DK (and the Drive key of a user the owner acted as). */
export function clearSessionKey() {
  drop(SESSION_KEY, SESSION_UID, IMP_KEY, IMP_UID);
}

/**
 * The Drive key of the user the owner is acting as (opened through the owner
 * escrow): its own slot, bound to that user, never the owner's.
 */
export function saveImpersonationKey(dk, userId) {
  return put(IMP_KEY, IMP_UID, dk, userId);
}

export function loadImpersonationKey(userId) {
  return get(IMP_KEY, IMP_UID, userId, true);
}

/** The impersonation ended (or never started on this page): forget that user's key. */
export function clearImpersonationKey() {
  drop(IMP_KEY, IMP_UID);
}

/**
 * Called right before third-party script (the Turnstile widget on login,
 * Account and the public composer; public/js/turnstile.js) is added to the
 * page: the tab's Drive keys move out of sessionStorage into this module's
 * memory, where other script on the page cannot read them, and are gone when
 * the page is left (the Drive page asks again). `releaseSessionKeys()` writes
 * them back (the sign-in does, as it leaves the page). See SECURITY.md (Drive
 * keys, in the tab).
 */
export function holdSessionKeys() {
  if (held) return;
  const s = storage();
  const next = { [SESSION_KEY]: null, [SESSION_UID]: null, [IMP_KEY]: null, [IMP_UID]: null };
  if (s) {
    for (const k of Object.keys(next)) {
      try { next[k] = s.getItem(k); s.removeItem(k); } catch { /* storage refused */ }
    }
  }
  held = next;
}

export function releaseSessionKeys() {
  if (!held) return;
  const h = held;
  held = null;
  const s = storage();
  if (!s) return;
  for (const [k, v] of Object.entries(h)) {
    try { if (v) s.setItem(k, v); else s.removeItem(k); } catch { /* storage refused */ }
  }
}
