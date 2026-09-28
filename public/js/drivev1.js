// drivev1.js — the Drive keys of the release before the key model v2, kept
// only to open them once more for the upgrade (docs/DRIVE.md §3.3). Nothing
// here seals anything new: it opens the old Drive key (DK) from its wraps —
// the password (Argon2id), a recovery code, a passkey's PRF output, or the
// owner's escrow key — and the fields DK sealed (names, metadata, file keys,
// reverse-link keys), so that driveupgrade.js can re-seal them under the
// user's KEK. Once every Drive is upgraded the server has none of this left
// and this module has nothing to open.
//
// The old formats (docs/DRIVE.md of that release): sub-keys HKDF(DK, "",
// "secbin-drive/v1 names" | "… files"); a sealed field { iv, ct } with AAD
// "secbin-drive/v1\n<field>\n<nodeId>\n"; a wrap "1.<iv>.<ct>" (escrow:
// "1.<epk>.<kid>.<iv>.<ct>") with AAD field "wrap:<kind>", node id its ref.

import { utf8, b64urlFromBytes, bytesFromB64url, sha256Hex } from './bytes.js';
import { hkdf32, DecryptError } from './crypto.js';
import { readSlot, writeSlot } from './drivekeys.js';

const EMPTY = new Uint8Array(0);
const VERSION = '1';
const DK_BYTES = 32;
const SALT_BYTES = 16;
/** The old Drive's own Argon2id cost (fixed). */
export const DRIVE_ARGON2 = Object.freeze({ mKiB: 65536, t: 3, p: 1 });
/** SHA-256("secbin-drive/v1 prf"): the PRF input the old passkey wraps used (a test checks it). */
export const DRIVE_PRF_SALT = new Uint8Array([
  0x7c, 0x53, 0xc3, 0x1c, 0xb5, 0xb3, 0xcc, 0x57, 0xbd, 0x63, 0x2e, 0xda, 0x13, 0x81, 0x08, 0xe6,
  0x8c, 0x8e, 0x04, 0xd2, 0x1b, 0x3c, 0x8a, 0x5f, 0x30, 0x04, 0x60, 0x70, 0xa4, 0x6c, 0xb3, 0x19,
]);

const info = (s) => utf8(`secbin-drive/v1 ${s}`);
const aad = (field, nodeId) => utf8(`secbin-drive/v1\n${field}\n${nodeId}\n`);
const isDk = (dk) => dk instanceof Uint8Array && dk.length === DK_BYTES;

async function aesKey(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
}
async function open(key, ad, iv, ct) {
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: ad, tagLength: 128 }, key, ct));
  } catch {
    throw new DecryptError();
  }
}

/** { names, files }: the old DK's two AES-256-GCM sub-keys. */
export async function deriveSubkeysV1(dk) {
  if (!isDk(dk)) throw new TypeError('invalid Drive key');
  const [names, files] = await Promise.all([hkdf32(dk, EMPTY, info('names')), hkdf32(dk, EMPTY, info('files'))]);
  return { names: await aesKey(names), files: await aesKey(files) };
}

/**
 * The old Drive key's check value (the server kept it with the Drive):
 * HMAC-SHA-256 under DK's raw "files" sub-key of "secbin-drive/v1 kcv" — a
 * key that gives another value is not this Drive's.
 */
export async function keyCheckValueV1(dk) {
  if (!isDk(dk)) throw new TypeError('invalid Drive key');
  const raw = await hkdf32(dk, EMPTY, info('files'));
  const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return b64urlFromBytes(new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8('secbin-drive/v1 kcv'))));
}

/** Open an old sealed field → bytes; DecryptError when it is not this node's `field`. */
export async function openFieldV1(key, field, nodeId, sealed) {
  let iv;
  let ct;
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

// ── the wraps ──────────────────────────────────────────────────────────────
const wrapAad = (kind, ref) => aad(`wrap:${kind}`, ref);
async function kekFrom(ikm, label, salt = EMPTY) {
  return aesKey(await hkdf32(ikm, salt, info(label)));
}
function segments(data, count) {
  if (typeof data !== 'string' || data.length > 4096) return null;
  const parts = data.split('.');
  if (parts.length !== count + 1 || parts[0] !== VERSION) return null;
  try { return parts.slice(1).map((p) => bytesFromB64url(p)); } catch { return null; }
}
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

/** The old DK from its password wrap, or null. */
export async function unlockWithPassword(password, driveSalt, wraps) {
  const pw = listOf(wraps, 'pw');
  if (!pw.length || typeof password !== 'string' || !password) return null;
  let salt;
  try { salt = bytesFromB64url(driveSalt); } catch { return null; }
  if (salt.length !== SALT_BYTES) return null;
  const { argon2idRaw } = await import('./kdf.js');
  const raw = await argon2idRaw(utf8(password.normalize('NFC')), salt, { t: DRIVE_ARGON2.t, mKiB: DRIVE_ARGON2.mKiB, p: DRIVE_ARGON2.p });
  const kek = await kekFrom(raw, 'kek-pw');
  for (const w of pw) {
    const dk = await unwrapWith(kek, w);
    if (dk) return dk;
  }
  return null;
}

function normalizeRecoveryCode(code) {
  if (typeof code !== 'string' || code.length > 64) return null;
  const v = code.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  return /^[0-9A-HJKMNP-TV-Z]{16}$/.test(v) ? v : null;
}

/** The old DK from a recovery code's wrap, or null. */
export async function unlockWithRecovery(code, wraps) {
  const norm = normalizeRecoveryCode(code);
  if (!norm) return null;
  const kek = await kekFrom(utf8(norm), 'kek-recovery');
  const ref = await sha256Hex(utf8(`secbin-recovery/v1:${norm}`));
  const all = listOf(wraps, 'recovery');
  for (const w of [...all.filter((x) => x.ref === ref), ...all.filter((x) => x.ref !== ref)]) {
    const dk = await unwrapWith(kek, w);
    if (dk) return dk;
  }
  return null;
}

/** The old DK from a passkey's wrap (its PRF output for DRIVE_PRF_SALT), or null. */
export async function unlockWithPrf(prfOutput, credentialId, wraps) {
  const b = prfOutput instanceof ArrayBuffer ? new Uint8Array(prfOutput)
    : ArrayBuffer.isView(prfOutput) ? new Uint8Array(prfOutput.buffer, prfOutput.byteOffset, prfOutput.byteLength) : null;
  if (!b || b.length < 32) return null;
  const kek = await kekFrom(b, 'kek-prf');
  for (const w of listOf(wraps, 'passkey').filter((x) => x.ref === credentialId)) {
    const dk = await unwrapWith(kek, w);
    if (dk) return dk;
  }
  return null;
}

// ── the owner's escrow of that release ─────────────────────────────────────
const ECDH = { name: 'ECDH', namedCurve: 'P-256' };

/** The kid of an escrow public JWK: the first 16 bytes of SHA-256 over its raw point. */
export async function escrowKeyId(publicJwk) {
  const pub = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: publicJwk.x, y: publicJwk.y }, ECDH, true, []);
  const d = new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(await crypto.subtle.exportKey('raw', pub))));
  return b64urlFromBytes(d.subarray(0, 16));
}

/** The kid an escrow wrap was made for, or null. */
export function escrowWrapKeyId(wrap) {
  const parts = wrap && typeof wrap.data === 'string' ? wrap.data.split('.') : [];
  return parts.length === 5 && parts[0] === VERSION ? parts[2] : null;
}

/**
 * The owner's sealed escrow private key (under the owner's old DK) → {
 * privateKey, kid } (the kid derived from the key itself); DecryptError on
 * a wrong DK.
 */
export async function openEscrowKey(dk, data) {
  const seg = segments(data, 2);
  if (!seg || seg[0].length !== 12) throw new DecryptError('invalid escrow key');
  const { files } = await deriveSubkeysV1(dk);
  const pkcs8 = await open(files, aad('escrowPriv', 'drive'), seg[0], seg[1]);
  try {
    const jwk = await crypto.subtle.exportKey('jwk', await crypto.subtle.importKey('pkcs8', pkcs8, ECDH, true, ['deriveBits']));
    return { privateKey: await crypto.subtle.importKey('pkcs8', pkcs8, ECDH, false, ['deriveBits']), kid: await escrowKeyId(jwk) };
  } catch {
    throw new DecryptError('invalid escrow key');
  } finally {
    pkcs8.fill(0);
  }
}

/** A user's old DK from their escrow wrap with the owner's escrow private key, or null. */
export async function unlockWithEscrow(privateKey, wrap) {
  const parts = wrap && typeof wrap.data === 'string' ? wrap.data.split('.') : [];
  if (wrap?.kind !== 'escrow' || parts.length !== 5 || parts[0] !== VERSION) return null;
  try {
    const epk = bytesFromB64url(parts[1]);
    const iv = bytesFromB64url(parts[3]);
    const ct = bytesFromB64url(parts[4]);
    if (epk.length !== 65 || iv.length !== 12) return null;
    const ephPub = await crypto.subtle.importKey('raw', epk, ECDH, false, []);
    const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: ephPub }, privateKey, 256));
    const kek = await kekFrom(shared, 'kek-escrow', epk);
    const dk = await open(kek, wrapAad('escrow', `escrow:${parts[2]}`), iv, ct);
    return isDk(dk) ? dk : null;
  } catch {
    return null;
  }
}

/** An old reverse-link private key (sealed under DK's "files" key, field "reversePriv") → PKCS#8 bytes. */
export async function openReversePrivV1(dk, id, value) {
  const { files } = await deriveSubkeysV1(dk);
  return openFieldV1(files, 'reversePriv', id, value);
}

// ── the tab's copy of the old DK (only while a Drive waits for its upgrade) ─
const SLOT = 'secbin_dk';
const SLOT_UID = 'secbin_dk_uid';

/** Keep the old DK for this tab (the sign-in opened it), bound to the account. */
export function saveLegacyKey(dk, userId) {
  if (!isDk(dk) || typeof userId !== 'string' || !userId) return false;
  return writeSlot(SLOT, b64urlFromBytes(dk)) && writeSlot(SLOT_UID, userId);
}

/** This tab's old DK for `userId`, or null. */
export function loadLegacyKey(userId) {
  const v = readSlot(SLOT);
  if (!v || readSlot(SLOT_UID) !== userId) return null;
  try {
    const dk = bytesFromB64url(v);
    return isDk(dk) ? dk : null;
  } catch {
    return null;
  }
}

export function clearLegacyKey() {
  writeSlot(SLOT, null);
  writeSlot(SLOT_UID, null);
}
