// ids.js — server-side identifier and token handling (SPEC.md §7).
// Share IDs carry 128 bits of CSPRNG entropy plus a 1-char storage-class prefix
// (k = KV note, b = view-limited note, f = file share). Delete / upload tokens,
// grants and API keys carry 256 bits; the server stores only their SHA-256 and
// verifies in constant time. Imports the shared byte helpers.

import {
  randomBytes, b64urlFromBytes, bytesFromB64url, utf8, sha256Hex, timingSafeEqualHex,
} from '../../public/js/bytes.js';

const CLASSES = ['k', 'b', 'f'];
const ID_RANDOM_BYTES = 16;   // 128-bit entropy
const ID_B64_LEN = 22;        // b64url length of 16 bytes (unpadded)
const TOKEN_BYTES = 32;       // 256-bit delete token

/** Generate a share id: class prefix ('k' | 'b' | 'f') + base64url(16 CSPRNG bytes). */
export function genId(cls) {
  if (!CLASSES.includes(cls)) throw new Error('bad id class');
  return cls + b64urlFromBytes(randomBytes(ID_RANDOM_BYTES));
}

/**
 * Parse/validate a share id. Returns { cls, burn, file } or null if the id is
 * malformed (wrong prefix, wrong length, non-16-byte body). Callers treat null
 * as 404 — the read path also uses `cls` to pick the storage backend.
 */
export function parseId(id) {
  if (typeof id !== 'string' || id.length !== ID_B64_LEN + 1) return null;
  const cls = id[0];
  if (!CLASSES.includes(cls)) return null;
  const body = id.slice(1);
  try {
    if (bytesFromB64url(body).length !== ID_RANDOM_BYTES) return null;
  } catch {
    return null;
  }
  return { cls, burn: cls === 'b', file: cls === 'f' };
}

/** Generate a 256-bit token (delete / upload / grant) as base64url. */
export function genDeleteToken() {
  return b64urlFromBytes(randomBytes(TOKEN_BYTES));
}
export const genToken = genDeleteToken;

/** API key: "sbk_" + base64url(32 CSPRNG bytes). */
export function genApiKey() {
  return 'sbk_' + b64urlFromBytes(randomBytes(TOKEN_BYTES));
}

/** Session id (inside the encrypted session token): 128 bits. */
export function genSessionId() {
  return b64urlFromBytes(randomBytes(ID_RANDOM_BYTES));
}

/** SHA-256 (hex) of a delete-token string — the only form stored server-side. */
export function hashToken(token) {
  return sha256Hex(utf8(token));
}

/**
 * Constant-time verification of a presented delete token against a stored hash.
 * Validates the token's encoding/length first, then compares fixed-length hex
 * hashes in constant time. Returns false on any malformed input (fail closed).
 */
export async function verifyToken(presented, storedHashHex) {
  if (typeof presented !== 'string' || typeof storedHashHex !== 'string') return false;
  try {
    if (bytesFromB64url(presented).length !== TOKEN_BYTES) return false;
  } catch {
    return false;
  }
  const h = await hashToken(presented);
  return timingSafeEqualHex(h, storedHashHex);
}
