// jwt.js — session tokens: a signed JWT (JWS, HS256 with SIG) nested inside an
// encrypted JWT (JWE compact, alg "dir" + enc "A256GCM" with ENC). Sign-then-
// encrypt: the cookie is opaque to the browser and to anything logging it, and
// forging or altering it needs both keys. Implemented on Web Crypto only.
//
// Verification is strict and fail-closed: exact header values (no "alg":"none",
// no algorithm confusion, no "crit", no "zip"), exact segment counts, canonical
// base64url, and typed claims. Returns null — never throws — on any defect.

import { b64urlFromBytes, bytesFromB64url, utf8, fromUtf8, randomBytes } from '../../public/js/bytes.js';

const JWE_HEADER = { alg: 'dir', enc: 'A256GCM', cty: 'JWT' };
const JWS_HEADER = { alg: 'HS256', typ: 'JWT' };
const JWE_HEADER_B64 = b64urlFromBytes(utf8(JSON.stringify(JWE_HEADER)));
const JWS_HEADER_B64 = b64urlFromBytes(utf8(JSON.stringify(JWS_HEADER)));
const MAX_TOKEN = 4096;

const hmacKeys = new WeakMap();
const aesKeys = new WeakMap();

async function hmacKey(keys) {
  let k = hmacKeys.get(keys);
  if (!k) {
    k = await crypto.subtle.importKey('raw', keys.sig, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    hmacKeys.set(keys, k);
  }
  return k;
}

async function aesKey(keys) {
  let k = aesKeys.get(keys);
  if (!k) {
    k = await crypto.subtle.importKey('raw', keys.enc, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    aesKeys.set(keys, k);
  }
  return k;
}

/** Sign then encrypt `claims` (a plain object) → compact JWE string. */
export async function sealToken(keys, claims) {
  const payload = b64urlFromBytes(utf8(JSON.stringify(claims)));
  const signingInput = `${JWS_HEADER_B64}.${payload}`;
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', await hmacKey(keys), utf8(signingInput)));
  const jws = `${signingInput}.${b64urlFromBytes(sig)}`;

  const iv = randomBytes(12);
  const sealed = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: utf8(JWE_HEADER_B64), tagLength: 128 },
    await aesKey(keys), utf8(jws)));
  const ct = sealed.subarray(0, sealed.length - 16);
  const tag = sealed.subarray(sealed.length - 16);
  // Compact JWE: header . (empty encrypted key for "dir") . iv . ciphertext . tag
  return `${JWE_HEADER_B64}..${b64urlFromBytes(iv)}.${b64urlFromBytes(ct)}.${b64urlFromBytes(tag)}`;
}

/** Decrypt then verify → claims object, or null on any defect. */
export async function openToken(keys, token) {
  try {
    if (typeof token !== 'string' || token.length === 0 || token.length > MAX_TOKEN) return null;
    const parts = token.split('.');
    if (parts.length !== 5 || parts[0] !== JWE_HEADER_B64 || parts[1] !== '') return null;
    const iv = bytesFromB64url(parts[2]);
    const ct = bytesFromB64url(parts[3]);
    const tag = bytesFromB64url(parts[4]);
    if (iv.length !== 12 || tag.length !== 16) return null;
    const sealed = new Uint8Array(ct.length + 16);
    sealed.set(ct);
    sealed.set(tag, ct.length);
    let jws;
    try {
      jws = fromUtf8(new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: utf8(JWE_HEADER_B64), tagLength: 128 }, await aesKey(keys), sealed)));
    } catch {
      return null;
    }
    const jp = jws.split('.');
    if (jp.length !== 3 || jp[0] !== JWS_HEADER_B64) return null;
    const ok = await crypto.subtle.verify('HMAC', await hmacKey(keys), bytesFromB64url(jp[2]), utf8(`${jp[0]}.${jp[1]}`));
    if (!ok) return null;
    const claims = JSON.parse(fromUtf8(bytesFromB64url(jp[1])));
    if (claims === null || typeof claims !== 'object' || Array.isArray(claims)) return null;
    return claims;
  } catch {
    return null;
  }
}
