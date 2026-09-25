// webauthn.js — server-side WebAuthn (passkeys): verify a registration
// (navigator.credentials.create) and an assertion (navigator.credentials.get)
// with Web Crypto only. No attestation is requested ("none"), so the
// attestation statement is not evaluated; what is verified is what makes a
// passkey trustworthy for sign-in:
//   - clientDataJSON: type, the one-time challenge, and this exact origin;
//   - authenticatorData: the RP ID hash (this hostname), user presence AND
//     user verification (PIN / biometric) — so a passkey is two factors;
//   - the signature over authenticatorData ‖ SHA-256(clientDataJSON), with
//     the public key stored at registration (ES256, EdDSA or RS256);
//   - the signature counter never goes backwards (a cloned authenticator).
// A malformed input never throws past verify*(): it returns { ok: false }.

import { b64urlFromBytes, bytesFromB64url, utf8 } from '../../public/js/bytes.js';

/** COSE algorithms offered at registration, in order of preference. */
export const COSE_ALGS = [-7, -8, -257]; // ES256, EdDSA (Ed25519), RS256
const MAX_B64 = 16 * 1024;

class Bad extends Error {}
const bad = (m) => { throw new Bad(m); };

// ── a minimal CBOR reader (RFC 8949): the subset WebAuthn uses ─────────────
export function cborDecode(bytes, { allowTrailing = false } = {}) {
  let i = 0;
  const need = (n) => { if (i + n > bytes.length) bad('cbor: truncated'); };
  const uint = (info) => {
    if (info < 24) return info;
    const n = { 24: 1, 25: 2, 26: 4, 27: 8 }[info] || bad('cbor: bad length');
    need(n);
    let v = 0;
    for (let k = 0; k < n; k++) v = v * 256 + bytes[i++];
    if (!Number.isSafeInteger(v)) bad('cbor: integer too large');
    return v;
  };
  const item = (depth) => {
    if (depth > 16) bad('cbor: too deep');
    need(1);
    const b = bytes[i++];
    const major = b >> 5;
    const info = b & 31;
    if (info === 31) bad('cbor: indefinite lengths are not used by WebAuthn');
    switch (major) {
      case 0: return uint(info);
      case 1: return -1 - uint(info);
      case 2: { const n = uint(info); need(n); const v = bytes.slice(i, i + n); i += n; return v; }
      case 3: { const n = uint(info); need(n); const v = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(i, i + n)); i += n; return v; }
      case 4: { const n = uint(info); if (n > 1024) bad('cbor: array too long'); const a = []; for (let k = 0; k < n; k++) a.push(item(depth + 1)); return a; }
      case 5: {
        const n = uint(info);
        if (n > 256) bad('cbor: map too long');
        const m = new Map();
        for (let k = 0; k < n; k++) { const key = item(depth + 1); m.set(key, item(depth + 1)); }
        return m;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        return bad('cbor: unsupported simple value');
      default: return bad('cbor: unsupported type (tags are not used by WebAuthn)');
    }
  };
  const v = item(0);
  if (!allowTrailing && i !== bytes.length) bad('cbor: trailing bytes');
  return { value: v, length: i };
}

// ── authenticator data ─────────────────────────────────────────────────────
const FLAG_UP = 0x01;
const FLAG_UV = 0x04;
const FLAG_BE = 0x08;
const FLAG_BS = 0x10;
const FLAG_AT = 0x40;
const FLAG_ED = 0x80;

export function parseAuthData(ad) {
  if (!(ad instanceof Uint8Array) || ad.length < 37) bad('authenticator data too short');
  const flags = ad[32];
  const out = {
    rpIdHash: ad.slice(0, 32),
    flags,
    up: !!(flags & FLAG_UP),
    uv: !!(flags & FLAG_UV),
    backupEligible: !!(flags & FLAG_BE),
    backedUp: !!(flags & FLAG_BS),
    signCount: ((ad[33] << 24) >>> 0) + (ad[34] << 16) + (ad[35] << 8) + ad[36],
  };
  let i = 37;
  if (flags & FLAG_AT) {
    if (ad.length < i + 18) bad('attested credential data too short');
    i += 16; // AAGUID (not used: no attestation)
    const len = (ad[i] << 8) + ad[i + 1];
    i += 2;
    if (len < 16 || len > 1023 || ad.length < i + len) bad('bad credential id length');
    out.credentialId = ad.slice(i, i + len);
    i += len;
    const { value, length } = cborDecode(ad.subarray(i), { allowTrailing: true });
    out.cosePublicKey = ad.slice(i, i + length);
    out.coseKey = value;
    i += length;
  }
  if (flags & FLAG_ED) {
    const { length } = cborDecode(ad.subarray(i), { allowTrailing: true });
    i += length;
  }
  if (i !== ad.length) bad('trailing authenticator data');
  return out;
}

// ── COSE keys → Web Crypto ────────────────────────────────────────────────
const b64 = (u8) => b64urlFromBytes(u8);

/** A stored COSE public key (bytes) → { alg, key: CryptoKey, verify params }. */
export async function importCoseKey(coseBytes) {
  const { value: k } = cborDecode(coseBytes);
  if (!(k instanceof Map)) bad('COSE key is not a map');
  const kty = k.get(1);
  const alg = k.get(3);
  if (alg === -7 && kty === 2 && k.get(-1) === 1) {
    const x = k.get(-2); const y = k.get(-3);
    if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) bad('bad P-256 key');
    const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: b64(x), y: b64(y), ext: true }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return { alg, key, params: { name: 'ECDSA', hash: 'SHA-256' }, der: true };
  }
  if (alg === -8 && kty === 1 && k.get(-1) === 6) {
    const x = k.get(-2);
    if (!(x instanceof Uint8Array) || x.length !== 32) bad('bad Ed25519 key');
    const key = await crypto.subtle.importKey('raw', x, { name: 'Ed25519' }, false, ['verify']);
    return { alg, key, params: { name: 'Ed25519' }, der: false };
  }
  if (alg === -257 && kty === 3) {
    const n = k.get(-1); const e = k.get(-2);
    if (!(n instanceof Uint8Array) || !(e instanceof Uint8Array) || n.length < 256) bad('bad RSA key (2048 bits or more)');
    const key = await crypto.subtle.importKey('jwk', { kty: 'RSA', n: b64(n), e: b64(e), alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    return { alg, key, params: { name: 'RSASSA-PKCS1-v1_5' }, der: false };
  }
  return bad('unsupported key type or algorithm');
}

/** DER ECDSA-Sig-Value → raw r‖s (32 bytes each), as Web Crypto expects. */
export function derToRawP256(der) {
  let i = 0;
  const expect = (b) => { if (der[i++] !== b) bad('bad DER signature'); };
  const len = () => { const l = der[i++]; if (l & 0x80) bad('bad DER length'); return l; };
  expect(0x30);
  if (len() !== der.length - 2) bad('bad DER length');
  const int = () => {
    expect(0x02);
    const l = len();
    let v = der.subarray(i, i + l);
    i += l;
    while (v.length > 32 && v[0] === 0) v = v.subarray(1);
    if (v.length > 32 || v.length === 0) bad('bad DER integer');
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = int();
  const s = int();
  if (i !== der.length) bad('bad DER signature');
  const raw = new Uint8Array(64);
  raw.set(r); raw.set(s, 32);
  return raw;
}

// ── helpers ────────────────────────────────────────────────────────────────
const sha256 = async (u8) => new Uint8Array(await crypto.subtle.digest('SHA-256', u8));
const eq = (a, b) => a.length === b.length && a.every((x, k) => x === b[k]);

function field(obj, name) {
  const v = obj?.[name];
  if (typeof v !== 'string' || !v || v.length > MAX_B64) bad(`missing ${name}`);
  try { return bytesFromB64url(v); } catch { return bad(`bad ${name}`); }
}

function clientData(bytes, type, challenge, origin) {
  let cd;
  try { cd = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { bad('bad clientDataJSON'); }
  if (!cd || cd.type !== type) bad('wrong ceremony type');
  if (cd.challenge !== challenge) bad('wrong challenge');
  if (cd.origin !== origin) bad('wrong origin');
  if (cd.crossOrigin === true) bad('cross-origin ceremony');
}

/**
 * Verify a registration → { ok, credentialId (b64url), publicKey (COSE,
 * b64url), alg, signCount, backupEligible, backedUp, transports } or
 * { ok: false, reason }.
 */
export async function verifyRegistration(cred, { challenge, origin, rpId }) {
  try {
    if (!cred || cred.type !== 'public-key') bad('not a public-key credential');
    const r = cred.response || {};
    const cdBytes = field(r, 'clientDataJSON');
    clientData(cdBytes, 'webauthn.create', challenge, origin);
    const { value: att } = cborDecode(field(r, 'attestationObject'));
    if (!(att instanceof Map) || !(att.get('authData') instanceof Uint8Array)) bad('bad attestation object');
    const ad = parseAuthData(att.get('authData'));
    if (!eq(ad.rpIdHash, await sha256(utf8(rpId)))) bad('wrong RP ID');
    if (!ad.up || !ad.uv) bad('user presence and verification are required');
    if (!ad.credentialId || !ad.coseKey) bad('no credential in the response');
    const id = b64(ad.credentialId);
    if (cred.id !== id && cred.rawId !== id) bad('credential id mismatch');
    const imported = await importCoseKey(ad.cosePublicKey);
    if (!COSE_ALGS.includes(imported.alg)) bad('algorithm not allowed');
    const transports = Array.isArray(r.transports)
      ? r.transports.filter((t) => typeof t === 'string' && /^[a-z-]{2,16}$/.test(t)).slice(0, 8)
      : [];
    return {
      ok: true,
      credentialId: id,
      publicKey: b64(ad.cosePublicKey),
      alg: imported.alg,
      signCount: ad.signCount,
      backupEligible: ad.backupEligible,
      backedUp: ad.backedUp,
      transports,
    };
  } catch (e) {
    if (e instanceof Bad) return { ok: false, reason: e.message };
    return { ok: false, reason: 'invalid registration' };
  }
}

/** The credential id an assertion claims (b64url), or null. */
export function assertionId(cred) {
  const id = cred && typeof cred.id === 'string' ? cred.id : null;
  return id && /^[A-Za-z0-9_-]{16,1400}$/.test(id) ? id : null;
}

/**
 * Verify an assertion for a stored credential → { ok, signCount, backedUp,
 * userHandle } or { ok: false, reason }.
 */
export async function verifyAssertion(cred, { challenge, origin, rpId, publicKey, signCount = 0 }) {
  try {
    if (!cred || cred.type !== 'public-key') bad('not a public-key credential');
    const r = cred.response || {};
    const cdBytes = field(r, 'clientDataJSON');
    clientData(cdBytes, 'webauthn.get', challenge, origin);
    const adBytes = field(r, 'authenticatorData');
    const ad = parseAuthData(adBytes);
    if (!eq(ad.rpIdHash, await sha256(utf8(rpId)))) bad('wrong RP ID');
    if (!ad.up || !ad.uv) bad('user presence and verification are required');
    const k = await importCoseKey(bytesFromB64url(publicKey));
    let sig = field(r, 'signature');
    if (k.der) sig = derToRawP256(sig);
    const signed = new Uint8Array(adBytes.length + 32);
    signed.set(adBytes);
    signed.set(await sha256(cdBytes), adBytes.length);
    if (!(await crypto.subtle.verify(k.params, k.key, sig, signed))) bad('bad signature');
    // Counters that are in use must increase (0 = the authenticator has none).
    if ((ad.signCount !== 0 || signCount !== 0) && ad.signCount <= signCount) bad('signature counter went backwards (cloned authenticator?)');
    let userHandle = null;
    if (typeof r.userHandle === 'string' && r.userHandle) {
      try { userHandle = b64(bytesFromB64url(r.userHandle)); } catch { bad('bad userHandle'); }
    }
    return { ok: true, signCount: ad.signCount, backedUp: ad.backedUp, userHandle };
  } catch (e) {
    if (e instanceof Bad) return { ok: false, reason: e.message };
    return { ok: false, reason: 'invalid assertion' };
  }
}

// ── options for the browser (the JSON forms of WebAuthn Level 3) ──────────
const RP_NAME = 'secbin';

/** navigator.credentials.create() options: a discoverable, user-verified passkey. */
export function creationOptions({ challenge, timeoutMs, user, exclude = [] }, rpId) {
  return {
    rp: { id: rpId, name: RP_NAME },
    user: { id: user.handle, name: user.name, displayName: user.name },
    challenge,
    pubKeyCredParams: COSE_ALGS.map((alg) => ({ type: 'public-key', alg })),
    timeout: timeoutMs,
    attestation: 'none',
    authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'required' },
    excludeCredentials: exclude.map((c) => ({ type: 'public-key', id: c.id, transports: c.transports })),
  };
}

/** navigator.credentials.get() options; `allow` empty = any passkey for this site. */
export function requestOptions({ challenge, timeoutMs, allow = [] }, rpId) {
  return {
    challenge,
    rpId,
    timeout: timeoutMs,
    userVerification: 'required',
    allowCredentials: allow.map((c) => ({ type: 'public-key', id: c.id, transports: c.transports })),
  };
}
