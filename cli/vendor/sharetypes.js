// sharetypes.js — the structured share payloads, encrypted like any note
// (fmt "url" and "secret"): building them in the composer / CLI and
// validating them, fail closed, on the recipient's side. Shared by the browser
// and the CLI (vendored copy). The server never sees these payloads.
//
//   url    — the plaintext is one absolute http(s) URL. Recipients see it with
//            its host spelled out and open it only through an explicit,
//            confirmed click: never an automatic redirect.
//   secret — the plaintext is JSON { v: 1, title?, username?, password?, url?,
//            notes?, totp? }, shown masked with reveal/copy. `totp` is a
//            base32 seed or an otpauth://totp/ URI; codes are computed locally
//            (RFC 6238, WebCrypto HMAC).

export const MAX_URL_LENGTH = 2048;
export const SECRET_FIELDS = Object.freeze({
  title: 200, username: 500, password: 4096, url: MAX_URL_LENGTH, notes: 20000, totp: 1024,
});

/** Thrown for any payload that does not validate. */
export class ShareTypeError extends Error {
  constructor(message) { super(message); this.name = 'ShareTypeError'; }
}

// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

/** Parse and validate a shareable URL: absolute http(s), no credentials, no controls. */
export function parseShareUrl(text) {
  const raw = String(text ?? '').trim();
  if (!raw || raw.length > MAX_URL_LENGTH || CONTROL.test(raw) || /\s/.test(raw)) throw new ShareTypeError('Enter a single http:// or https:// link.');
  let u;
  try { u = new URL(raw); } catch { throw new ShareTypeError('That is not a valid link.'); }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new ShareTypeError('Only http:// and https:// links can be shared.');
  if (u.username || u.password) throw new ShareTypeError('Links with a user name or password in them cannot be shared — use a secret share instead.');
  if (!u.hostname) throw new ShareTypeError('That link has no host.');
  // The stored form is the normalized href (percent-encoded), which can be
  // longer than what was typed: bound that, so the recipient accepts it too.
  if (u.href.length > MAX_URL_LENGTH) throw new ShareTypeError(`That link is too long once encoded (max ${MAX_URL_LENGTH} characters).`);
  return u;
}

/**
 * How to show a URL's destination so it cannot be spoofed: the host as the
 * browser will actually resolve it (punycode) and, when it differs, the
 * Unicode form, flagged — look-alike characters are a classic phishing trick.
 */
export function describeHost(u) {
  const ascii = u.hostname;
  let unicode = ascii;
  try { unicode = ascii.split('.').map((l) => (l.startsWith('xn--') ? decodePunycode(l.slice(4)) : l)).join('.'); } catch { unicode = ascii; }
  return { ascii, unicode, idn: unicode !== ascii, insecure: u.protocol === 'http:' };
}

// RFC 3492 punycode decoder (display only).
function decodePunycode(input) {
  const base = 36; const tMin = 1; const tMax = 26; const skew = 38; const damp = 700;
  const out = [];
  let i = 0; let n = 128; let bias = 72;
  const basic = input.lastIndexOf('-');
  for (let j = 0; j < Math.max(0, basic); j++) out.push(input.charCodeAt(j));
  const digit = (c) => (c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base);
  const adapt = (delta, numPoints, first) => {
    let d = first ? Math.floor(delta / damp) : delta >> 1;
    d += Math.floor(d / numPoints);
    let k = 0;
    for (; d > ((base - tMin) * tMax) >> 1; k += base) d = Math.floor(d / (base - tMin));
    return Math.floor(k + ((base - tMin + 1) * d) / (d + skew));
  };
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
    const oldi = i;
    for (let w = 1, k = base; ; k += base) {
      if (idx >= input.length) throw new Error('bad punycode');
      const d = digit(input.charCodeAt(idx++));
      if (d >= base) throw new Error('bad punycode');
      i += d * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (d < t) break;
      w *= base - t;
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

/** Build the plaintext for a secret share; empty fields are dropped. */
export function buildSecret(fields) {
  const out = { v: 1 };
  for (const [k, max] of Object.entries(SECRET_FIELDS)) {
    const v = fields?.[k];
    if (v === undefined || v === null || v === '') continue;
    if (typeof v !== 'string') throw new ShareTypeError(`${k} must be text`);
    if (v.length > max) throw new ShareTypeError(`${k} is too long (max ${max} characters)`);
    out[k] = v;
  }
  if (out.url !== undefined) parseShareUrl(out.url);
  if (out.totp !== undefined) parseTotp(out.totp);
  if (Object.keys(out).length === 1) throw new ShareTypeError('Fill in at least one field.');
  return JSON.stringify(out);
}

/** Parse a decrypted secret share (untrusted) → a clean object. */
export function parseSecret(text) {
  let d;
  try { d = JSON.parse(text); } catch { throw new ShareTypeError('This secret could not be read.'); }
  if (!d || typeof d !== 'object' || Array.isArray(d) || d.v !== 1) throw new ShareTypeError('This secret could not be read.');
  const out = {};
  for (const k of Object.keys(d)) {
    if (k === 'v') continue;
    if (!Object.prototype.hasOwnProperty.call(SECRET_FIELDS, k)) throw new ShareTypeError('This secret could not be read.');
    if (typeof d[k] !== 'string' || d[k].length > SECRET_FIELDS[k]) throw new ShareTypeError('This secret could not be read.');
    out[k] = d[k];
  }
  if (Object.keys(out).length === 0) throw new ShareTypeError('This secret could not be read.');
  return out;
}

// ── TOTP (RFC 6238 / RFC 4226) ────────────────────────────────────────────────

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(s) {
  const clean = String(s).toUpperCase().replace(/[\s-]/g, '').replace(/=+$/, '');
  if (!clean || !/^[A-Z2-7]+$/.test(clean)) throw new ShareTypeError('The one-time-code seed is not valid base32.');
  const out = [];
  let bits = 0; let value = 0;
  for (const c of clean) {
    value = (value << 5) | B32.indexOf(c);
    bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(out);
}

/** A base32 seed or otpauth://totp/… URI → { key, algorithm, digits, period }. */
export function parseTotp(input) {
  const s = String(input).trim();
  let secret = s; let algorithm = 'SHA-1'; let digits = 6; let period = 30;
  if (/^otpauth:/i.test(s)) {
    let u;
    try { u = new URL(s); } catch { throw new ShareTypeError('The otpauth:// link is not valid.'); }
    if (u.host.toLowerCase() !== 'totp') throw new ShareTypeError('Only time-based (totp) codes are supported.');
    secret = u.searchParams.get('secret') || '';
    const alg = (u.searchParams.get('algorithm') || 'SHA1').toUpperCase();
    algorithm = new Map([['SHA1', 'SHA-1'], ['SHA256', 'SHA-256'], ['SHA512', 'SHA-512']]).get(alg);
    if (!algorithm) throw new ShareTypeError('Unsupported one-time-code algorithm.');
    digits = Number(u.searchParams.get('digits') || 6);
    period = Number(u.searchParams.get('period') || 30);
  }
  if (![6, 7, 8].includes(digits)) throw new ShareTypeError('One-time codes must have 6–8 digits.');
  if (!Number.isInteger(period) || period < 1 || period > 300) throw new ShareTypeError('Invalid one-time-code period.');
  const key = base32Decode(secret);
  if (key.length < 10) throw new ShareTypeError('The one-time-code seed is too short.');
  return { key, algorithm, digits, period };
}

/** The TOTP code at `timeMs` (default now) and seconds until it changes. */
export async function totpCode(input, timeMs = Date.now()) {
  const { key, algorithm, digits, period } = typeof input === 'string' ? parseTotp(input) : input;
  const counter = Math.floor(timeMs / 1000 / period);
  const msg = new Uint8Array(8);
  new DataView(msg.buffer).setBigUint64(0, BigInt(counter));
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: algorithm }, false, ['sign']);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', k, msg));
  const off = mac[mac.length - 1] & 0x0f;
  const bin = ((mac[off] & 0x7f) << 24) | (mac[off + 1] << 16) | (mac[off + 2] << 8) | mac[off + 3];
  const code = String(bin % 10 ** digits).padStart(digits, '0');
  const remaining = period - (Math.floor(timeMs / 1000) % period);
  return { code, remaining, period };
}
