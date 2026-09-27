// sharetypes.js — the structured share payloads, encrypted like any note
// (fmt "url" and "secret"): building them in the composer / CLI and
// validating them, fail closed, on the recipient's side. Shared by the browser
// and the CLI (vendored copy). The server never sees these payloads.
//
//   url    — the plaintext is one absolute URL. Which URLs a sender may share
//            is the admin's "URL rules" (default: http and https; other
//            schemes such as tel: and regular expressions may be allowed),
//            checked here by the sender's browser or CLI — the server cannot
//            see the URL. Dangerous schemes (javascript:, data:, file:, …) are
//            refused on both sides whatever the rules say. Recipients see the
//            destination spelled out and open it only through an explicit,
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

// ── URL rules ────────────────────────────────────────────────────────────────
// A rule is "scheme:<name>://" (links like https://…; http and https are
// always written this way), "scheme:<name>:" (links like tel:… with no "//"),
// "scheme:*" (any scheme that is not forbidden, either form) or
// "re:<regular expression>", matched
// case-insensitively against the whole normalized URL (e.g.
// re:^https://([a-z0-9-]+\.)*example\.com/). A URL is allowed when any rule
// matches it. The owner's rules are ["scheme:*"].

export const DEFAULT_URL_RULES = Object.freeze(['scheme:http://', 'scheme:https://']);
export const MAX_URL_RULES = 50;
export const MAX_URL_RULE_LENGTH = 300;

/** Never shareable or openable, whatever the rules: they run code or read local data. */
export const FORBIDDEN_SCHEMES = Object.freeze(new Set([
  'javascript', 'data', 'vbscript', 'file', 'blob', 'about', 'filesystem', 'view-source', 'jar',
  'chrome', 'chrome-extension', 'chrome-search', 'edge', 'moz-extension', 'ms-browser-extension',
  'resource', 'intent', 'wyciwyg', 'livescript', 'mocha', 'res', 'ms-appx', 'ms-appx-web',
]));

/**
 * What a recipient may open straight from the page. Every other allowed
 * scheme (vscode:, ssh:, smb:, search-ms:…) is shown in full with Copy only:
 * the sender's URL rules are checked by the sender's own browser or CLI, so a
 * modified client could otherwise hand recipients an app link on this origin.
 */
export const RECIPIENT_OPEN_SCHEMES = Object.freeze(new Set(['http', 'https', 'mailto', 'tel', 'sms']));

const SCHEME_RE = /^[a-z][a-z0-9+.-]{0,31}$/;
// Browsers always write these with "//" (http:example.com becomes http://example.com/).
const HIERARCHICAL = new Set(['http', 'https', 'ws', 'wss', 'ftp']);
// Schemes that never use "//": an old bare "scheme:tel" rule becomes "scheme:tel:".
const OPAQUE = new Set(['mailto', 'tel', 'sms', 'geo', 'magnet', 'urn', 'news', 'callto', 'facetime', 'facetime-audio', 'maps', 'bitcoin']);

/**
 * Rules from before the scheme:name:// / scheme:name: syntax ("scheme:tel"),
 * rewritten to allow exactly what they allowed: http, https and the like with
 * "//", mailto, tel and the like without, any other scheme in both forms.
 * Anything else is returned unchanged (and checked by normalizeUrlRules).
 */
export function upgradeUrlRules(list) {
  if (!Array.isArray(list)) return list;
  const out = [];
  for (const item of list) {
    const m = /^scheme:([a-z][a-z0-9+.-]{0,31})$/i.exec(String(item ?? '').trim());
    if (!m) { out.push(item); continue; }
    const name = m[1].toLowerCase();
    if (HIERARCHICAL.has(name)) out.push(`scheme:${name}://`);
    else if (OPAQUE.has(name)) out.push(`scheme:${name}:`);
    else out.push(`scheme:${name}://`, `scheme:${name}:`);
  }
  return out;
}

/** Validate and canonicalize a rule list (throws Error with a readable message). */
export function normalizeUrlRules(list) {
  if (!Array.isArray(list)) throw new Error('URL rules must be a list');
  if (list.length > MAX_URL_RULES) throw new Error(`at most ${MAX_URL_RULES} URL rules`);
  const out = [];
  for (const item of list) {
    const r = String(item ?? '').trim();
    if (!r) continue;
    if (r.length > MAX_URL_RULE_LENGTH) throw new Error(`a URL rule is at most ${MAX_URL_RULE_LENGTH} characters`);
    const m = /^(scheme|re):(.*)$/s.exec(r);
    if (!m) throw new Error(`"${r.slice(0, 40)}": start a rule with scheme: or re:`);
    if (m[1] === 'scheme') {
      const body = m[2].trim().toLowerCase();
      if (body === '*') { out.push('scheme:*'); continue; }
      const sm = /^([^:/]*)(:\/\/|:)?$/.exec(body);
      const name = sm ? sm[1] : '';
      if (!SCHEME_RE.test(name)) throw new Error(`"${r.slice(0, 40)}": not a URL scheme`);
      if (FORBIDDEN_SCHEMES.has(name)) throw new Error(`the ${name}: scheme can never be allowed`);
      // Say which form: with "//" (scheme:name://) or without (scheme:name:).
      if (!sm[2]) throw new Error(`"${r.slice(0, 40)}": write scheme:${name}:// (links like ${name}://…) or scheme:${name}: (links like ${name}:… without //)`);
      if (HIERARCHICAL.has(name) && sm[2] === ':') throw new Error(`${name} links always have //: write scheme:${name}://`);
      out.push(`scheme:${name}${sm[2]}`);
    } else {
      const pattern = m[2];
      if (!pattern) throw new Error('empty regular expression');
      try { new RegExp(pattern, 'iu'); } catch (e) { throw new Error(`"${pattern.slice(0, 40)}": ${e.message}`, { cause: e }); }
      out.push(`re:${pattern}`);
    }
  }
  return [...new Set(out)];
}

/** Rules from untrusted input (a server response): invalid lists fall back to the default. */
export function urlRulesOf(value) {
  // An older server may still send "scheme:tel": read it as it was meant.
  try { return value === undefined ? [...DEFAULT_URL_RULES] : normalizeUrlRules(upgradeUrlRules(value)); } catch { return [...DEFAULT_URL_RULES]; }
}

const schemeOf = (u) => u.protocol.slice(0, -1).toLowerCase();

/**
 * The first of `rules` that allows a parsed URL, or null (forbidden schemes
 * never match). re: rules are JavaScript regular expressions, tested
 * case-insensitively (flags "iu") against the whole normalized link; they
 * match anywhere in it unless anchored with ^ (and $).
 */
export function matchingUrlRule(u, rules = DEFAULT_URL_RULES) {
  const scheme = schemeOf(u);
  if (FORBIDDEN_SCHEMES.has(scheme)) return null;
  const slashes = u.href.slice(scheme.length + 1).startsWith('//');
  for (const r of rules) {
    if (r === 'scheme:*' || r === `scheme:${scheme}${slashes ? '://' : ':'}`) return r;
    if (r.startsWith('re:')) {
      try { if (new RegExp(r.slice(3), 'iu').test(u.href)) return r; } catch { /* invalid rule: ignore */ }
    }
  }
  return null;
}

/** True when a parsed URL is allowed by `rules` (forbidden schemes never are). */
export function urlAllowed(u, rules = DEFAULT_URL_RULES) {
  return matchingUrlRule(u, rules) !== null;
}

/** re: rules that are not anchored at the start: they match anywhere in a link. */
export const unanchoredRules = (rules) => rules.filter((r) => r.startsWith('re:') && !r.slice(3).startsWith('^'));

/** A short description of what the rules allow ("http, https and tel links"). */
export function describeUrlRules(rules = DEFAULT_URL_RULES) {
  if (rules.includes('scheme:*')) return 'links of any safe kind';
  const schemes = rules.filter((r) => r.startsWith('scheme:')).map((r) => r.slice(7));
  const re = rules.filter((r) => r.startsWith('re:')).length;
  const parts = [];
  if (schemes.length) parts.push(`${schemes.length > 1 ? `${schemes.slice(0, -1).join(', ')} and ${schemes.at(-1)}` : schemes[0]} links`);
  if (re) parts.push(`links matching ${re} pattern${re > 1 ? 's' : ''} set by the administrator`);
  return parts.length ? parts.join(', or ') : 'no links';
}

/**
 * Parse and validate a URL share: absolute, no credentials, no controls, and
 * allowed. The sender passes the account's `rules`; a recipient passes
 * `{ recipient: true }` (the sender's rules are not known there, so any
 * scheme that is not forbidden is accepted — and shown for what it is).
 */
export function parseShareUrl(text, { rules = DEFAULT_URL_RULES, recipient = false } = {}) {
  const raw = String(text ?? '').trim();
  if (!raw || raw.length > MAX_URL_LENGTH || CONTROL.test(raw) || /\s/.test(raw)) throw new ShareTypeError('Enter a single link, with no spaces.');
  let u;
  try { u = new URL(raw); } catch {
    if (/^[a-z][a-z0-9+.-]{0,31}:\/{0,2}$/i.test(raw)) throw new ShareTypeError('That link is incomplete: add the address after the scheme, e.g. https://example.com/page.');
    throw new ShareTypeError('That is not a valid link.');
  }
  const scheme = schemeOf(u);
  if (FORBIDDEN_SCHEMES.has(scheme)) throw new ShareTypeError(`${scheme}: links can never be shared.`);
  if (!recipient && !urlAllowed(u, rules)) throw new ShareTypeError(`This link is not allowed for your account: you may share ${describeUrlRules(rules)}.`);
  if (u.username || u.password) throw new ShareTypeError('Links with a user name or password in them cannot be shared — use a secret share instead.');
  if ((scheme === 'http' || scheme === 'https') && !u.hostname) throw new ShareTypeError('That link has no host.');
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
  const scheme = schemeOf(u);
  // Links without a host (tel:, mailto:, sms:, geo:, …) open another app: show
  // the whole address instead of a host.
  const openable = RECIPIENT_OPEN_SCHEMES.has(scheme);
  if (!u.hostname) return { ascii: u.href, unicode: u.href, idn: false, insecure: false, scheme, external: true, openable };
  const ascii = u.hostname;
  let unicode;
  try { unicode = ascii.split('.').map((l) => (l.startsWith('xn--') ? decodePunycode(l.slice(4)) : l)).join('.'); } catch { unicode = ascii; }
  return { ascii, unicode, idn: unicode !== ascii, insecure: u.protocol === 'http:', scheme, external: scheme !== 'http' && scheme !== 'https', openable };
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
