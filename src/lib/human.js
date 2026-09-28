// human.js — CAPTCHA grants for shares that have the CAPTCHA (the
// shareCaptcha / reverseCaptcha role options, src/lib/settings.js).
//
// A recipient's browser passes the Turnstile check once on the check page
// (/p/<id>?check, public/js/check.js) and gets a grant: a short string signed
// here (HMAC-SHA-256 with a key derived from SIG), stateless, that says "this
// network passed the CAPTCHA for this share until <exp>":
//
//   h1.<b64url(JSON { k, id, n, iat, exp, j? })>.<b64url(HMAC)>
//
//   k    's' (a note, file share or Drive share) or 'r' (a reverse share)
//   id   the share id; a grant for one share opens no other
//   n    a keyed hash of the caller's network (the Guard's key: an IPv4
//        address or an IPv6 prefix), so a grant copied elsewhere fails
//   iat  when the check was passed; exp  when the grant lapses
//   j    reverse grants only: a random id, spent by the session start it is
//        used for (the Drive keeps it until exp), so each session start needs
//        its own CAPTCHA, as each needed its own Turnstile token before
//
// A share grant lasts SHARE_GRANT_SEC and slides while it is used (every
// content call that passes renews it, as does the page's keep-alive), never
// past SHARE_GRANT_CAP_SEC after the check. Content routes send it in
// X-Secbin-Human; without a valid one they answer 403 captcha_required,
// which is not counted as an invalid fetch.
//
// The same derived key also makes the per-navigation page key (pageKey): the
// Worker writes it into the recipient's page only on a real navigation, and
// the page uses it to seal the link's key in sessionStorage while the check
// page (which runs Cloudflare's script) is open. See SECURITY.md.

import { sessionKeys } from './config.js';
import { HttpError } from './http.js';
import { b64urlFromBytes, bytesFromB64url, utf8, fromUtf8, randomBytes } from '../../public/js/bytes.js';

export const SHARE_GRANT_SEC = 600;
export const SHARE_GRANT_CAP_SEC = 12 * 3600;
export const REVERSE_GRANT_SEC = 600;
export const HUMAN_HEADER = 'x-secbin-human';
const MAX_GRANT = 512;
const ID_RE = /^[A-Za-z0-9_-]{8,40}$/;
const B64_RE = /^[A-Za-z0-9_-]+$/;
const nowSec = () => Math.floor(Date.now() / 1000);

const keyCache = new Map();
/** An HMAC key derived from SIG for `label` (cached per SIG value). */
async function derived(env, label) {
  const k = sessionKeys(env);
  if (!k) throw new HttpError(503, 'not_configured', 'The server is not fully configured. Please contact the administrator.');
  const cacheKey = `${k.id}\0${label}`;
  let key = keyCache.get(cacheKey);
  if (!key) {
    const master = await crypto.subtle.importKey('raw', k.sig, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const raw = new Uint8Array(await crypto.subtle.sign('HMAC', master, utf8(`secbin/${label}/v1`)));
    key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
    if (keyCache.size > 8) keyCache.clear();
    keyCache.set(cacheKey, key);
  }
  return key;
}

const mac = async (env, label, text) => new Uint8Array(await crypto.subtle.sign('HMAC', await derived(env, label), utf8(text)));

/** The network tag a grant is bound to (from the Guard's tracking key). */
export async function netTag(env, guardKey) {
  return b64urlFromBytes(await mac(env, 'human-net', String(guardKey ?? ''))).slice(0, 22);
}

async function seal(env, claims) {
  const body = b64urlFromBytes(utf8(JSON.stringify(claims)));
  return `h1.${body}.${b64urlFromBytes(await mac(env, 'human-grant', `h1.${body}`))}`;
}

/** A new grant for `kind` ('s' | 'r') and share `id`, bound to network tag `net`. */
export async function issueGrant(env, { kind, id, net }) {
  const t = nowSec();
  const claims = { k: kind, id, n: net, iat: t, exp: t + (kind === 'r' ? REVERSE_GRANT_SEC : SHARE_GRANT_SEC) };
  if (kind === 'r') claims.j = b64urlFromBytes(randomBytes(16));
  return { grant: await seal(env, claims), expires: claims.exp, claims };
}

/**
 * The claims of a valid grant for `kind`, `id` and network `net`, or null
 * (malformed, forged, for another share, kind or network, or lapsed).
 */
export async function readGrant(env, token, { kind, id, net }) {
  if (typeof token !== 'string' || token.length > MAX_GRANT) return null;
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== 'h1' || !B64_RE.test(parts[1]) || !B64_RE.test(parts[2])) return null;
  let sig;
  try { sig = bytesFromB64url(parts[2]); } catch { return null; }
  if (sig.length !== 32) return null;
  const ok = await crypto.subtle.verify('HMAC', await derived(env, 'human-grant'), sig, utf8(`h1.${parts[1]}`));
  if (!ok) return null;
  let c;
  try { c = JSON.parse(fromUtf8(bytesFromB64url(parts[1]))); } catch { return null; }
  if (!c || typeof c !== 'object' || c.k !== kind || c.id !== id || c.n !== net) return null;
  if (!Number.isSafeInteger(c.iat) || !Number.isSafeInteger(c.exp) || c.exp <= nowSec() || c.exp - c.iat > SHARE_GRANT_CAP_SEC) return null;
  if (kind === 'r' && (typeof c.j !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(c.j))) return null;
  return c;
}

/**
 * A share grant renewed from its claims: SHARE_GRANT_SEC from now, never past
 * SHARE_GRANT_CAP_SEC after the check → { grant, expires } (the same when
 * there is nothing to add).
 */
export async function renewGrant(env, claims) {
  const exp = Math.min(nowSec() + SHARE_GRANT_SEC, claims.iat + SHARE_GRANT_CAP_SEC);
  if (exp <= claims.exp) return null;
  const next = { ...claims, exp };
  return { grant: await seal(env, next), expires: exp, claims: next };
}

/** The refusal a content route gives without a valid grant (never counted as an invalid fetch). */
export const captchaRequired = (reverse = false) => new HttpError(403, 'captcha_required', reverse
  ? 'This link requires a CAPTCHA; open it in a browser.'
  : 'This share requires a CAPTCHA; open it in a browser.');

// ── the page key (see public/js/pagekey.js) ─────────────────────────────────

/** A fresh nonce for a page key. */
export const pageNonce = () => b64urlFromBytes(randomBytes(16));
export const PAGE_NONCE_RE = /^[A-Za-z0-9_-]{22}$/;

/** The page key for share page `kind` ('p' | 'r'), share `id` and nonce `n` (32 bytes, base64url). */
export async function pageKey(env, kind, id, n) {
  if (!ID_RE.test(String(id)) || !PAGE_NONCE_RE.test(String(n))) throw new Error('bad page key input');
  return b64urlFromBytes(await mac(env, 'page-key', `${kind}\0${id}\0${n}`));
}
