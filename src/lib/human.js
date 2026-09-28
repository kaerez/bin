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
// The recipient's page seals the link's key in sessionStorage under a random,
// cookie-bound page key (below) while the check page, which runs Cloudflare's
// script, is open. See SECURITY.md.

import { sessionKeys } from './config.js';
import { HttpError } from './http.js';
import { rateLimit, recordFailure, CAPTCHA_VERIFY } from './guard.js';
import { requireTurnstile } from './turnstile.js';
import { b64urlFromBytes, bytesFromB64url, utf8, fromUtf8, randomBytes } from '../../public/js/bytes.js';

export const SHARE_GRANT_SEC = 600;
export const SHARE_GRANT_CAP_SEC = 12 * 3600;
export const REVERSE_GRANT_SEC = 600;
export const HUMAN_HEADER = 'x-secbin-human';
const MAX_GRANT = 512;
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

/**
 * The network as a Drive upload session keeps it (rsessions.net, the
 * per-network session cap): an HMAC of the Guard's tracking key under a key of
 * its own, never the address or an unkeyed hash of it (SECURITY.md, "Records
 * at rest"). The Drive hashes it again per link and keeps 24 bits.
 */
export async function reverseNet(env, guardKey) {
  return b64urlFromBytes(await mac(env, 'reverse-net', String(guardKey ?? ''))).slice(0, 22);
}

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

/**
 * Verify the request's Turnstile token for `action`, for an anonymous caller
 * (the grant routes and a reverse session start): at most CAPTCHA_VERIFY
 * checks per network and window reach Cloudflare's siteverify (`429
 * rate_limited` beyond), and a missing or failed token counts as an invalid
 * request in the Guard, like a wrong link. `g` is the caller's ipContext.
 */
export async function verifyCaptcha(env, g, request, action) {
  const rl = await rateLimit(env, g, 'captcha-verify', CAPTCHA_VERIFY);
  if (!rl.ok) {
    throw new HttpError(429, 'rate_limited', 'Too many CAPTCHA checks from your network. Try again later.', rl.until ? { until: rl.until } : undefined, { 'retry-after': '600' });
  }
  try {
    await requireTurnstile(env, request, action, { limited: false }); // counted above (captcha-verify)
  } catch (e) {
    if (e instanceof HttpError && (e.code === 'turnstile_failed' || e.code === 'turnstile_required')) {
      const b = await recordFailure(env, g, 'invalid');
      if (b.newlyBlocked) throw new HttpError(429, 'blocked', 'Too many invalid requests from your network. Try again later.', { until: b.until });
    }
    throw e;
  }
}

/** The refusal a content route gives without a valid grant (never counted as an invalid fetch). */
export const captchaRequired = (reverse = false) => new HttpError(403, 'captcha_required', reverse
  ? 'This link requires a CAPTCHA; open it in a browser.'
  : 'This share requires a CAPTCHA; open it in a browser.');

// ── the page key (see public/js/pagekey.js) ─────────────────────────────────
//
// A random key, never derived from anything a page can read: 32 random bytes
// and a nonce `n` (16 bytes) made on each strict navigation to /p/<id> or
// /r/<id>. The Worker writes `n.key` into that document and into an HttpOnly,
// Secure, SameSite=Strict cookie named by the nonce (one per tab's round
// trip), scoped to the share's own path. On the return
// from the check page (/p/<id>?n=<n>) the key is written into the document
// again only when that cookie comes with the navigation and names the same
// nonce, and the cookie is cleared in the same response: one round trip, one
// use. A client outside the browser has no cookie; a script in the browser
// cannot read it (HttpOnly) and its fetch() is not a document navigation.

export const PAGE_KEY_PREFIX = '__Secure-secbin_pk_';
export const PAGE_KEY_MAX_AGE = 15 * 60;
/** Page key cookies kept per share path at most (a new one clears the oldest beyond it). */
export const PAGE_KEYS_MAX = 4;
export const PAGE_NONCE_RE = /^[A-Za-z0-9_-]{22}$/;
const PAGE_KEY_RE = /^[A-Za-z0-9_-]{43}$/;

/** A new page key → { n, key } (base64url; 16 and 32 random bytes). */
export const newPageKey = () => ({ n: b64urlFromBytes(randomBytes(16)), key: b64urlFromBytes(randomBytes(32)) });

/**
 * The page keys in the request's cookies (only this share path's are sent):
 * `__Secure-secbin_pk_<n>=<key>.<issued, unix seconds>` → [{ n, key, t }],
 * malformed ones left out. Each tab's round trip has its own cookie (its own
 * nonce), so two tabs of one share do not replace each other's.
 */
export function pageKeysIn(request) {
  const out = [];
  const header = request.headers.get('cookie') || '';
  if (header.length > 8192) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const name = part.slice(0, i).trim();
    if (!name.startsWith(PAGE_KEY_PREFIX)) continue;
    const n = name.slice(PAGE_KEY_PREFIX.length);
    const [key, t, extra] = part.slice(i + 1).trim().split('.');
    if (!PAGE_NONCE_RE.test(n) || !PAGE_KEY_RE.test(key || '') || extra !== undefined || !/^\d{1,12}$/.test(t || '')) continue;
    out.push({ n, key, t: Number(t) });
  }
  return out;
}

/** Set-Cookie for page key `pk` ({ n, key }) on `path` (/p/<id> or /r/<id>), or the removal of nonce `n`'s when `pk` is null. */
export function pageKeyCookie(path, n, pk = null) {
  const value = pk ? `${pk.key}.${Math.floor(Date.now() / 1000)}` : '';
  return `${PAGE_KEY_PREFIX}${n}=${value}; Path=${path}; HttpOnly; Secure; SameSite=Strict; Max-Age=${pk ? PAGE_KEY_MAX_AGE : 0}`;
}
