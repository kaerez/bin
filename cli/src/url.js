// url.js — build/parse secbin share URLs: "/p/" + id + "#" + b64url(F)
// (SPEC.md §10). Parsing is strict and fail-closed: the fragment must decode to
// exactly 32 bytes (the fragment secret F) BEFORE any network request is made,
// ids must match the server's shape (SPEC.md §7), and plain http is refused
// except toward localhost (wrangler dev).
//
// There is deliberately no default server: secbin is self-hosted, and silently
// sending ciphertext (or an API key) to a server the user never chose would be
// a surprise. create/send need --server or SECBIN_SERVER; get/delete take the
// origin from the share URL.
import { bytesFromB64url } from '../vendor/bytes.js';
import { UsageError } from './errors.js';

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
// classPrefix ("k" unlimited note in KV | "b" view-limited note | "f" file
// share) + b64url(random(16)) = 22 chars — SPEC.md §7.
const ID_RE = /^[kbf][A-Za-z0-9_-]{22}$/;

function parseUrl(raw, what) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    throw new UsageError(`invalid ${what}: "${String(raw).slice(0, 200)}"`);
  }
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && LOCAL_HOSTS.has(u.hostname))) {
    throw new UsageError('refusing a non-HTTPS server (only localhost may use plain http)');
  }
  if (u.username || u.password) throw new UsageError(`${what} must not contain credentials`);
  return u;
}

/** Validate/normalize a server base URL (--server / SECBIN_SERVER) → origin. */
export function normalizeServer(raw) {
  const u = parseUrl(raw, 'server URL');
  if (u.pathname !== '/' || u.search || u.hash) {
    throw new UsageError('server URL must be a bare origin (e.g. https://secbin.example.com)');
  }
  return u.origin;
}

/**
 * The server for commands that talk to an account endpoint: --server, else
 * $SECBIN_SERVER. Never a built-in default (see the header comment).
 */
export function requireServer(flag, env) {
  const raw = flag ?? env.SECBIN_SERVER;
  if (raw === undefined || raw === '') {
    throw new UsageError('no server configured — pass --server <origin> or set SECBIN_SERVER (e.g. https://secbin.example.com)');
  }
  return normalizeServer(raw);
}

/** Validate a share id against the server's id shape. */
export function parseId(id) {
  if (!ID_RE.test(id)) throw new UsageError(`malformed share id: "${String(id).slice(0, 60)}"`);
  return id;
}

/** API path segment for an id: file shares ("f") live under /api/file, notes under /api/paste. */
export function kindOf(id) {
  return id[0] === 'f' ? 'file' : 'paste';
}

/** Whether a valid id belongs to the expected storage class (fail-closed check on server replies). */
export function isIdOfClass(id, cls) {
  return typeof id === 'string' && ID_RE.test(id) && id[0] === cls;
}

/**
 * Parse a full share URL into { server, id, fragment }. The fragment is
 * checked to b64url-decode to exactly 32 bytes before anything touches the
 * network, reusing bytesFromB64url's fail-closed behavior.
 */
export function parseShareUrl(raw) {
  const u = parseUrl(raw, 'share URL');
  const m = /^\/p\/([^/]+)$/.exec(u.pathname);
  if (!m) throw new UsageError('not a secbin share URL (expected …/p/<id>#<key>)');
  const id = parseId(m[1]);
  const fragment = u.hash.replace(/^#/, '');
  if (!fragment) {
    throw new UsageError('share URL is missing its #key fragment — the share cannot be decrypted without it');
  }
  let key = null;
  try {
    key = bytesFromB64url(fragment);
  } catch {
    /* handled below, fail closed */
  }
  if (!key || key.length !== 32) throw new UsageError('invalid key fragment in share URL');
  return { server: u.origin, id, fragment };
}

/**
 * Accept either a share URL (fragment optional — deleting needs no key) or a
 * bare share id resolved against `fallbackServer` (--server / SECBIN_SERVER).
 * Returns { server, id }.
 */
export function parseUrlOrId(raw, fallbackServer) {
  if (/^[A-Za-z0-9_-]+$/.test(raw)) {
    const id = parseId(raw);
    if (fallbackServer === undefined || fallbackServer === '') {
      throw new UsageError('a bare share id needs --server <origin> or SECBIN_SERVER (or pass the full share URL)');
    }
    return { server: normalizeServer(fallbackServer), id };
  }
  const u = parseUrl(raw, 'share URL');
  const m = /^\/p\/([^/]+)$/.exec(u.pathname);
  if (!m) throw new UsageError('not a secbin share URL or share id');
  return { server: u.origin, id: parseId(m[1]) };
}

/** Compose the shareable URL. `F` never appears anywhere but the fragment. */
export function buildShareUrl(server, id, fragment) {
  return `${server}/p/${id}#${fragment}`;
}
