// http.js — response helpers, security headers, cookies, bounded body reads and
// request-shape guards shared by every route. Nothing here throws on hostile
// input: malformed requests become clean 4xx JSON responses.

// Mirrors public/_headers so Worker-served pages/assets get the same policy.
// 'wasm-unsafe-eval' permits WebAssembly compilation (Argon2id, pdf.js image
// decoders) but NOT JavaScript eval; blob: is allowed only for images/media in
// the safe viewer; frames and plugins stay disabled.
export const CSP = [
  "default-src 'none'",
  "script-src 'self' 'wasm-unsafe-eval'",
  "style-src 'self'",
  "img-src 'self' data: blob:",
  "media-src blob:",
  "connect-src 'self'",
  "font-src 'self'",
  "worker-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "frame-src 'none'",
  "object-src 'none'",
].join('; ');

export const SECURITY_HEADERS = {
  'content-security-policy': CSP,
  'x-content-type-options': 'nosniff',
  'x-frame-options': 'DENY',
  'referrer-policy': 'no-referrer',
  'permissions-policy': 'browsing-topics=(), interest-cohort=()',
  'cross-origin-resource-policy': 'same-origin',
  'cross-origin-opener-policy': 'same-origin',
  'strict-transport-security': 'max-age=63072000; includeSubDomains; preload',
};

const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
};

export function json(obj, status = 200, extraHeaders) {
  const headers = new Headers(JSON_HEADERS);
  if (extraHeaders) for (const [k, v] of Object.entries(extraHeaders)) headers.append(k, v);
  return new Response(JSON.stringify(obj), { status, headers });
}

/** Error response: { error: <code>, message: <human text> [, ...extra] }. */
export function err(status, code, message, extra) {
  return json({ error: code, message: message || code, ...(extra || {}) }, status);
}

export const notFound = () => err(404, 'not_found', 'Not found.');
export const methodNotAllowed = (allow) => json({ error: 'method_not_allowed', message: 'Method not allowed' }, 405, { allow });

/** Re-emit an asset response with the security headers and no-store. */
export function withSecurityHeaders(res, { noStore = true } = {}) {
  const out = new Response(res.body, res);
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) out.headers.set(k, v);
  if (noStore) out.headers.set('cache-control', 'no-store');
  return out;
}

export function redirect(location, status = 302) {
  return new Response(null, { status, headers: { location, 'cache-control': 'no-store', ...SECURITY_HEADERS } });
}

/**
 * Read a request body under a hard byte cap without buffering an attacker-sized
 * payload. Returns a Uint8Array, or null when the stream exceeds `max` (413).
 */
export async function readCappedBody(stream, max) {
  if (!stream) return new Uint8Array(0);
  const reader = stream.getReader();
  const chunks = [];
  let received = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      received += value.byteLength;
      if (received > max) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const out = new Uint8Array(received);
  let offset = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.byteLength; }
  return out;
}

export class HttpError extends Error {
  constructor(status, code, message, extra) {
    super(message || code);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
  toResponse() { return err(this.status, this.code, this.message, this.extra); }
}

/**
 * Parse a JSON request body with the CSRF guards every state-changing call
 * shares: the media type must be application/json (forces a CORS preflight for
 * cross-origin browsers — the API sends no CORS headers), Sec-Fetch-Site must
 * not be cross-site, and the body is read under `max` bytes.
 */
export async function readJsonBody(request, max = 64 * 1024) {
  const ct = (request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
  if (ct !== 'application/json') throw new HttpError(415, 'unsupported_media_type', 'Content-Type must be application/json.');
  assertNotCrossSite(request);
  const cl = Number(request.headers.get('content-length'));
  if (Number.isFinite(cl) && cl > max) throw new HttpError(413, 'too_large', 'Request body is too large.');
  const bytes = await readCappedBody(request.body, max);
  if (bytes === null) throw new HttpError(413, 'too_large', 'Request body is too large.');
  try {
    const v = JSON.parse(new TextDecoder().decode(bytes));
    if (v === null || typeof v !== 'object' || Array.isArray(v)) throw new Error('not an object');
    return v;
  } catch {
    throw new HttpError(400, 'invalid_json', 'Invalid JSON body.');
  }
}

export function assertNotCrossSite(request) {
  if ((request.headers.get('sec-fetch-site') || '').toLowerCase() === 'cross-site') {
    throw new HttpError(403, 'cross_site', 'Cross-site requests are not allowed.');
  }
}

/**
 * State-changing calls without a JSON body (DELETE, POST actions) must carry a
 * custom header — a non-simple request a cross-origin page cannot send without
 * a (failing) preflight.
 */
export function assertIntent(request) {
  assertNotCrossSite(request);
  if ((request.headers.get('x-secbin-intent') || '') !== '1') {
    throw new HttpError(400, 'missing_intent', 'This request requires the "X-Secbin-Intent: 1" header.');
  }
}

// ── cookies ──────────────────────────────────────────────────────────────────

export function getCookie(request, name) {
  const header = request.headers.get('cookie');
  if (!header) return null;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

export function sessionCookie(name, value, maxAgeSec) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.max(0, Math.floor(maxAgeSec))}`;
}

export function clearCookie(name) {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
}

/** Client IP as seen by Cloudflare; a fixed placeholder when absent (tests/dev). */
export function clientIp(request) {
  return request.headers.get('cf-connecting-ip') || '0.0.0.0';
}

export function decodePathSegment(s) {
  try { return decodeURIComponent(s); } catch { return null; }
}
