// client.js — HTTP client for the secbin v2 API. A port of public/js/api.js:
// same endpoints, same real-HTTP-status semantics, and every secret (access
// proofs, delete / upload tokens, download grants, the API key) travels only in
// a request header — never in a URL, where it could land in server/proxy logs.
//
// Differences from the browser client: an absolute, configurable base URL (the
// browser fetches same-origin), an injectable fetch for tests, API-key (Bearer)
// auth instead of the session cookie, per-request timeouts, and redirects are
// refused outright. The `cache: 'no-store'` hint is dropped — Node's fetch has
// no HTTP cache.
import { MAX_CHUNK_CT } from '../vendor/files.js';

export class ApiError extends Error {
  constructor(message, status, code = null) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

async function readJson(res) {
  try { return await res.json(); } catch { return null; }
}

// Server-supplied strings are echoed to the user's terminal, so a hostile or
// compromised server must not be able to steer it: strip every C0/C1 control
// character (including ESC — no ANSI/OSC injection) and cap the length. The
// machine-readable error code is only kept when it has the expected shape.
// eslint-disable-next-line no-control-regex
const clean = (s) => s.replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ').trim().slice(0, 300);

function toApiError(data, status, fallback) {
  const d = isPlainObject(data) ? data : {};
  const code = typeof d.error === 'string' && /^[a-z0-9_]{1,64}$/.test(d.error) ? d.error : null;
  const message = typeof d.message === 'string' && clean(d.message) ? clean(d.message)
    : typeof d.error === 'string' && clean(d.error) ? clean(d.error)
      : fallback;
  return new ApiError(message, status, code);
}

const malformed = () => new ApiError('Malformed response from the server.', 502, 'malformed');

// Node's fetch has no default timeout: without one, an unresponsive server
// hangs the CLI forever (and a view-spending open would leave the user unsure
// whether the share survived). Chunk transfers move up to 8 MiB each, so they
// get a longer budget than the small JSON calls.
const TIMEOUT_MS = 30_000;
const TRANSFER_TIMEOUT_MS = 300_000;

export class Client {
  /**
   * @param {string} server   validated origin (url.js normalizeServer)
   * @param {Function} fetchImpl
   * @param {{apiKey?: string}} opts  API key for the creation endpoints only
   */
  constructor(server, fetchImpl = globalThis.fetch, { apiKey } = {}) {
    this.server = server;
    this.fetchImpl = fetchImpl;
    this.apiKey = apiKey;
  }

  async fetch(url, init, timeout = TIMEOUT_MS) {
    try {
      // redirect: 'error' — the API never redirects, and following one would
      // replay our custom secret headers (x-delete-token, x-upload-token,
      // access proofs) to wherever the redirect points.
      return await this.fetchImpl(url, { ...init, redirect: 'error', signal: AbortSignal.timeout(timeout) });
    } catch (e) {
      if (e && (e.name === 'TimeoutError' || e.name === 'AbortError')) {
        throw new ApiError(`No response from the server after ${timeout / 1000}s.`, 0);
      }
      // Node buries the useful part ("ECONNREFUSED", "ENOTFOUND", TLS errors,
      // "unexpected redirect") in e.cause and surfaces only "fetch failed" —
      // name the host and the real reason instead.
      if (e && e.name === 'TypeError') {
        const why = e.cause?.code ?? e.cause?.message ?? e.message;
        let host = '';
        try { host = ` ${new URL(url).host}`; } catch { /* keep the bare message */ }
        throw new ApiError(`cannot reach the server${host}: ${clean(String(why))}`, 0);
      }
      throw e;
    }
  }

  /** JSON request → parsed object (shape-checked by the caller). */
  async request(path, { method = 'GET', headers = {}, body, auth = false, fallback = 'Request failed.' } = {}) {
    const h = { ...headers };
    if (body !== undefined) h['content-type'] = 'application/json';
    if (auth && this.apiKey) h.authorization = `Bearer ${this.apiKey}`;
    const res = await this.fetch(`${this.server}${path}`, {
      method, headers: h, body: body === undefined ? undefined : JSON.stringify(body),
    });
    const data = await readJson(res);
    if (!res.ok) throw toApiError(data, res.status, fallback);
    if (!isPlainObject(data)) throw malformed();
    return data;
  }

  // ── public share API ───────────────────────────────────────────────────────

  /** The non-secret head `{v, adata, meta}` of a note or file share. Never spends a view. */
  head(kind, id) {
    return this.request(`/api/${kind}/${encodeURIComponent(id)}`, { fallback: 'Not found.' });
  }

  /**
   * Open a share with its access proofs — the only request that returns
   * ciphertext, and (for view-limited shares) the one that spends a view. The
   * server checks both proofs first: a wrong link or password gets 403 and
   * spends nothing.
   */
  open(kind, id, { linkProof, keyProof }) {
    return this.request(`/api/${kind}/${encodeURIComponent(id)}/open`, {
      method: 'POST',
      headers: { 'x-link-proof': linkProof, 'x-key-proof': keyProof },
      fallback: 'Could not open the share.',
    });
  }

  /** One encrypted chunk of a file share under a download grant (bounded read). */
  async chunk(id, i, grant) {
    const res = await this.fetch(`${this.server}/api/file/${encodeURIComponent(id)}/chunk/${i}`, {
      headers: { 'x-download-grant': grant },
    }, TRANSFER_TIMEOUT_MS);
    if (!res.ok) throw toApiError(await readJson(res), res.status, 'Download failed.');
    return readCapped(res, MAX_CHUNK_CT);
  }

  /** Delete with the delete token (header, never URL). */
  deleteShare(kind, id, token) {
    return this.request(`/api/${kind}/${encodeURIComponent(id)}`, {
      method: 'DELETE', headers: { 'x-delete-token': token }, fallback: 'Delete failed.',
    });
  }

  // ── creation (API key) ─────────────────────────────────────────────────────

  /** Create a note. `paste` is encryptPaste().body. Returns { id, deletetoken, expires }. */
  async createNote(paste, label) {
    const d = await this.request('/api/private/paste', { method: 'POST', auth: true, body: { paste, label } });
    if (typeof d.id !== 'string' || typeof d.deletetoken !== 'string' || !TOKEN_RE.test(d.deletetoken)) throw malformed();
    return d;
  }

  /** Authorize a file upload. Returns { id, uploadtoken, deletetoken, chunks }. */
  async initFile(body) {
    const d = await this.request('/api/private/file', { method: 'POST', auth: true, body });
    if (typeof d.id !== 'string' || !TOKEN_RE.test(d.uploadtoken ?? '') || !TOKEN_RE.test(d.deletetoken ?? '')
        || !Number.isSafeInteger(d.chunks)) throw malformed();
    return d;
  }

  /** Upload one encrypted chunk (exact size enforced by the server). */
  async putChunk(id, i, bytes, uploadToken) {
    const headers = { 'content-type': 'application/octet-stream', 'x-upload-token': uploadToken };
    if (this.apiKey) headers.authorization = `Bearer ${this.apiKey}`;
    const res = await this.fetch(`${this.server}/api/private/file/${encodeURIComponent(id)}/chunk/${i}`, {
      method: 'PUT', headers, body: bytes,
    }, TRANSFER_TIMEOUT_MS);
    const data = await readJson(res);
    if (!res.ok) throw toApiError(data, res.status, 'Upload failed.');
    return data;
  }

  /** Activate the upload with its encrypted manifest paste. */
  finalizeFile(id, uploadToken, paste, label) {
    return this.request(`/api/private/file/${encodeURIComponent(id)}/finalize`, {
      method: 'POST', auth: true, headers: { 'x-upload-token': uploadToken }, body: { paste, label },
    });
  }
}

/**
 * Read a response body under a hard byte cap, so a hostile server cannot make
 * the CLI buffer an arbitrarily large "chunk" (the real maximum is CHUNK + tag).
 */
async function readCapped(res, max) {
  if (!res.body) return new Uint8Array(await res.arrayBuffer());
  const reader = res.body.getReader();
  const parts = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    n += value.byteLength;
    if (n > max) {
      await reader.cancel().catch(() => {});
      throw malformed();
    }
    parts.push(value);
  }
  const out = new Uint8Array(n);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.byteLength; }
  return out;
}
