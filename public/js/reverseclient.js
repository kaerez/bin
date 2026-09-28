// reverseclient.js — the anonymous uploader of a reverse share (docs/REVERSE.md
// §3, §6.2), without the DOM: open the link, check files against its limits,
// start a session (password proof, human check), encrypt and upload each file
// exactly like a Drive file, and end the session. Everything that describes a
// file — its path, type, time and key — leaves this browser only sealed to the
// share's public key, which is in the link's #fragment and never sent.
//
// Every request goes through api.js (`reverseApi`, /api/reverse/<id>/…). The
// uploader is anonymous: those routes read no session, so api.js sends no CSRF
// token with them and never asks /api/private/me, even when a signed-in user's
// cookie is in the same browser (SECURITY.md "CSRF"). The link proof, the
// session grant and the upload tokens stand in for it.

import { reverseApi, ApiError } from './api.js';
import { pubFromFragment, linkProof, passwordProof, openNote, sealUpload, newNodeId, MAX_PATH_BYTES } from './reversekeys.js';
import { randomBytes, utf8, b64urlFromBytes } from './bytes.js';
import { CHUNK, encryptChunk, importFileKey, checkPath } from './files.js';
import { detectMime } from './mime.js';
import { declare, refusedTypes, uncheckableExt, describeType } from './filepolicy.js';

const ID_RE = /^r[A-Za-z0-9_-]{22}$/;
const MAX_SEGMENT_BYTES = 255;

/** The link is not usable (wrong or missing key, unknown id). */
export class LinkError extends Error {
  constructor(message) { super(message); this.name = 'LinkError'; }
}

const aborted = (signal) => signal.reason ?? new DOMException('Upload cancelled.', 'AbortError');

/** "/r/<id>" + "#<key>" → { id, pub } or throws LinkError. */
export function parseLink(pathname, hash) {
  const m = /^\/r\/([^/]+)\/?$/.exec(String(pathname || ''));
  const id = m ? m[1] : '';
  if (!ID_RE.test(id)) throw new LinkError('This is not a valid upload link.');
  const pub = pubFromFragment(hash);
  if (!pub) throw new LinkError('The link is incomplete: its key (the part after “#”) is missing or damaged. Ask for the whole link again.');
  return { id, pub };
}

/** A relative path as dropped or picked → the path to send, or throws with a readable reason. */
export function cleanPath(p) {
  const path = String(p ?? '').replace(/^\/+/, '');
  try { checkPath(path); } catch { throw new Error(`“${path}” is not a file name that can be sent.`); }
  if (utf8(path).length > MAX_PATH_BYTES) throw new Error(`“${path.slice(0, 80)}…” has a path that is too long.`);
  for (const seg of path.split('/')) if (utf8(seg).length > MAX_SEGMENT_BYTES) throw new Error(`“${seg.slice(0, 80)}…” has a name that is too long.`);
  return path;
}

/**
 * Check a list of files ({ path, file }) against the link's limits (the head's
 * `limits`) → { ok: true, count, bytes } or { ok: false, error }. The server
 * checks again; this is so the uploader learns before anything is sent.
 */
export function checkFiles(entries, limits = {}) {
  const files = entries.filter((e) => e && e.file);
  if (!files.length) return { ok: false, error: 'Choose at least one file (empty folders are not sent).' };
  const bytes = files.reduce((n, e) => n + e.file.size, 0);
  try { for (const e of files) cleanPath(e.path); } catch (e) { return { ok: false, error: e.message }; }
  if (limits.filesLeft !== null && limits.filesLeft !== undefined && files.length > limits.filesLeft) {
    return { ok: false, error: limits.filesLeft === 0 ? 'This link does not accept any more files.' : `This link accepts ${limits.filesLeft} more file${limits.filesLeft === 1 ? '' : 's'}; you chose ${files.length}.` };
  }
  if (limits.bytesLeft !== null && limits.bytesLeft !== undefined && bytes > limits.bytesLeft) {
    return { ok: false, error: `These files are too large for this link (${bytes} bytes; ${limits.bytesLeft} bytes left).` };
  }
  if (limits.maxFileBytes !== null && limits.maxFileBytes !== undefined) {
    const big = files.find((e) => e.file.size > limits.maxFileBytes);
    if (big) return { ok: false, error: `“${big.path}” is larger than this link allows for one file (${limits.maxFileBytes} bytes).` };
  }
  const t = limits.types;
  if (t && (t.mode === 'allow' || t.mode === 'block')) {
    const odd = files.find((e) => uncheckableExt(e.path));
    if (odd) return { ok: false, error: `“${odd.path}” has an unusual extension that cannot be checked against the file types this link accepts.` };
    for (const e of files) {
      const d = declare([{ path: e.path, type: e.type || detectMime({ name: e.path, platformType: e.file.type, head: new Uint8Array(0) }) }]);
      const refused = refusedTypes(t.mode, t.rules, d.types);
      if (refused.length) return { ok: false, error: `This link does not accept ${refused.map(describeType).join(', ')} files (“${e.path}”).` };
    }
  }
  return { ok: true, count: files.length, bytes };
}

/**
 * Open the link → a ReverseUpload. Throws LinkError (bad link), or ApiError
 * (410 gone, 423 locked, 429 blocked…).
 */
export async function openLink({ pathname, hash, api = reverseApi } = {}) {
  const { id, pub } = parseLink(pathname, hash);
  const lp = await linkProof(pub);
  let head;
  try {
    head = await api.open(id, lp);
  } catch (e) {
    if (e instanceof ApiError && (e.code === 'bad_link' || e.code === 'not_found')) throw new LinkError('This upload link is not valid. Check that you have the whole link.');
    throw e;
  }
  let note = null;
  if (head.note) {
    try { note = await openNote(pub, id, head.note); } catch { note = null; }
  }
  return new ReverseUpload({ id, pub, linkProof: lp, head, note, api });
}

export class ReverseUpload {
  constructor({ id, pub, linkProof: lp, head, note, api }) {
    Object.assign(this, { id, pub, linkProof: lp, head, note, api, grant: null });
  }

  get limits() { return this.head.limits || {}; }
  get needsPassword() { return !!this.head.password; }

  /**
   * Start the session: the password proof (when the link has a password) and
   * the CAPTCHA grant from the check page (`humanGrant`, when the link has the
   * CAPTCHA; each grant starts one session) or a Turnstile token. A wrong
   * password rejects with ApiError code 'bad_password'.
   */
  async begin({ password = '', turnstile = null, humanGrant = null } = {}) {
    let keyProof = null;
    if (this.head.password) {
      if (!password) throw new ApiError('Enter the password for this link.', 401, 'password_required');
      keyProof = await passwordProof(password, this.head.password.salt, this.head.password.t, this.pub);
    }
    const r = await this.api.begin(this.id, { linkProof: this.linkProof, keyProof, turnstile, humanGrant });
    if (typeof r.grant !== 'string') throw new ApiError('Malformed response from the server.', 502, 'malformed');
    this.grant = r.grant;
    return r;
  }

  /** Encrypt and upload one file (`path` relative, `file` a File/Blob) → its node id. */
  async uploadOne({ path, file, type }, { onProgress, signal } = {}) {
    if (!this.grant) throw new Error('Start the upload first.');
    const clean = cleanPath(path);
    const size = file.size;
    const head = new Uint8Array(await file.slice(0, 64).arrayBuffer());
    const mime = type || detectMime({ name: clean, platformType: file.type, head });
    const node = newNodeId();
    const fk = randomBytes(32);
    const sealedParts = await sealUpload(this.pub, this.id, node, fk, { path: clean, type: mime, mtime: file.lastModified || 0, size });
    const body = { id: node, ...sealedParts, size };
    const t = this.limits.types;
    if (t && (t.mode === 'allow' || t.mode === 'block')) body.types = declare([{ path: clean, type: mime }]).types;
    const init = await this.api.createFile(this.id, this.grant, body, signal);
    const n = Math.ceil(size / CHUNK);
    if (init.id !== node || init.chunks !== n || typeof init.uploadToken !== 'string') throw new ApiError('Malformed response from the server.', 502, 'malformed');
    const token = init.uploadToken;
    try {
      const key = await importFileKey(b64urlFromBytes(fk));
      let done = 0;
      if (onProgress) onProgress(0, size);
      for (let i = 0; i < n; i++) {
        if (signal?.aborted) throw aborted(signal);
        const plain = new Uint8Array(await file.slice(i * CHUNK, Math.min(size, (i + 1) * CHUNK)).arrayBuffer());
        const ct = await encryptChunk(key, i, n, plain);
        try {
          await this.api.putChunk(this.id, node, i, ct, token, signal);
        } catch (e) {
          if ((e instanceof ApiError && e.status < 500) || e?.name === 'AbortError') throw e;
          await this.api.putChunk(this.id, node, i, ct, token, signal); // one retry for transient failures
        }
        done += plain.length;
        if (onProgress) onProgress(done, size);
      }
      if (signal?.aborted) throw aborted(signal);
      // 409 busy: a retried chunk's first write is still being stored; try again shortly.
      for (let k = 0; ; k++) {
        try {
          await this.api.finalize(this.id, this.grant, node, token);
          break;
        } catch (e) {
          if (!(e instanceof ApiError && e.code === 'busy') || k >= 10) throw e;
          await new Promise((r) => setTimeout(r, 500 * (k + 1)));
        }
      }
    } catch (e) {
      this.api.cancel(this.id, this.grant, node, token).catch(() => {}); // give the reservation back now
      throw e;
    }
    return node;
  }

  /**
   * Upload files ({ path, file }) one after another. onProgress(bytesDone,
   * total), onFile(path, index) → { files, bytes } sent.
   */
  async upload(entries, { onProgress, onFile, signal } = {}) {
    const files = entries.filter((e) => e && e.file);
    const total = files.reduce((s, e) => s + e.file.size, 0);
    let before = 0;
    for (const [k, e] of files.entries()) {
      if (signal?.aborted) throw aborted(signal);
      if (onFile) onFile(e.path, k);
      const base = before;
      await this.uploadOne(e, { signal, onProgress: onProgress && ((d) => onProgress(base + d, total)) });
      before += e.file.size;
    }
    if (onProgress) onProgress(total, total);
    return { files: files.length, bytes: total };
  }

  /** End the session (the user's log records how many files and bytes arrived). */
  async done() {
    if (!this.grant) return { files: 0, bytes: 0 };
    const g = this.grant;
    this.grant = null;
    return this.api.done(this.id, g);
  }
}
