// helpers.js — an in-memory mock of the secbin v2 API as a fetch
// implementation, plus an injectable `io` for the command tests.
//
// The mock follows src/routes/{public,private}.js: heads never carry wk/ct;
// opens verify SHA-256(proof) against the stored acc.lh / acc.kh BEFORE they
// release ciphertext or spend a view (403 bad_link / bad_password spend
// nothing); view-limited notes and file shares count views; creation requires
// `authorization: Bearer sbk_…`; file uploads enforce exact chunk sizes and a
// manifest matching the authorized upload; chunks download under a grant;
// errors are JSON { error, message } with real HTTP statuses. "Delete now"
// (POST …/expire) needs both proofs and the sender's opt-in (meta.deletable).
// A share with the CAPTCHA (policy.captcha: 'allow' | 'require' | 'off', as the
// role options; `captcha` on create) serves nothing to the CLI: 403
// captcha_required, as src/routes/public.js answers without a grant.
import { refusedTypes } from '../vendor/filepolicy.js';
import { b64urlFromBytes, randomBytes, sha256Hex, utf8 } from '../vendor/bytes.js';
import { proofHash } from '../vendor/crypto.js';
import { CHUNK, PAD, TAG } from '../vendor/files.js';
import { expireSeconds, isProof, MAX_VIEWS, validateCreate } from '../vendor/format.js';
import { UsageError } from '../src/errors.js';

export const SERVER = 'https://secbin.test.example';
export const KEY = 'sbk_' + b64urlFromBytes(new Uint8Array(32).fill(9));
export const OTHER_KEY = 'sbk_' + b64urlFromBytes(new Uint8Array(32).fill(8));

const token = () => b64urlFromBytes(randomBytes(32));
const now = () => Math.floor(Date.now() / 1000);
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

/**
 * `policy` lets a test play the account's limits: { text: false, files: false,
 * quota: true, maxViews, maxFilesPerShare, maxFileBytes, fileTypeMode,
 * fileTypeRules, maxFolderDepth, openerDelete, urlRules } — urlRules makes the
 * server answer GET /api/private/policy (otherwise it 404s, like an old server).
 */
export function makeServer({ keys = [KEY], policy = {} } = {}) {
  const notes = new Map(); // id → { paste, acc, dth, views, left, label }
  const files = new Map(); // id → { state, uth, dth, padded, chunks, data, views, left, expire, paste, acc, grants, label, init }
  const calls = []; // { method, path, headers, body }

  const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
  const err = (status, error, message = error) => json(status, { error, message });

  const fetchImpl = async (rawUrl, init = {}) => {
    const u = new URL(rawUrl);
    const method = init.method ?? 'GET';
    const h = new Headers(init.headers ?? {});
    calls.push({ method, path: u.pathname, headers: Object.fromEntries(h), body: init.body });

    const auth = () => {
      const a = h.get('authorization');
      if (!a) return err(401, 'unauthenticated', 'Please log in.');
      const m = /^Bearer (sbk_[A-Za-z0-9_-]{43})$/.exec(a);
      if (!m) return err(401, 'invalid_api_key', 'Invalid API key.');
      if (!keys.includes(m[1])) return err(401, 'invalid_api_key', 'Invalid, expired or disabled API key.');
      return null;
    };
    const limitCheck = (kind, views) => {
      if (policy.quota) return err(429, 'quota_exceeded', 'Quota reached: 5 shares per 1d via the API.');
      if (kind === 'text' && policy.text === false) return err(403, 'text_disabled', 'Creating notes is not allowed for this account via the API.');
      if (kind === 'files' && policy.files === false) return err(403, 'files_disabled', 'File sharing is not allowed for this account via the API.');
      if (views !== null && policy.maxViews !== undefined && views > policy.maxViews) {
        return err(403, 'too_many_views', `At most ${policy.maxViews} views are allowed via the API.`);
      }
      return null;
    };
    const readBody = () => {
      try { return JSON.parse(init.body); } catch { return null; }
    };
    // As src/lib/settings.js resolveCaptcha: → true / false, or an error response.
    const captchaFor = (asked) => {
      const mode = policy.captcha ?? 'allow';
      if (asked !== undefined && typeof asked !== 'boolean') return err(400, 'invalid_captcha', 'captcha must be true or false.');
      if (mode === 'require') return true;
      if (mode === 'off') return asked === true ? err(403, 'captcha_disabled', 'CAPTCHA is disabled for shares of your role.') : false;
      return asked ?? policy.captchaDefault === true;
    };

    if (u.pathname === '/api/private/policy' && policy.urlRules !== undefined) {
      const denied = auth();
      if (denied) return denied;
      if (policy.noPolicyScope) return err(403, 'scope_denied', 'This API key does not have the "policy" scope.');
      return json(200, { url: true, urlRules: policy.urlRules });
    }

    // ── creation (API key) ──────────────────────────────────────────────────
    if (u.pathname === '/api/private/paste') {
      if (method !== 'POST') return err(405, 'method_not_allowed');
      const denied = auth();
      if (denied) return denied;
      const body = readBody();
      let clean;
      try { clean = validateCreate(body?.paste); } catch (e) { return err(400, 'invalid_format', e.message); }
      if (clean.adata.fmt === 'files') return err(400, 'invalid_format', 'File manifests are created through /api/private/file.');
      const bar = clean.adata.bar;
      const views = bar ? (clean.meta.views ?? 1) : null;
      const limited = limitCheck('text', views);
      if (limited) return limited;
      if (clean.meta.deletable === true && policy.openerDelete === false) return err(403, 'opener_delete_disabled', 'Recipient delete is not allowed.');
      const captcha = captchaFor(body.captcha);
      if (captcha instanceof Response) return captcha;
      const id = (bar ? 'b' : 'k') + b64urlFromBytes(randomBytes(16));
      const deletetoken = token();
      const created = now();
      const expires = created + expireSeconds(clean.meta.expire);
      const meta = { expire: clean.meta.expire, created, expires };
      if (bar) meta.views = views;
      if (clean.meta.deletable === true) meta.deletable = true;
      notes.set(id, {
        paste: { v: 2, ct: clean.ct, wk: clean.wk, adata: clean.adata, meta },
        acc: clean.acc, dth: await sha256Hex(utf8(deletetoken)), views, left: views, label: body.label, captcha,
      });
      return json(201, { id, deletetoken, expires, captcha });
    }

    if (u.pathname === '/api/private/file') {
      if (method !== 'POST') return err(405, 'method_not_allowed');
      const denied = auth();
      if (denied) return denied;
      const body = readBody() ?? {};
      const { views, expire, padded } = body;
      if (views !== null && !(Number.isSafeInteger(views) && views >= 1 && views <= MAX_VIEWS)) return err(400, 'invalid_views', 'bad views');
      if (expireSeconds(expire) === null) return err(400, 'invalid_expire', 'Invalid expiry.');
      if (!Number.isSafeInteger(padded) || padded < PAD || padded % PAD !== 0) return err(400, 'invalid_size', 'padded must be a positive multiple of 64 KiB.');
      const limited = limitCheck('files', views);
      if (limited) return limited;
      if (policy.maxFilesPerShare !== undefined && !(body.files <= policy.maxFilesPerShare)) return err(403, 'too_many_files', `At most ${policy.maxFilesPerShare} files per share via the API.`);
      if (policy.maxFileBytes !== undefined && !(body.maxFile <= policy.maxFileBytes)) return err(413, 'file_too_large', `Each file may be at most ${policy.maxFileBytes} bytes via the API.`);
      const typed = policy.fileTypeMode === 'allow' || policy.fileTypeMode === 'block';
      const deep = policy.maxFolderDepth !== undefined;
      if ((typed && body.types === undefined) || (deep && body.depth === undefined)) {
        return json(400, { error: 'declaration_required', message: 'declare', policy: { mode: policy.fileTypeMode ?? 'any', rules: typed ? policy.fileTypeRules : [], maxFolderDepth: deep ? policy.maxFolderDepth : null } });
      }
      if (typed && refusedTypes(policy.fileTypeMode, policy.fileTypeRules, body.types).length) return err(403, 'file_type_not_allowed', 'refused');
      if (deep && !(body.depth <= policy.maxFolderDepth)) return err(403, 'folder_too_deep', 'too deep');
      if (body.deletable === true && policy.openerDelete === false) return err(403, 'opener_delete_disabled', 'Recipient delete is not allowed.');
      const captcha = captchaFor(body.captcha);
      if (captcha instanceof Response) return captcha;
      const id = 'f' + b64urlFromBytes(randomBytes(16));
      const uploadtoken = token();
      const deletetoken = token();
      const chunks = Math.ceil(padded / CHUNK);
      files.set(id, {
        state: 'pending', uth: uploadtoken, dth: deletetoken, padded, chunks, data: [], views, left: views,
        expire, grants: new Set(), init: body, captcha,
      });
      return json(201, { id, uploadtoken, deletetoken, chunks, captcha });
    }

    const up = /^\/api\/private\/file\/([^/]+)\/(chunk|finalize)(?:\/(\d+))?$/.exec(u.pathname);
    if (up) {
      const denied = auth();
      if (denied) return denied;
      const rec = files.get(up[1]);
      if (!rec || rec.state !== 'pending') return err(410, 'gone', 'This upload has expired or was already finalized.');
      if (h.get('x-upload-token') !== rec.uth) return err(403, 'bad_token', 'Missing or invalid X-Upload-Token.');
      if (up[2] === 'chunk') {
        if (method !== 'PUT') return err(405, 'method_not_allowed');
        if (h.get('content-type') !== 'application/octet-stream') return err(415, 'unsupported_media_type');
        const i = Number(up[3]);
        if (!(i >= 0 && i < rec.chunks)) return err(400, 'bad_index', 'No such chunk index.');
        const bytes = new Uint8Array(init.body);
        const expected = Math.min(CHUNK, rec.padded - i * CHUNK) + TAG;
        if (bytes.length !== expected) return err(400, 'bad_size', `Chunk ${i} must be exactly ${expected} bytes.`);
        rec.data[i] = bytes.slice();
        return json(200, { ok: true });
      }
      if (method !== 'POST') return err(405, 'method_not_allowed');
      const body = readBody();
      let clean;
      try { clean = validateCreate(body?.paste); } catch (e) { return err(400, 'invalid_format', e.message); }
      if (clean.adata.fmt !== 'files') return err(400, 'invalid_format', 'The manifest must be a fmt:"files" paste.');
      if (clean.adata.bar !== (rec.views !== null) || clean.meta.expire !== rec.expire || (clean.meta.views ?? null) !== rec.views
          || (clean.meta.deletable === true) !== (rec.init.deletable === true)) {
        return err(400, 'invalid_format', 'The manifest’s view limit and expiry must match the upload.');
      }
      for (let i = 0; i < rec.chunks; i++) if (!rec.data[i]) return err(409, 'incomplete', `Chunk ${i} has not been uploaded.`);
      const created = now();
      const expires = created + expireSeconds(rec.expire);
      const meta = { expire: rec.expire, created, expires };
      if (rec.views !== null) meta.views = rec.views;
      if (rec.init.deletable === true) meta.deletable = true;
      Object.assign(rec, { state: 'active', acc: clean.acc, label: body.label, paste: { v: 2, ct: clean.ct, wk: clean.wk, adata: clean.adata, meta } });
      return json(200, { ok: true, id: up[1], expires });
    }

    // ── the key user's shares ("read" / "manage"; policy.noRead / noManage drop a scope) ──
    if (u.pathname === '/api/private/shares') {
      if (method !== 'GET') return err(405, 'method_not_allowed');
      const denied = auth();
      if (denied) return denied;
      if (policy.noRead) return err(403, 'scope_denied', 'This API key does not have the "read" scope.');
      const all = [...notes.entries(), ...[...files.entries()].filter(([, f]) => f.state === 'active' || f.state === 'revoked')]
        .map(([id, r]) => ({ id, kind: id[0] === 'f' ? 'files' : 'text', label: r.label ?? '', created: 0, expires: r.noExpiry ? null : r.paste?.meta.expires ?? 0,
          views_total: r.views ?? null, left: r.revoked ? null : r.left ?? null, opens: 0, status: r.revoked ? 'revoked' : 'active', locked: r.locked ? 1 : 0 }))
        .filter((r) => !u.searchParams.get('status') || r.status === u.searchParams.get('status'));
      const off = Number(u.searchParams.get('offset')) || 0;
      return json(200, { rows: all.slice(off, off + (policy.pageSize ?? 50)), total: all.length });
    }
    // One share (GET, "read"), its receipts (GET …/opens, "read"; rec.receipts), label / extend (PATCH, "manage").
    const so = /^\/api\/private\/shares\/([^/]+)(\/opens)?$/.exec(u.pathname);
    if (so) {
      const denied = auth();
      if (denied) return denied;
      const rec = notes.get(so[1]) ?? files.get(so[1]);
      const need = method === 'GET' ? 'read' : 'manage';
      if ((need === 'read' && policy.noRead) || (need === 'manage' && policy.noManage)) return err(403, 'scope_denied', `This API key does not have the "${need}" scope.`);
      if (!rec) return err(404, 'not_found', 'Share not found.');
      if (so[2]) {
        if (method !== 'GET') return err(405, 'method_not_allowed');
        const rows = rec.receipts ?? [];
        return json(200, { total: rows.length, fields: policy.receiptFields ?? [], rows });
      }
      const row = () => ({ id: so[1], kind: so[1][0] === 'f' ? 'files' : 'text', label: rec.label ?? '', created: rec.paste?.meta.created ?? 0,
        expires: rec.noExpiry ? null : rec.paste?.meta.expires ?? 0, views_total: rec.views ?? null, left: rec.left ?? null, opens: (rec.receipts ?? []).length,
        status: rec.revoked ? 'revoked' : 'active', locked: rec.locked ? 1 : 0 });
      if (method === 'GET') return json(200, { share: row() });
      if (method !== 'PATCH') return err(405, 'method_not_allowed');
      if (h.get('content-type') !== 'application/json') return err(415, 'unsupported_media_type');
      if (rec.locked) return err(423, 'share_locked', 'The administrator has locked this share; it cannot be changed.');
      const body = readBody() ?? {};
      if (body.label === undefined && body.views === undefined && body.expires === undefined) return err(400, 'invalid', 'Nothing to change.');
      if (body.label !== undefined) {
        if (typeof body.label !== 'string' || body.label.length > 100) return err(400, 'invalid_label', 'Labels are up to 100 characters.');
        rec.label = body.label;
      }
      if (body.views !== undefined) {
        if (rec.views === null || rec.views === undefined) return err(400, 'invalid', 'This note already has unlimited views.');
        if (body.views !== null && !(Number.isSafeInteger(body.views) && body.views >= rec.views)) return err(400, 'invalid', 'Views can only grow.');
        if (body.views === null && policy.allowUnlimitedViews === false) return err(403, 'unlimited_views_disabled', 'Unlimited views are not allowed for this account via the API.');
        rec.left = body.views === null ? null : rec.left + (body.views - rec.views);
        rec.views = body.views;
      }
      if (body.expires !== undefined) {
        if (!Number.isSafeInteger(body.expires) || body.expires <= now()) return err(400, 'invalid_expiry', 'Expiry must be in the future and within 365 days.');
        if (rec.paste) rec.paste.meta.expires = body.expires;
        else rec.expiresAt = body.expires;
      }
      return json(200, { ok: true });
    }
    const sr = /^\/api\/private\/shares\/([^/]+)\/revoke$/.exec(u.pathname);
    if (sr) {
      if (method !== 'POST') return err(405, 'method_not_allowed');
      const denied = auth();
      if (denied) return denied;
      if (policy.noManage) return err(403, 'scope_denied', 'This API key does not have the "manage" scope.');
      if (h.get('x-secbin-intent') !== '1') return err(400, 'missing_intent', 'This request requires the "X-Secbin-Intent: 1" header.');
      const rec = notes.get(sr[1]) ?? files.get(sr[1]);
      if (!rec) return err(404, 'not_found', 'Share not found.');
      if (rec.locked) return err(423, 'share_locked', 'The administrator has locked this share; it cannot be changed.');
      rec.revoked = true;
      if (notes.has(sr[1])) notes.delete(sr[1]);
      return json(200, { ok: true });
    }

    // ── public share API ────────────────────────────────────────────────────
    const m = /^\/api\/(paste|file)\/([^/]+)(?:\/(open|chunk|expire)(?:\/(\d+))?)?$/.exec(u.pathname);
    if (!m) return err(404, 'not_found', 'Not found.');
    const [, kind, id, action, idx] = m;
    const isFile = id[0] === 'f';
    if ((kind === 'file') !== isFile) return err(404, 'not_found', 'This share does not exist.');
    const rec = isFile ? files.get(id) : notes.get(id);
    const missing = () => (id[0] === 'k' ? err(404, 'not_found', 'This share does not exist.') : err(410, 'gone', 'This share does not exist, has expired, or has no views left.'));
    const metaOut = (r) => (r.paste.adata.bar ? { ...r.paste.meta, views: r.views, left: r.left } : { ...r.paste.meta });
    // The CLI holds no CAPTCHA grant: a protected share answers nothing (before anything is looked at or spent).
    if (rec && rec.captcha === true && method !== 'DELETE') return err(403, 'captcha_required', 'This share requires a CAPTCHA; open it in a browser.');

    if (!action) {
      if (method === 'GET') {
        if (!rec || (isFile && rec.state !== 'active')) return missing();
        return json(200, { v: rec.paste.v, adata: rec.paste.adata, meta: metaOut(rec) });
      }
      if (method === 'DELETE') {
        const t = h.get('x-delete-token');
        if (!t) return err(400, 'missing_token', 'Missing deletion token.');
        if (!rec) return err(404, 'not_found', 'This share does not exist.');
        const ok = isFile ? t === rec.dth : (await sha256Hex(utf8(t))) === rec.dth;
        if (!ok) return err(403, 'bad_token', 'Wrong deletion token. The share was not deleted.');
        (isFile ? files : notes).delete(id);
        return json(200, { status: 'deleted', id });
      }
      return err(405, 'method_not_allowed');
    }

    if (action === 'open') {
      if (method !== 'POST') return err(405, 'method_not_allowed');
      const lp = h.get('x-link-proof');
      const kp = h.get('x-key-proof');
      if (!isProof(lp) || !isProof(kp)) return err(400, 'missing_proof', 'Opening a share requires the X-Link-Proof and X-Key-Proof headers.');
      if (!rec || (isFile && rec.state !== 'active')) return missing();
      if ((await proofHash(lp)) !== rec.acc.lh) return err(403, 'bad_link', 'The link is incomplete or corrupted.');
      if ((await proofHash(kp)) !== rec.acc.kh) return err(403, 'bad_password', 'Wrong password.');
      if (rec.left !== null) {
        rec.left -= 1;
        if (rec.left <= 0) {
          rec.left = 0;
          if (isFile) rec.state = 'closed';
          else notes.delete(id);
        }
      }
      const p = rec.paste;
      const paste = { v: p.v, ct: p.ct, wk: p.wk, adata: p.adata, meta: metaOut(rec) };
      if (!isFile) return json(200, paste);
      const grant = token();
      rec.grants.add(grant);
      return json(200, { paste, grant, grantExpires: now() + 3600, chunks: rec.chunks, padded: rec.padded });
    }

    if (action === 'expire' && idx === undefined) {
      if (method !== 'POST') return err(405, 'method_not_allowed');
      const lp = h.get('x-link-proof');
      const kp = h.get('x-key-proof');
      if (!isProof(lp) || !isProof(kp)) return err(400, 'missing_proof', 'Missing proofs.');
      if (!rec || (isFile && rec.state !== 'active')) return missing();
      if ((await proofHash(lp)) !== rec.acc.lh) return err(403, 'bad_link', 'The link is incomplete or corrupted.');
      if ((await proofHash(kp)) !== rec.acc.kh) return err(403, 'bad_password', 'Wrong password.');
      if (rec.paste.meta.deletable !== true) return err(403, 'not_allowed', 'The sender did not allow recipients to delete this share.');
      (isFile ? files : notes).delete(id);
      return json(200, { status: 'deleted', id });
    }

    if (action === 'chunk' && isFile && idx !== undefined) {
      if (method !== 'GET') return err(405, 'method_not_allowed');
      const g = h.get('x-download-grant') ?? '';
      if (!TOKEN_RE.test(g) || !rec || !rec.grants.has(g)) return err(403, 'bad_grant', 'The download window has expired — open the link again.');
      const bytes = rec.data[Number(idx)];
      if (!bytes) return err(404, 'not_found', 'No such chunk.');
      return new Response(bytes, { status: 200, headers: { 'content-type': 'application/octet-stream' } });
    }
    return err(404, 'not_found', 'Not found.');
  };

  const opens = () => calls.filter((c) => c.method === 'POST' && c.path.endsWith('/open'));
  const chunkGets = () => calls.filter((c) => c.method === 'GET' && /\/chunk\/\d+$/.test(c.path));
  return { fetchImpl, calls, notes, files, opens, chunkGets };
}

export const scripted = (answers) => () => Promise.resolve(answers.shift());

export function makeIo({
  stdin = '', tty = false, stderrIsTTY = false, env = {}, server,
  promptHidden, promptLine, promptMultiline, confirm, readKey, copy,
} = {}) {
  const out = [];
  const err = [];
  const io = {
    stdout: (s) => out.push(s),
    stderr: (s) => err.push(s),
    env: { SECBIN_SERVER: SERVER, SECBIN_API_KEY: KEY, ...env },
    fetch: server.fetchImpl,
    stdinIsTTY: tty,
    stderrIsTTY,
    columns: () => 80,
    rows: () => 40,
    readStdin: async () => Buffer.from(stdin, 'utf8'),
    promptHidden: promptHidden ?? (() => Promise.reject(new UsageError('no prompt available in test'))),
    promptLine: promptLine ?? (() => Promise.reject(new UsageError('no line prompt in test'))),
    promptMultiline: promptMultiline ?? (() => Promise.reject(new UsageError('no multiline prompt in test'))),
    confirm: confirm ?? (() => Promise.resolve(false)),
    readKey: readKey ?? (() => Promise.reject(new UsageError('no key reader in test'))),
    copy: copy ?? (() => Promise.reject(new UsageError('no clipboard in test'))),
  };
  return { io, out, err, text: { out: () => out.join(''), err: () => err.join('') } };
}
