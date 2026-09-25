// private.js — /api/private/*: everything that needs an account. Share
// creation (notes + file uploads) accepts a session or an API key; the account,
// "My shares" and admin surfaces are session-only.

import { json, err, HttpError, readJsonBody, readCappedBody, assertIntent, assertNotCrossSite, decodePathSegment, methodNotAllowed } from '../lib/http.js';
import { authenticate, issueSession, actorId, logoutCookie } from '../lib/auth.js';
import { directory, cachedSettings, ipContext, recordFailure } from '../lib/guard.js';
import { genId, parseId, genDeleteToken, genToken, genApiKey, hashToken } from '../lib/ids.js';
import { ttlSeconds, MAX_BODY, MAX_BURN_RECORD, kvExists, kvPut, kvGet, kvDelete, burnStub, fileStub } from '../lib/store.js';
import { validateCreate, FormatError, MAX_CT_B64, expireSeconds, MAX_VIEWS, MAX_TTL } from '../../public/js/format.js';
import { MAX_CHUNK_CT, HARD_MAX_SHARE_BYTES, PAD } from '../../public/js/files.js';
import { r2Key } from '../fileshare-do.js';
import { verifierFrom } from './auth.js';
import { handleAdmin } from './admin.js';
import { binding } from '../lib/config.js';

const now = () => Math.floor(Date.now() / 1000);
const EXTRA_KEYS = ['max', 'quota', 'until', 'policy', 'refused'];
const fromDir = (r) => {
  const extra = {};
  for (const k of EXTRA_KEYS) if (r[k] !== undefined) extra[k] = r[k];
  return err(r.status, r.error, r.message, Object.keys(extra).length ? extra : undefined);
};

/** Attach a sliding-session cookie refresh to any JSON response. */
function withAuth(a, res) {
  if (a.setCookie) res.headers.append('set-cookie', a.setCookie);
  return res;
}

function parseCreatePaste(body) {
  if (!body.paste || typeof body.paste !== 'object') throw new HttpError(400, 'invalid', 'Missing "paste".');
  if (typeof body.paste.ct === 'string' && body.paste.ct.length > MAX_CT_B64) throw new HttpError(413, 'too_large', 'The note is too large.');
  try {
    return validateCreate(body.paste);
  } catch (e) {
    if (e instanceof FormatError) throw new HttpError(400, 'invalid_format', e.message);
    throw e;
  }
}

export async function handlePrivate(request, env, url, ctx) {
  const p = url.pathname;

  if (p.startsWith('/api/private/admin/') || p === '/api/private/admin') return handleAdmin(request, env, url, ctx);

  // ── share creation (session or API key) ────────────────────────────────────
  if (p === '/api/private/paste') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const a = await authenticate(request, env, { allowApiKey: true });
    return withAuth(a, await createNote(request, env, a));
  }
  if (p === '/api/private/file') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const a = await authenticate(request, env, { allowApiKey: true });
    return withAuth(a, await initFile(request, env, a));
  }
  const fm = p.match(/^\/api\/private\/file\/([^/]+)\/(chunk|finalize)(?:\/(\d{1,6}))?$/);
  if (fm) {
    const a = await authenticate(request, env, { allowApiKey: true });
    const id = decodePathSegment(fm[1]);
    const info = id && parseId(id);
    if (!info || !info.file) return err(404, 'not_found', 'Not found.');
    if (fm[2] === 'chunk' && fm[3] !== undefined) {
      if (request.method !== 'PUT') return methodNotAllowed('PUT');
      return withAuth(a, await putChunk(request, env, a, id, Number(fm[3])));
    }
    if (fm[2] === 'finalize' && fm[3] === undefined) {
      if (request.method !== 'POST') return methodNotAllowed('POST');
      return withAuth(a, await finalizeFile(request, env, a, id));
    }
    return err(404, 'not_found', 'Not found.');
  }

  // ── session-only surfaces ─────────────────────────────────────────────────
  const a = await authenticate(request, env);
  const dir = directory(env);

  if (p === '/api/private/me') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    const me = await dir.me(a.user.id, { impersonating: !!a.actor });
    return withAuth(a, json({ ...me, impersonatedBy: a.actor ? a.actor.username : null }));
  }

  if (p === '/api/private/me/password') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    if (a.actor) return err(403, 'impersonating', 'Use the admin panel to reset this user’s password.');
    const g = await ipContext(env, request);
    const body = await readJsonBody(request);
    const current = await verifierFrom(body.current);
    const next = await verifierFrom(body.proof);
    if (!current || !next) return err(400, 'invalid_credential', 'Invalid password proof.');
    const r = await dir.changePassword(a.user.id, { current, salt: body.salt, t: body.t, verifier: next, lockoutOff: g.off.all });
    if (!r.ok) {
      // Wrong current passwords also count against the caller's network, so a
      // thief's IP gets blocked from logging in again.
      if (r.error === 'wrong_password' || r.error === 'session_revoked') await recordFailure(env, g, 'login');
      const res = fromDir(r);
      if (r.error === 'session_revoked') res.headers.append('set-cookie', logoutCookie());
      return res;
    }
    // The session version moved on (all other sessions end); keep this device signed in.
    const { cookie } = await issueSession(env, { uid: a.user.id, ver: r.ver, settings: await sessionSettings(env) });
    return json({ ok: true }, 200, { 'set-cookie': cookie });
  }

  if (p === '/api/private/me/activity') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    const before = Number(url.searchParams.get('before')) || null;
    return withAuth(a, json({ rows: await dir.activity(a.user.id, { before, limit: 50 }) }));
  }

  if (p === '/api/private/me/keys') {
    if (request.method === 'GET') return withAuth(a, json({ keys: await dir.listKeys(a.user.id) }));
    if (request.method === 'POST') {
      if (a.actor) return err(403, 'impersonating', 'API keys cannot be created while impersonating.');
      const body = await readJsonBody(request);
      const key = genApiKey();
      const expires = body.expiresInSec === undefined || body.expiresInSec === null
        ? null
        : Number.isSafeInteger(body.expiresInSec) && body.expiresInSec >= 3600 && body.expiresInSec <= MAX_TTL ? now() + body.expiresInSec : -1;
      if (expires === -1) return err(400, 'invalid_expiry', 'Key lifetime must be between 1 hour and 365 days.');
      const r = await dir.createKey(a.user.id, { name: body.name, hash: await hashToken(key), expires });
      if (!r.ok) return fromDir(r);
      return json({ ok: true, id: r.id, key }, 201);
    }
    return methodNotAllowed('GET, POST');
  }
  const km = p.match(/^\/api\/private\/me\/keys\/([A-Za-z0-9_-]{16})$/);
  if (km) {
    if (request.method !== 'DELETE') return methodNotAllowed('DELETE');
    assertIntent(request);
    const r = await dir.revokeKey(a.user.id, km[1], actorId(a));
    return r.ok ? json({ ok: true }) : fromDir(r);
  }

  if (p === '/api/private/shares') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    return withAuth(a, json(await listShares(env, a, url)));
  }
  const sm = p.match(/^\/api\/private\/shares\/([^/]+)(\/revoke)?$/);
  if (sm) {
    const id = decodePathSegment(sm[1]);
    const info = id && parseId(id);
    if (!info) return err(404, 'not_found', 'Share not found.');
    if (sm[2]) {
      if (request.method !== 'POST') return methodNotAllowed('POST');
      assertIntent(request);
      return revokeShare(env, a, id, info);
    }
    if (request.method !== 'PATCH') return methodNotAllowed('PATCH');
    return updateShare(request, env, a, id, info);
  }

  return err(404, 'not_found', 'Not found.');
}

async function sessionSettings(env) {
  const s = await cachedSettings(env);
  return { idleSec: s['session.idleSec'], absSec: s['session.absSec'] };
}

// ── notes ──────────────────────────────────────────────────────────────────
async function createNote(request, env, a) {
  const body = await readJsonBody(request, MAX_BODY);
  const clean = parseCreatePaste(body);
  if (clean.adata.fmt === 'files') return err(400, 'invalid_format', 'File manifests are created through /api/private/file.');
  const bar = clean.adata.bar;
  const views = bar ? (clean.meta.views ?? 1) : null;
  const ttl = ttlSeconds(clean.meta.expire);
  const dir = directory(env);
  const auth = await dir.authorizeCreate(a.user.id, a.channel, { kind: 'text', views, expireSec: ttl });
  if (!auth.ok) return fromDir(auth);

  const created = now();
  const expires = created + ttl;
  const meta = { expire: clean.meta.expire, created, expires };
  if (bar) meta.views = views;
  const paste = { v: clean.v, ct: clean.ct, wk: clean.wk, adata: clean.adata, meta };
  const deleteToken = genDeleteToken();
  const record = { paste, dth: await hashToken(deleteToken), acc: clean.acc };

  if (bar && JSON.stringify({ ...record, exp: 0, views, left: views }).length > MAX_BURN_RECORD) {
    await dir.refund(a.user.id, auth.refund);
    return err(413, 'too_large', 'The note is too large for a view-limited share.');
  }
  let id;
  try {
    for (let attempt = 0; ; attempt++) {
      id = genId(bar ? 'b' : 'k');
      if (bar) {
        if (await burnStub(env, id).create(record, ttl, views)) break;
      } else if (!(await kvExists(env, id))) {
        await kvPut(env, id, record, ttl);
        break;
      }
      if (attempt >= 4) throw new Error('id allocation failed');
    }
  } catch (e) {
    await dir.refund(a.user.id, auth.refund);
    throw e;
  }
  await dir.recordShare({ id, uid: a.user.id, kind: 'text', label: body.label, created, expires, views }, actorId(a));
  return json({ id, deletetoken: deleteToken, expires }, 201);
}

// ── file uploads ───────────────────────────────────────────────────────────
async function initFile(request, env, a) {
  binding(env, 'FILES'); // fail before charging quota if R2 is not configured
  const body = await readJsonBody(request);
  const { views, expire, padded } = body;
  if (views !== null && !(Number.isSafeInteger(views) && views >= 1 && views <= MAX_VIEWS)) return err(400, 'invalid_views', `views must be 1–${MAX_VIEWS} or null (unlimited).`);
  const ttl = expireSeconds(expire);
  if (ttl === null) return err(400, 'invalid_expire', 'Invalid expiry.');
  if (!Number.isSafeInteger(padded) || padded < PAD || padded % PAD !== 0 || padded > HARD_MAX_SHARE_BYTES + PAD) {
    return err(400, 'invalid_size', 'padded must be a positive multiple of 64 KiB.');
  }
  const settings = await cachedSettings(env);
  const dir = directory(env);
  const auth = await dir.authorizeCreate(a.user.id, a.channel, {
    kind: 'files', views, expireSec: ttl, bytes: padded,
    files: body.files, maxFile: body.maxFile, types: body.types, depth: body.depth,
  });
  if (!auth.ok) return fromDir(auth);
  const uploadToken = genToken();
  const deleteToken = genDeleteToken();
  let id;
  try {
    for (let attempt = 0; ; attempt++) {
      id = genId('f');
      const ok = await fileStub(env, id).init({
        id, uid: a.user.id, uth: await hashToken(uploadToken), dth: await hashToken(deleteToken),
        padded, views, expire, ttl, pendingSec: settings['files.pendingSec'],
      });
      if (ok) break;
      if (attempt >= 4) throw new Error('id allocation failed');
    }
  } catch (e) {
    await dir.refund(a.user.id, auth.refund);
    throw e;
  }
  return json({ id, uploadtoken: uploadToken, deletetoken: deleteToken, chunks: Math.ceil(padded / (8 * 1024 * 1024)) }, 201);
}

async function putChunk(request, env, a, id, i) {
  assertNotCrossSite(request);
  const ct = (request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
  if (ct !== 'application/octet-stream') return err(415, 'unsupported_media_type', 'Chunks must be application/octet-stream.');
  const token = request.headers.get('x-upload-token') || '';
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return err(403, 'bad_token', 'Missing or invalid X-Upload-Token.');
  const cl = Number(request.headers.get('content-length'));
  if (Number.isFinite(cl) && cl > MAX_CHUNK_CT) return err(413, 'too_large', 'Chunk is too large.');
  const bytes = await readCappedBody(request.body, MAX_CHUNK_CT);
  if (bytes === null) return err(413, 'too_large', 'Chunk is too large.');
  const uth = await hashToken(token);
  const stub = fileStub(env, id);
  const auth = await stub.authorizeChunk(a.user.id, uth, i, bytes.length);
  if (auth.status === 'forbidden') return err(403, 'forbidden', 'Not your upload.');
  if (auth.status === 'bad_index') return err(400, 'bad_index', 'No such chunk index.');
  if (auth.status === 'bad_size') return err(400, 'bad_size', `Chunk ${i} must be exactly ${auth.expected} bytes.`);
  if (auth.status !== 'ok') return err(410, 'gone', 'This upload has expired or was already finalized.');
  await binding(env, 'FILES').put(r2Key(id, i), bytes, { httpMetadata: { contentType: 'application/octet-stream' } });
  const c = await stub.commitChunk(a.user.id, uth, i, bytes.length);
  if (c.status !== 'ok') return err(410, 'gone', 'This upload has expired.');
  return json({ ok: true });
}

async function finalizeFile(request, env, a, id) {
  const token = request.headers.get('x-upload-token') || '';
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return err(403, 'bad_token', 'Missing or invalid X-Upload-Token.');
  const body = await readJsonBody(request, MAX_BODY);
  const clean = parseCreatePaste(body);
  if (clean.adata.fmt !== 'files') return err(400, 'invalid_format', 'The manifest must be a fmt:"files" paste.');
  if (JSON.stringify(clean).length > MAX_BURN_RECORD) return err(413, 'too_large', 'The manifest is too large.');
  const stub = fileStub(env, id);
  const r = await stub.finalize(a.user.id, await hashToken(token), { paste: clean, acc: clean.acc });
  if (r.status === 'forbidden') return err(403, 'forbidden', 'Not your upload.');
  if (r.status === 'mismatch') return err(400, 'invalid_format', 'The manifest’s view limit and expiry must match the upload.');
  if (r.status === 'incomplete') return err(409, 'incomplete', `Chunk ${r.missing} has not been uploaded.`);
  if (r.status !== 'ok') return err(410, 'gone', 'This upload has expired or was already finalized.');
  await directory(env).recordShare({ id, uid: a.user.id, kind: 'files', label: body.label, created: r.created, expires: r.expires, views: clean.meta.views ?? null }, actorId(a));
  return json({ ok: true, id, expires: r.expires });
}

// ── My shares ──────────────────────────────────────────────────────────────
async function liveStatus(env, id) {
  const info = parseId(id);
  if (!info) return { status: 'gone' };
  if (info.file) return fileStub(env, id).status();
  if (info.burn) return burnStub(env, id).status();
  const rec = await kvGet(env, id);
  return rec ? { status: 'ok', views: null, left: null, expires: rec.paste.meta.expires } : { status: 'gone' };
}

/** Refresh active rows from their live store (views left, expiry, gone). */
export async function withLiveStatus(env, dir, rows) {
  return Promise.all(rows.map(async (r) => {
    if (r.status !== 'active') return { ...r, left: null };
    const s = await liveStatus(env, r.id);
    if (s.status === 'gone') {
      await dir.markShareEnded(r.id, 'ended');
      return { ...r, status: 'ended', left: 0 };
    }
    return { ...r, views_total: s.views ?? r.views_total, left: s.left ?? null, expires: s.expires ?? r.expires };
  }));
}

async function listShares(env, a, url) {
  const q = (url.searchParams.get('q') || '').slice(0, 100);
  const status = ['active', 'revoked', 'expired', 'consumed', 'deleted', 'ended'].includes(url.searchParams.get('status')) ? url.searchParams.get('status') : '';
  const offset = Number(url.searchParams.get('offset')) || 0;
  const dir = directory(env);
  const { rows, total } = await dir.listShares(a.user.id, { q, status, limit: 50, offset });
  return { rows: await withLiveStatus(env, dir, rows), total };
}

async function updateShare(request, env, a, id, info) {
  const body = await readJsonBody(request);
  const dir = directory(env);
  const row = await dir.getShare(a.user.id, id);
  if (!row) return err(404, 'not_found', 'Share not found.');
  if (row.locked) return shareLocked();
  return changeShare(env, dir, row, info, body, { uid: a.user.id, actor: actorId(a) });
}

const shareLocked = () => err(423, 'share_locked', 'The administrator has locked this share; it cannot be changed.');

/**
 * Apply a label / views / expiry change to a share and its index row. Users go
 * through their own limits (authorizeIncrease); the admin (`admin` = owner id)
 * is bounded only by the hard protocol maxima and may change locked shares.
 * Views and expiry can only grow — the stores cannot shrink them safely.
 */
export async function changeShare(env, dir, row, info, body, { uid, actor, admin = null }) {
  const id = row.id;
  const patch = {};
  if (body.label !== undefined) patch.label = body.label;
  const change = {};
  if (body.views !== undefined) {
    if (body.views !== null && !(Number.isSafeInteger(body.views) && body.views >= 1 && body.views <= MAX_VIEWS)) return err(400, 'invalid_views', 'Invalid views.');
    if (!info.burn && !info.file) return err(400, 'invalid', 'This note already has unlimited views.');
    change.views = body.views;
  }
  if (body.expires !== undefined) {
    if (!Number.isSafeInteger(body.expires) || body.expires <= now() || body.expires > now() + MAX_TTL) return err(400, 'invalid_expiry', 'Expiry must be in the future and within 365 days.');
    change.expires = body.expires;
  }
  if (change.views !== undefined || change.expires !== undefined) {
    if (row.status !== 'active') return err(409, 'not_active', 'Only active shares can be changed.');
    if (!admin) {
      const ok = await dir.authorizeIncrease(uid, { views: change.views, expireAt: change.expires });
      if (!ok.ok) return fromDir(ok);
    }
    // Re-check the lock right before touching the store (the admin may have
    // locked it since `row` was read). A residual window of one RPC remains;
    // it can only extend a share, never destroy one, and the index update
    // below then refuses with 423.
    if (!admin && await dir.isShareLocked(id)) return shareLocked();
    let r;
    if (info.file) r = await fileStub(env, id).extend(change);
    else if (info.burn) r = await burnStub(env, id).extend(change);
    else r = await extendKv(env, id, change);
    if (r.status === 'invalid') return err(400, 'invalid', r.message);
    if (r.status !== 'ok') {
      await dir.markShareEnded(id, 'ended');
      return err(410, 'gone', 'This share no longer exists.');
    }
    if (change.views !== undefined) patch.views = r.views;
    if (change.expires !== undefined) patch.expires = r.expires;
  }
  if (Object.keys(patch).length === 0) return err(400, 'invalid', 'Nothing to change.');
  const u = await dir.updateShare(uid, id, patch, actor, { admin });
  return u.ok ? json({ ok: true }) : fromDir(u);
}

async function extendKv(env, id, { expires }) {
  const rec = await kvGet(env, id);
  if (!rec) return { status: 'gone' };
  if (expires === undefined) return { status: 'invalid', message: 'Nothing to change.' };
  if (expires <= rec.paste.meta.expires) return { status: 'invalid', message: 'Expiry can only be extended.' };
  rec.paste.meta.expires = expires;
  await kvPut(env, id, rec, Math.max(60, expires - now()));
  return { status: 'ok', expires };
}

async function revokeShare(env, a, id, info) {
  const dir = directory(env);
  const row = await dir.getShare(a.user.id, id);
  if (!row) return err(404, 'not_found', 'Share not found.');
  if (row.locked) return shareLocked();
  if (info && info.file) binding(env, 'FILES'); // fail before marking anything revoked
  // Mark revoked first: the Directory re-checks the lock atomically, so a
  // share locked in the meantime is refused before any content is destroyed.
  // A share already marked revoked (an earlier purge failed) is purged again.
  if (row.status !== 'revoked') {
    const u = await dir.updateShare(a.user.id, id, { status: 'revoked' }, actorId(a));
    if (!u.ok) return fromDir(u);
  }
  await purgeShare(env, id, info);
  return json({ ok: true });
}

export async function purgeShare(env, id, info = parseId(id)) {
  if (!info) return;
  if (info.file) binding(env, 'FILES'); // never report a revoke that left ciphertext in R2
  if (info.file) await fileStub(env, id).revoke();
  else if (info.burn) await burnStub(env, id).revoke();
  else await kvDelete(env, id);
}
