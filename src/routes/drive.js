// drive.js — /api/private/drive*: the signed-in user's Drive (docs/DRIVE.md
// §6), and the Drive half of the owner's escrow route. Session only (API keys
// are refused by authenticate()); key material cannot change while the owner
// impersonates. Every state-changing call goes through the same CSRF guards
// as the rest of the private API (JSON body, Sec-Fetch-Site, intent header or
// upload token).
//
// The server stores what the browser encrypted and checks only what it can
// see: the tree's shape, sizes and chunk counts against the role's Drive
// capacity and largest file, and exact chunk sizes on upload.

import { json, err, readJsonBody, readCappedBody, assertIntent, assertNotCrossSite, decodePathSegment, methodNotAllowed, SECURITY_HEADERS } from '../lib/http.js';
import { authenticate, actorId } from '../lib/auth.js';
import { directory } from '../lib/guard.js';
import { genId, genToken, genDeleteToken, hashToken } from '../lib/ids.js';
import { MAX_BODY, MAX_BURN_RECORD, driveStub, fileStub } from '../lib/store.js';
import { validateCreate, FormatError, expireSeconds, MAX_VIEWS } from '../../public/js/format.js';
import { MAX_CHUNK_CT } from '../../public/js/files.js';
import { binding } from '../lib/config.js';
import { HARD_MAX_DRIVE_BYTES } from '../lib/settings.js';
import { NODE_ID_RE, ROOT } from '../drive-do.js';

const fromDir = (r) => {
  const extra = {};
  for (const k of ['max', 'used', 'quota', 'policy', 'refused']) if (r[k] !== undefined) extra[k] = r[k];
  return err(r.status, r.error, r.message, Object.keys(extra).length ? extra : undefined);
};
const withAuth = (a, res) => {
  if (a.setCookie) res.headers.append('set-cookie', a.setCookie);
  return res;
};
const invalid = (message) => err(400, 'invalid', message);

// ── validation of what the browser sends (all of it opaque to the server) ──
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
const SALT_RE = /^[A-Za-z0-9_-]{22}$/;
const JWK_COORD_RE = /^[A-Za-z0-9_-]{43}$/;
export const WRAP_KINDS = ['pw', 'recovery', 'passkey', 'escrow'];
const WRAP_REF_RE = /^[A-Za-z0-9_-]{1,1400}$/;
/** A wrap's data (and escrowPriv): base64url segments joined by "." (docs/DRIVE.md §3). */
const WRAP_DATA_RE = /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/;
export const MAX_WRAP_DATA = 1024;
const MAX_NAME_CT = 4096;
const MAX_META_CT = 8192;
const MAX_FK_CT = 256;
const MAX_SHARE_NODES = 10000;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** An encrypted field {iv, ct} (base64url, 12-byte IV) as stored JSON text, or null if invalid. */
export function encField(v, maxCt) {
  if (!isObj(v) || Object.keys(v).length !== 2 || typeof v.iv !== 'string' || typeof v.ct !== 'string') return null;
  if (!/^[A-Za-z0-9_-]{16}$/.test(v.iv)) return null;
  // At least the 16-byte GCM tag.
  if (v.ct.length < 22 || v.ct.length > maxCt || !B64URL_RE.test(v.ct)) return null;
  return JSON.stringify({ iv: v.iv, ct: v.ct });
}

/** A wrap's opaque payload (or the sealed escrow private key), or null: only its length and charset are checked. */
export function wrapData(v) {
  return typeof v === 'string' && v.length <= MAX_WRAP_DATA && WRAP_DATA_RE.test(v) ? v : null;
}

/** The escrow public key: an EC P-256 public JWK (never a private one), canonical JSON text, or null. */
export function escrowJwk(v) {
  if (!isObj(v) || v.kty !== 'EC' || v.crv !== 'P-256' || !JWK_COORD_RE.test(v.x ?? '') || !JWK_COORD_RE.test(v.y ?? '')) return null;
  const allowed = new Set(['kty', 'crv', 'x', 'y', 'ext', 'key_ops', 'alg']);
  if (Object.keys(v).some((k) => !allowed.has(k))) return null; // "d" (a private key) included
  return JSON.stringify({ kty: 'EC', crv: 'P-256', x: v.x, y: v.y });
}

/** One `pw` and one `escrow` wrap (their ref is their kind); one per passkey / recovery code. */
function wrapRef(kind, ref) {
  if (kind === 'pw' || kind === 'escrow') return ref === kind ? ref : null;
  return typeof ref === 'string' && WRAP_REF_RE.test(ref) ? ref : null;
}

/**
 * Drop the Drive wraps of passkeys and recovery codes the account no longer
 * has (after a removal, a new set of codes, an admin reset). Only the wraps:
 * the browser adds new ones.
 */
export async function syncCredentialWraps(env, uid) {
  const c = await directory(env).credentialRefs(uid);
  if (!c || !c.drive) return;
  await driveStub(env, uid).pruneWraps(uid, { passkey: c.passkeys, recovery: c.recovery });
}

const nodeId = (s) => (s === ROOT || NODE_ID_RE.test(s) ? s : null);

/** Everything under /api/private/drive. */
export async function handleDrive(request, env, url) {
  const p = url.pathname;
  const a = await authenticate(request, env); // session only: an API key gets 403
  const uid = a.user.id;
  const dir = directory(env);
  const pol = await dir.driveAccess(uid);
  if (!pol.ok) return fromDir(pol);
  const drive = () => driveStub(env, uid);
  const escrowPub = () => (pol.escrowPub ? JSON.parse(pol.escrowPub) : null);

  if (p === '/api/private/drive') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    if (!pol.enabled) return withAuth(a, json({ enabled: false, capacity: pol.capacity, maxFile: pol.maxFile, used: pol.used, driveSalt: null, wraps: [], escrowPub: escrowPub() }));
    const s = await drive().summary(uid);
    const out = { enabled: true, capacity: pol.capacity, maxFile: pol.maxFile, used: s.used, driveSalt: s.driveSalt, wraps: s.wraps, escrowPub: escrowPub() };
    if (pol.owner) out.escrowPriv = s.escrowPriv;
    if (s.used !== pol.used) await dir.setDriveUsed(uid, s.used);
    return withAuth(a, json(out));
  }

  if (!pol.enabled) return err(403, 'drive_disabled', 'Your role does not include a Drive.');

  if (p === '/api/private/drive/keys') {
    if (request.method !== 'PUT') return methodNotAllowed('PUT');
    if (a.actor) return err(403, 'impersonating', 'Drive keys cannot be changed while impersonating.');
    const body = await readJsonBody(request);
    return withAuth(a, await setKeys(env, dir, a, pol, body));
  }

  if (p === '/api/private/drive/folders') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const body = await readJsonBody(request);
    const parent = typeof body.parent === 'string' ? nodeId(body.parent) : null;
    const name = encField(body.name, MAX_NAME_CT);
    const meta = body.meta === undefined || body.meta === null ? null : encField(body.meta, MAX_META_CT);
    const id = body.id === undefined ? genId('f').slice(1) : typeof body.id === 'string' && NODE_ID_RE.test(body.id) ? body.id : null;
    if (!parent || !name || !id || (meta === null && body.meta !== undefined && body.meta !== null)) return invalid('Send { id?, parent, name: {iv, ct}, meta? }.');
    const r = await drive().createFolder(uid, { id, parent, name, meta });
    return withAuth(a, r.ok ? json({ id: r.id }, 201) : fromDir(r));
  }

  if (p === '/api/private/drive/files') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    binding(env, 'FILES');
    const body = await readJsonBody(request);
    const parent = typeof body.parent === 'string' ? nodeId(body.parent) : null;
    const name = encField(body.name, MAX_NAME_CT);
    const meta = body.meta === undefined || body.meta === null ? null : encField(body.meta, MAX_META_CT);
    const fk = encField(body.fk, MAX_FK_CT);
    const id = body.id === undefined ? genId('f').slice(1) : typeof body.id === 'string' && NODE_ID_RE.test(body.id) ? body.id : null;
    if (!parent || !name || !fk || !id || (meta === null && body.meta !== undefined && body.meta !== null)) return invalid('Send { id?, parent, name, meta?, size, fk } (encrypted fields as {iv, ct}).');
    if (!Number.isSafeInteger(body.size) || body.size < 0 || body.size > HARD_MAX_DRIVE_BYTES) return err(400, 'invalid_size', 'size must be the file’s size in bytes.');
    const uploadToken = genToken();
    const r = await drive().createFile(uid, {
      id, parent, name, meta, size: body.size, fk, uploadHash: await hashToken(uploadToken),
      capacity: pol.capacity ?? HARD_MAX_DRIVE_BYTES, maxFile: pol.maxFile ?? HARD_MAX_DRIVE_BYTES, pendingSec: pol.pendingSec,
    });
    if (!r.ok) return withAuth(a, fromDir(r));
    await dir.setDriveUsed(uid, r.used);
    return withAuth(a, json({ id: r.id, uploadToken, chunks: r.chunks }, 201));
  }

  const fm = p.match(/^\/api\/private\/drive\/files\/([^/]+)\/(chunk|finalize)(?:\/(\d{1,6}))?$/);
  if (fm) {
    const id = nodeId(decodePathSegment(fm[1]) ?? '');
    if (!id || id === ROOT) return err(404, 'not_found', 'No such file.');
    if (fm[2] === 'chunk' && fm[3] !== undefined) {
      if (request.method === 'GET') return downloadChunk(request, env, a, uid, id, Number(fm[3]));
      if (request.method !== 'PUT') return methodNotAllowed('GET, PUT');
      return withAuth(a, await putChunk(request, env, uid, id, Number(fm[3])));
    }
    if (fm[2] === 'finalize' && fm[3] === undefined) {
      if (request.method !== 'POST') return methodNotAllowed('POST');
      assertNotCrossSite(request);
      const token = uploadTokenOf(request);
      if (!token) return err(403, 'bad_token', 'Missing or invalid X-Upload-Token.');
      const r = await drive().finalize(uid, id, await hashToken(token));
      if (r.status === 'forbidden') return err(403, 'forbidden', 'Wrong upload token.');
      if (r.status === 'incomplete') return err(409, 'incomplete', `Chunk ${r.missing} has not been uploaded.`);
      if (r.status !== 'ok') return err(410, 'gone', 'This upload has expired or was already finalized.');
      return withAuth(a, json({ ok: true }));
    }
    return err(404, 'not_found', 'Not found.');
  }

  const nm = p.match(/^\/api\/private\/drive\/nodes\/([^/]+)(\/shares)?$/);
  if (nm) {
    const id = nodeId(decodePathSegment(nm[1]) ?? '');
    if (!id) return err(404, 'not_found', 'No such item.');
    if (nm[2]) {
      if (request.method !== 'GET') return methodNotAllowed('GET');
      return withAuth(a, await nodeShares(env, dir, uid, id));
    }
    if (request.method === 'GET') {
      const r = await drive().getNode(uid, id);
      return withAuth(a, r.ok ? json({ node: r.node, children: r.children, path: r.path }) : fromDir(r));
    }
    if (request.method === 'PATCH') {
      const body = await readJsonBody(request);
      const patch = {};
      if (body.parent !== undefined) {
        patch.parent = typeof body.parent === 'string' ? nodeId(body.parent) : null;
        if (!patch.parent) return invalid('parent must be a folder id.');
      }
      if (body.name !== undefined) {
        patch.name = encField(body.name, MAX_NAME_CT);
        if (!patch.name) return invalid('name must be {iv, ct}.');
      }
      if (body.meta !== undefined) {
        patch.meta = body.meta === null ? null : encField(body.meta, MAX_META_CT);
        if (patch.meta === null && body.meta !== null) return invalid('meta must be {iv, ct} or null.');
      }
      if (!Object.keys(patch).length) return invalid('Nothing to change.');
      const r = await drive().patchNode(uid, id, patch);
      return withAuth(a, r.ok ? json({ ok: true }) : fromDir(r));
    }
    if (request.method === 'DELETE') {
      assertIntent(request);
      binding(env, 'FILES'); // never report a delete that left ciphertext in R2
      const r = await drive().deleteNode(uid, id);
      if (!r.ok) return withAuth(a, fromDir(r));
      await endShares(env, dir, uid, r.shares, actorId(a));
      await dir.setDriveUsed(uid, r.used);
      return withAuth(a, json({ ok: true, deleted: r.deleted, sharesEnded: r.shares.length }));
    }
    return methodNotAllowed('GET, PATCH, DELETE');
  }

  if (p === '/api/private/drive/shares') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    return withAuth(a, await createShare(request, env, dir, a));
  }

  return err(404, 'not_found', 'Not found.');
}

const uploadTokenOf = (request) => {
  const t = request.headers.get('x-upload-token') || '';
  return /^[A-Za-z0-9_-]{43}$/.test(t) ? t : null;
};

// ── key material ───────────────────────────────────────────────────────────
async function setKeys(env, dir, a, pol, body) {
  const out = { set: [], remove: [] };
  if (body.driveSalt !== undefined) {
    if (typeof body.driveSalt !== 'string' || !SALT_RE.test(body.driveSalt)) return invalid('driveSalt must be 16 bytes, base64url.');
    out.driveSalt = body.driveSalt;
  }
  for (const [list, key] of [[body.set, 'set'], [body.remove, 'remove']]) {
    if (list === undefined) continue;
    if (!Array.isArray(list) || list.length > 64) return invalid(`${key} must be a list of at most 64 wraps.`);
    for (const w of list) {
      if (!isObj(w) || !WRAP_KINDS.includes(w.kind)) return invalid(`Each wrap needs a kind: ${WRAP_KINDS.join(', ')}.`);
      const ref = wrapRef(w.kind, w.ref);
      if (ref === null) return invalid(`Invalid ref for a ${w.kind} wrap.`);
      if (key === 'remove') { out.remove.push({ kind: w.kind, ref }); continue; }
      const data = wrapData(w.data);
      if (data === null) return invalid(`A wrap's data is at most ${MAX_WRAP_DATA} characters of base64url segments joined by ".".`);
      out.set.push({ kind: w.kind, ref, data });
    }
  }
  if (body.escrowPriv !== undefined || body.escrowPub !== undefined) {
    if (!pol.owner) return err(403, 'owner_only', 'Only the owner holds the escrow key.');
  }
  if (body.escrowPriv !== undefined) {
    out.escrowPriv = body.escrowPriv === null ? null : wrapData(body.escrowPriv);
    if (out.escrowPriv === null && body.escrowPriv !== null) return invalid('escrowPriv is sealed like a wrap\'s data.');
  }
  let jwk;
  if (body.escrowPub !== undefined) {
    jwk = escrowJwk(body.escrowPub);
    if (!jwk) return invalid('escrowPub must be an EC P-256 public JWK.');
  }
  if (out.driveSalt === undefined && !out.set.length && !out.remove.length && out.escrowPriv === undefined && jwk === undefined) return invalid('Nothing to change.');
  // Passkey and recovery-code wraps belong to credentials the account has now.
  const refs = out.set.some((w) => w.kind === 'passkey' || w.kind === 'recovery') ? await dir.credentialRefs(a.user.id) : null;
  for (const w of out.set) {
    if (w.kind === 'passkey' && !refs.passkeys.includes(w.ref)) return invalid('A passkey wrap must name one of your passkeys (its credential id).');
    if (w.kind === 'recovery' && !refs.recovery.includes(w.ref)) return invalid('A recovery wrap must name one of your current recovery codes (its hash).');
  }
  const r = await driveStub(env, a.user.id).setKeys(a.user.id, out);
  if (!r.ok) return fromDir(r);
  if (jwk !== undefined) {
    const e = await dir.setEscrowPub(a.user.id, jwk);
    if (!e.ok) return fromDir(e);
  }
  return json({ ok: true });
}

// ── upload and download ────────────────────────────────────────────────────
async function putChunk(request, env, uid, id, i) {
  assertNotCrossSite(request);
  const ct = (request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
  if (ct !== 'application/octet-stream') return err(415, 'unsupported_media_type', 'Chunks must be application/octet-stream.');
  const token = uploadTokenOf(request);
  if (!token) return err(403, 'bad_token', 'Missing or invalid X-Upload-Token.');
  binding(env, 'FILES');
  const cl = Number(request.headers.get('content-length'));
  if (Number.isFinite(cl) && cl > MAX_CHUNK_CT) return err(413, 'too_large', 'Chunk is too large.');
  const bytes = await readCappedBody(request.body, MAX_CHUNK_CT);
  if (bytes === null) return err(413, 'too_large', 'Chunk is too large.');
  const r = await driveStub(env, uid).putChunk(uid, id, await hashToken(token), i, bytes);
  if (r.status === 'forbidden') return err(403, 'forbidden', 'Wrong upload token.');
  if (r.status === 'bad_index') return err(400, 'bad_index', 'No such chunk index.');
  if (r.status === 'bad_size') return err(400, 'bad_size', `Chunk ${i} must be exactly ${r.expected} bytes.`);
  if (r.status !== 'ok') return err(410, 'gone', 'This upload has expired or was already finalized.');
  return json({ ok: true });
}

async function downloadChunk(request, env, a, uid, id, i) {
  assertNotCrossSite(request);
  const r = await driveStub(env, uid).chunkKey(uid, id, i);
  if (r.status === 'bad_index') return err(404, 'not_found', 'No such chunk.');
  if (r.status !== 'ok') return err(404, 'not_found', 'No such file.');
  const obj = await binding(env, 'FILES').get(r.key);
  if (!obj) return err(410, 'gone', 'This chunk is missing.');
  return withAuth(a, new Response(obj.body, {
    status: 200,
    headers: {
      ...SECURITY_HEADERS,
      'content-type': 'application/octet-stream',
      'content-length': String(obj.size),
      'content-disposition': 'attachment; filename="chunk.bin"',
      'cache-control': 'no-store',
    },
  }));
}

// ── shares ─────────────────────────────────────────────────────────────────
/** End shares whose Drive items are gone: their FileShare records go (never the d/ objects) and their rows become "revoked". */
async function endShares(env, dir, uid, ids, actor) {
  if (!ids.length) return;
  for (const id of ids) await fileStub(env, id).revoke();
  await dir.endDriveShares(uid, ids, actor);
}

async function nodeShares(env, dir, uid, id) {
  const r = await driveStub(env, uid).sharesOf(uid, id);
  if (!r.ok) return fromDir(r);
  const rows = await dir.sharesByIds(uid, r.shares);
  const live = [];
  const ended = new Set(r.shares);
  for (const row of rows) {
    if (row.status !== 'active') continue;
    const s = await fileStub(env, row.id).status();
    if (s.status === 'gone') { await dir.markShareEnded(row.id, 'ended'); continue; }
    ended.delete(row.id);
    const views = s.views === undefined ? row.views_total : s.views;
    // My-shares rows (so the same revoke flow works), plus `state` / `maxViews` aliases.
    live.push({ ...row, views_total: views, left: s.left ?? null, expires: s.expires ?? row.expires, state: row.status, maxViews: views });
  }
  // Ended shares no longer reference anything.
  if (ended.size) await driveStub(env, uid).dropRefs(uid, [...ended]);
  return json({ shares: live });
}

/**
 * A Drive share: a FileShare record referencing Drive files, authorized
 * exactly like a file share (limits, file policy declarations, quotas of kind
 * "files"), recorded in My shares as kind "drive".
 */
async function createShare(request, env, dir, a) {
  const uid = a.user.id;
  const body = await readJsonBody(request, MAX_BODY);
  const { views, expire } = body;
  if (!Array.isArray(body.nodes) || body.nodes.length < 1 || body.nodes.length > MAX_SHARE_NODES
      || !body.nodes.every((n) => typeof n === 'string' && NODE_ID_RE.test(n))) return invalid(`nodes must list 1–${MAX_SHARE_NODES} Drive file ids.`);
  if (views !== null && !(Number.isSafeInteger(views) && views >= 1 && views <= MAX_VIEWS)) return err(400, 'invalid_views', `views must be 1–${MAX_VIEWS} or null (unlimited).`);
  const ttl = expireSeconds(expire);
  if (ttl === null) return err(400, 'invalid_expire', 'Invalid expiry.');
  const deletable = body.deletable === true;
  if (!isObj(body.paste)) return invalid('Missing "paste" (the encrypted manifest).');
  // `acc` travels inside the paste (as for every creation) and / or next to it: the same.
  if (body.acc !== undefined && body.paste.acc !== undefined && JSON.stringify(body.acc) !== JSON.stringify(body.paste.acc)) return invalid('"acc" differs from the paste\'s.');
  let clean;
  try {
    clean = validateCreate(body.paste.acc === undefined && body.acc !== undefined ? { ...body.paste, acc: body.acc } : body.paste);
  } catch (e) {
    if (e instanceof FormatError) return err(400, 'invalid_format', e.message);
    throw e;
  }
  if (clean.adata.fmt !== 'files') return err(400, 'invalid_format', 'The manifest must be a fmt:"files" paste.');
  if (JSON.stringify(clean).length > MAX_BURN_RECORD) return err(413, 'too_large', 'The manifest is too large.');
  const refsR = await driveStub(env, uid).shareRefs(uid, body.nodes);
  if (!refsR.ok) return fromDir(refsR);
  const auth = await dir.authorizeCreate(uid, a.channel, {
    kind: 'files', drive: true, views, expireSec: ttl, files: refsR.refs.length,
    types: body.types, depth: body.depth, deletable,
  });
  if (!auth.ok) return fromDir(auth);
  const deleteToken = genDeleteToken();
  let id;
  let r;
  try {
    for (let attempt = 0; ; attempt++) {
      id = genId('f');
      r = await fileStub(env, id).initRefs({
        id, dth: await hashToken(deleteToken), refs: refsR.refs, views, expire, ttl, deletable, paste: clean, acc: clean.acc,
      });
      if (r.status !== 'exists') break;
      if (attempt >= 4) throw new Error('id allocation failed');
    }
  } catch (e) {
    await dir.refund(uid, auth.refund);
    throw e;
  }
  if (r.status === 'mismatch') {
    await dir.refund(uid, auth.refund);
    return err(400, 'invalid_format', 'The manifest’s view limit, expiry and recipient-delete setting must match the request.');
  }
  await dir.recordShare({ id, uid, kind: 'drive', label: body.label, created: r.created, expires: r.expires, views, lh: clean.acc.lh }, actorId(a));
  const added = await driveStub(env, uid).addRefs(uid, id, body.nodes);
  if (!added.ok) {
    // An item was deleted between the check and now: the share must not outlive it.
    await endShares(env, dir, uid, [id], actorId(a));
    await dir.refund(uid, auth.refund);
    return fromDir(added);
  }
  return json({ id, deletetoken: deleteToken, expires: r.expires }, 201);
}

// ── owner escrow (routed from /api/private/admin/drive/escrow/<userId>) ─────
/**
 * The owner opens a user's escrow wrap (to unwrap that Drive's key in the
 * owner's browser, e.g. to write a fresh password wrap after a reset). Needs a
 * reason; every use is logged (drive.escrow_used).
 */
export async function escrowRoute(request, env, ownerId, targetId) {
  if (request.method !== 'POST') return methodNotAllowed('POST');
  const body = await readJsonBody(request);
  // eslint-disable-next-line no-control-regex
  const reason = typeof body.reason === 'string' ? body.reason.replace(/[\u0000-\u001f\u007f]/g, ' ').trim() : '';
  if (reason.length < 3 || reason.length > 500) return err(400, 'reason_required', 'Give a reason (3–500 characters); it is logged.');
  const dir = directory(env);
  const logged = await dir.driveAdminAction(ownerId, targetId, 'drive.escrow_used', `reason=${reason}`);
  if (!logged.ok) return fromDir(logged);
  const v = await driveStub(env, targetId).escrowView(targetId);
  return json({ wrap: v.wrap, wraps: v.wraps });
}

/**
 * The owner writes a user's new `pw` wrap after resetting their password
 * (made in the owner's browser from the escrow wrap): only a `pw` wrap and the
 * Drive salt; nothing else changes. Logged (drive.pw_rewrapped).
 */
export async function adminSetUserKeys(request, env, ownerId, targetId) {
  if (request.method !== 'PUT') return methodNotAllowed('PUT');
  const body = await readJsonBody(request);
  if (targetId === ownerId) return err(400, 'use_own_keys', 'Change your own Drive keys from your Drive.');
  if (typeof body.driveSalt !== 'string' || !SALT_RE.test(body.driveSalt)) return invalid('driveSalt must be 16 bytes, base64url.');
  const set = Array.isArray(body.set) && body.set.length === 1 ? body.set[0] : null;
  const data = set && isObj(set) && set.kind === 'pw' && set.ref === 'pw' ? wrapData(set.data) : null;
  if (!data || (body.remove !== undefined && !(Array.isArray(body.remove) && body.remove.length === 0))) return invalid('Send { driveSalt, set: [{ kind: "pw", ref: "pw", data }] } (a password wrap only).');
  const dir = directory(env);
  const logged = await dir.driveAdminAction(ownerId, targetId, 'drive.pw_rewrapped', 'after a password reset');
  if (!logged.ok) return fromDir(logged);
  const r = await driveStub(env, targetId).setKeys(targetId, { driveSalt: body.driveSalt, set: [{ kind: 'pw', ref: 'pw', data }], remove: [] });
  return r.ok ? json({ ok: true }) : fromDir(r);
}

/** The account is being deleted: its Drive goes, with every share of it. */
export async function destroyDrive(env, uid) {
  binding(env, 'FILES');
  const r = await driveStub(env, uid).destroy(uid);
  for (const id of r.shares) await fileStub(env, id).revoke();
}
