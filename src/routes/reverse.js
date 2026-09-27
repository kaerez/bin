// reverse.js — reverse shares ("Receive files", docs/REVERSE.md): the user's
// routes under /api/private/drive (create, list, the received files and their
// re-wrap) and the anonymous uploader's routes under /api/reverse/<id>.
//
// The server stores what the browsers encrypted — the share's private key
// sealed with the user's Drive key, the uploader's file names, metadata and
// file keys sealed to the share's public key (which only the link holds) —
// and checks only what it can see: the link proof, the password proof (both
// as SHA-256 hashes), the human check, sizes and counts against the share's
// limits and the Drive's capacity, and exact chunk sizes. The password only
// gates the uploader; the data is always encrypted to the user's key.

import { json, err, readJsonBody, readCappedBody, assertIntent, assertNotCrossSite, decodePathSegment, methodNotAllowed } from '../lib/http.js';
import { actorId } from '../lib/auth.js';
import { directory, ipContext, isBlocked, recordFailure } from '../lib/guard.js';
import { genToken, hashToken } from '../lib/ids.js';
import { driveStub } from '../lib/store.js';
import { binding } from '../lib/config.js';
import { requireTurnstile, TURNSTILE_ACTIONS } from '../lib/turnstile.js';
import { stepUpFrom, afterRefusal } from './stepup.js';
import { HARD_MAX_DRIVE_BYTES } from '../lib/settings.js';
import { expireSeconds, isProof, ARGON2, MAX_TTL } from '../../public/js/format.js';
import { MAX_CHUNK_CT } from '../../public/js/files.js';
import { normalizeRules, checkDeclaredTypes, refusedTypes, describeType } from '../../public/js/filepolicy.js';
import { b64urlFromBytes, bytesFromB64url, timingSafeEqualHex } from '../../public/js/bytes.js';
import { NODE_ID_RE, ROOT, MAX_REVERSE_FILES, RECEIVED_FAIL_REASONS } from '../drive-do.js';
import { encField } from './drive.js';

export const REVERSE_ID_RE = /^r[A-Za-z0-9_-]{22}$/;
const B64_43 = /^[A-Za-z0-9_-]{43}$/;
const SALT_RE = /^[A-Za-z0-9_-]{22}$/;
const WRAP_RE = /^1\.[A-Za-z0-9_-]{87}\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{107}$/;
// Caps on the sealed fields, just above what the browsers produce: a note of
// 1000 bytes, a PKCS#8 P-256 key, an upload's path of 1024 bytes, its
// metadata JSON; the Drive-format name / meta / fk of a re-wrapped file.
const MAX_NOTE_CT = 1400;
const MAX_PRIV_CT = 256;
const MAX_PATH_CT = 1400;
const MAX_META_CT = 1024;
const MAX_NAME_CT = 512;
const MAX_FK_CT = 128;
/** Bound parameters per query stay well under the Durable Object SQLite limit (100). */
const ID_BATCH = 80;
const GONE = 'This link no longer accepts files: it has expired or was revoked.';
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const invalid = (message) => err(400, 'invalid', message);
const fromDo = (r) => {
  const extra = {};
  for (const k of ['max', 'used', 'refused']) if (r[k] !== undefined) extra[k] = r[k];
  return err(r.status, r.error, r.message, Object.keys(extra).length ? extra : undefined);
};
const eqB64 = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqualHex(a, b);
async function proofHashOf(b64) {
  return b64urlFromBytes(new Uint8Array(await crypto.subtle.digest('SHA-256', bytesFromB64url(b64))));
}

/** A bound on a byte / file count: null (none) or an integer in [1, max]; undefined when invalid. */
function bound(v, max) {
  if (v === undefined || v === null) return null;
  return Number.isSafeInteger(v) && v >= 1 && v <= max ? v : undefined;
}

// ── the user (session; called from src/routes/drive.js) ──────────────────────

/**
 * /api/private/drive/reverse and /api/private/drive/received[/<id>] (the
 * Drive route has checked the session and that the role has a Drive; creating
 * also needs the reverse-share option). Returns null for any other path.
 */
export async function handleReverseOwner(request, env, url, a) {
  const p = url.pathname;
  const uid = a.user.id;
  const dir = directory(env);
  const drive = () => driveStub(env, uid);

  if (p === '/api/private/drive/reverse') {
    if (request.method === 'GET') {
      const folder = url.searchParams.get('folder');
      if (folder !== null && folder !== ROOT && !NODE_ID_RE.test(folder)) return invalid('folder must be a folder id.');
      const r = await drive().listReverse(uid, folder);
      const rows = [];
      for (let i = 0; i < r.reverse.length; i += ID_BATCH) rows.push(...await dir.sharesByIds(uid, r.reverse.slice(i, i + ID_BATCH).map((x) => x.id)));
      const byId = new Map(rows.map((x) => [x.id, x]));
      return json({
        reverse: r.reverse.filter((x) => byId.has(x.id)).map((x) => {
          const row = byId.get(x.id);
          // The index row decides (revoked, expired, locked by the admin); the Drive adds the counters.
          const status = row.status !== 'active' ? row.status : x.status === 'active' ? 'active' : 'ended';
          return { ...x, label: row.label, locked: !!row.locked, status };
        }),
      });
    }
    if (request.method !== 'POST') return methodNotAllowed('GET, POST');
    return createReverse(request, env, dir, a);
  }

  if (p === '/api/private/drive/received') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    const rawAfter = url.searchParams.get('after');
    let after = null;
    if (rawAfter !== null) {
      const c = /^(\d{1,12})\.([A-Za-z0-9_-]{22})$/.exec(rawAfter);
      if (!c) return invalid('after must be the "next" value of the previous page.');
      after = { created: Number(c[1]), id: c[2] };
    }
    const failed = url.searchParams.get('failed') === '1';
    const r = await drive().received(uid, { after, failed });
    if (failed) {
      // With the link's label (the share index has it), for the user to recognise them.
      const ids = [...new Set(r.items.map((i) => i.rs))];
      const rows = [];
      for (let i = 0; i < ids.length; i += ID_BATCH) rows.push(...await dir.sharesByIds(uid, ids.slice(i, i + ID_BATCH)));
      const label = new Map(rows.map((x) => [x.id, x.label]));
      return json({ items: r.items.map((i) => ({ ...i, label: label.get(i.rs) ?? '' })), more: r.more, next: r.next });
    }
    return json({ items: r.items, keys: r.keys, more: r.more, next: r.next });
  }

  const m = p.match(/^\/api\/private\/drive\/received\/([^/]+)(\/failed)?$/);
  if (m) {
    const node = decodePathSegment(m[1]);
    if (!node || !NODE_ID_RE.test(node)) return err(404, 'not_found', 'No such item.');
    if (m[2]) {
      // The browser could not take it in (POST, with a reason), or will try again (DELETE).
      if (request.method !== 'POST' && request.method !== 'DELETE') return methodNotAllowed('POST, DELETE');
      let reason = null;
      if (request.method === 'POST') {
        const body = await readJsonBody(request);
        if (body.reason !== undefined && !RECEIVED_FAIL_REASONS.includes(body.reason)) return invalid(`reason must be one of ${RECEIVED_FAIL_REASONS.join(', ')}.`);
        reason = body.reason ?? null;
      } else assertIntent(request);
      const r = await drive().markReceived(uid, node, { failed: request.method === 'POST', reason });
      if (!r.ok) return fromDo(r);
      // Drive actions: the user's own, or the owner's while acting as the user (imp).
      await dir.driveLog(actorId(a), uid, request.method === 'POST' ? 'drive.received_failed' : 'drive.received_retried', `id=${r.rs} files=1`);
      return json({ ok: true, received: r.received, failed: r.failed });
    }
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const body = await readJsonBody(request);
    const parent = typeof body.parent === 'string' && (body.parent === ROOT || NODE_ID_RE.test(body.parent)) ? body.parent : null;
    const name = encField(body.name, MAX_NAME_CT);
    const meta = encField(body.meta, MAX_META_CT);
    const fk = encField(body.fk, MAX_FK_CT);
    if (!parent || !name || !meta || !fk) return invalid('Send { parent, name, meta, fk } (encrypted fields as {iv, ct}).');
    const r = await drive().acceptReceived(uid, node, { parent, name, meta, fk });
    if (!r.ok) return fromDo(r);
    await dir.setDriveUsed(uid, r.used);
    await dir.driveLog(actorId(a), uid, 'drive.received_taken_in', `id=${r.rs} files=1`);
    return json({ ok: true });
  }
  return null;
}

async function createReverse(request, env, dir, a) {
  const uid = a.user.id;
  const body = await readJsonBody(request);
  if (typeof body.id !== 'string' || !REVERSE_ID_RE.test(body.id)) return invalid('id must be "r" and 16 random bytes (base64url).');
  const folder = typeof body.folder === 'string' && (body.folder === ROOT || NODE_ID_RE.test(body.folder)) ? body.folder : null;
  if (!folder) return invalid('folder must be a folder id.');
  const priv = encField(body.priv, MAX_PRIV_CT);
  if (!priv) return invalid('priv must be the sealed private key {iv, ct}.');
  if (typeof body.lh !== 'string' || !B64_43.test(body.lh)) return invalid('lh must be the link proof\'s hash.');
  const note = body.note === undefined || body.note === null ? null : encField(body.note, MAX_NOTE_CT);
  if (note === null && body.note !== undefined && body.note !== null) return invalid('note must be {iv, ct}.');
  let pw = null;
  if (body.password !== undefined && body.password !== null) {
    const x = body.password;
    if (!isObj(x) || typeof x.salt !== 'string' || !SALT_RE.test(x.salt) || !Number.isInteger(x.t) || x.t < ARGON2.tMin || x.t > ARGON2.tMax
        || typeof x.ph !== 'string' || !B64_43.test(x.ph)) return invalid('password must be { salt, t, ph }.');
    pw = { salt: x.salt, t: x.t, ph: x.ph };
  }
  const ttl = expireSeconds(body.expire);
  if (ttl === null || ttl > MAX_TTL) return err(400, 'invalid_expire', 'Invalid expiry.');
  const maxFiles = bound(body.maxFiles, MAX_REVERSE_FILES);
  const maxBytes = bound(body.maxBytes, HARD_MAX_DRIVE_BYTES);
  const maxFileBytes = bound(body.maxFileBytes, HARD_MAX_DRIVE_BYTES);
  if (maxFiles === undefined) return invalid(`maxFiles must be 1–${MAX_REVERSE_FILES} or null.`);
  if (maxBytes === undefined || maxFileBytes === undefined) return invalid('maxBytes and maxFileBytes must be a number of bytes or null.');
  let types = null;
  if (body.types !== undefined && body.types !== null) {
    if (!isObj(body.types) || !['allow', 'block'].includes(body.types.mode)) return invalid('types must be { mode: "allow" | "block", rules }.');
    let rules;
    try { rules = normalizeRules(body.types.rules); } catch (e) { return invalid(e.message); }
    if (!rules.length) return invalid('List at least one file type, or allow any type.');
    types = { mode: body.types.mode, rules };
  }
  // The id is claimed in the share index first, atomically with the role's
  // checks and its count of active reverse shares: an id another account
  // holds is refused (409), and concurrent creates cannot pass the limit.
  const claim = await dir.claimReverse(uid, { id: body.id, expireSec: ttl, maxBytes, label: body.label, lh: body.lh });
  if (!claim.ok) return fromDo(claim);
  let r;
  try {
    // New key material in the user's Drive: the user confirms with the
    // password or a passkey (a stolen session alone cannot open a link that
    // sends files to it). The owner acting as the user ("Log in as") confirms
    // nothing, as for every other change to the account; the log keeps the
    // real actor.
    if (!a.actor) {
      const g = await ipContext(env, request);
      const step = await stepUpFrom(body, new URL(request.url));
      const v = await dir.verifyCurrent(uid, step.current, { ...step, lockoutOff: g.off.all });
      if (!v.ok) {
        await dir.releaseReverse(uid, body.id);
        return afterRefusal(env, g, v, fromDo(v));
      }
    }
    r = await driveStub(env, uid).createReverse(uid, {
      id: body.id, folder, priv, lh: body.lh, ph: pw?.ph, salt: pw?.salt, t: pw?.t, note, ttl,
      opts: { maxFiles, maxBytes: claim.maxBytes, maxFileBytes, types },
    });
  } catch (e) {
    await dir.releaseReverse(uid, body.id); // the id is free again
    throw e;
  }
  if (!r.ok) {
    await dir.releaseReverse(uid, body.id);
    return fromDo(r);
  }
  const act = await dir.activateReverse(uid, body.id, { created: r.created, expires: r.expires }, actorId(a));
  if (!act.ok) {
    await driveStub(env, uid).endReverse(uid, body.id);
    return fromDo(act);
  }
  return json({ id: body.id, expires: r.expires }, 201);
}

// ── the uploader (anonymous) ─────────────────────────────────────────────────

const blockedRes = (until) => err(429, 'blocked', 'Too many invalid requests from your network. Try again later.', until ? { until } : undefined);
async function failed(env, g, res) {
  const b = await recordFailure(env, g, 'invalid');
  return b.newlyBlocked ? blockedRes(b.until) : res;
}
const grantOf = (request) => {
  const t = request.headers.get('x-reverse-grant') || '';
  return B64_43.test(t) ? t : null;
};
const uploadTokenOf = (request) => {
  const t = request.headers.get('x-upload-token') || '';
  return B64_43.test(t) ? t : null;
};

/** Everything under /api/reverse/. */
export async function handleReversePublic(request, env, url) {
  const m = url.pathname.match(/^\/api\/reverse\/([^/]+)\/(open|begin|files|done)(?:\/([^/]+)(?:\/(chunk|finalize)(?:\/(\d{1,6}))?)?)?$/);
  // Before any Guard accounting (another site could get a visitor's network blocked).
  assertNotCrossSite(request);
  const g = await ipContext(env, request);
  const b = await isBlocked(env, g, 'invalid');
  if (b.blocked) return blockedRes(b.until);
  if (!m) return failed(env, g, err(404, 'not_found', 'Not found.'));
  const [, rawId, action, rawNode, sub, idx] = m;
  const id = decodePathSegment(rawId);
  if (!id || !REVERSE_ID_RE.test(id)) return failed(env, g, err(404, 'not_found', 'Not found.'));
  const dir = directory(env);
  const tg = await dir.reverseTarget(id);
  if (tg.state === 'unknown') return failed(env, g, err(404, 'not_found', 'Not found.'));

  // A link proof, where one is sent, must be this share's (a late visitor with
  // the right link is not counted as a guess; anyone else is).
  let lh = null;
  if (action === 'open' || action === 'begin') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    assertIntent(request);
    const lp = request.headers.get('x-link-proof');
    if (!isProof(lp)) return err(400, 'missing_proof', 'Send the link proof (X-Link-Proof).');
    lh = await proofHashOf(lp);
    if (!eqB64(lh, tg.lh)) return failed(env, g, err(403, 'bad_link', 'The link is incomplete or corrupted.'));
  }
  if (!tg.ok) {
    if (tg.state === 'locked') return err(423, 'share_locked', 'The administrator has locked this link.');
    const res = err(410, 'gone', GONE);
    return lh ? res : failed(env, g, res);
  }
  const uid = tg.uid;
  const drive = driveStub(env, uid);

  if (action === 'open') {
    if (rawNode !== undefined) return err(404, 'not_found', 'Not found.');
    const r = await drive.reverseOpen(uid, id, { roleMaxBytes: tg.roleMaxBytes });
    if (r.status !== 'ok') return err(410, 'gone', GONE);
    return json(r.head);
  }

  if (action === 'begin') {
    if (rawNode !== undefined) return err(404, 'not_found', 'Not found.');
    const r = await drive.reverseOpen(uid, id);
    if (r.status !== 'ok') return err(410, 'gone', GONE);
    const kp = request.headers.get('x-key-proof');
    if (r.ph && !kp) return err(401, 'password_required', 'This link needs a password.', { salt: r.head.password.salt, t: r.head.password.t });
    const lockedRes = (until) => err(429, 'password_locked', 'Too many wrong passwords for this link. Try again later.', { until });
    if (r.head.password && r.head.password.lockedUntil) return lockedRes(r.head.password.lockedUntil);
    // The human check first: without a token no password guess is answered.
    await requireTurnstile(env, request, TURNSTILE_ACTIONS.reverse);
    const grant = genToken();
    // The password is checked in the Drive, with the link's lockout (all networks).
    const proofHash = r.ph && isProof(kp) ? await proofHashOf(kp) : null;
    const s = await drive.reverseBegin(uid, id, await hashToken(grant), tg.pendingSec, { net: g.key, proofHash });
    if (s.status === 'bad_password') {
      await dir.reverseEvent(id, 'bad_password');
      return failed(env, g, err(403, 'bad_password', 'Wrong password.', s.until ? { until: s.until } : undefined));
    }
    if (s.status === 'pw_locked') return lockedRes(s.until);
    if (s.status === 'busy') return err(429, 'busy', 'Too many uploads to this link are in progress. Try again later.');
    if (s.status !== 'ok') return err(410, 'gone', GONE);
    return json({ grant, expires: s.expires });
  }

  if (action === 'done') {
    if (rawNode !== undefined) return err(404, 'not_found', 'Not found.');
    if (request.method !== 'POST') return methodNotAllowed('POST');
    assertIntent(request);
    const grant = grantOf(request);
    if (!grant) return failed(env, g, err(403, 'bad_grant', 'Missing or invalid X-Reverse-Grant.'));
    const r = await drive.reverseDone(uid, id, await hashToken(grant));
    if (r.status !== 'ok') return failed(env, g, err(403, 'bad_grant', 'This upload session has ended.'));
    if (r.files > 0) await dir.reverseEvent(id, 'received', { files: r.files, bytes: r.bytes });
    return json({ files: r.files, bytes: r.bytes });
  }

  // files
  binding(env, 'FILES');
  if (rawNode === undefined) {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const grant = grantOf(request);
    if (!grant) return failed(env, g, err(403, 'bad_grant', 'Missing or invalid X-Reverse-Grant.'));
    return createFile(request, env, g, drive, uid, id, tg, grant);
  }
  const node = decodePathSegment(rawNode);
  if (!node || !NODE_ID_RE.test(node)) return err(404, 'not_found', 'No such file.');
  const token = uploadTokenOf(request);
  if (sub === 'chunk' && idx !== undefined) {
    if (request.method !== 'PUT') return methodNotAllowed('PUT');
    const ct = (request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
    if (ct !== 'application/octet-stream') return err(415, 'unsupported_media_type', 'Chunks must be application/octet-stream.');
    if (!token) return failed(env, g, err(403, 'bad_token', 'Missing or invalid X-Upload-Token.'));
    const cl = Number(request.headers.get('content-length'));
    if (Number.isFinite(cl) && cl > MAX_CHUNK_CT) return err(413, 'too_large', 'Chunk is too large.');
    const bytes = await readCappedBody(request.body, MAX_CHUNK_CT);
    if (bytes === null) return err(413, 'too_large', 'Chunk is too large.');
    const i = Number(idx);
    const r = await drive.reversePutChunk(uid, id, node, await hashToken(token), i, bytes);
    if (r.status === 'forbidden') return failed(env, g, err(403, 'bad_token', 'Wrong upload token.'));
    if (r.status === 'bad_index') return err(400, 'bad_index', 'No such chunk index.');
    if (r.status === 'bad_size') return err(400, 'bad_size', `Chunk ${i} must be exactly ${r.expected} bytes.`);
    if (r.status !== 'ok') return err(410, 'gone', 'This upload has expired or was already finished.');
    return json({ ok: true });
  }
  const grant = grantOf(request);
  if (!grant) return failed(env, g, err(403, 'bad_grant', 'Missing or invalid X-Reverse-Grant.'));
  if (!token) return failed(env, g, err(403, 'bad_token', 'Missing or invalid X-Upload-Token.'));
  if (sub === 'finalize' && idx === undefined) {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const r = await drive.reverseFinalize(uid, id, await hashToken(grant), node, await hashToken(token), tg.pendingSec);
    if (r.status === 'bad_grant') return failed(env, g, err(403, 'bad_grant', 'This upload session has ended.'));
    if (r.status === 'forbidden') return failed(env, g, err(403, 'bad_token', 'Wrong upload token.'));
    if (r.status === 'incomplete') return err(409, 'incomplete', `Chunk ${r.missing} has not been uploaded.`);
    if (r.status === 'busy') return json({ error: 'busy', message: 'A chunk of this file is still being stored. Try again in a moment.' }, 409, { 'retry-after': '1' });
    if (r.status !== 'ok') return err(410, 'gone', 'This upload has expired or was already finished.');
    return json({ ok: true });
  }
  if (sub === undefined) {
    if (request.method !== 'DELETE') return methodNotAllowed('DELETE');
    const r = await drive.reverseCancel(uid, id, await hashToken(grant), node, await hashToken(token));
    if (r.status === 'bad_grant') return failed(env, g, err(403, 'bad_grant', 'This upload session has ended.'));
    if (r.status === 'forbidden') return failed(env, g, err(403, 'bad_token', 'Wrong upload token.'));
    if (r.status !== 'ok') return err(410, 'gone', 'This upload has already finished or ended.');
    const u = await drive.usage(uid);
    await dir.setDriveUsed(uid, u.used);
    return json({ ok: true });
  }
  return err(404, 'not_found', 'Not found.');
}

async function createFile(request, env, g, drive, uid, id, tg, grant) {
  const body = await readJsonBody(request);
  const node = typeof body.id === 'string' && NODE_ID_RE.test(body.id) ? body.id : null;
  const name = encField(body.name, MAX_PATH_CT);
  const meta = encField(body.meta, MAX_META_CT);
  const wrap = typeof body.wrap === 'string' && WRAP_RE.test(body.wrap) ? body.wrap : null;
  if (!node || !name || !meta || !wrap) return invalid('Send { id, name, meta, size, wrap, types? } (encrypted as the uploader page does).');
  if (!Number.isSafeInteger(body.size) || body.size < 0 || body.size > HARD_MAX_DRIVE_BYTES) return err(400, 'invalid_size', 'size must be the file’s size in bytes.');
  // The share's file types: declared by the uploader's browser (names are encrypted), as for file shares.
  const o = await drive.reverseOpen(uid, id, { roleMaxBytes: tg.roleMaxBytes });
  if (o.status !== 'ok') return err(410, 'gone', GONE);
  const rules = o.head.limits.types;
  if (rules) {
    if (body.types === undefined) return err(400, 'declaration_required', 'This link accepts only some file types: declare the file\'s type.', { policy: rules });
    const types = checkDeclaredTypes(body.types);
    if (!types || types.length !== 1) return invalid('types must declare this one file\'s type.');
    const refused = refusedTypes(rules.mode, rules.rules, types);
    if (refused.length) return err(403, 'file_type_not_allowed', `This link does not accept ${refused.map(describeType).join(', ')} files.`, { refused });
  }
  const uploadToken = genToken();
  const r = await drive.reverseCreateFile(uid, id, await hashToken(grant), {
    node, name, meta, size: body.size, wrap, uploadHash: await hashToken(uploadToken),
    capacity: tg.capacity ?? HARD_MAX_DRIVE_BYTES, maxFile: tg.maxFile ?? HARD_MAX_DRIVE_BYTES, pendingSec: tg.pendingSec,
    roleMaxBytes: tg.roleMaxBytes, // the role's current cap applies to existing links too
  });
  if (!r.ok) return r.error === 'bad_grant' ? failed(env, g, fromDo(r)) : fromDo(r);
  await directory(env).setDriveUsed(uid, r.used);
  return json({ id: r.id, uploadToken, chunks: r.chunks }, 201);
}
