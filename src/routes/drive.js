// drive.js — /api/private/drive*: the signed-in user's Drive (docs/DRIVE.md
// §6), and the Drive half of the owner's escrow route. Session only (API keys
// are refused by authenticate()). Every state-changing call goes through the
// same CSRF guards as the rest of the private API (JSON body, Sec-Fetch-Site,
// intent header or upload token).
//
// Every user's Drive is set up with an escrow wrap for the owner's current
// escrow key (the owner's key must exist first), which the user cannot
// remove. While the owner impersonates a user, the whole Drive works for them
// (the owner's browser opens it with the owner escrow, through the logged
// route POST /api/private/drive/escrow); only the user's own key wraps cannot
// be removed or replaced then, and no Drive is created then. What the owner does in the Drive while
// impersonating is recorded in the admin audit with the real actor and never
// in the user's own activity (docs/DRIVE.md §9).
//
// The server stores what the browser encrypted and checks only what it can
// see: the tree's shape, sizes and chunk counts against the role's Drive
// capacity and largest file, and exact chunk sizes on upload.

import { json, err, readJsonBody, readCappedBody, assertIntent, assertNotCrossSite, decodePathSegment, methodNotAllowed, SECURITY_HEADERS } from '../lib/http.js';
import { authenticate, actorId } from '../lib/auth.js';
import { directory, ipContext } from '../lib/guard.js';
import { stepUpFrom, afterRefusal } from './stepup.js';
import { genId, genToken, genDeleteToken, hashToken } from '../lib/ids.js';
import { MAX_BODY, MAX_BURN_RECORD, driveStub, fileStub } from '../lib/store.js';
import { validateCreate, FormatError, expireSeconds, MAX_VIEWS } from '../../public/js/format.js';
import { MAX_CHUNK_CT } from '../../public/js/files.js';
import { utf8, bytesFromB64url, b64urlFromBytes, timingSafeEqualHex } from '../../public/js/bytes.js';
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
/** The user's own wraps (the escrow wrap is the owner's way in). */
const OWN_KINDS = ['pw', 'recovery', 'passkey'];
/** A raw P-256 ECDSA signature (r ‖ s, 64 bytes), base64url. */
const SIG_RE = /^[A-Za-z0-9_-]{86}$/;
/** The Drive key's check value (drivekeys.js keyCheckValue): an HMAC-SHA-256, base64url. */
const KCV_RE = /^[A-Za-z0-9_-]{43}$/;
/** Constant-time comparison of two check values. */
const sameKcv = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqualHex(a, b);
const WRAP_REF_RE = /^[A-Za-z0-9_-]{1,1400}$/;
/** A wrap's data (and escrowPriv): base64url segments joined by "." (docs/DRIVE.md §3). */
const WRAP_DATA_RE = /^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$/;
export const MAX_WRAP_DATA = 1024;
// The largest sealed fields the browser makes (a 255-byte name seals to about
// 362 characters, the metadata JSON to about 300), with room to spare; they
// count towards the capacity as well.
export const MAX_NAME_CT = 512;
export const MAX_META_CT = 1024;
const MAX_FK_CT = 256;
const MAX_PIN_CT = 256;
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
  // Each coordinate is exactly 32 bytes (canonical base64url).
  try { if (bytesFromB64url(v.x).length !== 32 || bytesFromB64url(v.y).length !== 32) return null; } catch { return null; }
  const allowed = new Set(['kty', 'crv', 'x', 'y', 'ext', 'key_ops', 'alg']);
  if (Object.keys(v).some((k) => !allowed.has(k))) return null; // "d" (a private key) included
  return JSON.stringify({ kty: 'EC', crv: 'P-256', x: v.x, y: v.y });
}

/**
 * The kid of an escrow public JWK (object or its JSON text): the first 16
 * bytes of SHA-256 over the raw point 0x04 ‖ x ‖ y, base64url — what the
 * browser puts in an escrow wrap (drivekeys.js escrowKeyId).
 */
export async function escrowKid(jwk) {
  const j = typeof jwk === 'string' ? JSON.parse(jwk) : jwk;
  const raw = new Uint8Array(65);
  raw[0] = 4;
  raw.set(bytesFromB64url(j.x), 1);
  raw.set(bytesFromB64url(j.y), 33);
  return b64urlFromBytes(new Uint8Array(await crypto.subtle.digest('SHA-256', raw)).subarray(0, 16));
}

/** The kid an escrow wrap's data names ("1.<epk>.<kid>.<iv>.<ct>"), or null. */
export const escrowWrapKid = (data) => {
  const parts = typeof data === 'string' ? data.split('.') : [];
  return parts.length === 5 && parts[0] === '1' ? parts[2] : null;
};

/** The message the owner's signing key signs for an escrow public key (drivekeys.js endorsement). */
export const endorsement = (jwk) => {
  const j = typeof jwk === 'string' ? JSON.parse(jwk) : jwk;
  return utf8(`secbin-drive/v1 escrow-endorse\n${j.x}\n${j.y}`);
};

/** Whether `sig` is the owner's signing key's signature over the escrow key. */
async function endorsed(signJwk, escrowJwkText, sig) {
  try {
    const j = typeof signJwk === 'string' ? JSON.parse(signJwk) : signJwk;
    const key = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: j.x, y: j.y }, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, bytesFromB64url(sig), endorsement(escrowJwkText));
  } catch {
    return false;
  }
}

/** One `pw` and one `escrow` wrap (their ref is their kind); one per passkey / recovery code. */
function wrapRef(kind, ref) {
  if (kind === 'pw' || kind === 'escrow') return ref === kind ? ref : null;
  return typeof ref === 'string' && WRAP_REF_RE.test(ref) ? ref : null;
}

/**
 * Drop the Drive wraps of passkeys and recovery codes the account no longer
 * has (after a removal, a new set of codes, an admin reset, a code spent at
 * sign-in). Only the wraps: the browser adds new ones. → the wraps removed.
 */
export async function syncCredentialWraps(env, uid) {
  const c = await directory(env).credentialRefs(uid);
  if (!c || !c.drive) return [];
  return (await driveStub(env, uid).pruneWraps(uid, { passkey: c.passkeys, recovery: c.recovery })).wraps;
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
  const escrowSign = () => ({ escrowSignPub: pol.escrowSignPub ? JSON.parse(pol.escrowSignPub) : null, escrowSig: pol.escrowSig || null });
  // The owner's earlier escrow keys still needed by some user's escrow wrap (the rest are dropped).
  const oldEscrow = async (ownerId) => (await driveStub(env, ownerId).pruneOldEscrow(ownerId, await dir.escrowKidsInUse())).escrowPrivOld;

  // Record a Drive action like any other: the user's own, also when the owner
  // takes it while impersonating them (the admin audit has the real actor).
  const driveLog = (action, detail) => dir.driveLog(actorId(a), uid, action, detail);

  if (p === '/api/private/drive') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    if (!pol.enabled) return withAuth(a, json({ enabled: false, capacity: pol.capacity, maxFile: pol.maxFile, used: pol.used, driveSalt: null, wraps: [], escrowPub: escrowPub() }));
    const s = await drive().summary(uid);
    const out = {
      enabled: true, capacity: pol.capacity, maxFile: pol.maxFile, used: s.used, driveSalt: s.driveSalt, wraps: s.wraps,
      escrowPub: escrowPub(), ...escrowSign(), escrowPin: s.escrowPin ? JSON.parse(s.escrowPin) : null, pwStale: s.pwStale,
      ownerReset: pol.ownerReset ? JSON.parse(pol.ownerReset) : null,
    };
    if (a.actor) {
      // Impersonating: the escrow wrap only through the logged route below.
      out.wraps = s.wraps.map((w) => (w.kind === 'escrow' ? { kind: w.kind, ref: w.ref, data: null } : w));
    }
    if (pol.owner) {
      Object.assign(out, {
        escrowPriv: s.escrowPriv, escrowSignPriv: s.escrowSignPriv, escrowPrivOld: await oldEscrow(uid), escrowKids: await dir.escrowKidsInUse(),
        escrowVersion: await escrowVersionOf(pol, s), kit: s.kit, archives: s.archives,
      });
    }
    if (s.used !== pol.used) await dir.setDriveUsed(uid, s.used);
    return withAuth(a, json(out));
  }

  if (!pol.enabled) return err(403, 'drive_disabled', 'Your role does not include a Drive.');

  if (p === '/api/private/drive/keys') {
    if (request.method !== 'PUT') return methodNotAllowed('PUT');
    const body = await readJsonBody(request);
    return withAuth(a, await setKeys(request, env, url, dir, a, pol, body));
  }

  // The owner's recovery kit (docs/DRIVE.md §3, "Owner recovery kit"): made,
  // opened and checked only in the owner's browser; nothing of it is ever sent.
  // The owner's own, never while acting as a user; the admin audit records
  // each download, use and check.
  if (p === '/api/private/drive/kit' || p.startsWith('/api/private/drive/kit/') || p === '/api/private/drive/start-over' || p.startsWith('/api/private/drive/archive/')) {
    if (a.actor) return err(403, 'impersonating', 'The recovery kit is the owner’s own: return to your account first.');
    if (!pol.owner) return err(403, 'owner_only', 'Only the administrator has this recovery kit.');
    return withAuth(a, await kitRoute(request, env, url, dir, uid, pol, a.user.username));
  }

  // The owner, acting as this user: the user's escrow wrap with the owner's
  // own sealed escrow key, to open the user's Drive in the owner's browser.
  if (p === '/api/private/drive/escrow') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    if (!a.actor) return err(403, 'not_impersonating', 'Only for the owner acting as this user (otherwise Admin → Users).');
    await readJsonBody(request);
    const s = await drive().summary(uid);
    const wrap = s.wraps.find((w) => w.kind === 'escrow') || null;
    const own = await driveStub(env, a.actor.id).summary(a.actor.id);
    if (wrap) await dir.driveEscrowUsed(a.actor.id, uid, 'opened while acting as the user');
    return withAuth(a, json({ ownerId: a.actor.id, escrowPub: escrowPub(), escrowPriv: own.escrowPriv, escrowPrivOld: await oldEscrow(a.actor.id), wrap, wraps: s.wraps.length }));
  }

  if (p === '/api/private/drive/folders') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const body = await readJsonBody(request);
    const parent = typeof body.parent === 'string' ? nodeId(body.parent) : null;
    const name = encField(body.name, MAX_NAME_CT);
    const meta = body.meta === undefined || body.meta === null ? null : encField(body.meta, MAX_META_CT);
    const id = body.id === undefined ? genId('f').slice(1) : typeof body.id === 'string' && NODE_ID_RE.test(body.id) ? body.id : null;
    if (!parent || !name || !id || (meta === null && body.meta !== undefined && body.meta !== null)) return invalid('Send { id?, parent, name: {iv, ct}, meta? }.');
    const r = await drive().createFolder(uid, { id, parent, name, meta, capacity: pol.capacity ?? HARD_MAX_DRIVE_BYTES });
    if (!r.ok) return withAuth(a, fromDir(r));
    await dir.setDriveUsed(uid, r.used);
    await driveLog('drive.folder_created', `id=${r.id}`);
    return withAuth(a, json({ id: r.id }, 201));
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
      if (request.method === 'GET') {
        const res = await downloadChunk(request, env, a, uid, id, Number(fm[3]));
        if (res.status === 200 && fm[3] === '0') await driveLog('drive.file_read', `id=${id}`);
        return res;
      }
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
      if (r.status === 'busy') return err(409, 'busy', 'A chunk of this file is still being written: finalize again in a moment.');
      if (r.status !== 'ok') return err(410, 'gone', 'This upload has expired or was already finalized.');
      await driveLog('drive.file_uploaded', `id=${id}`);
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
      const r = await drive().patchNode(uid, id, { ...patch, capacity: pol.capacity ?? HARD_MAX_DRIVE_BYTES });
      if (!r.ok) return withAuth(a, fromDir(r));
      await dir.setDriveUsed(uid, r.used);
      await driveLog('drive.item_changed', `id=${id} ${[patch.parent !== undefined ? 'moved' : '', patch.name !== undefined ? 'renamed' : ''].filter(Boolean).join(' ') || 'meta'}`);
      return withAuth(a, json({ ok: true }));
    }
    if (request.method === 'DELETE') {
      assertIntent(request);
      binding(env, 'FILES'); // never report a delete that left ciphertext in R2
      const r = await drive().deleteNode(uid, id);
      if (!r.ok) return withAuth(a, fromDir(r));
      await endShares(env, dir, uid, r.shares, actorId(a));
      await dir.setDriveUsed(uid, r.used);
      await driveLog('drive.item_deleted', `id=${id} items=${r.deleted} shares_ended=${r.shares.length}`);
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
const wrapKey = (w) => `${w.kind}\n${w.ref}`;

/**
 * PUT /api/private/drive/keys. The rules (docs/DRIVE.md §3):
 * - a user's Drive is set up (its first wraps) only once the owner's escrow
 *   key exists, and with an escrow wrap for it and a wrap of the user's own;
 *   an escrow wrap is always for the current escrow key; the user cannot
 *   remove it; no change leaves a Drive without a wrap of the user's own;
 * - the step-up (the account's password or a passkey: `current` / `reauth`)
 *   is needed for any change of the owner's escrow key pair or signing key
 *   once one exists (the first set-up is exempt), and for removing a wrap,
 *   replacing the `pw` wrap or replacing `driveSalt` — except the Drive's
 *   first set-up and a `pw` wrap the server marked stale (the normal
 *   password-change flow);
 * - a new escrow public key must carry the owner's signing key's signature
 *   once a signing key exists;
 * - while the owner impersonates the user, only wraps added for credentials
 *   the owner gives the user (a `pw` wrap when there is none, with its salt,
 *   new recovery-code and passkey wraps) — never a Drive created, never a
 *   wrap removed or replaced.
 */
async function setKeys(request, env, url, dir, a, pol, body) {
  const uid = a.user.id;
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
  const ownerKeys = ['escrowPriv', 'escrowPub', 'escrowSignPriv', 'escrowSignPub', 'escrowSig'].filter((k) => body[k] !== undefined);
  if (ownerKeys.length && !pol.owner) return err(403, 'owner_only', 'Only the administrator holds the escrow key.');
  for (const k of ['escrowPriv', 'escrowSignPriv']) {
    if (body[k] === undefined) continue;
    out[k] = wrapData(body[k]);
    if (out[k] === null) return invalid(`${k} is sealed like a wrap's data.`);
  }
  let jwk;
  if (body.escrowPub !== undefined) {
    jwk = escrowJwk(body.escrowPub);
    if (!jwk) return invalid('escrowPub must be an EC P-256 public JWK.');
  }
  let signJwk;
  if (body.escrowSignPub !== undefined) {
    signJwk = escrowJwk(body.escrowSignPub);
    if (!signJwk) return invalid('escrowSignPub must be an EC P-256 public JWK.');
  }
  if (body.escrowSig !== undefined && (typeof body.escrowSig !== 'string' || !SIG_RE.test(body.escrowSig))) return invalid('escrowSig must be a P-256 signature (64 bytes, base64url).');
  if (body.escrowPin !== undefined) {
    out.escrowPin = encField(body.escrowPin, MAX_PIN_CT);
    if (!out.escrowPin) return invalid('escrowPin must be {iv, ct}.');
  }
  // A user's browser moved the Drive to an owner reset's escrow key by itself
  // (`escrowReset`: that reset's epoch): recorded once the wrap is stored.
  let resetRewrap = null;
  if (body.escrowReset !== undefined) {
    const rec = pol.ownerReset ? JSON.parse(pol.ownerReset) : null;
    if (pol.owner || a.actor || !rec || body.escrowReset !== rec.epoch || !out.set.some((w) => w.kind === 'escrow')) return invalid('escrowReset names the current owner reset, with the escrow wrap for its key.');
    resetRewrap = rec;
  }
  if (out.driveSalt === undefined && !out.set.length && !out.remove.length && !ownerKeys.length && out.escrowPin === undefined) return invalid('Nothing to change.');
  const cur = await driveStub(env, uid).summary(uid);
  const existing = new Set(cur.wraps.map(wrapKey));
  const first = cur.wraps.length === 0;
  // The owner's escrow key: every user's Drive has an escrow wrap for the current one.
  if (!pol.owner) {
    if (out.remove.some((w) => w.kind === 'escrow')) return err(403, 'escrow_required', 'The escrow wrap cannot be removed: the administrator keeps access to every Drive.');
    const escrow = out.set.find((w) => w.kind === 'escrow');
    if (first && !a.actor) {
      if (!pol.escrowPub) return err(409, 'escrow_not_ready', 'The Drive is not ready yet: the administrator must sign in once first.');
      if (!escrow) return invalid('A new Drive needs its escrow wrap.');
      if (!out.set.some((w) => OWN_KINDS.includes(w.kind))) return invalid('A new Drive needs a password, passkey or recovery-code wrap.');
    }
    if (escrow) {
      if (!pol.escrowPub) return err(409, 'escrow_not_ready', 'There is no escrow key yet.');
      if (escrowWrapKid(escrow.data) !== await escrowKid(pol.escrowPub)) return invalid('An escrow wrap must be for the current escrow key.');
    }
  }
  if (a.actor) {
    const addOnly = !first && out.set.every((w) => OWN_KINDS.includes(w.kind) && !existing.has(wrapKey(w)))
      && (out.driveSalt === undefined || (out.set.some((w) => w.kind === 'pw') && !existing.has('pw\npw')))
      && out.escrowPin === undefined && !ownerKeys.length;
    if (first) return err(403, 'impersonating', 'The user has not signed in since the Drive was enabled: their Drive does not exist yet.');
    if (out.remove.length || !addOnly || !out.set.length) {
      return err(403, 'impersonating', 'While acting as a user you can open and use their Drive and add keys for what you give them, but never remove or replace their own keys.');
    }
  }
  // Passkey and recovery-code wraps belong to credentials the account has now.
  const refs = out.set.some((w) => w.kind === 'passkey' || w.kind === 'recovery') ? await dir.credentialRefs(uid) : null;
  for (const w of out.set) {
    if (w.kind === 'passkey' && !refs.passkeys.includes(w.ref)) return invalid('A passkey wrap must name one of your passkeys (its credential id).');
    if (w.kind === 'recovery' && !refs.recovery.includes(w.ref)) return invalid('A recovery wrap must name one of your current recovery codes (its hash).');
  }
  // A new escrow key is signed by the owner's signing key (users' browsers check it).
  const signKey = signJwk ?? pol.escrowSignPub;
  if ((jwk !== undefined || signJwk !== undefined || body.escrowSig !== undefined) && signKey) {
    const target = jwk ?? pol.escrowPub;
    if (!target || typeof body.escrowSig !== 'string' || !(await endorsed(signKey, target, body.escrowSig))) {
      return invalid('The escrow key must be signed by the escrow signing key (escrowSig).');
    }
  }
  // Changes that need the step-up.
  const hasPw = existing.has('pw\npw');
  const newPw = out.set.some((w) => w.kind === 'pw');
  const pwExempt = cur.pwStale || !hasPw; // the normal password-change flow (or no pw wrap yet)
  const needs = [];
  if (ownerKeys.length && (pol.escrowPub || cur.escrowPriv || pol.escrowSignPub || cur.escrowSignPriv)) needs.push('escrow');
  if (!first) {
    if (out.remove.some((w) => existing.has(wrapKey(w)))) needs.push('remove');
    if (newPw && !pwExempt) needs.push('pw');
    if (out.driveSalt !== undefined && cur.driveSalt && !(newPw && pwExempt)) needs.push('salt');
  }
  if (needs.length) {
    const g = await ipContext(env, request);
    const step = await stepUpFrom(body, url); // 400 reauth_required without one
    const r = await dir.verifyCurrent(uid, step.current, { reauth: step.reauth, origin: step.origin, rpId: step.rpId, lockoutOff: g.off.all });
    if (!r.ok) return afterRefusal(env, g, r, fromDir(r));
  }
  // The Drive key's check value: a password wrap is accepted after the first
  // set-up only as a wrap of the same DK (the value kept since then); a Drive
  // without one keeps the first value it is given.
  if (body.kcv !== undefined && (typeof body.kcv !== 'string' || !KCV_RE.test(body.kcv))) return invalid('kcv must be the Drive key’s check value (32 bytes, base64url).');
  if (!first && out.set.some((w) => w.kind === 'pw') && body.kcv === undefined) return err(400, 'kcv_required', 'A new password key needs the Drive key’s check value.');
  if (body.kcv !== undefined && cur.kcv && !sameKcv(body.kcv, cur.kcv)) return err(409, 'kcv_mismatch', 'That key is not this Drive’s key.');
  if (body.kcv !== undefined && !cur.kcv) out.kcv = body.kcv;
  const oldKid = out.escrowPriv !== undefined && pol.escrowPub && jwk !== undefined ? await escrowKid(pol.escrowPub) : undefined;
  // A new escrow key pair (the first, or a rotation) moves the escrow key's version.
  const newEscrowKid = out.escrowPriv !== undefined && jwk !== undefined ? await escrowKid(jwk) : undefined;
  const r = await driveStub(env, uid).setKeys(uid, { ...out, oldKid, newEscrowKid, firstEscrow: !pol.escrowPub });
  if (!r.ok) return fromDir(r);
  if (jwk !== undefined || signJwk !== undefined || body.escrowSig !== undefined) {
    const e = await dir.setEscrowPub(uid, jwk, { signPub: signJwk, sig: body.escrowSig });
    if (!e.ok) return fromDir(e);
  }
  const escrow = out.set.find((w) => w.kind === 'escrow');
  if (escrow) await dir.setEscrowKid(uid, escrowWrapKid(escrow.data));
  if (resetRewrap && escrow) await dir.driveEscrowRewrapped(uid, short(escrowWrapKid(escrow.data)));
  const kinds = (l) => [...new Set(l.map((w) => w.kind))].join(', ');
  const what = [out.set.length ? `added ${kinds(out.set)}` : '', out.remove.length ? `removed ${kinds(out.remove)}` : '', out.driveSalt !== undefined ? 'salt' : ''].filter(Boolean);
  if (what.length) await dir.driveLog(actorId(a), uid, 'drive.keys_changed', what.join('; '));
  return json({ ok: true });
}

// ── the owner's recovery kit (docs/DRIVE.md §3) ──────────────────────────
const KIT_ISSUES = ['format', 'owner', 'auth', 'dk', 'current', 'signing', 'past', 'version', 'proof'];
const kitVersionOf = (v) => (Number.isSafeInteger(v) && v >= 1 && v <= 1e6 ? v : null);
/** A kid's short fingerprint, as the pages show it (driveclient.js kidFingerprint). */
const short = (kid) => { const k = String(kid || ''); return k.length >= 8 ? `${k.slice(0, 4)}-${k.slice(4, 8)}` : k; };

/**
 * The escrow key's version (1 at the first creation, one more at each
 * rotation; docs/DRIVE.md §3): `{ version, kid, created }` for the current
 * escrow key, or null when there is none. A key made before versions were
 * recorded is version 1 with no date; a record for another kid (the public key
 * restored or replaced outside a rotation) gives no version.
 */
async function escrowVersionOf(pol, s) {
  if (!pol.escrowPub) return null;
  const kid = await escrowKid(pol.escrowPub);
  const v = s.escrowVer;
  if (!v) return { version: 1, kid, created: null };
  return v.kid === kid ? { version: v.version, kid, created: v.created ?? null } : { version: null, kid, created: null };
}

/** The owner's password or a passkey (`current` / `reauth`), as for Account; → null or the refusal. */
async function ownerStepUp(request, env, url, dir, uid, body) {
  const g = await ipContext(env, request);
  const step = await stepUpFrom(body, url); // 400 reauth_required without one
  const r = await dir.verifyCurrent(uid, step.current, { reauth: step.reauth, origin: step.origin, rpId: step.rpId, lockoutOff: g.off.all });
  return r.ok ? null : afterRefusal(env, g, r, fromDir(r));
}

/**
 * /api/private/drive/kit… (the owner, not impersonating):
 * - `POST …/kit` `{ event: 'exported', current | reauth }` — the owner's
 *   browser gives the kit file out only after this: the step-up is checked,
 *   the escrow key's version and kid are recorded (with the time) in the
 *   owner's Drive and `drive.kit_exported` in the admin audit;
 *   `{ event: 'used', version?, current | reauth }` — the kit opened the
 *   owner's Drive (the step-up also proves the password the new `pw` wrap is
 *   made with); `{ event: 'verified', verdict, issues?, version? }` — the
 *   read-only check's verdict (`drive.kit_verified`), nothing else is written;
 * - `GET …/kit/probe` — for the check: one user's escrow wrap per kid users'
 *   wraps are made for (each recorded as `drive.escrow_used`, as the admin
 *   escrow route), to be opened in the browser and discarded;
 * - `PUT …/kit/keys` — restore sealed escrow keys (restoreKitKeys).
 */
async function kitRoute(request, env, url, dir, uid, pol, username) {
  const p = url.pathname;
  if (p === '/api/private/drive/kit') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    assertIntent(request);
    const body = await readJsonBody(request);
    const cur = await driveStub(env, uid).summary(uid);
    const ver = await escrowVersionOf(pol, cur);
    if (body.event === 'exported') {
      if (!ver) return err(409, 'no_escrow', 'There is no escrow key to back up yet: open your Drive once first.');
      const refused = await ownerStepUp(request, env, url, dir, uid, body);
      if (refused) return refused;
      const r = await driveStub(env, uid).recordKit(uid, { version: ver.version, kid: ver.kid });
      await dir.driveOwnerLog(uid, 'drive.kit_exported', `version=${ver.version ?? '?'} key=${short(ver.kid)}`);
      return json({ ok: true, kit: r.kit });
    }
    if (body.event === 'used') {
      const refused = await ownerStepUp(request, env, url, dir, uid, body);
      if (refused) return refused;
      await dir.driveOwnerLog(uid, 'drive.kit_used', `kit version=${kitVersionOf(body.version) ?? '?'}`);
      return json({ ok: true });
    }
    if (body.event === 'verified') {
      if (!['complete', 'incomplete', 'failed'].includes(body.verdict)) return invalid('verdict must be "complete", "incomplete" or "failed".');
      const issues = body.issues === undefined ? [] : body.issues;
      if (!Array.isArray(issues) || issues.length > KIT_ISSUES.length || !issues.every((x) => KIT_ISSUES.includes(x))) return invalid(`issues lists at most: ${KIT_ISSUES.join(', ')}.`);
      const v = kitVersionOf(body.version);
      await dir.driveOwnerLog(uid, 'drive.kit_verified', [`verdict=${body.verdict}`, v ? `kit version=${v}` : '', issues.length ? `issues=${[...new Set(issues)].join(',')}` : ''].filter(Boolean).join(' '));
      return json({ ok: true });
    }
    return invalid('Send { event: "exported" | "used" | "verified" }.');
  }
  if (p === '/api/private/drive/kit/probe') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    assertNotCrossSite(request); // it records escrow use
    const probes = [];
    for (const { kid, userId } of await dir.escrowKidUsers()) {
      const v = await driveStub(env, userId).escrowView(userId);
      if (!v.wrap) continue;
      const logged = await dir.driveAdminAction(uid, userId, 'drive.escrow_used', 'reason=owner recovery kit check');
      if (!logged.ok) continue;
      probes.push({ kid, wrap: v.wrap });
    }
    return json({ probes });
  }
  if (p === '/api/private/drive/kit/keys') {
    if (request.method !== 'PUT') return methodNotAllowed('PUT');
    assertIntent(request);
    return restoreKitKeys(request, env, url, dir, uid, pol, await readJsonBody(request));
  }
  if (p === '/api/private/drive/start-over') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    assertIntent(request);
    return startOver(request, env, url, dir, uid, pol, username, await readJsonBody(request));
  }
  const am = p.match(/^\/api\/private\/drive\/archive\/([1-9][0-9]{0,5})(\/nodes|\/finish)?$/);
  if (am) return archiveRoute(request, env, url, dir, uid, pol, username, Number(am[1]), am[2] || '');
  return err(404, 'not_found', 'Not found.');
}

/**
 * The owner's archived Drive `gen` (after starting over; docs/DRIVE.md §3):
 * - `GET …/archive/<gen>?after=<id>` — its sealed escrow keys and a page of
 *   its items, for the owner's browser to restore it with a recovery kit
 *   made for its (old) DK;
 * - `PUT …/archive/<gen>/nodes` `{ nodes: [{ id, name, meta?, fk? }], current
 *   | reauth }` — items back into the Drive, re-sealed in the browser under
 *   the Drive's DK now, folders first;
 * - `POST …/archive/<gen>/finish` `{ escrowPrivOld?: { <kid>: { pub, data } },
 *   current | reauth }` — once every item is back: its earlier escrow keys
 *   (re-sealed under the Drive's DK) join the owner's, for the kids users'
 *   wraps are still made for, and the archive goes (`drive.archive_restored`);
 * - `DELETE …/archive/<gen>` `{ confirm: <username>, current | reauth }` —
 *   the owner deletes it (its R2 objects included; the shares of its items
 *   end): no kit can restore it afterwards (`drive.archive_deleted`).
 * Nothing else deletes an archive.
 */
async function archiveRoute(request, env, url, dir, uid, pol, username, gen, sub) {
  if (!sub) {
    if (request.method === 'GET') {
      assertNotCrossSite(request);
      const after = url.searchParams.get('after') || '';
      if (after && !NODE_ID_RE.test(after)) return invalid('after must be an item id.');
      const r = await driveStub(env, uid).archiveView(uid, gen, { after, limit: 500 });
      return r.ok ? json(r) : fromDir(r);
    }
    if (request.method !== 'DELETE') return methodNotAllowed('GET, DELETE');
    assertIntent(request);
    binding(env, 'FILES');
    const body = await readJsonBody(request);
    if (typeof body.confirm !== 'string' || !username || body.confirm !== username) return err(400, 'confirm_required', 'Type your username to confirm.');
    const refused = await ownerStepUp(request, env, url, dir, uid, body);
    if (refused) return refused;
    const r = await driveStub(env, uid).deleteArchive(uid, gen);
    if (!r.ok) return fromDir(r);
    await endShares(env, dir, uid, r.shares, uid, 'drive item deleted');
    await dir.setDriveUsed(uid, r.used);
    await dir.driveOwnerLog(uid, 'drive.archive_deleted', `archive ${gen}; shares ended=${r.shares.length}`);
    return json({ ok: true });
  }
  const body = await readJsonBody(request, MAX_BODY);
  if (sub === '/nodes') {
    if (request.method !== 'PUT') return methodNotAllowed('PUT');
    assertIntent(request);
    if (!Array.isArray(body.nodes) || !body.nodes.length || body.nodes.length > 500) return invalid('nodes must list 1–500 items.');
    const list = [];
    for (const n of body.nodes) {
      if (!isObj(n) || typeof n.id !== 'string' || !NODE_ID_RE.test(n.id)) return invalid('Each item needs its id.');
      const name = encField(n.name, MAX_NAME_CT);
      const meta = n.meta === undefined ? undefined : n.meta === null ? null : encField(n.meta, MAX_META_CT);
      const fk = n.fk === undefined ? undefined : encField(n.fk, MAX_FK_CT);
      if (!name || meta === '' || (n.meta !== undefined && n.meta !== null && !meta) || (n.fk !== undefined && !fk)) return invalid('Each item needs name (and may have meta, fk) as {iv, ct}.');
      list.push({ id: n.id, name, ...(meta === undefined ? {} : { meta }), ...(fk === undefined ? {} : { fk }) });
    }
    const refused = await ownerStepUp(request, env, url, dir, uid, body);
    if (refused) return refused;
    const r = await driveStub(env, uid).restoreArchiveNodes(uid, gen, list);
    if (!r.ok) return fromDir(r);
    await dir.setDriveUsed(uid, r.used);
    return json({ ok: true, restored: r.restored, left: r.left });
  }
  if (request.method !== 'POST') return methodNotAllowed('POST');
  assertIntent(request);
  const old = {};
  if (body.escrowPrivOld !== undefined) {
    if (!isObj(body.escrowPrivOld) || Object.keys(body.escrowPrivOld).length > 64) return invalid('escrowPrivOld must be { kid: { pub, data } } (at most 64).');
    const inUse = new Set(await dir.escrowKidsInUse());
    const currentKid = pol.escrowPub ? await escrowKid(pol.escrowPub) : null;
    for (const [kid, x] of Object.entries(body.escrowPrivOld)) {
      const pub = isObj(x) ? escrowJwk(x.pub) : null;
      const data = isObj(x) ? wrapData(x.data) : null;
      if (!pub || !data || await escrowKid(pub) !== kid || kid === currentKid || !inUse.has(kid)) return err(400, 'key_mismatch', 'An earlier escrow key is not one a user’s Drive is still wrapped to.');
      old[kid] = data;
    }
  }
  const refused = await ownerStepUp(request, env, url, dir, uid, body);
  if (refused) return refused;
  const r = await driveStub(env, uid).finishArchive(uid, gen, { old });
  if (!r.ok) return fromDir(r);
  await dir.driveOwnerLog(uid, 'drive.archive_restored', `archive ${gen}; earlier escrow keys back: ${Object.keys(old).length}`);
  return json({ ok: true });
}

/**
 * POST /api/private/drive/start-over — the owner starts over without a
 * recovery kit (after AUTHN recovery, docs/DRIVE.md §3): `{ confirm: <the
 * owner's username>, driveSalt, set: [the new pw wrap], escrowPub, escrowPriv,
 * escrowSignPub, escrowSignPriv, escrowSig, current | reauth }`, all made in
 * the owner's browser under a new DK. Only when the owner's Drive has no wrap
 * the owner's credentials can open now (no passkey or recovery-code wrap, and
 * no password wrap or only a stale one), only with the typed username and the
 * step-up. The owner's Drive as it was (items, R2 objects, wraps, sealed
 * keys — all still sealed under the old DK) is kept as an archive that a kit
 * for the old DK can restore later; the Drive is set up again with the new
 * keys, and the new escrow pair counts as a rotation (the version goes up).
 * The owner reset is recorded in the Directory (its epoch, the new kid and
 * signing key): users' browsers move their Drives to the new key by
 * themselves once per reset (docs/DRIVE.md §3; the maintainer's accepted
 * exception to the signed-key pin). No user's Drive or wrap is touched here.
 * Recorded as `drive.owner_reset`.
 */
async function startOver(request, env, url, dir, uid, pol, username, body) {
  if (typeof body.confirm !== 'string' || !username || body.confirm !== username) return err(400, 'confirm_required', 'Type your username to confirm.');
  const cur = await driveStub(env, uid).summary(uid);
  if (!pol.escrowPub && typeof cur.escrowPriv !== 'string' && !pol.escrowSignPub) return err(409, 'nothing_to_reset', 'There is no escrow key yet: open your Drive to set it up.');
  const usable = cur.wraps.some((w) => w.kind === 'passkey' || w.kind === 'recovery' || (w.kind === 'pw' && !cur.pwStale));
  if (usable) return err(409, 'drive_unlockable', 'Your Drive can still be unlocked (a password, passkey or recovery-code key of yours opens it): unlock it instead.');
  if (typeof body.driveSalt !== 'string' || !SALT_RE.test(body.driveSalt)) return invalid('driveSalt must be 16 bytes, base64url.');
  const w = Array.isArray(body.set) && body.set.length === 1 && isObj(body.set[0]) ? body.set[0] : null;
  const pwData = w && w.kind === 'pw' && w.ref === 'pw' ? wrapData(w.data) : null;
  const jwk = escrowJwk(body.escrowPub);
  const signJwk = escrowJwk(body.escrowSignPub);
  const escrowPriv = wrapData(body.escrowPriv);
  const escrowSignPriv = wrapData(body.escrowSignPriv);
  if (!pwData || !jwk || !signJwk || !escrowPriv || !escrowSignPriv || typeof body.escrowSig !== 'string' || !SIG_RE.test(body.escrowSig) || typeof body.kcv !== 'string' || !KCV_RE.test(body.kcv)) {
    return invalid('Send { confirm, driveSalt, set: [a pw wrap], escrowPub, escrowPriv, escrowSignPub, escrowSignPriv, escrowSig, kcv } made under the new Drive key.');
  }
  const newKid = await escrowKid(jwk);
  if ((pol.escrowPub && newKid === await escrowKid(pol.escrowPub)) || (pol.escrowSignPub && signJwk === escrowJwk(JSON.parse(pol.escrowSignPub)))) return invalid('Starting over needs a new escrow key and a new signing key.');
  if (!(await endorsed(signJwk, jwk, body.escrowSig))) return invalid('The new escrow key must be signed by the new signing key (escrowSig).');
  const refused = await ownerStepUp(request, env, url, dir, uid, body);
  if (refused) return refused;
  const archived = await driveStub(env, uid).startOver(uid);
  const r = await driveStub(env, uid).setKeys(uid, { driveSalt: body.driveSalt, set: [{ kind: 'pw', ref: 'pw', data: pwData }], escrowPriv, escrowSignPriv, newEscrowKid: newKid, firstEscrow: !pol.escrowPub, kcv: body.kcv });
  if (!r.ok) return fromDir(r);
  const e = await dir.setEscrowPub(uid, jwk, { signPub: signJwk, sig: body.escrowSig });
  if (!e.ok) return fromDir(e);
  const reset = await dir.recordOwnerReset(uid, { kid: newKid, signPub: signJwk });
  const ver = await escrowVersionOf({ escrowPub: jwk }, await driveStub(env, uid).summary(uid));
  await dir.driveOwnerLog(uid, 'drive.owner_reset', `new escrow key version=${ver?.version ?? '?'} key=${short(newKid)}; reset ${reset.reset?.epoch ?? '?'}; old Drive kept as archive ${archived.gen}`);
  return json({ ok: true, escrowVersion: ver, archive: archived.gen, ownerReset: reset.reset ?? null });
}

/**
 * PUT /api/private/drive/kit/keys — the owner's browser, having opened DK
 * with the recovery kit, puts back sealed escrow keys from the kit's
 * snapshot that the owner's Drive has lost (or holds in a form that does not
 * open): `{ escrowPriv?: { pub, data }, escrowSignPriv?: { pub, data },
 * escrowPrivOld?: { <kid>: { pub, data } }, current | reauth }` (`data`
 * re-sealed under the owner's DK, `pub` the public key the browser derived
 * from the snapshot's private key). Each is accepted only for the key it
 * claims to be: the escrow key only when `pub` is the server's escrowPub, the
 * signing key only when it is escrowSignPub, an earlier key only when its kid
 * is one a user's escrow wrap is still for (drive.escrowKid:*). Always with
 * the owner's password or a passkey, as any change of the escrow keys (H-1).
 * Nothing else changes: not escrowPub, escrowSignPub, the version or a wrap.
 */
async function restoreKitKeys(request, env, url, dir, uid, pol, body) {
  const out = {};
  const one = (x) => {
    if (!isObj(x)) return null;
    const pub = escrowJwk(x.pub);
    const data = wrapData(x.data);
    return pub && data ? { pub, data } : null;
  };
  if (body.escrowPriv !== undefined) {
    const k = one(body.escrowPriv);
    if (!k || !pol.escrowPub || await escrowKid(k.pub) !== await escrowKid(pol.escrowPub)) return err(400, 'key_mismatch', 'That escrow key is not the current escrow key.');
    out.escrowPriv = k.data;
  }
  if (body.escrowSignPriv !== undefined) {
    const k = one(body.escrowSignPriv);
    const sp = pol.escrowSignPub ? escrowJwk(JSON.parse(pol.escrowSignPub)) : null;
    if (!k || !sp || k.pub !== sp) return err(400, 'key_mismatch', 'That signing key is not the current signing key.');
    out.escrowSignPriv = k.data;
  }
  if (body.escrowPrivOld !== undefined) {
    if (!isObj(body.escrowPrivOld) || Object.keys(body.escrowPrivOld).length > 64) return invalid('escrowPrivOld must be { kid: { pub, data } } (at most 64).');
    const inUse = new Set(await dir.escrowKidsInUse());
    const currentKid = pol.escrowPub ? await escrowKid(pol.escrowPub) : null;
    out.old = {};
    for (const [kid, x] of Object.entries(body.escrowPrivOld)) {
      const k = one(x);
      if (!k || await escrowKid(k.pub) !== kid || kid === currentKid || !inUse.has(kid)) return err(400, 'key_mismatch', 'An earlier escrow key is not one a user’s Drive is still wrapped to.');
      out.old[kid] = k.data;
    }
  }
  if (out.escrowPriv === undefined && out.escrowSignPriv === undefined && !Object.keys(out.old || {}).length) return invalid('Nothing to restore.');
  const refused = await ownerStepUp(request, env, url, dir, uid, body);
  if (refused) return refused;
  const r = await driveStub(env, uid).restoreEscrowKeys(uid, out);
  if (!r.ok) return fromDir(r);
  await dir.driveOwnerLog(uid, 'drive.kit_keys_restored', [out.escrowPriv ? 'escrow' : '', out.escrowSignPriv ? 'signing' : '', Object.keys(out.old || {}).length ? `earlier: ${Object.keys(out.old).length}` : ''].filter(Boolean).join(', '));
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
async function endShares(env, dir, uid, ids, actor, reason) {
  if (!ids.length) return;
  for (const id of ids) await fileStub(env, id).revoke();
  await dir.endDriveShares(uid, ids, actor, reason);
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
  const rec = await dir.recordShare({ id, uid, kind: 'drive', label: body.label, created: r.created, expires: r.expires, views, lh: clean.acc.lh }, actorId(a));
  if (rec && rec.ok === false) {
    // The (server-chosen) id is someone else's: never take it over.
    await fileStub(env, id).revoke();
    await dir.refund(uid, auth.refund);
    return fromDir(rec);
  }
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
 * reason; each call is recorded in the admin audit (drive.escrow_used, with
 * the reason), not in the user's own activity.
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
 * PUT /api/private/admin/drive/keys/<userId> — the owner, from Admin → Users,
 * for another user (never the owner's own Drive):
 * - after resetting the user's password: `{ driveSalt, set: [{ kind: 'pw',
 *   ref: 'pw', data }], kcv }` — a new `pw` wrap of the user's DK (opened in
 *   the owner's browser through the escrow), only with the Drive's key check
 *   value; nothing else changes (`drive.pw_rewrapped`);
 * - for a user with no Drive yet (just created, or reset before their first
 *   sign-in): `{ first: true, driveSalt, set: [pw, escrow], escrowPin, kcv }`
 *   — the Drive set up in the owner's browser, which knows the password it
 *   set: exactly one `pw` wrap and one `escrow` wrap for the current escrow
 *   key, only while the user's Drive has no wrap at all
 *   (`drive.created_by_owner`: admin audit; a system event for the user).
 */
export async function adminSetUserKeys(request, env, ownerId, targetId) {
  if (request.method !== 'PUT') return methodNotAllowed('PUT');
  assertIntent(request);
  const body = await readJsonBody(request);
  if (targetId === ownerId) return err(400, 'use_own_keys', 'Change your own Drive keys from your Drive.');
  if (typeof body.driveSalt !== 'string' || !SALT_RE.test(body.driveSalt)) return invalid('driveSalt must be 16 bytes, base64url.');
  if (body.remove !== undefined && !(Array.isArray(body.remove) && body.remove.length === 0)) return invalid('Nothing is removed here.');
  const dir = directory(env);
  const refs = await dir.credentialRefs(targetId);
  if (!refs) return err(404, 'not_found', 'User not found.');
  if (!refs.drive) return err(409, 'drive_disabled', 'This user’s role has no Drive.');
  const cur = await driveStub(env, targetId).summary(targetId);
  const list = Array.isArray(body.set) ? body.set : [];
  const pwW = list.find((w) => isObj(w) && w.kind === 'pw' && w.ref === 'pw');
  const pwData = pwW ? wrapData(pwW.data) : null;
  const kcvOk = typeof body.kcv === 'string' && KCV_RE.test(body.kcv);
  if (body.first === true) {
    if (cur.wraps.length) return err(409, 'drive_exists', 'This user already has a Drive: its keys are never replaced.');
    const pol = await dir.driveAccess(targetId);
    const esc = list.find((w) => isObj(w) && w.kind === 'escrow' && w.ref === 'escrow');
    const escData = esc ? wrapData(esc.data) : null;
    const pin = encField(body.escrowPin, MAX_PIN_CT);
    if (list.length !== 2 || !pwData || !escData || !pin) return invalid('Send { first: true, driveSalt, set: [a pw wrap, the escrow wrap], escrowPin, kcv }.');
    if (!kcvOk) return err(400, 'kcv_required', 'Send the Drive key’s check value (kcv).');
    if (!pol.ok || !pol.escrowPub) return err(409, 'escrow_not_ready', 'There is no escrow key yet.');
    if (escrowWrapKid(escData) !== await escrowKid(pol.escrowPub)) return invalid('The escrow wrap must be for the current escrow key.');
    const r = await driveStub(env, targetId).setKeys(targetId, { driveSalt: body.driveSalt, set: [{ kind: 'pw', ref: 'pw', data: pwData }, { kind: 'escrow', ref: 'escrow', data: escData }], escrowPin: pin, kcv: body.kcv, onlyIfEmpty: true });
    if (!r.ok) return fromDir(r);
    await dir.setEscrowKid(targetId, escrowWrapKid(escData));
    const logged = await dir.driveAdminAction(ownerId, targetId, 'drive.created_by_owner', 'with the password the owner set');
    if (!logged.ok) return fromDir(logged);
    return json({ ok: true, created: true });
  }
  if (list.length !== 1 || !pwData) return invalid('Send { driveSalt, set: [{ kind: "pw", ref: "pw", data }], kcv } (a password wrap only).');
  if (!cur.wraps.length) return err(409, 'no_drive', 'This user has no Drive yet: set it up with { first: true }.');
  if (!kcvOk) return err(400, 'kcv_required', 'Send the Drive key’s check value (kcv).');
  if (cur.kcv && !sameKcv(body.kcv, cur.kcv)) return err(409, 'kcv_mismatch', 'That key is not this Drive’s key.');
  const logged = await dir.driveAdminAction(ownerId, targetId, 'drive.pw_rewrapped', 'after a password reset');
  if (!logged.ok) return fromDir(logged);
  const r = await driveStub(env, targetId).setKeys(targetId, { driveSalt: body.driveSalt, set: [{ kind: 'pw', ref: 'pw', data: pwData }], remove: [], kcv: body.kcv });
  return r.ok ? json({ ok: true }) : fromDir(r);
}

/** A few attempts at an operation that may fail transiently (R2, a Durable Object). */
async function retry(fn, tries = 3) {
  for (let k = 1; ; k++) {
    try {
      return await fn();
    } catch (e) {
      if (k >= tries || (e && e.status && e.status < 500)) throw e;
      await new Promise((res) => setTimeout(res, 50 * k));
    }
  }
}

/**
 * The account is being deleted: its Drive goes, with every share of it —
 * before the account itself (the caller deletes the account only when this
 * succeeded, so a failure leaves everything in place for a retry). The shares
 * end first (recipients get "gone"), then the ciphertext and the Drive's
 * state; each step is retried and safe to repeat.
 */
export async function destroyDrive(env, dir, uid, actor) {
  binding(env, 'FILES');
  const stub = () => driveStub(env, uid);
  const { shares } = await retry(() => stub().allShares(uid));
  for (const id of shares) await retry(() => fileStub(env, id).revoke());
  if (shares.length) await retry(() => dir.endDriveShares(uid, shares, actor, 'account deleted'));
  const r = await retry(() => stub().destroy(uid));
  // A share made in between.
  for (const id of r.shares.filter((x) => !shares.includes(x))) await retry(() => fileStub(env, id).revoke());
}

/**
 * The account's password changed (`reset`: set by the owner): the Drive's
 * `pw` wrap opens only with the old password now (docs/DRIVE.md §3).
 */
export async function drivePasswordChanged(env, uid, { reset = false } = {}) {
  const c = await directory(env).credentialRefs(uid);
  if (!c || !c.drive) return null;
  return driveStub(env, uid).passwordChanged(uid, { reset });
}

/**
 * AUTHN owner recovery (src/routes/auth.js): the owner's passkeys and recovery
 * codes are gone, so their Drive wraps go too, and the password is new, so the
 * `pw` wrap is marked stale: once the owner's recovery kit has opened the
 * Drive, the browser writes the new one without a second confirmation. No key
 * is created or changed here.
 */
export async function driveOwnerRecovered(env, ownerId) {
  const c = await directory(env).credentialRefs(ownerId);
  if (!c || !c.drive) return;
  await syncCredentialWraps(env, ownerId);
  await driveStub(env, ownerId).markPwStale(ownerId);
}
