// drive.js — /api/private/drive*: the signed-in user's Drive (docs/DRIVE.md
// §6). Session only (API keys are refused by authenticate()). Every
// state-changing call goes through the same CSRF guards as the rest of the
// private API, in authenticate() before anything else runs (src/lib/auth.js
// checkCsrf): Sec-Fetch-Site, the request shape (a JSON body, a chunk or the
// intent header), then the session's CSRF token; and then each route's own
// (JSON body, intent header, upload token).
//
// The key model v2 (docs/DRIVE.md §3): the server derives the user's KEKs
// (the Directory holds the root MEK, the sub-MEKs and the user salt) and
// hands them to the user's session, or to the owner acting as the user; the
// browser encrypts the content with a random DEK and seals the DEK, the name
// and the metadata under KEK(current sub-MEK). The Worker checks that what
// is stored opens under that KEK (so it can re-seal it later) and never keeps
// anything it opened. What the owner does in the Drive while impersonating is
// recorded as the user's own action: it shows in the user's activity as
// theirs, with no trace of the impersonation, and the admin audit keeps the
// owner as the real actor (docs/DRIVE.md §9).
//
// Drives made before the key model v2 are upgraded (docs/DRIVE.md §3.3): the
// old Drive key is opened in a browser (the user's, or the owner's through
// the escrow of that release), every item is re-sealed under the user's KEK
// and checked here, and only then do the old key wraps go.

import { json, err, readJsonBody, readCappedBody, assertIntent, assertNotCrossSite, decodePathSegment, methodNotAllowed, appendCookies, SECURITY_HEADERS } from '../lib/http.js';
import { authenticate, actorId } from '../lib/auth.js';
import { requireTurnstile, TURNSTILE_ACTIONS } from '../lib/turnstile.js';
import { directory, ipContext } from '../lib/guard.js';
import { stepUpFrom, afterRefusal } from './stepup.js';
import { genId, genToken, genDeleteToken, hashToken } from '../lib/ids.js';
import { MAX_BODY, MAX_BURN_RECORD, driveStub, fileStub } from '../lib/store.js';
import { validateCreate, FormatError, expireSeconds, MAX_VIEWS } from '../../public/js/format.js';
import { MAX_CHUNK_CT } from '../../public/js/files.js';
import { KEY_RE, MEK_ID_RE, keyCheckValue, saltCheckValue, sameCheck, keyBytes, isAtRest, openAtRest, openLinkKey } from '../../public/js/drivekeys.js';
import { b64urlFromBytes } from '../../public/js/bytes.js';
import { binding } from '../lib/config.js';
import { HARD_MAX_DRIVE_BYTES } from '../lib/settings.js';
import { NODE_ID_RE, ROOT, KEYS_PAGE } from '../drive-do.js';
import { handleReverseOwner } from './reverse.js';
import { driveTypeRefusal, sealedTypeRefusal, typedPolicy } from '../lib/drivepolicy.js';
import { userKeys, keksOf, openItem, checkNewItem, checkField, checkLinkKey, openLink, fieldKeys, toRest, fromRest } from '../lib/mek.js';

const fromDir = (r) => {
  const extra = {};
  for (const k of ['max', 'used', 'quota', 'policy', 'refused', 'retryAfter', 'v1Items', 'v1Links']) if (r[k] !== undefined) extra[k] = r[k];
  return err(r.status, r.error, r.message, Object.keys(extra).length ? extra : undefined);
};
/** Attach a sliding-session cookie refresh (session + CSRF token cookies) to a response. */
const withAuth = (a, res) => appendCookies(res, a.setCookie);
const invalid = (message) => err(400, 'invalid', message);
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// ── validation of what the browser sends ────────────────────────────────────
const B64URL_RE = /^[A-Za-z0-9_-]+$/;
// The largest sealed fields the browser makes (a 255-byte name seals to about
// 362 characters, the metadata JSON to about 300), with room to spare; they
// count towards the capacity as well.
export const MAX_NAME_CT = 512;
export const MAX_META_CT = 1024;
/** A sealed DEK (32 bytes + the tag) and a sealed link key (PKCS#8 P-256). */
const MAX_DEK_CT = 128;
const MAX_LINK_CT = 256;
/** Personal kit checks per session and window (seconds). */
export const KIT_VERIFY_MAX = 30;
export const KIT_VERIFY_WINDOW = 600;
const MAX_SHARE_NODES = 10000;

/** An encrypted field {iv, ct} (base64url, 12-byte IV) as stored JSON text, or null if invalid. */
export function encField(v, maxCt) {
  if (!isObj(v) || Object.keys(v).length !== 2 || typeof v.iv !== 'string' || typeof v.ct !== 'string') return null;
  if (!/^[A-Za-z0-9_-]{16}$/.test(v.iv)) return null;
  // At least the 16-byte GCM tag.
  if (v.ct.length < 22 || v.ct.length > maxCt || !B64URL_RE.test(v.ct)) return null;
  return JSON.stringify({ iv: v.iv, ct: v.ct });
}

/**
 * An item's key fields as the browser sends them: `ks` (the item's 32-byte
 * salt) and `mek` (the sub-MEK it sealed under) → { ks, mek } or null.
 */
function keyFields(body) {
  return typeof body.ks === 'string' && KEY_RE.test(body.ks) && typeof body.mek === 'string' && MEK_ID_RE.test(body.mek) ? { ks: body.ks, mek: body.mek } : null;
}

/**
 * Drop the Drive wraps (of the release before: a Drive still waiting for its
 * upgrade) of passkeys and recovery codes the account no longer has: a removed
 * passkey or replaced codes lose theirs at once, the owner's too, while Drives
 * wait (the escrow and the owner's other sign-in methods still open the old
 * Drive key). Only the wraps an AUTHN owner recovery kept (driveOwnerRecovered)
 * stay while any Drive waits. → the wraps removed (a recovery code spent at
 * sign-in comes back once, so that sign-in can still open the old Drive key
 * for the upgrade).
 */
export async function syncCredentialWraps(env, uid) {
  const dir = directory(env);
  const c = await dir.credentialRefs(uid);
  if (!c || !c.drive) return [];
  const held = c.owner && (await dir.migrationList()).some((r) => r.state !== 'done');
  return (await driveStub(env, uid).pruneWraps(uid, { passkey: c.passkeys, recovery: c.recovery, held })).wraps;
}

const nodeId = (s) => (s === ROOT || NODE_ID_RE.test(s) ? s : null);

/** The owner's password or a passkey (`current` / `reauth`), as for Account; → null or the refusal. */
export async function stepUp(request, env, url, dir, uid, body) {
  const g = await ipContext(env, request);
  const step = await stepUpFrom(body, url); // 400 reauth_required without one
  const r = await dir.verifyCurrent(uid, step.current, { reauth: step.reauth, origin: step.origin, rpId: step.rpId, lockoutOff: g.off.all });
  return r.ok ? null : afterRefusal(env, g, r, fromDir(r));
}

/** The keyring exists (generated on first need): the Directory's Drive policy with the current sub-MEK. */
async function accessWithKeys(dir, uid) {
  let pol = await dir.driveAccess(uid);
  if (pol.ok && pol.enabled && !pol.current) {
    await dir.ensureKeys();
    pol = await dir.driveAccess(uid);
  }
  return pol;
}

/** Everything under /api/private/drive. */
export async function handleDrive(request, env, url) {
  const p = url.pathname;
  const a = await authenticate(request, env); // session only: an API key gets 403
  const uid = a.user.id;
  const dir = directory(env);
  const pol = await accessWithKeys(dir, uid);
  if (!pol.ok) return fromDir(pol);
  const drive = () => driveStub(env, uid);

  // Record a Drive action like any other: the user's own, also when the owner
  // takes it while impersonating them (the admin audit has the real actor).
  const driveLog = (action, detail) => dir.driveLog(actorId(a), uid, action, detail);

  if (p === '/api/private/drive') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    if (!pol.enabled) return withAuth(a, json({ enabled: false, capacity: pol.capacity, maxFile: pol.maxFile, used: pol.used }));
    const s = await drive().summary(uid);
    // A Drive of the release before with nothing in it: nothing to upgrade.
    if (pol.migration === 'pending' && s.items === 0 && !s.migration.v1Links) await finishUpgrade(env, dir, uid, { owner: pol.owner, byOwner: null });
    const pending = pol.migration === 'pending' && !(s.items === 0 && !s.migration.v1Links);
    const out = {
      enabled: true, capacity: pol.capacity, maxFile: pol.maxFile, used: s.used,
      received: s.received, receivedFailed: s.receivedFailed, current: pol.current,
      // The personal kit against the keys now: the page's "download a new kit" notice (no key detail).
      kit: pol.kit,
      migration: pending || s.migration.v1Items || s.migration.v1Links ? { pending: true, v1Items: s.migration.v1Items, v1Links: s.migration.v1Links, legacy: s.migration.wraps > 0 } : null,
    };
    if (s.used !== pol.used) await dir.setDriveUsed(uid, s.used);
    return withAuth(a, json(out));
  }

  if (!pol.enabled) return err(403, 'drive_disabled', 'Your role does not include a Drive.');

  // The user's KEKs for this session (docs/DRIVE.md §3): no prompt, no secret
  // of the user's; the owner acting as the user gets the user's (admin audit).
  // A POST with a JSON body ({}): it may make the account's salt and writes to
  // the admin audit, so it is a change like any other (the CSRF token too).
  if (p === '/api/private/drive/keys') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    await readJsonBody(request);
    const s = await drive().summary(uid);
    const k = await userKeys(env, uid, { meks: s.meks, createSalt: nothingSealed(s) });
    if (a.actor) await dir.driveKeysUsed(a.actor.id, uid, 'opened while acting as the user');
    return withAuth(a, json(keysOut(k)));
  }

  // Reverse shares and the files they received (docs/REVERSE.md §6.1).
  if (p === '/api/private/drive/reverse' || p === '/api/private/drive/received' || p.startsWith('/api/private/drive/received/')) {
    const r = await handleReverseOwner(request, env, url, a, pol);
    if (r) return withAuth(a, r);
  }

  // A restore from a personal kit is the owner's alone, from Admin → Security → Keys (docs/DRIVE.md
  // §3.1): never the user's (it could change what opens the Drive), nor the owner's acting as a user.
  if (p === '/api/private/drive/kit/restore' || p === '/api/private/drive/kit/items') {
    return err(403, 'owner_only', 'Only the administrator restores from a personal kit (Admin → Security → Keys).');
  }
  // The personal kit (docs/DRIVE.md §3.1): the user's own, never while acting as a user.
  if (p === '/api/private/drive/kit' || p.startsWith('/api/private/drive/kit/')) {
    if (a.actor) return err(403, 'impersonating', 'A personal kit is the user’s own: the key kit (Admin → Security → Keys) covers every Drive.');
    return withAuth(a, await kitRoute(request, env, url, dir, a, driveLog));
  }

  // The upgrade of a Drive made before the key model v2, in the user's own browser.
  if (p === '/api/private/drive/migrate' || p.startsWith('/api/private/drive/migrate/')) {
    if (a.actor) return err(403, 'impersonating', 'Upgrade this user’s Drive from Admin → Security → Keys.');
    return withAuth(a, await upgradeRoute(request, env, url, dir, uid, p.slice('/api/private/drive/migrate'.length), { owner: pol.owner, byOwner: null, state: pol.migration, actor: uid }));
  }

  if (p === '/api/private/drive/folders') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const body = await readJsonBody(request);
    const parent = typeof body.parent === 'string' ? nodeId(body.parent) : null;
    const name = encField(body.name, MAX_NAME_CT);
    const meta = body.meta === undefined || body.meta === null ? null : encField(body.meta, MAX_META_CT);
    const kf = keyFields(body);
    const id = body.id === undefined ? genId('f').slice(1) : typeof body.id === 'string' && NODE_ID_RE.test(body.id) ? body.id : null;
    if (!parent || !name || !id || !kf || (meta === null && body.meta !== undefined && body.meta !== null)) return invalid('Send { id?, parent, name: {iv, ct}, meta?, ks, mek }.');
    const keys = await userKeys(env, uid);
    const mfp = await checkNewItem(uid, keys, { kind: 'dir', ...kf, name, meta });
    // The role's folder-depth limit (maxFolderDepth): the Drive checks it against its tree.
    const r = await drive().createFolder(uid, { id, parent, name, meta, ...kf, mfp, capacity: pol.capacity ?? HARD_MAX_DRIVE_BYTES, maxDepth: pol.policy.maxFolderDepth });
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
    const meta = encField(body.meta, MAX_META_CT);
    const dek = encField(body.dek, MAX_DEK_CT);
    const kf = keyFields(body);
    const id = body.id === undefined ? genId('f').slice(1) : typeof body.id === 'string' && NODE_ID_RE.test(body.id) ? body.id : null;
    if (!parent || !name || !meta || !dek || !kf || !id) return invalid('Send { id?, parent, name, meta, size, dek, ks, mek } (sealed fields as {iv, ct}).');
    if (!Number.isSafeInteger(body.size) || body.size < 0 || body.size > HARD_MAX_DRIVE_BYTES) return err(400, 'invalid_size', 'size must be the file’s size in bytes.');
    // The role's file-type rules, as for file shares: checked against what the browser declares.
    const typeRefused = driveTypeRefusal(pol.policy, body.types);
    if (typeRefused) return withAuth(a, typeRefused);
    const keys = await userKeys(env, uid);
    // …and on what is stored: the sealed name's extension and the metadata's type, opened in memory only.
    let sealedRefused = null;
    const mfp = await checkNewItem(uid, keys, { kind: 'file', ...kf, name, meta, dek },
      typedPolicy(pol.policy) ? (n, m) => { sealedRefused = sealedTypeRefusal(pol.policy, n, m, body.types); } : null);
    if (sealedRefused) return withAuth(a, sealedRefused);
    const uploadToken = genToken();
    // One file added to the Drive: the quotas of kind drive-upload count it
    // (and those of kind drive-bytes its size) now, and give it back when the
    // Drive refuses it (below: full, too deep…) or the upload never completes
    // (deleted unfinished, or purged: the Drive reports it).
    const quota = await dir.authorizeDriveUpload(uid, { size: body.size });
    if (!quota.ok) return withAuth(a, fromDir(quota));
    let r;
    try {
      r = await drive().createFile(uid, {
        id, parent, name, meta, size: body.size, dek, ...kf, mfp, uploadHash: await hashToken(uploadToken),
        capacity: pol.capacity ?? HARD_MAX_DRIVE_BYTES, maxFile: pol.maxFile ?? HARD_MAX_DRIVE_BYTES, pendingSec: pol.pendingSec,
        maxDepth: pol.policy.maxFolderDepth,
      });
    } catch (e) {
      await dir.refund(uid, quota.refund);
      throw e;
    }
    if (!r.ok) {
      await dir.refund(uid, quota.refund);
      return withAuth(a, fromDir(r));
    }
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
      return withAuth(a, json({ ok: true, ch: r.ch }));
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
      if (patch.name !== undefined || patch.meta !== undefined) {
        // A new name or metadata is sealed under the item's own keys (its mek and salt).
        const kf = keyFields(body);
        if (!kf) return invalid('A new name or metadata comes with the item’s ks and mek.');
        Object.assign(patch, kf);
        const keys = await userKeys(env, uid, { meks: [kf.mek] });
        if (patch.name !== undefined) await checkField(uid, keys, kf, 'name', patch.name);
        if (patch.meta) await checkField(uid, keys, kf, 'meta', patch.meta);
      }
      const r = await drive().patchNode(uid, id, { ...patch, capacity: pol.capacity ?? HARD_MAX_DRIVE_BYTES, maxDepth: pol.policy.maxFolderDepth });
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
      if (r.unfinished?.length) await dir.refundDriveUploads(uid, r.unfinished); // the files and their bytes
      await endShares(env, dir, uid, r.shares, actorId(a));
      // Reverse shares of a deleted folder end with it (no FileShare record to revoke).
      if (r.reverse.length) await dir.endDriveShares(uid, r.reverse, actorId(a));
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

/**
 * Nothing in this Drive is sealed under a key its user salt gives (no item,
 * no link key): a missing salt may then be made anew. A salt that was lost
 * while anything is sealed under it is only restored (a kit, an import).
 */
const nothingSealed = (s) => s.items === 0 && s.links === 0;

/** A user's KEKs as a session gets them. */
function keysOut(k) {
  const b = (x) => (x ? b64urlFromBytes(x) : undefined);
  return {
    userId: k.userId, current: k.current, changing: k.changing,
    keys: [...k.keks].map(([mekId, v]) => ({ mekId, fp: v.fp, from: v.from, until: v.until, kek: b(v.kek), ...(v.kekOld ? { kekOld: b(v.kekOld) } : {}) })),
    missing: k.missing, broken: k.broken,
  };
}

const uploadTokenOf = (request) => {
  const t = request.headers.get('x-upload-token') || '';
  return /^[A-Za-z0-9_-]{43}$/.test(t) ? t : null;
};

// ── the personal kit (docs/DRIVE.md §3.1) ───────────────────────────────────
/**
 * /api/private/drive/kit… (the user's own):
 * - `GET …/kit` — the kit's state against the keys now: the key version and
 *   its date, the last download (its date and version) and whether it is
 *   stale (the keys changed since); no key detail;
 * - `POST …/kit` `{ current | reauth }` — the kit's content, for the browser
 *   to seal under a passphrase: the id, the username, the user salt, the key
 *   version and the KEK of every sub-MEK the Drive uses (and the current
 *   one), after the step-up (`drive.kit_exported`); the download is recorded
 *   against the key version, for the notice;
 * - `POST …/kit/verify` `{ keks: { mekId: check }, salt: check }` — read-only:
 *   each check value compared here in constant time → match / mismatch /
 *   absent per sub-MEK, with each one's dates, and the key version now
 *   (`drive.kit_verified`); at most KIT_VERIFY_MAX per session per
 *   KIT_VERIFY_WINDOW.
 * Both POSTs are Account-page changes like the others: with Turnstile on,
 * each needs a fresh CAPTCHA token for "account", checked after the body is
 * read and before the step-up (so a password guess costs a token) and the
 * rate limit. A restore from the kit is the owner's (src/routes/keys.js,
 * Admin → Security → Keys): `…/kit/restore` and `…/kit/items` answer 403
 * above.
 */
async function kitRoute(request, env, url, dir, a, driveLog) {
  const p = url.pathname;
  const uid = a.user.id;
  const drive = driveStub(env, uid);
  if (p === '/api/private/drive/kit') {
    if (request.method === 'GET') {
      const st = await dir.userKitStatus(uid);
      return st.ok ? json({ version: st.version, versionAt: st.versionAt, last: st.last, stale: st.stale }) : fromDir(st);
    }
    if (request.method !== 'POST') return methodNotAllowed('GET, POST');
    assertIntent(request);
    const body = await readJsonBody(request);
    await requireTurnstile(env, request, TURNSTILE_ACTIONS.account);
    const refused = await stepUp(request, env, url, dir, uid, body);
    if (refused) return refused;
    const s = await drive.summary(uid);
    const k = await userKeys(env, uid, { meks: s.meks, createSalt: nothingSealed(s) });
    await driveLog('drive.kit_exported', `sub-MEKs: ${k.keks.size}`);
    const o = keysOut(k);
    // What this kit holds, against the key version its KEKs were derived at.
    const st = await dir.userKitDownloaded(uid, { version: k.version, meks: [...k.keks.keys()] });
    return json({
      kit: { id: uid, username: a.user.username, userSalt: k.salt, current: k.current, keyVersion: k.version, keks: o.keys.map(({ kekOld, ...x }) => x) }, // eslint-disable-line no-unused-vars
      missing: k.missing, broken: k.broken,
      status: st.ok ? { version: st.version, versionAt: st.versionAt, last: st.last, stale: st.stale } : null,
    });
  }
  if (p === '/api/private/drive/kit/verify') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    assertIntent(request);
    const body = await readJsonBody(request);
    await requireTurnstile(env, request, TURNSTILE_ACTIONS.account);
    const rl = await drive.hit(uid, `kitcheck:${a.claims?.sid || 'none'}`, KIT_VERIFY_MAX, KIT_VERIFY_WINDOW);
    if (!rl.ok) return err(429, 'rate_limited', 'Too many kit checks: try again in a few minutes.', { retryAfter: rl.retryAfter });
    const given = isObj(body.keks) ? body.keks : {};
    const s = await drive.summary(uid);
    const all = await userKeys(env, uid, { all: true });
    const inUse = new Set(s.meks);
    const out = [];
    for (const [mekId, v] of all.keks) {
      const g = typeof given[mekId] === 'string' ? given[mekId] : null;
      const result = g === null ? 'absent' : sameCheck(g, await keyCheckValue(v.kek, 'kek')) ? 'match' : 'mismatch';
      out.push({ mekId, fp: v.fp, from: v.from, until: v.until, inUse: inUse.has(mekId), current: mekId === all.current, result });
    }
    const salt = typeof body.salt === 'string' ? (sameCheck(body.salt, await saltCheckValue(all.salt, uid)) ? 'match' : 'mismatch') : 'absent';
    const extra = Object.keys(given).filter((id) => !all.keks.has(id)).slice(0, 100);
    const complete = salt === 'match' && out.filter((x) => x.inUse || x.current).every((x) => x.result === 'match');
    await driveLog('drive.kit_verified', `${complete ? 'complete' : 'incomplete'}: salt ${salt}; KEKs ${out.filter((x) => x.result === 'match').length}/${out.length}`);
    return json({ complete, salt, keks: out, extra, version: all.version, now: Math.floor(Date.now() / 1000) });
  }
  return err(404, 'not_found', 'Not found.');
}

/** "n.<id>" / "r.<id>" (a page cursor of sealedPage) → { kind, id } or null. */
export function parseAfter(v) {
  const m = /^([nr])\.([A-Za-z0-9_-]{22,23})$/.exec(v || '');
  return m ? { kind: m[1], id: m[2] } : null;
}

/**
 * Does `salt` open this account's Drive? It is tried (with the KEK and the
 * field keys it gives, under the root and during a root change the previous
 * one) on one of each kind of thing sealed under it, in turn: an item, a link
 * key, a received item, a link key of the release before kept at rest
 * (`extra`: the owner's kit material, Directory saltRestore). →
 * 'ok' | 'wrong' | 'empty' (nothing is sealed under it) | 'has' (the account
 * has a salt: nothing to restore) | 'unknown' (no such account) |
 * 'unreadable' (what it holds is sealed under sub-MEKs nobody has here).
 */
export async function saltCheck(env, dir, uid, salt, { ownerId = null, extra = null } = {}) {
  const drive = driveStub(env, uid);
  const probe = async (p) => {
    const r = await dir.saltRestore(uid, salt, p, { ownerId, extra });
    if (!r.ok) return r.error === 'exists' ? 'has' : r.error === 'invalid' ? 'unknown' : 'unreadable';
    return r;
  };
  const keysOf = (r, k) => [r[k], r[`${k}Old`]].filter(Boolean).map(keyBytes);
  // An item, else a link key, under a sub-MEK this server (or the owner's kit) has: the first of each sub-MEK in turn.
  const page = await drive.sealedPage(uid, { limit: 50 });
  let unreadable = false;
  for (const mek of [...new Set(page.items.map((i) => i.mek))]) {
    const item = page.items.find((i) => i.mek === mek);
    const r = await probe({ mek });
    if (r === 'unreadable') { unreadable = true; continue; }
    if (typeof r === 'string') return r;
    try { const got = await openItem(uid, keysOf(r, 'kek'), item); got.name.fill(0); if (got.dek) got.dek.fill(0); return 'ok'; } catch { return 'wrong'; }
  }
  for (const link of page.links) {
    const r = await probe({ mek: link.mek, field: 'linkKey' });
    if (r === 'unreadable') { unreadable = true; continue; }
    if (typeof r === 'string') return r;
    try {
      const fks = keysOf(r, 'fieldKey');
      const sealed = JSON.parse(await fromRest({ cur: { linkKey: fks[0] }, old: fks[1] ? { linkKey: fks[1] } : null }, uid, 'linkKey', link.id, link.priv));
      for (const kek of keysOf(r, 'kek')) {
        try { (await openLinkKey(kek, { userId: uid, mekId: link.mek, linkId: link.id }, sealed)).fill(0); return 'ok'; } catch { /* the next one */ }
      }
    } catch { /* does not open */ }
    return 'wrong';
  }
  // Items sealed only under sub-MEKs nobody has here: the salt cannot be checked (nor used).
  if (unreadable) return 'unreadable';
  // Only values the field layer seals: a received item, a link key of the release before.
  const rest = await drive.atRestPage(uid, { after: { kind: 'n', id: '' }, limit: 1 });
  const rec = rest.received.find((x) => isAtRest(x.name));
  const legacy = rec ? null : (await drive.legacyPage(uid, { limit: 1 })).links.find((l) => isAtRest(l.priv));
  if (!rec && !legacy) return 'empty';
  const field = rec ? 'received' : 'linkKey';
  const r = await probe({ field });
  if (typeof r === 'string') return r;
  for (const k of keysOf(r, 'fieldKey')) {
    try { await openAtRest(k, { userId: uid, field, ref: rec ? `name:${rec.id}` : legacy.id }, rec ? rec.name : legacy.priv); return 'ok'; } catch { /* the next one */ }
  }
  return 'wrong';
}

// ── the upgrade of a Drive made before the key model v2 (docs/DRIVE.md §3.3) ──
const LINK_ID_RE = /^r[A-Za-z0-9_-]{22}$/;

/**
 * The upgrade's routes, for the user's own Drive (`byOwner` null) or, from
 * Admin, for a user's Drive (`byOwner`: the owner's id), under `sub`:
 * - `GET ''` — what is left (items and link keys sealed the old way) and what
 *   opens the old Drive key: the user's own wraps and salt; for the owner's
 *   own Drive also the sealed escrow keys (to open users' Drives);
 * - `GET /items?after=` — a page of the old items (their sealed fields);
 * - `PUT ''` `{ items: [{ id, ks, mek, name, meta?, dek? }], links: [{ id,
 *   mek, priv }] }` — the same items re-sealed in the browser under the
 *   user's KEK: each is checked (it opens under the current KEK) and stored
 *   only where the item is still sealed the old way (compare-and-set: a
 *   repeat changes nothing, so the upgrade can stop and resume at any time);
 * - `POST /finish` — verification, a page per call from where the last call
 *   stopped (the cursor is kept in the Drive, so no page is skipped): every
 *   item and link key must open under the user's KEKs; after the last page
 *   the old key wraps go (the owner's own, and the escrow records, only
 *   once every Drive is upgraded). A failure starts the verification over.
 * - `POST /retire` `{ ids, current | reauth }` — link keys of the release
 *   before that the old Drive key does not open (the step-up): those links
 *   end, their keys go and what they received that was not taken in is
 *   listed as failed, so that the upgrade can finish.
 * `state`: the Drive's upgrade state now; `actor`: who confirms a step-up.
 */
async function upgradeRoute(request, env, url, dir, uid, sub, { owner, byOwner, state = null, actor }) {
  const drive = driveStub(env, uid);
  // A Drive holding something of the release before with no upgrade row (audit v2r N5): it waits from now on.
  if (state === null) {
    const L0 = await drive.legacyKeys(uid);
    if (L0.v1Items + L0.v1Links > 0) {
      await dir.migrationSet(uid, { state: 'pending', v1Items: L0.v1Items, v1Links: L0.v1Links });
      state = 'pending';
    }
  }
  if (sub === '' && request.method === 'GET') {
    assertNotCrossSite(request);
    const L = await drive.legacyKeys(uid);
    const st = (await dir.migrationList()).find((r) => r.id === uid);
    const out = { state: st ? st.state : null, v1Items: L.v1Items, v1Links: L.v1Links, archived: L.archived, legacy: L.wraps.length > 0, kcv: L.kcv };
    if (!byOwner) {
      // The user's own ways to open the old Drive key (the escrow wrap is the owner's).
      Object.assign(out, { driveSalt: L.driveSalt, wraps: L.wraps.filter((w) => w.kind !== 'escrow') });
      if (owner) Object.assign(out, { escrowPriv: L.escrowPriv, escrowPrivOld: L.escrowPrivOld, escrowPub: parseJson((await dir.legacyEscrow()).escrowPub) });
    }
    return json(out);
  }
  if (sub === '/items') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    assertNotCrossSite(request);
    const after = url.searchParams.get('after') || '';
    if (after && !NODE_ID_RE.test(after)) return invalid('after must be an item id.');
    const r = await drive.legacyPage(uid, { after });
    // A link key kept at rest comes back as the release before sealed it (the browser opens it with the old Drive key).
    if (r.links.length) {
      const fk = await fieldKeys(env, uid);
      for (const l of r.links) {
        try { l.priv = await fromRest(fk, uid, 'linkKey', l.id, l.priv); } catch { l.priv = null; }
      }
    }
    return json(r);
  }
  if (sub === '') {
    if (request.method !== 'PUT') return methodNotAllowed('GET, PUT');
    assertIntent(request);
    const body = await readJsonBody(request, MAX_BODY);
    // An upgrade that is finished stays finished (a late or repeated upload changes nothing).
    if (state !== 'pending') return err(409, 'already_upgraded', 'This Drive is upgraded already.');
    const list = Array.isArray(body.items) ? body.items : [];
    const lks = Array.isArray(body.links) ? body.links : [];
    if (!list.length && !lks.length) return invalid('Send the upgraded items and / or link keys.');
    if (list.length + lks.length > KEYS_PAGE) return invalid(`At most ${KEYS_PAGE} at once.`);
    const keys = await userKeys(env, uid);
    const items = [];
    for (const x of list) {
      const name = isObj(x) ? encField(x.name, MAX_NAME_CT) : null;
      const meta = isObj(x) && x.meta ? encField(x.meta, MAX_META_CT) : null;
      const dek = isObj(x) && x.dek ? encField(x.dek, MAX_DEK_CT) : null;
      const kf = isObj(x) ? keyFields(x) : null;
      if (!name || !kf || !NODE_ID_RE.test(x.id ?? '') || (x.meta && !meta) || (x.dek && !dek)) return invalid('Each item needs id, ks, mek, name (meta?, dek? as {iv, ct}).');
      const mfp = await checkNewItem(uid, keys, { kind: dek ? 'file' : 'dir', ...kf, name, meta, dek });
      items.push({ id: x.id, ...kf, mfp, name, meta, dek });
    }
    const fk = lks.length ? await fieldKeys(env, uid) : null;
    const links = [];
    for (const l of lks) {
      const priv = isObj(l) ? encField(l.priv, MAX_LINK_CT) : null;
      if (!priv || !LINK_ID_RE.test(l.id ?? '') || !MEK_ID_RE.test(l.mek ?? '')) return invalid('Each link needs id, mek and priv ({iv, ct}).');
      await checkLinkKey(uid, keys, l.id, l.mek, priv);
      links.push({ id: l.id, mek: l.mek, priv: await toRest(fk, uid, 'linkKey', l.id, priv) });
    }
    const r = await drive.applyLegacy(uid, { items, links });
    await dir.migrationSet(uid, { state: 'pending', v1Items: r.v1Items, v1Links: r.v1Links });
    return json({ ok: true, done: r.done, skipped: r.skipped, v1Items: r.v1Items, v1Links: r.v1Links });
  }
  if (sub === '/finish') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    assertIntent(request);
    await readJsonBody(request);
    // The cursor is the server's own: every page is verified, none can be skipped.
    const after = parseAfter((await drive.upgradeCursor(uid)).cursor);
    const v = await verifyPage(env, uid, after);
    if (v.failed.length) {
      await drive.upgradeCursor(uid, null);
      return err(409, 'verify_failed', `${v.failed.length} item(s) do not open under the Drive keys: nothing was removed.`, { failed: v.failed.slice(0, 20) });
    }
    if (v.next) {
      await drive.upgradeCursor(uid, `${v.next.kind}.${v.next.id}`);
      return json({ ok: true, verified: v.verified, next: `${v.next.kind}.${v.next.id}` });
    }
    await drive.upgradeCursor(uid, null);
    const r = await finishUpgrade(env, dir, uid, { owner, byOwner });
    if (!r.ok) return fromDir(r);
    return json({ ok: true, verified: v.verified, done: true, left: r.left, cleanup: r.cleanup });
  }
  if (sub === '/retire') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    assertIntent(request);
    const body = await readJsonBody(request);
    const ids = Array.isArray(body.ids) ? body.ids.filter((x) => typeof x === 'string' && LINK_ID_RE.test(x)) : [];
    if (!ids.length || ids.length !== body.ids.length || ids.length > 1000) return invalid('ids must list 1–1000 reverse-share ids.');
    const refused = await stepUp(request, env, url, dir, actor, body);
    if (refused) return refused;
    const r = await drive.retireLegacyLinks(uid, ids);
    if (r.retired.length) {
      await dir.endDriveShares(uid, r.retired, byOwner ? { id: byOwner, adm: true } : uid, 'link retired');
      const detail = `links=${r.retired.length} received_failed=${r.failed}`;
      if (byOwner) await dir.driveAdminAction(byOwner, uid, 'drive.links_retired', detail);
      else await dir.driveLog(uid, uid, 'drive.links_retired', detail);
      await dir.migrationSet(uid, { state: 'pending', v1Items: r.v1Items, v1Links: r.v1Links });
    }
    return json({ ok: true, retired: r.retired, failed: r.failed, v1Items: r.v1Items, v1Links: r.v1Links });
  }
  return err(404, 'not_found', 'Not found.');
}

const parseJson = (v) => { try { return v ? JSON.parse(v) : null; } catch { return null; } };

/** One page of the upgrade's verification: every item and link key opens under the user's KEKs → { verified, failed, next }. */
async function verifyPage(env, uid, after) {
  const drive = driveStub(env, uid);
  const page = await drive.sealedPage(uid, { after });
  const meks = [...new Set([...page.items.map((i) => i.mek), ...page.links.map((l) => l.mek)])];
  const keys = await userKeys(env, uid, { meks });
  const failed = [];
  for (const it of page.items) {
    try {
      const r = await openItem(uid, keksOf(keys, it.mek), it);
      r.name.fill(0);
      if (r.dek) r.dek.fill(0);
    } catch {
      failed.push(it.id);
    }
  }
  const fk = page.links.length ? await fieldKeys(env, uid) : null;
  for (const l of page.links) {
    try { (await openLink(uid, keys, l.id, l.mek, JSON.parse(await fromRest(fk, uid, 'linkKey', l.id, l.priv)))).pkcs8.fill(0); } catch { failed.push(l.id); }
  }
  return { verified: page.items.length + page.links.length, failed, next: page.next };
}

/**
 * The Drive is upgraded and verified: its old key wraps go (a user's at
 * once; the owner's, with the owner's sealed escrow keys, only when every
 * Drive is upgraded, since they open the others), and the Directory records
 * it; once no Drive is left, the escrow records go too.
 */
async function finishUpgrade(env, dir, uid, { owner, byOwner }) {
  const drive = driveStub(env, uid);
  if (!owner) {
    const d = await drive.dropLegacy(uid, { owner: false });
    if (!d.ok) return d;
  } else {
    const st = await drive.summary(uid);
    if (st.migration.v1Items || st.migration.v1Links) return { ok: false, status: 409, error: 'not_upgraded', message: 'Some items are still sealed by the release before.' };
  }
  const m = await dir.migrationSet(uid, { state: 'done', v1Items: 0, v1Links: 0 });
  if (byOwner) await dir.driveAdminAction(byOwner, uid, 'drive.migrated', 'Drive key upgrade verified; the old key wraps removed');
  else await dir.driveLog(uid, uid, 'drive.migrated', 'Drive key upgrade verified');
  let cleanup = false;
  if (m.left === 0) cleanup = await legacyCleanup(env, dir);
  return { ok: true, left: m.left, cleanup };
}

/**
 * Every Drive is upgraded: the owner's old wraps and sealed escrow keys, and
 * the escrow records, go (after the last upgrade, and after the last account
 * still waiting is deleted). Nothing happens while any Drive waits.
 */
export async function legacyCleanup(env, dir) {
  const { ownerId } = await dir.legacyEscrow();
  if (!ownerId) return false;
  const r = await dir.migrationCleanup(ownerId);
  if (!r.ok || !r.done) return false;
  const d = await driveStub(env, ownerId).dropLegacy(ownerId, { owner: true });
  return !!d.ok;
}

/**
 * Admin → Security → Keys, the upgrade of users' Drives (the owner's own
 * session; routed from src/routes/admin.js):
 * - `GET /api/private/admin/drive/migration` — each Drive still waiting (or
 *   done), with what is left in it;
 * - `POST …/migrate/<userId>/escrow` — the user's escrow wrap of the release
 *   before (opened in the owner's browser with the owner's own old Drive key)
 *   and the user's current KEK, to re-seal their items under it (admin audit:
 *   `drive.escrow_used`);
 * - `GET …/migrate/<userId>`, `GET …/items`, `PUT …`, `POST …/finish` — as
 *   the user's own upgrade.
 */
export async function adminDriveRoute(request, env, url, ownerId) {
  const p = url.pathname;
  const dir = directory(env);
  if (p === '/api/private/admin/drive/migration') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    const rows = await dir.migrationList();
    const out = [];
    for (const r of rows) {
      let st = { v1Items: r.v1Items, v1Links: r.v1Links, legacy: null };
      if (r.state !== 'done') {
        try {
          const s = await driveStub(env, r.id).summary(r.id);
          st = { v1Items: s.migration.v1Items, v1Links: s.migration.v1Links, legacy: s.migration.wraps > 0, items: s.items };
          if (st.v1Items !== r.v1Items || st.v1Links !== r.v1Links) await dir.migrationSet(r.id, { state: 'pending', v1Items: st.v1Items, v1Links: st.v1Links });
        } catch (e) {
          console.warn('secbin: drive migration state not read', e && e.message ? e.message : e);
        }
      }
      out.push({ id: r.id, username: r.username, role: r.role, state: r.state, disabled: !!r.disabled, ...st, updated: r.updated });
    }
    let { escrowPub } = await dir.legacyEscrow();
    const left = out.filter((d) => d.state !== 'done').length;
    // Nothing waits any more (e.g. the last waiting account was deleted): the escrow records go now.
    if (!left && escrowPub && (await legacyCleanup(env, dir))) escrowPub = (await dir.legacyEscrow()).escrowPub;
    return json({ drives: out, left, legacyEscrow: !!escrowPub });
  }
  if (p === '/api/private/admin/drive/archive') return archiveRoute(request, env, url, dir, ownerId);
  const m = p.match(/^\/api\/private\/admin\/drive\/migrate\/([A-Za-z0-9_-]{16})(\/escrow|\/items|\/finish|\/retire)?$/);
  if (!m) return err(404, 'not_found', 'Not found.');
  const [, uid, sub = ''] = m;
  if (uid === ownerId) return err(400, 'use_own', 'Upgrade your own Drive from the Drive page.');
  // A disabled account's Drive is upgraded too (its keys must not wait for the account).
  const pol = await dir.driveAccess(uid, { forUpgrade: true });
  if (!pol.ok) return fromDir(pol);
  if (sub === '/escrow') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    assertIntent(request);
    const body = await readJsonBody(request);
    // It hands out the user's old Drive key wrap and current KEK: the step-up, as for Show.
    const refused = await stepUp(request, env, url, dir, ownerId, body);
    if (refused) return refused;
    const L = await driveStub(env, uid).legacyKeys(uid);
    const wrap = L.wraps.find((w) => w.kind === 'escrow') || null;
    const logged = await dir.driveAdminAction(ownerId, uid, 'drive.escrow_used', 'reason=Drive key upgrade (the old Drive key, and the current KEK to re-seal under)');
    if (!logged.ok) return fromDir(logged);
    const k = await userKeys(env, uid, { createSalt: nothingSealed(await driveStub(env, uid).summary(uid)) });
    const cur = k.keks.get(k.current);
    return json({ wrap, wraps: L.wraps.length, kcv: L.kcv, v1Items: L.v1Items, v1Links: L.v1Links, current: k.current, kek: cur ? b64urlFromBytes(cur.kek) : null, fp: cur ? cur.fp : null });
  }
  return upgradeRoute(request, env, url, dir, uid, sub, { owner: false, byOwner: ownerId, state: pol.migration, actor: ownerId });
}

/**
 * The owner's archive of the release before (a start over; docs/DRIVE.md
 * §3.3): `GET` — what it holds (items, bytes, received files, the links it
 * pauses); `DELETE` `{ current | reauth, confirm: <username> }` — deleted
 * with its content, and those links end (admin audit: `drive.archive_deleted`).
 */
async function archiveRoute(request, env, url, dir, ownerId) {
  const drive = driveStub(env, ownerId);
  if (request.method === 'GET') {
    assertNotCrossSite(request);
    return json(await drive.archiveInfo(ownerId));
  }
  if (request.method !== 'DELETE') return methodNotAllowed('GET, DELETE');
  assertIntent(request);
  binding(env, 'FILES'); // never report a delete that left ciphertext in R2
  const body = await readJsonBody(request);
  const refused = await stepUp(request, env, url, dir, ownerId, body);
  if (refused) return refused;
  if (typeof body.confirm !== 'string' || body.confirm !== (await dir.userName(ownerId))) return err(400, 'confirm', 'Type your username to confirm.');
  const r = await drive.deleteArchive(ownerId);
  if (r.links.length) await dir.endDriveShares(ownerId, r.links, { id: ownerId, adm: true }, 'link retired');
  await dir.setDriveUsed(ownerId, r.used);
  await dir.driveAdminAction(ownerId, ownerId, 'drive.archive_deleted', `items=${r.items} bytes=${r.bytes} links_ended=${r.links.length}`);
  const st = await dir.migrationList();
  if (st.some((x) => x.id === ownerId && x.state !== 'done')) await dir.migrationSet(ownerId, { state: 'pending', v1Items: r.v1Items, v1Links: r.v1Links });
  return json({ ok: true, items: r.items, bytes: r.bytes, links: r.links.length });
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
    live.push({ ...row, captcha: !!row.captcha, views_total: views, left: s.left ?? null, expires: s.expires ?? row.expires, state: row.status, maxViews: views });
  }
  // Ended shares no longer reference anything.
  if (ended.size) await driveStub(env, uid).dropRefs(uid, [...ended]);
  return json({ shares: live });
}

/**
 * A Drive share: a FileShare record referencing Drive files, authorized
 * exactly like a file share (limits, file policy declarations; counted by the
 * quotas of kind "drive", "files" and "all"), recorded in My shares as kind
 * "drive".
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
    types: body.types, depth: body.depth, deletable, captcha: body.captcha,
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
        hc: auth.captcha === true,
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
  const rec = await dir.recordShare({ id, uid, kind: 'drive', label: body.label, created: r.created, expires: r.expires, views, lh: clean.acc.lh, captcha: auth.captcha === true }, actorId(a));
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
  return json({ id, deletetoken: deleteToken, expires: r.expires, captcha: auth.captcha === true }, 201);
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
  const { shares, reverse = [] } = await retry(() => stub().allShares(uid));
  for (const id of shares) await retry(() => fileStub(env, id).revoke());
  if (shares.length) await retry(() => dir.endDriveShares(uid, shares, actor, 'account deleted'));
  // Reverse shares have no FileShare record: their Directory rows end here.
  if (reverse.length) await retry(() => dir.endDriveShares(uid, reverse, actor, 'account deleted'));
  const r = await retry(() => stub().destroy(uid));
  // A share made in between.
  for (const id of r.shares.filter((x) => !shares.includes(x))) await retry(() => fileStub(env, id).revoke());
  const lateReverse = (r.reverse || []).filter((x) => !reverse.includes(x));
  if (lateReverse.length) await retry(() => dir.endDriveShares(uid, lateReverse, actor, 'account deleted'));
}


/**
 * The account's password changed (`reset`: set by the owner): a Drive still
 * waiting for its upgrade keeps its old password wrap only as long as it may
 * be needed (docs/DRIVE.md §3.3).
 */
export async function drivePasswordChanged(env, uid, { reset = false } = {}) {
  const c = await directory(env).credentialRefs(uid);
  if (!c || !c.drive) return null;
  return driveStub(env, uid).passwordChanged(uid, { reset });
}

/**
 * AUTHN owner recovery (src/routes/auth.js): the owner's passkeys and recovery
 * codes are gone. Their old Drive wraps (of the release before) stay while any
 * Drive still waits for its upgrade: the owner's old Drive key opens the
 * escrow of every user's, and a wrap may still open it (the paper recovery
 * codes, a passkey). Once nothing waits, they go. No Drive key changes.
 */
export async function driveOwnerRecovered(env, ownerId) {
  const dir = directory(env);
  const c = await dir.credentialRefs(ownerId);
  if (!c || !c.drive) return;
  // Kept, and marked so that a later passkey or code change does not prune them while a Drive waits.
  if ((await dir.migrationList()).some((r) => r.state !== 'done')) { await driveStub(env, ownerId).holdWraps(ownerId); return; }
  await syncCredentialWraps(env, ownerId);
}
