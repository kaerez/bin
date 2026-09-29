// reverse.js — reverse shares ("Receive", docs/REVERSE.md): the user's
// routes under /api/private/drive (create, list, the received files and their
// re-wrap) and the anonymous uploader's routes under /api/reverse/<id>.
//
// The server stores what the browsers encrypted — the share's private key
// sealed under HKDF(KEK, "reverse-link") (docs/DRIVE.md §3), the uploader's
// file names, metadata and file keys sealed to the share's public key (which
// only the link holds) — both also sealed at rest with the user's field key
// (the field layer) — and checks only what it can see: the link proof, the
// password proof (both as SHA-256 hashes), the human check, sizes and counts
// against the share's limits and the Drive's capacity, and exact chunk sizes.
// The password only gates the uploader. An upload is encrypted in the
// uploader's browser to the link's key until the user's browser takes it into
// the Drive (then it is sealed under the user's KEK like any Drive file). The
// link's private key is sealed under the user's KEK, which the server derives:
// the server can open an upload before it is taken in, as it can any Drive file
// (SECURITY.md, "Drive keys"); a copy of R2 or of the Drive object alone cannot.

import { json, err, readJsonBody, readCappedBody, assertIntent, assertNotCrossSite, decodePathSegment, methodNotAllowed } from '../lib/http.js';
import { actorId } from '../lib/auth.js';
import { directory, ipContext, isBlocked, recordFailure } from '../lib/guard.js';
import { recordOpen } from '../lib/receipts.js';
import { genToken, hashToken } from '../lib/ids.js';
import { driveStub } from '../lib/store.js';
import { binding } from '../lib/config.js';
import { turnstileKeys, TURNSTILE_ACTIONS } from '../lib/turnstile.js';
import { issueGrant, readGrant, netTag, reverseNet, captchaRequired, verifyCaptcha, HUMAN_HEADER } from '../lib/human.js';
import { stepUpFrom, afterRefusal } from './stepup.js';
import { HARD_MAX_DRIVE_BYTES, NO_EXPIRY, apiExpiry } from '../lib/settings.js';
import { expireSeconds, isProof, ARGON2, MAX_TTL, MAX_VIEWS } from '../../public/js/format.js';
import { MAX_CHUNK_CT } from '../../public/js/files.js';
import { normalizeRules, checkDeclaredTypes, refusedTypes, describeType } from '../../public/js/filepolicy.js';
import { b64urlFromBytes, bytesFromB64url, timingSafeEqualHex } from '../../public/js/bytes.js';
import { NODE_ID_RE, ROOT, MAX_REVERSE_FILES, RECEIVED_FAIL_REASONS } from '../drive-do.js';
import { encField } from './drive.js';
import { KEY_RE, MEK_ID_RE } from '../../public/js/drivekeys.js';
import { userKeys, checkNewItem, checkLinkKey, fieldKeys, toRest, fromRest } from '../lib/mek.js';
import { normalizeAccept, widening as widensKinds, limitsWidening, isKind, KIND_ACTIONS, KIND_PLURALS, DEFAULT_ACCEPT } from '../../public/js/receivekinds.js';
import { driveTypeRefusal, sealedTypeRefusal, typedPolicy } from '../lib/drivepolicy.js';

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
const MAX_DEK_CT = 128;
/** Bound parameters per query stay well under the Durable Object SQLite limit (100). */
const ID_BATCH = 80;
const GONE = 'This link no longer accepts files: it has expired, was revoked, or has taken all the uploads it allows.';
// The owner started over: the link's key is in the archive until a kit restores it (docs/DRIVE.md §3.2).
const PAUSED = 'This link is not accepting files right now.';
const pausedRes = () => err(409, 'paused', PAUSED);
// The user's receive-upload quota is reached (its details stay the user's).
const NOT_ACCEPTING = 'This link can’t accept more uploads right now. Try again later.';
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const invalid = (message) => err(400, 'invalid', message);
const fromDo = (r) => {
  const extra = {};
  for (const k of ['max', 'used', 'refused', 'quota', 'folder']) if (r[k] !== undefined) extra[k] = r[k];
  return err(r.status, r.error, r.message, Object.keys(extra).length ? extra : undefined);
};
const eqB64 = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqualHex(a, b);
async function proofHashOf(b64) {
  return b64urlFromBytes(new Uint8Array(await crypto.subtle.digest('SHA-256', bytesFromB64url(b64))));
}

const parsed = (v) => { try { return typeof v === 'string' ? JSON.parse(v) : v; } catch { return null; } };
/**
 * A stored link key → its sealed {iv, ct} (the field layer removed), or null when it does not open.
 * A link key is always stored at rest: one in plain text (written to storage by someone other than
 * the Worker) is refused, never handed out (fails closed: the link shows no key).
 */
async function linkPriv(fk, uid, id, stored) {
  try { return parsed(await fromRest(fk, uid, 'linkKey', id, stored, { plain: false })); } catch { return null; }
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
 *
 * CSRF: these are cookie-authenticated, so every change here (create, take
 * in, mark failed, retry) has already passed authenticate()'s checks in the
 * Drive route: Sec-Fetch-Site, the request shape and the session's CSRF token
 * (src/lib/auth.js checkCsrf), before the step-up and before the id is
 * claimed. Extend, revoke and lock go through the shares routes, which check
 * the same. test/csrf.test.js reads this file and fails if a route or method
 * here is missing from its sweep. `pol`: the Drive's policy (Directory
 * driveAccess), whose file rules apply to a take-in.
 */
export async function handleReverseOwner(request, env, url, a, pol) {
  const p = url.pathname;
  const uid = a.user.id;
  const dir = directory(env);
  const drive = () => driveStub(env, uid);

  if (p === '/api/private/drive/reverse') {
    if (request.method === 'GET') {
      const folder = url.searchParams.get('folder');
      if (folder !== null && folder !== ROOT && !NODE_ID_RE.test(folder)) return invalid('folder must be a folder id.');
      const r = await drive().listReverse(uid, folder);
      // Each link key without the field layer (the browser opens it with the KEK of its mek).
      const fk = r.reverse.length ? await fieldKeys(env, uid) : null;
      for (const x of r.reverse) x.priv = await linkPriv(fk, uid, x.id, x.priv);
      const rows = [];
      for (let i = 0; i < r.reverse.length; i += ID_BATCH) rows.push(...await dir.sharesByIds(uid, r.reverse.slice(i, i + ID_BATCH).map((x) => x.id)));
      const byId = new Map(rows.map((x) => [x.id, x]));
      return json({
        reverse: r.reverse.filter((x) => byId.has(x.id)).map((x) => {
          const row = byId.get(x.id);
          // The index row decides (revoked, expired, locked by the admin); the Drive adds the counters.
          const status = row.status !== 'active' ? row.status : ['active', 'paused'].includes(x.status) ? x.status : 'ended';
          return { ...x, expires: apiExpiry(x.expires), label: row.label, locked: !!row.locked, status };
        }),
      });
    }
    if (request.method !== 'POST') return methodNotAllowed('GET, POST');
    return createReverse(request, env, dir, a, pol);
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
    if (!failed && r.keys.length) {
      // What each link takes now: what it accepts that the user's role still allows (as the
      // uploader's routes check it); an item of a kind the role dropped fails at take-in.
      const kinds = await dir.receiveKindsOf(uid);
      for (const k of r.keys) k.accept = (Array.isArray(k.accept) ? k.accept : DEFAULT_ACCEPT).filter((x) => kinds.includes(x));
    }
    if (!failed && (r.items.length || r.keys.length)) {
      // The field layer comes off here: the browser gets the uploader's sealed fields and the link keys.
      const fk = await fieldKeys(env, uid);
      // A received item's fields were always sealed at rest: one in plain text (written to storage by
      // someone other than the Worker) is refused, never trusted for its declared kind.
      const opened = (ref, v) => fromRest(fk, uid, 'received', ref, v, { plain: false });
      for (const it of r.items) {
        try {
          it.name = parsed(await opened(`name:${it.id}`, it.name));
          it.meta = it.meta ? parsed(await opened(`meta:${it.id}`, it.meta)) : null;
          it.fk = parsed(await opened(`wrap:${it.id}`, it.fk));
          // The kind its session declared, sealed with the wrap (none: refused at take-in, `kind`).
          it.declared = it.fk && isKind(it.fk.declared) ? it.fk.declared : null;
          if (it.fk) delete it.fk.declared;
        } catch (e) {
          // One item that does not open never holds up the rest: the browser records it as failed
          // (`unsealed`: a field stored in plain text, recorded as `kind`).
          Object.assign(it, { name: null, meta: null, fk: null, declared: null, unreadable: true, ...(e?.code === 'not_at_rest' ? { unsealed: true } : {}) });
        }
      }
      for (const k of r.keys) k.priv = await linkPriv(fk, uid, k.id, k.priv);
    }
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
    const dek = encField(body.dek, MAX_DEK_CT);
    const kf = typeof body.ks === 'string' && KEY_RE.test(body.ks) && typeof body.mek === 'string' && MEK_ID_RE.test(body.mek) ? { ks: body.ks, mek: body.mek } : null;
    if (!parent || !name || !meta || !dek || !kf) return invalid('Send { parent, name, meta, dek, ks, mek, types? } (sealed fields as {iv, ct}).');
    // The kind its session declared (sealed at rest with its wrap; plain text refused) must be one the
    // link accepts and the user's role allows now; the browser checks the item is that kind (§3).
    const w = await drive().receivedDeclared(uid, node);
    if (!w.ok) return fromDo(w);
    let declared;
    try { declared = parsed(await fromRest(await fieldKeys(env, uid), uid, 'received', `wrap:${node}`, w.wrap, { plain: false }))?.declared ?? null; } catch { declared = null; }
    const nowKinds = await dir.receiveKindsOf(uid);
    if (!isKind(declared) || !w.accept.includes(declared) || !nowKinds.includes(declared)) {
      return err(409, 'kind_not_accepted', 'This item is of a kind its link or your role does not accept now.');
    }
    // The role's Drive rules apply to what is taken in, on top of the link's own type rules (the
    // uploader's page checked those): its file types (declared, as for an upload) and folder depth
    // (the Drive checks its tree), so a Receive link is no way around the Drive's policy.
    const typeRefused = driveTypeRefusal(pol.policy, body.types, 'added to');
    if (typeRefused) return typeRefused;
    // Taken in: sealed under the current KEK like any Drive file (checked here), and the type rule
    // enforced on what is stored (the sealed name and metadata, opened in memory only).
    let sealedRefused = null;
    const mfp = await checkNewItem(uid, await userKeys(env, uid), { kind: 'file', ...kf, name, meta, dek },
      typedPolicy(pol.policy) ? (n, m) => { sealedRefused = sealedTypeRefusal(pol.policy, n, m, body.types, 'added to'); } : null);
    if (sealedRefused) return sealedRefused;
    const r = await drive().acceptReceived(uid, node, { parent, name, meta, dek, ...kf, mfp, maxDepth: pol.policy.maxFolderDepth });
    if (!r.ok) return fromDo(r);
    await dir.setDriveUsed(uid, r.used);
    await dir.driveLog(actorId(a), uid, 'drive.received_taken_in', `id=${r.rs} files=1`);
    return json({ ok: true });
  }
  return null;
}

async function createReverse(request, env, dir, a, pol) {
  const uid = a.user.id;
  const body = await readJsonBody(request);
  if (typeof body.id !== 'string' || !REVERSE_ID_RE.test(body.id)) return invalid('id must be "r" and 16 random bytes (base64url).');
  const folder = typeof body.folder === 'string' && (body.folder === ROOT || NODE_ID_RE.test(body.folder)) ? body.folder : null;
  if (!folder) return invalid('folder must be a folder id.');
  const priv = encField(body.priv, MAX_PRIV_CT);
  if (!priv) return invalid('priv must be the sealed private key {iv, ct}.');
  if (typeof body.mek !== 'string' || !MEK_ID_RE.test(body.mek)) return invalid('mek must be the sub-MEK the key is sealed under.');
  if (typeof body.lh !== 'string' || !B64_43.test(body.lh)) return invalid('lh must be the link proof\'s hash.');
  const note = body.note === undefined || body.note === null ? null : encField(body.note, MAX_NOTE_CT);
  if (note === null && body.note !== undefined && body.note !== null) return invalid('note must be {iv, ct}.');
  const pw = body.password === undefined || body.password === null ? null : passwordOf(body.password);
  if (pw === undefined) return invalid('password must be { salt, t, ph }.');
  // "never": no expiry (only where the role allows it: reverseNoExpiry).
  const ttl = body.expire === 'never' ? null : expireSeconds(body.expire);
  if (body.expire !== 'never' && (ttl === null || ttl > MAX_TTL)) return err(400, 'invalid_expire', 'Invalid expiry.');
  // Views (a view: one upload session granted); none sent: unlimited.
  const views = body.views === undefined ? null : body.views;
  if (!validViews(views)) return err(400, 'invalid_views', `views must be 1–${MAX_VIEWS} or null (unlimited).`);
  const maxFiles = bound(body.maxFiles, MAX_REVERSE_FILES);
  const maxBytes = bound(body.maxBytes, HARD_MAX_DRIVE_BYTES);
  const maxFileBytes = bound(body.maxFileBytes, HARD_MAX_DRIVE_BYTES);
  if (maxFiles === undefined) return invalid(`maxFiles must be 1–${MAX_REVERSE_FILES} or null.`);
  if (maxBytes === undefined || maxFileBytes === undefined) return invalid('maxBytes and maxFileBytes must be a number of bytes or null.');
  const types = body.types === undefined || body.types === null ? null : typesOf(body.types);
  if (typeof types === 'string') return invalid(types);
  // What the link accepts (files only when not sent, as every link before this option).
  const accept = acceptIn(body.accept);
  if (typeof accept === 'string') return invalid(accept);
  // The id is claimed in the share index first, atomically with the role's
  // checks and its count of active reverse shares: an id another account
  // holds is refused (409), and concurrent creates cannot pass the limit.
  const claim = await dir.claimReverse(uid, { id: body.id, expireSec: ttl, maxBytes, label: body.label, lh: body.lh, captcha: body.captcha, views, password: !!pw, accept });
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
        await dir.releaseReverse(uid, body.id, claim.refund);
        return afterRefusal(env, g, v, fromDo(v));
      }
    }
    // The link key opens under the user's current KEK (the server re-seals it later), and is kept at rest under the field layer.
    await checkLinkKey(uid, await userKeys(env, uid), body.id, body.mek, priv);
    const stored = await toRest(await fieldKeys(env, uid), uid, 'linkKey', body.id, priv);
    r = await driveStub(env, uid).createReverse(uid, {
      id: body.id, folder, priv: stored, mek: body.mek, lh: body.lh, ph: pw?.ph, salt: pw?.salt, t: pw?.t, note, ttl, views, captcha: claim.captcha === true,
      // The Drive's folder-depth rule, from the same policy the take-in holds files to.
      opts: { maxFiles, maxBytes: claim.maxBytes, maxFileBytes, types, accept }, maxDepth: pol?.policy?.maxFolderDepth ?? null,
    });
  } catch (e) {
    await dir.releaseReverse(uid, body.id, claim.refund); // the id is free again, and the quota
    throw e;
  }
  if (!r.ok) {
    await dir.releaseReverse(uid, body.id, claim.refund);
    return fromDo(r);
  }
  const act = await dir.activateReverse(uid, body.id, { created: r.created, expires: r.expires }, actorId(a));
  if (!act.ok) {
    await driveStub(env, uid).endReverse(uid, body.id);
    await dir.refund(uid, claim.refund);
    return fromDo(act);
  }
  return json({ id: body.id, expires: apiExpiry(r.expires), views, captcha: claim.captcha === true, accept }, 201);
}

/** A link's accepted kinds as sent (undefined or null: files only) → the list, or the reason it is refused (a string). */
function acceptIn(v) {
  if (v === undefined || v === null) return [...DEFAULT_ACCEPT];
  try { return normalizeAccept(v); } catch (e) { return e.message; }
}

/** An uploader password as the browser sends it → { salt, t, ph }, or undefined when malformed. */
function passwordOf(x) {
  if (!isObj(x) || typeof x.salt !== 'string' || !SALT_RE.test(x.salt) || !Number.isInteger(x.t) || x.t < ARGON2.tMin || x.t > ARGON2.tMax
      || typeof x.ph !== 'string' || !B64_43.test(x.ph)) return undefined;
  return { salt: x.salt, t: x.t, ph: x.ph };
}
/** A link's file types → { mode, rules }, or the reason they are refused (a string). */
function typesOf(v) {
  if (!isObj(v) || !['allow', 'block'].includes(v.mode)) return 'types must be { mode: "allow" | "block", rules }.';
  let rules;
  try { rules = normalizeRules(v.rules); } catch (e) { return e.message; }
  if (!rules.length) return 'List at least one file type, or allow any type.';
  return { mode: v.mode, rules };
}
const validViews = (v) => v === null || (Number.isSafeInteger(v) && v >= 1 && v <= MAX_VIEWS);
const now = () => Math.floor(Date.now() / 1000);

/**
 * PATCH /api/private/shares/<id> of a reverse share (src/routes/private.js
 * changeShare; a session, or an API key with "manage"): the label, and —
 * where the role allows (reverseEdit and the value's own option, for the
 * channel the change comes through) — the expiry (`expires`: a time, or null
 * for none), the views (`views`, null: unlimited), the limits (`maxFiles`,
 * `maxBytes`, `maxFileBytes`, `types`), the CAPTCHA (`captcha`), the
 * uploader password (`password`: { salt, t, ph } made in the browser from
 * the link's key, or null: none), the note (`note`: { iv, ct } sealed in
 * the browser, or null: none), what the link accepts (`accept`: files,
 * note, url, secret — as the role allows the kinds it adds) and the Drive
 * folder uploads land in (`folder`: a folder of the user's own Drive, within
 * the role's folder depth; what it received and is not taken in yet moves
 * with it). The server sees neither the password nor the note. The owner
 * changing another user's link directly (`admin`) may change the label,
 * expiry and views only.
 */
export async function changeReverse(env, dir, row, body, { uid, actor, admin = null, channel = 'all', keyId = null, request = null, impersonating = false }) {
  const id = row.id;
  const change = {}; // the values as the role checks them
  const set = {}; // what the Drive stores
  if (body.label !== undefined) change.label = body.label;
  if (body.expires !== undefined) {
    if (body.expires !== null && !(Number.isSafeInteger(body.expires) && body.expires > now() && body.expires <= now() + MAX_TTL)) {
      return err(400, 'invalid_expiry', 'Expiry must be in the future and within 365 days, or null for none.');
    }
    change.expires = body.expires;
    set.expires = body.expires === null ? NO_EXPIRY : body.expires;
  }
  if (body.views !== undefined) {
    if (!validViews(body.views)) return err(400, 'invalid_views', `views must be 1–${MAX_VIEWS} or null (unlimited).`);
    change.views = set.views = body.views;
  }
  const opts = {};
  if (body.maxFiles !== undefined) {
    opts.maxFiles = bound(body.maxFiles, MAX_REVERSE_FILES);
    if (opts.maxFiles === undefined) return invalid(`maxFiles must be 1–${MAX_REVERSE_FILES} or null.`);
  }
  for (const k of ['maxBytes', 'maxFileBytes']) {
    if (body[k] === undefined) continue;
    opts[k] = bound(body[k], HARD_MAX_DRIVE_BYTES);
    if (opts[k] === undefined) return invalid('maxBytes and maxFileBytes must be a number of bytes or null.');
  }
  if (body.types !== undefined) {
    opts.types = body.types === null ? null : typesOf(body.types);
    if (typeof opts.types === 'string') return invalid(opts.types);
  }
  if (body.accept !== undefined) {
    const accept = acceptIn(body.accept === null ? undefined : body.accept);
    if (typeof accept === 'string') return invalid(accept);
    opts.accept = change.accept = accept;
  }
  if (Object.keys(opts).length) {
    set.opts = opts;
    change.limits = true;
    if (opts.maxBytes !== undefined) change.maxBytes = opts.maxBytes;
  }
  if (body.captcha !== undefined) {
    if (typeof body.captcha !== 'boolean') return err(400, 'invalid_captcha', 'captcha must be true or false.');
    change.captcha = set.captcha = body.captcha;
  }
  if (body.password !== undefined) {
    const pw = body.password === null ? null : passwordOf(body.password);
    if (pw === undefined) return invalid('password must be { salt, t, ph } or null.');
    change.password = set.password = pw;
  }
  if (body.note !== undefined) {
    const note = body.note === null ? null : encField(body.note, MAX_NOTE_CT);
    if (note === null && body.note !== null) return invalid('note must be {iv, ct} or null.');
    change.note = set.note = note;
  }
  if (body.folder !== undefined) {
    if (typeof body.folder !== 'string' || (body.folder !== ROOT && !NODE_ID_RE.test(body.folder))) return invalid('folder must be a folder id of your Drive ("root" for its top folder).');
    change.folder = set.folder = body.folder;
  }
  const keys = Object.keys(change);
  if (!keys.length) return invalid('Nothing to change.');
  if (admin && keys.some((k) => !['label', 'expires', 'views'].includes(k))) {
    return err(403, 'user_only', 'Only the user can change a link’s limits, folder, CAPTCHA, password or note.');
  }
  const detail = keys.some((k) => k !== 'label');
  if (detail && row.status !== 'active') return err(409, 'not_active', 'Only active shares can be changed.');
  const owner = row.user_id ?? uid;
  const drive = driveStub(env, owner);
  // The kinds a change of `accept` adds are checked against the role (a kind the link has may stay).
  let cur = null;
  if (change.accept !== undefined) {
    cur = await drive.reverseStatus(owner, id);
    if (cur.status !== 'ok') {
      await dir.markShareEnded(id, 'ended');
      return err(410, 'gone', 'This share no longer exists.');
    }
    change.added = change.accept.filter((k) => !(cur.accept || DEFAULT_ACCEPT).includes(k));
  }
  const ok = await dir.authorizeReverseChange(uid, change, { channel, admin: !!admin });
  if (!ok.ok) return fromDo(ok);
  if (ok.maxBytes !== undefined) set.opts.maxBytes = ok.maxBytes; // "none" is the role's limit, when it has one
  // A new folder is held to the role's folder depth (for this channel), by the Drive's own rule.
  if (set.folder !== undefined) set.maxDepth = ok.maxFolderDepth ?? null;
  const patch = {};
  if (change.label !== undefined) patch.label = change.label;
  let r = null;
  if (detail) {
    // The lock first, before anything is checked or written (the admin may have locked it since `row` was read).
    if (!admin && await dir.isShareLocked(id)) return err(423, 'share_locked', 'The administrator has locked this share; it cannot be changed.');
    // A change that weakens the link's protection — removing or changing its
    // password, turning its CAPTCHA off, no expiry, unlimited views, new kinds
    // it accepts, its own file types or size limits loosened — needs what
    // creating one needs: the user's password or a passkey (a stolen session
    // alone cannot turn a link into an open, lasting upload channel). Never
    // through an API key; the owner acting as the user, or changing it
    // directly, confirms nothing, as for every other change to the account.
    if (!admin) {
      cur = await drive.reverseStatus(owner, id);
      if (cur.status !== 'ok') {
        await dir.markShareEnded(id, 'ended');
        return err(410, 'gone', 'This share no longer exists.');
      }
      // The limits as they will be stored (maxBytes "none" is the role's limit, when it has one).
      const weak = weakening(change, cur, set.opts || {});
      if (weak.length) {
        if (channel === 'api') {
          return err(403, 'step_up_required', 'Removing or changing an upload link’s password, turning its CAPTCHA off, removing its expiry or its views limit, letting it accept files, links or credentials it did not, or loosening its file types or size limits, needs your password or a passkey in the browser; an API key cannot do it.', { weakens: weak });
        }
        if (!impersonating) {
          const g = await ipContext(env, request);
          const step = await stepUpFrom(body, new URL(request.url));
          const v = await dir.verifyCurrent(uid, step.current, { ...step, lockoutOff: g.off.all });
          if (!v.ok) return afterRefusal(env, g, v, fromDo(v));
        }
      }
    }
    r = await drive.updateReverse(owner, id, set);
    if (r.status === 'invalid') return err(400, 'invalid', r.message, r.used !== undefined ? { used: r.used } : undefined);
    if (r.status === 'refused') return fromDo(r.fail); // the folder: not the user's, not a folder, too deep or full
    if (r.status !== 'ok') {
      await dir.markShareEnded(id, 'ended');
      return err(410, 'gone', 'This share no longer exists.');
    }
    if (set.expires !== undefined) patch.expires = r.expires;
    if (set.views !== undefined) patch.views = r.views;
    // The index enforces the CAPTCHA (the uploader's begin reads it there).
    if (set.captcha !== undefined) patch.captcha = r.captcha;
    patch.detail = [
      ...(set.password !== undefined ? [set.password ? 'password=set' : 'password=removed'] : []),
      ...(set.note !== undefined ? [set.note ? 'note=set' : 'note=removed'] : []),
      ...(set.opts !== undefined ? ['limits'] : []),
      ...(set.opts?.accept !== undefined ? [`accept=${set.opts.accept.join(',')}`] : []),
      ...(r.prev && r.prev.folder !== undefined ? [`folder=${r.folder}`] : []),
    ];
  }
  const u = await dir.updateShare(uid, id, patch, actor, { admin, keyId });
  if (!u.ok) {
    // The index refused (locked in the meantime): the Drive goes back to what it held, so the two never differ.
    const back = r && r.prev ? await drive.restoreReverse(owner, id, r.prev) : { ok: true };
    if (!back.ok && back.error === 'folder_gone') {
      // Its old folder was deleted meanwhile: the link and its waiting items stay in the new one
      // (nothing else was kept). That move stands, so it is logged, and the answer says so.
      await dir.reverseMoveKept(uid, id, back.folder, actor, { keyId });
      return err(u.status, u.error, `${u.message} The link’s folder change was kept: its old folder no longer exists.`, { kept: ['folder'], folder: back.folder });
    }
    return fromDo(u);
  }
  return json(r ? { ok: true, expires: apiExpiry(r.expires), views: r.views, left: r.left, used: r.used, accept: r.accept, folder: r.folder } : { ok: true });
}

/**
 * Pause (`on`) or resume reverse share `row` (its share-index row, the
 * caller's own; a session, or an API key with "manage"): paused, it takes no
 * new upload session — the uploader's `open` and `begin` answer `409 paused`
 * — and the sessions open now end, their unfinished uploads deleted; what it
 * received stays and is taken in as before. Neither needs reverseEdit (like
 * revoking and the label), both only an active link that is not locked, and
 * the role's reverse shares. Pausing tightens the link: nothing more. Resuming
 * reopens an upload channel the user closed, so it weakens the link: it needs
 * the password proof or a passkey (`body.current` / `body.reauth`), as the
 * other weakening changes do, and is refused for an API key (`403
 * step_up_required`); the owner acting as the user confirms nothing. Logged
 * as a share change (`paused` / `resumed`, with the API key's id).
 */
export async function pauseReverse(env, dir, row, on, { uid, actor, channel = 'all', keyId = null, request = null, body = {}, impersonating = false }) {
  const id = row.id;
  if (row.locked || await dir.isShareLocked(id)) return err(423, 'share_locked', 'The administrator has locked this share; it cannot be changed.');
  if (row.status !== 'active') return err(409, 'not_active', 'Only active links can be paused or resumed.');
  const ok = await dir.authorizeReverseChange(uid, { pause: on }, { channel });
  if (!ok.ok) return fromDo(ok);
  const drive = driveStub(env, uid);
  if (!on) {
    // Only a link the user paused resumes (before the step-up: nothing to confirm otherwise).
    const cur = await drive.reverseStatus(uid, id);
    if (cur.status === 'ok' && !cur.paused) return json({ ok: true, paused: false });
    if (cur.status === 'ok' && !cur.held) return err(409, 'not_paused', 'This link was not paused by you, so it cannot be resumed.');
    if (cur.status === 'ok') {
      if (channel === 'api') {
        return err(403, 'step_up_required', 'Resuming an upload link reopens it to anonymous senders: it needs your password or a passkey in the browser; an API key cannot do it.', { weakens: ['paused'] });
      }
      if (!impersonating) {
        const g = await ipContext(env, request);
        const step = await stepUpFrom(body, new URL(request.url));
        const v = await dir.verifyCurrent(uid, step.current, { ...step, lockoutOff: g.off.all });
        if (!v.ok) return afterRefusal(env, g, v, fromDo(v));
      }
    }
  }
  const r = await drive.pauseReverse(uid, id, on);
  if (r.status === 'gone') {
    // Ended in its Drive (expired, its folder deleted); one the owner's start over paused cannot be resumed.
    const s = await drive.reverseStatus(uid, id);
    if (s.status === 'gone') {
      await dir.markShareEnded(id, s.state === 'expired' ? 'expired' : 'ended');
      return err(410, 'gone', 'This share no longer exists.');
    }
    return err(409, 'not_paused', 'This link was not paused by you, so it cannot be resumed.');
  }
  await dir.setDriveUsed(uid, r.used);
  if (r.status === 'unchanged') return json({ ok: true, paused: on }); // already so: nothing to log
  const u = await dir.updateShare(uid, id, { detail: [on ? 'paused' : 'resumed'] }, actor, { keyId });
  if (!u.ok) {
    // The index refused (locked in the meantime): the link goes back to how it was.
    await drive.pauseReverse(uid, id, !on);
    return fromDo(u);
  }
  return json({ ok: true, paused: on });
}

/**
 * Which parts of `change` weaken reverse share `cur` (its state in the Drive:
 * expires, views, password, captcha, accept and its limits) → a list of
 * names (empty: none). `opts`: the new limits as they will be stored.
 * Adding a password where there is none, turning the CAPTCHA on, an expiry,
 * fewer views or tighter limits never weaken it. Letting it accept files,
 * links or credentials it did not does ('accept'): each is a new way for an
 * anonymous sender to reach the user (a file of any type, a link to follow, a
 * secret entrusted to a channel that is not end-to-end); a note is plain text
 * shown inertly, less than a file carries, and does not. So does loosening
 * its own file limits ('types', 'maxFiles', 'maxBytes', 'maxFileBytes':
 * receivekinds.js limitsWidening): a file type it refused, or more or larger
 * files than it took. Raising its views or extending its expiry (within the
 * role's limits) is the Extend of every share and does not.
 */
export function weakening(change, cur, opts = {}) {
  const out = [];
  if (change.expires === null && !(cur.expires >= NO_EXPIRY)) out.push('expires');
  if (change.views === null && cur.views !== null && cur.views !== undefined) out.push('views');
  if (change.password !== undefined && cur.password) out.push('password');
  if (change.captcha === false && cur.captcha) out.push('captcha');
  if (change.accept !== undefined && widensKinds(cur.accept || DEFAULT_ACCEPT, change.accept).length) out.push('accept');
  // Its own file limits loosened (`opts`: the new limits as they will be stored): file types less
  // restrictive, and most files, most bytes or largest file raised or removed (receivekinds.js).
  out.push(...limitsWidening(cur, opts));
  return out;
}

// ── the uploader (anonymous) ─────────────────────────────────────────────────
// CSRF: exempt from the session's CSRF token, like the other anonymous routes
// (SECURITY.md "CSRF"). The uploader has no account: nothing here reads the
// session cookie, so a forged request carries no user's authority, and a
// signed-in user's cookie in the same browser changes nothing. What these
// routes act on is held by the link instead (the link proof from the
// #fragment, then the session grant and the per-file upload token), and they
// keep their own guards: the cross-site check before any Guard accounting,
// a non-simple request (the intent header, a JSON or octet-stream body, or
// the grant and upload-token headers, which a cross-origin page cannot send
// without a failing preflight), Turnstile on `begin` (before the password),
// the link's password lockout, the Guard's `invalid` scope and the
// per-network session limit.

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

/** What a link takes now: the kinds it accepts (`head.accept`) that its user's role allows (`tg.kinds`). */
const acceptedNow = (head, tg) => (Array.isArray(head?.accept) ? head.accept : DEFAULT_ACCEPT).filter((k) => Array.isArray(tg.kinds) && tg.kinds.includes(k));
const notAccepted = (kind) => err(403, 'kind_not_accepted', `This link does not accept ${KIND_PLURALS[kind] ?? 'that'}.`, { kind });

/** Everything under /api/reverse/. */
export async function handleReversePublic(request, env, url) {
  const m = url.pathname.match(/^\/api\/reverse\/([^/]+)\/(open|begin|files|done|human)(?:\/([^/]+)(?:\/(chunk|finalize)(?:\/(\d{1,6}))?)?)?$/);
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
  if (tg.state === 'unknown') {
    // The link of an account deleted since (its index row and Drive are gone): a grant or upload token
    // it issued is a genuine uploader's late request (the Directory keeps their hashes for a day:
    // reverseLateAdd), answered 410 and never counted; anything else is a guess.
    if ((action === 'files' || action === 'done') && (await lateOfDeleted(dir, id, request))) return err(410, 'gone', GONE);
    return failed(env, g, err(404, 'not_found', 'Not found.'));
  }

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
    if (lh) return res;
    // A grant or an upload token this link issued (its session or upload ended with it, e.g. when it
    // was revoked): an uploader's late request, never counted; an unknown or forged one is.
    if (tg.uid && (action === 'files' || action === 'done') && (await issuedBy(env, tg.uid, id, request)).known) return res;
    return failed(env, g, res);
  }
  const uid = tg.uid;
  const drive = driveStub(env, uid);
  // The link's CAPTCHA is in force only while the server has Turnstile keys.
  const captcha = tg.captcha && !!(await turnstileKeys(env));

  if (action === 'human') {
    // A CAPTCHA grant for this link (the check page, before the uploader page
    // starts a session): a Turnstile token for "reverse-upload" → { grant }.
    if (rawNode !== undefined) return err(404, 'not_found', 'Not found.');
    if (request.method !== 'POST') return methodNotAllowed('POST');
    assertIntent(request);
    // A link whose views are used up (or that ended in its Drive) takes no
    // session: no CAPTCHA is checked and no grant is issued for it. Without a
    // link proof here, the 410 counts in the Guard as for any ended link.
    const o = await drive.reverseOpen(uid, id);
    if ((o.status !== 'ok' && o.status !== 'paused') || o.usedUp || (o.status === 'ok' && !acceptedNow(o.head, tg).length)) return failed(env, g, err(410, 'gone', GONE));
    if (!captcha) return json({ grant: null, expires: null });
    await verifyCaptcha(env, g, request, TURNSTILE_ACTIONS.reverse);
    const r = await issueGrant(env, { kind: 'r', id, net: await netTag(env, g.key) });
    return json({ grant: r.grant, expires: r.expires });
  }

  if (action === 'open') {
    if (rawNode !== undefined) return err(404, 'not_found', 'Not found.');
    const r = await drive.reverseOpen(uid, id, { roleMaxBytes: tg.roleMaxBytes });
    if (r.status === 'paused') return pausedRes(); // the link proof matched (above)
    // Revoked, expired, or its views used up (as a used-up share: 410); or its
    // user's role no longer allows anything it accepts.
    const accept = r.status === 'ok' ? acceptedNow(r.head, tg) : [];
    if (r.status !== 'ok' || r.usedUp || !accept.length) return err(410, 'gone', GONE);
    return json({ ...r.head, accept, expires: apiExpiry(r.head.expires), captcha });
  }

  if (action === 'begin') {
    if (rawNode !== undefined) return err(404, 'not_found', 'Not found.');
    // What the session sends, as the uploader's browser declares it (a JSON
    // body { type }; none: files, as every client before these kinds). The
    // server sees the kind of a send, never its content (docs/REVERSE.md §2).
    let kind = 'files';
    if ((request.headers.get('content-type') || '').split(';')[0].trim().toLowerCase() === 'application/json') {
      const body = await readJsonBody(request);
      if (body.type !== undefined) {
        if (!isKind(body.type)) return invalid('type must be files, note, url or secret.');
        kind = body.type;
      }
    }
    const r = await drive.reverseOpen(uid, id);
    // Paused: no session, before the human check and the password (nothing is answered).
    if (r.status === 'paused') return pausedRes();
    // Its views used up: no session either, and no CAPTCHA or password is checked.
    const accept = r.status === 'ok' ? acceptedNow(r.head, tg) : [];
    if (r.status !== 'ok' || r.usedUp || !accept.length) return err(410, 'gone', GONE);
    // The link, and its user's role now, must take this kind (before any CAPTCHA, password or view).
    if (!accept.includes(kind)) return notAccepted(kind);
    const kp = request.headers.get('x-key-proof');
    if (r.ph && !kp) return err(401, 'password_required', 'This link needs a password.', { salt: r.head.password.salt, t: r.head.password.t });
    const lockedRes = (until) => err(429, 'password_locked', 'Too many wrong passwords for this link. Try again later.', { until });
    if (r.head.password && r.head.password.lockedUntil) return lockedRes(r.head.password.lockedUntil);
    // The CAPTCHA first (when the link has it): without it no password guess
    // is answered. A grant from …/human (spent by this session start,
    // whatever follows) or, as before these grants, a Turnstile token.
    let human = null;
    if (captcha) {
      const held = request.headers.get(HUMAN_HEADER);
      if (held) {
        const c = await readGrant(env, held, { kind: 'r', id, net: await netTag(env, g.key) });
        if (!c) throw captchaRequired(true);
        human = { j: c.j, exp: c.exp };
      } else if (request.headers.get('x-secbin-turnstile')) {
        await verifyCaptcha(env, g, request, TURNSTILE_ACTIONS.reverse);
      } else throw captchaRequired(true);
    }
    // The user's quotas of kind receive-upload, receive and the kind's own
    // (receive-file, receive-note, receive-url, receive-secret) count this
    // session (given back below when it does not start, and when it ends
    // having sent nothing). At the quota the uploader learns only that the
    // link cannot take uploads now, never the user's quota.
    const quota = await dir.authorizeReceiveUpload(uid, kind);
    if (!quota.ok) return quota.status === 429 ? err(429, 'not_accepting', NOT_ACCEPTING) : err(410, 'gone', GONE);
    const grant = genToken();
    // The password is checked in the Drive, with the link's lockout (all networks).
    const proofHash = r.ph && isProof(kp) ? await proofHashOf(kp) : null;
    let s;
    try {
      s = await drive.reverseBegin(uid, id, await hashToken(grant), tg.pendingSec, { net: await reverseNet(env, g.key), proofHash, human, kind });
    } catch (e) {
      await dir.refund(uid, quota.refund);
      throw e;
    }
    if (s.status !== 'ok') await dir.refund(uid, quota.refund);
    if (s.lapsed?.length) await refundLapsed(dir, uid, s.lapsed); // sessions that sent nothing
    if (s.status === 'captcha_used') throw captchaRequired(true);
    if (s.status === 'bad_password') {
      await dir.reverseEvent(id, 'bad_password');
      return failed(env, g, err(403, 'bad_password', 'Wrong password.', s.until ? { until: s.until } : undefined));
    }
    if (s.status === 'pw_locked') return lockedRes(s.until);
    if (s.status === 'busy') return err(429, 'busy', 'Too many uploads to this link are in progress. Try again later.');
    if (s.status === 'paused') return pausedRes();
    // used_up (the last view went to a concurrent start) or ended: 410, as a used-up share.
    if (s.status !== 'ok') return err(410, 'gone', GONE);
    // A receipt for the user: one view, one upload session granted (a start that failed is none).
    await recordOpen(env, request, id);
    return json({ grant, expires: s.expires });
  }

  if (action === 'done') {
    if (rawNode !== undefined) return err(404, 'not_found', 'Not found.');
    if (request.method !== 'POST') return methodNotAllowed('POST');
    assertIntent(request);
    const grant = grantOf(request);
    if (!grant) return failed(env, g, err(403, 'bad_grant', 'Missing or invalid X-Reverse-Grant.'));
    const r = await drive.reverseDone(uid, id, await hashToken(grant));
    if (r.status !== 'ok') return lateOrForged(env, g, uid, id, request, err(403, 'bad_grant', 'This upload session has ended.'));
    if (r.files > 0) await dir.reverseEvent(id, 'received', { files: r.files, bytes: r.bytes });
    else if (r.started) await dir.refundAt(uid, KIND_ACTIONS[isKind(r.kind) ? r.kind : 'files'], [r.started]); // it sent nothing: not counted
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
    const i = Number(idx);
    // The chunk request starts: checked (the token, the upload still open) and recorded as the
    // upload's activity before its body is read, so a slow sender is never released as idle while
    // its chunk is still arriving (docs/REVERSE.md §4).
    const st = await drive.reverseChunkStart(uid, id, node, await hashToken(token), i);
    if (st.status !== 'ok') return chunkRefusal(env, g, st, i);
    const bytes = await readCappedBody(request.body, MAX_CHUNK_CT);
    if (bytes === null) return err(413, 'too_large', 'Chunk is too large.');
    // The upload's content counts in the Drive as it arrives: each chunk must fit (docs/REVERSE.md §4).
    const r = await drive.reversePutChunk(uid, id, node, await hashToken(token), i, bytes, { capacity: tg.capacity ?? HARD_MAX_DRIVE_BYTES });
    if (r.status !== 'ok') return chunkRefusal(env, g, r, i);
    await dir.setDriveUsed(uid, r.used);
    return json({ ok: true });
  }
  const grant = grantOf(request);
  if (!grant) return failed(env, g, err(403, 'bad_grant', 'Missing or invalid X-Reverse-Grant.'));
  if (!token) return failed(env, g, err(403, 'bad_token', 'Missing or invalid X-Upload-Token.'));
  if (sub === 'finalize' && idx === undefined) {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const r = await drive.reverseFinalize(uid, id, await hashToken(grant), node, await hashToken(token), tg.pendingSec);
    if (r.status === 'bad_grant') return lateOrForged(env, g, uid, id, request, err(403, 'bad_grant', 'This upload session has ended.'));
    if (r.status === 'forbidden') return failed(env, g, err(403, 'bad_token', 'Wrong upload token.'));
    if (r.status === 'incomplete') return err(409, 'incomplete', `Chunk ${r.missing} has not been uploaded.`);
    if (r.status === 'busy') return json({ error: 'busy', message: 'A chunk of this file is still being stored. Try again in a moment.' }, 409, { 'retry-after': '1' });
    // The user's drive-bytes quota is reached (the uploader learns nothing of it).
    if (r.status === 'quota') return err(429, 'not_accepting', NOT_ACCEPTING);
    if (r.status !== 'ok') return err(410, 'gone', 'This upload has expired or was already finished.');
    return json({ ok: true });
  }
  if (sub === undefined) {
    if (request.method !== 'DELETE') return methodNotAllowed('DELETE');
    const r = await drive.reverseCancel(uid, id, await hashToken(grant), node, await hashToken(token));
    if (r.status === 'bad_grant') return lateOrForged(env, g, uid, id, request, err(403, 'bad_grant', 'This upload session has ended.'));
    if (r.status === 'forbidden') return failed(env, g, err(403, 'bad_token', 'Wrong upload token.'));
    if (r.status !== 'ok') return err(410, 'gone', 'This upload has already finished or ended.');
    const u = await drive.usage(uid);
    await dir.setDriveUsed(uid, u.used);
    return json({ ok: true });
  }
  return err(404, 'not_found', 'Not found.');
}

/** A chunk request the Drive refused (reverseChunkStart, reversePutChunk: `r`) → the answer; only a wrong token counts. */
function chunkRefusal(env, g, r, i) {
  if (r.status === 'forbidden') return failed(env, g, err(403, 'bad_token', 'Wrong upload token.'));
  if (r.status === 'bad_index') return err(400, 'bad_index', 'No such chunk index.');
  if (r.status === 'bad_size') return err(400, 'bad_size', `Chunk ${i} must be exactly ${r.expected} bytes.`);
  if (r.status === 'full') return err(413, 'drive_full', 'There is not enough space left for that file.');
  // No chunk started for 10 minutes: the reservation was released (never counted); the session may reserve it again.
  if (r.status === 'released') return err(410, 'released', 'This upload waited too long without data and was released: send the file again.');
  return err(410, 'gone', 'This upload has expired or was already finished.');
}

/**
 * Did link `id` issue the session grant (X-Reverse-Grant) or upload token
 * (X-Upload-Token) `request` carries — a session open or ended, an upload
 * reserved or dropped (the Drive keeps them for a day: rgone)? → { known, state }.
 */
async function issuedBy(env, uid, id, request) {
  const hashes = await requestHashes(request);
  return hashes.length ? driveStub(env, uid).grantKnown(uid, id, hashes) : { known: false, state: 'gone' };
}
/** The hashes of the session grant and upload token `request` carries (as the Drive stores them). */
async function requestHashes(request) {
  const hashes = [];
  for (const t of [grantOf(request), uploadTokenOf(request)]) if (t) hashes.push(await hashToken(t));
  return hashes;
}
/** Did link `id`, of an account deleted since, issue the grant or upload token `request` carries (Directory reverseLate)? */
async function lateOfDeleted(dir, id, request) {
  const hashes = await requestHashes(request);
  return hashes.length > 0 && (await dir.reverseLateKnown(id, hashes)) === true;
}
/**
 * A grant-bearing request its session no longer takes: a grant or token the
 * link issued is a genuine uploader's late request (the link was paused,
 * revoked or ended, or the session ended) and is never counted in the Guard —
 * `409 paused` while the link is paused, `410` once it has ended, else `res`;
 * only an unknown or forged one counts (`res`, counted).
 */
async function lateOrForged(env, g, uid, id, request, res) {
  const k = await issuedBy(env, uid, id, request);
  if (!k.known) return failed(env, g, res);
  if (k.state === 'paused') return pausedRes();
  if (k.state !== 'active') return err(410, 'gone', GONE);
  return res;
}

/** Give back the quota of sessions that lapsed having sent nothing (`lapsed`: [{ started, kind }]), per kind of send. */
async function refundLapsed(dir, uid, lapsed) {
  for (const [kind, action] of Object.entries(KIND_ACTIONS)) {
    const times = lapsed.filter((x) => (isKind(x.kind) ? x.kind : 'files') === kind).map((x) => x.started);
    if (times.length) await dir.refundAt(uid, action, times);
  }
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
  const o = await drive.reverseOpen(uid, id, { roleMaxBytes: tg.roleMaxBytes, session: await hashToken(grant) });
  // A paused link has no session (they ended when it was paused): a grant it issued gets 409 paused,
  // uncounted; one it never issued is a guess.
  const ended = err(403, 'bad_grant', 'This upload session has ended. Reload the page to start again.');
  if (o.status === 'paused') return lateOrForged(env, g, uid, id, request, ended);
  if (o.status !== 'ok') return err(410, 'gone', GONE);
  if (!o.session) return lateOrForged(env, g, uid, id, request, ended);
  // Every upload: the kind of its session must still be one the link and its user's role take.
  if (!acceptedNow(o.head, tg).includes(o.session.kind)) return notAccepted(o.session.kind);
  // The file types apply to files only (a note, a link or a credential is not a file of a type).
  const rules = o.session.kind === 'files' ? o.head.limits.types : null;
  if (rules) {
    if (body.types === undefined) return err(400, 'declaration_required', 'This link accepts only some file types: declare the file\'s type.', { policy: rules });
    const types = checkDeclaredTypes(body.types);
    if (!types || types.length !== 1) return invalid('types must declare this one file\'s type.');
    const refused = refusedTypes(rules.mode, rules.rules, types);
    if (refused.length) return err(403, 'file_type_not_allowed', `This link does not accept ${refused.map(describeType).join(', ')} files.`, { refused });
  }
  // A received file is Drive storage: its size counts under the user's drive-bytes quotas when it is
  // finished (reverseFinalize). Refused now, before anything is sent, when it could not fit there.
  const room = await directory(env).authorizeReceivedBytes(uid, { size: body.size, dry: true });
  if (!room.ok) return room.status === 429 ? err(429, 'not_accepting', NOT_ACCEPTING) : err(410, 'gone', GONE);
  const uploadToken = genToken();
  // At rest, under the user's field layer (the Drive object sees only these).
  const fk = await fieldKeys(env, uid);
  const r = await drive.reverseCreateFile(uid, id, await hashToken(grant), {
    node, name: await toRest(fk, uid, 'received', `name:${node}`, name), meta: await toRest(fk, uid, 'received', `meta:${node}`, meta),
    // The session's declared kind goes with the item, sealed at rest with its wrap (never in plain
    // text): the user's browser fails an item whose sealed marker is another kind (docs/REVERSE.md §3).
    wrap: await toRest(fk, uid, 'received', `wrap:${node}`, JSON.stringify({ kind: 'rs', data: wrap, declared: o.session.kind })), size: body.size, uploadHash: await hashToken(uploadToken),
    capacity: tg.capacity ?? HARD_MAX_DRIVE_BYTES, maxFile: tg.maxFile ?? HARD_MAX_DRIVE_BYTES, pendingSec: tg.pendingSec,
    roleMaxBytes: tg.roleMaxBytes, // the role's current cap applies to existing links too
  });
  if (!r.ok) return r.error === 'bad_grant' ? lateOrForged(env, g, uid, id, request, fromDo(r)) : fromDo(r);
  await directory(env).setDriveUsed(uid, r.used);
  return json({ id: r.id, uploadToken, chunks: r.chunks }, 201);
}
