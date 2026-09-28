// public.js — the unauthenticated, capability-gated read surface: share heads,
// proof-gated opens, file chunk downloads under a grant, delete-by-token, and
// the public viewer policy. Every failure a guesser would produce (unknown id,
// wrong #fragment, wrong password, bad grant, bad delete token) feeds the
// Guard's "invalid" scope, and blocked callers are refused up front.

import { json, err, HttpError, assertNotCrossSite, decodePathSegment, methodNotAllowed, SECURITY_HEADERS } from '../lib/http.js';
import { kvGet, kvDelete, burnStub, fileStub } from '../lib/store.js';
import { ipContext, isBlocked, recordFailure, directory, cachedPublicConfig } from '../lib/guard.js';
import { parseUserAgent, parseLanguages } from '../lib/ua.js';
import { parseId, verifyToken, genToken, hashToken } from '../lib/ids.js';
import { isProof } from '../../public/js/format.js';
import { b64urlFromBytes, bytesFromB64url, timingSafeEqualHex } from '../../public/js/bytes.js';
import { binding } from '../lib/config.js';
import { turnstileKeys } from '../lib/turnstile.js';

const GONE = 'This share does not exist, has expired, or has no views left.';

async function proofHashOf(b64) {
  return b64urlFromBytes(new Uint8Array(await crypto.subtle.digest('SHA-256', bytesFromB64url(b64))));
}

/** Read + validate the two proof headers → their hashes, or throw 400. */
async function proofHashes(request) {
  const lp = request.headers.get('x-link-proof');
  const kp = request.headers.get('x-key-proof');
  if (!isProof(lp) || !isProof(kp)) throw new HttpError(400, 'missing_proof', 'Opening a share requires the X-Link-Proof and X-Key-Proof headers.');
  return { lh: await proofHashOf(lp), kh: await proofHashOf(kp) };
}

const eqB64 = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqualHex(a, b);

async function blockedResponse(env, g) {
  const b = await isBlocked(env, g, 'invalid');
  if (!b.blocked) return null;
  return err(429, 'blocked', 'Too many invalid requests from your network. Try again later.', b.until ? { until: b.until } : undefined);
}

/** Record an "invalid" failure and return `res` (or a 429 if that tipped the block). */
async function failed(env, g, res) {
  const b = await recordFailure(env, g, 'invalid');
  if (b.newlyBlocked) return err(429, 'blocked', 'Too many invalid requests from your network. Try again later.', { until: b.until });
  return res;
}

/**
 * A well-formed id whose content is gone (or never existed). Not counted as
 * invalid when it was a share that expired, was used up, revoked or deleted
 * and the request's link proof (the #key) is right: that is a legitimate
 * recipient arriving late. Counted when the id was never a share, or when the
 * link proof is wrong (a guess at a share that no longer exists). A request
 * without a proof (the first metadata fetch) is not counted for a known share.
 * The answer is the same "gone" either way.
 */
async function goneFor(env, g, id, res, lh = null) {
  if ((await directory(env).goneShare(id, lh)) === 'ok') return res;
  return failed(env, g, res);
}

/**
 * Read receipt: record that a share was opened, with what the request itself
 * revealed (address, Cloudflare's coarse location, browser, OS, languages).
 * Never fails the open.
 */
// A flood guard in front of the single Directory object: beyond
// RECENT_OPEN_BURST opens of one share from one address within a minute, this
// isolate stops recording them (the Directory throttles stored receipts again
// for all isolates). Ordinary use, several people behind one address
// included, is counted in full.
const recentOpens = new Map();
const RECENT_OPEN_MS = 60_000;
const RECENT_OPEN_BURST = 5;
const RECENT_OPEN_MAX = 5000;
function flooding(key) {
  const t = Date.now();
  const e = recentOpens.get(key);
  if (e && t - e.start < RECENT_OPEN_MS) {
    e.n += 1;
    return e.n > RECENT_OPEN_BURST;
  }
  if (recentOpens.size >= RECENT_OPEN_MAX) recentOpens.clear();
  recentOpens.set(key, { start: t, n: 1 });
  return false;
}

async function recordOpen(env, request, id) {
  try {
    if (flooding(`${id}|${request.headers.get('cf-connecting-ip') || ''}`)) return;
    const ua = parseUserAgent(request.headers.get('user-agent'));
    const cf = request.cf || {};
    await directory(env).recordOpen(id, {
      ip: request.headers.get('cf-connecting-ip') || '',
      country: typeof cf.country === 'string' ? cf.country : '',
      region: typeof cf.region === 'string' ? cf.region : '',
      city: typeof cf.city === 'string' ? cf.city : '',
      browser: ua.browser, version: ua.version, os: ua.os,
      langs: parseLanguages(request.headers.get('accept-language')),
    });
  } catch (e) {
    console.warn('secbin: read receipt not recorded', e && e.message ? e.message : e);
  }
}

const proofFailure = (status) => (status === 'bad_link'
  ? err(403, 'bad_link', 'The link is incomplete or corrupted.')
  : err(403, 'bad_password', 'Wrong password.'));

export async function handlePublic(request, env, url) {
  const { pathname } = url;

  if (pathname === '/api/config') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    // The site key is public by design; null means no human check anywhere.
    return json({ ...(await cachedPublicConfig(env)), turnstile: (await turnstileKeys(env))?.sitekey ?? null });
  }

  if (pathname === '/api/paste') {
    // v1 anonymous creation is gone: creating needs an account.
    return err(410, 'moved', 'Creating notes now requires an account: POST /api/private/paste.');
  }

  // /chunk/<i> reads a file share's stream; /chunk/<ref>/<i> a Drive share's file.
  const m = pathname.match(/^\/api\/(paste|file)\/([^/]+)(?:\/(open|expire|extend|chunk)(?:\/(\d{1,6})(?:\/(\d{1,6}))?)?)?$/);
  if (!m) return null;
  const [, kind, rawId, action, idx, idx2] = m;
  const id = decodePathSegment(rawId);

  // Before any Guard accounting: another site can make a visitor's browser
  // send simple GETs here (<img src>, no preflight). Counted as "invalid",
  // they would get the visitor's network blocked from opening shares. The
  // app only ever calls these from its own pages; the CLI sends no header.
  assertNotCrossSite(request);
  const g = await ipContext(env, request);
  const blocked = await blockedResponse(env, g);
  if (blocked) return blocked;

  const info = id === null ? null : parseId(id);
  if (!info || (kind === 'file') !== info.file) {
    return failed(env, g, err(404, 'not_found', GONE));
  }

  if (!action) {
    if (request.method === 'GET') return readHead(env, g, id, info);
    if (request.method === 'DELETE') return deleteByToken(request, env, g, id, info);
    return methodNotAllowed('GET, DELETE');
  }
  if (action === 'open') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    assertNotCrossSite(request);
    const proofs = await proofHashes(request);
    const res = await (info.file ? openFile(env, g, id, proofs) : openPaste(env, g, id, info, proofs));
    if (res.status === 200) await recordOpen(env, request, id);
    return res;
  }
  if (action === 'expire') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    assertNotCrossSite(request);
    const proofs = await proofHashes(request);
    return expireByOpener(env, g, id, info, proofs);
  }
  if (action === 'extend' && info.file && idx === undefined) {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    return extendGrant(request, env, g, id);
  }
  if (action === 'chunk' && info.file && idx !== undefined) {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    return idx2 === undefined ? downloadChunk(request, env, g, id, Number(idx)) : downloadChunk(request, env, g, id, Number(idx2), Number(idx));
  }
  return err(404, 'not_found', 'Not found.');
}

async function readHead(env, g, id, info) {
  if (info.file) {
    const r = await fileStub(env, id).head();
    if (r.status !== 'ok') return goneFor(env, g, id, err(410, 'gone', GONE));
    return json(r.head);
  }
  if (info.burn) {
    const r = await burnStub(env, id).head();
    if (r.status !== 'ok') return goneFor(env, g, id, err(410, 'gone', GONE));
    return json(r.head);
  }
  const rec = await kvGet(env, id);
  if (!rec) return goneFor(env, g, id, err(404, 'not_found', GONE));
  return json({ v: rec.paste.v, adata: rec.paste.adata, meta: rec.paste.meta });
}

async function openPaste(env, g, id, info, { lh, kh }) {
  if (info.burn) {
    const r = await burnStub(env, id).open(lh, kh);
    if (r.status === 'ok') {
      if (r.paste.meta.left === 0) await directory(env).markShareEnded(id, 'consumed');
      return json(r.paste);
    }
    if (r.status === 'bad_link' || r.status === 'bad_password') return failed(env, g, proofFailure(r.status));
    return goneFor(env, g, id, err(410, 'gone', GONE), lh);
  }
  const rec = await kvGet(env, id);
  if (!rec) return goneFor(env, g, id, err(404, 'not_found', GONE), lh);
  if (!eqB64(lh, rec.acc.lh)) return failed(env, g, proofFailure('bad_link'));
  if (!eqB64(kh, rec.acc.kh)) return failed(env, g, proofFailure('bad_password'));
  const p = rec.paste;
  return json({ v: p.v, ct: p.ct, wk: p.wk, adata: p.adata, meta: p.meta });
}

async function openFile(env, g, id, { lh, kh }) {
  const grant = genToken();
  const client = (await hashToken(`grant-client:${g.key}`)).slice(0, 16);
  // The sender's role decides the download window and the viewer policy, now.
  const policy = await directory(env).shareOpenPolicy(id);
  const r = await fileStub(env, id).open(lh, kh, await hashToken(grant), policy.grantSec, client);
  if (r.status === 'ok') {
    if (r.paste.meta.left === 0) await directory(env).markShareEnded(id, 'consumed');
    // `now`: the server's time, so the viewer's download-window warning does not depend on its clock.
    const out = { paste: r.paste, grant, grantExpires: r.grantExpires, now: Math.floor(Date.now() / 1000), chunks: r.chunks, padded: r.padded, viewer: policy.viewer };
    if (r.refs) out.refs = r.refs; // a Drive share: its files' chunk counts and sizes
    return json(out);
  }
  if (r.status === 'bad_link' || r.status === 'bad_password') return failed(env, g, proofFailure(r.status));
  if (r.status === 'busy') {
    return json({ error: 'busy', message: 'Too many downloads of this share are in progress. Try again in a few minutes.' }, 429, { 'retry-after': '300' });
  }
  return goneFor(env, g, id, err(410, 'gone', GONE), lh);
}

/**
 * "Delete now" by a recipient: needs the same two proofs as opening (so only
 * someone who can open the share), works only when the sender allowed it, and
 * is refused while the admin has the share locked. Spends no view.
 */
async function expireByOpener(env, g, id, info, { lh, kh }) {
  const dir = directory(env);
  if (info.file) binding(env, 'FILES');
  // Checked now, not only at creation: a lock, or the admin withdrawing the
  // sender's permission, stops "delete now" on existing shares too.
  const allowed = await dir.recipientDeleteStatus(id);
  if (allowed === 'locked') return err(423, 'share_locked', 'The administrator has locked this share; it cannot be deleted.');
  if (allowed !== 'ok') return err(403, 'not_allowed', 'Recipients may not delete this share.');
  let status;
  if (info.file || info.burn) {
    status = (await (info.file ? fileStub(env, id) : burnStub(env, id)).expireByOpener(lh, kh)).status;
  } else {
    const rec = await kvGet(env, id);
    if (!rec) status = 'gone';
    else if (!eqB64(lh, rec.acc.lh)) status = 'bad_link';
    else if (!eqB64(kh, rec.acc.kh)) status = 'bad_password';
    else if (rec.paste.meta.deletable !== true) status = 'not_allowed';
    else { await kvDelete(env, id); status = 'ok'; }
  }
  if (status === 'ok') {
    await dir.shareDeletedByRecipient(id);
    return json({ status: 'deleted', id });
  }
  if (status === 'bad_link' || status === 'bad_password') return failed(env, g, proofFailure(status));
  if (status === 'not_allowed') return err(403, 'not_allowed', 'The sender did not allow recipients to delete this share.');
  return goneFor(env, g, id, err(410, 'gone', GONE), lh);
}

/**
 * Keep a download window open longer (WCAG 2.2.1): the grant itself is the
 * credential (as for chunks); the window is the sender's role's, now. Every
 * refusal counts towards the network's "invalid" limit, so repeated calls end
 * in 429 (refused up front, before the Directory): a bad grant, an id that
 * was never a share (answered from the Directory's index alone, without
 * creating a FileShare object), a grant past its last extension (the viewer
 * stops asking after the first 409) and a share that has ended (a late tab
 * asks once). Each extension is recorded in the share owner's activity log.
 */
async function extendGrant(request, env, g, id) {
  const grant = request.headers.get('x-download-grant') || '';
  if (!/^[A-Za-z0-9_-]{43}$/.test(grant)) return failed(env, g, err(403, 'bad_grant', 'A valid X-Download-Grant header is required.'));
  const policy = await directory(env).shareOpenPolicy(id);
  if (!policy.known) return failed(env, g, err(410, 'gone', GONE));
  const r = await fileStub(env, id).extendGrant(await hashToken(grant), policy.grantSec);
  if (r.status === 'ok') {
    await directory(env).recordDownloadExtended(id, { n: r.extensions, until: r.grantExpires });
    return json({ grantExpires: r.grantExpires, extensionsLeft: r.extensionsLeft, now: Math.floor(Date.now() / 1000) });
  }
  if (r.status === 'limit') return failed(env, g, err(409, 'extend_limit', 'The download window cannot be extended again. Open the link again if views remain.', { grantExpires: r.grantExpires }));
  if (r.status === 'bad_grant') return failed(env, g, err(403, 'bad_grant', 'The download window has expired — open the link again.'));
  return failed(env, g, err(410, 'gone', GONE));
}

/** Chunk i of a file share's stream, or (with `ref`) chunk i of a Drive share's file number `ref`. */
async function downloadChunk(request, env, g, id, i, ref = null) {
  const grant = request.headers.get('x-download-grant') || '';
  if (!/^[A-Za-z0-9_-]{43}$/.test(grant)) return failed(env, g, err(403, 'bad_grant', 'A valid X-Download-Grant header is required.'));
  const stub = fileStub(env, id);
  const r = ref === null ? await stub.chunkAccess(await hashToken(grant), i) : await stub.chunkAccessRef(await hashToken(grant), ref, i);
  if (r.status === 'bad_index') return err(404, 'not_found', 'No such chunk.');
  if (r.status !== 'ok') return failed(env, g, err(r.status === 'bad_grant' ? 403 : 410, r.status === 'bad_grant' ? 'bad_grant' : 'gone',
    r.status === 'bad_grant' ? 'The download window has expired — open the link again.' : GONE));
  const obj = await binding(env, 'FILES').get(r.key);
  if (!obj) return err(410, 'gone', GONE);
  return new Response(obj.body, {
    status: 200,
    headers: {
      ...SECURITY_HEADERS,
      'content-type': 'application/octet-stream',
      'content-length': String(obj.size),
      'content-disposition': 'attachment; filename="chunk.bin"',
      'cache-control': 'no-store',
    },
  });
}

async function deleteByToken(request, env, g, id, info) {
  // The token travels in a header, never the URL (request URLs reach logs).
  const token = request.headers.get('x-delete-token');
  if (!token) return err(400, 'missing_token', 'Missing deletion token.');
  // An admin lock freezes the share for everyone but the admin — including
  // its delete token. (Only link holders know the 128-bit id, so saying
  // "locked" before checking the token reveals nothing new.)
  if (await directory(env).isShareLocked(id)) return err(423, 'share_locked', 'The administrator has locked this share; it cannot be deleted.');
  if (info.file) binding(env, 'FILES'); // never report a delete that left ciphertext in R2
  if (info.file || info.burn) {
    const r = await (info.file ? fileStub(env, id) : burnStub(env, id)).remove(token);
    if (r.status === 'ok') { await directory(env).markShareEnded(id, 'deleted'); return json({ status: 'deleted', id }); }
    if (r.status === 'bad') return failed(env, g, err(403, 'bad_token', 'Wrong deletion token. The share was not deleted.'));
    return goneFor(env, g, id, err(404, 'not_found', GONE));
  }
  const rec = await kvGet(env, id);
  if (!rec) return goneFor(env, g, id, err(404, 'not_found', GONE));
  if (!(await verifyToken(token, rec.dth))) return failed(env, g, err(403, 'bad_token', 'Wrong deletion token. The share was not deleted.'));
  await kvDelete(env, id);
  await directory(env).markShareEnded(id, 'deleted');
  return json({ status: 'deleted', id });
}
