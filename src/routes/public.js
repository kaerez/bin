// public.js — the unauthenticated, capability-gated read surface: share heads,
// proof-gated opens, file chunk downloads under a grant, delete-by-token, and
// the public viewer policy. Every failure a guesser would produce (unknown id,
// wrong #fragment, wrong password, bad grant, bad delete token) feeds the
// Guard's "invalid" scope, and blocked callers are refused up front.

import { json, err, HttpError, assertNotCrossSite, decodePathSegment, methodNotAllowed, SECURITY_HEADERS } from '../lib/http.js';
import { kvGet, kvDelete, burnStub, fileStub } from '../lib/store.js';
import { ipContext, isBlocked, recordFailure, directory } from '../lib/guard.js';
import { parseId, verifyToken, genToken, hashToken } from '../lib/ids.js';
import { isProof } from '../../public/js/format.js';
import { b64urlFromBytes, bytesFromB64url, timingSafeEqualHex } from '../../public/js/bytes.js';
import { binding } from '../lib/config.js';

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

const proofFailure = (status) => (status === 'bad_link'
  ? err(403, 'bad_link', 'The link is incomplete or corrupted.')
  : err(403, 'bad_password', 'Wrong password.'));

export async function handlePublic(request, env, url) {
  const { pathname } = url;

  if (pathname === '/api/config') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    return json(await directory(env).publicConfig());
  }

  if (pathname === '/api/paste') {
    // v1 anonymous creation is gone: creating needs an account.
    return err(410, 'moved', 'Creating notes now requires an account: POST /api/private/paste.');
  }

  const m = pathname.match(/^\/api\/(paste|file)\/([^/]+)(?:\/(open|chunk)(?:\/(\d{1,6}))?)?$/);
  if (!m) return null;
  const [, kind, rawId, action, idx] = m;
  const id = decodePathSegment(rawId);

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
    return info.file ? openFile(env, g, id, proofs) : openPaste(env, g, id, info, proofs);
  }
  if (action === 'chunk' && info.file && idx !== undefined) {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    return downloadChunk(request, env, g, id, Number(idx));
  }
  return err(404, 'not_found', 'Not found.');
}

async function readHead(env, g, id, info) {
  if (info.file) {
    const r = await fileStub(env, id).head();
    if (r.status !== 'ok') return failed(env, g, err(410, 'gone', GONE));
    return json(r.head);
  }
  if (info.burn) {
    const r = await burnStub(env, id).head();
    if (r.status !== 'ok') return failed(env, g, err(410, 'gone', GONE));
    return json(r.head);
  }
  const rec = await kvGet(env, id);
  if (!rec) return failed(env, g, err(404, 'not_found', GONE));
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
    return failed(env, g, err(410, 'gone', GONE));
  }
  const rec = await kvGet(env, id);
  if (!rec) return failed(env, g, err(404, 'not_found', GONE));
  if (!eqB64(lh, rec.acc.lh)) return failed(env, g, proofFailure('bad_link'));
  if (!eqB64(kh, rec.acc.kh)) return failed(env, g, proofFailure('bad_password'));
  const p = rec.paste;
  return json({ v: p.v, ct: p.ct, wk: p.wk, adata: p.adata, meta: p.meta });
}

async function openFile(env, g, id, { lh, kh }) {
  const settings = g.settings;
  const grant = genToken();
  const r = await fileStub(env, id).open(lh, kh, await hashToken(grant), settings['files.grantSec']);
  if (r.status === 'ok') {
    if (r.paste.meta.left === 0) await directory(env).markShareEnded(id, 'consumed');
    return json({ paste: r.paste, grant, grantExpires: r.grantExpires, chunks: r.chunks, padded: r.padded });
  }
  if (r.status === 'bad_link' || r.status === 'bad_password') return failed(env, g, proofFailure(r.status));
  if (r.status === 'busy') {
    return json({ error: 'busy', message: 'Too many downloads of this share are in progress. Try again in a few minutes.' }, 429, { 'retry-after': '300' });
  }
  return failed(env, g, err(410, 'gone', GONE));
}

async function downloadChunk(request, env, g, id, i) {
  const grant = request.headers.get('x-download-grant') || '';
  if (!/^[A-Za-z0-9_-]{43}$/.test(grant)) return failed(env, g, err(403, 'bad_grant', 'A valid X-Download-Grant header is required.'));
  const r = await fileStub(env, id).chunkAccess(await hashToken(grant), i);
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
  if (info.file || info.burn) {
    const r = await (info.file ? fileStub(env, id) : burnStub(env, id)).remove(token);
    if (r.status === 'ok') { await directory(env).markShareEnded(id, 'deleted'); return json({ status: 'deleted', id }); }
    if (r.status === 'bad') return failed(env, g, err(403, 'bad_token', 'Wrong deletion token. The share was not deleted.'));
    return failed(env, g, err(404, 'not_found', GONE));
  }
  const rec = await kvGet(env, id);
  if (!rec) return failed(env, g, err(404, 'not_found', GONE));
  if (!(await verifyToken(token, rec.dth))) return failed(env, g, err(403, 'bad_token', 'Wrong deletion token. The share was not deleted.'));
  await kvDelete(env, id);
  await directory(env).markShareEnded(id, 'deleted');
  return json({ status: 'deleted', id });
}
