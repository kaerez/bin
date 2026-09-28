// drive-helpers.js — fixtures for the Drive suites: enable the Drive for a
// user (through a role of their own, as an admin would), encrypted-looking
// fields, folder / file creation and a complete chunked upload.
import { SELF } from 'cloudflare:test';
import { ORIGIN, fetchJson, owner, intent, csrfHeaders } from './helpers.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';
import { driveChunkSize } from '../src/drive-do.js';
import { escrowKid } from '../src/routes/drive.js';

/** An opaque {iv, ct} field as the browser would send it (random bytes: the server cannot tell). */
export const enc = (n = 32) => ({ iv: b64urlFromBytes(randomBytes(12)), ct: b64urlFromBytes(randomBytes(n + 16)) });
export const newNodeId = () => b64urlFromBytes(randomBytes(16));
/** A stand-in for the Drive key's check value (drivekeys.js keyCheckValue): the server only compares it. */
export const KCV = b64urlFromBytes(randomBytes(32));
/**
 * What one item's sealed fields add to the Drive's `used` (docs/DRIVE.md §10):
 * a folder's name, or a file's name, metadata and key, as the fixtures send them.
 */
export const FIELD_BYTES = JSON.stringify(enc()).length;
export const DIR_BYTES = FIELD_BYTES;
export const FILE_BYTES = 3 * FIELD_BYTES;
/** `n` bytes standing in for ciphertext (random at the start; getRandomValues takes at most 64 KiB). */
export function someBytes(n) {
  const b = new Uint8Array(n);
  b.set(randomBytes(Math.min(n, 65536)));
  for (let i = 65536; i < n; i++) b[i] = (i * 31) & 0xff;
  return b;
}

/** Set role options for `uid` (a role of their own). */
export async function driveLimits(uid, patch) {
  const oc = await owner();
  const r = await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: uid, channel: 'all', patch } });
  if (r.status !== 200) throw new Error(`limits: ${r.status} ${await r.text()}`);
}
export const enableDrive = (uid, extra = {}) => driveLimits(uid, { driveEnabled: true, ...extra });

export async function mkdir(cookie, parent = 'root', { id } = {}) {
  const r = await fetchJson('/api/private/drive/folders', { method: 'POST', cookie, body: { parent, name: enc(), ...(id ? { id } : {}) } });
  return { res: r, id: r.status === 201 ? (await r.json()).id : null };
}

export async function createFile(cookie, parent, size, { id } = {}) {
  const r = await fetchJson('/api/private/drive/files', { method: 'POST', cookie, body: { parent, name: enc(), meta: enc(), size, fk: enc(32), ...(id ? { id } : {}) } });
  return { res: r, ...(r.status === 201 ? await r.json() : {}) };
}

/** A raw chunk upload as the browser sends it: the session's CSRF token too (`headers` may override it). */
export const putChunk = async (cookie, id, i, bytes, token, headers = {}) => SELF.fetch(`${ORIGIN}/api/private/drive/files/${id}/chunk/${i}`, {
  method: 'PUT', headers: { cookie, ...(await csrfHeaders(cookie)), 'content-type': 'application/octet-stream', 'x-upload-token': token, ...headers }, body: bytes,
});
// As the browser sends it (api.js drive.finalize): no body, so the intent header (the request-shape check).
export const finalize = (cookie, id, token) => fetchJson(`/api/private/drive/files/${id}/finalize`, { method: 'POST', cookie, headers: { ...intent, 'x-upload-token': token } });
export const getChunk = (cookie, id, i) => SELF.fetch(`${ORIGIN}/api/private/drive/files/${id}/chunk/${i}`, { headers: { cookie } });

/** Create + upload + finalize a file of `size` bytes of (random) ciphertext; returns its id and the chunks written. */
export async function uploadFile(cookie, parent, size) {
  const f = await createFile(cookie, parent, size);
  if (f.res.status !== 201) throw new Error(`create file: ${f.res.status} ${await f.res.text()}`);
  const chunks = [];
  for (let i = 0; i < f.chunks; i++) {
    const bytes = someBytes(driveChunkSize(size, i));
    const r = await putChunk(cookie, f.id, i, bytes, f.uploadToken);
    if (r.status !== 200) throw new Error(`chunk ${i}: ${r.status} ${await r.text()}`);
    chunks.push(bytes);
  }
  const fin = await finalize(cookie, f.id, f.uploadToken);
  if (fin.status !== 200) throw new Error(`finalize: ${fin.status} ${await fin.text()}`);
  return { id: f.id, chunks };
}

export const del = (cookie, id) => fetchJson(`/api/private/drive/nodes/${id}`, { method: 'DELETE', cookie, headers: intent });
export const node = async (cookie, id) => fetchJson(`/api/private/drive/nodes/${id}`, { cookie });
export const drive = async (cookie) => (await fetchJson('/api/private/drive', { cookie })).json();

/**
 * The owner's escrow key (docs/DRIVE.md §3: it exists before any user's Drive):
 * set once (a stand-in public key; the server only checks its form) and
 * returned. A user's Drive is set up with an escrow wrap for it (escrowWrap).
 */
export async function ensureEscrow() {
  const oc = await owner();
  const st = await drive(oc);
  if (st.escrowPub) return st.escrowPub;
  const jwk = { kty: 'EC', crv: 'P-256', x: b64urlFromBytes(randomBytes(32)), y: b64urlFromBytes(randomBytes(32)) };
  const priv = `1.${b64urlFromBytes(randomBytes(12))}.${b64urlFromBytes(randomBytes(150))}`;
  const r = await fetchJson('/api/private/drive/keys', { method: 'PUT', cookie: oc, headers: intent, body: { escrowPub: jwk, escrowPriv: priv } });
  if (r.status !== 200) throw new Error(`escrow key: ${r.status} ${await r.text()}`);
  return jwk;
}

/** An escrow wrap (opaque stand-in data) for the owner's current escrow key. */
export async function escrowWrap() {
  const kid = await escrowKid(await ensureEscrow());
  return { kind: 'escrow', ref: 'escrow', data: `1.${b64urlFromBytes(randomBytes(65))}.${kid}.${b64urlFromBytes(randomBytes(12))}.${b64urlFromBytes(randomBytes(48))}` };
}
