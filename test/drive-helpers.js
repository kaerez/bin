// drive-helpers.js — fixtures for the Drive suites (key model v2, docs/
// DRIVE.md §3): enable the Drive for a user (through a role of their own, as
// an admin would), the session's KEKs from the server, items sealed for real
// under the current KEK (the server checks every seal opens), folder / file
// creation and a complete chunked upload.
import { SELF } from 'cloudflare:test';
import { ORIGIN, fetchJson, owner, intent, csrfHeaders } from './helpers.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';
import { keyBytes, newSalt, sealName, sealDek, openName, openDek } from '../public/js/drivekeys.js';
import { importFileKey, encryptChunk } from '../public/js/files.js';
import { driveChunkSize, driveChunks } from '../src/drive-do.js';

/** An opaque {iv, ct} field (random bytes: the server checks the Drive's seals, so this one does NOT open). */
export const enc = (n = 32) => ({ iv: b64urlFromBytes(randomBytes(12)), ct: b64urlFromBytes(randomBytes(n + 16)) });
export const newNodeId = () => b64urlFromBytes(randomBytes(16));

/** The fixtures' plaintext sizes: a name, a file's metadata, a DEK. */
export const NAME_LEN = 20;
export const META_LEN = 40;
const fieldLen = (n) => JSON.stringify({ iv: 'x'.repeat(16), ct: 'x'.repeat(Math.ceil(((n + 16) * 4) / 3)) }).length;
/**
 * What one item's sealed fields add to the Drive's `used` (docs/DRIVE.md §10):
 * a folder's name and salt; a file's name, metadata, sealed DEK and salt.
 */
export const DIR_BYTES = fieldLen(NAME_LEN) + 43;
export const FILE_BYTES = fieldLen(NAME_LEN) + fieldLen(META_LEN) + fieldLen(32) + 43;

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

// ── the session's keys ──────────────────────────────────────────────────────
const keyCache = new Map();
/** POST /api/private/drive/keys as `cookie` → { userId, current, keks: Map(mekId → bytes), raw } (cached per cookie; `fresh` re-reads). */
export async function driveKeys(cookie, { fresh = false } = {}) {
  if (!fresh && keyCache.has(cookie)) return keyCache.get(cookie);
  const r = await fetchJson('/api/private/drive/keys', { method: 'POST', cookie, body: {} });
  if (r.status !== 200) throw new Error(`drive keys: ${r.status} ${await r.text()}`);
  const raw = await r.json();
  const k = { userId: raw.userId, current: raw.current, keks: new Map(raw.keys.map((x) => [x.mekId, keyBytes(x.kek)])), raw };
  keyCache.set(cookie, k);
  return k;
}
export const forgetKeys = () => keyCache.clear();

/** A fixed-length random plaintext (so the sealed sizes are known). */
const plain = (n) => randomBytes(n);

/**
 * An item's fields sealed under the session's current KEK → { ks, mek, name,
 * meta?, dek?, dekBytes? } (the body fields the server expects). `kind`:
 * 'dir' or 'file'; `keys`: from driveKeys (else read now).
 */
export async function sealed(cookie, kind = 'dir', { keys = null, name = plain(NAME_LEN), meta = plain(META_LEN), dek = randomBytes(32), mek = null } = {}) {
  const k = keys || await driveKeys(cookie);
  const m = mek || k.current;
  const kek = k.keks.get(m);
  const ks = newSalt();
  const at = { userId: k.userId, mekId: m, salt: ks };
  const out = { ks, mek: m, name: await sealName(kek, at, 'name', name) };
  if (kind === 'file') {
    out.meta = await sealName(kek, at, 'meta', meta);
    out.dek = await sealDek(kek, at, dek);
    out.dekBytes = dek;
  }
  return out;
}

/** Open a stored item's name / DEK with the session's KEKs (a check in tests). */
export async function openStored(cookie, item) {
  const k = await driveKeys(cookie, { fresh: true });
  const kek = k.keks.get(item.mek);
  const at = { userId: k.userId, mekId: item.mek, salt: item.ks };
  return { name: await openName(kek, at, 'name', item.name), dek: item.dek ? await openDek(kek, at, item.dek) : null };
}

export async function mkdir(cookie, parent = 'root', { id, fields } = {}) {
  const f = fields || await sealed(cookie, 'dir');
  const r = await fetchJson('/api/private/drive/folders', { method: 'POST', cookie, body: { parent, name: f.name, ks: f.ks, mek: f.mek, ...(id ? { id } : {}) } });
  return { res: r, id: r.status === 201 ? (await r.json()).id : null, fields: f };
}

export async function createFile(cookie, parent, size, { id, fields } = {}) {
  const f = fields || await sealed(cookie, 'file');
  const r = await fetchJson('/api/private/drive/files', { method: 'POST', cookie, body: { parent, name: f.name, meta: f.meta, dek: f.dek, ks: f.ks, mek: f.mek, size, ...(id ? { id } : {}) } });
  return { res: r, fields: f, ...(r.status === 201 ? await r.json() : {}) };
}

/** A raw chunk upload as the browser sends it: the session's CSRF token too (`headers` may override it). */
export const putChunk = async (cookie, id, i, bytes, token, headers = {}) => SELF.fetch(`${ORIGIN}/api/private/drive/files/${id}/chunk/${i}`, {
  method: 'PUT', headers: { cookie, ...(await csrfHeaders(cookie)), 'content-type': 'application/octet-stream', 'x-upload-token': token, ...headers }, body: bytes,
});
// As the browser sends it (api.js drive.finalize): no body, so the intent header (the request-shape check).
export const finalize = (cookie, id, token) => fetchJson(`/api/private/drive/files/${id}/finalize`, { method: 'POST', cookie, headers: { ...intent, 'x-upload-token': token } });
export const getChunk = (cookie, id, i) => SELF.fetch(`${ORIGIN}/api/private/drive/files/${id}/chunk/${i}`, { headers: { cookie } });

/** Create + upload + finalize a file of `size` bytes of (random) ciphertext → { id, chunks, fields, ch }. */
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
  return { id: f.id, chunks, fields: f.fields, ch: (await fin.json()).ch };
}

/** Upload `plainBytes` encrypted for real under a fresh DEK (as the browser does) → { id, fields, dek }. */
export async function uploadRealFile(cookie, parent, plainBytes) {
  const f = await createFile(cookie, parent, plainBytes.length);
  if (f.res.status !== 201) throw new Error(`create file: ${f.res.status} ${await f.res.text()}`);
  const key = await importFileKey(b64urlFromBytes(f.fields.dekBytes));
  const n = driveChunks(plainBytes.length);
  const size = 8 * 1024 * 1024;
  for (let i = 0; i < n; i++) {
    const ct = await encryptChunk(key, i, n, plainBytes.subarray(i * size, Math.min(plainBytes.length, (i + 1) * size)));
    const r = await putChunk(cookie, f.id, i, ct, f.uploadToken);
    if (r.status !== 200) throw new Error(`chunk ${i}: ${r.status} ${await r.text()}`);
  }
  const fin = await finalize(cookie, f.id, f.uploadToken);
  if (fin.status !== 200) throw new Error(`finalize: ${fin.status} ${await fin.text()}`);
  return { id: f.id, fields: f.fields, dek: f.fields.dekBytes };
}

export const del = (cookie, id) => fetchJson(`/api/private/drive/nodes/${id}`, { method: 'DELETE', cookie, headers: intent });
export const node = async (cookie, id) => fetchJson(`/api/private/drive/nodes/${id}`, { cookie });
export const drive = async (cookie) => (await fetchJson('/api/private/drive', { cookie })).json();
