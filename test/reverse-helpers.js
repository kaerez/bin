// reverse-helpers.js — what the reverse-share tests share (workerd): a user
// who may receive files, creating a reverse share as the user's browser does,
// and the anonymous uploader's requests (open, begin, reserve, chunks,
// finalize) with the real client crypto.
import { env, SELF, runInDurableObject } from 'cloudflare:test';
import { makeUser, fetchJson, intent, ORIGIN, proofFor, USER_PW } from './helpers.js';
import { enableDrive, driveKeys, sealed } from './drive-helpers.js';
import {
  setReverseStretcher, createReverseKey, linkProof, linkHash, passwordGate, passwordProof,
  sealNote, sealUpload, newReverseId, newNodeId, pubOfPrivate,
} from '../public/js/reversekeys.js';
import { sealLinkKey, openLinkKey } from '../public/js/drivekeys.js';
import { hkdf32 } from '../public/js/crypto.js';
import { randomBytes, utf8, b64urlFromBytes } from '../public/js/bytes.js';
import { CHUNK, encryptChunk, importFileKey } from '../public/js/files.js';

// Argon2id stand-in (workerd cannot compile WebAssembly; the server never runs it).
setReverseStretcher(async (pw, salt) => hkdf32(pw, salt, utf8('test-stretch')));

export const dirStub = () => env.DIRECTORY.get(env.DIRECTORY.idFromName('directory'));
export const driveOf = (uid) => env.DRIVE.get(env.DRIVE.idFromName(`drive:${uid}`));
export const errorOf = async (r) => (await r.json()).error;

export async function receiver(name, limits = {}) {
  const u = await makeUser(name);
  await enableDrive(u.id, { reverseEnabled: true, ...limits });
  return u;
}

/**
 * A link's private key sealed as the user's browser does (docs/DRIVE.md §3):
 * under HKDF(KEK of the current sub-MEK, "reverse-link"), bound to the link
 * id → { priv, mek }.
 */
export async function sealLinkPriv(cookie, id, privateKey) {
  const k = await driveKeys(cookie);
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
  return { priv: await sealLinkKey(k.keks.get(k.current), { userId: k.userId, mekId: k.current, linkId: id }, pkcs8), mek: k.current };
}
/** A link's private key opened with the session's KEK of `mek` → { privateKey, pub }. Throws when it does not open. */
export async function openLinkPriv(cookie, id, priv, mek) {
  const k = await driveKeys(cookie, { fresh: true });
  const kek = k.keks.get(mek);
  if (!kek) throw new Error(`no KEK for ${mek}`);
  return pubOfPrivate(await openLinkKey(kek, { userId: k.userId, mekId: mek, linkId: id }, priv));
}

/**
 * Create a reverse share on `folder` as the user's browser would, confirmed
 * with the user's password (`confirm: false`: no confirmation, as the owner
 * acting as the user sends).
 */
export async function newReverse(cookie, { folder = 'root', password, note, id = newReverseId(), confirm = true, ...opts } = {}) {
  const { pub, privateKey } = await createReverseKey();
  const body = { id, folder, ...(await sealLinkPriv(cookie, id, privateKey)), lh: await linkHash(pub), expire: '7d', ...opts };
  if (confirm) body.current = proofFor(USER_PW);
  if (typeof password === 'string') body.password = await passwordGate(password, pub);
  else if (password !== undefined) body.password = password; // as sent (validation tests)
  if (typeof note === 'string') body.note = await sealNote(pub, id, note);
  else if (note !== undefined) body.note = note;
  const res = await fetchJson('/api/private/drive/reverse', { method: 'POST', cookie, body, headers: intent });
  return { res, id, pub, privateKey, body };
}

/** An uploader request (anonymous). */
export function rv(id, path, { method = 'POST', headers = {}, body, ip } = {}) {
  return fetchJson(`/api/reverse/${id}${path}`, { method, body, headers: { ...intent, ...headers }, ip });
}
export const openLink = async (r, ip, pub = r.pub) => rv(r.id, '/open', { headers: { 'x-link-proof': await linkProof(pub) }, ip });
export async function begin(r, { password, ip, token, pub = r.pub } = {}) {
  const headers = { 'x-link-proof': await linkProof(pub) };
  if (password) {
    const head = await (await openLink(r, ip)).json();
    headers['x-key-proof'] = await passwordProof(password, head.password.salt, head.password.t, r.pub);
  }
  if (token) headers['x-secbin-turnstile'] = token;
  return rv(r.id, '/begin', { headers, ip });
}
export async function grantOf(r, opts) {
  const res = await begin(r, opts);
  if (res.status !== 200) throw new Error(`begin: ${res.status} ${await res.text()}`);
  return (await res.json()).grant;
}
export const putChunk = (id, node, i, bytes, token, ip) => SELF.fetch(`${ORIGIN}/api/reverse/${id}/files/${node}/chunk/${i}`, {
  method: 'PUT', headers: { 'content-type': 'application/octet-stream', 'x-upload-token': token, ...(ip ? { 'cf-connecting-ip': ip } : {}) }, body: bytes,
});

/** Encrypt + reserve one file (no chunks yet) → { res, node, fk, data }. */
export async function reserve(r, grant, { path = 'a.txt', bytes = utf8('hello world'), type = 'text/plain', types, size, ip } = {}) {
  const nodeId = newNodeId();
  const fk = randomBytes(32);
  const sealed = await sealUpload(r.pub, r.id, nodeId, fk, { path, type, mtime: 1700000000000, size: bytes.length });
  const body = { id: nodeId, ...sealed, size: size ?? bytes.length };
  if (types) body.types = types;
  const res = await rv(r.id, '/files', { headers: { 'x-reverse-grant': grant }, body, ip });
  return { res, node: nodeId, fk, bytes, data: res.status === 201 ? await res.json() : null };
}
/** Reserve, upload every chunk and finalize one file. */
export async function send(r, grant, opts = {}) {
  const f = await reserve(r, grant, opts);
  if (f.res.status !== 201) throw new Error(`reserve: ${f.res.status} ${await f.res.text()}`);
  const key = await importFileKey(b64urlFromBytes(f.fk));
  const n = f.data.chunks;
  for (let i = 0; i < n; i++) {
    const ct = await encryptChunk(key, i, n, f.bytes.slice(i * CHUNK, (i + 1) * CHUNK));
    const pr = await putChunk(r.id, f.node, i, ct, f.data.uploadToken, opts.ip);
    if (pr.status !== 200) throw new Error(`chunk: ${pr.status} ${await pr.text()}`);
  }
  const fin = await rv(r.id, `/files/${f.node}/finalize`, { headers: { 'x-reverse-grant': grant, 'x-upload-token': f.data.uploadToken }, ip: opts.ip });
  if (fin.status !== 200) throw new Error(`finalize: ${fin.status} ${await fin.text()}`);
  return f;
}
export const received = async (cookie, query = '') => (await fetchJson(`/api/private/drive/received${query}`, { cookie })).json();
/** What the received files not yet taken in add to the Drive's use: their sealed path, metadata and wrap (as stored, at rest). */
export const overhead = (uid) => runInDurableObject(driveOf(uid), (inst, state) => state.storage.sql.exec(
  'SELECT COALESCE(SUM(LENGTH(name) + LENGTH(meta) + LENGTH(fk)), 0) AS s FROM nodes WHERE rs IS NOT NULL').one().s);
// The sealed fields of the Drive's own items (every item counts, docs/DRIVE.md §10).
export const ownSealed = (uid) => runInDurableObject(driveOf(uid), (inst, state) => state.storage.sql.exec(
  "SELECT COALESCE(SUM(LENGTH(name) + COALESCE(LENGTH(meta), 0) + COALESCE(LENGTH(fk), 0) + COALESCE(LENGTH(dek), 0) + COALESCE(LENGTH(ks), 0)), 0) AS s FROM nodes WHERE rs IS NULL AND id != 'root'").one().s);

/** A take-in (docs/REVERSE.md §6.1) with a well-formed body sealed under the session's KEK (its content is not checked: the server cannot). */
export async function takeInAny(cookie, id, parent = 'root', headers = intent) {
  const f = await sealed(cookie, 'file');
  return fetchJson(`/api/private/drive/received/${id}`, { method: 'POST', cookie, headers, body: { parent, name: f.name, meta: f.meta, dek: f.dek, ks: f.ks, mek: f.mek } });
}
