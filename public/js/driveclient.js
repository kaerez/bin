// driveclient.js — the Drive in the browser (docs/DRIVE.md): list, upload,
// download, rename, move, delete and share files and folders, receive files
// (reverse shares), and the personal kit.
//
// The key model v2 (docs/DRIVE.md §3): the server derives the user's KEK for
// each sub-MEK and hands the KEKs to this session (GET /api/private/drive/
// keys) — no prompt, no password. Here each file gets a random DEK, which
// encrypts its content in CHUNK-sized pieces (files.js encryptChunk, no
// padding: chunk i is exactly min(CHUNK, size − i·CHUNK) + 16 bytes), and
// the DEK, the name and the metadata are sealed under KEK(current sub-MEK)
// with a random 32-byte salt per item (drivekeys.js). The server stores that
// ciphertext; it holds the keys that open it (SECURITY.md, "Drive").

import { drive as api, session, ApiError, updateShare } from './api.js';
import {
  keyBytes, newKey, newSalt, sealDek, openDek, sealName, openName, sealLinkKey, openLinkKey, keyCheckValue, saltCheckValue,
  purgeStaleSlots, effectiveAt, chunkHash, ciphertextHash,
} from './drivekeys.js';
import { encryptPaste } from './crypto.js';
import { utf8, fromUtf8, b64urlFromBytes, bytesFromB64url, randomBytes } from './bytes.js';
import { sealDriveKit, parseDriveKit, openDriveKit, DriveKitError } from './drivekit.js';
import { CHUNK, encryptChunk, importFileKey, checkPath, MAX_ENTRIES, cleanName } from './files.js';
import { detectMime, normalizeMime, OCTET } from './mime.js';
import { RefsReader, saveFile, saveZip } from './downloads.js';
import { buildRefsManifest, refChunks } from './refsmanifest.js';
import { declare, refusedTypes, uncheckableExt, describeType } from './filepolicy.js';
import { createReverseKey, linkHash, passwordGate, sealNote, fragmentOf, openUpload, newReverseId, pubOfPrivate } from './reversekeys.js';
import { deriveSubkeysV1, openFieldV1, openReversePrivV1, clearLegacyKey } from './drivev1.js';
import { itemOf, itemName, itemExt, withExt, KIND_LABELS } from './receivekinds.js';
import { provenLegacyKey } from './driveupgrade.js';

/** The account's role has no Drive. */
export class DriveDisabled extends Error {
  constructor(message = 'The Drive is not enabled for your account.') {
    super(message);
    this.name = 'DriveDisabled';
  }
}

/**
 * The Drive's keys cannot be had now (`reason`: 'keys_missing' — the
 * server lost its keyring and the administrator restores it; 'salt_missing'
 * — this account's user salt is missing: a kit restores it).
 */
export class DriveUnavailable extends Error {
  constructor(message, reason) {
    super(message);
    this.name = 'DriveUnavailable';
    this.reason = reason;
  }
}

export const ROOT = 'root';
const ROOT_NAME = 'Drive';
const MAX_NAME_BYTES = 255;
const MAX_DEPTH = 64;
/**
 * Folder levels a received file's path may create below its link's folder
 * (never past MAX_DEPTH in all): deeper folders are flattened — the file goes
 * into the deepest folder allowed. And new folders one take-in may create:
 * past that, files go into the deepest of their folders that exists.
 */
export const RECEIVED_MAX_DEPTH = 8;
export const RECEIVED_MAX_NEW_FOLDERS = 200;
/** Pages of received files one take-in reads at most (500 each). */
const RECEIVED_MAX_PAGES = 40;
const newId = () => b64urlFromBytes(randomBytes(16));
const malformed = () => new ApiError('Malformed response from the server.', 502, 'malformed');
const aborted = (signal, what) => signal.reason ?? new DOMException(`${what} cancelled.`, 'AbortError');
const sealed = (v) => (typeof v === 'string' ? JSON.parse(v) : v);

/**
 * downloads.js reports each chunk's plaintext length (onBytes(n)); this turns
 * that into onProgress(bytesDone, total), as uploads report it, and stops the
 * transfer (with the signal's AbortError) once `signal` is aborted.
 */
function byteCounter(total, onProgress, signal) {
  let done = 0;
  if (onProgress) onProgress(0, total);
  return (n) => {
    if (signal?.aborted) throw aborted(signal, 'Download');
    done += n;
    if (onProgress) onProgress(done, total);
  };
}

/** `name`, or "name (2).ext", "name (3).ext"… when `taken` already has it. */
function uniqueName(taken, name) {
  let n = name;
  const dot = name.lastIndexOf('.');
  const [stem, ext] = dot > 0 ? [name.slice(0, dot), name.slice(dot)] : [name, ''];
  for (let k = 2; taken.has(n); k++) n = `${stem} (${k})${ext}`;
  taken.add(n);
  return n;
}

/**
 * The Drive name of a received note, link or credential (receivekinds.js
 * itemName): a note's title made a usable name ("/" and "\" become "-",
 * control characters go, at most MAX_NAME_BYTES), else — or when nothing is
 * left of it — "Note from <date>" and so on.
 */
function itemLeaf(item, createdSec) {
  const fallback = itemName({ kind: item.kind }, createdSec);
  if (!(item.kind === 'note' && item.title)) return fallback;
  // eslint-disable-next-line no-control-regex
  let t = cleanName(item.title).replace(/[/\\]/g, '-').replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  while (t && utf8(t).length > MAX_NAME_BYTES) t = t.slice(0, -1);
  try { return t && t !== '.' && t !== '..' ? checkName(t) : fallback; } catch { return fallback; }
}

/**
 * A node name → the name to store (cleaned: files.js cleanName strips the
 * bidi overrides and isolates, U+200B, U+FEFF and U+0085 / U+2028 / U+2029,
 * then NFC), or throws: no "/", "\", control characters, "." or ".."; 1–255
 * bytes. Hebrew, Arabic, ZWNJ / ZWJ and LRM / RLM stay as they are.
 */
export function checkName(raw) {
  const name = typeof raw === 'string' ? cleanName(raw) : raw;
  // eslint-disable-next-line no-control-regex
  if (typeof name !== 'string' || !name || name === '.' || name === '..' || /[\u0000-\u001f\u007f/\\]/.test(name)) {
    throw new Error('Names cannot be empty, "." or "..", or contain "/", "\\" or control characters.');
  }
  if (utf8(name).length > MAX_NAME_BYTES) throw new Error(`Names can be at most ${MAX_NAME_BYTES} bytes long.`);
  return name;
}

async function whoAmI(user) {
  if (user && typeof user.id === 'string') return { id: user.id, role: user.role, impersonating: !!user.impersonating };
  const s = await session();
  if (!s.authenticated || !s.user) throw new ApiError('Please log in.', 401, 'unauthenticated');
  return { id: s.user.id, role: s.user.role, impersonating: !!s.impersonatedBy };
}

/** GET /api/private/drive, or DriveDisabled. */
async function loadState() {
  let st;
  try {
    st = await api.state();
  } catch (e) {
    if (e instanceof ApiError && (e.code === 'drive_disabled' || e.status === 404 || (e.status === 403 && e.code !== 'impersonating'))) throw new DriveDisabled(e.message);
    throw e;
  }
  if (st.enabled !== true) throw new DriveDisabled();
  return st;
}

/**
 * The session's KEKs, from the server → { userId, current, changing, keks:
 * Map(mekId → [kek, kekOld?]), list: [{ mekId, fp, from, until }] }. Kept in
 * this page's memory only (the DriveClient), never in browser storage, and
 * never read from it: a failure here is shown, with no stored key to fall
 * back on (drivekeys.js, "what the tab keeps").
 */
async function fetchKeys(u) {
  let r;
  try {
    r = await api.keys();
  } catch (e) {
    if (e instanceof ApiError && (e.code === 'keys_missing' || e.code === 'salt_missing')) throw new DriveUnavailable(e.message, e.code);
    throw e;
  }
  if (!r || r.userId !== u.id || !Array.isArray(r.keys)) throw malformed();
  const keks = new Map();
  for (const k of r.keys) keks.set(k.mekId, [keyBytes(k.kek), ...(k.kekOld ? [keyBytes(k.kekOld)] : [])]);
  if (!r.current || !keks.has(r.current)) throw new DriveUnavailable('The current Drive key is not available: ask the administrator to check Admin → Security → Keys.', 'keys_missing');
  return { userId: u.id, current: r.current, changing: !!r.changing, keks, list: r.keys.map(({ mekId, fp, from, until }) => ({ mekId, fp, from, until })) };
}

/**
 * The Drive → DriveClient. No prompt: the server hands this session the
 * KEKs. Throws DriveDisabled (the role has no Drive) or DriveUnavailable (the
 * keys cannot be had now). `user` ({ id, role, impersonating }) saves a
 * session lookup; while the owner acts as the user, it is the user's Drive
 * (the server records the owner's use of the user's keys).
 */
export async function openDrive({ user } = {}) {
  purgeStaleSlots(); // what a release before kept in the tab (the KEK slots, the old impersonation DK)
  const u = await whoAmI(user);
  const st = await loadState();
  const keys = await fetchKeys(u);
  // The old Drive key (a Drive waiting for its upgrade): only once proven to be this Drive's.
  const legacy = u.impersonating || !st.migration ? null : await provenLegacyKey(u.id).catch(() => null);
  if (!u.impersonating && !st.migration) await dropLegacyKey(u);
  return new DriveClient(keys, u, st, legacy);
}

/**
 * Nothing waits for the upgrade here any more (it was done in another tab, or
 * by the owner through the escrow): the tab's old Drive key goes. The owner's
 * stays while it still opens users' Drives (until the clean-up removed the
 * owner's old wraps: GET …/migrate says `legacy: false`).
 */
async function dropLegacyKey(u) {
  if (u.role === 'owner') {
    const m = await api.migrate().catch(() => null);
    if (!m || m.legacy) return;
  }
  clearLegacyKey();
}

// ── the client ─────────────────────────────────────────────────────────────

export class DriveClient {
  constructor(keys, user, state = {}, legacy = null) {
    this.keys = keys;
    this.user = user;
    /** What the upgrade of a Drive made before the key model v2 still has to do, or null (docs/DRIVE.md §3.3). */
    this.migration = state.migration || null;
    this.state = state;
    /** The Drive key of the release before, while this Drive waits for its upgrade (the sign-in opened it; checked, driveupgrade.js provenLegacyKey). */
    this.legacy = user.impersonating ? null : legacy;
    this.legacyKeys = null;
  }

  /** The KEKs again (after the server answered that the current sub-MEK changed). */
  async refreshKeys() {
    this.keys = await fetchKeys(this.user);
  }

  /**
   * The page no longer acts for this session (the session ended —
   * session-timeout.js — or the browser is now signed in as someone else:
   * another tab signed in, or started or ended impersonation): every key this
   * client holds is overwritten and dropped; every later call that needs a key
   * fails, so nothing more is opened or sealed with it.
   */
  forget() {
    for (const list of this.keys?.keks?.values() ?? []) for (const k of list) k.fill(0);
    if (this.legacy) this.legacy.fill(0);
    this.keys = { userId: this.user.id, current: null, changing: false, keks: new Map(), list: [] };
    this.legacy = null;
    this.legacyKeys = null;
    this.forgotten = true;
  }

  #where(mekId, salt) {
    return { userId: this.user.id, mekId, salt };
  }
  #keks(mekId) {
    return this.keys.keks.get(mekId) || [];
  }
  /** Try each KEK of `mekId` until `fn(kek)` works. */
  async #withKek(mekId, fn) {
    let last = null;
    for (const kek of this.#keks(mekId)) {
      try { return await fn(kek); } catch (e) { last = e; }
    }
    throw last || new Error('This item is sealed under a key this session does not have.');
  }
  /** The current sub-MEK and its KEK. */
  #cur() {
    return { mek: this.keys.current, kek: this.#keks(this.keys.current)[0] };
  }
  /** A new item's key fields and sealed name / meta / DEK under the current KEK. */
  async #sealNew({ name, meta = null, dek = null }) {
    const { mek, kek } = this.#cur();
    const ks = newSalt();
    const at = this.#where(mek, ks);
    return {
      ks, mek,
      name: await sealName(kek, at, 'name', name),
      ...(meta !== null ? { meta: await sealName(kek, at, 'meta', meta) } : {}),
      ...(dek ? { dek: await sealDek(kek, at, dek) } : {}),
    };
  }
  /** Retry once with fresh keys when the server says the current sub-MEK changed. */
  async #fresh(fn) {
    try {
      return await fn();
    } catch (e) {
      if (!(e instanceof ApiError && e.code === 'mek_not_current')) throw e;
      await this.refreshKeys();
      return fn();
    }
  }

  async #legacySub() {
    if (!this.legacy) return null;
    this.legacyKeys ??= await deriveSubkeysV1(this.legacy);
    return this.legacyKeys;
  }

  /** An item's field → text (v2: under its KEK; an item of the release before: under the old Drive key when this tab has it). */
  async #text(n, field) {
    const v = field === 'name' ? n.name : n.meta;
    if (n.v1) {
      const k = await this.#legacySub();
      if (!k) throw new Error('not upgraded yet');
      return fromUtf8(await openFieldV1(k.names, field, n.id, sealed(v)));
    }
    return fromUtf8(await this.#withKek(n.mek, (kek) => openName(kek, this.#where(n.mek, n.ks), field, sealed(v))));
  }

  /** { used, capacity } in bytes (capacity null = no limit). */
  async usage() {
    const st = await loadState();
    return { used: st.used, capacity: st.capacity ?? null };
  }

  /**
   * A server node → { id, parent, kind, name, type, mtime, size, chunks,
   * created, updated } (name null if unreadable). A file is readable only
   * with its sealed metadata, whose size must be the server's and match the
   * chunk count: a file whose metadata is missing, altered or disagrees is
   * `unreadable`, never an empty (or cut) file (SECURITY.md §1). An item of
   * the release before that this tab cannot open yet is `upgrading`.
   */
  async decode(n) {
    if (!n || typeof n.id !== 'string') throw malformed();
    const base = { id: n.id, parent: n.parent ?? null, kind: n.kind === 'file' ? 'file' : 'dir', size: n.size ?? 0, chunks: n.chunks ?? 0, created: n.created ?? 0, updated: n.updated ?? 0 };
    if (n.id === ROOT) return { ...base, kind: 'dir', name: ROOT_NAME, type: null, mtime: 0 };
    const waiting = !!n.v1 && !this.legacy;
    let name = null;
    let renamed = false;
    try {
      const raw = await this.#text(n, 'name');
      name = cleanName(raw); // an older name with spoofing characters shows (and downloads) cleaned
      renamed = name !== raw;
    } catch { /* unreadable */ }
    const badName = name === null;
    let type = null;
    let mtime = 0;
    let item = null;
    if (base.kind === 'file') {
      let ok = false;
      try {
        const m = JSON.parse(await this.#text(n, 'meta'));
        type = normalizeMime(m.type) || OCTET;
        mtime = Number.isSafeInteger(m.mtime) && m.mtime >= 0 ? m.mtime : 0;
        ok = Number.isSafeInteger(m.size) && m.size === base.size && base.chunks === refChunks(base.size);
        if (m.renamed === true) renamed = true; // a received file whose name was cleaned when it was taken in
        // A note, link or credential received through a Receive link: its kind is in the sealed metadata.
        item = itemOf(m);
      } catch { /* missing or unreadable metadata */ }
      if (!ok) name = null;
    }
    return {
      ...base, name, type: base.kind === 'file' ? (type || OCTET) : null, mtime,
      ...(name === null ? { unreadable: true } : {}), ...(badName ? { badName: true } : {}), ...(waiting ? { upgrading: true } : {}),
      ...(renamed && name !== null ? { renamed: true } : {}), ...(item && name !== null ? { item } : {}),
    };
  }

  /** A file node's DEK (base64url). */
  async #fileKey(n) {
    const raw = n.dek || n.fk ? n : (await api.node(n.id)).node;
    if (raw.v1) {
      const k = await this.#legacySub();
      if (!k) throw new Error('This file waits for the Drive upgrade.');
      return b64urlFromBytes(await openFieldV1(k.files, 'fk', raw.id, sealed(raw.fk)));
    }
    const dek = await this.#withKek(raw.mek, (kek) => openDek(kek, this.#where(raw.mek, raw.ks), sealed(raw.dek)));
    return b64urlFromBytes(dek);
  }

  /**
   * A folder's content → { node, path, children }: `path` is [{ id, name }]
   * from the root down to and including the node; children are sorted,
   * folders first.
   */
  async list(nodeId = ROOT) {
    const r = await api.node(nodeId);
    if (!r || !r.node || !Array.isArray(r.children)) throw malformed();
    const raw = r.children.filter((c) => c && c.state !== 'pending');
    const children = await Promise.all(raw.map((c) => this.decode(c)));
    children.sort((a, b) => (a.kind === b.kind ? String(a.name ?? '').localeCompare(String(b.name ?? '')) : a.kind === 'dir' ? -1 : 1));
    const node = await this.decode(r.node);
    let anc = Array.isArray(r.path) ? r.path.filter((p) => p && p.id !== node.id) : [];
    if (anc.length && anc[0].id !== ROOT && anc[anc.length - 1].id === ROOT) anc = anc.reverse();
    const path = [];
    for (const p of anc) { const d = await this.decode(p); path.push({ id: d.id, name: d.name }); }
    path.push({ id: node.id, name: node.name });
    return { node, path, children };
  }

  /** A new folder → its id. */
  async mkdir(parentId, name) {
    const clean = checkName(name);
    const id = newId();
    const r = await this.#fresh(async () => api.mkdir({ id, parent: parentId, ...(await this.#sealNew({ name: clean })) }));
    if (r.id !== undefined && r.id !== id) throw malformed();
    return id;
  }

  /**
   * Upload a File (or a Blob with `name`) into `parentId` → its id. Options:
   * onProgress(bytesDone, total), signal (AbortSignal), name, type, mtime,
   * taken (a Set of the names already in the folder, from names(); updated
   * here — else the folder is read). A name already taken gets " (2)"….
   */
  async upload(parentId, file, { onProgress, signal, name, type, mtime, taken } = {}) {
    // A name already used in the folder gets " (2)", " (3)"… (the server cannot see names).
    const fileName = uniqueName(taken ?? (await this.names(parentId)).names, checkName(name ?? file.name));
    const size = file.size;
    const head = new Uint8Array(await file.slice(0, 64).arrayBuffer());
    const mime = normalizeMime(type) || detectMime({ name: fileName, platformType: file.type, head });
    const time = Number.isSafeInteger(mtime) && mtime >= 0 ? mtime : (file.lastModified || 0);
    const id = newId();
    const dek = newKey();
    const n = refChunks(size);
    const init = await this.#fresh(async () => api.createFile({
      id, parent: parentId, size,
      ...(await this.#sealNew({ name: fileName, meta: JSON.stringify({ type: mime, mtime: time, size }), dek })),
    }));
    const token = init.uploadToken ?? init.uploadtoken;
    if ((init.id !== undefined && init.id !== id) || init.chunks !== n || typeof token !== 'string') throw malformed();
    try {
      const key = await importFileKey(b64urlFromBytes(dek));
      let done = 0;
      if (onProgress) onProgress(0, size);
      for (let i = 0; i < n; i++) {
        if (signal?.aborted) throw aborted(signal, 'Upload');
        const plain = new Uint8Array(await file.slice(i * CHUNK, Math.min(size, (i + 1) * CHUNK)).arrayBuffer());
        const ct = await encryptChunk(key, i, n, plain);
        try {
          await api.putChunk(id, i, ct, token, signal);
        } catch (e) {
          if ((e instanceof ApiError && e.status < 500) || e?.name === 'AbortError') throw e;
          await api.putChunk(id, i, ct, token, signal); // one retry for transient failures
        }
        done += plain.length;
        if (onProgress) onProgress(done, size);
      }
      if (signal?.aborted) throw aborted(signal, 'Upload');
      // "busy": an earlier attempt of a chunk (one this loop retried) is still being written.
      for (let tries = 0; ; tries++) {
        try {
          await api.finalize(id, token);
          break;
        } catch (e) {
          if (!(e instanceof ApiError && e.code === 'busy') || tries >= 20) throw e;
          await new Promise((res) => setTimeout(res, 250));
        }
      }
    } catch (e) {
      api.remove(id).catch(() => {}); // free the capacity now (the server purges it later anyway)
      throw e;
    } finally {
      dek.fill(0);
    }
    return id;
  }

  /**
   * Upload many files by relative path into `parentId`, creating (or reusing)
   * folders on the way. `entries` = [{ path, file } | { path, dir: true }].
   * opts: onProgress(bytesDone, total), onFile(path), signal. → [ids of files].
   */
  async uploadTree(parentId, entries, { onProgress, onFile, signal } = {}) {
    const total = entries.reduce((s, e) => s + (e.dir ? 0 : e.file.size), 0);
    const folders = new Map([['', parentId]]);
    const inside = new Map(); // folder id → { dirs: Map(name → id), names: Set }
    const contentOf = async (id) => {
      if (!inside.has(id)) inside.set(id, await this.names(id).catch(() => ({ dirs: new Map(), names: new Set() })));
      return inside.get(id);
    };
    const ensure = async (dirPath) => {
      if (folders.has(dirPath)) return folders.get(dirPath);
      const cut = dirPath.lastIndexOf('/');
      const parent = await ensure(cut < 0 ? '' : dirPath.slice(0, cut));
      const leaf = dirPath.slice(cut + 1);
      const here = await contentOf(parent);
      // An existing folder of that name is reused (merged into); a file of that name is not.
      let id = here.dirs.get(leaf);
      if (!id) {
        id = await this.mkdir(parent, uniqueName(here.names, leaf));
        here.dirs.set(leaf, id);
        inside.set(id, { dirs: new Map(), names: new Set() });
      }
      folders.set(dirPath, id);
      return id;
    };
    const ids = [];
    let before = 0;
    for (const e of entries) {
      if (signal?.aborted) throw aborted(signal, 'Upload');
      const path = checkPath(cleanName(e.path));
      path.split('/').forEach(checkName);
      if (e.dir) { await ensure(path); continue; }
      const cut = path.lastIndexOf('/');
      const dir = await ensure(cut < 0 ? '' : path.slice(0, cut));
      if (onFile) onFile(path);
      const base = before;
      const { names: taken } = await contentOf(dir);
      ids.push(await this.upload(dir, e.file, { name: path.slice(cut + 1), taken, signal, onProgress: onProgress && ((d) => onProgress(base + d, total)) }));
      before += e.file.size;
    }
    if (onProgress) onProgress(total, total);
    return ids;
  }

  /**
   * The names in folder `id` → { names: Set (every readable name), dirs:
   * Map(folder name → id) }, for picking names that do not clash.
   */
  async names(id) {
    const r = await api.node(id);
    if (!r || !Array.isArray(r.children)) throw malformed();
    const names = new Set();
    const dirs = new Map();
    for (const c of r.children.filter((x) => x && x.state !== 'pending')) {
      const d = await this.decode(c).catch(() => null);
      if (!d || d.name === null) continue;
      names.add(d.name);
      if (d.kind === 'dir' && !dirs.has(d.name)) dirs.set(d.name, d.id);
    }
    return { names, dirs };
  }

  /**
   * Rename: the new name is sealed under the item's own keys (its sub-MEK
   * and salt); if the server re-sealed the item meanwhile (`stale_keys`), it
   * is read again and sealed once more.
   */
  async rename(id, name) {
    const clean = checkName(name);
    for (let tries = 0; ; tries++) {
      const { node: n } = await api.node(id);
      if (!n || n.v1) throw new Error('This item waits for the Drive upgrade: rename it afterwards.');
      try {
        const sealedName = await this.#withKek(n.mek, (kek) => sealName(kek, this.#where(n.mek, n.ks), 'name', clean));
        await api.update(id, { name: sealedName, ks: n.ks, mek: n.mek });
        return;
      } catch (e) {
        if (e instanceof ApiError && e.code === 'stale_keys' && tries < 2) { await this.refreshKeys(); continue; }
        throw e;
      }
    }
  }

  async move(id, parentId) {
    await api.update(id, { parent: parentId });
  }

  /** Delete a node (recursively); every share that references it ends. */
  async remove(id) {
    await api.remove(id);
  }

  /** The file entry (with its key) and a reader for one file node. */
  async #fileEntry(raw, path) {
    const d = await this.decode(raw);
    if (d.kind !== 'file' || d.unreadable) throw new Error(d.upgrading ? 'This file waits for the Drive upgrade.' : 'This file cannot be read.');
    return { path: path ?? d.name, size: d.size, type: d.type, mtime: d.mtime, fk: await this.#fileKey(raw), node: d.id, chunks: d.chunks, ch: typeof raw.ch === 'string' ? raw.ch : null, ...(d.item ? { item: d.item } : {}) };
  }

  /**
   * A reader of Drive files: each file's chunks are checked against its
   * ciphertext hash (`ch`, when the server has one) as they arrive — the last
   * chunk is not handed over unless every chunk gives the recorded hash
   * (AES-GCM checks each chunk under the file's DEK as well).
   */
  #reader(entries, total) {
    const seen = new Map(); // node → chunk hashes so far
    return new RefsReader({
      manifest: { v: 3, entries, total, view: null },
      fetch: async (entry, i) => {
        const ct = await api.chunk(entry.node, i);
        if (typeof entry.ch !== 'string' || !entry.ch || !entry.chunks) return ct;
        const hs = i === 0 ? [] : seen.get(entry.node) || [];
        hs[i] = await chunkHash(ct instanceof Uint8Array ? ct : new Uint8Array(ct));
        seen.set(entry.node, hs);
        if (i === entry.chunks - 1) {
          seen.delete(entry.node);
          if (hs.length !== entry.chunks || (await ciphertextHash(entry.chunks, (k) => hs[k])) !== entry.ch) {
            throw new Error('This file’s stored content does not match the hash recorded when it was uploaded: it was not saved. Report this to the administrator.');
          }
        }
        return ct;
      },
      refs: entries.filter((e) => !e.dir).map((e) => ({ chunks: e.chunks })),
    });
  }

  /**
   * One file → { entry, reader, save(onBytes?), blob(onBytes?) }: `reader` and
   * `entry` work with downloads.js saveFile; save() streams it to disk (or a
   * download), blob() returns it in memory (small files, previews). Options
   * (used when save/blob get no onBytes): onProgress(bytesDone, total) and
   * signal (AbortSignal: the transfer stops with its AbortError).
   */
  async download(id, { onProgress, signal } = {}) {
    const r = await api.node(id);
    if (!r || !r.node) throw malformed();
    const entry = { ...(await this.#fileEntry(r.node)), ref: 0 };
    const reader = this.#reader([entry], entry.size);
    const counter = () => byteCounter(entry.size, onProgress, signal);
    return {
      entry,
      reader,
      save: (onBytes) => saveFile(reader, entry, onBytes ?? counter()),
      blob: async (onBytes) => new Blob([await reader.bytes(entry, onBytes ?? counter())], { type: entry.type }),
    };
  }

  /**
   * A note, link or credential of the Drive → { item, name, bytes, text }
   * (its content, decrypted here; the regular viewers show it: typedview.js).
   * Throws when the node is not one.
   */
  async readItem(id, { onProgress, signal } = {}) {
    const d = await this.download(id, { onProgress, signal });
    if (!d.entry.item) throw new Error('This is not a note, link or credential.');
    const bytes = await d.reader.bytes(d.entry, byteCounter(d.entry.size, onProgress, signal));
    return { item: d.entry.item, name: d.entry.path, bytes, text: fromUtf8(bytes) };
  }

  /**
   * Flatten nodes into { files: [{ path, id, ...entry }], dirs: [path] }:
   * each top-level node by its own name, folders recursively; duplicate
   * names get " (2)", " (3)"… so every path is unique.
   */
  async #collect(nodeIds) {
    const out = { files: [], dirs: [], count: 0 };
    const top = new Set();
    for (const id of nodeIds) {
      if (id === ROOT) { await this.#walk(ROOT, '', out, 1); continue; }
      const r = await api.node(id);
      if (!r || !r.node) throw malformed();
      const d = await this.decode(r.node);
      if (d.unreadable) throw new Error('A file or folder name cannot be read.');
      // Paths for ZIPs and manifests: never ".." or "/" from a name; a note, link or credential with its extension.
      const name = uniqueName(top, checkName(d.item ? withExt(d.name, itemExt(d.item, { stored: true })) : d.name));
      if (++out.count > MAX_ENTRIES) throw new Error(`At most ${MAX_ENTRIES} files and folders at once.`);
      if (d.kind === 'file') {
        out.files.push({ ...(await this.#fileEntry(r.node, name)), id });
      } else {
        out.dirs.push(name);
        await this.#walk(id, name, out, 2);
      }
    }
    return out;
  }

  /** Walk folder `dirId` into `out` ({ files, dirs, count }), with paths under `path`. */
  async #walk(dirId, path, out, depth) {
    if (depth > MAX_DEPTH) throw new Error('The folders are nested too deeply.');
    const r = await api.node(dirId);
    if (!r || !Array.isArray(r.children)) throw malformed();
    const taken = new Set();
    for (const c of r.children.filter((x) => x && x.state !== 'pending')) {
      if (++out.count > MAX_ENTRIES) throw new Error(`At most ${MAX_ENTRIES} files and folders at once.`);
      const d = await this.decode(c);
      if (d.unreadable) throw new Error('A file or folder name cannot be read.');
      // Paths for ZIPs and manifests: never ".." or "/" from a name; a note, link or credential with its extension.
      const leaf = uniqueName(taken, checkName(d.item ? withExt(d.name, itemExt(d.item, { stored: true })) : d.name));
      const p = path ? `${path}/${leaf}` : leaf;
      if (d.kind === 'file') {
        out.files.push({ ...(await this.#fileEntry(c, p)), id: c.id });
      } else {
        out.dirs.push(p);
        await this.#walk(c.id, p, out, depth + 1);
      }
    }
  }

  /**
   * Save a folder as a ZIP of its content (downloads.js saveZip) → resolves
   * when saved. opts: onProgress(bytesDone, total), signal, zipName.
   */
  async downloadFolder(id, { onProgress, signal, zipName } = {}) {
    const r = await api.node(id);
    if (!r || !r.node) throw malformed();
    const d = await this.decode(r.node);
    const out = { files: [], dirs: [], count: 0 };
    await this.#walk(id, '', out, 1);
    const entries = [...out.files.map((f, ref) => ({ ...f, ref })), ...out.dirs.map((path) => ({ path, dir: true }))];
    const total = out.files.reduce((s, f) => s + f.size, 0);
    const reader = this.#reader(entries, total);
    await saveZip(reader, '', zipName || `${d.name || 'drive'}.zip`, byteCounter(total, onProgress, signal));
  }

  /**
   * Share files and folders → { url, id, deletetoken }. opts: views (null =
   * unlimited), expire, password, deletable, label; `limits` (the profile's)
   * applies the administrator's file-type and folder-depth policy here, as the
   * composer does; `view` is the viewer snapshot ({ rules, maxBytes } or null).
   * The manifest (v3: paths, sizes, types and each file's DEK) is sealed with
   * a fresh link key and optional password exactly like a file share's (its
   * key is in the link). The content is the Drive's ciphertext, and its DEK is
   * sealed in the Drive under the user's KEK, which the server derives: the
   * server can open a Drive share's files as it can any Drive file (SECURITY.md,
   * "Drive keys").
   * `captcha`: true / false (the role allows a choice), undefined (its default).
   */
  async share(nodeIds, { views = null, expire, password = '', deletable = false, label = '', limits = null, view = null, captcha } = {}) {
    if (!Array.isArray(nodeIds) || !nodeIds.length) throw new Error('Choose what to share.');
    const { files, dirs } = await this.#collect(nodeIds);
    if (!files.length) throw new Error('There are no files to share.');
    // A link or a credential received through a Receive link is shared as what it is: only where the
    // account may share links or credentials (as the composer; the server cannot see what an item is).
    if (limits) {
      for (const [kind, key] of [['url', 'url'], ['secret', 'secret']]) {
        if (limits[key] !== true && files.some((f) => f.item && f.item.kind === kind)) throw new Error(`Your account is not allowed to share ${KIND_LABELS[kind].toLowerCase()}s: leave out the ${KIND_LABELS[kind].toLowerCase()} you received, or ask the administrator.`);
      }
      if (limits.text === false && files.some((f) => f.item)) throw new Error('Your account is not allowed to share notes, links or credentials: leave out the ones you received, or ask the administrator.');
    }
    const body = { nodes: files.map((f) => f.id), views, expire };
    const typePolicy = limits && ['allow', 'block'].includes(limits.fileTypeMode);
    const depthPolicy = limits && Number.isInteger(limits.maxFolderDepth);
    if (typePolicy || depthPolicy) {
      const d = declare([...files, ...dirs.map((p) => ({ path: p, dir: true }))]);
      if (depthPolicy && d.depth > limits.maxFolderDepth) throw new Error(`Folders may nest at most ${limits.maxFolderDepth} levels deep for your account; this share has ${d.depth}.`);
      if (typePolicy) {
        const odd = files.find((f) => uncheckableExt(f.path));
        if (odd) throw new Error(`"${odd.path}" has an unusual extension that cannot be checked against your administrator's file-type policy.`);
        const refused = refusedTypes(limits.fileTypeMode, limits.fileTypeRules, d.types);
        if (refused.length) throw new Error(`Your administrator does not allow ${refused.map(describeType).join(', ')} files.`);
        body.types = d.types;
      }
      if (depthPolicy) body.depth = d.depth;
    }
    const manifest = buildRefsManifest({ files: files.map((f) => ({ path: f.path, size: f.size, type: f.type, mtime: f.mtime, fk: f.fk, ...(f.item ? { item: f.item } : {}) })), dirs, view });
    const { body: paste, fragment } = await encryptPaste({
      text: JSON.stringify(manifest), fmt: 'files', password, bar: views !== null, views: views ?? undefined, expire, deletable,
    });
    Object.assign(body, { paste, acc: paste.acc });
    if (deletable) body.deletable = true;
    if (label) body.label = label;
    if (typeof captcha === 'boolean') body.captcha = captcha;
    const r = await api.share(body);
    if (typeof r.id !== 'string' || typeof r.deletetoken !== 'string') throw malformed();
    return { url: `${location.origin}/p/${r.id}#${fragment}`, id: r.id, deletetoken: r.deletetoken, captcha: r.captcha === true };
  }

  /** The shares that reference a node. */
  async shares(nodeId) {
    const r = await api.shares(nodeId);
    return Array.isArray(r.shares) ? r.shares : [];
  }

  // ── reverse shares (docs/REVERSE.md) ───────────────────────────────────

  /** A link key as the server lists it → { privateKey, pub } (null: it does not open here). */
  async #linkKey(id, mek, priv) {
    if (!priv) return null;
    try {
      if (!mek) {
        if (!this.legacy) return null; // sealed by the release before: after the upgrade
        return await pubOfPrivate(await openReversePrivV1(this.legacy, id, priv));
      }
      return await pubOfPrivate(await this.#withKek(mek, (kek) => openLinkKey(kek, { userId: this.user.id, mekId: mek, linkId: id }, sealed(priv))));
    } catch {
      return null;
    }
  }

  /**
   * A reverse share on folder `folderId` → { url, id, expires }: a new link key
   * pair (its private key sealed under HKDF(KEK, "reverse-link")), the link
   * proof's hash, the note sealed with the link key, and — with a password —
   * the gate the server checks (it only lets the uploader in; it protects
   * nothing). opts: label, note, password, expire ("7d"), maxFiles, maxBytes,
   * maxFileBytes (null = none), types ({ mode, rules } or null), and `step`:
   * the "confirm it's you" part ({ current } or { reauth }, as for API keys).
   * `captcha`: uploaders pass the CAPTCHA first (true / false where the role
   * allows a choice; undefined: its default). `expire` "never": no expiry
   * (where the role allows it); `views`: upload sessions allowed (null:
   * unlimited, where the role allows it); `accept`: what it takes (files,
   * note, url, secret: receivekinds.js; files only when not given).
   */
  async createReverse(folderId, { label = '', note = '', password = '', expire = '7d', views = null, maxFiles = null, maxBytes = null, maxFileBytes = null, types = null, step = {}, captcha, accept } = {}) {
    const id = newReverseId();
    const { pub, privateKey } = await createReverseKey();
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey('pkcs8', privateKey));
    const extra = { lh: await linkHash(pub), expire, views, maxFiles, maxBytes, maxFileBytes, types, ...(Array.isArray(accept) ? { accept } : {}) };
    if (note) extra.note = await sealNote(pub, id, note);
    if (password) extra.password = await passwordGate(password, pub);
    if (label) extra.label = label;
    if (typeof captcha === 'boolean') extra.captcha = captcha;
    try {
      const r = await this.#fresh(async () => {
        const { mek, kek } = this.#cur();
        return api.createReverse({ id, folder: folderId, mek, priv: await sealLinkKey(kek, { userId: this.user.id, mekId: mek, linkId: id }, pkcs8), ...extra, ...step });
      });
      if (r.id !== id) throw malformed();
      return { url: reverseUrl(id, pub), id, expires: r.expires ?? null, views: r.views ?? null, captcha: r.captcha === true, accept: Array.isArray(r.accept) ? r.accept : ['files'] };
    } finally {
      pkcs8.fill(0);
    }
  }

  /**
   * Reverse shares (of one folder, or all) → rows as the server lists them,
   * each with `url` (the link, rebuilt from its private key here) or null.
   */
  async reverseShares(folderId = null) {
    const r = await api.reverse(folderId);
    const rows = Array.isArray(r.reverse) ? r.reverse : [];
    return Promise.all(rows.map(async (x) => {
      const k = await this.#linkKey(x.id, x.mek, x.priv);
      const { priv, mek, ...rest } = x; // eslint-disable-line no-unused-vars
      return { ...rest, url: k ? reverseUrl(x.id, k.pub) : null };
    }));
  }

  /**
   * Change reverse share `id` (PATCH /api/private/shares/<id>, docs/REVERSE.md
   * §6.1): the plain values as given (label, expires — a time or null for
   * none —, views, maxFiles, maxBytes, maxFileBytes, types, captcha, and the
   * step-up `current` / `reauth` a weakening change needs) and, sealed here
   * with the link's key (which this session's KEK opens), the note (`note`:
   * its text, '' to remove it) and the uploader password (`password`: the new
   * one; `null` or `removePassword: true` to remove it). Neither is sent in
   * clear; like uploads to the link they are not end-to-end (the server holds
   * the keys that open the link's key). Refuses an empty change (it never
   * reports success for nothing). → the server's answer.
   */
  async updateReverse(id, { note, password, removePassword = false, ...plain } = {}) {
    const body = { ...plain };
    const newPassword = typeof password === 'string' && password !== '' ? password : null;
    if (note !== undefined || newPassword) {
      const r = await api.reverse();
      const x = (Array.isArray(r.reverse) ? r.reverse : []).find((y) => y.id === id);
      const k = x ? await this.#linkKey(x.id, x.mek, x.priv) : null;
      if (!k) throw new Error('This link’s key does not open here, so its note and password cannot be changed now.');
      if (note !== undefined) body.note = note ? await sealNote(k.pub, id, note) : null;
      if (newPassword) body.password = await passwordGate(newPassword, k.pub);
    }
    if (!newPassword && (removePassword || password === null)) body.password = null;
    if (!Object.keys(body).some((k) => k !== 'current' && k !== 'reauth')) throw new Error('Nothing to change.');
    return updateShare(id, body);
  }

  /**
   * Take in the files reverse shares have received: open each with its
   * share's private key, create (or reuse, by name) the upload's folders in
   * the target folder, and seal its DEK, name and metadata under the current
   * KEK like any Drive file (the content is not touched) → { added, failed,
   * renamed, flattened, deferred, more }.
   * - Names are cleaned (files.js cleanName: direction overrides and
   *   invisible separators removed, NFC); a file whose name changed is marked
   *   `renamed` in its metadata, which the Drive shows.
   * - A note, link or credential (its kind in the uploader's sealed
   *   metadata) goes into the link's folder itself, named "Note from <date>"
   *   and so on (a note with a title: the title), and keeps its kind marker
   *   in the Drive's sealed metadata; `kinds` counts what was added by kind.
   * - At most RECEIVED_MAX_DEPTH folder levels (and MAX_DEPTH in all) are
   *   created for a path, and RECEIVED_MAX_NEW_FOLDERS folders per take-in:
   *   past either, the file lands in the deepest folder allowed (`flattened`).
   * - What each item really is is held to its link's rules — its kind to what
   *   the link accepts, a file's type to the link's file types and its size to
   *   its largest file (the uploader's browser only declared them to the
   *   server): a mismatch is recorded as failed (`kind`, `type`, `size`).
   * - An item that cannot be taken in (it does not open, its name is not
   *   usable, the Drive refuses its place) is recorded as failed on the
   *   server: it leaves the queue (the Drive lists it to delete or try again),
   *   so it never holds up the items behind it. A network or server error —
   *   or a link whose key waits for the Drive upgrade — leaves it for the
   *   next time (`deferred`). The queue is read page by page (`next`).
   */
  async receivePending({ onItem } = {}) {
    const keys = new Map(); // share id → private key, or null (does not open) / 'later' (waits for the upgrade)
    const rules = new Map(); // share id → { accept, types, maxFileBytes }: what the link takes, held to what each item really is
    const folders = new Map(); // `${parent}\n${path}` → id
    const inside = new Map(); // folder id → { dirs: Map(name → id), names: Set }
    const depthOf = new Map(); // a link's folder → its depth in the tree
    let newFolders = 0;
    const contentOf = async (id) => {
      if (!inside.has(id)) inside.set(id, await this.names(id).catch(() => ({ dirs: new Map(), names: new Set() })));
      return inside.get(id);
    };
    // The folder for `dirPath` under `parent`, made where needed while the budget lasts; else the deepest one there is.
    const ensure = async (parent, dirPath) => {
      if (!dirPath) return parent;
      const key = `${parent}\n${dirPath}`;
      if (folders.has(key)) return folders.get(key);
      const cut = dirPath.lastIndexOf('/');
      const up = await ensure(parent, cut < 0 ? '' : dirPath.slice(0, cut));
      const leaf = dirPath.slice(cut + 1);
      const here = await contentOf(up);
      let id = here.dirs.get(leaf);
      if (!id) {
        if (newFolders >= RECEIVED_MAX_NEW_FOLDERS) return up;
        newFolders++;
        id = await this.mkdir(up, uniqueName(here.names, leaf));
        here.dirs.set(leaf, id);
        inside.set(id, { dirs: new Map(), names: new Set() });
      }
      folders.set(key, id);
      return id;
    };
    const levelsUnder = async (parent) => {
      if (!depthOf.has(parent)) {
        let d;
        try { const r = await api.node(parent); d = Array.isArray(r.path) ? r.path.filter((x) => x && x.id !== parent).length : 0; } catch { d = MAX_DEPTH; }
        depthOf.set(parent, d);
      }
      return Math.max(0, Math.min(RECEIVED_MAX_DEPTH, MAX_DEPTH - depthOf.get(parent)));
    };
    const failure = (reason) => Object.assign(new Error(reason), { receivedReason: reason });
    // A refusal by the Drive (full, folder full, too deep) fails the item; being signed out or losing the Drive stops the take-in.
    const refused = (e) => e instanceof ApiError && e.status >= 400 && e.status < 500 && e.status !== 401 && e.status !== 403 && e.code !== 'mek_not_current';
    // `kinds`: what was added, by kind (files, and notes, links and credentials received).
    const out = { added: 0, failed: 0, renamed: 0, flattened: 0, deferred: 0, more: false, kinds: { files: 0, note: 0, url: 0, secret: 0 } };
    let after = null;
    for (let page = 0; page < RECEIVED_MAX_PAGES; page++) {
      const r = await api.received(after);
      const items = Array.isArray(r.items) ? r.items : [];
      for (const k of Array.isArray(r.keys) ? r.keys : []) {
        if (keys.has(k.id)) continue;
        rules.set(k.id, { accept: Array.isArray(k.accept) && k.accept.length ? k.accept : ['files'], types: k.types && ['allow', 'block'].includes(k.types.mode) && Array.isArray(k.types.rules) ? k.types : null,
          maxFileBytes: Number.isSafeInteger(k.maxFileBytes) ? k.maxFileBytes : null });
        if (!k.mek && !this.legacy) { keys.set(k.id, 'later'); continue; }
        const got = await this.#linkKey(k.id, k.mek, k.priv);
        keys.set(k.id, got ? got.privateKey : null);
      }
      for (const it of items) {
        try {
          const priv = keys.get(it.rs);
          if (priv === 'later') { out.deferred++; continue; }
          if (!priv) throw failure('unreadable');
          let got;
          try { got = await openUpload(priv, it.rs, it); } catch { throw failure('unreadable'); }
          // The uploader's sealed size must be the server's (the chunks follow from it): else it fails closed.
          if (got.size !== it.size) throw failure('unreadable');
          // A note, link or credential: in the link's folder itself, named from its kind (a note: its
          // title) and the time the server received it; its kind marker stays in the sealed metadata.
          const item = got.item;
          let path;
          let renamed = false;
          if (item) {
            path = itemLeaf(item, it.created);
          } else {
            try {
              path = checkPath(cleanName(got.path));
              path.split('/').forEach(checkName);
            } catch { throw failure('name'); }
            renamed = path !== got.path;
          }
          // What it really is, against the link's rules (the uploader's browser only declared it to the
          // server, and a modified one can lie): its kind, and for a file its type and size. A mismatch
          // fails (listed, to delete): it never enters the Drive.
          const rule = rules.get(it.rs) || { accept: ['files'], types: null, maxFileBytes: null };
          if (!rule.accept.includes(item ? item.kind : 'files')) throw failure('kind');
          if (!item) {
            if (rule.maxFileBytes !== null && it.size > rule.maxFileBytes) throw failure('size');
            if (rule.types) {
              if (uncheckableExt(path)) throw failure('type');
              const d = declare([{ path, type: normalizeMime(got.type) || OCTET }]);
              if (refusedTypes(rule.types.mode, rule.types.rules, d.types).length) throw failure('type');
            }
          }
          const segs = path.split('/');
          const leafName = segs.pop();
          const allowed = item ? 0 : await levelsUnder(it.parent);
          const want = segs.slice(0, allowed).join('/');
          let parent;
          try { parent = await ensure(it.parent, want); } catch (e) {
            if (!(e instanceof ApiError)) throw failure('name'); // a folder name this Drive cannot store
            throw refused(e) ? failure('place') : e;
          }
          // Deeper than allowed, or out of new folders: in the deepest folder there is.
          const flattened = segs.length > allowed || (want !== '' && folders.get(`${it.parent}\n${want}`) !== parent);
          const type = normalizeMime(got.type) || OCTET;
          const { names: taken } = await contentOf(parent);
          const leaf = uniqueName(taken, leafName);
          const marker = item ? (item.kind === 'note' ? { kind: 'note', fmt: item.fmt } : { kind: item.kind }) : null;
          const meta = { type, mtime: got.mtime, size: it.size, ...(renamed ? { renamed: true } : {}), ...(marker || {}) };
          try {
            // The server's size is the one the chunks have: the metadata says the same.
            await this.#fresh(async () => api.acceptReceived(it.id, { parent, ...(await this.#sealNew({ name: leaf, meta: JSON.stringify(meta), dek: got.fk })) }));
          } catch (e) {
            taken.delete(leaf);
            throw refused(e) ? failure('place') : e;
          } finally {
            got.fk.fill(0);
          }
          out.added++;
          out.kinds[item ? item.kind : 'files']++;
          if (renamed) out.renamed++;
          if (flattened) out.flattened++;
          if (onItem) onItem({ id: it.id, path, name: leaf, parent, renamed, flattened, ...(item ? { item } : {}) });
        } catch (e) {
          if (!e || !e.receivedReason) {
            if (e instanceof ApiError && (e.status === 401 || e.status === 403)) throw e; // signed out, or no Drive: stop
            out.deferred++; // a network or server error: next time
            continue;
          }
          out.failed++;
          await api.receivedFailed(it.id, e.receivedReason).catch(() => {});
        }
      }
      out.more = !!r.more;
      after = typeof r.next === 'string' ? r.next : null;
      if (!out.more || !after) break;
    }
    return out;
  }

  /**
   * Received files that could not be taken in → { items: [{ id, rs, label,
   * size, created, failed, reason }], more, next, total } (`total`, the count
   * of all of them, on the first page only).
   */
  async failedReceived(after = null) {
    let total;
    if (!after) {
      const st = await api.state();
      total = Number.isSafeInteger(st.receivedFailed) ? st.receivedFailed : null;
      if (total === 0) return { items: [], more: false, next: null, total };
    }
    const r = await api.receivedFailedList(after);
    const items = Array.isArray(r.items) ? r.items : [];
    return { items, more: !!r.more, next: typeof r.next === 'string' ? r.next : null, ...(after ? {} : { total: total ?? items.length }) };
  }

  /** Put a failed received file back in the queue (the next take-in tries it again). */
  async retryReceived(id) {
    await api.receivedRetry(id);
  }
}

/** The uploader's link of a reverse share: /r/<id>#<the raw public key>. */
function reverseUrl(id, pub) {
  return `${location.origin}/r/${id}#${fragmentOf(pub)}`;
}

// ── the personal kit (docs/DRIVE.md §3.1), for the Account page ────────────
//
// A file the user downloads and keeps offline: their id, username, user salt
// and the KEK of every sub-MEK their Drive uses (secbin-user-kit/2), sealed
// here under a passphrase (drivekit.js). With a copy of the ciphertext, it
// opens that user's files and reverse-share links offline. Only the owner
// restores from one, on this server (Admin → Security → Keys, keysclient.js).

/** A sub-MEK's fingerprint as the pages show it (xxxx-xxxx-xxx). */
export const fpText = (fp) => (typeof fp === 'string' && fp.length >= 8 ? `${fp.slice(0, 4)}-${fp.slice(4, 8)}-${fp.slice(8)}` : '—');

/**
 * Build the personal kit → { text, keks, missing } (`text`: the file). The
 * server hands its content only after the step-up (`step`: { current } |
 * { reauth }), and records the download.
 */
export async function buildPersonalKit({ user, passphrase = '', step } = {}) {
  const u = await whoAmI(user);
  if (u.impersonating) throw new ApiError('A personal kit is the user’s own: return to your account first.', 403, 'impersonating');
  const r = await api.kit(step || {});
  const k = r.kit;
  if (!k || k.id !== u.id || typeof k.userSalt !== 'string' || !Array.isArray(k.keks)) throw malformed();
  const payload = { v: 2, id: k.id, username: k.username, made: Math.floor(Date.now() / 1000), userSalt: k.userSalt, current: k.current, keks: k.keks.map(({ mekId, fp, from, until, kek }) => ({ mekId, fp, from, until, kek })) };
  const text = await sealDriveKit('user', payload, { accountId: u.id, origin: location.origin, passphrase: String(passphrase ?? '') });
  return { text, keks: payload.keks.length, missing: [...(r.missing || []), ...(r.broken || [])] };
}

/** Open a personal kit's text for `u` → its payload (keys as bytes). Throws DriveKitError. */
async function readPersonalKit(text, passphrase, u) {
  const p = await openDriveKit(parseDriveKit(text), { kind: 'user', accountId: u.id, origin: location.origin, passphrase: String(passphrase ?? '') });
  if (p.id !== u.id || typeof p.userSalt !== 'string' || !Array.isArray(p.keks)) throw new DriveKitError('The kit opened, but its content is not valid.', 'payload');
  const keks = new Map();
  for (const k of p.keks.slice(0, 500)) {
    try { keks.set(k.mekId, { kek: keyBytes(k.kek), fp: k.fp, from: k.from, until: k.until }); } catch { /* skipped */ }
  }
  return { ...p, keks };
}

/**
 * The read-only check of a personal kit (docs/DRIVE.md §3.1): the kit opens
 * here (its format, account and server, the passphrase), then each KEK and
 * the salt are compared on the server by check value (match or no match
 * only, never a key). `date` (seconds; default now, future dates allowed):
 * which sub-MEK is in effect then, and whether the kit holds it. → { verdict:
 * 'complete' | 'incomplete' | 'failed', checks: [{ id, status, label,
 * detail }], atDate: { mekId, fp, inKit } | null, keks }.
 */
export async function verifyPersonalKit({ user, text, passphrase = '', date = null } = {}) {
  const u = await whoAmI(user);
  const checks = [];
  const add = (id, status, label, detail) => checks.push({ id, status, label, detail });
  let kit;
  try {
    const env = parseDriveKit(text);
    if (env.kind !== 'user') throw new DriveKitError('This is not a personal kit.', 'format');
    if (env.accountId !== u.id) throw new DriveKitError('This kit belongs to another account.', 'owner');
    add('format', 'pass', 'Format and account', `A personal kit for your account, for ${location.origin}.`);
    kit = await readPersonalKit(text, passphrase, u);
  } catch (e) {
    add(checks.length ? 'auth' : 'format', 'fail', checks.length ? 'Decrypts, authentication tag valid' : 'Format and account', e instanceof DriveKitError ? e.message : 'The kit could not be opened.');
    return { verdict: 'failed', checks, atDate: null, keks: [] };
  }
  add('auth', 'pass', 'Decrypts, authentication tag valid', 'The passphrase is right and the file is unchanged.');
  const body = { keks: {}, salt: await saltCheckValue(kit.userSalt, u.id) };
  for (const [id, k] of kit.keks) body.keks[id] = await keyCheckValue(k.kek, 'kek');
  for (const k of kit.keks.values()) k.kek.fill(0);
  const r = await api.kitVerify(body);
  add('salt', r.salt === 'match' ? 'pass' : 'fail', 'User salt', r.salt === 'match' ? 'It is this account’s salt.' : 'It is not this account’s salt: the kit cannot open this Drive.');
  const used = r.keks.filter((x) => x.inUse || x.current);
  const bad = used.filter((x) => x.result !== 'match');
  add('keks', bad.length ? 'fail' : 'pass', 'Keys for every sub-MEK your Drive uses', bad.length
    ? `Missing or different: ${bad.map((x) => fpText(x.fp)).join(', ')}. Download a fresh kit.`
    : `All ${used.length}: ${used.map((x) => fpText(x.fp)).join(', ')}.`);
  const t = Number.isSafeInteger(date) ? date : r.now;
  const eff = effectiveAt(r.keks.map((x) => ({ id: x.mekId, from: x.from, until: x.until, created: 0 })), t);
  const atDate = eff ? { mekId: eff.id, fp: r.keks.find((x) => x.mekId === eff.id)?.fp, inKit: r.keks.find((x) => x.mekId === eff.id)?.result === 'match' } : null;
  add('date', atDate && atDate.inKit ? 'pass' : 'warn', 'The sub-MEK in effect on the chosen date', atDate
    ? `${fpText(atDate.fp)} — ${atDate.inKit ? 'in this kit.' : 'not in this kit (it was added after the kit, or is scheduled): download a fresh kit after it starts.'}`
    : 'No sub-MEK is in effect on that date.');
  const verdict = checks.some((c) => c.status === 'fail') ? 'incomplete' : 'complete';
  return { verdict, checks, atDate, keks: r.keks };
}

// Byte helpers some pages use with the kit.
export { bytesFromB64url, b64urlFromBytes };
