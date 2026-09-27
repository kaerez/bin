// driveclient.mock.js — TEMPORARY in-memory stand-in for public/js/driveclient.js
// (shard B), with the same exports, so the Drive UI can be built and tested
// before the real client and server land. Loaded only when the Drive page's
// URL has ?mock=1 (public/dashboard/js/drive.js); nothing here touches the
// network or stores anything. Delete this file at integration.
//
// Test hooks (URL): &state=locked (default) | unlocked | disabled;
// &capacity=<bytes>. Unlock with any password, recovery code or passkey
// except the literal "wrong". `revokeShare(id)` is a mock-only export the page
// uses instead of the real /api/private/shares/<id>/revoke while mocked.

import { createZipWriter } from './zip.js';
import { safeName } from './downloads.js';

export class DriveLocked extends Error {
  constructor(message = 'The Drive is locked.') { super(message); this.name = 'DriveLocked'; this.credentialIds = []; }
}
export class DriveDisabled extends Error {
  constructor(message = 'Drive is not enabled for your account.') { super(message); this.name = 'DriveDisabled'; }
}

const params = new URLSearchParams(typeof location !== 'undefined' ? location.search : '');
const KEY = 'secbin_mock_dk';
const now = () => Math.floor(Date.now() / 1000);
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
let seq = 0;
const newId = () => `n${(++seq).toString(36)}${Math.random().toString(36).slice(2, 8)}`;

const state = {
  capacity: Number(params.get('capacity')) || 50 * 1024 * 1024,
  nodes: new Map(), // id → { id, parent, kind, name, type, mtime, size, updated, bytes }
  shares: [], // { id, nodes: [ids], label, status, created, expires, views_total, left }
};

function put(parent, kind, name, extra = {}) {
  const id = newId();
  state.nodes.set(id, { id, parent, kind, name, type: kind === 'file' ? 'application/octet-stream' : '', mtime: Date.now(), size: 0, updated: now(), bytes: null, ...extra });
  return id;
}
const text = (s) => new TextEncoder().encode(s);
function seed() {
  state.nodes.set('root', { id: 'root', parent: null, kind: 'dir', name: '', size: 0, updated: now() });
  const docs = put('root', 'dir', 'Documents');
  const reports = put(docs, 'dir', 'Reports');
  put(reports, 'file', 'q1.txt', { type: 'text/plain', bytes: text('Q1 numbers\n'), size: 11 });
  put(reports, 'dir', 'Archive');
  put(docs, 'file', 'notes.md', { type: 'text/markdown', bytes: text('# Notes\nhello\n'), size: 14 });
  const photos = put('root', 'dir', 'Photos');
  put(photos, 'file', 'cat.png', { type: 'image/png', bytes: new Uint8Array(2048), size: 2048 });
  put('root', 'dir', 'Empty');
  put('root', 'file', 'readme.txt', { type: 'text/plain', bytes: text('Welcome to the mock Drive.\n'), size: 27 });
}
seed();

const used = () => [...state.nodes.values()].reduce((n, x) => n + (x.kind === 'file' ? x.size : 0), 0);
const node = (id) => { const n = state.nodes.get(id); if (!n) throw new Error('That item no longer exists.'); return n; };
const kids = (id) => [...state.nodes.values()].filter((n) => n.parent === id);
const within = (id, anc) => { for (let x = state.nodes.get(id); x; x = state.nodes.get(x.parent)) if (x.id === anc) return true; return false; };
const pub = (n) => ({ id: n.id, kind: n.kind, name: n.name, type: n.type || '', mtime: n.mtime || 0, size: n.size || 0, updated: n.updated });
const aborted = () => new DOMException('The upload was cancelled.', 'AbortError');

function nameFree(parent, name, except = null) {
  if (kids(parent).some((k) => k.name === name && k.id !== except)) throw new Error(`An item named “${name}” already exists in this folder.`);
}

async function fakeTransfer(size, onProgress, signal) {
  const steps = Math.max(2, Math.min(8, Math.ceil(size / 4096)));
  for (let i = 1; i <= steps; i++) {
    if (signal && signal.aborted) throw aborted();
    await wait(40);
    if (onProgress) onProgress(i / steps);
  }
}

function saveBlob(blob, name) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = safeName(name);
  a.hidden = true;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60_000);
}

export class DriveClient {
  async usage() { return { used: used(), capacity: state.capacity }; }

  async list(nodeId = 'root') {
    const n = node(nodeId);
    if (n.kind !== 'dir') throw new Error('Not a folder.');
    const path = [];
    for (let x = n; x; x = state.nodes.get(x.parent)) path.unshift({ id: x.id, name: x.name });
    return { node: pub(n), path, children: kids(nodeId).map(pub) };
  }

  async mkdir(parentId, name) {
    node(parentId);
    nameFree(parentId, name);
    return { id: put(parentId, 'dir', name) };
  }

  async upload(parentId, file, { onProgress, signal } = {}) {
    node(parentId);
    if (used() + file.size > state.capacity) throw new Error('Not enough space left in your Drive.');
    nameFree(parentId, file.name);
    await fakeTransfer(file.size, onProgress, signal);
    const bytes = new Uint8Array(await file.arrayBuffer());
    return { id: put(parentId, 'file', file.name, { type: file.type || 'application/octet-stream', mtime: file.lastModified || Date.now(), size: file.size, bytes }) };
  }

  async uploadTree(parentId, entries, { onProgress, signal } = {}) {
    const total = entries.reduce((n, e) => n + e.file.size, 0);
    if (used() + total > state.capacity) throw new Error('Not enough space left in your Drive.');
    let done = 0;
    const dirs = new Map([['', parentId]]);
    const dirFor = (segs) => {
      let at = parentId;
      for (let i = 0; i < segs.length; i++) {
        const p = segs.slice(0, i + 1).join('/');
        if (!dirs.has(p)) {
          const existing = kids(at).find((k) => k.kind === 'dir' && k.name === segs[i]);
          dirs.set(p, existing ? existing.id : put(at, 'dir', segs[i]));
        }
        at = dirs.get(p);
      }
      return at;
    };
    const ids = [];
    for (const e of entries) {
      const segs = e.path.split('/');
      const at = dirFor(segs.slice(0, -1));
      nameFree(at, segs.at(-1));
      await fakeTransfer(e.file.size, (f) => onProgress && onProgress(total ? (done + f * e.file.size) / total : 1), signal);
      done += e.file.size;
      ids.push(put(at, 'file', segs.at(-1), { type: e.file.type || 'application/octet-stream', mtime: e.file.lastModified || Date.now(), size: e.file.size, bytes: new Uint8Array(await e.file.arrayBuffer()) }));
    }
    return { ids };
  }

  async rename(id, name) {
    const n = node(id);
    if (id === 'root') throw new Error('The top folder cannot be renamed.');
    nameFree(n.parent, name, id);
    n.name = name;
    n.updated = now();
    return { ok: true };
  }

  async move(id, parentId) {
    const n = node(id);
    node(parentId);
    if (id === 'root' || within(parentId, id)) throw new Error('A folder cannot be moved into itself.');
    nameFree(parentId, n.name, id);
    n.parent = parentId;
    n.updated = now();
    return { ok: true };
  }

  async remove(id) {
    if (id === 'root') throw new Error('The top folder cannot be deleted.');
    node(id);
    const gone = [...state.nodes.keys()].filter((k) => within(k, id));
    for (const k of gone) state.nodes.delete(k);
    for (const s of state.shares) if (s.status === 'active' && s.nodes.some((x) => gone.includes(x))) s.status = 'revoked';
    return { ok: true };
  }

  async download(id, { onProgress } = {}) {
    const n = node(id);
    await fakeTransfer(n.size, onProgress);
    saveBlob(new Blob([n.bytes || new Uint8Array(0)], { type: 'application/octet-stream' }), n.name);
  }

  async downloadFolder(id, { onProgress } = {}) {
    const n = node(id);
    const parts = [];
    const zip = createZipWriter({ write: async (b) => { parts.push(b.slice()); } });
    const walk = async (dirId, prefix) => {
      for (const k of kids(dirId).sort((a, b) => a.name.localeCompare(b.name))) {
        const p = prefix + k.name;
        if (k.kind === 'dir') { await zip.addDir(p); await walk(k.id, p + '/'); } else {
          await zip.addFile(p, k.mtime, (async function* () { yield k.bytes || new Uint8Array(0); })());
        }
      }
    };
    await walk(id, '');
    await zip.finish();
    if (onProgress) onProgress(1);
    saveBlob(new Blob(parts, { type: 'application/zip' }), `${n.name || 'drive'}.zip`);
  }

  async share(nodeIds, { views = 1, expire = '24h', label = '' } = {}) {
    for (const id of nodeIds) node(id);
    const m = /^(\d+)([mhd])$/.exec(expire);
    const sec = m ? Number(m[1]) * { m: 60, h: 3600, d: 86400 }[m[2]] : 86400;
    const id = `fMOCK${Math.random().toString(36).slice(2, 12).padEnd(10, '0')}${(++seq).toString(36)}`;
    state.shares.push({ id, nodes: [...nodeIds], label: label || '', status: 'active', created: now(), expires: now() + sec, views_total: views, left: views });
    return { url: `${location.origin}/p/${id}#mock-key-${Math.random().toString(36).slice(2, 10)}`, id, deletetoken: 'mock-delete-token' };
  }

  async shares(nodeId) {
    node(nodeId);
    return state.shares.filter((s) => s.nodes.some((x) => within(x, nodeId) || within(nodeId, x))).map((s) => ({ ...s, kind: 'drive' }));
  }
}

let client = null;

export async function openDrive() {
  const st = params.get('state') || 'locked';
  if (st === 'disabled') throw new DriveDisabled();
  let unlocked = st === 'unlocked';
  try { unlocked = unlocked || sessionStorage.getItem(KEY) === '1'; } catch { /* storage off */ }
  if (!unlocked) throw new DriveLocked();
  client = client || new DriveClient();
  return client;
}

export async function unlockDrive(creds = {}) {
  await wait(60);
  const secret = creds.password ?? creds.code ?? (creds.prfOutput ? 'prf' : '');
  if (!secret || secret === 'wrong') throw new Error('That did not unlock your Drive.');
  try { sessionStorage.setItem(KEY, '1'); } catch { /* storage off */ }
  client = client || new DriveClient();
  return client;
}

/** Mock-only: the page's revoke while mocked (the real page uses api.revokeShare). */
export async function revokeShare(id) {
  const s = state.shares.find((x) => x.id === id);
  if (!s) throw new Error('No such share.');
  s.status = 'revoked';
  return { ok: true };
}
