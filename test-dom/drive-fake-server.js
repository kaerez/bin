// drive-fake-server.js — an in-memory stand-in for the Drive API (docs/DRIVE.md
// §6) behind a mocked fetch, shared by the DOM suites of the Drive client
// (driveclient.test.js) and the Drive page (drive.test.js). It keeps only what
// the real server would: sealed names, sizes, chunks, wraps — and its key
// rules (docs/DRIVE.md §6, src/routes/drive.js setKeys): a user's Drive is set
// up only once the owner's escrow key exists, with an escrow wrap for it (never
// removable) and a wrap of the user's own; the step-up for removing wraps,
// replacing the pw wrap or the salt (unless stale or the first set-up) and for
// changing the owner's escrow or signing key once one exists; a new escrow key
// signed by the signing key; the old escrow key kept (`escrowPrivOld`); while
// the owner impersonates (`impersonatedBy`), only added wraps and the logged
// escrow route. Not a test file itself
// (vitest.dom.config.js picks up *.test.js only).
import { vi } from 'vitest';
import { CHUNK, TAG, encryptChunk, importFileKey } from '../public/js/files.js';
import { deriveSubkeys, sealField, escrowKeyId, escrowWrapKeyId, escrowKeyEndorsed } from '../public/js/drivekeys.js';
import { randomBytes, b64urlFromBytes } from '../public/js/bytes.js';

/** An in-memory Drive server for one user (plus an owner) and a fetch that talks to it. */
export function fakeServer({ role = 'user', enabled = true, capacity = 1 << 30 } = {}) {
  const S = {
    user: { id: role === 'owner' ? 'owner1' : 'u1', role },
    enabled,
    capacity,
    driveSalt: null,
    wraps: new Map(),
    escrowPub: null,
    escrowPriv: null,
    nodes: new Map([['root', { id: 'root', parent: null, kind: 'dir', name: '', size: 0, chunks: 0, state: 'ready', created: 1, updated: 1 }]]),
    chunks: new Map(),
    shareBodies: [],
    shares: [], // { id, nodes, label, created, expires, views_total, left, status }
    revoked: [],
    requests: [],
    userWraps: null, // the "other user" for the escrow route
    adminKeys: [],
    pwStale: false,
    escrowPin: null,
    escrowSignPub: null,
    escrowSig: null,
    escrowSignPriv: null,
    escrowPrivOld: {}, // the owner's earlier escrow keys (sealed, by kid)
    impersonatedBy: null, // the owner's username while the owner acts as this user
    ownerId: 'owner1',
    ownerEscrowPriv: null, // the owner's sealed escrow key (for the impersonation escrow route)
    escrowUses: 0,
    busyFinalize: 0, // answer finalize "busy" this many times
  };
  const ok = (data, status = 200) => ({ ok: status < 400, status, type: 'basic', json: async () => data, arrayBuffer: async () => new ArrayBuffer(0) });
  const bin = (bytes) => ({ ok: true, status: 200, type: 'basic', json: async () => null, arrayBuffer: async () => bytes.slice().buffer });
  const fail = (status, error) => ok({ error, message: error }, status);
  const kids = (id) => [...S.nodes.values()].filter((n) => n.parent === id);
  const ancestors = (n) => { const out = []; let p = n.parent; while (p) { const a = S.nodes.get(p); out.unshift(a); p = a.parent; } return out; };
  const within = (id, anc) => { for (let x = S.nodes.get(id); x; x = S.nodes.get(x.parent)) if (x.id === anc) return true; return false; };
  const pub = (n) => ({ ...n });
  const used = () => [...S.nodes.values()].reduce((s, n) => s + n.size, 0);
  const shareRow = ({ nodes, ...row }) => { void nodes; return { ...row, kind: 'drive', locked: 0 }; };
  S.fetch = vi.fn(async (url, init = {}) => {
    const method = init.method || 'GET';
    const u = new URL(url, 'https://bin.example');
    const p = u.pathname;
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : init.body;
    S.requests.push({ method, path: p, body, headers: init.headers || {} });
    let m;
    if (p === '/api/auth/session') return ok({ authenticated: true, user: S.user, impersonatedBy: S.impersonatedBy });
    if (p === '/api/private/drive' && method === 'GET') {
      if (!S.enabled) return ok({ enabled: false });
      const wraps = [...S.wraps.values()].map((w) => (S.impersonatedBy && w.kind === 'escrow' ? { ...w, data: null } : w));
      return ok({
        enabled: true, capacity: S.capacity, used: used(), driveSalt: S.driveSalt, wraps, escrowPub: S.escrowPub, escrowSignPub: S.escrowSignPub, escrowSig: S.escrowSig,
        escrowPin: S.escrowPin, pwStale: S.pwStale,
        ...(role === 'owner' ? { escrowPriv: S.escrowPriv, escrowSignPriv: S.escrowSignPriv, escrowPrivOld: S.escrowPrivOld } : {}),
      });
    }
    if (p === '/api/private/drive/escrow' && method === 'POST') {
      if (!S.impersonatedBy) return fail(403, 'not_impersonating');
      const wrap = [...S.wraps.values()].find((w) => w.kind === 'escrow') || null;
      if (wrap) S.escrowUses++;
      return ok({ ownerId: S.ownerId, escrowPub: S.escrowPub, escrowPriv: S.ownerEscrowPriv, escrowPrivOld: S.escrowPrivOld, wrap, wraps: S.wraps.size });
    }
    if (p === '/api/private/drive/keys' && method === 'PUT') {
      const has = (k, r) => S.wraps.has(`${k}|${r}`);
      const OWN = ['pw', 'recovery', 'passkey'];
      const first = S.wraps.size === 0;
      const set = body.set || [];
      const remove = body.remove || [];
      const newPw = set.some((w) => w.kind === 'pw');
      const ownerKeys = ['escrowPriv', 'escrowPub', 'escrowSignPriv', 'escrowSignPub', 'escrowSig'].filter((k) => body[k] !== undefined);
      if (ownerKeys.length && role !== 'owner') return fail(403, 'owner_only');
      if (role !== 'owner') {
        if (remove.some((w) => w.kind === 'escrow')) return fail(403, 'escrow_required');
        const escrow = set.find((w) => w.kind === 'escrow');
        if (first && !S.impersonatedBy) {
          if (!S.escrowPub) return fail(409, 'escrow_not_ready');
          if (!escrow || !set.some((w) => OWN.includes(w.kind))) return fail(400, 'invalid');
        }
        if (escrow && (!S.escrowPub || escrowWrapKeyId(escrow) !== await escrowKeyId(S.escrowPub))) return fail(400, 'invalid');
      }
      if (S.impersonatedBy) {
        if (first) return fail(403, 'impersonating');
        const addOnly = set.length && set.every((w) => OWN.includes(w.kind) && !has(w.kind, w.ref)) && (!body.driveSalt || (newPw && !has('pw', 'pw'))) && !body.escrowPin && !ownerKeys.length;
        if (remove.length || !addOnly) return fail(403, 'impersonating');
      }
      const signKey = body.escrowSignPub ?? S.escrowSignPub;
      if ((body.escrowPub || body.escrowSignPub || body.escrowSig) && signKey && !(await escrowKeyEndorsed(signKey, body.escrowPub ?? S.escrowPub, body.escrowSig))) return fail(400, 'invalid');
      const pwExempt = S.pwStale || !has('pw', 'pw');
      const needs = (ownerKeys.length && (S.escrowPub || S.escrowPriv || S.escrowSignPub || S.escrowSignPriv))
        || (!first && (remove.some((w) => has(w.kind, w.ref)) || (newPw && !pwExempt) || (body.driveSalt && S.driveSalt && !(newPw && pwExempt))));
      if (needs && !body.current && !body.reauth) return fail(400, 'reauth_required');
      if (needs && body.current && body.current !== S.proof) return fail(403, 'wrong_password');
      const own = new Set([...S.wraps.values()].filter((w) => OWN.includes(w.kind)).map((w) => `${w.kind}|${w.ref}`));
      for (const w of remove) own.delete(`${w.kind}|${w.ref}`);
      for (const w of set) if (OWN.includes(w.kind)) own.add(`${w.kind}|${w.ref}`);
      if (!first && own.size === 0) return fail(409, 'last_own_wrap');
      if (body.driveSalt) S.driveSalt = body.driveSalt;
      for (const w of remove) S.wraps.delete(`${w.kind}|${w.ref}`);
      for (const w of set) S.wraps.set(`${w.kind}|${w.ref}`, w);
      if (newPw) S.pwStale = false;
      if (body.escrowPriv && S.escrowPriv && body.escrowPub && S.escrowPub) S.escrowPrivOld = { ...S.escrowPrivOld, [await escrowKeyId(S.escrowPub)]: S.escrowPriv };
      if (body.escrowPriv) S.escrowPriv = body.escrowPriv;
      if (body.escrowPub) S.escrowPub = body.escrowPub;
      if (body.escrowSignPriv) S.escrowSignPriv = body.escrowSignPriv;
      if (body.escrowSignPub) S.escrowSignPub = body.escrowSignPub;
      if (body.escrowSig) S.escrowSig = body.escrowSig;
      if (body.escrowPin) S.escrowPin = body.escrowPin;
      return ok({ ok: true });
    }
    if ((m = p.match(/^\/api\/private\/drive\/nodes\/([^/]+)$/))) {
      const n = S.nodes.get(m[1]);
      if (!n) return fail(404, 'not_found');
      if (method === 'GET') return ok({ node: pub(n), children: kids(n.id).map(pub), path: ancestors(n).map(pub) });
      if (method === 'PATCH') {
        if (body.parent && (body.parent === n.id || within(body.parent, n.id))) return fail(409, 'cycle');
        if (body.name) n.name = body.name;
        if (body.parent) n.parent = body.parent;
        return ok({ ok: true });
      }
      if (method === 'DELETE') {
        const drop = (id) => { kids(id).forEach((c) => drop(c.id)); S.nodes.delete(id); };
        drop(n.id);
        for (const s of S.shares) if (s.status === 'active' && s.nodes.some((x) => !S.nodes.has(x))) s.status = 'revoked';
        return ok({ ok: true });
      }
    }
    if ((m = p.match(/^\/api\/private\/drive\/nodes\/([^/]+)\/shares$/))) {
      // A node's active shares: those referencing it, or (for a folder) a file under it.
      return ok({ shares: S.shares.filter((s) => s.status === 'active' && s.nodes.some((x) => within(x, m[1]))).map(shareRow) });
    }
    if ((m = p.match(/^\/api\/private\/shares\/([^/]+)\/revoke$/)) && method === 'POST') {
      const s = S.shares.find((x) => x.id === m[1]);
      if (!s) return fail(404, 'not_found');
      s.status = 'revoked';
      S.revoked.push(s.id);
      return ok({ ok: true });
    }
    if (p === '/api/private/drive/folders' && method === 'POST') {
      if (!/^[A-Za-z0-9_-]{22}$/.test(body.id) || S.nodes.has(body.id)) return fail(409, 'bad_id');
      S.nodes.set(body.id, { id: body.id, parent: body.parent, kind: 'dir', name: body.name, size: 0, chunks: 0, state: 'ready', created: 2, updated: 2 });
      return ok({ id: body.id });
    }
    if (p === '/api/auth/prelogin' && method === 'POST') return ok({ salt: 'AAAAAAAAAAAAAAAAAAAAAA', t: 3 });
    if (p === '/api/private/drive/files' && method === 'POST') {
      if (!/^[A-Za-z0-9_-]{22}$/.test(body.id) || S.nodes.has(body.id)) return fail(409, 'bad_id');
      if (used() + body.size > S.capacity) return fail(413, 'drive_full');
      const chunks = Math.ceil(body.size / CHUNK);
      S.nodes.set(body.id, { id: body.id, parent: body.parent, kind: 'file', name: body.name, meta: body.meta, fk: body.fk, size: body.size, chunks, state: 'pending', created: 3, updated: 3 });
      return ok({ id: body.id, uploadToken: `tok-${body.id}`, chunks });
    }
    if ((m = p.match(/^\/api\/private\/drive\/files\/([^/]+)\/chunk\/(\d+)$/))) {
      const n = S.nodes.get(m[1]);
      const i = Number(m[2]);
      if (method === 'PUT') {
        if (init.headers['x-upload-token'] !== `tok-${n.id}`) return fail(403, 'bad_token');
        if (i >= n.chunks || body.length !== Math.min(CHUNK, n.size - i * CHUNK) + TAG) return fail(400, 'bad_size');
        S.chunks.set(`${n.id}/${i}`, body.slice());
        return ok({ ok: true });
      }
      const c = S.chunks.get(`${n.id}/${i}`);
      return c ? bin(c) : fail(404, 'not_found');
    }
    if ((m = p.match(/^\/api\/private\/drive\/files\/([^/]+)\/finalize$/))) {
      const n = S.nodes.get(m[1]);
      if (S.busyFinalize > 0) { S.busyFinalize--; return fail(409, 'busy'); } // a chunk write still in flight
      for (let i = 0; i < n.chunks; i++) if (!S.chunks.has(`${n.id}/${i}`)) return fail(409, 'incomplete');
      n.state = 'ready';
      return ok({ ok: true });
    }
    if (p === '/api/private/drive/shares' && method === 'POST') {
      S.shareBodies.push(body);
      const id = `fSHARE${S.shareBodies.length}`;
      const now = Math.floor(Date.now() / 1000);
      S.shares.push({ id, nodes: [...body.nodes], label: body.label || '', created: now, expires: now + 86400, views_total: body.views, left: body.views, status: 'active' });
      return ok({ id, deletetoken: `dt${S.shareBodies.length}` });
    }
    if (/^\/api\/private\/admin\/drive\/escrow\/[^/]+$/.test(p)) {
      const wraps = S.userWraps || [];
      return ok({ wrap: wraps.find((w) => w.kind === 'escrow') || null, wraps });
    }
    if ((m = p.match(/^\/api\/private\/admin\/drive\/keys\/([^/]+)$/))) {
      S.adminKeys.push({ userId: m[1], body });
      return ok({ ok: true });
    }
    return fail(404, `unrouted ${method} ${p}`);
  });
  return S;
}

/**
 * Store a tree as the browser would have written it under `dk` (sealed names
 * and metadata, chunked content): `tree` = { name: bytes (a file) | { … } (a
 * folder) }. → Map(path → node id).
 */
export async function seedTree(S, dk, tree, parent = 'root', prefix = '', ids = new Map()) {
  const keys = await deriveSubkeys(dk);
  for (const [name, v] of Object.entries(tree)) {
    const id = b64urlFromBytes(randomBytes(16));
    const path = prefix + name;
    const nameField = JSON.stringify(await sealField(keys.names, 'name', id, name));
    if (v instanceof Uint8Array) {
      const fk = randomBytes(32);
      const n = Math.ceil(v.length / CHUNK);
      const key = await importFileKey(b64urlFromBytes(fk));
      for (let i = 0; i < n; i++) S.chunks.set(`${id}/${i}`, await encryptChunk(key, i, n, v.slice(i * CHUNK, (i + 1) * CHUNK)));
      S.nodes.set(id, {
        id, parent, kind: 'file', name: nameField, size: v.length, chunks: n, state: 'ready', created: 1700000000, updated: 1700000000,
        meta: JSON.stringify(await sealField(keys.names, 'meta', id, JSON.stringify({ type: 'text/plain', mtime: 1700000000000, size: v.length }))),
        fk: JSON.stringify(await sealField(keys.files, 'fk', id, fk)),
      });
    } else {
      S.nodes.set(id, { id, parent, kind: 'dir', name: nameField, size: 0, chunks: 0, state: 'ready', created: 1700000000, updated: 1700000000 });
      await seedTree(S, dk, v, id, `${path}/`, ids);
    }
    ids.set(path, id);
  }
  return ids;
}
