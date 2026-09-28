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
// escrow route; the owner recovery kit's routes (the step-up for a download,
// a use and a restore of keys; a restored key only for the server's own
// public keys; the escrow key's version) and starting over; the key check
// value with every first set-up and every later wrap or pin, the step-up for
// replacing a wrap, no escrow wrap in the owner's own Drive, no first set-up
// of a Drive with content or keys but no wrap, one `escrowReset` record per
// epoch. Like the real server (src/lib/csrf.js), every signed-in change
// (POST / PUT / PATCH / DELETE under /api/private/, and log-out) must carry the
// session's CSRF token in X-Secbin-CSRF, the one GET /api/private/me hands out
// (403 csrf_mismatch otherwise, before anything changes): the Drive client
// sends it through public/js/api.js. Every fake server stands for the same
// browser session, so they share the token (FAKE_CSRF). Not a test file itself
// (vitest.dom.config.js picks up *.test.js only).
import { vi } from 'vitest';
import { CHUNK, TAG, encryptChunk, importFileKey } from '../public/js/files.js';
import { deriveSubkeys, sealField, escrowKeyId, escrowWrapKeyId, escrowKeyEndorsed, keyCheckValue } from '../public/js/drivekeys.js';
import { randomBytes, b64urlFromBytes } from '../public/js/bytes.js';
import { sealUpload, newNodeId } from '../public/js/reversekeys.js';

/** The session's CSRF token (43 base64url characters, as the server's HMAC). */
export const FAKE_CSRF = b64urlFromBytes(randomBytes(32));
const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
/** Where the real server checks the token: cookie-authenticated changes (authenticate()) and log-out. */
export const needsCsrf = (method, path) => STATE_CHANGING.has(method) && (path.startsWith('/api/private/') || path === '/api/auth/logout');
/** A request header, from a plain object or a Headers. */
export const headerOf = (headers, name) => {
  if (!headers) return undefined;
  if (typeof headers.get === 'function') return headers.get(name) ?? undefined;
  const k = Object.keys(headers).find((x) => x.toLowerCase() === name);
  return k === undefined ? undefined : headers[k];
};

/** An in-memory Drive server for one user (plus an owner) and a fetch that talks to it. */
export function fakeServer({ role = 'user', enabled = true, capacity = 1 << 30 } = {}) {
  const S = {
    user: { id: role === 'owner' ? 'owner1' : 'u1', role, username: role === 'owner' ? 'owner' : 'alice' },
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
    reverse: [], // reverse shares: the create bodies plus { status, files, bytes, created, expires }
    receivedPage: 500, // received files per page (as the server)
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
    escrowVer: null, // the owner's: { version, kid, created } of the current escrow key
    kit: null, // the owner's latest recovery kit: { version, kid, at }
    escrowKids: [], // the kids users' escrow wraps are made for (drive.escrowKid:*)
    probes: [], // the kit check's live proof: [{ kid, wrap }] (one user's escrow wrap per kid)
    audit: [], // the owner's recovery actions: { action, detail }
    ownerReset: null, // { epoch, kid, signPub, at }: the latest owner start over (public)
    archives: [], // the owner's archived Drives: { gen, at, nodes: Map, wraps, driveSalt, escrowPriv, escrowSignPriv, escrowPrivOld }
    activity: [], // the user's own activity rows the fake records (drive.escrow_rewrapped)
    kcv: null, // the Drive key's check value, kept from the first set-up
    userDrives: {}, // other users' Drives the owner set up here: { [userId]: { wraps, driveSalt, escrowPin, kcv } }
    driveOff: new Set(), // other users whose role has no Drive (the admin keys route answers 409 drive_disabled)
    meCalls: 0, // GET /api/private/me (the page recording its session)
  };
  let clock = 1700000000;
  const tick = () => ++clock;
  /** AUTHN owner recovery: a new password (proof), passkeys and codes (and their wraps) gone, the pw wrap stale. */
  S.authnRecovery = (proof) => {
    for (const k of [...S.wraps.keys()]) if (k.startsWith('passkey|') || k.startsWith('recovery|')) S.wraps.delete(k);
    S.pwStale = true;
    S.proof = proof;
  };
  const stepFail = (body) => {
    if (!body.current && !body.reauth) return fail(400, 'reauth_required');
    if (body.current && body.current !== S.proof) return fail(403, 'wrong_password');
    return null;
  };
  const newVersion = async (pub) => {
    const kid = await escrowKeyId(pub);
    if (S.escrowVer && S.escrowVer.kid === kid) return;
    S.escrowVer = { version: S.escrowVer ? S.escrowVer.version + 1 : 1, kid, created: tick() };
  };
  const sameKey = (a, b) => !!a && !!b && a.x === b.x && a.y === b.y;
  const ok = (data, status = 200) => {
    const res = { ok: status < 400, status, type: 'basic', json: async () => data, arrayBuffer: async () => new ArrayBuffer(0) };
    res.clone = () => res; // api.js reads a 403's body twice (csrf_mismatch or not)
    return res;
  };
  const bin = (bytes) => ({ ok: true, status: 200, type: 'basic', json: async () => null, arrayBuffer: async () => bytes.slice().buffer });
  const fail = (status, error) => ok({ error, message: error }, status);
  // Received files (reverse shares) are not in the tree until the browser re-wraps them.
  const kids = (id) => [...S.nodes.values()].filter((n) => n.parent === id && !n.rs);
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
    // The page records its session (api.js bindSession) from here; not a Drive request.
    if (p === '/api/private/me' && method === 'GET') {
      S.meCalls++;
      return ok({ user: S.user, impersonatedBy: S.impersonatedBy, csrf: FAKE_CSRF });
    }
    S.requests.push({ method, path: p, body, headers: init.headers || {} });
    if (needsCsrf(method, p) && headerOf(init.headers, 'x-secbin-csrf') !== FAKE_CSRF) return fail(403, 'csrf_mismatch');
    let m;
    if (p === '/api/auth/session') return ok({ authenticated: true, user: S.user, impersonatedBy: S.impersonatedBy });
    if (p === '/api/private/drive' && method === 'GET') {
      if (!S.enabled) return ok({ enabled: false });
      const received = [...S.nodes.values()].filter((n) => n.rs && n.state === 'ready' && !n.rfail).length;
      const wraps = [...S.wraps.values()].map((w) => (S.impersonatedBy && w.kind === 'escrow' ? { ...w, data: null } : w));
      return ok({
        enabled: true, capacity: S.capacity, used: used(), driveSalt: S.driveSalt, wraps, escrowPub: S.escrowPub, escrowSignPub: S.escrowSignPub, escrowSig: S.escrowSig,
        escrowPin: S.escrowPin, pwStale: S.pwStale, ownerReset: S.ownerReset, kcv: S.kcv,
        received, receivedFailed: [...S.nodes.values()].filter((n) => n.rs && n.state === 'ready' && n.rfail).length,
        ...(role === 'owner' ? {
          escrowPriv: S.escrowPriv, escrowSignPriv: S.escrowSignPriv, escrowPrivOld: S.escrowPrivOld, escrowKids: S.escrowKids, kit: S.kit,
          archives: S.archives.map((a) => ({ gen: a.gen, at: a.at, items: a.nodes.size, bytes: [...a.nodes.values()].reduce((t, n) => t + n.size, 0), paused: S.reverse.filter((r) => r.agen === a.gen && r.status === 'paused').length })),
          escrowVersion: S.escrowPub ? (S.escrowVer && S.escrowVer.kid === await escrowKeyId(S.escrowPub) ? S.escrowVer : { version: null, kid: await escrowKeyId(S.escrowPub), created: null }) : null,
        } : {}),
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
      const keyless = S.wraps.size === 0 && ([...S.nodes.values()].some((n) => n.parent === 'root') || !!S.kcv || !!S.escrowPriv || !!S.escrowSignPriv);
      const first = S.wraps.size === 0 && !keyless;
      if (body.first === true && !S.impersonatedBy && (S.wraps.size || keyless)) return fail(409, S.wraps.size ? 'drive_exists' : 'drive_keyless');
      const set = body.set || [];
      const remove = body.remove || [];
      const newPw = set.some((w) => w.kind === 'pw');
      const ownerKeys = ['escrowPriv', 'escrowPub', 'escrowSignPriv', 'escrowSignPub', 'escrowSig'].filter((k) => body[k] !== undefined);
      if (ownerKeys.length && role !== 'owner') return fail(403, 'owner_only');
      if (role === 'owner' && set.some((w) => w.kind === 'escrow')) return fail(400, 'escrow_own');
      if (role !== 'owner') {
        if (remove.some((w) => w.kind === 'escrow')) return fail(403, 'escrow_required');
        const escrow = set.find((w) => w.kind === 'escrow');
        if (first && !S.impersonatedBy) {
          if (!S.escrowPub) return fail(409, 'escrow_not_ready');
          if (!escrow || !set.some((w) => OWN.includes(w.kind)) || !body.escrowPin) return fail(400, 'invalid');
        }
        if (escrow && (!S.escrowPub || escrowWrapKeyId(escrow) !== await escrowKeyId(S.escrowPub))) return fail(400, 'invalid');
      }
      if (S.impersonatedBy) {
        if (first || keyless) return fail(403, 'impersonating');
        const addOnly = set.length && set.every((w) => OWN.includes(w.kind) && !has(w.kind, w.ref)) && (!body.driveSalt || (newPw && !has('pw', 'pw'))) && !body.escrowPin && !ownerKeys.length;
        if (remove.length || !addOnly) return fail(403, 'impersonating');
      }
      const signKey = body.escrowSignPub ?? S.escrowSignPub;
      if ((body.escrowPub || body.escrowSignPub || body.escrowSig) && signKey && !(await escrowKeyEndorsed(signKey, body.escrowPub ?? S.escrowPub, body.escrowSig))) return fail(400, 'invalid');
      // The key check value: with the first set-up; after it, with every wrap or pin written (the same value).
      const touches = set.length > 0 || body.escrowPin !== undefined;
      if (first && set.length && !body.kcv) return fail(400, 'kcv_required');
      if (!first && touches) {
        if (!body.kcv) return fail(keyless ? 409 : 400, keyless ? 'drive_keyless' : 'kcv_required');
        if (!S.kcv) return fail(409, keyless ? 'drive_keyless' : 'kcv_missing');
        if (body.kcv !== S.kcv) return fail(409, keyless ? 'drive_keyless' : 'kcv_mismatch');
      }
      const pwExempt = S.pwStale || !has('pw', 'pw');
      // Replacing a wrap that is there (other data; the escrow wrap for the same key) is as a removal.
      const replaces = set.some((w) => {
        const x = S.wraps.get(`${w.kind}|${w.ref}`);
        if (!x || x.data === w.data || w.kind === 'pw') return false;
        return w.kind !== 'escrow' || escrowWrapKeyId(x) === escrowWrapKeyId(w);
      });
      const needs = (ownerKeys.length && (S.escrowPub || S.escrowPriv || S.escrowSignPub || S.escrowSignPriv)) || (keyless && touches)
        || (!first && (remove.some((w) => has(w.kind, w.ref)) || replaces || (newPw && !pwExempt) || (body.driveSalt && S.driveSalt && !(newPw && pwExempt))));
      if (needs && !body.current && !body.reauth) return fail(400, 'reauth_required');
      if (needs && body.current && body.current !== S.proof) return fail(403, 'wrong_password');
      const own = new Set([...S.wraps.values()].filter((w) => OWN.includes(w.kind)).map((w) => `${w.kind}|${w.ref}`));
      for (const w of remove) own.delete(`${w.kind}|${w.ref}`);
      for (const w of set) if (OWN.includes(w.kind)) own.add(`${w.kind}|${w.ref}`);
      if (!first && own.size === 0) return fail(409, 'last_own_wrap');
      if (body.kcv && S.kcv && body.kcv !== S.kcv) return fail(409, 'kcv_mismatch');
      if (first && set.length) S.kcv = body.kcv; // with the first wraps; never replaced
      if (body.driveSalt) S.driveSalt = body.driveSalt;
      for (const w of remove) S.wraps.delete(`${w.kind}|${w.ref}`);
      for (const w of set) S.wraps.set(`${w.kind}|${w.ref}`, w);
      if (newPw) S.pwStale = false;
      if (body.escrowPriv && S.escrowPriv && body.escrowPub && S.escrowPub) S.escrowPrivOld = { ...S.escrowPrivOld, [await escrowKeyId(S.escrowPub)]: S.escrowPriv };
      if (body.escrowPriv && body.escrowPub) await newVersion(body.escrowPub);
      if (body.escrowPriv) S.escrowPriv = body.escrowPriv;
      if (body.escrowPub) S.escrowPub = body.escrowPub;
      if (body.escrowSignPriv) S.escrowSignPriv = body.escrowSignPriv;
      if (body.escrowSignPub) S.escrowSignPub = body.escrowSignPub;
      if (body.escrowSig) S.escrowSig = body.escrowSig;
      if (body.escrowPin) S.escrowPin = body.escrowPin;
      if (body.escrowReset !== undefined) {
        if (role === 'owner' || !S.ownerReset || body.escrowReset !== S.ownerReset.epoch) return fail(400, 'invalid');
        if ((S.resetApplied || 0) >= body.escrowReset) return ok({ ok: true }); // once per epoch
        S.resetApplied = body.escrowReset;
        S.activity.push({ action: 'drive.escrow_rewrapped', detail: `new escrow key ${escrowWrapKeyId(set.find((w) => w.kind === 'escrow'))}` });
        S.audit.push({ action: 'drive.escrow_rewrapped', detail: `user=${S.user.username}` });
      }
      return ok({ ok: true });
    }
    if (p === '/api/private/drive/kit' || p.startsWith('/api/private/drive/kit/') || p === '/api/private/drive/start-over' || p.startsWith('/api/private/drive/archive/')) {
      if (S.impersonatedBy) return fail(403, 'impersonating');
      if (role !== 'owner') return fail(403, 'owner_only');
      const kid = S.escrowPub ? await escrowKeyId(S.escrowPub) : null;
      if (p === '/api/private/drive/kit' && method === 'POST') {
        if (body.event === 'exported') {
          if (!kid) return fail(409, 'no_escrow');
          const f = stepFail(body);
          if (f) return f;
          S.kit = { version: S.escrowVer && S.escrowVer.kid === kid ? S.escrowVer.version : null, kid, at: tick() };
          S.audit.push({ action: 'drive.kit_exported', detail: `version=${S.kit.version}` });
          return ok({ ok: true, kit: S.kit });
        }
        if (body.event === 'used') {
          const f = stepFail(body);
          if (f) return f;
          S.audit.push({ action: 'drive.kit_used', detail: `kit version=${body.version}` });
          return ok({ ok: true });
        }
        if (body.event === 'verified') {
          if (!['complete', 'incomplete', 'failed'].includes(body.verdict)) return fail(400, 'invalid');
          S.audit.push({ action: 'drive.kit_verified', detail: `verdict=${body.verdict} issues=${(body.issues || []).join(',')}` });
          return ok({ ok: true });
        }
        return fail(400, 'invalid');
      }
      if (p === '/api/private/drive/kit/probe' && method === 'POST') {
        S.escrowUses += S.probes.length;
        return ok({ probes: S.probes });
      }
      if (p === '/api/private/drive/kit/keys' && method === 'PUT') {
        if (body.escrowPriv && (!kid || !sameKey(body.escrowPriv.pub, S.escrowPub))) return fail(400, 'key_mismatch');
        if (body.escrowSignPriv && !sameKey(body.escrowSignPriv.pub, S.escrowSignPub)) return fail(400, 'key_mismatch');
        for (const [k, x] of Object.entries(body.escrowPrivOld || {})) {
          if (k === kid || !S.escrowKids.includes(k) || await escrowKeyId(x.pub) !== k) return fail(400, 'key_mismatch');
        }
        const f = stepFail(body);
        if (f) return f;
        if (body.escrowPriv) S.escrowPriv = body.escrowPriv.data;
        if (body.escrowSignPriv) S.escrowSignPriv = body.escrowSignPriv.data;
        for (const [k, x] of Object.entries(body.escrowPrivOld || {})) S.escrowPrivOld = { ...S.escrowPrivOld, [k]: x.data };
        S.audit.push({ action: 'drive.kit_keys_restored', detail: '' });
        return ok({ ok: true });
      }
      if (p === '/api/private/drive/start-over' && method === 'POST') {
        if (body.confirm !== S.user.username) return fail(400, 'confirm_required');
        if ([...S.wraps.values()].some((w) => w.kind === 'passkey' || w.kind === 'recovery' || (w.kind === 'pw' && !S.pwStale))) return fail(409, 'drive_unlockable');
        if (!(await escrowKeyEndorsed(body.escrowSignPub, body.escrowPub, body.escrowSig))) return fail(400, 'invalid');
        const f = stepFail(body);
        if (f) return f;
        // The Drive as it was becomes an archive (chunks untouched); the Drive starts empty.
        const gen = (S.archives.reduce((g, a) => Math.max(g, a.gen), S.archiveGen || 0)) + 1;
        S.archiveGen = gen;
        const nodes = new Map([...S.nodes].filter(([id]) => id !== 'root'));
        S.archives.push({ gen, at: tick(), nodes, wraps: [...S.wraps.values()], driveSalt: S.driveSalt, escrowPriv: S.escrowPriv, escrowSignPriv: S.escrowSignPriv, escrowPrivOld: S.escrowPrivOld });
        for (const id of nodes.keys()) S.nodes.delete(id);
        // As the server: the links' keys are in the archive; the active ones are paused.
        for (const r of S.reverse) {
          if (r.agen === undefined || r.agen === null) r.agen = gen;
          if (r.agen === gen && r.status === 'active') r.status = 'paused';
        }
        S.wraps.clear();
        for (const w of body.set) S.wraps.set(`${w.kind}|${w.ref}`, w);
        S.archives.at(-1).kcv = S.kcv;
        S.kcv = body.kcv;
        Object.assign(S, { driveSalt: body.driveSalt, pwStale: false, escrowPriv: body.escrowPriv, escrowSignPriv: body.escrowSignPriv, escrowPub: body.escrowPub, escrowSignPub: body.escrowSignPub, escrowSig: body.escrowSig, escrowPrivOld: {}, kit: null, escrowPin: null });
        await newVersion(body.escrowPub);
        S.ownerReset = { epoch: (S.ownerReset ? S.ownerReset.epoch : 0) + 1, kid: await escrowKeyId(body.escrowPub), signPub: body.escrowSignPub, at: tick() };
        S.audit.push({ action: 'drive.owner_reset', detail: `version=${S.escrowVer.version} archive ${gen}` });
        return ok({ ok: true, escrowVersion: S.escrowVer, archive: gen, ownerReset: S.ownerReset });
      }
      if ((m = p.match(/^\/api\/private\/drive\/archive\/(\d+)(\/nodes|\/finish)?$/))) {
        const a = S.archives.find((x) => x.gen === Number(m[1]));
        if (!a) return fail(404, 'not_found');
        if (!m[2] && method === 'GET') {
          const after = u.searchParams.get('after') || '';
          const all = [...a.nodes.values()].sort((x, y) => (x.id < y.id ? -1 : 1)).filter((n) => n.id > after);
          const page = all.slice(0, S.archivePage || 500);
          const out = (n) => ({ ...n, name: typeof n.name === 'string' ? JSON.parse(n.name) : n.name, meta: n.meta ? (typeof n.meta === 'string' ? JSON.parse(n.meta) : n.meta) : null, fk: n.fk ? (typeof n.fk === 'string' ? JSON.parse(n.fk) : n.fk) : null });
          const links = after ? {} : { reverse: S.reverse.filter((r) => r.agen === a.gen).map((r) => ({ id: r.id, priv: r.priv, status: r.status })) };
          return ok({ gen: a.gen, at: a.at, escrowPriv: a.escrowPriv, escrowSignPriv: a.escrowSignPriv, escrowPrivOld: a.escrowPrivOld, items: a.nodes.size, nodes: page.map(out), ...links, next: all.length > page.length ? page[page.length - 1].id : null });
        }
        const f = stepFail(body);
        if (!m[2] && method === 'DELETE') {
          if (body.confirm !== S.user.username) return fail(400, 'confirm_required');
          if (f) return f;
          for (const id of a.nodes.keys()) for (const k of [...S.chunks.keys()]) if (k.startsWith(`${id}/`)) S.chunks.delete(k);
          for (const r of S.reverse) if (r.agen === a.gen && r.status === 'paused') { r.status = 'revoked'; S.audit.push({ action: 'reverse.revoked', detail: `id=${r.id} reason=archive_deleted` }); }
          S.archives = S.archives.filter((x) => x !== a);
          S.audit.push({ action: 'drive.archive_deleted', detail: `archive ${a.gen}` });
          return ok({ ok: true });
        }
        if (f) return f;
        if (m[2] === '/nodes' && method === 'PUT') {
          for (const x of body.nodes) {
            const n = a.nodes.get(x.id);
            if (!n) return fail(404, 'not_found');
            if (n.parent !== 'root' && !S.nodes.has(n.parent) && !body.nodes.some((y) => y.id === n.parent)) return fail(409, 'parent_first');
            // A received item comes back as it is (its id only); any other item needs its name re-sealed.
            if (n.rs ? (x.name !== undefined || x.meta !== undefined || x.fk !== undefined) : x.name === undefined) return fail(400, n.rs ? 'received_as_is' : 'invalid');
          }
          for (const x of body.nodes) {
            const n = a.nodes.get(x.id);
            if (n.rs) { S.nodes.set(x.id, { ...n }); a.nodes.delete(x.id); continue; }
            S.nodes.set(x.id, { ...n, name: JSON.stringify(x.name), ...(x.meta !== undefined ? { meta: JSON.stringify(x.meta) } : {}), ...(x.fk !== undefined ? { fk: JSON.stringify(x.fk) } : {}) });
            a.nodes.delete(x.id);
          }
          return ok({ ok: true, restored: body.nodes.length, left: a.nodes.size });
        }
        if (m[2] === '/finish' && method === 'POST') {
          if (a.nodes.size) return fail(409, 'archive_not_empty');
          for (const [k, x] of Object.entries(body.escrowPrivOld || {})) {
            if (k === kid || !S.escrowKids.includes(k) || await escrowKeyId(x.pub) !== k) return fail(400, 'key_mismatch');
          }
          const links = S.reverse.filter((r) => r.agen === a.gen);
          const given = body.reverse || {};
          if (Object.keys(given).length !== links.length || links.some((r) => !given[r.id])) return fail(409, 'reverse_keys_required');
          for (const [k, x] of Object.entries(body.escrowPrivOld || {})) S.escrowPrivOld = { ...S.escrowPrivOld, [k]: x.data };
          for (const r of links) {
            Object.assign(r, { priv: given[r.id], agen: null });
            if (r.status === 'paused') { r.status = 'active'; S.audit.push({ action: 'reverse.resumed', detail: `id=${r.id}` }); }
          }
          S.archives = S.archives.filter((x) => x !== a);
          S.audit.push({ action: 'drive.archive_restored', detail: `archive ${a.gen}` });
          return ok({ ok: true });
        }
        return fail(405, 'method');
      }
      return fail(404, 'not_found');
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
    if (p === '/api/private/drive/reverse' && method === 'POST') {
      if (!/^r[A-Za-z0-9_-]{22}$/.test(body.id) || S.reverse.some((r) => r.id === body.id)) return fail(409, 'exists');
      const now = Math.floor(Date.now() / 1000);
      S.reverse.push({ ...body, status: 'active', files: 0, bytes: 0, created: now, expires: now + 7 * 86400 });
      return ok({ id: body.id, expires: now + 7 * 86400 }, 201);
    }
    if (p === '/api/private/drive/reverse' && method === 'GET') {
      const folder = u.searchParams.get('folder');
      const rows = S.reverse.filter((r) => !folder || r.folder === folder).map((r) => ({
        id: r.id, folder: r.folder, label: r.label || '', created: r.created, expires: r.expires, status: r.status, locked: false, priv: r.priv,
        password: !!r.password, note: !!r.note, captcha: r.captcha === true, maxFiles: r.maxFiles ?? null, maxBytes: r.maxBytes ?? null, maxFileBytes: r.maxFileBytes ?? null, types: r.types ?? null, files: r.files, bytes: r.bytes,
      }));
      return ok({ reverse: rows });
    }
    if (p === '/api/private/drive/received' && method === 'GET') {
      // As the server: oldest first, pages of S.receivedPage with a cursor; `failed=1` lists the failed ones.
      const failed = u.searchParams.get('failed') === '1';
      const after = u.searchParams.get('after');
      const archivedKey = (n) => S.reverse.some((r) => r.id === n.rs && r.agen !== undefined && r.agen !== null);
      const all = [...S.nodes.values()].filter((n) => n.rs && n.state === 'ready' && !!n.rfail === failed && !archivedKey(n))
        .sort((a, b) => a.created - b.created || (a.id < b.id ? -1 : 1));
      const from = after ? all.findIndex((n) => `${n.created}.${n.id}` === after) + 1 : 0;
      const page = all.slice(from, from + S.receivedPage);
      const more = from + page.length < all.length;
      const next = more ? `${page[page.length - 1].created}.${page[page.length - 1].id}` : null;
      if (failed) {
        return ok({ items: page.map((n) => ({ id: n.id, rs: n.rs, label: S.reverse.find((r) => r.id === n.rs)?.label || '', size: n.size, created: n.created, failed: n.rfail, reason: n.rwhy })), more, next });
      }
      const items = page.map((n) => ({ id: n.id, parent: n.parent, rs: n.rs, name: n.name, meta: n.meta, fk: n.fk, size: n.size, chunks: n.chunks, created: n.created }));
      const keys = [...new Set(items.map((i) => i.rs))].map((id) => S.reverse.find((r) => r.id === id)).filter(Boolean).map((r) => ({ id: r.id, priv: r.priv }));
      return ok({ items, keys, more, next });
    }
    if ((m = p.match(/^\/api\/private\/drive\/received\/([^/]+)\/failed$/))) {
      const n = S.nodes.get(m[1]);
      if (!n || !n.rs) return fail(409, 'not_received');
      if (method === 'POST') Object.assign(n, { rfail: 1700000500, rwhy: body.reason });
      else Object.assign(n, { rfail: null, rwhy: null });
      return ok({ ok: true });
    }
    if ((m = p.match(/^\/api\/private\/drive\/received\/([^/]+)$/)) && method === 'POST') {
      const n = S.nodes.get(m[1]);
      if (!n || !n.rs) return fail(409, 'not_received');
      if (!S.nodes.has(body.parent) || S.nodes.get(body.parent).kind !== 'dir') return fail(404, 'not_found');
      Object.assign(n, { parent: body.parent, name: body.name, meta: body.meta, fk: body.fk, rs: null, rfail: null });
      S.accepted = (S.accepted || []).concat([{ id: n.id, body }]);
      return ok({ ok: true });
    }
    if ((m = p.match(/^\/api\/private\/shares\/([^/]+)\/revoke$/)) && method === 'POST') {
      const rv = S.reverse.find((x) => x.id === m[1]);
      if (rv) { rv.status = 'revoked'; S.revoked.push(rv.id); return ok({ ok: true }); }
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
      return ok({ wrap: wraps.find((w) => w.kind === 'escrow') || null, wraps: wraps.length });
    }
    if ((m = p.match(/^\/api\/private\/admin\/drive\/keys\/([^/]+)$/))) {
      // The owner, for another user: a pw wrap after a reset (the key check value
      // must be the Drive's), or the first set-up of a Drive that has no wrap.
      S.adminKeys.push({ userId: m[1], body });
      if (S.driveOff.has(m[1])) return fail(409, 'drive_disabled');
      const d = S.userDrives[m[1]];
      if (!body.kcv) return fail(400, 'kcv_required');
      if (body.first) {
        if (d && d.wraps.length) return fail(409, 'drive_exists');
        if (!S.escrowPub) return fail(409, 'escrow_not_ready');
        const kinds = (body.set || []).map((w) => w.kind).sort().join();
        if (kinds !== 'escrow,pw' || escrowWrapKeyId(body.set.find((w) => w.kind === 'escrow')) !== await escrowKeyId(S.escrowPub) || !body.escrowPin) return fail(400, 'invalid');
        S.userDrives[m[1]] = { wraps: body.set, driveSalt: body.driveSalt, escrowPin: body.escrowPin, kcv: body.kcv };
        S.audit.push({ action: 'drive.created_by_owner', detail: m[1] });
        return ok({ ok: true, created: true });
      }
      if (d && !d.kcv) return fail(409, 'kcv_missing');
      if (d && d.kcv !== body.kcv) return fail(409, 'kcv_mismatch');
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
  // A real Drive has its key check value from its first set-up (the browser proves a tab key against it).
  if (!S.kcv) S.kcv = await keyCheckValue(dk);
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

/**
 * A file received through reverse share `rid` (public key `pub`), stored as
 * the uploader's browser would have sent it: content under a fresh file key,
 * path and metadata sealed with a metadata key, both wrapped to `pub`.
 * `bad: true` stores a wrap that does not open. → the node id.
 */
export async function seedReceived(S, { rid, pub, folder = 'root', path, bytes, type = 'text/plain', bad = false }) {
  const id = newNodeId();
  const fk = randomBytes(32);
  const n = Math.ceil(bytes.length / CHUNK);
  const key = await importFileKey(b64urlFromBytes(fk));
  for (let i = 0; i < n; i++) S.chunks.set(`${id}/${i}`, await encryptChunk(key, i, n, bytes.slice(i * CHUNK, (i + 1) * CHUNK)));
  const sealed = await sealUpload(pub, bad ? `r${'A'.repeat(22)}` : rid, id, fk, { path, type, mtime: 1700000000000, size: bytes.length });
  S.nodes.set(id, {
    id, parent: folder, kind: 'file', name: sealed.name, meta: sealed.meta, fk: { kind: 'rs', data: sealed.wrap },
    size: bytes.length, chunks: n, state: 'ready', created: 1700000000, updated: 1700000000, rs: rid,
  });
  return id;
}
