// drive-fake-server.js — an in-memory stand-in for the Drive API (docs/DRIVE.md
// §6) behind a mocked fetch, shared by the DOM suites of the Drive client
// (driveclient.test.js), the Drive page (drive.test.js), reverse shares
// (reverse.test.js), the kits and the keyring pages. It keeps what the real
// server would and follows its key rules (the key model v2, docs/DRIVE.md
// §3; src/routes/drive.js, src/lib/mek.js): it holds the root MEK and the
// sub-MEKs and derives the user's KEKs (drivekeys.js deriveKek, the real
// derivation) for POST /api/private/drive/keys; every item sealed by the
// browser must open under the current KEK (409 mek_not_current for another
// sub-MEK, 400 bad_seal otherwise); a rename is sealed under the item's own
// sub-MEK and salt (409 stale_keys when they changed); the personal kit's
// routes need the step-up and are refused while the owner acts as the user
// (`impersonatedBy`), and a restore from one is refused to everyone there
// (403 owner_only); the key kit, a restore from a user's personal kit and
// the keyring routes of Admin → Security → Keys are the owner's. Like the real server (src/lib/csrf.js), every
// signed-in change (POST / PUT / PATCH / DELETE under /api/private/, and
// log-out) must carry the session's CSRF token in X-Secbin-CSRF, the one GET
// /api/private/me hands out (403 csrf_mismatch otherwise, before anything
// changes): the Drive client sends it through public/js/api.js. Every fake
// server stands for the same browser session, so they share the token
// (FAKE_CSRF). Not a test file itself (vitest.dom.config.js picks up *.test.js
// only).
import { vi } from 'vitest';
import { CHUNK, TAG, encryptChunk, decryptChunk, importFileKey } from '../public/js/files.js';
import {
  deriveKek, newKey, newSalt, newMekId, sealName, sealDek, openName, openDek, openLinkKey, keyFingerprint, keyCheckValue, saltCheckValue,
  sameCheck, effectiveAt, mekStatus,
} from '../public/js/drivekeys.js';
import { randomBytes, b64urlFromBytes, bytesFromB64url, utf8 } from '../public/js/bytes.js';
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
    user: { id: role === 'owner' ? 'owner1ownerowner' : 'u1useruseruser01', role, username: role === 'owner' ? 'owner' : 'alice' },
    enabled,
    capacity,
    // The keyring (the server's): the root MEK, the sub-MEKs, this account's salt.
    root: newKey(),
    subs: [],
    salt: newSalt(),
    keysError: null, // 'keys_missing' | 'salt_missing': POST /drive/keys refuses
    nodes: new Map([['root', { id: 'root', parent: null, kind: 'dir', name: '', size: 0, chunks: 0, state: 'ready', created: 1, updated: 1 }]]),
    chunks: new Map(),
    shareBodies: [],
    shares: [], // { id, nodes, label, created, expires, views_total, left, status }
    revoked: [],
    requests: [],
    reverse: [], // reverse shares: the create bodies plus { status, files, bytes, created, expires }
    receivedPage: 500, // received files per page (as the server)
    impersonatedBy: null, // the owner's username while the owner acts as this user
    busyFinalize: 0, // answer finalize "busy" this many times
    proof: null, // the password proof the step-up accepts (confirm.js stretches the password)
    migration: null, // what GET /api/private/drive says of the upgrade (null: nothing to upgrade)
    audit: [], // the owner's key actions: { action, detail }
    activity: [], // the user's own activity rows the fake records
    kitRecord: null, // the key kit's record (at, root, subs, v)
    kitVerifyLeft: 30,
    keyVersion: { n: 0, at: null }, // the keyring's version (docs/DRIVE.md §3.1): up by one on every key change here
    userKit: null, // the user's last personal-kit download: { at, v, meks }
    meCalls: 0, // GET /api/private/me (the page recording its session)
    // Refusals the real server makes and this fake does not decide itself (the role's file policy, a quota):
    // { method, path: RegExp, status, error, message, extra } — the first match answers instead.
    refusals: [],
  };
  let clock = 1700000000;
  const tick = () => ++clock;
  const now = () => Math.floor(Date.now() / 1000);
  /** A sub-MEK: { id, key, fp, from, until, created, note }. */
  S.addSub = async ({ from = now() - 3600, until = null, key = newKey(), note = '' } = {}) => {
    const s = { id: newMekId(), key, fp: await keyFingerprint(key), from, until, created: tick(), note };
    const open = S.subs.find((x) => x.until === null);
    if (open && until === null) open.until = from;
    S.subs.push(s);
    S.bumpKeys();
    return s;
  };
  /** A key change: the keyring's version goes up (as the Directory's #bumpKeyVersion). */
  S.bumpKeys = () => { S.keyVersion = { n: S.keyVersion.n + 1, at: now() }; };
  /** The personal kit's state, as the Directory's #userKitState. */
  S.kitState = () => {
    const last = S.userKit ? { at: S.userKit.at, version: S.userKit.v } : null;
    const cur = S.current()?.id ?? null;
    return { version: S.keyVersion.n, versionAt: S.keyVersion.at, last, stale: !!last && (last.version < S.keyVersion.n || (!!cur && !S.userKit.meks.includes(cur))) };
  };
  S.current = () => effectiveAt(S.subs, now());
  S.kekOf = async (mekId, uid = S.user.id, salt = S.salt) => {
    const s = S.subs.find((x) => x.id === mekId);
    return s ? deriveKek(S.root, s.key, salt, uid) : null;
  };
  S.ready = S.addSub({ from: now() - 86400 });

  const stepFail = (body) => {
    if (!body.current && !body.reauth) return fail(400, 'reauth_required');
    if (body.current && S.proof && body.current !== S.proof) return fail(403, 'wrong_password');
    return null;
  };
  const ok = (data, status = 200) => {
    const res = { ok: status < 400, status, type: 'basic', json: async () => data, arrayBuffer: async () => new ArrayBuffer(0) };
    res.clone = () => res; // api.js reads a 403's body twice (csrf_mismatch or not)
    return res;
  };
  const bin = (bytes) => ({ ok: true, status: 200, type: 'basic', json: async () => null, arrayBuffer: async () => bytes.slice().buffer });
  const fail = (status, error) => ok({ error, message: error }, status);
  // Received files (reverse shares) are not in the tree until the browser takes them in.
  const kids = (id) => [...S.nodes.values()].filter((n) => n.parent === id && !n.rs);
  const ancestors = (n) => { const out = []; let p = n.parent; while (p) { const a = S.nodes.get(p); out.unshift(a); p = a.parent; } return out; };
  const within = (id, anc) => { for (let x = S.nodes.get(id); x; x = S.nodes.get(x.parent)) if (x.id === anc) return true; return false; };
  const pub = (n) => ({ ...n });
  const used = () => [...S.nodes.values()].reduce((s, n) => s + n.size, 0);
  const shareRow = ({ nodes, ...row }) => { void nodes; return { ...row, kind: 'drive', locked: 0 }; };
  const parsed = (v) => (typeof v === 'string' ? JSON.parse(v) : v);
  /** As src/lib/mek.js checkNewItem: under the current KEK, or refused. */
  const checkSeal = async ({ kind, ks, mek, name, meta, dek }) => {
    const cur = S.current();
    if (!cur || mek !== cur.id) return fail(409, 'mek_not_current');
    if (typeof ks !== 'string' || !name) return fail(400, 'invalid');
    const kek = await S.kekOf(mek);
    const at = { userId: S.user.id, mekId: mek, salt: ks };
    try {
      await openName(kek, at, 'name', parsed(name));
      if (meta) await openName(kek, at, 'meta', parsed(meta));
      if (kind === 'file') await openDek(kek, at, parsed(dek));
    } catch {
      return fail(400, 'bad_seal');
    }
    return null;
  };
  const keysOut = async () => {
    const cur = S.current();
    const inUse = new Set([...S.nodes.values()].map((n) => n.mek).filter(Boolean));
    const list = S.subs.filter((s) => s.id === cur?.id || inUse.has(s.id));
    return {
      userId: S.user.id, current: cur ? cur.id : null, changing: false,
      keys: await Promise.all(list.map(async (s) => ({ mekId: s.id, fp: s.fp, from: s.from, until: s.until, kek: b64urlFromBytes(await S.kekOf(s.id)) }))),
      missing: [], broken: [],
    };
  };

  S.fetch = vi.fn(async (url, init = {}) => {
    await S.ready;
    const method = init.method || 'GET';
    const u = new URL(url, 'https://bin.example');
    const p = u.pathname;
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : init.body;
    // The page records its session (api.js bindSession) from here; not a Drive request.
    if (p === '/api/private/me' && method === 'GET') {
      S.meCalls++;
      return ok({ user: S.user, impersonatedBy: S.impersonatedBy, csrf: FAKE_CSRF });
    }
    // The public config (the CAPTCHA's site key when `S.turnstile` is set): not a Drive request.
    if (p === '/api/config' && method === 'GET') return ok({ turnstile: S.turnstile || null });
    S.requests.push({ method, path: p, body, headers: init.headers || {} });
    if (needsCsrf(method, p) && headerOf(init.headers, 'x-secbin-csrf') !== FAKE_CSRF) return fail(403, 'csrf_mismatch');
    const refusal = S.refusals.find((r) => r.method === method && r.path.test(p));
    if (refusal) return ok({ error: refusal.error, message: refusal.message, ...(refusal.extra || {}) }, refusal.status);
    let m;
    if (p === '/api/auth/session') return ok({ authenticated: true, user: S.user, impersonatedBy: S.impersonatedBy });
    if (p === '/api/auth/prelogin' && method === 'POST') return ok({ salt: 'AAAAAAAAAAAAAAAAAAAAAA', t: 3 });
    if (p === '/api/private/drive' && method === 'GET') {
      if (!S.enabled) return ok({ enabled: false });
      const received = [...S.nodes.values()].filter((n) => n.rs && n.state === 'ready' && !n.rfail).length;
      return ok({
        enabled: true, capacity: S.capacity, used: used(), current: S.current()?.id ?? null, migration: S.migration, kit: S.kitState(),
        received, receivedFailed: [...S.nodes.values()].filter((n) => n.rs && n.state === 'ready' && n.rfail).length,
      });
    }
    if (!S.enabled && p.startsWith('/api/private/drive/')) return fail(403, 'drive_disabled');
    if (p === '/api/private/drive/keys' && method === 'POST') {
      if (S.keysError) return fail(S.keysError === 'keys_missing' ? 503 : 409, S.keysError);
      if (S.impersonatedBy) S.audit.push({ action: 'drive.keys_used', detail: S.user.id });
      return ok(await keysOut());
    }
    // ── the personal kit ─────────────────────────────────────────────────
    // A restore from one is the owner's (Admin → Security → Keys), never the user's.
    if (p === '/api/private/drive/kit/restore' || p === '/api/private/drive/kit/items') return fail(403, 'owner_only');
    if (p === '/api/private/drive/kit' || p.startsWith('/api/private/drive/kit/')) {
      if (S.impersonatedBy) return fail(403, 'impersonating');
      if (p === '/api/private/drive/kit' && method === 'GET') return ok(S.kitState());
      if (p === '/api/private/drive/kit' && method === 'POST') {
        if (S.turnstile && !headerOf(init.headers, 'x-secbin-turnstile')) return fail(403, 'turnstile_required');
        const f = stepFail(body);
        if (f) return f;
        const k = await keysOut();
        S.activity.push({ action: 'drive.kit_exported', detail: `sub-MEKs: ${k.keys.length}` });
        S.userKit = { at: now(), v: S.keyVersion.n, meks: k.keys.map((x) => x.mekId) };
        return ok({ kit: { id: S.user.id, username: S.user.username, userSalt: S.salt, current: k.current, keyVersion: S.keyVersion.n, keks: k.keys }, missing: [], broken: [], status: S.kitState() });
      }
      if (p === '/api/private/drive/kit/verify' && method === 'POST') {
        if (S.turnstile && !headerOf(init.headers, 'x-secbin-turnstile')) return fail(403, 'turnstile_required');
        if (S.kitVerifyLeft-- <= 0) return fail(429, 'rate_limited');
        const inUse = new Set([...S.nodes.values()].map((n) => n.mek).filter(Boolean));
        const cur = S.current();
        const keks = await Promise.all(S.subs.map(async (s) => {
          const g = body.keks && typeof body.keks[s.id] === 'string' ? body.keks[s.id] : null;
          const result = g === null ? 'absent' : sameCheck(g, await keyCheckValue(await S.kekOf(s.id), 'kek')) ? 'match' : 'mismatch';
          return { mekId: s.id, fp: s.fp, from: s.from, until: s.until, inUse: inUse.has(s.id), current: s.id === cur?.id, result };
        }));
        const salt = typeof body.salt === 'string' ? (sameCheck(body.salt, await saltCheckValue(S.salt, S.user.id)) ? 'match' : 'mismatch') : 'absent';
        S.activity.push({ action: 'drive.kit_verified', detail: salt });
        return ok({ complete: salt === 'match' && keks.filter((x) => x.inUse || x.current).every((x) => x.result === 'match'), salt, keks, extra: [], version: S.keyVersion.n, now: now() });
      }
      return fail(404, 'not_found');
    }
    // ── the upgrade of a Drive made before the key model v2 ──────────────
    if (p === '/api/private/drive/migrate' && method === 'GET') {
      return ok(S.legacyState || { state: null, v1Items: 0, v1Links: 0, archived: 0, legacy: false, kcv: null, driveSalt: null, wraps: [] });
    }
    if (p === '/api/private/drive/migrate/items' && method === 'GET') return ok(S.legacyItems || { items: [], links: [], next: null });
    if ((m = p.match(/^\/api\/private\/drive\/nodes\/([^/]+)$/))) {
      const n = S.nodes.get(m[1]);
      if (!n) return fail(404, 'not_found');
      if (method === 'GET') return ok({ node: pub(n), children: kids(n.id).map(pub), path: ancestors(n).map(pub) });
      if (method === 'PATCH') {
        if (body.parent && (body.parent === n.id || within(body.parent, n.id))) return fail(409, 'cycle');
        if (body.name) {
          if (body.ks !== n.ks || body.mek !== n.mek) return fail(409, 'stale_keys');
          try { await openName(await S.kekOf(n.mek), { userId: S.user.id, mekId: n.mek, salt: n.ks }, 'name', parsed(body.name)); } catch { return fail(400, 'bad_seal'); }
          n.name = body.name;
        }
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
      if (body.mek !== S.current()?.id) return fail(409, 'mek_not_current');
      try { await openLinkKey(await S.kekOf(body.mek), { userId: S.user.id, mekId: body.mek, linkId: body.id }, body.priv); } catch { return fail(400, 'bad_seal'); }
      const t = Math.floor(Date.now() / 1000);
      // "never": no expiry (the API says null); views as sent (none: unlimited), none used yet.
      const expires = body.expire === 'never' ? null : t + 7 * 86400;
      S.reverse.push({ ...body, status: 'active', files: 0, bytes: 0, created: t, expires, views: body.views ?? null, used: 0, accept: body.accept ?? ['files'] });
      return ok({ id: body.id, expires, views: body.views ?? null, accept: body.accept ?? ['files'] }, 201);
    }
    if (p === '/api/private/drive/reverse' && method === 'GET') {
      const folder = u.searchParams.get('folder');
      const rows = S.reverse.filter((r) => !folder || r.folder === folder).map((r) => ({
        id: r.id, folder: r.folder, label: r.label || '', created: r.created, expires: r.expires, status: r.status, locked: false, priv: r.priv, mek: r.mek ?? null,
        password: !!r.password, note: !!r.note, captcha: r.captcha === true, maxFiles: r.maxFiles ?? null, maxBytes: r.maxBytes ?? null, maxFileBytes: r.maxFileBytes ?? null, types: r.types ?? null, files: r.files, bytes: r.bytes,
        views: r.views ?? null, used: r.used ?? 0, left: r.views === null || r.views === undefined ? null : Math.max(0, r.views - (r.used ?? 0)),
        accept: r.accept ?? ['files'], held: r.held === true,
        // Uploads in progress (the server's #uploading): reserved, not finished.
        uploading: r.uploading ?? { files: 0, bytes: 0, size: 0, held: 0, since: null },
      }));
      return ok({ reverse: rows });
    }
    if (p === '/api/private/drive/received' && method === 'GET') {
      // As the server: oldest first, pages of S.receivedPage with a cursor; `failed=1` lists the failed ones.
      const failed = u.searchParams.get('failed') === '1';
      const after = u.searchParams.get('after');
      const all = [...S.nodes.values()].filter((n) => n.rs && n.state === 'ready' && !!n.rfail === failed)
        .sort((a, b) => a.created - b.created || (a.id < b.id ? -1 : 1));
      const from = after ? all.findIndex((n) => `${n.created}.${n.id}` === after) + 1 : 0;
      const page = all.slice(from, from + S.receivedPage);
      const more = from + page.length < all.length;
      const next = more ? `${page[page.length - 1].created}.${page[page.length - 1].id}` : null;
      if (failed) {
        return ok({ items: page.map((n) => ({ id: n.id, rs: n.rs, label: S.reverse.find((r) => r.id === n.rs)?.label || '', size: n.size, created: n.created, failed: n.rfail, reason: n.rwhy })), more, next });
      }
      // `declared`: the kind the item's session declared (sealed with its wrap on the server); each
      // link's `accept` as the user's role allows it now (S.roleKinds, as the server filters it).
      // `unsealed`: a field the server found in plain text at rest (no fields, no declared kind).
      const items = page.map((n) => (n.unsealed ? { id: n.id, parent: n.parent, rs: n.rs, name: null, meta: null, fk: null, size: n.size, chunks: n.chunks, created: n.created, declared: null, unreadable: true, unsealed: true }
        : { id: n.id, parent: n.parent, rs: n.rs, name: n.name, meta: n.meta, fk: n.fk, size: n.size, chunks: n.chunks, created: n.created, declared: n.declared ?? null }));
      const roleKinds = S.roleKinds || ['files', 'note', 'url', 'secret'];
      const keys = [...new Set(items.map((i) => i.rs))].map((id) => S.reverse.find((r) => r.id === id)).filter(Boolean)
        .map((r) => ({ id: r.id, priv: r.priv, mek: r.mek ?? null, types: r.types ?? null, maxFileBytes: r.maxFileBytes ?? null, accept: (r.accept ?? ['files']).filter((k) => roleKinds.includes(k)) }));
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
      const f = await checkSeal({ kind: 'file', ...body });
      if (f) return f;
      const n = S.nodes.get(m[1]);
      if (!n || !n.rs) return fail(409, 'not_received');
      if (!S.nodes.has(body.parent) || S.nodes.get(body.parent).kind !== 'dir') return fail(404, 'not_found');
      Object.assign(n, { parent: body.parent, name: body.name, meta: body.meta, dek: body.dek, ks: body.ks, mek: body.mek, fk: undefined, rs: null, rfail: null });
      S.accepted = (S.accepted || []).concat([{ id: n.id, body }]);
      return ok({ ok: true });
    }
    if ((m = p.match(/^\/api\/private\/shares\/([^/]+)$/)) && method === 'PATCH') {
      // A reverse share's change (src/routes/reverse.js changeReverse): recorded as sent, applied to the row.
      const rv = S.reverse.find((x) => x.id === m[1]);
      if (!rv) return fail(404, 'not_found');
      S.patches = (S.patches || []).concat([{ id: rv.id, body }]);
      for (const k of ['label', 'expires', 'views', 'maxFiles', 'maxBytes', 'maxFileBytes', 'types', 'captcha', 'password', 'note', 'accept', 'folder']) if (body[k] !== undefined) rv[k] = body[k];
      return ok({ ok: true, expires: rv.expires, views: rv.views ?? null, folder: rv.folder });
    }
    if ((m = p.match(/^\/api\/private\/receive\/([^/]+)\/(pause|resume)$/)) && method === 'POST') {
      // Pause / resume a Receive link (src/routes/reverse.js pauseReverse): recorded, applied to the row.
      const rv = S.reverse.find((x) => x.id === m[1]);
      if (!rv) return fail(404, 'not_found');
      const on = m[2] === 'pause';
      S.pauses = (S.pauses || []).concat([{ id: rv.id, on, intent: headerOf(init.headers, 'x-secbin-intent') ?? null, ...(on ? {} : { body: body ?? null }) }]);
      Object.assign(rv, on ? { status: 'paused', held: true } : { status: 'active', held: false });
      return ok({ ok: true, paused: on });
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
      const f = await checkSeal({ kind: 'dir', ...body });
      if (f) return f;
      S.nodes.set(body.id, { id: body.id, parent: body.parent, kind: 'dir', name: body.name, ks: body.ks, mek: body.mek, size: 0, chunks: 0, state: 'ready', created: 2, updated: 2 });
      return ok({ id: body.id });
    }
    if (p === '/api/private/drive/files' && method === 'POST') {
      if (!/^[A-Za-z0-9_-]{22}$/.test(body.id) || S.nodes.has(body.id)) return fail(409, 'bad_id');
      const f = await checkSeal({ kind: 'file', ...body });
      if (f) return f;
      if (used() + body.size > S.capacity) return fail(413, 'drive_full');
      const chunks = Math.ceil(body.size / CHUNK);
      S.nodes.set(body.id, { id: body.id, parent: body.parent, kind: 'file', name: body.name, meta: body.meta, dek: body.dek, ks: body.ks, mek: body.mek, size: body.size, chunks, state: 'pending', created: 3, updated: 3 });
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
      return ok({ ok: true, ch: 'x'.repeat(43) });
    }
    if (p === '/api/private/drive/shares' && method === 'POST') {
      S.shareBodies.push(body);
      const id = `fSHARE${S.shareBodies.length}`;
      const t = Math.floor(Date.now() / 1000);
      S.shares.push({ id, nodes: [...body.nodes], label: body.label || '', created: t, expires: t + 86400, views_total: body.views, left: body.views, status: 'active' });
      return ok({ id, deletetoken: `dt${S.shareBodies.length}` });
    }
    // ── Admin → Security → Keys (the owner's) ──────────────────────────────
    if (p.startsWith('/api/private/admin/keys')) return keysRoute(method, p, body);
    if (p === '/api/private/admin/users' && method === 'GET') return ok({ users: [S.user, ...(S.otherUsers || [])] });
    if (p === '/api/private/admin/drive/migration' && method === 'GET') return ok({ drives: S.migrationDrives || [], left: (S.migrationDrives || []).filter((d) => d.state !== 'done').length, legacyEscrow: false });
    // The owner's archive of the release before (S.archive: { items, bytes, received, links }).
    if (p === '/api/private/admin/drive/archive') {
      if (method === 'GET') return ok({ ok: true, items: 0, bytes: 0, received: 0, links: [], ...(S.archive || {}) });
      const f = stepFail(body || {});
      if (f) return f;
      if (body.confirm !== S.user.username) return fail(400, 'confirm');
      const a = S.archive || { items: 0, links: [] };
      S.archive = null;
      S.audit.push({ action: 'drive.archive_deleted', detail: `items=${a.items}` });
      return ok({ ok: true, items: a.items, bytes: a.bytes || 0, links: a.links.length });
    }
    return fail(404, `unrouted ${method} ${p}`);
  });

  // The keyring routes, as src/routes/keys.js answers them (the parts the pages use).
  S.candidates = new Map();
  S.job = null;
  const status = async () => {
    const t = now();
    return {
      ok: true, ready: true, lost: false, root: { fp: await keyFingerprint(S.root), created: 1700000000, changing: !!S.rootOld, oldFp: S.rootOld ? await keyFingerprint(S.rootOld) : null, oldOrigin: S.rootOld ? (S.rootOldOrigin || 'changed') : null, check: S.rootOld ? (S.rootCheck || null) : null },
      subs: S.subs.map((s) => ({ id: s.id, fp: s.fp, from: s.from, until: s.until, created: s.created, note: s.note, status: mekStatus(S.subs, s, t), opens: true })),
      current: S.current()?.id ?? null, job: S.job, kit: S.kitRecord, kitFresh: !!S.kitRecord && S.kitRecord.subs === S.subs.length, version: S.keyVersion, users: 2, now: t,
    };
  };
  async function keysRoute(method, p, body) {
    if (role !== 'owner' || S.impersonatedBy) return fail(403, S.impersonatedBy ? 'impersonating' : 'owner_only');
    let m;
    if (p === '/api/private/admin/keys' && method === 'GET') return ok(await status());
    if (p === '/api/private/admin/keys/usage') {
      const counts = {};
      for (const n of S.nodes.values()) if (n.mek) counts[n.mek] = (counts[n.mek] || 0) + 1;
      return ok({ ok: true, counts, v1: 0, drives: 1 });
    }
    if (p === '/api/private/admin/keys/jobs/step') {
      if (S.job && !S.job.finished && S.job.kind === 'root') {
        S.rootOld = null;
        Object.assign(S.job, { finished: true, result: { ok: true, message: 'Every item is re-sealed under the new root MEK and was checked; the old one was removed.' } });
      }
      if (S.job && !S.job.finished) {
        const from = S.job.from;
        const cur = S.current();
        for (const n of S.nodes.values()) {
          if (n.mek !== from || !cur) continue;
          const kek = await S.kekOf(from);
          const at = { userId: S.user.id, mekId: from, salt: n.ks };
          const name = await openName(kek, at, 'name', parsed(n.name));
          const meta = n.meta ? await openName(kek, at, 'meta', parsed(n.meta)) : null;
          const dek = n.kind === 'file' ? await openDek(kek, at, parsed(n.dek)) : null;
          const ks = newSalt();
          const kek2 = await S.kekOf(cur.id);
          const at2 = { userId: S.user.id, mekId: cur.id, salt: ks };
          Object.assign(n, { ks, mek: cur.id, name: await sealName(kek2, at2, 'name', name), ...(meta ? { meta: await sealName(kek2, at2, 'meta', meta) } : {}), ...(dek ? { dek: await sealDek(kek2, at2, dek) } : {}) });
          S.job.done++;
        }
        if (S.job.remove) { S.subs = S.subs.filter((s) => s.id !== from); S.bumpKeys(); }
        Object.assign(S.job, { finished: true, drive: 1, drives: 1, result: { ok: true, message: `Nothing is sealed under ${from} any more.` } });
      }
      return ok({ job: S.job });
    }
    if (p === '/api/private/admin/keys/verify') {
      // Check values only, compared here (read-only).
      const t = now();
      const subs = await Promise.all(S.subs.map(async (x) => ({ id: x.id, fp: x.fp, from: x.from, until: x.until, status: mekStatus(S.subs, x, t),
        result: typeof body.subs?.[x.id] === 'string' ? (sameCheck(body.subs[x.id], await keyCheckValue(x.key, 'mek')) ? 'match' : 'mismatch') : 'absent' })));
      const root = typeof body.root === 'string' ? (sameCheck(body.root, await keyCheckValue(S.root, 'mek')) ? 'match' : 'mismatch') : 'absent';
      const given = body.salts?.[S.user.id];
      const salts = { total: 1, match: 0, mismatch: 0, absent: 0, extra: 0 };
      if (typeof given !== 'string') salts.absent++; else if (sameCheck(given, await saltCheckValue(S.salt, S.user.id))) salts.match++; else salts.mismatch++;
      S.verifyBodies = (S.verifyBodies || []).concat([body]);
      return ok({ ok: true, complete: root === 'match' && subs.every((x) => x.result === 'match') && salts.match === 1, now: t, version: S.keyVersion, root, subs, salts, extraSubs: [] });
    }
    if (p === '/api/private/admin/keys/export/verify') {
      // As src/routes/keys.js keysVerify: the step-up, check values compared here, each DEK on its file's first chunk.
      { const f2 = stepFail(body); if (f2) return f2; }
      S.xverifyBodies = (S.xverifyBodies || []).concat([body]);
      const t = now();
      const same = async (given, key, kind) => typeof given === 'string' && sameCheck(given, await keyCheckValue(key, kind));
      const root = { result: typeof body.root === 'string' ? ((await same(body.root, S.root, 'mek')) ? 'match' : 'mismatch') : 'absent', fp: await keyFingerprint(S.root) };
      const list = [];
      for (const x of S.subs) {
        const given = body.subs ? body.subs[x.id] : undefined;
        list.push({ id: x.id, fp: x.fp, from: x.from, until: x.until, status: mekStatus(S.subs, x, t), result: !body.subs ? 'absent' : typeof given !== 'string' ? 'missing' : (await same(given, x.key, 'mek')) ? 'match' : 'mismatch' });
      }
      const unknown = Object.keys(body.subs || {}).filter((id) => !S.subs.some((x) => x.id === id));
      const users = [];
      for (const x of body.users || []) {
        if (x.id !== S.user.id) { users.push({ id: x.id, username: null, salt: 'unknown', keks: [] }); continue; }
        const res = { id: x.id, username: S.user.username, salt: typeof x.salt !== 'string' ? 'absent' : sameCheck(x.salt, await saltCheckValue(S.salt, x.id)) ? 'match' : 'mismatch', keks: [] };
        for (const [mekId, given] of Object.entries(x.keks || {})) {
          const kek = await S.kekOf(mekId);
          res.keks.push({ mekId, result: !kek ? 'unknown' : (await same(given, kek, 'kek')) ? 'match' : 'mismatch' });
        }
        if (x.deks) {
          const d = { total: x.deks.length, opens: 0, fails: 0, missing: 0, empty: 0, unchecked: 0, failed: [], missingIds: [] };
          for (const e of x.deks) {
            const n = S.nodes.get(e.id);
            if (!n || n.kind !== 'file') { d.missing++; d.missingIds.push(e.id); continue; }
            try { await decryptChunk(await importFileKey(e.dek), 0, n.chunks, S.chunks.get(`${n.id}/0`)); d.opens++; } catch { d.fails++; d.failed.push(e.id); }
          }
          res.deks = d;
        }
        users.push(res);
      }
      const matches = root.result !== 'mismatch' && !list.some((x) => x.result === 'mismatch') && !unknown.length
        && users.every((x) => x.username !== null && ['match', 'absent'].includes(x.salt) && x.keks.every((k) => k.result === 'match') && (!x.deks || (!x.deks.fails && !x.deks.missing)));
      S.audit.push({ action: 'keys.export_verified', detail: matches ? 'matches' : 'does not match' });
      return ok({ ok: true, now: t, root, subs: { inFile: !!body.subs, list, unknown }, users, matches });
    }
    if (p === '/api/private/admin/keys/import') {
      { const f2 = stepFail(body); if (f2) return f2; } // the preview too (as the server: audit A F7)
      S.importBodies = (S.importBodies || []).concat([body]);
      return ok({ ok: true, dryRun: body.dryRun !== false, keys: { root: 'same', subs: [], salts: { restored: 0, same: 1, kept: 0, unknown: 0 } }, users: (body.document.users || []).map((u) => ({ id: u.id, username: u.username, keks: { match: (u.keks || []).length, mismatch: 0, unknown: 0 } })) });
    }
    const f = stepFail(body || {});
    if (f) return f;
    if (p === '/api/private/admin/keys/candidate') {
      const key = newKey();
      const id = b64urlFromBytes(randomBytes(12));
      S.candidates.set(id, key);
      return ok({ ok: true, id, key: b64urlFromBytes(key), fp: await keyFingerprint(key), expires: now() + 600 });
    }
    if (p === '/api/private/admin/keys/subs' && method === 'POST') {
      const key = body.candidate ? S.candidates.get(body.candidate) : bytesFromB64url(body.key);
      if (!key) return fail(410, 'candidate_expired');
      S.candidates.delete(body.candidate);
      const s = await S.addSub({ from: body.rotate || !body.from ? now() : body.from, key, note: body.note || '' });
      S.audit.push({ action: body.rotate ? 'keys.rotated' : 'keys.added', detail: s.id });
      return ok({ ok: true, id: s.id, fp: s.fp, from: s.from });
    }
    if ((m = p.match(/^\/api\/private\/admin\/keys\/subs\/([^/]+)(\/current|\/show)?$/))) {
      const s = S.subs.find((x) => x.id === m[1]);
      if (!s) return fail(404, 'not_found');
      if (m[2] === '/show') { S.audit.push({ action: 'keys.viewed', detail: s.fp }); return ok({ ok: true, key: b64urlFromBytes(s.key), fp: s.fp }); }
      if (m[2] === '/current') {
        const t = now();
        for (const x of S.subs) { if (x === s) { x.until = null; if (x.from > t) x.from = t; } else if (x.until === null || x.until > t) x.until = Math.max(x.from, t); }
        return ok({ ok: true });
      }
      if (method === 'PATCH') { Object.assign(s, { from: body.from ?? s.from, until: body.until === undefined ? s.until : body.until, note: body.note ?? s.note }); return ok({ ok: true }); }
      if (method === 'DELETE') {
        if ([...S.nodes.values()].some((n) => n.mek === s.id)) return fail(409, 'in_use');
        S.subs = S.subs.filter((x) => x !== s);
        S.bumpKeys();
        return ok({ ok: true });
      }
    }
    if (p === '/api/private/admin/keys/root/show') return ok({ ok: true, key: b64urlFromBytes(S.root), fp: await keyFingerprint(S.root) });
    // A root change that could not finish (S.rootOld set): run it again, go back, or drop the old root.
    if (p === '/api/private/admin/keys/jobs' && method === 'POST' && body.kind === 'root') {
      if (!S.rootOld) return fail(409, 'not_changing');
      S.rootJobs = (S.rootJobs || 0) + 1;
      S.job = { kind: 'root', from: null, drives: 1, drive: 1, phase: 'verify', done: 0, failed: S.stuckIds?.length || 0, failedIds: S.stuckIds || [], pass: 1, verifying: true, finished: true, result: S.stuckIds?.length ? { ok: false, message: 'Still does not open.' } : { ok: true, message: 'Every item is re-sealed.' } };
      // The root change's check, kept with it (as the Directory's mek.rootCheck).
      S.rootCheck = S.stuckIds?.length ? { failed: S.stuckIds.length, ids: S.stuckIds } : null;
      if (!S.stuckIds?.length) S.rootOld = null;
      return ok({ ok: true, job: S.job });
    }
    if (p === '/api/private/admin/keys/root/undo') {
      if (!S.rootOld) return fail(409, 'not_changing');
      if (S.rootOldOrigin === 'restored' && !S.rootOldProven) return fail(409, 'unproven_root');
      [S.root, S.rootOld] = [S.rootOld, S.root];
      S.rootOldOrigin = 'changed';
      S.rootCheck = null;
      S.audit.push({ action: 'keys.root_changed', detail: 'undone' });
      S.job = { kind: 'root', from: null, drives: 1, drive: 1, phase: 'items', done: 0, failed: 0, failedIds: [], pass: 1, finished: false, result: null };
      return ok({ ok: true, job: S.job });
    }
    if (p === '/api/private/admin/keys/root/drop-old') {
      if (!S.rootOld) return fail(409, 'not_changing');
      const fp = await keyFingerprint(S.rootOld);
      if (![fp, `${fp.slice(0, 4)}-${fp.slice(4, 8)}-${fp.slice(8)}`].includes(String(body.confirm || '').trim())) return fail(400, 'confirm');
      if (!S.rootCheck) return fail(409, 'not_checked');
      const lost = S.rootCheck.failed;
      S.rootOld = null;
      S.rootCheck = null;
      S.audit.push({ action: 'keys.root_old_dropped', detail: `items left unreadable: ${lost}` });
      return ok({ ok: true, lost, ids: [] });
    }
    if (p === '/api/private/admin/keys/jobs' && method === 'POST') {
      S.job = { kind: 'reseal', from: body.from, remove: !!body.remove, drives: 1, drive: 1, phase: 'items', done: 0, failed: 0, failedIds: [], pass: 1, finished: false, result: null };
      return ok({ ok: true, job: S.job });
    }
    if (p === '/api/private/admin/keys/kit') {
      S.kitRecord = { at: now(), root: await keyFingerprint(S.root), subs: S.subs.length, v: S.keyVersion.n };
      S.audit.push({ action: 'keys.kit_exported', detail: '' });
      return ok({ ok: true, kit: S.kitRecord, material: {
        made: now(), current: S.current()?.id ?? null, keyVersion: S.keyVersion, root: { key: b64urlFromBytes(S.root), fp: await keyFingerprint(S.root), created: 1700000000 },
        subs: S.subs.map((s) => ({ id: s.id, key: b64urlFromBytes(s.key), fp: s.fp, from: s.from, until: s.until, created: s.created, note: s.note })),
        salts: { [S.user.id]: { salt: S.salt, username: S.user.username } },
      } });
    }
    if (p === '/api/private/admin/keys/export') {
      const doc = { format: 'secbin-keys-export/1', created: now(), origin: 'https://bin.example', users: [] };
      if (body.root) doc.root = { key: b64urlFromBytes(S.root), fp: await keyFingerprint(S.root), created: 1700000000 };
      const want = body.subs === 'all' ? S.subs : S.subs.filter((x) => (body.subs || []).includes(x.id));
      if (want.length) doc.subs = want.map((x) => ({ id: x.id, key: b64urlFromBytes(x.key), fp: x.fp, from: x.from, until: x.until, created: x.created, note: x.note }));
      if ((body.salts || []).length) doc.salts = Object.fromEntries(body.salts.filter((id) => id === S.user.id).map((id) => [id, S.salt]));
      for (const x of body.users || []) {
        const e = { id: x.id, username: x.id === S.user.id ? S.user.username : 'other' };
        if (x.keks) e.keks = await Promise.all(S.subs.map(async (sub) => ({ mekId: sub.id, fp: sub.fp, from: sub.from, until: sub.until, kek: b64urlFromBytes(await S.kekOf(sub.id)) })));
        if (x.deks) {
          // This account's files: the DEK each seal holds (the others' Drives are not in the fake).
          e.deks = [];
          for (const n of x.id === S.user.id ? S.nodes.values() : []) {
            if (n.kind !== 'file' || n.rs) continue;
            e.deks.push({ id: n.id, dek: b64urlFromBytes(await openDek(await S.kekOf(n.mek), { userId: S.user.id, mekId: n.mek, salt: n.ks }, parsed(n.dek))) });
          }
        }
        doc.users.push(e);
      }
      S.exportBodies = (S.exportBodies || []).concat([body]);
      return ok({ document: doc });
    }
    // A user's personal kit (as keys.js userKitRestore): that user's kit only; S.kitRestorePages calls
    // before it is done (`next`), S.kitLost: the sub-MEKs the server cannot open.
    if ((m = p.match(/^\/api\/private\/admin\/keys\/users\/([^/]+)\/kit-restore$/))) {
      if (!body.kit || body.kit.id !== m[1]) return fail(400, 'kit_mismatch');
      S.kitRestoreBodies = (S.kitRestoreBodies || []).concat([body]);
      const n = S.kitRestoreBodies.length;
      const salt = m[1] === S.user.id && body.kit.salt === S.salt ? 'same' : 'kept';
      const lost = S.kitLost || [];
      const next = lost.length && n < (S.kitRestorePages || 1) ? { mek: lost[0], after: `n.${'A'.repeat(22)}` } : null;
      S.audit.push({ action: 'drive.kit_restored', detail: `salt ${salt}; sub-MEKs the server cannot open: ${lost.length}` });
      return ok({ salt, unreadable: lost, done: lost.length ? 2 : 0, failed: 0, left: [], next });
    }
    if ((m = p.match(/^\/api\/private\/admin\/keys\/users\/([^/]+)\/view$/))) {
      if (body.what === 'deks') return ok({ userId: m[1], username: S.user.username, files: [], next: null });
      return ok({ userId: m[1], username: S.user.username, salt: S.salt, current: S.current()?.id, items: 0,
        keks: await Promise.all(S.subs.map(async (sub) => ({ mekId: sub.id, fp: sub.fp, from: sub.from, until: sub.until, kek: b64urlFromBytes(await S.kekOf(sub.id)), inUse: false }))) });
    }
    return fail(404, `unrouted ${method} ${p}`);
  }
  return S;
}

/**
 * Store a tree as the browser would have written it under the user's current
 * KEK (sealed names and metadata, a DEK per file, chunked content): `tree` =
 * { name: bytes (a file) | { … } (a folder) }. → Map(path → node id).
 */
export async function seedTree(S, tree, parent = 'root', prefix = '', ids = new Map()) {
  await S.ready;
  const cur = S.current();
  const kek = await S.kekOf(cur.id);
  for (const [name, v] of Object.entries(tree)) {
    const id = b64urlFromBytes(randomBytes(16));
    const path = prefix + name;
    const ks = newSalt();
    const at = { userId: S.user.id, mekId: cur.id, salt: ks };
    const nameField = JSON.stringify(await sealName(kek, at, 'name', utf8(name)));
    if (v instanceof Uint8Array) {
      const dek = randomBytes(32);
      const n = Math.ceil(v.length / CHUNK);
      const key = await importFileKey(b64urlFromBytes(dek));
      for (let i = 0; i < n; i++) S.chunks.set(`${id}/${i}`, await encryptChunk(key, i, n, v.slice(i * CHUNK, (i + 1) * CHUNK)));
      S.nodes.set(id, {
        id, parent, kind: 'file', name: nameField, size: v.length, chunks: n, state: 'ready', created: 1700000000, updated: 1700000000, ks, mek: cur.id,
        meta: JSON.stringify(await sealName(kek, at, 'meta', utf8(JSON.stringify({ type: 'text/plain', mtime: 1700000000000, size: v.length })))),
        dek: JSON.stringify(await sealDek(kek, at, dek)),
      });
    } else {
      S.nodes.set(id, { id, parent, kind: 'dir', name: nameField, size: 0, chunks: 0, state: 'ready', created: 1700000000, updated: 1700000000, ks, mek: cur.id });
      await seedTree(S, v, id, `${path}/`, ids);
    }
    ids.set(path, id);
  }
  return ids;
}

/**
 * A file received through reverse share `rid` (public key `pub`), stored as
 * the uploader's browser would have sent it: content under a fresh file key,
 * path and metadata sealed with a metadata key, both wrapped to `pub`.
 * `bad: true` stores a wrap that does not open; `item`: a note, link or
 * credential's kind marker (sealed in its metadata); `declared`: the kind its
 * session declared to the server (default: what it is; null: none); `unsealed`:
 * listed as the server lists a wrap it found in plain text. → the node id.
 */
export async function seedReceived(S, { rid, pub, folder = 'root', path, bytes, type = 'text/plain', bad = false, item = null, created = 1700000000, declared = item ? item.kind : 'files', unsealed = false }) {
  const id = newNodeId();
  const fk = randomBytes(32);
  const n = Math.ceil(bytes.length / CHUNK);
  const key = await importFileKey(b64urlFromBytes(fk));
  for (let i = 0; i < n; i++) S.chunks.set(`${id}/${i}`, await encryptChunk(key, i, n, bytes.slice(i * CHUNK, (i + 1) * CHUNK)));
  const sealed = await sealUpload(pub, bad ? `r${'A'.repeat(22)}` : rid, id, fk, { path, type, mtime: 1700000000000, size: bytes.length, item });
  S.nodes.set(id, {
    id, parent: folder, kind: 'file', name: sealed.name, meta: sealed.meta, fk: { kind: 'rs', data: sealed.wrap },
    size: bytes.length, chunks: n, state: 'ready', created, updated: created, rs: rid, declared, unsealed,
  });
  return id;
}
