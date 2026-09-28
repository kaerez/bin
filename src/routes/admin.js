// admin.js — /api/private/admin/*: owner-only administration. Every route
// requires a real owner session (not an API key, not while impersonating),
// except "unimpersonate", which is how an impersonating owner returns.

import { json, err, readJsonBody, assertIntent, methodNotAllowed } from '../lib/http.js';
import { authenticate, issueSession } from '../lib/auth.js';
import { directory, guardShards, guardShardFor, guardKeyFor, invalidateGuardCaches, cachedSettings, ipContext, RATE_LIMIT_SCOPES } from '../lib/guard.js';
import { isGuardTag } from '../lib/records.js';
import { authnToken, bfpDisabled, sessionKeys } from '../lib/config.js';
import { GUARD_SCOPES, apiExpiry } from '../lib/settings.js';
import { verifierFrom } from './auth.js';
import { purgeShare, changeShare, withLiveStatus, createApiKey } from './private.js';
import { stepUpFrom, stepUpIfGiven, afterRefusal } from './stepup.js';
import { turnstileKeys, turnstileConfig, invalidateTurnstileCache } from '../lib/turnstile.js';
import { shareInfo } from '../lib/ids.js';
import { MAX_SHARE_FILTER_USERS } from '../directory-do.js';
import { validateExport, validateDecisions, PortableError, MAX_IMPORT_BYTES, MAX_EXPORT_USERS, USER_PARTS, OWNER_PARTS, SYSTEM_PARTS } from '../lib/portable.js';
import { adminDriveRoute, syncCredentialWraps, destroyDrive, drivePasswordChanged, legacyCleanup, stepUp } from './drive.js';
import { handleKeys } from './keys.js';

const fromDir = (r) => err(r.status, r.error, r.message);
/** As fromDir, with what a change weakens when it needs the step-up (400 reauth_required). */
const fromDirWeak = (r) => err(r.status, r.error, r.message, r.weakens ? { weakens: r.weakens } : undefined);
/** The session a new one replaces (impersonation starting or ending): revoked with it. */
const replaced = (a) => ({ sid: a.claims.sid, exp: a.claims.exp });
const ID_RE = /^[A-Za-z0-9_-]{16}$/;
// Where limits, quotas and viewer rules are set: "global" (the Default role),
// "role:<id>" (a custom role) or the public account's id.
const SCOPE_RE = /^(global|role:default|role:[A-Za-z0-9_-]{16}|[A-Za-z0-9_-]{16})$/;
const SCOPE_MSG = 'scope must be "global", "role:<id>" or the public account';
const now = () => Math.floor(Date.now() / 1000);
const SHARE_KINDS = ['text', 'files', 'url', 'secret', 'drive', 'reverse'];
const SHARE_STATUSES = ['active', 'revoked', 'expired', 'consumed', 'deleted', 'ended'];

/** Parse the admin share-list filters from the query string (all optional). */
export function shareFilters(sp) {
  const int = (k) => {
    const v = sp.get(k);
    if (v === null || v === '') return null;
    const n = Number(v);
    return Number.isSafeInteger(n) && n >= 0 ? n : null;
  };
  const users = (sp.get('users') || '').split(',').map((u) => u.trim()).filter((u) => ID_RE.test(u)).slice(0, MAX_SHARE_FILTER_USERS);
  const kind = SHARE_KINDS.includes(sp.get('kind')) ? sp.get('kind') : '';
  const status = SHARE_STATUSES.includes(sp.get('status')) ? sp.get('status') : '';
  const lockedRaw = sp.get('locked');
  const locked = lockedRaw === 'true' ? true : lockedRaw === 'false' ? false : null;
  // expiry=none: reverse shares with no expiry; expiry=set: shares that expire.
  const expiry = ['none', 'set'].includes(sp.get('expiry')) ? sp.get('expiry') : '';
  return {
    users, kind, status, locked, expiry,
    q: (sp.get('q') || '').slice(0, 100),
    createdFrom: int('createdFrom'), createdTo: int('createdTo'),
    expiresFrom: int('expiresFrom'), expiresTo: int('expiresTo'),
    limit: Math.min(200, int('limit') ?? 50), offset: int('offset') ?? 0,
  };
}

export async function handleAdmin(request, env, url) {
  const p = url.pathname;
  const a = await authenticate(request, env);
  const dir = directory(env);

  if (p === '/api/private/admin/unimpersonate') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    assertIntent(request);
    if (!a.actor) return err(400, 'not_impersonating', 'You are not impersonating anyone.');
    // The impersonation session is revoked, and the owner's new session keeps
    // the sign-in's absolute timeout (see issueSession): going in and out of
    // impersonation never extends a session or leaves the old one usable.
    const r = await dir.endImpersonation(a.actor.id, a.user.id, replaced(a));
    if (!r.ok) return fromDir(r);
    const { cookie } = await issueSession(env, { uid: r.user.id, ver: r.ver, settings: r.settings, iat: a.claims.iat, notAfter: a.claims.exp });
    return json({ ok: true }, 200, { 'set-cookie': cookie });
  }

  if (a.actor) return err(403, 'impersonating', 'Return to your own account to use the admin panel.');
  if (a.user.role !== 'owner') return err(403, 'forbidden', 'Owner only.');
  const me = a.user.id;

  // The Drive keys (docs/DRIVE.md §3): the keyring, the key kit, the keys
  // parts of Import / export, one user's keys (Security → Keys); and the
  // upgrade of Drives made before the key model v2.
  if (p === '/api/private/admin/keys' || p.startsWith('/api/private/admin/keys/')) return handleKeys(request, env, url, a);
  if (p === '/api/private/admin/drive/migration' || p === '/api/private/admin/drive/archive' || p.startsWith('/api/private/admin/drive/migrate/')) return adminDriveRoute(request, env, url, me);

  if (p === '/api/private/admin/shares') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    const { rows, total } = await dir.adminListShares(shareFilters(url.searchParams));
    return json({ rows: await withLiveStatus(env, dir, rows), total });
  }

  const om = p.match(/^\/api\/private\/admin\/shares\/([A-Za-z0-9_-]{16,32})\/opens$/);
  if (om) {
    // The admin always sees every read-receipt detail.
    if (request.method !== 'GET') return methodNotAllowed('GET');
    const r = await dir.shareOpens(me, om[1], { admin: true });
    return r.ok ? json({ total: r.total, fields: r.fields, rows: r.rows }) : fromDir(r);
  }

  const sm = p.match(/^\/api\/private\/admin\/shares\/([A-Za-z0-9_-]{16,32})(?:\/(revoke|lock))?$/);
  if (sm) {
    const id = sm[1];
    const info = shareInfo(id);
    if (!info) return err(404, 'not_found', 'Share not found.');
    const row = await dir.adminShare(id);
    if (!row) return err(404, 'not_found', 'Share not found.');
    if (!sm[2]) {
      if (request.method === 'GET') return json({ share: { ...row, expires: apiExpiry(row.expires) } });
      if (request.method !== 'PATCH') return methodNotAllowed('GET, PATCH');
      const body = await readJsonBody(request);
      // Direct admin edits: bounded by the protocol maxima only, allowed on
      // locked shares, and logged as admin actions (not in the user's log).
      return changeShare(env, dir, row, info, body, { uid: row.user_id, actor: me, admin: me });
    }
    if (request.method !== 'POST') return methodNotAllowed('POST');
    if (sm[2] === 'revoke') {
      assertIntent(request);
      await purgeShare(env, id, info);
      const r = await dir.updateShare(row.user_id, id, { status: 'revoked' }, me, { admin: me });
      return r.ok ? json({ ok: true }) : fromDir(r);
    }
    const body = await readJsonBody(request);
    if (typeof body.locked !== 'boolean') return err(400, 'invalid', 'Send {"locked": true|false}.');
    const r = await dir.setShareLock(me, id, body.locked);
    return r.ok ? json({ ok: true, locked: r.locked }) : fromDir(r);
  }

  // ── export / import (always re-confirmed: the owner's password or a passkey) ──
  if (p === '/api/private/admin/export' || p === '/api/private/admin/import') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const isImport = p.endsWith('import');
    // An export request lists the users, each with its parts (up to MAX_EXPORT_USERS).
    const body = await readJsonBody(request, isImport ? MAX_IMPORT_BYTES : 1024 * 1024);
    // Step-up: an export can hold password verifiers and an import can
    // create accounts and add passkeys, so a session alone (e.g. a stolen cookie) is not
    // enough. `current` or `reauth`, as for the key routes; a wrong password or a failed
    // passkey counts like a wrong current password (lockout, and the network's failures).
    const refused = await stepUp(request, env, url, dir, me, body);
    if (refused) return refused;
    if (!isImport) {
      // users: "all" or [id…] (each with the parts in `parts`), or [{id, parts}] (parts per user).
      const partsOf = (v) => (Array.isArray(v) ? USER_PARTS.filter((k) => v.includes(k)) : []);
      const users = body.users === 'all' ? 'all' : Array.isArray(body.users)
        ? body.users.slice(0, MAX_EXPORT_USERS + 1).map((u) => (typeof u === 'string' ? u : u && typeof u === 'object' ? { id: String(u.id), parts: partsOf(u.parts) } : null))
          .filter((u) => u !== null && ID_RE.test(typeof u === 'string' ? u : u.id))
        : [];
      // system: true (everything) or { settings, roles, ipRules, turnstile, public }.
      const sysSel = body.system === true ? true
        : body.system && typeof body.system === 'object' ? Object.fromEntries(SYSTEM_PARTS.map((k) => [k, body.system[k] === true])) : false;
      // owner: the owner's row, its parts among passkeys and recoveryCodes.
      const owner = Array.isArray(body.owner) ? OWNER_PARTS.filter((k) => body.owner.includes(k)) : [];
      const r = await dir.exportData({ system: sysSel, users, parts: partsOf(body.parts), owner, origin: url.origin }, me);
      return r.ok ? json({ document: r.doc }) : fromDir(r);
    }
    let doc;
    let decisions;
    try {
      doc = validateExport(body.document);
      decisions = validateDecisions(body.decisions, doc);
    } catch (e) {
      if (e instanceof PortableError) return err(400, 'invalid_import', e.message);
      throw e;
    }
    const g = await ipContext(env, request);
    const r = await dir.importData(doc, decisions, { dryRun: body.dryRun !== false, callerIp: g.ip, host: url.hostname }, me);
    if (!r.ok) return json({ error: r.error, message: r.message, plan: r.plan }, r.status);
    if (r.applied) { invalidateGuardCaches(); invalidateTurnstileCache(); }
    return json(r);
  }

  // ── public access: its profile, trackers (settings go through /settings) ──
  if (p === '/api/private/admin/public') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    const blockedOnly = url.searchParams.get('blocked') === 'true';
    return json({ profile: await dir.publicProfile(), trackers: await dir.listTrackers({ limit: 200, blocked: blockedOnly ? true : null }) });
  }
  const tm = p.match(/^\/api\/private\/admin\/public\/trackers\/([A-Za-z0-9_-]{12})$/);
  if (tm) {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const body = await readJsonBody(request);
    const r = await dir.adminTracker(tm[1], body.action, me);
    return r.ok ? json(r) : fromDir(r);
  }

  if (p === '/api/private/admin/overview') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    const g = await dir.adminGlobal();
    const off = bfpDisabled(env);
    // turnstile: keys are in force, so the roles' CAPTCHA options are enforced (the role editor says when not).
    return json({ ...g, turnstile: !!(await turnstileKeys(env)), env: { authnSet: !!authnToken(env), sessionKeys: !!sessionKeys(env), bfpDisabled: off.all, bfpSetupDisabled: off.setup } });
  }

  if (p === '/api/private/admin/settings') {
    if (request.method !== 'PATCH') return methodNotAllowed('PATCH');
    // Room for the whole accessibility statement (A11Y_MAX_TOTAL characters,
    // up to 4 bytes each in UTF-8) in one save.
    const { current, reauth, ...patch } = await readJsonBody(request, 256 * 1024);
    // A change that weakens a security control needs the password or a passkey (the Directory decides).
    const g = await ipContext(env, request);
    const step = await stepUpIfGiven({ current, reauth }, url);
    const r = await dir.setSettings(patch, me, { ...step, lockoutOff: g.off.all });
    invalidateGuardCaches();
    return r.ok ? json(r) : afterRefusal(env, g, r, fromDirWeak(r));
  }

  // Turnstile keys set here apply when the deployment sets none.
  if (p === '/api/private/admin/turnstile') {
    if (request.method === 'GET') {
      const k = await turnstileKeys(env);
      return json({ ...(await dir.turnstileStatus()), active: k ? k.source : null, deployment: !!turnstileConfig(env) });
    }
    if (request.method !== 'PUT') return methodNotAllowed('GET, PUT');
    const body = await readJsonBody(request);
    const g = await ipContext(env, request);
    const step = await stepUpFrom(body, url);
    const r = await dir.setTurnstileKeys(me, { sitekey: body.sitekey, secret: body.secret, clear: body.clear === true, ...step, lockoutOff: g.off.all });
    invalidateTurnstileCache();
    return r.ok ? json(r) : afterRefusal(env, g, r, fromDir(r));
  }

  if (p === '/api/private/admin/limits') {
    if (request.method !== 'PATCH') return methodNotAllowed('PATCH');
    const body = await readJsonBody(request);
    if (!SCOPE_RE.test(String(body.scope))) return err(400, 'invalid_scope', SCOPE_MSG);
    const g = await ipContext(env, request);
    const step = await stepUpIfGiven(body, url);
    const r = await dir.setLimits(body.scope === 'global' ? '' : body.scope, body.channel, body.patch, me, { ...step, lockoutOff: g.off.all });
    return r.ok ? json(r) : afterRefusal(env, g, r, fromDirWeak(r));
  }

  if (p === '/api/private/admin/quotas' || p === '/api/private/admin/viewer-rules') {
    if (request.method !== 'PUT') return methodNotAllowed('PUT');
    const body = await readJsonBody(request);
    if (!SCOPE_RE.test(String(body.scope))) return err(400, 'invalid_scope', SCOPE_MSG);
    const scope = body.scope === 'global' ? '' : body.scope;
    const r = p.endsWith('quotas') ? await dir.setQuotas(scope, body.list, me) : await dir.setViewerRules(scope, body.list, me);
    return r.ok ? json(r) : fromDir(r);
  }

  // Roles: list and create (or duplicate with `from`); one role's detail,
  // rename / own-quotas switch, delete.
  if (p === '/api/private/admin/roles') {
    if (request.method === 'GET') return json(await dir.listRoles());
    if (request.method !== 'POST') return methodNotAllowed('GET, POST');
    const body = await readJsonBody(request);
    const r = body.from !== undefined ? await dir.duplicateRole(String(body.from), body.name, me) : await dir.createRole(body.name, me);
    return r.ok ? json(r, 201) : fromDir(r);
  }
  const roleM = p.match(/^\/api\/private\/admin\/roles\/([A-Za-z0-9_-]{16})$/);
  if (roleM) {
    if (request.method === 'GET') { const r = await dir.roleDetail(roleM[1]); return r.ok ? json(r) : fromDir(r); }
    if (request.method === 'PATCH') {
      const body = await readJsonBody(request);
      const r = await dir.updateRole(roleM[1], { name: body.name, ownQuotas: body.ownQuotas }, me);
      return r.ok ? json(r) : fromDir(r);
    }
    if (request.method === 'DELETE') {
      assertIntent(request);
      const r = await dir.deleteRole(roleM[1], me);
      return r.ok ? json(r) : fromDir(r);
    }
    return methodNotAllowed('GET, PATCH, DELETE');
  }

  if (p === '/api/private/admin/users') {
    if (request.method === 'GET') return json({ users: await dir.listUsers() });
    if (request.method === 'POST') {
      const body = await readJsonBody(request);
      const verifier = await verifierFrom(body.proof);
      if (!verifier) return err(400, 'invalid_credential', 'Invalid password proof.');
      const r = await dir.createUser({ username: body.username, salt: body.salt, t: body.t, verifier }, me);
      return r.ok ? json(r, 201) : fromDir(r);
    }
    return methodNotAllowed('GET, POST');
  }

  const um = p.match(/^\/api\/private\/admin\/users\/([A-Za-z0-9_-]{16})(?:\/(password|unlock|impersonate|passkeys|keys|role)(?:\/([A-Za-z0-9_-]{16}))?)?$/);
  if (um) {
    const [, uid, action, keyId] = um;
    if (keyId && action !== 'keys') return err(404, 'not_found', 'Not found.');
    if (!action) {
      if (request.method === 'GET') {
        const d = await dir.userDetail(uid);
        return d ? json(d) : err(404, 'not_found', 'User not found.');
      }
      if (request.method === 'PATCH') {
        const body = await readJsonBody(request);
        const r = await dir.updateUser(uid, { username: body.username, disabled: body.disabled }, me);
        return r.ok ? json(r) : fromDir(r);
      }
      if (request.method === 'DELETE') {
        assertIntent(request);
        const can = await dir.canDeleteUser(uid);
        if (!can.ok) return fromDir(can);
        // The Drive goes first (its shares end, then its ciphertext and state),
        // so the account is deleted only once nothing of its Drive is left;
        // on a failure the account stays and deleting it again retries.
        try {
          await destroyDrive(env, dir, uid, { id: me, adm: true }); // an admin action: never in the user's activity
        } catch (e) {
          if (e && e.status && e.status < 600) throw e; // e.g. 503 not_configured
          console.warn('secbin: drive not destroyed', e && e.message ? e.message : e);
          return err(503, 'drive_not_deleted', 'The account was not deleted: its Drive could not be removed right now. Try again.');
        }
        const r = await dir.deleteUser(uid, me);
        if (!r.ok) return fromDir(r);
        // The last Drive waiting for its upgrade may have gone with the account: the old escrow records go too.
        try { await legacyCleanup(env, dir); } catch (e) { console.warn('secbin: legacy Drive keys not cleaned up', e && e.message ? e.message : e); }
        if (url.searchParams.get('revokeShares') === '1') {
          for (const id of r.shares) await purgeShare(env, id);
        }
        return json({ ok: true, revoked: url.searchParams.get('revokeShares') === '1' ? r.shares.length : 0 });
      }
      return methodNotAllowed('GET, PATCH, DELETE');
    }
    if (action === 'password') {
      if (request.method !== 'POST') return methodNotAllowed('POST');
      const body = await readJsonBody(request);
      const verifier = await verifierFrom(body.proof);
      if (!verifier) return err(400, 'invalid_credential', 'Invalid password proof.');
      const r = await dir.setPassword(uid, { salt: body.salt, t: body.t, verifier }, me);
      if (!r.ok) return fromDir(r);
      // The Drive's password wrap opens only with the old password now.
      await drivePasswordChanged(env, uid, { reset: true });
      if (uid === me) {
        // Resetting your own password ends your other sessions; keep this one.
        const s = await cachedSettings(env);
        const { cookie } = await issueSession(env, { uid: me, ver: r.ver, settings: { idleSec: s['session.idleSec'], absSec: s['session.absSec'] } });
        return json({ ok: true }, 200, { 'set-cookie': cookie });
      }
      return json({ ok: true });
    }
    if (action === 'unlock') {
      if (request.method !== 'POST') return methodNotAllowed('POST');
      assertIntent(request);
      return json(await dir.unlockUser(uid, me));
    }
    if (action === 'passkeys') {
      // Remove an account's passkeys and recovery codes. Another user's: no
      // confirmation (as for setting their password); the owner's own: the
      // password or a passkey, as on Account.
      if (request.method !== 'POST') return methodNotAllowed('POST');
      assertIntent(request);
      const g = await ipContext(env, request);
      const body = await readJsonBody(request);
      const step = uid === me ? await stepUpFrom(body, url) : {};
      const r = await dir.adminResetPasskeys(uid, me, { ...step, lockoutOff: g.off.all });
      if (r.ok) await syncCredentialWraps(env, uid);
      return r.ok ? json(r) : afterRefusal(env, g, r, fromDir(r));
    }
    if (action === 'role') {
      if (request.method !== 'PUT') return methodNotAllowed('PUT');
      const body = await readJsonBody(request);
      const r = await dir.setUserRole(uid, body.roleId, me);
      return r.ok ? json(r) : fromDir(r);
    }
    if (action === 'impersonate') {
      if (request.method !== 'POST') return methodNotAllowed('POST');
      assertIntent(request);
      // As for "Return to admin": the owner's session is revoked and the new one keeps its absolute timeout.
      const r = await dir.impersonate(me, uid, replaced(a));
      if (!r.ok) return fromDir(r);
      const { cookie } = await issueSession(env, { uid: r.target.id, act: me, ver: r.ver, settings: r.settings, iat: a.claims.iat, notAfter: a.claims.exp });
      return json({ ok: true, user: r.target }, 200, { 'set-cookie': cookie });
    }
    // API keys of a user: the owner creates, changes and revokes them for
    // other users freely; on the owner's own account the confirmation applies.
    if (action === 'keys' && !keyId) {
      if (request.method !== 'POST') return methodNotAllowed('POST');
      const body = await readJsonBody(request);
      const g = await ipContext(env, request);
      const step = uid === me ? await stepUpFrom(body, url) : {};
      const r = await createApiKey(dir, uid, body, { ...step, actorId: me, lockoutOff: g.off.all });
      return r.ok ? json({ ok: true, id: r.id, key: r.key }, 201) : afterRefusal(env, g, r, fromDir(r));
    }
    if (keyId) {
      if (request.method !== 'DELETE' && request.method !== 'PATCH') return methodNotAllowed('PATCH, DELETE');
      if (request.method === 'DELETE') assertIntent(request);
      const body = request.method === 'PATCH' || uid === me ? await readJsonBody(request) : {};
      const g = await ipContext(env, request);
      const step = { ...(uid === me ? await stepUpFrom(body, url) : {}), lockoutOff: g.off.all };
      const r = request.method === 'DELETE'
        ? await dir.revokeKey(uid, keyId, me, step)
        : await dir.updateKey(uid, keyId, { name: body.name, scopes: body.scopes, actorId: me, ...step });
      return r.ok ? json({ ok: true }) : afterRefusal(env, g, r, fromDir(r));
    }
  }

  // Clearing logs destroys evidence, so it needs the owner to confirm again: the password or a
  // passkey (`current` or `reauth`, as every step-up; failures count like wrong passwords).
  if (p === '/api/private/admin/logs/clear') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const body = await readJsonBody(request, 16 * 1024);
    const refused = await stepUp(request, env, url, dir, me, body);
    if (refused) return refused;
    const r = await dir.clearLogs({ scope: body.scope, userId: body.user, before: body.before ?? null });
    return r.ok ? json(r) : fromDir(r);
  }

  if (p === '/api/private/admin/audit') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    const before = Number(url.searchParams.get('before')) || null;
    const subject = url.searchParams.get('user');
    return json({ rows: await dir.audit({ before, limit: 100, subject: subject && ID_RE.test(subject) ? subject : null }) });
  }

  if (p === '/api/private/admin/ip-rules') {
    if (request.method === 'GET') return json({ rules: await dir.ipRules() });
    if (request.method === 'POST') {
      const body = await readJsonBody(request);
      const expires = body.expiresInSec ? now() + Number(body.expiresInSec) : null;
      const g = await ipContext(env, request);
      const step = await stepUpIfGiven(body, url);
      const r = await dir.addIpRule({ cidr: body.cidr, action: body.action, expires, note: body.note, callerIp: g.ip }, me, { ...step, lockoutOff: g.off.all });
      invalidateGuardCaches();
      return r.ok ? json(r, 201) : afterRefusal(env, g, r, fromDirWeak(r));
    }
    return methodNotAllowed('GET, POST');
  }
  const rm = p.match(/^\/api\/private\/admin\/ip-rules\/([A-Za-z0-9_-]{16})$/);
  if (rm) {
    if (request.method !== 'DELETE') return methodNotAllowed('DELETE');
    assertIntent(request);
    const r = await dir.removeIpRule(rm[1], me);
    invalidateGuardCaches();
    return r.ok ? json(r) : fromDir(r);
  }

  if (p === '/api/private/admin/guard') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    const lists = await Promise.all(guardShards(env).map((s) => s.list()));
    const blocks = lists.flatMap((l) => l.blocks).sort((x, y) => y.since - x.since);
    const tracking = lists.flatMap((l) => l.tracking).sort((x, y) => y.count - x.count);
    // The addresses are sealed at rest (SECURITY.md, "Records at rest"): opened here, for the owner's view only.
    const addrs = await dir.openGuardAddrs([...blocks, ...tracking].map((r) => ({ scope: r.scope, key: r.key, addr: r.addr, rk: r.rk })));
    const shown = (list, off) => list.map(({ addr: _a, rk: _k, ...r }, i) => ({ ...r, addr: addrs[off + i] }));
    return json({ blocks: shown(blocks, 0), tracking: shown(tracking, blocks.length) });
  }
  const gm = p.match(/^\/api\/private\/admin\/guard\/(unblock|block)$/);
  if (gm) {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const body = await readJsonBody(request);
    if (![...GUARD_SCOPES, ...RATE_LIMIT_SCOPES].includes(body.scope) || typeof body.key !== 'string' || body.key.length > 64) return err(400, 'invalid', 'scope and key are required');
    // A row's key (a tag), or an address / prefix as the owner knows it: its tag (SECURITY.md, "Records at rest").
    const key = isGuardTag(body.key) ? body.key : await guardKeyFor(env, body.key);
    const stub = guardShardFor(env, key);
    // The row's address, for the audit entry (sealed there like every sign-in record).
    const row = await stub.row(body.scope, key);
    if (gm[1] === 'unblock') {
      await stub.unblock(body.scope, key);
      // A row from before the tags (not re-keyed yet) is keyed by the address itself.
      if (key !== body.key) await guardShardFor(env, body.key).unblock(body.scope, body.key);
      await dir.guardLog({ action: 'guard.unblocked', scope: body.scope, key, row: row ?? (key !== body.key ? { addr: body.key, rk: null } : null) }, me);
    } else {
      const sec = Number(body.seconds);
      if (!Number.isSafeInteger(sec) || sec < 1 || sec > 365 * 86400) return err(400, 'invalid', 'seconds must be 1–31536000');
      await stub.block(body.scope, key, now() + sec);
      await dir.guardLog({ action: 'guard.blocked', scope: body.scope, key, row, seconds: sec }, me);
    }
    return json({ ok: true });
  }

  return err(404, 'not_found', 'Not found.');
}
