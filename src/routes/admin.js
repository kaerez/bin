// admin.js — /api/private/admin/*: owner-only administration. Every route
// requires a real owner session (not an API key, not while impersonating),
// except "unimpersonate", which is how an impersonating owner returns.

import { json, err, readJsonBody, assertIntent, methodNotAllowed } from '../lib/http.js';
import { authenticate, issueSession } from '../lib/auth.js';
import { directory, guardShards, guardShardFor, invalidateGuardCaches, cachedSettings } from '../lib/guard.js';
import { authnToken, bfpDisabled, sessionKeys } from '../lib/config.js';
import { GUARD_SCOPES } from '../lib/settings.js';
import { verifierFrom } from './auth.js';
import { purgeShare, changeShare, withLiveStatus } from './private.js';
import { parseId } from '../lib/ids.js';

const fromDir = (r) => err(r.status, r.error, r.message);
const ID_RE = /^[A-Za-z0-9_-]{16}$/;
const now = () => Math.floor(Date.now() / 1000);
const SHARE_KINDS = ['text', 'files', 'url', 'secret'];
const SHARE_STATUSES = ['active', 'revoked', 'expired', 'consumed', 'deleted', 'ended'];

/** Parse the admin share-list filters from the query string (all optional). */
export function shareFilters(sp) {
  const int = (k) => {
    const v = sp.get(k);
    if (v === null || v === '') return null;
    const n = Number(v);
    return Number.isSafeInteger(n) && n >= 0 ? n : null;
  };
  const users = (sp.get('users') || '').split(',').map((u) => u.trim()).filter((u) => ID_RE.test(u)).slice(0, 100);
  const kind = SHARE_KINDS.includes(sp.get('kind')) ? sp.get('kind') : '';
  const status = SHARE_STATUSES.includes(sp.get('status')) ? sp.get('status') : '';
  const lockedRaw = sp.get('locked');
  const locked = lockedRaw === 'true' ? true : lockedRaw === 'false' ? false : null;
  return {
    users, kind, status, locked,
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
    const r = await dir.endImpersonation(a.actor.id, a.user.id);
    if (!r.ok) return fromDir(r);
    const { cookie } = await issueSession(env, { uid: r.user.id, ver: r.ver, settings: r.settings });
    return json({ ok: true }, 200, { 'set-cookie': cookie });
  }

  if (a.actor) return err(403, 'impersonating', 'Return to your own account to use the admin panel.');
  if (a.user.role !== 'owner') return err(403, 'forbidden', 'Owner only.');
  const me = a.user.id;

  if (p === '/api/private/admin/shares') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    const { rows, total } = await dir.adminListShares(shareFilters(url.searchParams));
    return json({ rows: await withLiveStatus(env, dir, rows), total });
  }

  const sm = p.match(/^\/api\/private\/admin\/shares\/([A-Za-z0-9_-]{16,32})(?:\/(revoke|lock))?$/);
  if (sm) {
    const id = sm[1];
    const info = parseId(id);
    if (!info) return err(404, 'not_found', 'Share not found.');
    const row = await dir.adminShare(id);
    if (!row) return err(404, 'not_found', 'Share not found.');
    if (!sm[2]) {
      if (request.method === 'GET') return json({ share: row });
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

  if (p === '/api/private/admin/overview') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    const g = await dir.adminGlobal();
    const off = bfpDisabled(env);
    return json({ ...g, env: { authnSet: !!authnToken(env), sessionKeys: !!sessionKeys(env), bfpDisabled: off.all, bfpSetupDisabled: off.setup } });
  }

  if (p === '/api/private/admin/settings') {
    if (request.method !== 'PATCH') return methodNotAllowed('PATCH');
    const body = await readJsonBody(request);
    const r = await dir.setSettings(body, me);
    invalidateGuardCaches();
    return r.ok ? json(r) : fromDir(r);
  }

  if (p === '/api/private/admin/limits') {
    if (request.method !== 'PATCH') return methodNotAllowed('PATCH');
    const body = await readJsonBody(request);
    const scope = body.scope === 'global' ? '' : body.scope;
    if (scope !== '' && !ID_RE.test(String(scope))) return err(400, 'invalid_scope', 'scope must be "global" or a user id');
    const r = await dir.setLimits(scope, body.channel, body.patch, me);
    return r.ok ? json(r) : fromDir(r);
  }

  if (p === '/api/private/admin/quotas' || p === '/api/private/admin/viewer-rules') {
    if (request.method !== 'PUT') return methodNotAllowed('PUT');
    const body = await readJsonBody(request);
    const scope = body.scope === 'global' ? '' : body.scope;
    if (scope !== '' && !ID_RE.test(String(scope))) return err(400, 'invalid_scope', 'scope must be "global" or a user id');
    const r = p.endsWith('quotas') ? await dir.setQuotas(scope, body.list, me) : await dir.setViewerRules(scope, body.list, me);
    return r.ok ? json(r) : fromDir(r);
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

  const um = p.match(/^\/api\/private\/admin\/users\/([A-Za-z0-9_-]{16})(?:\/(password|unlock|impersonate|keys\/([A-Za-z0-9_-]{16})))?$/);
  if (um) {
    const [, uid, action, keyId] = um;
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
        const r = await dir.deleteUser(uid, me);
        if (!r.ok) return fromDir(r);
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
    if (action === 'impersonate') {
      if (request.method !== 'POST') return methodNotAllowed('POST');
      assertIntent(request);
      const r = await dir.impersonate(me, uid);
      if (!r.ok) return fromDir(r);
      const { cookie } = await issueSession(env, { uid: r.target.id, act: me, ver: r.ver, settings: r.settings });
      return json({ ok: true, user: r.target }, 200, { 'set-cookie': cookie });
    }
    if (keyId) {
      if (request.method !== 'DELETE') return methodNotAllowed('DELETE');
      assertIntent(request);
      const r = await dir.revokeKey(uid, keyId, me);
      return r.ok ? json(r) : fromDir(r);
    }
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
      const r = await dir.addIpRule({ cidr: body.cidr, action: body.action, expires, note: body.note }, me);
      invalidateGuardCaches();
      return r.ok ? json(r, 201) : fromDir(r);
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
    return json({
      blocks: lists.flatMap((l) => l.blocks).sort((x, y) => y.since - x.since),
      tracking: lists.flatMap((l) => l.tracking).sort((x, y) => y.count - x.count),
    });
  }
  const gm = p.match(/^\/api\/private\/admin\/guard\/(unblock|block)$/);
  if (gm) {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    const body = await readJsonBody(request);
    if (!GUARD_SCOPES.includes(body.scope) || typeof body.key !== 'string' || body.key.length > 64) return err(400, 'invalid', 'scope and key are required');
    const stub = guardShardFor(env, body.key);
    if (gm[1] === 'unblock') {
      await stub.unblock(body.scope, body.key);
      await dir.adminLog({ action: 'guard.unblocked', detail: `${body.scope} ${body.key}` }, me);
    } else {
      const sec = Number(body.seconds);
      if (!Number.isSafeInteger(sec) || sec < 1 || sec > 365 * 86400) return err(400, 'invalid', 'seconds must be 1–31536000');
      await stub.block(body.scope, body.key, now() + sec);
      await dir.adminLog({ action: 'guard.blocked', detail: `${body.scope} ${body.key} ${sec}s` }, me);
    }
    return json({ ok: true });
  }

  return err(404, 'not_found', 'Not found.');
}
