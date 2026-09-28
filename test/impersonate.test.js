// impersonate.test.js — the owner acting as a user ("Log in as") can do
// everything the user can on their account, with no confirmation (the
// owner's session is the authority): password (any password; the user's
// sessions end, the owner's does not), username, API keys, passkeys,
// recovery codes and the sign-in steps, as well as notes, files and "My
// shares" and the Drive. Impersonation is invisible to the user: their own activity shows
// each action as their own, while the owner-only admin audit keeps the
// start, the end and the real actor. The admin panel, nested impersonation
// and keys for the owner stay out of reach from inside impersonation.
import { describe, it, expect, beforeAll } from 'vitest';
import { env, runInDurableObject } from 'cloudflare:test';
import { owner, makeUser, login, fetchJson, cookieOf, salt16, proofFor, freshIp, ORIGIN, USER_PW, intent, createNote } from './helpers.js';
import { SoftAuthenticator } from './soft-authenticator.js';
import { enableDrive, escrowWrap, mkdir, uploadFile, getChunk, enc, del, KCV } from './drive-helpers.js';
import { encryptPaste } from '../public/js/crypto.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';

let oc;
beforeAll(async () => { oc = await owner(); });

const errorOf = async (r) => (await r.json()).error;
const allowApi = (uid) => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: uid, channel: 'all', patch: { apiEnabled: true, apiMaxKeys: null } } });
const call = (cookie) => (method, path, body) => fetchJson(path, { method, body, cookie, headers: method === 'DELETE' || path.endsWith('/revoke') ? { ...intent } : {}, ip: freshIp() });

/** Log in as `uid`; returns the impersonation cookie. */
async function impersonate(uid) {
  const r = await fetchJson(`/api/private/admin/users/${uid}/impersonate`, { method: 'POST', cookie: oc, headers: intent });
  expect(r.status).toBe(200);
  return cookieOf(r);
}

/** The user's own activity (as the user sees it) and the admin audit for them. */
const ownLog = async (cookie) => (await (await fetchJson('/api/private/me/activity', { cookie })).json()).rows;
const audit = async (uid) => (await (await fetchJson(`/api/private/admin/audit?user=${uid}`, { cookie: oc })).json()).rows;

/**
 * `action`, done by the owner while impersonating, shows in the user's own
 * activity as theirs (no actor, no hint of impersonation), and in the admin
 * audit with the owner as the real actor.
 */
async function loggedAsTheirs(uid, userCookie, action) {
  const mine = (await ownLog(userCookie)).filter((r) => r.action === action);
  for (const row of mine) expect(Object.keys(row).sort(), action).toEqual(['action', 'detail', 'id', 'ts']);
  const byOwner = (await audit(uid)).filter((r) => r.action === action && r.actor === 'owner' && r.imp === 1 && r.adm === 0);
  expect(byOwner.length, action).toBeGreaterThan(0);
  const ids = new Set(mine.map((r) => r.id));
  for (const row of byOwner) expect(ids.has(row.id), action).toBe(true);
}

/** Nothing the user sees mentions impersonation. */
async function invisible(userCookie) {
  const rows = await ownLog(userCookie);
  expect(rows.some((r) => /imperson/i.test(`${r.action} ${r.detail}`))).toBe(false);
  const me = await (await fetchJson('/api/private/me', { cookie: userCookie })).json();
  expect(me.impersonatedBy).toBeNull();
  expect(me.impersonating).toBe(false);
}

describe('while impersonating, the owner changes the account with no confirmation', () => {
  it('username', async () => {
    const u = await makeUser('imp-name');
    const ic = await impersonate(u.id);
    const r = await call(ic)('POST', '/api/private/me/username', { username: 'imp-name-2' });
    expect(r.status).toBe(200);
    expect((await r.json()).username).toBe('imp-name-2');
    const me = await (await fetchJson('/api/private/me', { cookie: ic })).json();
    expect(me).toMatchObject({ user: { username: 'imp-name-2' }, impersonatedBy: 'owner' });
    await loggedAsTheirs(u.id, u.cookie, 'username.changed');
    await invisible(u.cookie);
  });

  it('password: any password, the user\'s sessions end, the owner\'s carries on, passkeys and recovery codes stay', async () => {
    const u = await makeUser('imp-pw');
    // The user has a passkey and recovery codes of their own.
    const auth = new SoftAuthenticator();
    const o = await (await call(u.cookie)('POST', '/api/private/me/passkeys/options', {})).json();
    const added = await call(u.cookie)('POST', '/api/private/me/passkeys', { challengeId: o.challengeId, credential: await auth.create(o.publicKey, ORIGIN), name: 'Own', current: proofFor(USER_PW) });
    expect(added.status).toBe(201);
    const codes = (await added.json()).codes;
    expect(codes).toHaveLength(20);

    const ic = await impersonate(u.id);
    // A one-character password: the policy never applies to a password the owner sets.
    const r = await call(ic)('POST', '/api/private/me/password', { salt: salt16(), t: 3, proof: proofFor('x') });
    expect(r.status).toBe(200);
    expect(await r.json()).toMatchObject({ ok: true, passkeys: 1, recoveryLeft: 20 });
    // No new (non-impersonated) session is handed out.
    expect(r.headers.get('set-cookie')).toBeNull();
    const me = await fetchJson('/api/private/me', { cookie: ic });
    expect(me.status).toBe(200);
    expect((await me.json()).impersonatedBy).toBe('owner');
    // The user's own session ended; the new password works, and so does a recovery code.
    expect((await fetchJson('/api/private/me', { cookie: u.cookie })).status).toBe(401);
    const uc = await login('imp-pw', 'x');
    const rec = await fetchJson('/api/auth/recovery', { method: 'POST', body: { username: 'imp-pw', code: codes[0] }, ip: freshIp() });
    expect(rec.status).toBe(200);
    expect((await (await fetchJson('/api/private/me/passkeys', { cookie: uc })).json()).passkeys).toHaveLength(1);
    await loggedAsTheirs(u.id, uc, 'password.changed');
    await invisible(uc);
  });

  it('API keys: create, change and revoke (keys of the user, never of the owner)', async () => {
    const u = await makeUser('imp-keys');
    await allowApi(u.id);
    const ic = await impersonate(u.id);
    const send = call(ic);
    const c = await send('POST', '/api/private/me/keys', { name: 'cli', scopes: ['notes', 'read'] });
    expect(c.status).toBe(201);
    const { id, key } = await c.json();
    // The key belongs to the user: it lists their shares, and it is no way into the admin panel.
    const n = await createNote(ic, { text: 'x' }, { label: 'by-owner' });
    expect(n.res.status).toBe(201);
    const listed = await fetchJson('/api/private/shares', { headers: { authorization: `Bearer ${key}` } });
    expect((await listed.json()).rows.map((s) => s.id)).toContain(n.id);
    expect((await fetchJson('/api/private/admin/users', { headers: { authorization: `Bearer ${key}` } })).status).toBe(403);
    expect((await (await fetchJson('/api/private/me/keys', { cookie: oc })).json()).keys.map((k) => k.id)).not.toContain(id);
    expect((await send('PATCH', `/api/private/me/keys/${id}`, { name: 'cli-2', scopes: ['notes'] })).status).toBe(200);
    expect((await (await fetchJson('/api/private/me/keys', { cookie: u.cookie })).json()).keys).toMatchObject([{ id, name: 'cli-2', scopes: ['notes'] }]);
    expect((await send('DELETE', `/api/private/me/keys/${id}`, {})).status).toBe(200);
    expect((await (await fetchJson('/api/private/me/keys', { cookie: u.cookie })).json()).keys).toEqual([]);
    for (const action of ['apikey.created', 'apikey.updated', 'apikey.revoked', 'share.created']) await loggedAsTheirs(u.id, u.cookie, action);
    await invisible(u.cookie);
  });

  it('passkeys, recovery codes and the sign-in steps; the new codes go to the owner and existing ones stay', async () => {
    const u = await makeUser('imp-pk');
    const ic = await impersonate(u.id);
    const send = call(ic);
    // A passkey the user already has: never removed unless asked.
    const own = new SoftAuthenticator();
    const o0 = await (await call(u.cookie)('POST', '/api/private/me/passkeys/options', {})).json();
    const first = await call(u.cookie)('POST', '/api/private/me/passkeys', { challengeId: o0.challengeId, credential: await own.create(o0.publicKey, ORIGIN), name: 'Own', current: proofFor(USER_PW) });
    const userCodes = (await first.json()).codes;

    const auth = new SoftAuthenticator();
    const o = await send('POST', '/api/private/me/passkeys/options', {});
    expect(o.status).toBe(200);
    const opt = await o.json();
    expect(opt.publicKey.user.name).toBe('imp-pk');
    const add = await send('POST', '/api/private/me/passkeys', { challengeId: opt.challengeId, credential: await auth.create(opt.publicKey, ORIGIN), name: 'Owner-made' });
    expect(add.status).toBe(201);
    expect((await add.json()).codes).toBeNull(); // the user's codes are left as they are
    let st = await (await fetchJson('/api/private/me/passkeys', { cookie: u.cookie })).json();
    expect(st.passkeys.map((p) => p.name).sort()).toEqual(['Own', 'Owner-made']);
    expect(st.recoveryLeft).toBe(20);

    expect((await send('POST', '/api/private/me/second-factor', { on: true })).status).toBe(200);
    expect((await (await fetchJson('/api/private/me/passkeys', { cookie: u.cookie })).json()).mfa).toBe(true);
    expect((await send('POST', '/api/private/me/second-factor', { on: false })).status).toBe(200);

    const regen = await send('POST', '/api/private/me/recovery-codes', {});
    expect(regen.status).toBe(200);
    const codes = (await regen.json()).codes;
    expect(codes).toHaveLength(20);
    expect(codes).not.toContain(userCodes[0]);

    expect((await send('POST', `/api/private/me/passkeys/${auth.id}/remove`, {})).status).toBe(200);
    st = await (await fetchJson('/api/private/me/passkeys', { cookie: u.cookie })).json();
    expect(st.passkeys.map((p) => p.name)).toEqual(['Own']); // only the one asked for
    expect(st.recoveryLeft).toBe(20);
    // None of it ended the impersonation.
    expect((await (await fetchJson('/api/private/me', { cookie: ic })).json()).impersonatedBy).toBe('owner');
    // The codes the owner was shown work for the user.
    const rec = await fetchJson('/api/auth/recovery', { method: 'POST', body: { username: 'imp-pk', code: codes[0] }, ip: freshIp() });
    expect(rec.status).toBe(200);
    for (const action of ['passkey.added', 'passkey.removed', 'mfa.enabled', 'mfa.disabled']) await loggedAsTheirs(u.id, u.cookie, action);
    // recovery.issued: once by the user (their first passkey), once by the owner.
    const mine = (await ownLog(u.cookie)).filter((r) => r.action === 'recovery.issued');
    expect(mine).toHaveLength(2);
    expect((await audit(u.id)).filter((r) => r.action === 'recovery.issued').map((r) => r.imp)).toEqual([1, 0]);
    await invisible(u.cookie);
  });

  it('shares: create, label, extend, receipts and revoke', async () => {
    const u = await makeUser('imp-shares');
    const ic = await impersonate(u.id);
    const send = call(ic);
    const n = await createNote(ic, { text: 'x' }, { label: 'a' });
    expect(n.res.status).toBe(201);
    expect((await send('PATCH', `/api/private/shares/${n.id}`, { label: 'b', expires: Math.floor(Date.now() / 1000) + 30 * 86400 })).status).toBe(200);
    expect((await send('GET', `/api/private/shares/${n.id}/opens`)).status).toBe(200);
    expect((await send('POST', `/api/private/shares/${n.id}/revoke`, {})).status).toBe(200);
    const row = (await (await fetchJson(`/api/private/shares/${n.id}`, { cookie: u.cookie })).json()).share;
    expect(row).toMatchObject({ label: 'b', status: 'revoked' });
    expect(Object.keys(row)).not.toContain('actor');
    for (const action of ['share.created', 'share.updated', 'share.revoked']) await loggedAsTheirs(u.id, u.cookie, action);
    await invisible(u.cookie);
  });
});

describe('the Drive while impersonating (docs/DRIVE.md §9)', () => {
  /** A Drive share of `nodes` (a refs manifest, as the browser makes one). */
  async function driveShare(cookie, nodes) {
    const manifest = { v: 3, kind: 'refs', entries: nodes.map((id, ref) => ({ path: `f${ref}`, size: 0, type: 'application/octet-stream', mtime: 0, ref, fk: b64urlFromBytes(randomBytes(32)) })), dirs: [] };
    const { body } = await encryptPaste({ text: JSON.stringify(manifest), fmt: 'files', bar: false, expire: '1h' });
    const r = await fetchJson('/api/private/drive/shares', { method: 'POST', cookie, body: { nodes, views: null, expire: '1h', paste: body } });
    expect(r.status).toBe(201);
    return (await r.json()).id;
  }
  const wrap = () => `1.${b64urlFromBytes(randomBytes(12))}.${b64urlFromBytes(randomBytes(60))}`;

  it('folders, uploads, reads, renames, shares and deletes show in the user’s activity as theirs, exactly like their own', async () => {
    const u = await makeUser('imp-drive');
    await enableDrive(u.id);
    const keys = await fetchJson('/api/private/drive/keys', { method: 'PUT', cookie: u.cookie, headers: intent, body: { driveSalt: salt16(), set: [{ kind: 'pw', ref: 'pw', data: wrap() }, await escrowWrap()], escrowPin: enc(40), kcv: KCV } });
    expect(keys.status).toBe(200);
    // What the user does themselves, for comparison.
    const own = await uploadFile(u.cookie, 'root', 20);
    expect((await getChunk(u.cookie, own.id, 0)).status).toBe(200);
    const ownRows = await ownLog(u.cookie);

    const ic = await impersonate(u.id);
    expect((await fetchJson('/api/private/drive/escrow', { method: 'POST', cookie: ic, body: {} })).status).toBe(200);
    const folder = await mkdir(ic);
    expect(folder.res.status).toBe(201);
    const up = await uploadFile(ic, folder.id, 30);
    expect((await getChunk(ic, own.id, 0)).status).toBe(200);
    expect((await fetchJson(`/api/private/drive/nodes/${up.id}`, { method: 'PATCH', cookie: ic, headers: intent, body: { name: enc() } })).status).toBe(200);
    const sid = await driveShare(ic, [up.id]);
    expect((await call(ic)('PATCH', `/api/private/shares/${sid}`, { label: 'drive share' })).status).toBe(200);
    expect((await del(ic, folder.id)).status).toBe(200);
    expect((await fetchJson('/api/private/admin/unimpersonate', { method: 'POST', cookie: ic, headers: intent })).status).toBe(200);

    for (const action of ['drive.folder_created', 'drive.file_uploaded', 'drive.file_read', 'drive.item_changed', 'share.created', 'share.updated', 'share.revoked', 'drive.item_deleted']) {
      await loggedAsTheirs(u.id, u.cookie, action);
    }
    await invisible(u.cookie);
    // Rows done as the user look exactly like the user's own: same actions,
    // same detail format, no escrow use (the owner's key, admin audit only).
    const rows = (await ownLog(u.cookie)).filter((r) => !ownRows.some((x) => x.id === r.id));
    expect(rows.some((r) => /escrow|owner/i.test(`${r.action} ${r.detail}`))).toBe(false);
    const fmt = (r) => `${r.action} ${r.detail.replace(/[A-Za-z0-9_-]{22}/g, '<id>')}`;
    const byOwnerRead = rows.find((r) => r.action === 'drive.file_read');
    const byUserRead = ownRows.find((r) => r.action === 'drive.file_read');
    expect(fmt(byOwnerRead)).toBe(fmt(byUserRead));
    expect(fmt(rows.find((r) => r.action === 'drive.file_uploaded'))).toBe(fmt(ownRows.find((r) => r.action === 'drive.file_uploaded')));
    const esc = (await audit(u.id)).filter((r) => r.action === 'drive.escrow_used');
    expect(esc).toHaveLength(1);
    expect(esc[0]).toMatchObject({ actor: 'owner', imp: 1, adm: 1 });
  });
});

describe('what stays out of reach while impersonating', () => {
  it('the admin panel, nested impersonation and a passkey confirmation', async () => {
    const u = await makeUser('imp-limits');
    const v = await makeUser('imp-limits-2');
    const ic = await impersonate(u.id);
    expect(await errorOf(await fetchJson('/api/private/admin/users', { cookie: ic }))).toBe('impersonating');
    expect(await errorOf(await fetchJson(`/api/private/admin/users/${v.id}/impersonate`, { method: 'POST', cookie: ic, headers: intent }))).toBe('impersonating');
    const me = await (await fetchJson('/api/private/me', { cookie: oc })).json();
    expect(await errorOf(await fetchJson(`/api/private/admin/users/${me.user.id}/keys`, { method: 'POST', cookie: ic, body: { name: 'x' } }))).toBe('impersonating');
    // Nothing is confirmed while impersonating, so there is no challenge to ask for.
    expect(await errorOf(await call(ic)('POST', '/api/private/me/reauth', {}))).toBe('not_needed');
  });

  it('the Directory accepts "no confirmation" only from the enabled owner impersonating someone else', async () => {
    const u = await makeUser('imp-forged');
    const v = await makeUser('imp-forged-2');
    const me = await (await fetchJson('/api/private/me', { cookie: oc })).json();
    const dir = env.DIRECTORY.get(env.DIRECTORY.idFromName('directory'));
    await runInDurableObject(dir, async (instance) => {
      // Another user posing as the impersonator, or the owner "impersonating" themselves: refused.
      for (const [uid, actorId] of [[u.id, { id: v.id, imp: true }], [me.user.id, { id: me.user.id, imp: true }], [u.id, { id: me.user.id }]]) {
        expect((await instance.changeUsername(uid, { username: 'nope-name', actorId })).status).toBe(403);
        expect((await instance.regenerateRecoveryCodes(uid, { actorId })).status).toBe(403);
        expect((await instance.createKey(uid, { name: 'k', hash: 'a'.repeat(64), expires: null, actorId })).status).toBe(403);
      }
      // Without an impersonating actor, the step-up still applies.
      expect((await instance.changeUsername(u.id, { username: 'nope-name' })).error).toBe('wrong_password');
    });
  });

  it('admin actions on the user (created, disabled, enabled) are in the admin audit only', async () => {
    const u = await makeUser('adm-invisible');
    for (const disabled of [true, false]) {
      expect((await fetchJson(`/api/private/admin/users/${u.id}`, { method: 'PATCH', cookie: oc, body: { disabled } })).status).toBe(200);
    }
    const uc = await login('adm-invisible', USER_PW, freshIp());
    const own = (await ownLog(uc)).map((r) => r.action);
    expect(own).toContain('login');
    for (const a of ['user.created', 'user.disabled', 'user.enabled']) expect(own).not.toContain(a);
    const actions = (await audit(u.id)).map((r) => r.action);
    for (const a of ['user.created', 'user.disabled', 'user.enabled']) expect(actions).toContain(a);
  });

  it('start and end are in the admin audit only', async () => {
    const u = await makeUser('imp-audit');
    const ic = await impersonate(u.id);
    expect((await fetchJson('/api/private/admin/unimpersonate', { method: 'POST', cookie: ic, headers: intent })).status).toBe(200);
    const actions = (await audit(u.id)).map((r) => r.action);
    expect(actions).toContain('impersonate.start');
    expect(actions).toContain('impersonate.end');
    await invisible(u.cookie);
  });
});
