// receive-api.test.js — Receive links (reverse shares, docs/REVERSE.md) through
// /api/private/receive (docs/API.md), in workerd: the routes and their scopes
// (read / manage), the role options (reverseEnabled, apiEnabled, the API
// limits of the kinds and reverseEdit), the step-up rule for weakening
// changes (403 step_up_required for a key), no creation with a key; pause and
// resume (uploads stop, open sessions end, unfinished uploads go, the Guard
// does not count a visitor with the right link); receipts, one per upload
// session, with the visibility rules of regular receipts; and moving a link to
// another folder of the user's Drive (the depth rule, folders not the
// user's, deleted or not folders, the waiting items moving with it, the log).
// Synthetic data only.
import { runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll, vi } from 'vitest';
import { env } from 'cloudflare:test';
import { owner, makeUser, fetchJson, intent, freshIp, proofFor, USER_PW, cookieOf } from './helpers.js';
import { mkdir, uploadFile, del } from './drive-helpers.js';
import { changeReverse } from '../src/routes/reverse.js';
import { randomBytes, b64urlFromBytes } from '../public/js/bytes.js';
import { invalidateGuardCaches } from '../src/lib/guard.js';
import { dirStub, driveOf, errorOf, receiver, newReverse, rv, openLink, begin, grantOf, send, reserve, received, takeInAny, putChunk } from './reverse-helpers.js';
import { createReverseKey, linkProof, passwordProof } from '../public/js/reversekeys.js';

vi.setConfig({ testTimeout: 60000 });

let oc;
beforeAll(async () => { oc = await owner(); });

const CONFIRM = { current: proofFor(USER_PW) };
const bearer = (k) => ({ authorization: `Bearer ${k}` });
const limits = (scope, patch, channel = 'all') => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope, channel, patch } });
const audit = async (subject) => (await (await fetchJson(`/api/private/admin/audit?user=${subject}`, { cookie: oc })).json()).rows;
const mkKey = async (u, scopes) => {
  const r = await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { name: scopes.join('-') || 'default', ...(scopes.length ? { scopes } : {}), ...CONFIRM } });
  expect(r.status).toBe(201);
  return (await r.json()).key;
};
/** A user who may receive files and use API keys, with a "read" and a "manage" key. */
async function apiReceiver(name, extra = {}) {
  const u = await receiver(name, { apiEnabled: true, ...extra });
  return { ...u, read: await mkKey(u, ['read']), manage: await mkKey(u, ['manage']) };
}
const R = (id = '', sub = '') => `/api/private/receive${id ? `/${id}` : ''}${sub}`;
const driveRow = (uid, id) => runInDurableObject(driveOf(uid), (i, s) => s.storage.sql.exec('SELECT * FROM reverse WHERE id = ?', id).toArray()[0]);
const nodeRow = (uid, id) => runInDurableObject(driveOf(uid), (i, s) => s.storage.sql.exec('SELECT * FROM nodes WHERE id = ?', id).toArray()[0]);
const dirRow = (id) => runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('SELECT * FROM shares WHERE id = ?', id).toArray()[0]);
const folderLinks = async (cookie, folder) => (await (await fetchJson(`/api/private/drive/reverse?folder=${folder}`, { cookie })).json()).reverse.map((x) => x.id);

describe('the Receive links API: routes and scopes', () => {
  it('lists and shows the caller’s links with "read", never their key, note or password', async () => {
    const u = await apiReceiver('ra-list');
    const r = await newReverse(u.cookie, { label: 'tax papers', note: 'please send the forms', password: 'uploader pw' });
    expect(r.res.status).toBe(201);
    const other = await apiReceiver('ra-list-other');
    const o = await newReverse(other.cookie, {});

    const res = await fetchJson(R(), { headers: bearer(u.read) });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.total).toBe(1);
    expect(body.rows).toHaveLength(1);
    const link = body.rows[0];
    expect(link).toMatchObject({ id: r.id, label: 'tax papers', status: 'active', paused: false, held: false, folder: 'root', accept: ['files'],
      password: true, note: true, captcha: true, views: null, used: 0, opens: 0, received: { files: 0, bytes: 0 }, pending: 0, failed: 0 });
    expect(link.expires).toBeGreaterThan(Math.floor(Date.now() / 1000));
    // Only whether it has a key, note or password: never the values.
    const text = JSON.stringify(body);
    for (const k of ['priv', 'mek', 'lh', 'ph', 'salt']) expect(Object.keys(link)).not.toContain(k);
    expect(text).not.toContain(r.body.priv.ct);
    expect(text).not.toContain(r.body.note.ct);
    expect(text).not.toContain(r.body.password.ph);
    // One link; another user's is not found (as any unknown id), nor is a regular share.
    expect(await (await fetchJson(R(r.id), { headers: bearer(u.read) })).json()).toEqual({ link });
    expect((await fetchJson(R(o.id), { headers: bearer(u.read) })).status).toBe(404);
    expect((await fetchJson(R('kAAAAAAAAAAAAAAAAAAAAAA'), { headers: bearer(u.read) })).status).toBe(404);
    expect((await fetchJson(R('not-an-id'), { headers: bearer(u.read) })).status).toBe(404);
    // The same for a session (My shares' own calls).
    expect((await (await fetchJson(R(), { cookie: u.cookie })).json()).rows.map((x) => x.id)).toEqual([r.id]);
    // Filters: status, label.
    expect((await (await fetchJson(`${R()}?status=revoked`, { headers: bearer(u.read) })).json()).total).toBe(0);
    expect((await (await fetchJson(`${R()}?q=nothing-like-it`, { headers: bearer(u.read) })).json()).total).toBe(0);
  });

  it('holds each route to its scope, and a key to the account’s API use', async () => {
    const u = await apiReceiver('ra-scopes');
    const creator = await mkKey(u, []); // notes, files, policy: creation only
    const r = await newReverse(u.cookie, {});
    const scope = async (res, s) => { expect(res.status).toBe(403); expect(await res.json()).toMatchObject({ error: 'scope_denied' }); expect(s).toBeTruthy(); };
    for (const key of [creator, u.manage]) {
      await scope(await fetchJson(R(), { headers: bearer(key) }), 'read');
      await scope(await fetchJson(R(r.id), { headers: bearer(key) }), 'read');
      await scope(await fetchJson(R(r.id, '/opens'), { headers: bearer(key) }), 'read');
    }
    for (const key of [creator, u.read]) {
      await scope(await fetchJson(R(r.id), { method: 'PATCH', headers: bearer(key), body: { label: 'x' } }), 'manage');
      for (const sub of ['/pause', '/resume', '/revoke']) await scope(await fetchJson(R(r.id, sub), { method: 'POST', headers: { ...bearer(key), ...intent } }), 'manage');
    }
    // No creation through a key: the list takes GET only, and the Drive's create route refuses keys.
    expect((await fetchJson(R(), { method: 'POST', headers: bearer(u.manage), body: {} })).status).toBe(405);
    const c = await fetchJson('/api/private/drive/reverse', { method: 'POST', headers: { ...bearer(u.manage), ...intent }, body: {} });
    expect(c.status).toBe(403);
    expect(await errorOf(c)).toBe('api_key_not_allowed');
    // A change needs the intent header (as revoke on /shares).
    expect(await errorOf(await fetchJson(R(r.id, '/pause'), { method: 'POST', headers: bearer(u.manage) }))).toBe('missing_intent');
    // API use turned off: the keys stop at once.
    expect((await limits(u.id, { apiEnabled: false })).status).toBe(200);
    const off = await fetchJson(R(), { headers: bearer(u.read) });
    expect(off.status).toBe(401);
    expect(await errorOf(off)).toBe('invalid_api_key');
  });

  it('needs a role with reverse shares, for keys and sessions alike', async () => {
    const u = await apiReceiver('ra-role');
    const r = await newReverse(u.cookie, {});
    expect((await limits(u.id, { reverseEnabled: false })).status).toBe(200);
    for (const init of [{ headers: bearer(u.read) }, { cookie: u.cookie }]) {
      const res = await fetchJson(R(), init);
      expect(res.status).toBe(403);
      expect(await errorOf(res)).toBe('reverse_disabled');
    }
    expect(await errorOf(await fetchJson(R(r.id, '/pause'), { method: 'POST', headers: { ...bearer(u.manage), ...intent } }))).toBe('reverse_disabled');
    const noDrive = await makeUser('ra-role-none');
    expect((await limits(noDrive.id, { apiEnabled: true })).status).toBe(200);
    const k = await mkKey(noDrive, ['read']);
    expect(await errorOf(await fetchJson(R(), { headers: bearer(k) }))).toBe('reverse_disabled');
  });

  it('changes a link with "manage" as My shares does: weakening needs the browser (403 step_up_required); the role and API limits apply', async () => {
    const u = await apiReceiver('ra-change', { reverseNoExpiry: true, reverseCaptcha: 'allow', reverseUrl: true });
    const r = await newReverse(u.cookie, { views: 5, captcha: false, password: 'first pw', accept: ['files', 'note'] });
    const patch = (body) => fetchJson(R(r.id), { method: 'PATCH', headers: bearer(u.manage), body });
    // Tightening works: label, fewer views, limits, the CAPTCHA on, fewer kinds.
    const t = await patch({ label: 'via the API', views: 3, maxFiles: 4, captcha: true, accept: ['files'] });
    expect(t.status).toBe(200);
    expect(await t.json()).toMatchObject({ ok: true, views: 3, accept: ['files'], folder: 'root' });
    // Weakening never does: no expiry, unlimited views, the CAPTCHA off, the password removed, a kind added.
    for (const [body, weak] of [[{ expires: null }, 'expires'], [{ views: null }, 'views'], [{ captcha: false }, 'captcha'], [{ password: null }, 'password'], [{ accept: ['files', 'url'] }, 'accept']]) {
      const w = await patch(body);
      expect(w.status, weak).toBe(403);
      expect(await w.json(), weak).toMatchObject({ error: 'step_up_required', weakens: [weak] });
    }
    // Even with the password proof in the body.
    expect(await errorOf(await patch({ captcha: false, ...CONFIRM }))).toBe('step_up_required');
    const row = await driveRow(u.id, r.id);
    expect(row.views).toBe(3);
    expect(row.captcha).toBe(1);
    expect(row.ph).toBeTruthy();
    // The API limits of the role: a kind the key may not add, and no reverseEdit for keys.
    expect((await limits(u.id, { reverseText: false }, 'api')).status).toBe(200);
    expect(await errorOf(await patch({ accept: ['files', 'note'] }))).toBe('receive_kind_disabled');
    expect((await limits(u.id, { reverseEdit: false }, 'api')).status).toBe(200);
    expect(await errorOf(await patch({ maxFiles: 2 }))).toBe('reverse_edit_disabled');
    // The label (as on /shares) and pausing stay allowed.
    expect((await patch({ label: 'still' })).status).toBe(200);
    expect((await fetchJson(R(r.id, '/pause'), { method: 'POST', headers: { ...bearer(u.manage), ...intent } })).status).toBe(200);
    // The session keeps its own options (the API limits are for keys only).
    expect((await fetchJson(R(r.id), { method: 'PATCH', cookie: u.cookie, body: { maxFiles: 2 } })).status).toBe(200);
    // Every change made with the key names it (never the key itself).
    const log = await audit(u.id);
    const byKey = log.filter((e) => e.action === 'share.updated' && e.detail.startsWith(`id=${r.id}`) && /apikey=/.test(e.detail));
    expect(byKey.length).toBeGreaterThanOrEqual(3);
    expect(JSON.stringify(log)).not.toContain(u.manage);
  });

  it('revokes a link with "manage"; a locked one cannot be changed, paused or revoked', async () => {
    const u = await apiReceiver('ra-revoke');
    const a = await newReverse(u.cookie, {});
    const b = await newReverse(u.cookie, {});
    // Locked by the owner: 423 for every change.
    expect((await fetchJson(`/api/private/admin/shares/${b.id}/lock`, { method: 'POST', cookie: oc, body: { locked: true } })).status).toBe(200);
    for (const [path, init] of [[R(b.id), { method: 'PATCH', body: { label: 'x' } }], [R(b.id, '/pause'), { method: 'POST', headers: intent }], [R(b.id, '/revoke'), { method: 'POST', headers: intent }]]) {
      const res = await fetchJson(path, { ...init, headers: { ...bearer(u.manage), ...(init.headers || {}) } });
      expect(res.status, path).toBe(423);
    }
    const res = await fetchJson(R(a.id, '/revoke'), { method: 'POST', headers: { ...bearer(u.manage), ...intent } });
    expect(res.status).toBe(200);
    expect((await (await fetchJson(R(a.id), { headers: bearer(u.read) })).json()).link.status).toBe('revoked');
    expect((await openLink(a, freshIp())).status).toBe(410);
    // An ended link can be neither paused nor resumed.
    expect(await errorOf(await fetchJson(R(a.id, '/pause'), { method: 'POST', headers: { ...bearer(u.manage), ...intent } }))).toBe('not_active');
    expect((await audit(u.id)).some((e) => e.action === 'share.revoked' && e.detail.startsWith(`id=${a.id}`) && e.detail.includes('apikey='))).toBe(true);
  });
});

describe('the session path: CSRF, intent and origin', () => {
  it('a change without the session’s token, from another site or without the intent is refused, and nothing changes', async () => {
    const u = await receiver('ra-csrf');
    const a = await mkdir(u.cookie, 'root');
    const r = await newReverse(u.cookie, {});
    const tries = [
      [R(r.id, '/pause'), { method: 'POST', headers: intent }], [R(r.id, '/revoke'), { method: 'POST', headers: intent }],
      [R(r.id), { method: 'PATCH', body: { folder: a.id, label: 'x' } }],
    ];
    for (const [path, init] of tries) {
      const res = await fetchJson(path, { ...init, cookie: u.cookie, csrf: false, headers: { ...(init.headers || {}), 'x-secbin-csrf': 'A'.repeat(43) } });
      expect(`${path} ${res.status} ${await errorOf(res)}`).toBe(`${path} 403 csrf_mismatch`);
      const cross = await fetchJson(path, { ...init, cookie: u.cookie, headers: { ...(init.headers || {}), 'sec-fetch-site': 'cross-site' } });
      expect(cross.status, path).toBe(403);
    }
    expect(await errorOf(await fetchJson(R(r.id, '/resume'), { method: 'POST', cookie: u.cookie }))).toBe('missing_intent');
    expect(await driveRow(u.id, r.id)).toMatchObject({ held: null, folder: 'root', status: 'active' });
    expect((await (await fetchJson(R(r.id), { cookie: u.cookie })).json()).link).toMatchObject({ label: '', status: 'active', paused: false });
  });
});

describe('pause and resume', () => {
  it('a paused link takes no session; its open sessions end and unfinished uploads go; resumed, it takes uploads again', async () => {
    const u = await apiReceiver('ra-pause');
    const r = await newReverse(u.cookie, {});
    const ip = freshIp();
    // A finished file, and a session with a file reserved but not finished.
    const g1 = await grantOf(r, { ip });
    await send(r, g1, { ip });
    const g2 = await grantOf(r, { ip });
    const half = await reserve(r, g2, { ip, path: 'half.txt' });
    expect(half.res.status).toBe(201);
    expect((await driveRow(u.id, r.id)).files).toBe(2);

    const p = await fetchJson(R(r.id, '/pause'), { method: 'POST', headers: { ...bearer(u.manage), ...intent } });
    expect(p.status).toBe(200);
    expect(await p.json()).toEqual({ ok: true, paused: true });
    // The uploader: 409 paused on open and begin (the link proof matched), no grant for a session begun before.
    expect(await errorOf(await openLink(r, ip))).toBe('paused');
    expect(await errorOf(await begin(r, { ip }))).toBe('paused');
    // A grant it gave before the pause: 409 paused (a late request, not a guess).
    expect(await errorOf(await reserve(r, g1, { ip }).then((x) => x.res))).toBe('paused');
    // The unfinished upload was deleted and its reservation given back; the finished file stays.
    expect(await nodeRow(u.id, half.node)).toBeUndefined();
    expect((await driveRow(u.id, r.id)).files).toBe(1);
    expect((await received(u.cookie)).items).toHaveLength(1);
    // Taking in what it received still works while it is paused.
    const item = (await received(u.cookie)).items[0];
    expect((await takeInAny(u.cookie, item.id)).status).toBe(200);
    // My shares, the Drive's list and the API show it paused by the user (resumable).
    const mine = (await (await fetchJson('/api/private/shares', { cookie: u.cookie })).json()).rows.find((x) => x.id === r.id);
    expect(mine).toMatchObject({ status: 'active', paused: true, held: true });
    expect((await (await fetchJson('/api/private/drive/reverse', { cookie: u.cookie })).json()).reverse.find((x) => x.id === r.id)).toMatchObject({ status: 'paused', held: true });
    expect((await (await fetchJson(R(r.id), { headers: bearer(u.read) })).json()).link).toMatchObject({ status: 'active', paused: true, held: true });
    // Pausing again changes nothing; resuming (a session here, with the step-up) opens it again.
    expect(await (await fetchJson(R(r.id, '/pause'), { method: 'POST', cookie: u.cookie, headers: intent })).json()).toEqual({ ok: true, paused: true });
    expect(await (await fetchJson(R(r.id, '/resume'), { method: 'POST', cookie: u.cookie, headers: intent, body: CONFIRM })).json()).toEqual({ ok: true, paused: false });
    expect((await openLink(r, ip)).status).toBe(200);
    expect((await begin(r, { ip })).status).toBe(200);
    expect((await (await fetchJson(R(r.id), { headers: bearer(u.read) })).json()).link).toMatchObject({ paused: false, held: false });
    // Both are in the log.
    const log = await audit(u.id);
    expect(log.some((e) => e.action === 'share.updated' && e.detail.startsWith(`id=${r.id}`) && / paused( |$)/.test(e.detail) && e.detail.includes('apikey='))).toBe(true);
    expect(log.some((e) => e.action === 'share.updated' && e.detail.startsWith(`id=${r.id}`) && / resumed( |$)/.test(e.detail))).toBe(true);
  });

  it('a visitor with the right link is not counted by the Guard while it is paused; a wrong link is', async () => {
    const u = await receiver('ra-pause-guard');
    const r = await newReverse(u.cookie, {});
    expect((await fetchJson(R(r.id, '/pause'), { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(200);
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.invalid.max': 3 } });
    invalidateGuardCaches();
    try {
      const ip = freshIp();
      for (let i = 0; i < 6; i++) {
        expect((await openLink(r, ip)).status).toBe(409);
        expect((await begin(r, { ip })).status).toBe(409);
      }
      const other = await createReverseKey();
      const codes = [];
      for (let i = 0; i < 3; i++) codes.push((await openLink(r, ip, other.pub)).status);
      expect(codes).toEqual([403, 403, 429]);
    } finally {
      await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.invalid.max': 60 } });
      invalidateGuardCaches();
    }
  });

  it('a pause spends no quota and needs no reverseEdit; a link the owner’s start over paused cannot be resumed', async () => {
    const u = await receiver('ra-pause-rules', { reverseEdit: false });
    const r = await newReverse(u.cookie, {});
    expect((await fetchJson(R(r.id, '/pause'), { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(200);
    expect((await fetchJson(R(r.id, '/resume'), { method: 'POST', cookie: u.cookie, headers: intent, body: CONFIRM })).status).toBe(200);
    // Resuming a link that is not paused changes nothing (and asks for nothing).
    expect(await (await fetchJson(R(r.id, '/resume'), { method: 'POST', cookie: u.cookie, headers: intent })).json()).toEqual({ ok: true, paused: false });
    // Paused by the release before's start over (status 'paused' in its Drive): not the user's pause.
    await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec("UPDATE reverse SET status = 'paused' WHERE id = ?", r.id));
    expect(await errorOf(await fetchJson(R(r.id, '/resume'), { method: 'POST', cookie: u.cookie, headers: intent }))).toBe('not_paused');
    expect((await fetchJson(R(r.id), { cookie: u.cookie })).status).toBe(200);
    expect((await (await fetchJson(R(r.id), { cookie: u.cookie })).json()).link).toMatchObject({ paused: true, held: false });
  });
});

describe('pause and resume: the step-up, and late uploaders never counted', () => {
  it('resuming reopens the link: the step-up for a session (none while the owner acts as the user), never with a key; pausing needs none', async () => {
    const u = await apiReceiver('ra-resume-step');
    const r = await newReverse(u.cookie, {});
    const pauseKey = await fetchJson(R(r.id, '/pause'), { method: 'POST', headers: { ...bearer(u.manage), ...intent } });
    expect(pauseKey.status).toBe(200);
    // An API key cannot resume it, whatever it sends.
    for (const body of [undefined, CONFIRM]) {
      const k = await fetchJson(R(r.id, '/resume'), { method: 'POST', headers: { ...bearer(u.manage), ...intent }, body });
      expect(k.status).toBe(403);
      expect(await k.json()).toMatchObject({ error: 'step_up_required', weakens: ['paused'] });
    }
    // A session: the password proof or a passkey.
    expect(await errorOf(await fetchJson(R(r.id, '/resume'), { method: 'POST', cookie: u.cookie, headers: intent }))).toBe('reauth_required');
    expect(await errorOf(await fetchJson(R(r.id, '/resume'), { method: 'POST', cookie: u.cookie, headers: intent, body: { current: proofFor('not the password') } }))).toBe('wrong_password');
    expect((await driveRow(u.id, r.id)).held).toBeTruthy(); // still paused
    expect((await openLink(r, freshIp())).status).toBe(409);
    expect((await fetchJson(R(r.id, '/resume'), { method: 'POST', cookie: u.cookie, headers: intent, body: CONFIRM })).status).toBe(200);
    expect((await openLink(r, freshIp())).status).toBe(200);
    // The owner acting as the user confirms nothing.
    expect((await fetchJson(R(r.id, '/pause'), { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(200);
    const ic = cookieOf(await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
    expect((await fetchJson(R(r.id, '/resume'), { method: 'POST', cookie: ic, headers: intent })).status).toBe(200);
    expect((await driveRow(u.id, r.id)).held).toBeNull();
  });

  it('an uploader mid-upload is never blocked by a pause or a revoke; after resume it sends again; forged grants still count', async () => {
    const u = await receiver('ra-late');
    const r = await newReverse(u.cookie, {});
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    const f = await reserve(r, g, { ip, path: 'big.txt' });
    expect(f.res.status).toBe(201);
    const g2 = await grantOf(r, { ip }); // a session that has sent nothing yet
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.invalid.max': 3 } });
    invalidateGuardCaches();
    try {
      const H = (grant, token) => ({ 'x-reverse-grant': grant, ...(token ? { 'x-upload-token': token } : {}) });
      const late = async (grant, token, node) => [
        (await rv(r.id, '/files', { headers: H(grant), body: { id: 'A'.repeat(22), name: { iv: 'A'.repeat(16), ct: 'A'.repeat(40) }, meta: { iv: 'A'.repeat(16), ct: 'A'.repeat(40) }, size: 1, wrap: `1.${'A'.repeat(87)}.${'A'.repeat(16)}.${'A'.repeat(107)}` }, ip })).status,
        (await rv(r.id, `/files/${node}/finalize`, { headers: H(grant, token), ip })).status,
        (await putChunk(r.id, node, 0, new Uint8Array(27), token, ip)).status,
        (await rv(r.id, `/files/${node}`, { method: 'DELETE', headers: H(grant, token), ip })).status,
        (await rv(r.id, '/done', { headers: H(grant), ip })).status,
      ];
      // Paused under it: every late request is answered, none counted (the Guard allows 3).
      expect((await fetchJson(R(r.id, '/pause'), { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(200);
      for (let i = 0; i < 3; i++) {
        const codes = await late(g, f.data.uploadToken, f.node);
        expect(codes.every((c) => c === 409 || c === 410), JSON.stringify(codes)).toBe(true);
        expect((await rv(r.id, '/done', { headers: H(g2), ip })).status).toBe(409);
      }
      expect(await errorOf(await rv(r.id, '/done', { headers: H(g), ip }))).toBe('paused');
      // A forged grant is a guess (another network, so this one stays free).
      const other = freshIp();
      const forged = [];
      for (let i = 0; i < 3; i++) forged.push((await rv(r.id, '/done', { headers: H(b64urlFromBytes(randomBytes(32))), ip: other })).status);
      expect(forged).toEqual([403, 403, 429]);
      // Resumed: the uploader's network is not blocked, it starts again and sends.
      expect((await fetchJson(R(r.id, '/resume'), { method: 'POST', cookie: u.cookie, headers: intent, body: CONFIRM })).status).toBe(200);
      expect((await openLink(r, ip)).status).toBe(200);
      const g3 = await grantOf(r, { ip });
      await send(r, g3, { ip, path: 'after.txt' });
      // An old grant after the resume: its session ended (403), still not counted.
      for (let i = 0; i < 4; i++) expect((await rv(r.id, '/done', { headers: H(g), ip })).status).toBe(403);
      // Mid-upload during a revoke: the same, with 410.
      const f4 = await reserve(r, g3, { ip, path: 'cut.txt' });
      expect(f4.res.status).toBe(201);
      expect((await fetchJson(R(r.id, '/revoke'), { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(200);
      for (let i = 0; i < 3; i++) {
        const codes = await late(g3, f4.data.uploadToken, f4.node);
        expect(codes, JSON.stringify(codes)).toEqual([410, 410, 410, 410, 410]);
        expect((await openLink(r, ip)).status).toBe(410);
      }
      // Still not blocked: another link opens from this network.
      const r2 = await newReverse(u.cookie, {});
      expect((await openLink(r2, ip)).status).toBe(200);
      // A forged grant on the revoked link is a guess.
      const other2 = freshIp();
      const forged2 = [];
      for (let i = 0; i < 3; i++) forged2.push((await rv(r.id, '/done', { headers: H(b64urlFromBytes(randomBytes(32))), ip: other2 })).status);
      expect(forged2).toEqual([410, 410, 429]);
    } finally {
      await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.invalid.max': 60 } });
      invalidateGuardCaches();
    }
  });

  it('revoking needs no role option (as /shares/<id>/revoke); the other routes do', async () => {
    const u = await apiReceiver('ra-revoke-role');
    const a = await newReverse(u.cookie, {});
    const b = await newReverse(u.cookie, {});
    expect((await limits(u.id, { reverseEnabled: false })).status).toBe(200);
    expect(await errorOf(await fetchJson(R(a.id, '/pause'), { method: 'POST', headers: { ...bearer(u.manage), ...intent } }))).toBe('reverse_disabled');
    const k = await fetchJson(R(a.id, '/revoke'), { method: 'POST', headers: { ...bearer(u.manage), ...intent } });
    expect(k.status).toBe(200);
    const c = await fetchJson(R(b.id, '/revoke'), { method: 'POST', cookie: u.cookie, headers: intent });
    expect(c.status).toBe(200);
    expect((await dirRow(a.id)).status).toBe('revoked');
    expect((await dirRow(b.id)).status).toBe('revoked');
    // Its scope, intent and CSRF checks stay.
    expect(await errorOf(await fetchJson(R(a.id, '/revoke'), { method: 'POST', headers: { ...bearer(u.read), ...intent } }))).toBe('scope_denied');
    expect(await errorOf(await fetchJson(R(a.id, '/revoke'), { method: 'POST', headers: bearer(u.manage) }))).toBe('missing_intent');
    expect(await errorOf(await fetchJson(R(b.id, '/revoke'), { method: 'POST', cookie: u.cookie, csrf: false, headers: { ...intent, 'x-secbin-csrf': 'A'.repeat(43) } }))).toBe('csrf_mismatch');
  });

  it('one link is read on its own (reverseLinks), not with all the user’s links', async () => {
    const u = await receiver('ra-one');
    const a = await newReverse(u.cookie, {});
    const b = await newReverse(u.cookie, {});
    const got = await driveOf(u.id).reverseLinks(u.id, [a.id]);
    expect(got.reverse.map((x) => x.id)).toEqual([a.id]);
    expect(got.reverse[0].priv).toBeUndefined();
    expect((await driveOf(u.id).reverseLinks(u.id, [])).reverse).toEqual([]);
    expect((await (await fetchJson(R(b.id), { cookie: u.cookie })).json()).link.id).toBe(b.id);
  });
});

describe('receipts: one per upload session', () => {
  it('records each session started, with the details the admin lets the user see; a failed start is none', async () => {
    const u = await apiReceiver('ra-receipts');
    const r = await newReverse(u.cookie, { password: 'right one' });
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';
    // A wrong password: no session, no receipt.
    const wrong = await begin(r, { password: 'not it', ip: freshIp() });
    expect(await errorOf(wrong)).toBe('bad_password');
    expect((await (await fetchJson(R(r.id, '/opens'), { headers: bearer(u.read) })).json()).total).toBe(0);
    // Two sessions from two networks (as the uploader's browser: its user agent and languages).
    for (const ip of ['198.51.100.221', '198.51.100.222']) {
      const head = await (await openLink(r, ip)).json();
      const res = await rv(r.id, '/begin', { ip, headers: { 'x-link-proof': await linkProof(r.pub), 'x-key-proof': await passwordProof('right one', head.password.salt, head.password.t, r.pub), 'user-agent': ua, 'accept-language': 'he-IL,he;q=0.9,en-US;q=0.8' } });
      expect(res.status).toBe(200);
    }
    // Opening the page is not a session: still two.
    expect((await openLink(r, freshIp())).status).toBe(200);
    const mine = await (await fetchJson(R(r.id, '/opens'), { headers: bearer(u.read) })).json();
    expect(mine.total).toBe(2);
    expect(mine.fields).toEqual([]);
    expect(Object.keys(mine.rows[0])).toEqual(['ts']); // times only by default, as regular receipts
    // The same receipts through /shares (My shares) and in the lists' counts.
    expect(await (await fetchJson(`/api/private/shares/${r.id}/opens`, { cookie: u.cookie })).json()).toEqual(mine);
    expect((await (await fetchJson('/api/private/shares', { cookie: u.cookie })).json()).rows.find((x) => x.id === r.id).opens).toBe(2);
    expect((await (await fetchJson(R(r.id), { headers: bearer(u.read) })).json()).link.opens).toBe(2);
    // The admin lets the user see more.
    expect((await limits(u.id, { receiptBrowser: true, receiptLanguages: true })).status).toBe(200);
    const more = await (await fetchJson(R(r.id, '/opens'), { headers: bearer(u.read) })).json();
    expect(more.fields).toEqual(['receiptBrowser', 'receiptLanguages']);
    expect(more.rows[0]).toMatchObject({ browser: 'Chrome', browser_ver: '140', langs: 'he-IL, he, en-US' });
    expect(more.rows[0].ip).toBeUndefined();
    // The owner sees everything, in Admin → Shares as for every share.
    const adm = await (await fetchJson(`/api/private/admin/shares/${r.id}/opens`, { cookie: oc })).json();
    expect(adm.rows[0]).toMatchObject({ ip: '198.51.100.222', browser: 'Chrome', os: 'Windows 10/11' });
    expect((await (await fetchJson(`/api/private/admin/shares?q=`, { cookie: oc })).json()).rows.find((x) => x.id === r.id).opens).toBe(2);
    // Kept in the Directory's receipts (`opens`), so their limits and retention are those of every receipt:
    const rows = await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('SELECT user_id FROM opens WHERE share_id = ?', r.id).toArray());
    expect(rows).toEqual([{ user_id: u.id }, { user_id: u.id }]);
    // clearing the user's log clears them.
    const c = await fetchJson('/api/private/admin/logs/clear', { method: 'POST', cookie: oc, body: { current: proofFor('owner-password'), scope: 'user', user: u.id } });
    expect((await c.json()).receipts).toBe(2);
    expect((await (await fetchJson(R(r.id, '/opens'), { headers: bearer(u.read) })).json()).total).toBe(0);
    // Another user's link: not found.
    const other = await apiReceiver('ra-receipts-other');
    expect((await fetchJson(R(r.id, '/opens'), { headers: bearer(other.read) })).status).toBe(404);
  });

  it('are throttled as regular receipts: repeat sessions from one address are counted, stored once a minute', async () => {
    const u = await receiver('ra-receipts-repeat');
    const r = await newReverse(u.cookie, {});
    const ip = freshIp();
    for (let i = 0; i < 3; i++) expect((await begin(r, { ip })).status).toBe(200);
    const d = await (await fetchJson(R(r.id, '/opens'), { cookie: u.cookie })).json();
    expect(d.total).toBe(3);
    expect(d.rows).toHaveLength(1);
  });
});

describe('moving a link to another folder', () => {
  it('moves it, with what it received and has not taken in; the folder lists follow; logged', async () => {
    const u = await apiReceiver('ra-move');
    const a = await mkdir(u.cookie, 'root');
    const b = await mkdir(u.cookie, 'root');
    expect(a.id && b.id).toBeTruthy();
    const r = await newReverse(u.cookie, { folder: a.id });
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    const done = await send(r, g, { ip });
    const half = await reserve(r, g, { ip, path: 'still-uploading.txt' });
    expect(half.res.status).toBe(201);
    expect(await folderLinks(u.cookie, a.id)).toEqual([r.id]);

    const res = await fetchJson(R(r.id), { method: 'PATCH', cookie: u.cookie, body: { folder: b.id } });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ ok: true, folder: b.id });
    // The folders' lists (the Shares dialog, the Receive… dialog) follow it.
    expect(await folderLinks(u.cookie, a.id)).toEqual([]);
    expect(await folderLinks(u.cookie, b.id)).toEqual([r.id]);
    // The waiting item and the unfinished one moved with it; new uploads land there too.
    expect((await nodeRow(u.id, done.node)).parent).toBe(b.id);
    expect((await nodeRow(u.id, half.node)).parent).toBe(b.id);
    expect((await received(u.cookie)).items.find((x) => x.id === done.node).parent).toBe(b.id);
    const later = await send(r, g, { ip, path: 'later.txt' });
    expect((await nodeRow(u.id, later.node)).parent).toBe(b.id);
    // Taken in there (the browser takes in to the item's parent).
    expect((await takeInAny(u.cookie, done.node, b.id)).status).toBe(200);
    expect((await nodeRow(u.id, done.node)).parent).toBe(b.id);
    // Logged, by the folder's id (its name stays encrypted).
    expect((await audit(u.id)).some((e) => e.action === 'share.updated' && e.detail.startsWith(`id=${r.id}`) && e.detail.includes(`folder=${b.id}`))).toBe(true);
    // Through an API key too (and back to the top folder).
    const k = await fetchJson(R(r.id), { method: 'PATCH', headers: bearer(u.manage), body: { folder: 'root' } });
    expect(k.status).toBe(200);
    expect((await driveRow(u.id, r.id)).folder).toBe('root');
    expect((await audit(u.id)).some((e) => e.detail.startsWith(`id=${r.id}`) && e.detail.includes('folder=root') && e.detail.includes('apikey='))).toBe(true);
    // The same through /shares (My shares' Edit).
    expect((await fetchJson(`/api/private/shares/${r.id}`, { method: 'PATCH', cookie: u.cookie, body: { folder: a.id } })).status).toBe(200);
    expect((await driveRow(u.id, r.id)).folder).toBe(a.id);
  });

  it('refuses a folder deeper than the role allows, one that is not the user’s, deleted, not a folder, or a received item', async () => {
    const u = await receiver('ra-move-rules', { maxFolderDepth: 1 });
    const a = await mkdir(u.cookie, 'root');
    const r = await newReverse(u.cookie, { folder: a.id });
    expect(r.res.status).toBe(201);
    const patch = (folder) => fetchJson(R(r.id), { method: 'PATCH', cookie: u.cookie, body: { folder } });
    // Deeper than the role's folder depth (the Drive's rule: a file at its folder's depth).
    await limits(u.id, { maxFolderDepth: null });
    const deep = await mkdir(u.cookie, a.id);
    await limits(u.id, { maxFolderDepth: 1 });
    const d = await patch(deep.id);
    expect(d.status).toBe(403);
    expect(await d.json()).toMatchObject({ error: 'folder_too_deep', max: 1 });
    // Another user's folder: not in this Drive.
    const other = await receiver('ra-move-other');
    const theirs = await mkdir(other.cookie, 'root');
    const t = await patch(theirs.id);
    expect(t.status).toBe(404);
    expect(await errorOf(t)).toBe('folder_not_found');
    // A deleted folder.
    const gone = await mkdir(u.cookie, 'root');
    expect((await fetchJson(`/api/private/drive/nodes/${gone.id}`, { method: 'DELETE', cookie: u.cookie, headers: intent })).status).toBe(200);
    expect(await errorOf(await patch(gone.id))).toBe('folder_not_found');
    // A file.
    const f = await uploadFile(u.cookie, 'root', 5);
    expect(await errorOf(await patch(f.id))).toBe('not_a_folder');
    // A received item waiting to be taken in.
    const ip = freshIp();
    const sent = await send(r, await grantOf(r, { ip }), { ip });
    expect(await errorOf(await patch(sent.node))).toBe('folder_not_found');
    // Not a folder id at all.
    expect(await errorOf(await patch('../etc'))).toBe('invalid');
    expect(await errorOf(await patch(42))).toBe('invalid');
    // Nothing moved.
    expect((await driveRow(u.id, r.id)).folder).toBe(a.id);
    expect((await nodeRow(u.id, sent.node)).parent).toBe(a.id);
    // An API key is held to the API limit of the folder depth.
    expect((await limits(u.id, { apiEnabled: true, maxFolderDepth: null })).status).toBe(200);
    expect((await limits(u.id, { maxFolderDepth: 1 }, 'api')).status).toBe(200);
    const key = await mkKey(u, ['manage']);
    expect(await errorOf(await fetchJson(R(r.id), { method: 'PATCH', headers: bearer(key), body: { folder: deep.id } }))).toBe('folder_too_deep');
    expect((await patch(deep.id)).status).toBe(200); // the session: no limit now
  });

  it('an undo never points the link back at a folder deleted meanwhile: it stays, with its items, and the move is logged', async () => {
    const u = await receiver('ra-move-race');
    const a = await mkdir(u.cookie, 'root');
    const b = await mkdir(u.cookie, 'root');
    const r = await newReverse(u.cookie, { folder: a.id });
    const ip = freshIp();
    const sent = await send(r, await grantOf(r, { ip }), { ip });
    // The race: the move reaches the Drive, the old folder is deleted, then the index refuses (a lock).
    const real = dirStub();
    const racing = new Proxy(real, {
      get(t, k) {
        if (k === 'updateShare') return async () => { expect((await del(u.cookie, a.id)).status).toBe(200); return { ok: false, status: 423, error: 'share_locked', message: 'The administrator has locked this share; it cannot be changed.' }; };
        return (...args) => t[k](...args);
      },
    });
    const res = await changeReverse(env, racing, await dirRow(r.id), { folder: b.id }, { uid: u.id, actor: u.id });
    expect(res.status).toBe(423);
    expect(await res.json()).toMatchObject({ error: 'share_locked', kept: ['folder'], folder: b.id });
    // The link still receives, into the new folder, with its waiting item there.
    expect((await driveRow(u.id, r.id)).folder).toBe(b.id);
    expect((await nodeRow(u.id, sent.node)).parent).toBe(b.id);
    expect((await (await fetchJson(R(r.id), { cookie: u.cookie })).json()).link).toMatchObject({ status: 'active', folder: b.id });
    expect((await openLink(r, ip)).status).toBe(200);
    expect((await audit(u.id)).some((e) => e.action === 'share.updated' && e.detail === `id=${r.id} folder=${b.id} kept`)).toBe(true);
    // The Drive's own answer: the folder is kept, the rest put back.
    const c = await mkdir(u.cookie, 'root');
    const moved = await driveOf(u.id).updateReverse(u.id, r.id, { folder: c.id, maxDepth: null, views: 7 });
    expect((await del(u.cookie, b.id)).status).toBe(200);
    expect(await driveOf(u.id).restoreReverse(u.id, r.id, moved.prev)).toEqual({ ok: false, error: 'folder_gone', kept: ['folder'], folder: c.id });
    expect(await driveRow(u.id, r.id)).toMatchObject({ folder: c.id, views: null });
  });

  it('a take-in goes to the link’s folder as the server has it now: a page that listed the item before a move is refused', async () => {
    const u = await receiver('ra-move-takein');
    const a = await mkdir(u.cookie, 'root');
    const b = await mkdir(u.cookie, 'root');
    const other = await mkdir(u.cookie, 'root');
    const r = await newReverse(u.cookie, { folder: a.id });
    const ip = freshIp();
    const sent = await send(r, await grantOf(r, { ip }), { ip });
    expect((await received(u.cookie)).items.find((x) => x.id === sent.node).parent).toBe(a.id); // the page's listing
    expect((await fetchJson(R(r.id), { method: 'PATCH', cookie: u.cookie, body: { folder: b.id } })).status).toBe(200);
    // Taken in with that listing's folder: refused, with the folder it goes to now; still waiting.
    const stale = await takeInAny(u.cookie, sent.node, a.id);
    expect(stale.status).toBe(409);
    expect(await stale.json()).toMatchObject({ error: 'folder_moved', folder: b.id });
    expect(await errorOf(await takeInAny(u.cookie, sent.node, other.id))).toBe('folder_moved');
    expect((await received(u.cookie)).items.find((x) => x.id === sent.node).parent).toBe(b.id);
    // Into the new folder, or a folder below it (a path's folders): taken in.
    const sub = await mkdir(u.cookie, b.id);
    expect((await takeInAny(u.cookie, sent.node, sub.id)).status).toBe(200);
    expect((await nodeRow(u.id, sent.node)).parent).toBe(sub.id);
  });

  it('needs reverseEdit and an active link; the owner changing it directly cannot move it; an undo puts the items back', async () => {
    const u = await receiver('ra-move-edit');
    const a = await mkdir(u.cookie, 'root');
    const r = await newReverse(u.cookie, {});
    const adm = await fetchJson(`/api/private/admin/shares/${r.id}`, { method: 'PATCH', cookie: oc, body: { folder: a.id } });
    expect(adm.status).toBe(403);
    expect(await errorOf(adm)).toBe('user_only');
    expect((await limits(u.id, { reverseEdit: false })).status).toBe(200);
    expect(await errorOf(await fetchJson(R(r.id), { method: 'PATCH', cookie: u.cookie, body: { folder: a.id } }))).toBe('reverse_edit_disabled');
    expect((await limits(u.id, { reverseEdit: true })).status).toBe(200);
    // The Drive undoes a move the share index refused (restoreReverse): the link and its items go back.
    const ip = freshIp();
    const sent = await send(r, await grantOf(r, { ip }), { ip });
    const moved = await driveOf(u.id).updateReverse(u.id, r.id, { folder: a.id, maxDepth: null });
    expect(moved).toMatchObject({ status: 'ok', folder: a.id, prev: { folder: 'root' } });
    expect((await nodeRow(u.id, sent.node)).parent).toBe(a.id);
    await driveOf(u.id).restoreReverse(u.id, r.id, moved.prev);
    expect((await driveRow(u.id, r.id)).folder).toBe('root');
    expect((await nodeRow(u.id, sent.node)).parent).toBe('root');
    // Revoked: nothing but the label changes.
    expect((await fetchJson(R(r.id, '/revoke'), { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(200);
    expect(await errorOf(await fetchJson(R(r.id), { method: 'PATCH', cookie: u.cookie, body: { folder: a.id } }))).toBe('not_active');
  });
});
