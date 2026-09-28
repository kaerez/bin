// reverse-parity.test.js — reverse shares ("Receive" links, docs/REVERSE.md)
// with the options regular shares have, in workerd: the role options (Default,
// Owner, Public, custom roles inheriting, the API channel), links with no
// expiry in every expiry path (the index, the Drive, the uploader, the lists,
// the alarms and prunes), the views limit (a view: one upload session
// granted; atomic under concurrent starts; failed starts spend none; sessions
// already started finish), changing a link after creation (label, expiry,
// views, limits, CAPTCHA, password, note) on the session and API paths and
// by the owner directly, and migration 17 from the Directory the release
// before left. Synthetic data only.
import { env, runDurableObjectAlarm, runInDurableObject, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { owner, makeUser, fetchJson, intent, freshIp, proofFor, USER_PW, cookieOf, ORIGIN } from './helpers.js';
import worker from '../src/index.js';
import { setSiteverify } from '../src/lib/turnstile.js';
import { changeReverse } from '../src/routes/reverse.js';
import { driveLimits } from './drive-helpers.js';
import { PUBLIC_ID, SCHEMA_VERSION } from '../src/directory-do.js';
import { NO_EXPIRY, LIMITS, UNLIMITED, API_LIMIT_KEYS } from '../src/lib/settings.js';
import { passwordGate, passwordProof, sealNote, openNote, linkProof } from '../public/js/reversekeys.js';
import {
  dirStub, driveOf, errorOf, receiver, newReverse, rv, openLink, begin, grantOf, send,
} from './reverse-helpers.js';

vi.setConfig({ testTimeout: 60000 });

let oc;
beforeAll(async () => { oc = await owner(); });
afterEach(() => vi.useRealTimers());

const nowSec = () => Math.floor(Date.now() / 1000);
// The step-up a change that weakens a link needs (the user's password proof, as on create).
const CONFIRM = { current: proofFor(USER_PW) };
const patch = (cookie, id, body, headers = {}) => fetchJson(`/api/private/shares/${id}`, { method: 'PATCH', cookie, body, headers });
const myRow = async (cookie, id, qs = '') => (await (await fetchJson(`/api/private/shares${qs}`, { cookie })).json()).rows.find((x) => x.id === id);
const listed = async (cookie, id) => (await (await fetchJson('/api/private/drive/reverse', { cookie })).json()).reverse.find((x) => x.id === id);
const indexRow = (id) => runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('SELECT * FROM shares WHERE id = ?', id).toArray()[0]);
const driveRow = (uid, id) => runInDurableObject(driveOf(uid), (i, s) => s.storage.sql.exec('SELECT * FROM reverse WHERE id = ?', id).toArray()[0]);
const limits = (scope, p, channel = 'all') => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope, channel, patch: p } });
const audit = async (subject) => (await (await fetchJson(`/api/private/admin/audit?user=${subject}`, { cookie: oc })).json()).rows;
const me = async (cookie) => (await fetchJson('/api/private/me', { cookie })).json();

const NEW_KEYS = ['reverseMaxExpireSec', 'reverseNoExpiry', 'reverseMaxViews', 'reverseAllowUnlimitedViews', 'reversePassword', 'reversePasswordDefault', 'reverseEdit'];

describe('the role options', () => {
  it('Default, Owner and Public values; custom roles inherit; the API channel restricts some', async () => {
    const defaults = Object.fromEntries(NEW_KEYS.map((k) => [k, LIMITS[k].def]));
    expect(defaults).toEqual({ reverseMaxExpireSec: null, reverseNoExpiry: false, reverseMaxViews: null, reverseAllowUnlimitedViews: true,
      reversePassword: 'allow', reversePasswordDefault: 'off', reverseEdit: true });
    // The owner: everything allowed, no limits.
    expect(Object.fromEntries(NEW_KEYS.map((k) => [k, UNLIMITED[k]]))).toEqual({ reverseMaxExpireSec: null, reverseNoExpiry: true, reverseMaxViews: null,
      reverseAllowUnlimitedViews: true, reversePassword: 'allow', reversePasswordDefault: 'off', reverseEdit: true });
    expect((await me(oc)).limits).toMatchObject({ reverseNoExpiry: true, reverseMaxViews: null, reverseMaxExpireSec: null, reverseEdit: true });
    // A user of the Default role gets the Default values.
    const u = await makeUser('rp-defaults');
    expect((await me(u.cookie)).limits).toMatchObject(defaults);
    // The public account: none of them applies (it has no Drive).
    for (const k of NEW_KEYS) {
      const v = LIMITS[k].type === 'bool' ? true : LIMITS[k].type === 'enum' ? 'allow' : 60;
      const r = await limits(PUBLIC_ID, { [k]: v });
      expect(r.status, k).toBe(400);
    }
    // Validation.
    for (const bad of [{ reverseNoExpiry: 'yes' }, { reverseMaxViews: 0 }, { reverseMaxExpireSec: 366 * 86400 }, { reversePassword: 'maybe' }, { reversePasswordDefault: true }, { reverseEdit: null }]) {
      expect((await limits(u.id, bad)).status, JSON.stringify(bad)).toBe(400);
    }
    // A custom role inherits what it leaves unset (here: from the Default role).
    const role = await (await fetchJson('/api/private/admin/roles', { method: 'POST', cookie: oc, body: { name: 'rp-custom' } })).json();
    expect(role.id).toBeTruthy();
    const c = await makeUser('rp-custom-user');
    expect((await fetchJson(`/api/private/admin/users/${c.id}/role`, { method: 'PUT', cookie: oc, body: { roleId: role.id } })).status).toBe(200);
    expect((await limits(`role:${role.id}`, { reverseMaxViews: 3, reverseNoExpiry: true })).status).toBe(200);
    expect((await me(c.cookie)).limits).toMatchObject({ reverseMaxViews: 3, reverseNoExpiry: true, reverseEdit: true, reversePassword: 'allow' });
    expect((await (await fetchJson(`/api/private/admin/roles/${role.id}`, { cookie: oc })).json()).limits.all).toEqual({ reverseMaxViews: 3, reverseNoExpiry: true });
    expect((await limits(`role:${role.id}`, { reverseNoExpiry: 'inherit' })).status).toBe(200);
    expect((await me(c.cookie)).limits.reverseNoExpiry).toBe(false);
    // The Default role holds a value for every option: none can inherit.
    expect((await limits('global', { reverseEdit: 'inherit' })).status).toBe(400);
    // Some of them can be restricted for API keys too (they reach reverse shares through /api/private/shares).
    for (const k of ['reverseMaxExpireSec', 'reverseNoExpiry', 'reverseMaxViews', 'reverseAllowUnlimitedViews', 'reverseEdit']) expect(API_LIMIT_KEYS).toContain(k);
    expect((await limits(u.id, { reverseMaxViews: 2 }, 'api')).status).toBe(200);
    expect((await limits(u.id, { reversePassword: 'off' }, 'api')).status).toBe(400);
  });
});

describe('links with no expiry', () => {
  it('only where the role allows it (reverseNoExpiry, off in the Default role)', async () => {
    const u = await receiver('rp-noexp-role');
    let r = await newReverse(u.cookie, { expire: 'never' });
    expect(r.res.status).toBe(403);
    expect(await errorOf(r.res)).toBe('no_expiry_disabled');
    // The claim was released: the id is free, nothing was indexed.
    expect(await indexRow(r.id)).toBeUndefined();
    await driveLimits(u.id, { reverseNoExpiry: true });
    r = await newReverse(u.cookie, { expire: 'never' });
    expect(r.res.status).toBe(201);
    expect((await r.res.json()).expires).toBeNull();
    // Stored as NO_EXPIRY in the index and the Drive; shown as null everywhere.
    expect((await indexRow(r.id)).expires).toBe(NO_EXPIRY);
    expect((await driveRow(u.id, r.id)).expires).toBe(NO_EXPIRY);
    expect((await listed(u.cookie, r.id)).expires).toBeNull();
    expect((await myRow(u.cookie, r.id)).expires).toBeNull();
    expect((await (await fetchJson(`/api/private/shares/${r.id}`, { cookie: u.cookie })).json()).share.expires).toBeNull();
    const head = await (await openLink(r, freshIp())).json();
    expect(head.expires).toBeNull();
    // Logged as such.
    expect((await audit(u.id)).some((e) => e.action === 'share.created' && e.detail.includes(`id=${r.id}`) && e.detail.includes('expires=none'))).toBe(true);
    // An invalid expiry is still refused.
    for (const expire of ['forever', null, '0d', '400d']) expect((await newReverse(u.cookie, { expire })).res.status, String(expire)).toBe(400);
  });

  it('never expires in any path: the uploader, sessions, the alarms and prunes, the lists and filters; revoke ends it', async () => {
    const u = await receiver('rp-noexp-paths', { reverseNoExpiry: true, reverseMaxActive: 2 });
    const r = await newReverse(u.cookie, { expire: 'never', label: 'forever-inbox' });
    const short = await newReverse(u.cookie, { expire: '1h', label: 'short' });
    expect(r.res.status).toBe(201);
    // It counts as active (reverseMaxActive): a third link is refused.
    expect(await errorOf((await newReverse(u.cookie, { expire: '1h' })).res)).toBe('too_many_reverse');
    const ip = freshIp();
    // A session's deadline is its own (never NO_EXPIRY).
    const b = await begin(r, { ip });
    expect(b.status).toBe(200);
    const s = await b.json();
    expect(s.expires).toBeLessThan(nowSec() + 3600);
    await send(r, s.grant, { ip });
    // Two years later: still open; the Directory's and the Drive's alarms neither expire nor drop it.
    vi.useFakeTimers({ now: Date.now() + 2 * 365 * 86400 * 1000, toFake: ['Date'] });
    await runDurableObjectAlarm(dirStub());
    await runDurableObjectAlarm(driveOf(u.id));
    expect((await indexRow(r.id)).status).toBe('active');
    expect((await indexRow(short.id))?.status ?? 'pruned').not.toBe('active'); // the one with an expiry did (and left the index)
    expect(await driveRow(u.id, r.id)).toBeTruthy();
    expect((await openLink(r, ip)).status).toBe(200);
    expect((await begin(r, { ip })).status).toBe(200);
    // The lists (with today's clock: the sessions of the user and the owner would have lapsed in two years).
    vi.useRealTimers();
    const row = await myRow(u.cookie, r.id);
    expect(row).toMatchObject({ status: 'active', expires: null });
    // My shares and Admin → Shares filter by it.
    const none = (await (await fetchJson('/api/private/shares?expiry=none', { cookie: u.cookie })).json()).rows.map((x) => x.id);
    expect(none).toEqual([r.id]);
    const dated = await newReverse(u.cookie, { expire: '1h' });
    expect(dated.res.status).toBe(201); // the expired one no longer counts as active
    const set = (await (await fetchJson('/api/private/shares?expiry=set', { cookie: u.cookie })).json()).rows.map((x) => x.id);
    expect(set).toContain(dated.id);
    expect(set).not.toContain(r.id);
    const adm = await (await fetchJson(`/api/private/admin/shares?expiry=none&users=${u.id}`, { cookie: oc })).json();
    expect(adm.rows.map((x) => x.id)).toEqual([r.id]);
    expect(adm.rows[0].expires).toBeNull();
    expect((await (await fetchJson(`/api/private/admin/shares/${r.id}`, { cookie: oc })).json()).share.expires).toBeNull();
    // An expiry range never matches it by accident (NO_EXPIRY is not a date anyone picks).
    const ranged = await (await fetchJson(`/api/private/admin/shares?users=${u.id}&expiresFrom=0&expiresTo=${nowSec() + 400 * 86400}`, { cookie: oc })).json();
    expect(ranged.rows.map((x) => x.id)).not.toContain(r.id);
    // Revoke still works; the index row goes 30 days after it ended (not after it was made, not never).
    expect((await fetchJson(`/api/private/shares/${r.id}/revoke`, { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(200);
    expect((await openLink(r, ip)).status).toBe(410);
    const ended = (await indexRow(r.id)).ended;
    expect(ended).toBeGreaterThanOrEqual(nowSec() - 5);
    vi.useFakeTimers({ now: Date.now() + 29 * 86400 * 1000, toFake: ['Date'] });
    await runDurableObjectAlarm(dirStub());
    expect(await indexRow(r.id)).toBeTruthy();
    vi.useFakeTimers({ now: Date.now() + 2 * 86400 * 1000, toFake: ['Date'] });
    await runDurableObjectAlarm(dirStub());
    expect(await indexRow(r.id)).toBeUndefined();
  });

  it('an indefinite link can be given an expiry, and a link with one can be made indefinite (as the role allows)', async () => {
    const u = await receiver('rp-noexp-switch', { reverseNoExpiry: true, reverseMaxExpireSec: 7 * 86400 });
    const r = await newReverse(u.cookie, { expire: 'never' });
    // Beyond the role's longest expiry: refused.
    expect(await errorOf(await patch(u.cookie, r.id, { expires: nowSec() + 8 * 86400 }))).toBe('expiry_too_long');
    const at = nowSec() + 3 * 86400;
    let res = await patch(u.cookie, r.id, { expires: at });
    expect(res.status, await res.clone().text()).toBe(200);
    expect((await res.json()).expires).toBe(at);
    expect((await indexRow(r.id)).expires).toBe(at);
    expect((await driveRow(u.id, r.id)).expires).toBe(at);
    expect((await (await openLink(r, freshIp())).json()).expires).toBe(at);
    // Now it has one: as regular shares, it can only be extended…
    res = await patch(u.cookie, r.id, { expires: at - 3600 });
    expect(res.status).toBe(400);
    expect((await res.json()).message).toMatch(/only be extended/);
    expect((await patch(u.cookie, r.id, { expires: at + 3600 })).status).toBe(200);
    // …or made indefinite again.
    res = await patch(u.cookie, r.id, { expires: null, ...CONFIRM });
    expect(res.status).toBe(200);
    expect((await res.json()).expires).toBeNull();
    expect((await indexRow(r.id)).expires).toBe(NO_EXPIRY);
    // Without reverseNoExpiry: an indefinite link can still be given an expiry, never made indefinite.
    await driveLimits(u.id, { reverseNoExpiry: false });
    expect(await errorOf(await patch(u.cookie, r.id, { expires: null }))).toBe('no_expiry_disabled');
    expect((await patch(u.cookie, r.id, { expires: nowSec() + 86400 })).status).toBe(200);
    expect(await errorOf(await patch(u.cookie, r.id, { expires: null }))).toBe('no_expiry_disabled');
    // A past or malformed expiry.
    for (const expires of [nowSec() - 10, 'tomorrow', nowSec() + 400 * 86400]) expect((await patch(u.cookie, r.id, { expires })).status).toBe(400);
    expect((await (await fetchJson(`/api/private/shares/${r.id}`, { cookie: u.cookie })).json()).share.expires).not.toBeNull();
    // The activity log names the change without the sentinel.
    await driveLimits(u.id, { reverseNoExpiry: true });
    await patch(u.cookie, r.id, { expires: null, ...CONFIRM });
    expect((await audit(u.id)).some((e) => e.action === 'share.updated' && e.detail.includes('expires=none'))).toBe(true);
  });
});

describe('views (a view: one upload session granted)', () => {
  it('within the role: reverseMaxViews and reverseAllowUnlimitedViews, on create and on change', async () => {
    const u = await receiver('rp-views-role', { reverseMaxViews: 5 });
    expect(await errorOf((await newReverse(u.cookie, { views: 6 })).res)).toBe('too_many_views');
    for (const views of [0, -1, 1.5, '3', 100001]) expect((await newReverse(u.cookie, { views })).res.status, String(views)).toBe(400);
    const r = await newReverse(u.cookie, { views: 5 });
    expect(r.res.status).toBe(201);
    expect((await r.res.json()).views).toBe(5);
    expect(await listed(u.cookie, r.id)).toMatchObject({ views: 5, used: 0, left: 5 });
    expect(await myRow(u.cookie, r.id)).toMatchObject({ views_total: 5, left: 5 });
    expect(await errorOf(await patch(u.cookie, r.id, { views: 6 }))).toBe('too_many_views');
    // No views given: unlimited (allowed by the Default role), until the role says otherwise.
    const unl = await newReverse(u.cookie);
    expect(unl.res.status).toBe(201);
    expect(await listed(u.cookie, unl.id)).toMatchObject({ views: null, left: null });
    await driveLimits(u.id, { reverseAllowUnlimitedViews: false });
    expect(await errorOf((await newReverse(u.cookie)).res)).toBe('unlimited_views_disabled');
    expect(await errorOf((await newReverse(u.cookie, { views: null })).res)).toBe('unlimited_views_disabled');
    expect(await errorOf(await patch(u.cookie, r.id, { views: null }))).toBe('unlimited_views_disabled');
    await driveLimits(u.id, { reverseAllowUnlimitedViews: true, reverseMaxViews: null });
    expect((await patch(u.cookie, r.id, { views: null, ...CONFIRM })).status).toBe(200);
    expect(await listed(u.cookie, r.id)).toMatchObject({ views: null, left: null });
  });

  it('runs out after the views: the next start is refused (410); sessions already started finish; failed starts spend none', async () => {
    const u = await receiver('rp-views-run');
    const r = await newReverse(u.cookie, { views: 2, password: 'open sesame' });
    const ip = freshIp();
    // A start with the right password, from the page's first open (the page cannot open once used up).
    const pwHead = (await (await openLink(r, ip)).json()).password;
    const beginPw = async () => rv(r.id, '/begin', { headers: { 'x-link-proof': await linkProof(r.pub), 'x-key-proof': await passwordProof('open sesame', pwHead.salt, pwHead.t, r.pub) }, ip });
    // Failed starts: no link proof, a wrong link, no password, a wrong password — none spends a view.
    expect((await rv(r.id, '/begin')).status).toBe(400);
    const other = await newReverse(u.cookie);
    expect((await begin(r, { ip, pub: other.pub })).status).toBe(403);
    expect((await begin(r, { ip })).status).toBe(401);
    expect((await begin(r, { ip, password: 'wrong' })).status).toBe(403);
    // Opening the page is not a view either.
    for (let i = 0; i < 3; i++) expect((await openLink(r, ip)).status).toBe(200);
    expect((await driveRow(u.id, r.id)).used).toBe(0);
    const g1 = await grantOf(r, { ip, password: 'open sesame' });
    const g2 = await grantOf(r, { ip, password: 'open sesame' });
    expect(await listed(u.cookie, r.id)).toMatchObject({ views: 2, used: 2, left: 0 });
    // Used up: the page and a new start say it has ended (as a used-up share), before any password check.
    expect((await openLink(r, ip)).status).toBe(410);
    expect((await beginPw()).status).toBe(410);
    const locked = await driveRow(u.id, r.id);
    expect(locked.pwfails).toBe(0); // the right password was not even checked: nothing counted
    // The sessions already started finish their uploads.
    await send(r, g1, { ip });
    await send(r, g2, { ip, path: 'b.txt' });
    expect((await rv(r.id, '/done', { headers: { 'x-reverse-grant': g1 }, ip })).status).toBe(200);
    // It stays active (My shares: 0 left of 2), so the user can raise its views.
    expect(await myRow(u.cookie, r.id)).toMatchObject({ status: 'active', views_total: 2, left: 0 });
    expect((await patch(u.cookie, r.id, { views: 3 })).status).toBe(200);
    expect((await openLink(r, ip)).status).toBe(200);
    expect((await beginPw()).status).toBe(200);
    expect((await beginPw()).status).toBe(410);
  });

  it('lowering views: never below the views already used', async () => {
    const u = await receiver('rp-views-lower');
    const r = await newReverse(u.cookie, { views: 5 });
    const ip = freshIp();
    await grantOf(r, { ip });
    await grantOf(r, { ip });
    let res = await patch(u.cookie, r.id, { views: 1 });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.used).toBe(2);
    expect(body.message).toMatch(/2 already used/);
    expect((await driveRow(u.id, r.id)).views).toBe(5);
    res = await patch(u.cookie, r.id, { views: 2 });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ views: 2, used: 2, left: 0 });
    expect((await begin(r, { ip })).status).toBe(410);
    // An unlimited link counts its views too: it can be limited later, never below them.
    const unl = await newReverse(u.cookie);
    await grantOf(unl, { ip });
    await grantOf(unl, { ip });
    await grantOf(unl, { ip });
    expect((await patch(u.cookie, unl.id, { views: 2 })).status).toBe(400);
    expect((await patch(u.cookie, unl.id, { views: 4 })).status).toBe(200);
    expect(await listed(u.cookie, unl.id)).toMatchObject({ views: 4, used: 3, left: 1 });
  });

  it('a views-limited start still passes the "receive-upload" quota: a start the quota refuses spends no view, and a used-up link spends no quota', async () => {
    const u = await receiver('rp-views-quota');
    const r = await newReverse(u.cookie, { views: 3 });
    const setQuotas = (list) => fetchJson('/api/private/admin/quotas', { method: 'PUT', cookie: oc, body: { scope: u.id, list } });
    const used = async () => Object.fromEntries((await me(u.cookie)).quotas.map((x) => [x.kind, x.used]));
    expect((await setQuotas([{ channel: 'all', kind: 'receive-upload', n: 100, unit: 'y', max: 1 }])).status).toBe(200);
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    await send(r, g, { ip });
    expect((await rv(r.id, '/done', { headers: { 'x-reverse-grant': g }, ip })).status).toBe(200);
    expect((await used())['receive-upload']).toBe(1);
    // At the quota: 429, and the view is not spent.
    const refused = await begin(r, { ip });
    expect(refused.status).toBe(429);
    expect(await errorOf(refused)).toBe('not_accepting');
    expect((await driveRow(u.id, r.id)).used).toBe(1);
    // A used-up link: 410 before the quota is looked at (nothing charged).
    expect((await setQuotas([{ channel: 'all', kind: 'receive-upload', n: 100, unit: 'y', max: 10 }])).status).toBe(200);
    expect((await patch(u.cookie, r.id, { views: 1 })).status).toBe(200);
    expect((await begin(r, { ip })).status).toBe(410);
    expect((await used())['receive-upload']).toBe(0);
  });

  it('concurrent starts never get more sessions than the views', async () => {
    const u = await receiver('rp-views-race');
    const r = await newReverse(u.cookie, { views: 3 });
    // Distinct networks, so the per-network session cap (5) plays no part.
    const res = await Promise.all(Array.from({ length: 12 }, (_, i) => begin(r, { ip: `203.0.113.${40 + i}` })));
    const codes = res.map((x) => x.status);
    expect(codes.filter((c) => c === 200)).toHaveLength(3);
    expect(codes.filter((c) => c === 410)).toHaveLength(9);
    expect((await driveRow(u.id, r.id)).used).toBe(3);
    const sessions = await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec('SELECT COUNT(*) AS c FROM rsessions WHERE rid = ?', r.id).one().c);
    expect(sessions).toBe(3);
  });
});

describe('the uploader password after creation', () => {
  it('add, change and remove it; it gates the uploader only', async () => {
    const u = await receiver('rp-pw');
    const r = await newReverse(u.cookie);
    const ip = freshIp();
    expect((await begin(r, { ip })).status).toBe(200);
    // Add: made in the browser from the link's key (the server never sees the password).
    const res = await patch(u.cookie, r.id, { password: await passwordGate('first secret', r.pub) });
    expect(res.status, await res.clone().text()).toBe(200);
    expect((await listed(u.cookie, r.id)).password).toBe(true);
    expect((await begin(r, { ip })).status).toBe(401);
    expect((await begin(r, { ip, password: 'first secret' })).status).toBe(200);
    // Change.
    expect((await patch(u.cookie, r.id, { password: await passwordGate('second secret', r.pub), ...CONFIRM })).status).toBe(200);
    expect((await begin(r, { ip, password: 'first secret' })).status).toBe(403);
    expect((await begin(r, { ip, password: 'second secret' })).status).toBe(200);
    // Remove.
    expect((await patch(u.cookie, r.id, { password: null, ...CONFIRM })).status).toBe(200);
    expect((await listed(u.cookie, r.id)).password).toBe(false);
    expect((await (await openLink(r, ip)).json()).password).toBeNull();
    expect((await begin(r, { ip })).status).toBe(200);
    // Malformed.
    for (const password of ['plain text', { salt: 'x', t: 3, ph: 'y' }, { salt: 'A'.repeat(22), t: 99, ph: 'B'.repeat(43) }]) {
      expect((await patch(u.cookie, r.id, { password })).status).toBe(400);
    }
    // The log names what changed, never a value.
    const rows = (await audit(u.id)).filter((e) => e.action === 'share.updated' && e.detail.includes(r.id));
    expect(rows.map((e) => e.detail).join('\n')).toMatch(/password=set/);
    expect(rows.map((e) => e.detail).join('\n')).toMatch(/password=removed/);
    expect(rows.map((e) => e.detail).join('\n')).not.toMatch(/secret|ph=|salt/);
  });

  it('within the role: reversePassword "require" and "off", on create and on change', async () => {
    const u = await receiver('rp-pw-role', { reversePassword: 'require' });
    expect(await errorOf((await newReverse(u.cookie)).res)).toBe('password_required_by_role');
    const r = await newReverse(u.cookie, { password: 'needed' });
    expect(r.res.status).toBe(201);
    expect(await errorOf(await patch(u.cookie, r.id, { password: null }))).toBe('password_required_by_role');
    expect((await patch(u.cookie, r.id, { password: await passwordGate('another', r.pub), ...CONFIRM })).status).toBe(200);
    await driveLimits(u.id, { reversePassword: 'off' });
    expect(await errorOf((await newReverse(u.cookie, { password: 'not allowed' })).res)).toBe('password_disabled');
    expect(await errorOf(await patch(u.cookie, r.id, { password: await passwordGate('third', r.pub) }))).toBe('password_disabled');
    // Removing one is always possible under "off".
    expect((await patch(u.cookie, r.id, { password: null, ...CONFIRM })).status).toBe(200);
    expect((await newReverse(u.cookie)).res.status).toBe(201);
  });
});

describe('changing a link after creation', () => {
  it('the note, the limits and the CAPTCHA, each within the role', async () => {
    const u = await receiver('rp-edit', { reverseMaxBytes: 5000, reverseCaptcha: 'allow' });
    const r = await newReverse(u.cookie, { note: 'first note', maxFiles: 5, captcha: false });
    const ip = freshIp();
    // The note, sealed in the browser with the link's key.
    expect((await patch(u.cookie, r.id, { note: await sealNote(r.pub, r.id, 'second note') })).status).toBe(200);
    let head = await (await openLink(r, ip)).json();
    expect(await openNote(r.pub, r.id, head.note)).toBe('second note');
    expect((await patch(u.cookie, r.id, { note: null })).status).toBe(200);
    head = await (await openLink(r, ip)).json();
    expect(head.note).toBeNull();
    expect((await patch(u.cookie, r.id, { note: 'plain text' })).status).toBe(400);
    // The limits.
    const res = await patch(u.cookie, r.id, { maxFiles: 1, maxFileBytes: 100, types: { mode: 'allow', rules: ['ext:txt'] } });
    expect(res.status, await res.clone().text()).toBe(200);
    head = await (await openLink(r, ip)).json();
    expect(head.limits).toMatchObject({ maxFiles: 1, maxFileBytes: 100, types: { mode: 'allow', rules: ['ext:txt'] }, maxBytes: 5000 });
    expect(await errorOf(await patch(u.cookie, r.id, { maxBytes: 5001 }))).toBe('reverse_too_large');
    // "No limit" is the role's limit, as on create.
    expect((await patch(u.cookie, r.id, { maxBytes: null })).status).toBe(200);
    expect((await listed(u.cookie, r.id)).maxBytes).toBe(5000);
    expect((await patch(u.cookie, r.id, { maxBytes: 2000, types: null })).status).toBe(200);
    expect((await listed(u.cookie, r.id))).toMatchObject({ maxBytes: 2000, types: null, maxFiles: 1 });
    for (const bad of [{ maxFiles: 0 }, { maxFiles: 10001 }, { maxBytes: -1 }, { types: { mode: 'allow', rules: [] } }, { types: 'pdf' }]) {
      expect((await patch(u.cookie, r.id, bad)).status, JSON.stringify(bad)).toBe(400);
    }
    // The CAPTCHA: in the index (where the uploader's start checks it) and in the Drive's list.
    expect((await patch(u.cookie, r.id, { captcha: true })).status).toBe(200);
    expect((await indexRow(r.id)).captcha).toBe(1);
    expect((await listed(u.cookie, r.id)).captcha).toBe(true);
    expect((await myRow(u.cookie, r.id)).captcha).toBe(true);
    expect((await patch(u.cookie, r.id, { captcha: 'yes' })).status).toBe(400);
    await driveLimits(u.id, { reverseCaptcha: 'require' });
    expect(await errorOf(await patch(u.cookie, r.id, { captcha: false }))).toBe('captcha_required_by_role');
    await driveLimits(u.id, { reverseCaptcha: 'off' });
    expect((await patch(u.cookie, r.id, { captcha: false, ...CONFIRM })).status).toBe(200);
    expect((await indexRow(r.id)).captcha).toBe(0);
    expect(await errorOf(await patch(u.cookie, r.id, { captcha: true }))).toBe('captcha_disabled');
    // The label, as for every share.
    expect((await patch(u.cookie, r.id, { label: 'renamed' })).status).toBe(200);
    expect((await myRow(u.cookie, r.id)).label).toBe('renamed');
    // Nothing to change.
    expect((await patch(u.cookie, r.id, {})).status).toBe(400);
  });

  it('reverseEdit off: only the label (and revoking); a revoked, locked or someone else\'s link cannot be changed', async () => {
    const u = await receiver('rp-noedit', { reverseEdit: false });
    const r = await newReverse(u.cookie, { views: 2 });
    for (const body of [{ views: 3 }, { expires: nowSec() + 86400 }, { maxFiles: 1 }, { captcha: true }, { password: null }, { note: null }]) {
      expect(await errorOf(await patch(u.cookie, r.id, body)), JSON.stringify(body)).toBe('reverse_edit_disabled');
    }
    expect((await patch(u.cookie, r.id, { label: 'ok' })).status).toBe(200);
    await driveLimits(u.id, { reverseEdit: true });
    // Someone else's link.
    const other = await receiver('rp-noedit-other');
    expect((await patch(other.cookie, r.id, { views: 3 })).status).toBe(404);
    // Locked by the admin.
    expect((await fetchJson(`/api/private/admin/shares/${r.id}/lock`, { method: 'POST', cookie: oc, body: { locked: true } })).status).toBe(200);
    expect((await patch(u.cookie, r.id, { views: 3 })).status).toBe(423);
    expect((await fetchJson(`/api/private/admin/shares/${r.id}/lock`, { method: 'POST', cookie: oc, body: { locked: false } })).status).toBe(200);
    // Revoked.
    expect((await fetchJson(`/api/private/shares/${r.id}/revoke`, { method: 'POST', cookie: u.cookie, headers: intent })).status).toBe(200);
    expect((await patch(u.cookie, r.id, { views: 3 })).status).toBe(409);
    // CSRF: a cross-site PATCH and one without the session's token are refused before anything changes.
    const r2 = await newReverse(u.cookie, { views: 2 });
    expect((await patch(u.cookie, r2.id, { views: 3 }, { 'sec-fetch-site': 'cross-site' })).status).toBe(403);
    expect((await fetchJson(`/api/private/shares/${r2.id}`, { method: 'PATCH', cookie: u.cookie, body: { views: 3 }, csrf: false })).status).toBe(403);
    expect((await driveRow(u.id, r2.id)).views).toBe(2);
  });

  it('the owner directly (Admin → Shares): label, expiry and views; not the password, note, limits or CAPTCHA', async () => {
    const u = await receiver('rp-admin');
    const r = await newReverse(u.cookie, { views: 1 });
    const adm = (body) => fetchJson(`/api/private/admin/shares/${r.id}`, { method: 'PATCH', cookie: oc, body });
    expect((await adm({ views: 10 })).status).toBe(200);
    expect((await driveRow(u.id, r.id)).views).toBe(10);
    expect((await adm({ expires: nowSec() + 30 * 86400 })).status).toBe(200);
    // No expiry only where the user's role allows it.
    expect(await errorOf(await adm({ expires: null }))).toBe('no_expiry_disabled');
    await driveLimits(u.id, { reverseNoExpiry: true });
    expect((await adm({ expires: null })).status).toBe(200);
    for (const body of [{ password: null }, { note: null }, { maxFiles: 3 }, { captcha: false }]) expect(await errorOf(await adm(body)), JSON.stringify(body)).toBe('user_only');
    // Logged as the owner's (the admin audit), not in the user's own log.
    const rows = await audit(u.id);
    expect(rows.some((e) => e.action === 'share.updated' && e.adm === 1 && e.detail.includes('views=10'))).toBe(true);
  });

  it('the API: a key with "manage" changes a link within the API limits; "read" cannot', async () => {
    const u = await receiver('rp-api', { apiEnabled: true, reverseNoExpiry: true });
    const mk = async (scopes) => (await (await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { name: scopes.join('-'), scopes, current: proofFor(USER_PW) } })).json()).key;
    const manage = await mk(['manage', 'read']);
    const read = await mk(['read']);
    const r = await newReverse(u.cookie, { views: 2 });
    const api = (key, body) => fetchJson(`/api/private/shares/${r.id}`, { method: 'PATCH', body, headers: { authorization: `Bearer ${key}` } });
    expect((await api(read, { views: 3 })).status).toBe(403);
    let res = await api(manage, { views: 4 });
    expect(res.status, await res.clone().text()).toBe(200);
    expect((await driveRow(u.id, r.id)).views).toBe(4);
    // Listed through the API with its views and expiry.
    const listedApi = await (await fetchJson('/api/private/shares', { headers: { authorization: `Bearer ${read}` } })).json();
    expect(listedApi.rows.find((x) => x.id === r.id)).toMatchObject({ kind: 'reverse', views_total: 4 });
    // The API channel restricts further (never widens).
    expect((await limits(u.id, { reverseMaxViews: 5, reverseNoExpiry: false, reverseMaxExpireSec: 86400 }, 'api')).status).toBe(200);
    expect(await errorOf(await api(manage, { views: 6 }))).toBe('too_many_views');
    expect(await errorOf(await api(manage, { expires: null }))).toBe('no_expiry_disabled');
    expect(await errorOf(await api(manage, { expires: nowSec() + 2 * 86400 }))).toBe('expiry_too_long');
    // The session is not held to the API's limits.
    expect((await patch(u.cookie, r.id, { views: 6 })).status).toBe(200);
    expect((await patch(u.cookie, r.id, { expires: null, ...CONFIRM })).status).toBe(200);
    expect((await limits(u.id, { reverseEdit: false }, 'api')).status).toBe(200);
    expect(await errorOf(await api(manage, { views: 5 }))).toBe('reverse_edit_disabled');
    // A password made from the link's key works through the API too; the change names the key.
    expect((await limits(u.id, { reverseEdit: true }, 'api')).status).toBe(200);
    res = await api(manage, { password: await passwordGate('api secret', r.pub) });
    expect(res.status).toBe(200);
    expect((await begin(r, { ip: freshIp(), password: 'api secret' })).status).toBe(200);
    expect((await audit(u.id)).some((e) => e.action === 'share.updated' && e.detail.includes('password=set') && e.detail.includes('apikey='))).toBe(true);
  });
});

describe('weakening a link needs the step-up; tightening does not (audit of #74: L2, L3, I1, I2)', () => {
  const mkKey = async (u, scopes) => (await (await fetchJson('/api/private/me/keys', { method: 'POST', cookie: u.cookie, body: { name: scopes.join('-'), scopes, current: proofFor(USER_PW) } })).json()).key;
  const WEAK = (r) => [
    ['no expiry', { expires: null }],
    ['unlimited views', { views: null }],
    ['the password changed', async () => ({ password: await passwordGate('another gate', r.pub) })],
    ['the password removed', { password: null }],
    ['the CAPTCHA off', { captcha: false }],
  ];
  const bodyOf = async (b) => (typeof b === 'function' ? b() : b);

  it('a stolen session (no password, no passkey) is refused each weakening change; the password proof lets it through; nothing changes before', async () => {
    const u = await receiver('rp-weak-session', { reverseNoExpiry: true, reverseCaptcha: 'allow' });
    const r = await newReverse(u.cookie, { views: 2, password: 'first gate', captcha: true });
    for (const [what, b] of WEAK(r)) {
      const before = await driveRow(u.id, r.id);
      const body = await bodyOf(b);
      const res = await patch(u.cookie, r.id, body);
      expect(res.status, what).toBe(400);
      expect(await errorOf(res), what).toBe('reauth_required');
      // A wrong password: refused, counted as a failed confirmation.
      const wrong = await patch(u.cookie, r.id, { ...body, current: proofFor('not-the-password') });
      expect(wrong.status, what).toBe(403);
      expect(await errorOf(wrong), what).toBe('wrong_password');
      const after = await driveRow(u.id, r.id);
      expect([after.expires, after.views, after.ph, after.captcha], what).toEqual([before.expires, before.views, before.ph, before.captcha]);
      expect((await indexRow(r.id)).captcha, what).toBe(before.captcha);
    }
    for (const [what, b] of WEAK(r)) expect((await patch(u.cookie, r.id, { ...(await bodyOf(b)), ...CONFIRM })).status, what).toBe(200);
    const d = await driveRow(u.id, r.id);
    expect([d.expires, d.views, d.ph, d.captcha]).toEqual([NO_EXPIRY, null, null, 0]);
    expect((await indexRow(r.id)).captcha).toBe(0);
    // A change that weakens nothing (already so) needs no confirmation.
    expect((await patch(u.cookie, r.id, { expires: null, views: null, password: null, captcha: false, label: 'same' })).status).toBe(200);
  });

  it('tightening needs no confirmation: a password where there was none, the CAPTCHA on, an expiry, fewer views, tighter limits, the label', async () => {
    const u = await receiver('rp-tighten', { reverseNoExpiry: true, reverseCaptcha: 'allow' });
    const r = await newReverse(u.cookie, { expire: 'never', captcha: false });
    for (const body of [{ password: await passwordGate('gate', r.pub) }, { captcha: true }, { expires: nowSec() + 86400 }, { views: 3 }, { views: 2 }, { maxFiles: 1, maxFileBytes: 10 }, { label: 'tight' }, { expires: nowSec() + 2 * 86400 }]) {
      const res = await patch(u.cookie, r.id, body);
      expect(res.status, JSON.stringify(Object.keys(body))).toBe(200);
    }
    expect(await driveRow(u.id, r.id)).toMatchObject({ captcha: 1, views: 2 });
  });

  it('an API key cannot weaken a link, even with the password proof; it can tighten it', async () => {
    const u = await receiver('rp-weak-api', { apiEnabled: true, reverseNoExpiry: true, reverseCaptcha: 'allow' });
    const key = await mkKey(u, ['manage', 'read']);
    const api = (id, body) => fetchJson(`/api/private/shares/${id}`, { method: 'PATCH', body, headers: { authorization: `Bearer ${key}` } });
    const r = await newReverse(u.cookie, { views: 2, password: 'api gate', captcha: true });
    for (const [what, b] of WEAK(r)) {
      const res = await api(r.id, { ...(await bodyOf(b)), ...CONFIRM });
      expect(res.status, what).toBe(403);
      const e = await res.json();
      expect(e.error, what).toBe('step_up_required');
      expect(e.weakens.length, what).toBe(1);
    }
    expect(await driveRow(u.id, r.id)).toMatchObject({ views: 2, captcha: 1 });
    expect((await driveRow(u.id, r.id)).ph).toBeTruthy();
    // Tightening through the API.
    const open = await newReverse(u.cookie, { captcha: false });
    for (const body of [{ password: await passwordGate('added', open.pub) }, { captcha: true }, { views: 5 }, { views: 1 }, { maxFiles: 2 }, { expires: nowSec() + 8 * 86400 }, { label: 'via api' }]) {
      expect((await api(open.id, body)).status, JSON.stringify(Object.keys(body))).toBe(200);
    }
    expect(await driveRow(u.id, open.id)).toMatchObject({ captcha: 1, views: 1 });
    expect((await driveRow(u.id, open.id)).ph).toBeTruthy();
  });

  it('the owner acting as the user confirms nothing, as for every other change to the account', async () => {
    const u = await receiver('rp-weak-imp', { reverseNoExpiry: true, reverseCaptcha: 'allow' });
    const r = await newReverse(u.cookie, { views: 2, password: 'imp gate', captcha: true });
    const ic = cookieOf(await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
    for (const [what, b] of WEAK(r)) expect((await patch(ic, r.id, await bodyOf(b))).status, what).toBe(200);
    expect(await driveRow(u.id, r.id)).toMatchObject({ expires: NO_EXPIRY, views: null, ph: null, captcha: 0 });
  });

  it('…/human on a used-up link: 410 before any CAPTCHA check, no grant', async () => {
    const u = await receiver('rp-human', { reverseCaptcha: 'require' });
    const r = await newReverse(u.cookie, { views: 1 });
    let calls = 0;
    const restore = setSiteverify(async () => { calls += 1; return Response.json({ success: true, hostname: new URL(ORIGIN).hostname, action: 'reverse-upload' }); });
    const TS = { ...env, TURNSTILE_SITEKEY: '0x4AAAAAAAtestsitekey', TURNSTILE_SECRET: '0x4AAAAAAAtestsecretvalue' };
    const human = async () => {
      const ctx = createExecutionContext();
      const res = await worker.fetch(new Request(`${ORIGIN}/api/reverse/${r.id}/human`, { method: 'POST', headers: { ...intent, 'x-secbin-turnstile': `ok#${Math.random()}`, 'cf-connecting-ip': freshIp() } }), TS, ctx);
      await waitOnExecutionContext(ctx);
      return res;
    };
    try {
      const first = await human();
      expect(first.status).toBe(200);
      expect((await first.json()).grant).toBeTruthy();
      expect(calls).toBe(1);
      // Its one view used (the default role without Turnstile keys here: no CAPTCHA asked).
      await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec('UPDATE reverse SET used = views WHERE id = ?', r.id));
      const res = await human();
      expect(res.status).toBe(410);
      expect(await res.json()).not.toHaveProperty('grant');
      expect(calls).toBe(1); // no siteverify
    } finally {
      setSiteverify(restore);
    }
  });

  it('a lock between the Drive and the index writes puts the Drive back: the two never differ', async () => {
    const u = await receiver('rp-race', { reverseCaptcha: 'allow' });
    const r = await newReverse(u.cookie, { views: 2, captcha: true });
    const before = await driveRow(u.id, r.id);
    const row = await dirStub().getShare(u.id, r.id);
    // The Directory as the Worker sees it, but its index write refused (locked in between).
    const real = dirStub();
    const dir = new Proxy({}, { get: (t, k) => (k === 'updateShare' ? async () => ({ ok: false, status: 423, error: 'share_locked', message: 'locked' }) : (...a) => real[k](...a)) });
    const res = await changeReverse(env, dir, row, { views: 5, maxFiles: 3, captcha: true }, { uid: u.id, actor: u.id });
    expect(res.status).toBe(423);
    const after = await driveRow(u.id, r.id);
    expect([after.views, after.opts, after.captcha]).toEqual([before.views, before.opts, before.captcha]);
    // A lock seen first: nothing is written at all.
    expect((await fetchJson(`/api/private/admin/shares/${r.id}/lock`, { method: 'POST', cookie: oc, body: { locked: true } })).status).toBe(200);
    const locked = await changeReverse(env, real, { ...row, locked: 0 }, { views: 7 }, { uid: u.id, actor: u.id });
    expect(locked.status).toBe(423);
    expect((await driveRow(u.id, r.id)).views).toBe(2);
  });
});

describe('Import / export', () => {
  it('the roles part carries the new options, and an import applies (and validates) them', async () => {
    const CURRENT = proofFor('owner-password');
    const role = await (await fetchJson('/api/private/admin/roles', { method: 'POST', cookie: oc, body: { name: 'rp-portable' } })).json();
    expect((await limits(`role:${role.id}`, { reverseMaxViews: 6, reversePassword: 'require' })).status).toBe(200);
    const ex = await fetchJson('/api/private/admin/export', { method: 'POST', cookie: oc, body: { current: CURRENT, system: true, users: [] } });
    expect(ex.status).toBe(200);
    const doc = (await ex.json()).document;
    for (const k of NEW_KEYS) expect(doc.system.limits.all, k).toHaveProperty(k);
    const mine = doc.system.roles.find((r) => r.name === 'rp-portable');
    expect(mine.limits.all).toMatchObject({ reverseMaxViews: 6, reversePassword: 'require' });
    // Applied from the file.
    mine.limits.all.reverseNoExpiry = true;
    mine.limits.all.reverseMaxViews = 9;
    const imp = (document) => fetchJson('/api/private/admin/import', { method: 'POST', cookie: oc, body: { current: CURRENT, document, decisions: { system: true, users: {} }, dryRun: false } });
    const ok = await imp(doc);
    expect(ok.status, await ok.clone().text()).toBe(200);
    const d = await (await fetchJson(`/api/private/admin/roles/${role.id}`, { cookie: oc })).json();
    expect(d.limits.all).toMatchObject({ reverseNoExpiry: true, reverseMaxViews: 9, reversePassword: 'require' });
    // Validated like the admin API.
    mine.limits.all.reverseMaxViews = 0;
    expect((await imp(doc)).status).toBe(400);
  });
});

describe('migration 17 from the Directory the release before left', () => {
  it('keeps each role\'s expiry bound for reverse links, adds shares.ended, and links made before keep working', async () => {
    const u = await receiver('rp-m17');
    const oldLink = await newReverse(u.cookie, { password: 'kept secret', expire: '2d' });
    expect(oldLink.res.status).toBe(201);
    const role = await (await fetchJson('/api/private/admin/roles', { method: 'POST', cookie: oc, body: { name: 'rp-m17-role' } })).json();
    // The Directory and the Drive as the release before left them.
    await runInDurableObject(dirStub(), (i, s) => {
      const sql = s.storage.sql;
      sql.exec(`DELETE FROM limits WHERE key IN (${NEW_KEYS.map(() => '?').join(', ')})`, ...NEW_KEYS);
      sql.exec("INSERT INTO limits (user_id, channel, key, value) VALUES ('', 'all', 'maxExpireSec', '86400') ON CONFLICT(user_id, channel, key) DO UPDATE SET value = excluded.value");
      sql.exec("INSERT INTO limits (user_id, channel, key, value) VALUES (?, 'all', 'maxExpireSec', '3600') ON CONFLICT(user_id, channel, key) DO UPDATE SET value = excluded.value", `r:${role.id}`);
      sql.exec("INSERT INTO limits (user_id, channel, key, value) VALUES ('', 'api', 'maxExpireSec', '7200') ON CONFLICT(user_id, channel, key) DO UPDATE SET value = excluded.value");
      sql.exec('ALTER TABLE shares DROP COLUMN ended');
      sql.exec("UPDATE meta SET v = '16' WHERE k = 'schema_version'");
    });
    await runInDurableObject(driveOf(u.id), (i, s) => {
      s.storage.sql.exec('ALTER TABLE reverse DROP COLUMN views');
      s.storage.sql.exec('ALTER TABLE reverse DROP COLUMN used');
    });
    // New instances (as after a deploy): their constructors migrate.
    for (const stub of [dirStub(), driveOf(u.id)]) await runInDurableObject(stub, (i, s) => { try { s.abort('restart'); } catch { /* the instance ends here */ } }).catch(() => {});
    const after = await runInDurableObject(dirStub(), (i, s) => {
      const sql = s.storage.sql;
      const rows = sql.exec("SELECT user_id, channel, value FROM limits WHERE key = 'reverseMaxExpireSec' ORDER BY user_id, channel").toArray();
      return {
        version: sql.exec("SELECT v FROM meta WHERE k = 'schema_version'").one().v,
        cols: sql.exec('PRAGMA table_info(shares)').toArray().map((c) => c.name),
        rows,
        defaults: Object.fromEntries(sql.exec("SELECT key, value FROM limits WHERE user_id = '' AND channel = 'all'").toArray().map((x) => [x.key, JSON.parse(x.value)])),
      };
    });
    expect(SCHEMA_VERSION).toBe(18);
    expect(after.version).toBe('18'); // 18 (what Receive links accept) runs after it
    expect(after.cols).toContain('ended');
    expect(after.rows).toEqual(expect.arrayContaining([
      { user_id: '', channel: 'all', value: '86400' },
      { user_id: '', channel: 'api', value: '7200' },
      { user_id: `r:${role.id}`, channel: 'all', value: '3600' },
    ]));
    // The Default role holds a value for every new option.
    expect(after.defaults).toMatchObject({ reverseNoExpiry: false, reverseMaxViews: null, reverseAllowUnlimitedViews: true, reversePassword: 'allow', reversePasswordDefault: 'off', reverseEdit: true, reverseMaxExpireSec: 86400 });
    // The link made before: no views limit, its expiry and its password as they were.
    const d = await driveRow(u.id, oldLink.id);
    expect(d.views).toBeNull();
    expect(d.used).toBe(0);
    const head = await (await openLink(oldLink, freshIp())).json();
    expect(head.expires).toBeGreaterThan(nowSec() + 86400);
    expect(head.password).toBeTruthy();
    const ip = freshIp();
    expect((await begin(oldLink, { ip })).status).toBe(401);
    const g = await grantOf(oldLink, { ip, password: 'kept secret' });
    await send(oldLink, g, { ip });
    expect(await listed(u.cookie, oldLink.id)).toMatchObject({ views: null, used: 1, left: null });
    // Put the Default role's bound back (other tests use the Default role).
    await runInDurableObject(dirStub(), (i, s) => {
      s.storage.sql.exec("UPDATE limits SET value = 'null' WHERE user_id = '' AND key IN ('maxExpireSec', 'reverseMaxExpireSec')");
      s.storage.sql.exec("DELETE FROM limits WHERE user_id = '' AND channel = 'api' AND key IN ('maxExpireSec', 'reverseMaxExpireSec')");
    });
  });
});

describe('the uploader sees nothing new', () => {
  it('open does not reveal the views or who changed what (only what the link accepts, which the page offers)', async () => {
    const u = await receiver('rp-open');
    const r = await newReverse(u.cookie, { views: 3 });
    const head = await (await rv(r.id, '/open', { headers: { 'x-link-proof': await linkProof(r.pub) }, ip: freshIp() })).json();
    expect(Object.keys(head).sort()).toEqual(['accept', 'captcha', 'expires', 'limits', 'note', 'password']);
    expect(head.accept).toEqual(['files']);
    expect(Object.keys(head.limits).sort()).toEqual(['bytesLeft', 'filesLeft', 'maxBytes', 'maxFileBytes', 'maxFiles', 'types']);
  });
});
