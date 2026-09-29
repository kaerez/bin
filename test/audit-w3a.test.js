// audit-w3a.test.js — regression tests for the findings of security audit W3,
// part A (authentication and authorization, main at fc848a9):
//   A-1  moving a user to a looser role, or deleting a role with users, needs
//        the owner's step-up; a tightening assignment does not;
//   A-2  a quota removed, raised or given a shorter period (Default, a custom
//        role, the public account), and a role's quota switch to a looser
//        list, need it too;
//   A-3  made-up API keys, usernameless passkey challenges and made-up
//        sign-in challenges have per-network limits before the Directory,
//        which the owner sees and lifts;
//   A-4  removing a block rule, lifting a Guard block, unlocking an account
//        and unblocking (or forgetting) a browser id need the step-up;
//   A-5  the options that widen access or data exposure are weakening, and
//        every setting and role option is classified;
//   A-6  the per-network login limit is checked and counted in one Guard call:
//        concurrent wrong passwords never get more than the limit evaluated;
//   A-7  failed sign-ins and failed step-ups are in the audit log, added up,
//        sealed, the owner's included, unknown names by a keyed hash only;
//   A-8  an admin password reset, an owner recovery and (unless unticked) a
//        user's own password change revoke the account's API keys;
//   A-9  a password change keeps the session's absolute end;
//   A-10 an import refuses a custom role named "Public".
// Synthetic accounts and data only.
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { env, runInDurableObject } from 'cloudflare:test';
import worker from '../src/index.js';
import { owner, makeUser, login, fetchJson, cookieOf, freshIp, intent, proofFor, salt16, OWNER_STEP, ORIGIN, USER_PW, setOwnerCookie } from './helpers.js';
import { dirStub } from './reverse-helpers.js';
import { guardKeyFor, guardShardFor, API_KEY_FAILURES, PASSKEY_OPTIONS, AUTH_CHALLENGE, RATE_LIMIT_SCOPES } from '../src/lib/guard.js';
import {
  SETTINGS, LIMITS, WEAKENING_SETTINGS, WEAKENING_LIMITS, NOT_WEAKENING_SETTINGS, NOT_WEAKENING_LIMITS,
  weakenedSettings, weakenedLimits, weakenedQuotas, settingsWithDefaults, resolveLimits,
} from '../src/lib/settings.js';
import { validateExport } from '../src/lib/portable.js';

let oc;
let ownerId;
beforeAll(async () => {
  oc = await owner();
  ownerId = (await (await fetchJson('/api/private/me', { cookie: oc })).json()).user.id;
});
afterEach(() => { vi.useRealTimers(); });

const errorOf = async (r) => (await r.clone().json()).error;
const WRONG = { current: proofFor('not-the-owner-password') };
/** An admin write with exactly the confirmation given (`step: false`: the helpers add none). */
const admin = (method, path, body, step = {}) => fetchJson(path, { method, cookie: oc, headers: intent, body: body === undefined && !Object.keys(step).length ? undefined : { ...(body ?? {}), ...step }, step: false, ip: freshIp() });
/** A weakening change is refused without the step-up, naming what it weakens. */
const needsStepUp = async (r, weakens) => {
  expect([r.status, await errorOf(r)]).toEqual([400, 'reauth_required']);
  const got = (await r.json()).weakens;
  for (const w of weakens) expect(got).toContain(w);
};
const newRole = async (name) => {
  const r = await admin('POST', '/api/private/admin/roles', { name });
  expect(r.status).toBe(201);
  return (await r.json()).id;
};
const setRoleLimits = (id, patch, step = OWNER_STEP, channel = 'all') => admin('PATCH', '/api/private/admin/limits', { scope: `role:${id}`, channel, patch }, step);
const assign = (uid, roleId, step = {}) => admin('PUT', `/api/private/admin/users/${uid}/role`, { roleId }, step);
const roleOf = async (uid) => (await (await fetchJson(`/api/private/admin/users/${uid}`, { cookie: oc })).json()).role.id;
const quotas = (scope, list, step = {}) => admin('PUT', '/api/private/admin/quotas', { scope, list }, step);
const q = (max, n = 1, unit = 'd', kind = 'all', channel = 'all') => ({ channel, kind, n, unit, max });
const auditRows = async (subject) => (await (await fetchJson(`/api/private/admin/audit${subject ? `?user=${subject}` : ''}`, { cookie: oc })).json()).rows;
const guardRows = async () => (await fetchJson('/api/private/admin/guard', { cookie: oc })).json();
/** The network's Guard row for `scope` (`ip`/32), as the shard stores it. */
async function trackingOf(scope, ip) {
  const tag = await guardKeyFor(env, `${ip}/32`);
  return runInDurableObject(guardShardFor(env, tag), (_i, state) => state.storage.sql.exec('SELECT count FROM tracking WHERE scope = ? AND key = ?', scope, tag).toArray()[0]?.count ?? 0);
}
/** Seed the network's counter for `scope` (as that many refused requests would have left it). */
async function seed(scope, ip, count) {
  const tag = await guardKeyFor(env, `${ip}/32`);
  await runInDurableObject(guardShardFor(env, tag), (_i, state) => {
    const t = Math.floor(Date.now() / 1000);
    state.storage.sql.exec('INSERT OR REPLACE INTO tracking (scope, key, count, start, expires, addr, rk) VALUES (?, ?, ?, ?, ?, NULL, NULL)', scope, tag, count, t, t + 600);
  });
}
async function apiUser(name) {
  const u = await makeUser(name);
  const role = await newRole(`api ${name}`);
  expect((await setRoleLimits(role, { apiEnabled: true, apiMaxKeys: 5 })).status).toBe(200);
  expect((await assign(u.id, role, OWNER_STEP)).status).toBe(200);
  const r = await fetchJson(`/api/private/admin/users/${u.id}/keys`, { method: 'POST', cookie: oc, body: { name: 'k', scopes: ['read'] } });
  expect(r.status).toBe(201);
  return { ...u, key: (await r.json()).key };
}
const withKey = (key, ip = freshIp()) => fetchJson('/api/private/shares', { headers: { authorization: `Bearer ${key}` }, ip });

describe('A-1: a looser role for a user needs the owner\'s step-up', () => {
  it('assigning a looser role (or Default) asks for it, naming what loosens; a tighter one does not; a wrong password is refused', async () => {
    const u = await makeUser('w3a-role-user');
    const strict = await newRole('W3A strict');
    // Tightening the role's own options needs nothing.
    expect((await setRoleLimits(strict, { passkeys: 'second', sessionAbsSec: 3600, pwMinLength: 20 }, {})).status).toBe(200);
    // Default → strict tightens: no step-up.
    expect((await assign(u.id, strict)).status).toBe(200);
    // Strict → Default loosens the passkey mode, the session and the password policy.
    await needsStepUp(await assign(u.id, 'default'), ['passkeys', 'sessionAbsSec', 'pwMinLength']);
    expect(await roleOf(u.id)).toBe(strict); // nothing changed
    expect([(await assign(u.id, 'default', WRONG)).status, await errorOf(await assign(u.id, 'default', WRONG))]).toEqual([403, 'wrong_password']);
    expect((await assign(u.id, 'default', OWNER_STEP)).status).toBe(200);
    expect(await roleOf(u.id)).toBe('default');
    // A role that allows API keys (the audit's key-minting path) is looser too.
    const api = await newRole('W3A api');
    expect((await setRoleLimits(api, { apiEnabled: true })).status).toBe(200);
    await needsStepUp(await assign(u.id, api), ['apiEnabled']);
    // The same role again weakens nothing.
    expect((await assign(u.id, 'default')).status).toBe(200);
  });

  it('a role with a looser quota list is looser too', async () => {
    const u = await makeUser('w3a-role-quota');
    const tight = await newRole('W3A tight quota');
    const loose = await newRole('W3A loose quota');
    expect((await quotas(`role:${tight}`, [q(2)])).status).toBe(200); // the role's own list (Default has none)
    expect((await quotas(`role:${loose}`, [q(1000)], OWNER_STEP)).status).toBe(200);
    expect((await assign(u.id, tight)).status).toBe(200);
    await needsStepUp(await assign(u.id, loose), ['quotas']);
    expect((await assign(u.id, loose, OWNER_STEP)).status).toBe(200);
    expect((await assign(u.id, tight)).status).toBe(200); // back to the tighter one: nothing
  });

  it('deleting a role whose users would fall back to a looser Default asks for it (in the DELETE\'s JSON body); an empty role does not', async () => {
    const u = await makeUser('w3a-role-delete');
    const strict = await newRole('W3A delete strict');
    expect((await setRoleLimits(strict, { passkeys: 'second' }, {})).status).toBe(200);
    expect((await assign(u.id, strict)).status).toBe(200);
    await needsStepUp(await admin('DELETE', `/api/private/admin/roles/${strict}`), ['passkeys']);
    expect(await roleOf(u.id)).toBe(strict);
    const del = await fetchJson(`/api/private/admin/roles/${strict}`, { method: 'DELETE', cookie: oc, headers: intent, body: { ...OWNER_STEP }, step: false });
    expect(await del.json()).toMatchObject({ ok: true, moved: 1 });
    expect(await roleOf(u.id)).toBe('default');
    // No users: nothing loosens for anyone.
    const empty = await newRole('W3A empty');
    expect((await setRoleLimits(empty, { passkeys: 'second' }, {})).status).toBe(200);
    expect((await admin('DELETE', `/api/private/admin/roles/${empty}`)).status).toBe(200);
  });

  it('an API key never reaches the role routes (403 api_key_not_allowed, before any step-up)', async () => {
    const u = await apiUser('w3a-role-key');
    const r = await fetchJson(`/api/private/admin/users/${u.id}/role`, { method: 'PUT', headers: { authorization: `Bearer ${u.key}` }, body: { roleId: 'default', ...OWNER_STEP }, step: false });
    expect([r.status, await errorOf(r)]).toEqual([403, 'api_key_not_allowed']);
  });
});

describe('A-2: quota changes that loosen need the step-up', () => {
  it('weakenedQuotas: removed, raised or a shorter period loosens; added, lowered or a longer period does not', () => {
    expect(weakenedQuotas([q(5)], [])).toEqual(['all:all']);
    expect(weakenedQuotas([q(5)], [q(10000000)])).toEqual(['all:all']);
    expect(weakenedQuotas([q(5)], [q(5, 1, 'h')])).toEqual(['all:all']); // 5 an hour allows more than 5 a day
    expect(weakenedQuotas([q(5, 2, 'd')], [q(5, 1, 'd')])).toEqual(['all:all']);
    expect(weakenedQuotas([q(5, 31, 'd')], [q(5, 1, 'mo')])).toEqual(['all:all']); // a month may be 28 days
    expect(weakenedQuotas([q(5, 1, 'd', 'files')], [q(5, 1, 'd', 'text')])).toEqual(['all:files']);
    expect(weakenedQuotas([], [q(5)])).toEqual([]);
    expect(weakenedQuotas([q(5)], [q(3)])).toEqual([]);
    expect(weakenedQuotas([q(5)], [q(5, 7, 'd')])).toEqual([]);
    expect(weakenedQuotas([q(5, 1, 'mo')], [q(5, 1, 'mo')])).toEqual([]);
    expect(weakenedQuotas([q(5, 28, 'd')], [q(5, 1, 'mo')])).toEqual([]);
    expect(weakenedQuotas([q(5)], [q(5), q(1, 1, 'h')])).toEqual([]);
  });

  it('the Default role, a custom role and the public account', async () => {
    expect((await quotas('global', [q(5)])).status).toBe(200); // added: tightens
    await needsStepUp(await quotas('global', [q(10000000)]), ['quotas']);
    await needsStepUp(await quotas('global', [q(5, 1, 'h')]), ['quotas']);
    await needsStepUp(await quotas('global', []), ['quotas']);
    expect([(await quotas('global', [], WRONG)).status]).toEqual([403]);
    expect((await quotas('global', [q(3)])).status).toBe(200); // lower: tightens
    expect((await quotas('global', [q(3, 7, 'd')])).status).toBe(200); // longer period: tightens
    expect((await quotas('global', [], OWNER_STEP)).status).toBe(200);
    // The public account's own list (seeded with 10 a day).
    const pub = 'public-user-0000';
    await needsStepUp(await quotas(pub, []), ['quotas']);
    expect((await quotas(pub, [], OWNER_STEP)).status).toBe(200);
    expect((await quotas(pub, [q(10)])).status).toBe(200);
    // A custom role saving its own list compares with what its users were counted against (Default's).
    const role = await newRole('W3A quota role');
    expect((await quotas('global', [q(5)])).status).toBe(200);
    await needsStepUp(await quotas(`role:${role}`, [q(50)]), ['quotas']);
    expect((await quotas(`role:${role}`, [q(2)])).status).toBe(200);
    expect((await quotas('global', [], OWNER_STEP)).status).toBe(200);
  });

  it('a role switching its own quota list off (to a looser Default) asks for it; back on (stricter) does not', async () => {
    const role = await newRole('W3A own quotas');
    expect((await quotas(`role:${role}`, [q(2)])).status).toBe(200);
    const patch = (ownQuotas, step = {}) => admin('PATCH', `/api/private/admin/roles/${role}`, { ownQuotas }, step);
    await needsStepUp(await patch(false), ['quotas']);
    expect((await (await fetchJson(`/api/private/admin/roles/${role}`, { cookie: oc })).json()).role.ownQuotas).toBe(true);
    expect((await patch(false, OWNER_STEP)).status).toBe(200);
    expect((await patch(true)).status).toBe(200);
    // A rename alone needs nothing.
    expect((await admin('PATCH', `/api/private/admin/roles/${role}`, { name: 'W3A own quotas 2' })).status).toBe(200);
  });
});

describe('A-3: per-network limits on anonymous calls that reach the Directory', () => {
  it('made-up API keys: counted on a refusal only; past the limit the network is refused before the lookup, working keys included; the owner sees and lifts it', async () => {
    const u = await apiUser('w3a-keys');
    const busy = freshIp();
    for (let i = 0; i < 3; i++) expect((await withKey(u.key, busy)).status).toBe(200);
    expect(await trackingOf('api-key', busy)).toBe(0); // a working key is never counted
    const ip = freshIp();
    const fake = `sbk_${'A'.repeat(43)}`;
    expect((await withKey(fake, ip)).status).toBe(401);
    expect(await trackingOf('api-key', ip)).toBe(1);
    await seed('api-key', ip, API_KEY_FAILURES.max - 2);
    expect((await withKey(fake, ip)).status).toBe(401); // the (max − 1)th is still answered
    const over = await withKey(fake, ip);
    expect([over.status, await errorOf(over)]).toEqual([429, 'rate_limited']);
    expect(Number(over.headers.get('retry-after'))).toBeGreaterThan(0);
    // Blocked: even a working key from that network, before the Directory is asked.
    expect((await withKey(u.key, ip)).status).toBe(429);
    expect((await withKey(u.key, freshIp())).status).toBe(200);
    // Visible to the owner, and liftable (with the step-up: A-4).
    expect(RATE_LIMIT_SCOPES).toEqual(expect.arrayContaining(['api-key', 'passkey-options', 'auth-challenge']));
    const block = (await guardRows()).blocks.find((b) => b.scope === 'api-key' && b.addr === `${ip}/32`);
    expect(block).toBeTruthy();
    await needsStepUp(await admin('POST', '/api/private/admin/guard/unblock', { scope: 'api-key', key: block.key }), ['guard.unblock']);
    expect((await admin('POST', '/api/private/admin/guard/unblock', { scope: 'api-key', key: block.key }, OWNER_STEP)).status).toBe(200);
    expect((await withKey(u.key, ip)).status).toBe(200);
  });

  it('usernameless passkey challenges: every request counts, per network', async () => {
    const ip = freshIp();
    const options = () => fetchJson('/api/auth/passkey/options', { method: 'POST', body: {}, ip });
    expect((await options()).status).toBe(200);
    expect(await trackingOf('passkey-options', ip)).toBe(1);
    await seed('passkey-options', ip, PASSKEY_OPTIONS.max - 2);
    expect((await options()).status).toBe(200);
    const over = await options();
    expect([over.status, await errorOf(over)]).toEqual([429, 'rate_limited']);
    expect((await fetchJson('/api/auth/passkey/options', { method: 'POST', body: {}, ip: freshIp() })).status).toBe(200);
  });

  it('made-up sign-in challenges (passkey sign-in, second step): counted in their own scope, whose block refuses both before the Directory', async () => {
    const ip = freshIp();
    const made = 'A'.repeat(48);
    const pk = () => fetchJson('/api/auth/passkey/login', { method: 'POST', body: { challengeId: made, credential: { id: 'B'.repeat(22) } }, ip });
    const second = () => fetchJson('/api/auth/second-factor', { method: 'POST', body: { challengeId: 'C'.repeat(22), code: 'AAAA-AAAA-AAAA-AAAA' }, ip });
    expect([(await pk()).status, (await second()).status]).toEqual([400, 400]);
    expect(await trackingOf('auth-challenge', ip)).toBe(2);
    expect(await trackingOf('login', ip)).toBe(0); // not a wrong credential: the login count went back
    await seed('auth-challenge', ip, AUTH_CHALLENGE.max - 2);
    expect((await pk()).status).toBe(400);
    const over = await pk();
    expect([over.status, await errorOf(over)]).toEqual([429, 'rate_limited']);
    const refused = await second();
    expect([refused.status, await errorOf(refused)]).toEqual([429, 'rate_limited']);
    expect(Number(refused.headers.get('retry-after'))).toBeGreaterThan(0);
    // A recovery-code sign-in is not a challenge: it is refused as before.
    expect((await fetchJson('/api/auth/recovery', { method: 'POST', body: { username: 'nobody-w3a', code: 'AAAA-AAAA-AAAA-AAAA' }, ip })).status).toBe(401);
  });
});

describe('A-4: lifting a network control needs the step-up', () => {
  it('removing a block rule asks for it; removing an allow rule does not', async () => {
    const add = async (cidr, action) => (await (await fetchJson('/api/private/admin/ip-rules', { method: 'POST', cookie: oc, body: { cidr, action, note: 'w3a' } })).json()).id;
    const block = await add('203.0.113.0/28', 'block');
    await needsStepUp(await admin('DELETE', `/api/private/admin/ip-rules/${block}`), ['ipRule.block']);
    expect((await fetchJson('/api/private/admin/ip-rules', { cookie: oc }).then((r) => r.json())).rules.some((r) => r.id === block)).toBe(true);
    expect((await fetchJson(`/api/private/admin/ip-rules/${block}`, { method: 'DELETE', cookie: oc, headers: intent, body: { ...WRONG }, step: false, ip: freshIp() })).status).toBe(403);
    expect((await fetchJson(`/api/private/admin/ip-rules/${block}`, { method: 'DELETE', cookie: oc, headers: intent, body: { ...OWNER_STEP }, step: false })).status).toBe(200);
    const allow = await add('203.0.113.64/28', 'allow');
    expect((await admin('DELETE', `/api/private/admin/ip-rules/${allow}`)).status).toBe(200);
  });

  it('lifting a Guard block asks for it; placing one does not', async () => {
    const ip = freshIp();
    expect((await admin('POST', '/api/private/admin/guard/block', { scope: 'login', key: ip, seconds: 600 })).status).toBe(200);
    await needsStepUp(await admin('POST', '/api/private/admin/guard/unblock', { scope: 'login', key: ip }), ['guard.unblock']);
    expect((await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'owner', proof: proofFor('owner-password') }, ip })).status).toBe(429);
    expect((await admin('POST', '/api/private/admin/guard/unblock', { scope: 'login', key: ip }, OWNER_STEP)).status).toBe(200);
    expect((await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'owner', proof: proofFor('owner-password') }, ip })).status).toBe(200);
  });

  it('unlocking a locked account asks for it (in the POST\'s JSON body); an account with nothing counted needs nothing', async () => {
    const u = await makeUser('w3a-unlock');
    await runInDurableObject(dirStub(), (_i, s) => s.storage.sql.exec('INSERT OR REPLACE INTO failures (user_id, count, start, locked_until) VALUES (?, 0, ?, ?)', u.id, Math.floor(Date.now() / 1000), Math.floor(Date.now() / 1000) + 900));
    expect((await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'w3a-unlock', proof: proofFor(USER_PW) }, ip: freshIp() })).status).toBe(423);
    await needsStepUp(await admin('POST', `/api/private/admin/users/${u.id}/unlock`), ['account.unlock']);
    expect((await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'w3a-unlock', proof: proofFor(USER_PW) }, ip: freshIp() })).status).toBe(423);
    expect((await admin('POST', `/api/private/admin/users/${u.id}/unlock`, {}, OWNER_STEP)).status).toBe(200);
    expect((await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'w3a-unlock', proof: proofFor(USER_PW) }, ip: freshIp() })).status).toBe(200);
    expect((await admin('POST', `/api/private/admin/users/${u.id}/unlock`)).status).toBe(200); // nothing to lift
  });

  it('unblocking or forgetting a browser id asks for it; blocking one does not', async () => {
    const hash = `W3Atracker01${'x'.repeat(31)}`;
    await runInDurableObject(dirStub(), (_i, s) => s.storage.sql.exec("INSERT INTO trackers (id_hash, created, last_seen, uses, ip_hash, blocked, reason) VALUES (?, ?, ?, 1, 'h', 1, 'admin')", hash, 1, Math.floor(Date.now() / 1000)));
    const act = (action, step = {}) => admin('POST', '/api/private/admin/public/trackers/W3Atracker01', { action }, step);
    await needsStepUp(await act('unblock'), ['tracker.unblock']);
    await needsStepUp(await act('forget'), ['tracker.forget']);
    const blocked = () => runInDurableObject(dirStub(), (_i, s) => s.storage.sql.exec('SELECT blocked FROM trackers WHERE id_hash = ?', hash).toArray()[0]?.blocked);
    expect(await blocked()).toBe(1);
    expect((await act('unblock', OWNER_STEP)).status).toBe(200);
    expect(await blocked()).toBe(0);
    expect((await act('block')).status).toBe(200);
    expect((await act('forget', OWNER_STEP)).status).toBe(200);
    expect(await blocked()).toBeUndefined();
  });
});

describe('A-5: every option that widens access or data exposure is weakening', () => {
  it('the classification is complete: each setting and role option is weakening or has a reason not to be', () => {
    for (const k of Object.keys(SETTINGS)) {
      expect(WEAKENING_SETTINGS.includes(k) !== Object.prototype.hasOwnProperty.call(NOT_WEAKENING_SETTINGS, k), k).toBe(true);
    }
    for (const k of Object.keys(LIMITS)) {
      expect(WEAKENING_LIMITS.includes(k) !== Object.prototype.hasOwnProperty.call(NOT_WEAKENING_LIMITS, k), k).toBe(true);
    }
    for (const reason of [...Object.values(NOT_WEAKENING_SETTINGS), ...Object.values(NOT_WEAKENING_LIMITS)]) expect(typeof reason === 'string' && reason.length > 20).toBe(true);
  });

  it('settings: the tracking mode loosened, the notice off or emptied, a longer id retention, a longer download window', () => {
    const base = settingsWithDefaults({ 'public.tracking': 'both-restrictive' });
    const w = (patch) => weakenedSettings(base, { ...base, ...patch });
    expect(w({ 'public.tracking': 'tracker' })).toEqual(['public.tracking']);
    expect(w({ 'public.tracking': 'both-permissive' })).toEqual(['public.tracking']);
    expect(weakenedSettings({ ...base, 'public.tracking': 'tracker' }, { ...base, 'public.tracking': 'ip' })).toEqual([]); // the same rank
    expect(weakenedSettings({ ...base, 'public.tracking': 'tracker' }, base)).toEqual([]);
    expect(w({ 'public.notice': false })).toEqual(['public.notice']);
    expect(w({ 'public.noticeText': '' })).toEqual(['public.noticeText']);
    expect(w({ 'public.noticeText': 'Another notice.' })).toEqual([]);
    expect(w({ 'public.trackerIdleSec': base['public.trackerIdleSec'] + 86400 })).toEqual(['public.trackerIdleSec']);
    expect(w({ 'files.grantSec': base['files.grantSec'] + 60 })).toEqual(['files.grantSec']);
    expect(w({ 'files.pendingSec': base['files.pendingSec'] + 60 })).toEqual([]);
  });

  it('role options: Receive, the Drive, receipt details, notes, more keys, passkeys or active links, the viewer, a longer download window', () => {
    const base = resolveLimits({}, {});
    const w = (patch) => weakenedLimits(base, { ...base, ...patch }, settingsWithDefaults({}));
    const on = ['reverseEnabled', 'driveEnabled', 'receiptIp', 'receiptLocation', 'receiptBrowser', 'receiptOs', 'receiptLanguages', 'viewer'];
    for (const k of on) expect(w({ [k]: true }), k).toEqual([k]);
    expect(weakenedLimits({ ...base, text: false }, base, settingsWithDefaults({}))).toEqual(['text']);
    expect(weakenedLimits({ ...base, reverseText: false }, base, settingsWithDefaults({}))).toEqual(['reverseText']);
    expect(w({ apiMaxKeys: 50 })).toEqual(['apiMaxKeys']);
    expect(w({ apiMaxKeys: null })).toEqual(['apiMaxKeys']);
    expect(weakenedLimits({ ...base, passkeysMax: 2 }, { ...base, passkeysMax: 5 }, settingsWithDefaults({}))).toEqual(['passkeysMax']);
    expect(w({ reverseMaxActive: null })).toEqual(['reverseMaxActive']);
    expect(w({ fileGrantSec: 7200 })).toEqual(['fileGrantSec']);
    // Not weakening, with their reasons (NOT_WEAKENING_LIMITS).
    expect(w({ maxShareBytes: null, driveMaxBytes: null, openerDelete: true, reverseEdit: false, viewerCustomRules: true })).toEqual([]);
  });

  it('through the admin routes: turning Receive on for a role, the notice off for the public account\'s visitors', async () => {
    const role = await newRole('W3A receive');
    await needsStepUp(await setRoleLimits(role, { reverseEnabled: true }, {}), ['reverseEnabled']);
    await needsStepUp(await setRoleLimits(role, { receiptIp: true, receiptLocation: true }, {}), ['receiptIp', 'receiptLocation']);
    expect((await setRoleLimits(role, { reverseEnabled: true })).status).toBe(200);
    const settings = (patch, step = {}) => admin('PATCH', '/api/private/admin/settings', patch, step);
    await needsStepUp(await settings({ 'public.notice': false }), ['public.notice']);
    expect((await settings({ 'public.tracking': 'both-restrictive' })).status).toBe(200); // tightens
    await needsStepUp(await settings({ 'public.tracking': 'both-permissive' }), ['public.tracking']);
    await needsStepUp(await settings({ 'public.trackerIdleSec': 200 * 86400 }), ['public.trackerIdleSec']);
    expect((await settings({ 'public.tracking': 'tracker' }, OWNER_STEP)).status).toBe(200);
  });
});

describe('A-6: the per-network login limit is checked and counted at once', () => {
  it('60 concurrent wrong owner passwords from one network: at most guard.login.max are evaluated', async () => {
    const max = (await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json()).settings['guard.login.max'];
    const ip = freshIp();
    const all = await Promise.all(Array.from({ length: 60 }, () => fetchJson('/api/auth/login', { method: 'POST', body: { username: 'owner', proof: proofFor('w3a-wrong-guess') }, ip })));
    const statuses = all.map((r) => r.status);
    const evaluated = statuses.filter((s) => s === 401).length;
    expect(evaluated).toBeLessThanOrEqual(max);
    expect(evaluated + statuses.filter((s) => s === 429).length).toBe(60);
    // The owner's log adds the evaluated ones up (A-7): no more than the limit either.
    const failed = (await auditRows(ownerId)).filter((r) => r.action === 'login.failed' && r.detail.includes(`from=${ip}`))
      .reduce((n, r) => n + Number(/failed=(\d+)/.exec(r.detail)[1]), 0);
    expect(failed).toBeLessThanOrEqual(max);
    // The network is blocked now, the right password included.
    expect((await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'owner', proof: proofFor('owner-password') }, ip })).status).toBe(429);
  });

  it('a sign-in that did not fail gives its count back; the one that reaches the limit is still evaluated (429 after it)', async () => {
    const max = (await (await fetchJson('/api/private/admin/overview', { cookie: oc })).json()).settings['guard.login.max'];
    const u = await makeUser('w3a-burst');
    const ip = freshIp();
    const bad = () => fetchJson('/api/auth/login', { method: 'POST', body: { username: 'w3a-burst', proof: proofFor('nope-nope-nope') }, ip });
    for (let i = 0; i < 3; i++) expect((await bad()).status).toBe(401);
    expect((await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'w3a-burst', proof: proofFor(USER_PW) }, ip })).status).toBe(200);
    expect(await trackingOf('login', ip)).toBe(3);
    await runInDurableObject(dirStub(), (_i, s) => s.storage.sql.exec('DELETE FROM failures WHERE user_id = ?', u.id)); // keep the account lockout out of it
    for (let i = 3; i < max - 1; i++) expect((await bad()).status).toBe(401);
    expect([(await bad()).status]).toEqual([429]); // the max-th: evaluated, then the network is blocked
    expect((await bad()).status).toBe(429);
  });
});

describe('A-7: failed sign-ins and step-ups are in the audit log', () => {
  const failures = async (subject, action = 'login.failed') => (await auditRows(subject)).filter((r) => r.action === action);

  it('wrong passwords and recovery codes of a user: one entry that adds them up, sealed at rest, shown to the user too', async () => {
    const u = await makeUser('w3a-audit-user');
    const ip = freshIp();
    for (let i = 0; i < 3; i++) await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'w3a-audit-user', proof: proofFor('wrong-one-123') }, ip });
    await fetchJson('/api/auth/recovery', { method: 'POST', body: { username: 'w3a-audit-user', code: 'AAAA-AAAA-AAAA-AAAA' }, ip });
    const rows = await failures(u.id);
    expect(rows.length).toBe(1);
    // The detail, parsed (no pattern built from the address).
    const m = /^failed=(\d+) via=(.+) last=(\d+) from=(\S+)$/.exec(rows[0].detail);
    expect(m && { failed: m[1], via: m[2], from: m[4] }).toEqual({ failed: '4', via: 'password,recovery code', from: ip });
    const stored = await runInDurableObject(dirStub(), (_i, s) => s.storage.sql.exec("SELECT detail, rk FROM activity WHERE subject_id = ? AND action = 'login.failed'", u.id).toArray());
    expect(stored.length).toBe(1);
    expect(stored[0].rk).toBeTruthy(); // sealed (the keyring exists since set-up)
    expect(stored[0].detail).not.toContain(ip);
    const mine = (await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json()).rows;
    expect(mine.some((r) => r.action === 'login.failed')).toBe(true);
  });

  it('failed owner sign-ins are recorded (the owner has no lockout)', async () => {
    const before = (await failures(ownerId)).length;
    const ip = freshIp();
    await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'owner', proof: proofFor('w3a-owner-guess') }, ip });
    const rows = await failures(ownerId);
    expect(rows.length).toBeGreaterThanOrEqual(Math.max(1, before));
    expect(rows.some((r) => r.detail.includes(`from=${ip}`))).toBe(true);
  });

  it('an unknown username: the same refusal as a real one, logged under a keyed hash only (never the name typed)', async () => {
    await makeUser('w3a-real-name');
    const ip = freshIp();
    const real = await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'w3a-real-name', proof: proofFor('bad-guess-123') }, ip });
    const fake = await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'w3a-typed-secret-name', proof: proofFor('bad-guess-123') }, ip });
    expect([fake.status, await fake.json()]).toEqual([real.status, await real.json()]);
    const rows = (await auditRows()).filter((r) => r.action === 'login.failed' && r.subject_id?.startsWith('n:'));
    expect(rows.length).toBeGreaterThan(0);
    expect(rows[0].detail).toMatch(/^unknown username failed=1 via=password/);
    expect(rows[0].subject_id).toMatch(/^n:[A-Za-z0-9_-]{24}$/);
    const everything = await runInDurableObject(dirStub(), (_i, s) => JSON.stringify(s.storage.sql.exec('SELECT * FROM activity').toArray()));
    expect(everything).not.toContain('w3a-typed-secret-name');
  });

  it('many unknown names at once share one entry past the cap', async () => {
    await runInDurableObject(dirStub(), (_i, s) => {
      const t = Math.floor(Date.now() / 1000);
      for (let i = 0; i < 100; i++) s.storage.sql.exec("INSERT INTO activity (ts, actor_id, subject_id, action, detail) VALUES (?, NULL, ?, 'login.failed', 'x')", t, `n:seeded${String(i).padStart(16, '0')}`);
    });
    for (const n of ['w3a-spray-1', 'w3a-spray-2']) await fetchJson('/api/auth/login', { method: 'POST', body: { username: n, proof: proofFor('x-x-x-x-x-x') }, ip: freshIp() });
    const shared = (await auditRows()).filter((r) => r.action === 'login.failed' && r.subject_id === 'n:*');
    expect(shared.length).toBe(1);
    expect(shared[0].detail).toMatch(/^unknown username failed=2 /);
    await runInDurableObject(dirStub(), (_i, s) => s.storage.sql.exec("DELETE FROM activity WHERE subject_id LIKE 'n:seeded%' OR subject_id = 'n:*'"));
  });

  it('a failed second step, and a passkey no account has', async () => {
    const u = await makeUser('w3a-second');
    await runInDurableObject(dirStub(), (_i, s) => {
      s.storage.sql.exec("INSERT INTO passkeys (id, user_id, name, public_key, alg, created) VALUES ('w3apasskeyAAAAAAAA', ?, 'key', 'x', -7, ?)", u.id, Math.floor(Date.now() / 1000));
      s.storage.sql.exec('UPDATE users SET mfa = 1 WHERE id = ?', u.id);
    });
    const ip = freshIp();
    const first = await (await fetchJson('/api/auth/login', { method: 'POST', body: { username: 'w3a-second', proof: proofFor(USER_PW) }, ip })).json();
    expect(first.secondFactor).toBeTruthy();
    const r = await fetchJson('/api/auth/second-factor', { method: 'POST', body: { challengeId: first.secondFactor.challengeId, code: 'AAAA-AAAA-AAAA-AAAA' }, ip });
    expect(r.status).toBe(401);
    expect((await failures(u.id))[0].detail).toMatch(/^failed=1 via=recovery code after password /);
    const opt = await (await fetchJson('/api/auth/passkey/options', { method: 'POST', body: {}, ip })).json();
    const pk = await fetchJson('/api/auth/passkey/login', { method: 'POST', body: { challengeId: opt.challengeId, credential: { id: 'Z'.repeat(22) } }, ip });
    expect(pk.status).toBe(401);
    expect((await failures('n:passkey'))[0].detail).toMatch(/^unknown passkey failed=\d+ via=passkey /);
  });

  it('migration 20 rebuilds the index of the unsealed sign-in rows for the new actions (a Directory at 19)', async () => {
    const stub = () => env.DIRECTORY.get(env.DIRECTORY.idFromName('w3a-m20')); // a new stub after the restart
    const indexSql = () => runInDurableObject(stub(), (_i, s) => s.storage.sql.exec("SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'activity_unsealed'").one().sql);
    await runInDurableObject(stub(), (_i, s) => {
      const sql = s.storage.sql;
      // As release 19 left it: the index over the ten sign-in actions of then.
      sql.exec('DROP INDEX activity_unsealed');
      sql.exec("CREATE INDEX activity_unsealed ON activity(id) WHERE rk IS NULL AND action IN ('login', 'login.password_ok', 'logout', 'account.locked', 'account.unlocked', 'sessions.revoked', 'passkey.added', 'passkey.removed', 'guard.blocked', 'guard.unblocked')");
      sql.exec("UPDATE meta SET v = '19' WHERE k = 'schema_version'");
    });
    expect(await indexSql()).not.toContain('login.failed');
    await runInDurableObject(stub(), (_i, s) => { try { s.abort('restart'); } catch { /* the instance ends here */ } }).catch(() => {});
    expect(await runInDurableObject(stub(), (_i, s) => s.storage.sql.exec("SELECT v FROM meta WHERE k = 'schema_version'").one().v)).toBe('20');
    expect(await indexSql()).toContain("'login.failed', 'stepup.failed'");
  });

  it('a failed step-up (the owner\'s included) is recorded as stepup.failed', async () => {
    const r = await admin('PATCH', '/api/private/admin/settings', { csrfTokens: false }, WRONG);
    expect(await errorOf(r)).toBe('wrong_password');
    const rows = await failures(ownerId, 'stepup.failed');
    expect(rows.length).toBe(1);
    expect(rows[0].detail).toMatch(/^failed=\d+ via=password last=\d+$/);
  });
});

describe('A-8: credential resets revoke the account\'s API keys', () => {
  it('an admin password reset revokes them; the passkeys and recovery codes stay', async () => {
    const u = await apiUser('w3a-reset');
    await runInDurableObject(dirStub(), (_i, s) => {
      s.storage.sql.exec("INSERT INTO passkeys (id, user_id, name, public_key, alg, created) VALUES ('w3aresetpasskeyAAAA', ?, 'key', 'x', -7, 1)", u.id);
      s.storage.sql.exec("INSERT INTO recovery_codes (hash, user_id, created) VALUES ('w3a-reset-code', ?, 1)", u.id);
    });
    expect((await withKey(u.key)).status).toBe(200);
    const r = await fetchJson(`/api/private/admin/users/${u.id}/password`, { method: 'POST', cookie: oc, body: { salt: salt16(), t: 3, proof: proofFor('w3a-reset-new-pw') } });
    expect(await r.json()).toMatchObject({ ok: true, keysRevoked: 1 });
    expect((await withKey(u.key)).status).toBe(401);
    const d = await (await fetchJson(`/api/private/admin/users/${u.id}`, { cookie: oc })).json();
    expect(d.keys).toEqual([]);
    expect(d.passkeys).toMatchObject({ count: 1, recoveryLeft: 1 });
    expect((await auditRows(u.id)).find((x) => x.action === 'password.reset_by_admin').detail).toBe('API keys revoked=1');
  });

  it('a user\'s own password change revokes them unless "Also revoke my API keys" is unticked', async () => {
    const u = await apiUser('w3a-own-change');
    const change = (cookie, from, to, extra = {}) => fetchJson('/api/private/me/password', { method: 'POST', cookie, body: { current: proofFor(from), salt: salt16(), t: 3, proof: proofFor(to), ...extra } });
    const kept = await change(u.cookie, USER_PW, 'w3a-second-pw-1', { revokeKeys: false });
    expect(await kept.json()).toMatchObject({ ok: true, keysRevoked: 0 });
    expect((await withKey(u.key)).status).toBe(200);
    const c2 = cookieOf(kept);
    expect((await change(c2, 'w3a-second-pw-1', 'w3a-third-pw-12', { revokeKeys: 'yes' })).status).toBe(400);
    const gone = await change(c2, 'w3a-second-pw-1', 'w3a-third-pw-12');
    expect(await gone.json()).toMatchObject({ ok: true, keysRevoked: 1 });
    expect((await withKey(u.key)).status).toBe(401);
  });
});

describe('A-9: a password change keeps the session\'s absolute end', () => {
  it('the new session ends when the sign-in does, not later', async () => {
    const t0 = Date.now();
    vi.useFakeTimers({ now: t0, toFake: ['Date'] });
    await makeUser('w3a-abs');
    const c = await login('w3a-abs', USER_PW, freshIp());
    const endsAt = (await (await fetchJson('/api/private/me', { cookie: c })).json()).session.endsAt;
    vi.setSystemTime(t0 + 3600_000);
    const r = await fetchJson('/api/private/me/password', { method: 'POST', cookie: c, body: { current: proofFor(USER_PW), salt: salt16(), t: 3, proof: proofFor('w3a-abs-new-pw-1') } });
    expect(r.status).toBe(200);
    const after = (await (await fetchJson('/api/private/me', { cookie: cookieOf(r) })).json()).session.endsAt;
    expect(after).toBe(endsAt);
  });
});

describe('A-10: an import cannot create a custom role named "Public"', () => {
  it('refused in any case, trimmed; a user\'s role "Public" too', async () => {
    const CURRENT = proofFor('owner-password');
    const doc = (await (await fetchJson('/api/private/admin/export', { method: 'POST', cookie: oc, body: { current: CURRENT, system: { roles: true } } })).json()).document;
    const role = { name: ' pUbLiC ', ownQuotas: false, limits: { all: {}, api: {} }, quotas: [], viewerRules: [] };
    const bad = { ...doc, system: { ...doc.system, roles: [...(doc.system.roles ?? []), role] } };
    expect(() => validateExport(bad)).toThrow(/built-in role/);
    const r = await fetchJson('/api/private/admin/import', { method: 'POST', cookie: oc, body: { current: CURRENT, document: bad, decisions: { system: true }, dryRun: true } });
    expect([r.status, await errorOf(r)]).toEqual([400, 'invalid_import']);
    const userDoc = { ...doc, users: [{ username: 'w3a-imported', role: 'Public' }] };
    expect(() => validateExport(userDoc)).toThrow(/Public role belongs to the public/);
  });
});

// Last: the owner's password changes here.
describe('A-8: an owner recovery revokes the owner\'s API keys', () => {
  it('the owner\'s own key stops working after a recovery through AUTHN', async () => {
    const made = await fetchJson(`/api/private/admin/users/${ownerId}/keys`, { method: 'POST', cookie: oc, body: { ...OWNER_STEP, name: 'owner-key', scopes: ['read'] } });
    expect(made.status).toBe(201);
    const key = (await made.json()).key;
    expect((await withKey(key)).status).toBe(200);
    const NEW = 'w3a-a-brand-new-recovery-token-0123456789';
    const rec = await worker.fetch(new Request(`${ORIGIN}/api/auth/setup`, {
      method: 'POST', headers: { 'content-type': 'application/json', 'cf-connecting-ip': freshIp() },
      body: JSON.stringify({ token: NEW, username: 'owner', salt: salt16(), t: 3, proof: proofFor('w3a-recovered-owner') }),
    }), { ...env, AUTHN: NEW }, { waitUntil() {} });
    expect(rec.status).toBe(200);
    expect((await rec.json()).recovered).toBe(true);
    expect((await withKey(key)).status).toBe(401);
    oc = await login('owner', 'w3a-recovered-owner');
    setOwnerCookie(oc);
    expect((await auditRows(ownerId)).find((x) => x.action === 'owner.recovered').detail).toMatch(/API keys revoked=1/);
  });
});
