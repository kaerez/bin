// reverse-audit4.test.js — regression tests for the reverse-share findings of
// security audit round 4 (workerd, the real Worker and Durable Objects), each
// ported from its proof of concept and asserting the fixed behaviour:
//   R4-L1 an upload session is idle again (SESSION_IDLE_SEC) once nothing is
//         unfinished — after a finished or a cancelled file too — and gives
//         its per-network slot back;
//   R4-L2 a role's lowered reverseMaxBytes applies to existing links;
//   R4-L3 take-in, mark-failed and retry by the owner acting as the user are
//         Drive actions: the user's own in their activity, the owner as the
//         real actor in the admin audit (imp, not adm);
//   R4-I1 a reverse-share id is never claimable again, even after its index
//         row is pruned or its account deleted.
import { runDurableObjectAlarm, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import { owner, fetchJson, intent, freshIp, proofFor, USER_PW, cookieOf, login } from './helpers.js';
import { driveLimits, mkdir, driveKeys } from './drive-helpers.js';
import { SESSION_IDLE_SEC, MAX_SESSIONS_PER_NET, MAX_SESSIONS, RECEIVE_MAX_SEC } from '../src/drive-do.js';
import { createReverseKey, linkHash, sealNote } from '../public/js/reversekeys.js';
import { randomBytes } from '../public/js/bytes.js';
import {
  sealLinkPriv, takeInAny, dirStub, driveOf, errorOf, receiver, newReverse, rv, openLink, begin, grantOf, reserve, send, received,
} from './reverse-helpers.js';

let oc;
beforeAll(async () => { oc = await owner(); });
afterEach(() => vi.useRealTimers());
const at = (ms) => vi.useFakeTimers({ now: ms, toFake: ['Date'] });
const v6 = (k) => `2001:db8:77:${k.toString(16)}::1`; // a distinct IPv6 /64 per k
const audit = async (subject) => (await (await fetchJson(`/api/private/admin/audit?user=${subject}`, { cookie: oc })).json()).rows;
const sessions = (uid) => runInDurableObject(driveOf(uid), (inst, state) => state.storage.sql.exec('SELECT expires, started FROM rsessions').toArray());

describe('R4-L1: a session with nothing unfinished is idle again, whatever it sent before', () => {
  it('after a finished (empty) file it lapses after SESSION_IDLE_SEC and gives its per-network slot back', async () => {
    const u = await receiver('r4-l1', { filePendingSec: 3600 });
    const r = await newReverse(u.cookie);
    expect(r.res.status).toBe(201);
    const ip = freshIp();
    const grants = [];
    for (let k = 0; k < MAX_SESSIONS_PER_NET; k++) {
      const g = await grantOf(r, { ip });
      await send(r, g, { ip, bytes: new Uint8Array(0) }); // reserved (the session: filePendingSec) and finalized (idle again)
      grants.push(g);
    }
    const t0 = Date.now();
    // Nothing unfinished: each session ends SESSION_IDLE_SEC after its file, not filePendingSec.
    for (const x of await sessions(u.id)) expect(x.expires).toBeLessThanOrEqual(Math.floor(t0 / 1000) + SESSION_IDLE_SEC);
    // A 6th session from the same network is refused while they are open…
    const busy = await begin(r, { ip });
    expect([busy.status, await errorOf(busy)]).toEqual([429, 'busy']);
    // …but 11 minutes idle, they have lapsed: the grant reserves nothing and the network may begin again.
    at(t0 + (SESSION_IDLE_SEC + 60) * 1000);
    const stale = await reserve(r, grants[0], { ip, bytes: new Uint8Array(0) });
    expect([stale.res.status, await errorOf(stale.res)]).toEqual([403, 'bad_grant']);
    expect((await begin(r, { ip })).status).toBe(200);
  }, 120000);

  it('reserving and cancelling a file does not keep the session open either', async () => {
    const u = await receiver('r4-l1-cancel', { filePendingSec: 3600 });
    const r = await newReverse(u.cookie);
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    const f = await reserve(r, g, { ip });
    expect(f.res.status).toBe(201);
    const t0 = Date.now();
    // While the file is unfinished the session is open for filePendingSec.
    expect((await sessions(u.id))[0].expires).toBeGreaterThan(Math.floor(t0 / 1000) + SESSION_IDLE_SEC);
    const c = await rv(r.id, `/files/${f.node}`, { method: 'DELETE', headers: { 'x-reverse-grant': g, 'x-upload-token': f.data.uploadToken }, ip });
    expect(c.status).toBe(200);
    // The cancel sets the session's end to (the server's second at the cancel) + SESSION_IDLE_SEC,
    // and that second lies between t0 and t1: the bound is the latest of them (t0 is before the
    // cancel and may be a second earlier).
    const t1 = Date.now();
    expect((await sessions(u.id))[0].expires).toBeLessThanOrEqual(Math.floor(t1 / 1000) + SESSION_IDLE_SEC);
    at(t1 + (SESSION_IDLE_SEC + 60) * 1000);
    const late = await reserve(r, g, { ip });
    expect([late.res.status, await errorOf(late.res)]).toEqual([403, 'bad_grant']);
  }, 60000);

  it('a file still unfinished keeps the session open for filePendingSec; the total stays capped at RECEIVE_MAX_SEC', async () => {
    const u = await receiver('r4-l1-busy', { filePendingSec: 86400 });
    const r = await newReverse(u.cookie, { expire: '7d' });
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    expect((await reserve(r, g, { ip })).res.status).toBe(201); // left unfinished
    const [x] = await sessions(u.id);
    // filePendingSec (a day), within the cap of a day after the session began.
    expect(x.expires - x.started).toBeLessThanOrEqual(RECEIVE_MAX_SEC);
    expect(x.expires - x.started).toBeGreaterThan(RECEIVE_MAX_SEC - 60);
    at(Date.now() + (SESSION_IDLE_SEC + 60) * 1000);
    // Still open (a file is unfinished): another file can be reserved.
    expect((await reserve(r, g, { ip })).res.status).toBe(201);
    // Never past a day after it began, however busy.
    at(Date.now() + RECEIVE_MAX_SEC * 1000);
    const over = await reserve(r, g, { ip });
    expect([over.res.status, await errorOf(over.res)]).toEqual([403, 'bad_grant']);
  }, 60000);

  it(`${MAX_SESSIONS} sessions from ${MAX_SESSIONS / MAX_SESSIONS_PER_NET} IPv6 /64s no longer lock the link once idle`, async () => {
    const u = await receiver('r4-l1-dos', { filePendingSec: 3600 });
    const r = await newReverse(u.cookie);
    const nets = MAX_SESSIONS / MAX_SESSIONS_PER_NET;
    for (let k = 0; k < nets; k++) {
      for (let j = 0; j < MAX_SESSIONS_PER_NET; j++) {
        const g = await grantOf(r, { ip: v6(k) });
        await send(r, g, { ip: v6(k), bytes: new Uint8Array(0) });
      }
    }
    // Full now…
    const now = await begin(r, { ip: '203.0.113.9' });
    expect([now.status, await errorOf(now)]).toEqual([429, 'busy']);
    // …free again once they are idle.
    at(Date.now() + (SESSION_IDLE_SEC + 120) * 1000);
    expect((await begin(r, { ip: '203.0.113.9' })).status).toBe(200);
  }, 300000);
});

describe('R4-L2: the role\'s current reverseMaxBytes applies to existing links', () => {
  it('a link made while the role had no byte cap is held to the lowered cap', async () => {
    const u = await receiver('r4-l2', { reverseMaxBytes: null });
    const r = await newReverse(u.cookie);
    expect(r.res.status).toBe(201);
    await driveLimits(u.id, { reverseMaxBytes: 1000 });
    // A new link is held to 1000 bytes…
    expect((await newReverse(u.cookie, { maxBytes: 5000 })).res.status).toBe(403);
    // …and so is the old one: the uploader sees it, and a larger file is refused.
    const ip = freshIp();
    expect((await (await openLink(r, ip)).json()).limits).toMatchObject({ maxBytes: 1000, bytesLeft: 1000 });
    const g = await grantOf(r, { ip });
    const f = await reserve(r, g, { ip, bytes: randomBytes(50000) });
    expect([f.res.status, await errorOf(f.res)]).toEqual([413, 'share_full']);
    // A small file still fits.
    expect((await reserve(r, g, { ip, bytes: randomBytes(10) })).res.status).toBe(201);
  }, 60000);

  it('a link made under a 1 MiB role cap takes the lowered cap; the link\'s own smaller cap still applies', async () => {
    const u = await receiver('r4-l2b', { reverseMaxBytes: 1048576 });
    const r = await newReverse(u.cookie);
    const own = await newReverse(u.cookie, { maxBytes: 600 });
    expect(own.res.status).toBe(201);
    await driveLimits(u.id, { reverseMaxBytes: 1000 });
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    expect((await reserve(r, g, { ip, bytes: randomBytes(50000) })).res.status).toBe(413);
    expect((await (await openLink(own, ip)).json()).limits.maxBytes).toBe(600);
    // Raising the role's cap again does not raise a link's own.
    await driveLimits(u.id, { reverseMaxBytes: null });
    expect((await (await openLink(own, ip)).json()).limits.maxBytes).toBe(600);
    expect((await (await openLink(r, ip)).json()).limits.maxBytes).toBe(1048576);
  }, 60000);
});

describe('R4-L3: the owner acting as the user is in the admin audit for take-in, mark-failed and retry', () => {
  it('each is logged as the user\'s own (imp = 1, adm = 0) with the owner as the real actor; mkdir too', async () => {
    const u = await receiver('r4-l3');
    const r = await newReverse(u.cookie);
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    await send(r, g, { ip });
    await send(r, g, { ip, path: 'b.txt' });
    const items = (await received(u.cookie)).items;
    expect(items).toHaveLength(2);
    const ic = cookieOf(await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
    expect(ic).toBeTruthy();
    await driveKeys(ic); // the user's keys for this session (their own admin-audit row: drive.keys_used)
    const before = (await audit(u.id)).length;
    const acc = await takeInAny(ic, items[0].id, 'root', {});
    expect(acc.status).toBe(200);
    expect((await fetchJson(`/api/private/drive/received/${items[1].id}/failed`, { method: 'POST', cookie: ic, body: { reason: 'name' } })).status).toBe(200);
    expect((await fetchJson(`/api/private/drive/received/${items[1].id}/failed`, { method: 'DELETE', cookie: ic, headers: intent })).status).toBe(200);
    const mid = await audit(u.id);
    expect(mid.length).toBe(before + 3);
    const added = mid.slice(0, 3);
    expect(added.map((e) => [e.action, e.detail])).toEqual([
      ['drive.received_retried', `id=${r.id} files=1`],
      ['drive.received_failed', `id=${r.id} files=1`],
      ['drive.received_taken_in', `id=${r.id} files=1`],
    ]);
    for (const e of added) {
      expect(e).toMatchObject({ imp: 1, adm: 0, subject_id: u.id });
      expect(e.actor_id).not.toBe(u.id);
    }
    // The user's own activity shows them as theirs, with no actor.
    const mine = (await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json()).rows;
    for (const e of added) expect(Object.keys(mine.find((m) => m.id === e.id)).sort()).toEqual(['action', 'detail', 'id', 'ts']);
    // An ordinary Drive change while impersonating is logged the same way.
    expect((await mkdir(ic)).res.status).toBe(201);
    const after = await audit(u.id);
    expect(after.length).toBe(before + 4);
    expect(after[0]).toMatchObject({ action: 'drive.folder_created', imp: 1, adm: 0 });
  }, 60000);
});

describe('R4-I1: a reverse-share id is never claimable again', () => {
  const reclaim = async (cookie, ra, note) => {
    const { privateKey } = await createReverseKey();
    const body = {
      id: ra.id, folder: 'root', ...(await sealLinkPriv(cookie, ra.id, privateKey)), lh: await linkHash(ra.pub),
      note: await sealNote(ra.pub, ra.id, note), expire: '7d', current: proofFor(USER_PW),
    };
    return fetchJson('/api/private/drive/reverse', { method: 'POST', cookie, body, headers: intent });
  };

  it('30 days after a link ends its index row is pruned; its id still cannot be claimed, and the old link stays dead', async () => {
    const a = await receiver('r4-i1-a');
    await receiver('r4-i1-b');
    const ra = await newReverse(a.cookie, { note: 'Send the signed contract.', expire: '1h' });
    expect(ra.res.status).toBe(201);
    at(Date.now() + (3600 + 31 * 86400) * 1000);
    await runDurableObjectAlarm(dirStub());
    const row = await runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec('SELECT user_id FROM shares WHERE id = ?', ra.id).toArray()[0] || null);
    expect(row).toBeNull();
    // Another user (an uploader of A's link: knows the id and the key), and A too.
    for (const who of ['r4-i1-b', 'r4-i1-a']) {
      const res = await reclaim(await login(who, USER_PW), ra, 'NEW ADDRESS: also email your ID to attacker@example.invalid');
      expect([res.status, await errorOf(res)]).toEqual([409, 'exists']);
    }
    expect((await openLink(ra, freshIp())).status).toBe(404);
    // Only a hash of the id is kept.
    const kept = await runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec('SELECT h FROM reverse_ids').toArray().map((x) => x.h));
    expect(kept.length).toBeGreaterThan(0);
    expect(kept).not.toContain(ra.id);
  }, 60000);

  it('an id stays taken after its account is deleted; a claim that never completed leaves the id free', async () => {
    const a = await receiver('r4-i1-del');
    const b = await receiver('r4-i1-del-b');
    const ra = await newReverse(a.cookie);
    expect(ra.res.status).toBe(201);
    expect((await fetchJson(`/api/private/admin/users/${a.id}`, { method: 'DELETE', cookie: oc, headers: intent })).status).toBe(200);
    const res = await reclaim(b.cookie, ra, 'Mine now.');
    expect([res.status, await errorOf(res)]).toEqual([409, 'exists']);
    // A confirmation refused: the claim is released and never became a link, so the id is not tombstoned.
    const refused = await newReverse(b.cookie, { confirm: false, current: proofFor('not the password') });
    expect(refused.res.status).toBe(403);
    expect((await newReverse(b.cookie, { id: refused.id })).res.status).toBe(201);
  }, 60000);
});
