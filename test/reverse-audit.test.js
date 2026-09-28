// reverse-audit.test.js — regression tests for the reverse-share findings of
// security audit round 3 (workerd, the real Worker and Durable Objects):
//   H-1 a reverse-share id cannot be taken over by another user (claimed in
//       the share index first, never moved);
//   M-1 received files that cannot be taken in never block the ones behind
//       them (a cursor; failures recorded on the server, listed, removable);
//   L-1 the human check comes before the password; a per-link lockout;
//   L-2 the active-links limit holds under concurrent creates;
//   L-3 idle sessions lapse quickly; open sessions are capped per network;
//   L-4 `reverse.received` log entries add up per link per hour;
//   Info: finalize / cancel only by the session that reserved the file; empty
//       files count towards the link's limits; a reservation cannot be kept
//       alive past a day.
import { env, runDurableObjectAlarm, runInDurableObject, createExecutionContext, waitOnExecutionContext } from 'cloudflare:test';
import { describe, it, expect, beforeAll, afterEach, vi } from 'vitest';
import worker from '../src/index.js';
import { owner, fetchJson, intent, freshIp, ORIGIN, proofFor, USER_PW, cookieOf } from './helpers.js';
import { node, drive } from './drive-helpers.js';
import { setSiteverify } from '../src/lib/turnstile.js';
import { MAX_SESSIONS_PER_NET, SESSION_IDLE_SEC, PW_MAX_FAILS, PW_LOCK_SEC, RECEIVE_MAX_SEC } from '../src/drive-do.js';
import {
  createReverseKey, linkProof, linkHash, passwordProof, sealNote, openNote, openUpload, newNodeId,
} from '../public/js/reversekeys.js';
import { randomBytes, b64urlFromBytes } from '../public/js/bytes.js';
import { encryptChunk, importFileKey } from '../public/js/files.js';
import {
  sealLinkPriv, openLinkPriv, takeInAny, dirStub, driveOf, errorOf, receiver, newReverse, rv, openLink, begin, grantOf, putChunk, reserve, send, received,
} from './reverse-helpers.js';

let oc;
beforeAll(async () => { oc = await owner(); });
afterEach(() => vi.useRealTimers());

const audit = async (subject) => (await (await fetchJson(`/api/private/admin/audit?user=${subject}`, { cookie: oc })).json()).rows;
const shareRow = (id) => runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec('SELECT user_id, lh, status FROM shares WHERE id = ?', id).toArray()[0] || null);

describe('H-1: a reverse-share id never changes hands', () => {
  it('another user re-creating an existing id gets 409; the row, the link and its uploads stay with the first user', async () => {
    const a = await receiver('r3-h1-a');
    const b = await receiver('r3-h1-b');
    const ra = await newReverse(a.cookie, { note: 'Please send the signed contract.' });
    expect(ra.res.status).toBe(201);
    const before = await shareRow(ra.id);
    // B knows A's link (B was an uploader): same id, A's link-proof hash, B's own key and note.
    const { privateKey: bPriv } = await createReverseKey();
    const body = {
      id: ra.id, folder: 'root', ...(await sealLinkPriv(b.cookie, ra.id, bPriv)), lh: await linkHash(ra.pub),
      note: await sealNote(ra.pub, ra.id, 'NEW: also email your ID to attacker@example.com'), expire: '7d', current: proofFor(USER_PW),
    };
    const hij = await fetchJson('/api/private/drive/reverse', { method: 'POST', cookie: b.cookie, body, headers: intent });
    expect(hij.status).toBe(409);
    expect(await errorOf(hij)).toBe('exists');
    expect(await shareRow(ra.id)).toEqual(before);
    expect(before.user_id).toBe(a.id);
    // Nothing reached B's Drive.
    expect((await (await fetchJson('/api/private/drive/reverse', { cookie: b.cookie })).json()).reverse).toEqual([]);
    // A keeps it: listed, and the link shows A's note and delivers to A.
    expect((await fetchJson(`/api/private/shares/${ra.id}`, { cookie: a.cookie })).status).toBe(200);
    expect((await (await fetchJson('/api/private/drive/reverse', { cookie: a.cookie })).json()).reverse.map((x) => x.id)).toContain(ra.id);
    const ip = freshIp();
    expect(await openNote(ra.pub, ra.id, (await (await openLink(ra, ip)).json()).note)).toBe('Please send the signed contract.');
    await send(ra, await grantOf(ra, { ip }), { ip });
    expect((await received(a.cookie)).items).toHaveLength(1);
    expect((await received(b.cookie)).items).toHaveLength(0);
    // The owner acting as B cannot take it either.
    const ic = cookieOf(await fetchJson(`/api/private/admin/users/${b.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
    const again = await fetchJson('/api/private/drive/reverse', { method: 'POST', cookie: ic, body: { ...body, current: undefined }, headers: intent });
    expect(again.status).toBe(409);
    expect((await shareRow(ra.id)).user_id).toBe(a.id);
  });

  it('the same user re-using an id gets 409 too; a refused confirmation frees the id again', async () => {
    const u = await receiver('r3-h1-same');
    const r = await newReverse(u.cookie);
    expect(r.res.status).toBe(201);
    expect((await newReverse(u.cookie, { id: r.id })).res.status).toBe(409);
    // A wrong password: refused, and the id is not left claimed.
    const other = await newReverse(u.cookie, { confirm: false, current: proofFor('not the password') });
    expect(other.res.status).toBe(403);
    expect(await shareRow(other.id)).toBeNull();
    expect((await newReverse(u.cookie, { id: other.id })).res.status).toBe(201);
  });

  it('recordShare never moves a reverse row, even to its own user', async () => {
    const u = await receiver('r3-h1-rec');
    const v = await receiver('r3-h1-rec2');
    const r = await newReverse(u.cookie);
    const t = Math.floor(Date.now() / 1000);
    for (const uid of [v.id, u.id]) {
      expect(await dirStub().recordShare({ id: r.id, uid, kind: 'drive', label: 'x', created: t, expires: t + 60, views: null, lh: 'A'.repeat(43) })).toMatchObject({ ok: false, status: 409 });
    }
    const row = await shareRow(r.id);
    expect(row).toMatchObject({ user_id: u.id, status: 'active', lh: await linkHash(r.pub) });
  });
});

describe('L-2: the active-links limit is atomic', () => {
  it('concurrent creates with a limit of 1: exactly one succeeds', async () => {
    const u = await receiver('r3-l2', { reverseMaxActive: 1 });
    const rs = await Promise.all([0, 1, 2, 3].map(() => newReverse(u.cookie)));
    const codes = rs.map((x) => x.res.status).sort();
    expect(codes).toEqual([201, 409, 409, 409]);
    for (const x of rs.filter((y) => y.res.status === 409)) expect(await errorOf(x.res)).toBe('too_many_reverse');
    const active = await runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec("SELECT COUNT(*) AS c FROM shares WHERE user_id = ? AND kind = 'reverse' AND status != 'revoked'", u.id).one().c);
    expect(active).toBe(1);
  });
});

describe('M-1: received files that cannot be taken in never block the rest', () => {
  it('pages past 500 items with a cursor; a failure leaves the queue, is listed with its link, can be retried or deleted', async () => {
    const u = await receiver('r3-m1');
    const r = await newReverse(u.cookie, { label: 'Contracts' });
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    // Garbage: well-formed wraps to another key (the server cannot tell), zero bytes.
    const junk = { ...r, pub: (await createReverseKey()).pub };
    const f = await reserve(junk, g, { bytes: new Uint8Array(0), ip });
    expect((await rv(r.id, `/files/${f.node}/finalize`, { headers: { 'x-reverse-grant': g, 'x-upload-token': f.data.uploadToken }, ip })).status).toBe(200);
    await runInDurableObject(driveOf(u.id), (inst, state) => {
      for (let k = 0; k < 520; k++) {
        state.storage.sql.exec(`INSERT INTO nodes (id, parent, kind, name, meta, size, chunks, fk, state, created, updated, rs)
          SELECT ?, parent, kind, name, meta, size, chunks, fk, state, created - 10, updated, rs FROM nodes WHERE id = ?`, newNodeId(), f.node);
      }
      state.storage.sql.exec('UPDATE nodes SET created = created - 10 WHERE rs IS NOT NULL');
    });
    const good = await send(r, g, { path: 'contract.pdf', ip });
    const p1 = await received(u.cookie);
    expect(p1.items).toHaveLength(500);
    expect(p1.more).toBe(true);
    expect(p1.next).toMatch(/^\d+\.[A-Za-z0-9_-]{22}$/);
    expect(p1.items.map((i) => i.id)).not.toContain(good.node);
    const p2 = await received(u.cookie, `?after=${p1.next}`);
    expect(p2.more).toBe(false);
    expect(p2.next).toBeNull();
    expect(p2.items.map((i) => i.id)).toContain(good.node);
    expect(new Set([...p1.items, ...p2.items].map((i) => i.id)).size).toBe(522);
    expect((await fetchJson('/api/private/drive/received?after=zzz', { cookie: u.cookie })).status).toBe(400);
    // The good one opens with the share's key; the first does not: the browser records that.
    const { privateKey } = await openLinkPriv(u.cookie, r.id, p1.keys[0].priv, p1.keys[0].mek);
    expect((await openUpload(privateKey, r.id, p2.items.find((i) => i.id === good.node))).path).toBe('contract.pdf');
    const bad = p1.items[0];
    await expect(openUpload(privateKey, r.id, bad)).rejects.toThrow();
    const mark = (id, method, body) => fetchJson(`/api/private/drive/received/${id}/failed`, { method, cookie: u.cookie, headers: intent, body });
    expect((await mark(bad.id, 'POST', { reason: 'nonsense' })).status).toBe(400);
    const m = await mark(bad.id, 'POST', { reason: 'unreadable' });
    expect(m.status).toBe(200);
    expect(await m.json()).toMatchObject({ ok: true, received: 521, failed: 1 });
    expect((await drive(u.cookie))).toMatchObject({ received: 521, receivedFailed: 1 });
    expect((await received(u.cookie)).items.map((i) => i.id)).not.toContain(bad.id);
    const failed = await received(u.cookie, '?failed=1');
    expect(failed.items).toEqual([{ id: bad.id, rs: r.id, label: 'Contracts', size: 0, created: bad.created, failed: expect.any(Number), reason: 'unreadable' }]);
    expect(failed.keys).toBeUndefined();
    // The share lists it apart from the waiting ones.
    expect((await (await fetchJson('/api/private/drive/reverse', { cookie: u.cookie })).json()).reverse[0]).toMatchObject({ pending: 521, failed: 1 });
    // Try again: back in the queue.
    expect((await mark(bad.id, 'DELETE')).status).toBe(200);
    expect((await drive(u.cookie))).toMatchObject({ received: 522, receivedFailed: 0 });
    // Delete it (as any Drive item): gone from both lists.
    expect((await mark(bad.id, 'POST', { reason: 'unreadable' })).status).toBe(200);
    expect((await fetchJson(`/api/private/drive/nodes/${bad.id}`, { method: 'DELETE', cookie: u.cookie, headers: intent })).status).toBe(200);
    expect((await received(u.cookie, '?failed=1')).items).toEqual([]);
    // Only received files, and not another user's.
    expect((await mark(good.node, 'POST', {})).status).toBe(200);
    const other = await receiver('r3-m1-other');
    expect((await fetchJson(`/api/private/drive/received/${good.node}/failed`, { method: 'DELETE', cookie: other.cookie, headers: intent })).status).toBe(409);
    expect((await node(u.cookie, 'root')).status).toBe(200);
  }, 120000);
});

describe('L-1: the human check before the password; a lockout per link', () => {
  const TS_ENV = { ...env, TURNSTILE_SITEKEY: '0x4AAAAAAAtestsitekey', TURNSTILE_SECRET: '0x4AAAAAAAtestsecretvalue' };
  const tsFetch = async (path, headers = {}) => {
    const ctx = createExecutionContext();
    const res = await worker.fetch(new Request(`${ORIGIN}${path}`, { method: 'POST', headers }), TS_ENV, ctx);
    await waitOnExecutionContext(ctx);
    return res;
  };

  it('with Turnstile on, no password guess is answered without a valid token', async () => {
    const u = await receiver('r3-l1-ts');
    const r = await newReverse(u.cookie, { password: 'correct horse' });
    const prev = setSiteverify(async (form) => {
      const m = /^ok:(.+)$/.exec(form.get('response'));
      return Response.json(m ? { success: true, hostname: new URL(ORIGIN).hostname, action: m[1] } : { success: false });
    });
    try {
      const ip = freshIp();
      const lp = await linkProof(r.pub);
      const head = await (await tsFetch(`/api/reverse/${r.id}/open`, { ...intent, 'x-link-proof': lp, 'cf-connecting-ip': ip })).json();
      const guess = async (pw, token) => tsFetch(`/api/reverse/${r.id}/begin`, {
        ...intent, 'x-link-proof': lp, 'cf-connecting-ip': ip,
        'x-key-proof': await passwordProof(pw, head.password.salt, head.password.t, r.pub), ...(token ? { 'x-secbin-turnstile': token } : {}),
      });
      for (const pw of ['wrong guess', 'correct horse']) {
        const res = await guess(pw);
        expect([res.status, await errorOf(res)]).toEqual([403, 'captcha_required']);
        const bad = await guess(pw, 'nope');
        expect([bad.status, await errorOf(bad)]).toEqual([403, 'turnstile_failed']);
      }
      const wrong = await guess('wrong guess', 'ok:reverse-upload');
      expect([wrong.status, await errorOf(wrong)]).toEqual([403, 'bad_password']);
      expect((await guess('correct horse', 'ok:reverse-upload')).status).toBe(200);
    } finally {
      setSiteverify(prev);
    }
  });

  it(`${PW_MAX_FAILS} wrong passwords from any networks lock the link's password (the right one too) for a while`, async () => {
    const u = await receiver('r3-l1-lock');
    const r = await newReverse(u.cookie, { password: 'open sesame' });
    for (let k = 0; k < PW_MAX_FAILS; k++) {
      const res = await begin(r, { password: `guess ${k}`, ip: freshIp() });
      expect([res.status, await errorOf(res)]).toEqual([403, 'bad_password']);
    }
    const ip = freshIp();
    const locked = await begin(r, { password: 'open sesame', ip });
    expect(locked.status).toBe(429);
    const body = await locked.json();
    expect(body.error).toBe('password_locked');
    expect(body.until).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect((await (await openLink(r, ip)).json()).password.lockedUntil).toBe(body.until);
    // Logged for the user (at most once a minute).
    expect((await audit(u.id)).filter((e) => e.action === 'reverse.bad_password')).toHaveLength(1);
    vi.useFakeTimers({ now: Date.now() + (PW_LOCK_SEC + 1) * 1000, toFake: ['Date'] });
    expect((await openLink(r, ip)).status).toBe(200);
    expect((await begin(r, { password: 'open sesame', ip })).status).toBe(200);
    // The right password resets the count.
    const row = await runInDurableObject(driveOf(u.id), (inst, state) => state.storage.sql.exec('SELECT pwfails, pwlock FROM reverse WHERE id = ?', r.id).one());
    expect(row).toEqual({ pwfails: 0, pwlock: null });
  }, 60000);
});

describe('L-3: idle sessions lapse; open sessions are counted per network', () => {
  it(`${MAX_SESSIONS_PER_NET} open sessions per network; others are not held up; an idle one lapses after ${SESSION_IDLE_SEC} s`, async () => {
    const u = await receiver('r3-l3');
    const r = await newReverse(u.cookie);
    const ip = freshIp();
    const grants = [];
    for (let k = 0; k < MAX_SESSIONS_PER_NET; k++) grants.push(await grantOf(r, { ip }));
    const more = await begin(r, { ip });
    expect([more.status, await errorOf(more)]).toEqual([429, 'busy']);
    expect((await begin(r, { ip: freshIp() })).status).toBe(200);
    // The role's filePendingSec (an hour by default) no longer keeps an empty session open.
    vi.useFakeTimers({ now: Date.now() + (SESSION_IDLE_SEC + 1) * 1000, toFake: ['Date'] });
    const late = await reserve(r, grants[0], { ip });
    expect([late.res.status, await errorOf(late.res)]).toEqual([403, 'bad_grant']);
    expect((await begin(r, { ip })).status).toBe(200);
  }, 60000);

  it('a session with a file still being sent stays open for the role\'s filePendingSec', async () => {
    const u = await receiver('r3-l3-busy', { filePendingSec: 3600 });
    const r = await newReverse(u.cookie);
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    const f = await reserve(r, g, { bytes: randomBytes(10), ip });
    vi.useFakeTimers({ now: Date.now() + (SESSION_IDLE_SEC + 60) * 1000, toFake: ['Date'] });
    const key = await importFileKey(b64urlFromBytes(f.fk));
    expect((await putChunk(r.id, f.node, 0, await encryptChunk(key, 0, 1, f.bytes), f.data.uploadToken, ip)).status).toBe(200);
    expect((await rv(r.id, `/files/${f.node}/finalize`, { headers: { 'x-reverse-grant': g, 'x-upload-token': f.data.uploadToken }, ip })).status).toBe(200);
  }, 60000);
});

describe('L-4: reverse.received entries add up per link per hour', () => {
  it('many sessions within an hour make one entry with the totals; the next hour starts a new one', async () => {
    const u = await receiver('r3-l4');
    const r = await newReverse(u.cookie);
    const N = 12;
    for (let k = 0; k < N; k++) {
      const ip = freshIp();
      const g = await grantOf(r, { ip });
      await send(r, g, { bytes: new Uint8Array(k), ip });
      expect((await rv(r.id, '/done', { headers: { 'x-reverse-grant': g }, ip })).status).toBe(200);
    }
    const rows = (await audit(u.id)).filter((e) => e.action === 'reverse.received');
    expect(rows).toHaveLength(1);
    expect(rows[0].detail).toBe(`id=${r.id} files=${N} bytes=${(N * (N - 1)) / 2}`);
    vi.useFakeTimers({ now: Date.now() + 3601 * 1000, toFake: ['Date'] });
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    await send(r, g, { ip });
    expect((await rv(r.id, '/done', { headers: { 'x-reverse-grant': g }, ip })).status).toBe(200);
    expect((await audit(u.id)).filter((e) => e.action === 'reverse.received').map((e) => e.detail))
      .toEqual([`id=${r.id} files=1 bytes=11`, `id=${r.id} files=${N} bytes=${(N * (N - 1)) / 2}`]);
  }, 120000);
});

describe('L-4: take-ins are logged like Drive actions and add up per link, per actor, per hour', () => {
  it('the user\'s own take-ins make one entry per link; the owner acting as the user gets its own (imp); the next hour a new one', async () => {
    const u = await receiver('r3-l4-take');
    const r = await newReverse(u.cookie);
    const r2 = await newReverse(u.cookie);
    const nodes = [];
    for (const [link, n] of [[r, 3], [r2, 1]]) {
      const ip = freshIp();
      const g = await grantOf(link, { ip });
      for (let k = 0; k < n; k++) nodes.push((await send(link, g, { path: `f${k}.txt`, ip })).node);
      expect((await rv(link.id, '/done', { headers: { 'x-reverse-grant': g }, ip })).status).toBe(200);
    }
    const take = (cookie, id) => takeInAny(cookie, id);
    for (const id of [nodes[0], nodes[1], nodes[3]]) expect((await take(u.cookie, id)).status).toBe(200);
    const ic = cookieOf(await fetchJson(`/api/private/admin/users/${u.id}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));
    expect((await take(ic, nodes[2])).status).toBe(200);
    // Taken in once only: a second take-in is refused and logs nothing.
    expect((await take(u.cookie, nodes[0])).status).toBe(409);
    const rows = (await audit(u.id)).filter((e) => e.action === 'drive.received_taken_in');
    const pick = ({ detail, imp, adm, actor_id: actor }) => ({ detail, imp, adm, own: actor === u.id });
    expect(rows.map(pick)).toEqual([
      { detail: `id=${r.id} files=1`, imp: 1, adm: 0, own: false },
      { detail: `id=${r2.id} files=1`, imp: 0, adm: 0, own: true },
      { detail: `id=${r.id} files=2`, imp: 0, adm: 0, own: true },
    ]);
    // The user's own activity shows all three as theirs, with no actor.
    const mine = (await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json()).rows.filter((e) => e.action === 'drive.received_taken_in');
    expect(mine.map((e) => e.detail).sort()).toEqual([`id=${r.id} files=1`, `id=${r.id} files=2`, `id=${r2.id} files=1`].sort());
    for (const e of mine) expect(Object.keys(e).sort()).toEqual(['action', 'detail', 'id', 'ts']);
    // An hour later: a new entry.
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    const late = (await send(r, g, { ip })).node;
    vi.useFakeTimers({ now: Date.now() + 3601 * 1000, toFake: ['Date'] });
    expect((await take(u.cookie, late)).status).toBe(200);
    expect((await audit(u.id)).filter((e) => e.action === 'drive.received_taken_in' && e.imp === 0 && e.detail.startsWith(`id=${r.id} `)).map((e) => e.detail))
      .toEqual([`id=${r.id} files=1`, `id=${r.id} files=2`]);
    // The detail is checked: nothing else can be written under this action.
    const bad = await runInDurableObject(dirStub(), (inst) => inst.driveLog(u.id, u.id, 'drive.received_taken_in', 'id=x files=1'));
    expect(bad).toMatchObject({ ok: false, status: 400 });
  }, 120000);
});

describe('Info: sessions, empty files and keep-alives', () => {
  it('finalize and cancel accept only the session that reserved the file', async () => {
    const u = await receiver('r3-i3');
    const r = await newReverse(u.cookie);
    const ip = freshIp();
    const g1 = await grantOf(r, { ip });
    const g2 = await grantOf(r, { ip });
    const f = await reserve(r, g1, { bytes: new Uint8Array(0), ip });
    const h = (g) => ({ 'x-reverse-grant': g, 'x-upload-token': f.data.uploadToken });
    const fin = await rv(r.id, `/files/${f.node}/finalize`, { headers: h(g2), ip });
    expect([fin.status, await errorOf(fin)]).toEqual([403, 'bad_grant']);
    const del = await rv(r.id, `/files/${f.node}`, { method: 'DELETE', headers: h(g2), ip });
    expect([del.status, await errorOf(del)]).toEqual([403, 'bad_grant']);
    expect((await rv(r.id, `/files/${f.node}/finalize`, { headers: h(g1), ip })).status).toBe(200);
    expect(await (await rv(r.id, '/done', { headers: { 'x-reverse-grant': g1 }, ip })).json()).toEqual({ files: 1, bytes: 0 });
  });

  it('empty files count towards the link\'s files, and their sealed fields towards its bytes', async () => {
    const u = await receiver('r3-i8');
    const r = await newReverse(u.cookie, { maxFiles: 2, maxBytes: 4000 });
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    await send(r, g, { bytes: new Uint8Array(0), ip });
    const head = await (await openLink(r, ip)).json();
    expect(head.limits.filesLeft).toBe(1);
    expect(head.limits.bytesLeft).toBeLessThan(4000);
    expect(head.limits.bytesLeft).toBeGreaterThan(4000 - 2700);
    await send(r, g, { bytes: new Uint8Array(0), ip });
    const third = await reserve(r, g, { bytes: new Uint8Array(0), ip });
    expect([third.res.status, await errorOf(third.res)]).toEqual([409, 'too_many_files']);
    // A byte limit that cannot hold one more file's sealed fields refuses it, even empty.
    const small = await newReverse(u.cookie, { maxBytes: 100 });
    const g2 = await grantOf(small, { ip });
    const x = await reserve(small, g2, { bytes: new Uint8Array(0), ip });
    expect([x.res.status, await errorOf(x.res)]).toEqual([413, 'share_full']);
  });

  it(`a reservation cannot be kept alive by re-sent chunks past ${RECEIVE_MAX_SEC} s`, async () => {
    const u = await receiver('r3-keep', { filePendingSec: 3600 });
    const r = await newReverse(u.cookie);
    const ip = freshIp();
    const g = await grantOf(r, { ip });
    const f = await reserve(r, g, { bytes: randomBytes(10), ip });
    const key = await importFileKey(b64urlFromBytes(f.fk));
    const ct = await encryptChunk(key, 0, 1, f.bytes);
    const t0 = Date.now();
    vi.useFakeTimers({ now: t0, toFake: ['Date'] });
    for (let t = 3000; t < RECEIVE_MAX_SEC; t += 3000) {
      vi.setSystemTime(t0 + t * 1000);
      expect((await putChunk(r.id, f.node, 0, ct, f.data.uploadToken, ip)).status, String(t)).toBe(200);
    }
    vi.setSystemTime(t0 + (RECEIVE_MAX_SEC + 1) * 1000);
    expect((await putChunk(r.id, f.node, 0, ct, f.data.uploadToken, ip)).status).toBe(410);
    await runDurableObjectAlarm(driveOf(u.id));
    const left = await runInDurableObject(driveOf(u.id), (inst, state) => state.storage.sql.exec('SELECT COUNT(*) AS c FROM nodes WHERE id = ?', f.node).one().c);
    expect(left).toBe(0);
    expect((await (await openLink(r, ip)).json()).limits.bytesLeft).toBe(1024 ** 3);
  }, 120000);
});
