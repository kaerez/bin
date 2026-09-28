// drive-keys.test.js — the Drive key model v2 (docs/DRIVE.md §3, §3.1) in
// workerd, in a storage of its own: the keyring (created on first need; the
// root MEK and the sub-MEKs; owner only, the step-up for every change and
// view, the admin audit by fingerprint only), the derivations (every KEK and
// field key from the root MEK, a sub-MEK and the user salt), rotation (new
// items under the new sub-MEK, old ones keep theirs until a re-seal moves
// them), deleting a sub-MEK (a re-seal first), changing the root MEK (every
// item, link key and field-layer value re-sealed), the key kit and the
// personal kit (download, read-only verify, restore of only what is lost),
// the keys parts of Import / export (imports never replace working keys; a
// KEK only verifies; a DEK restores a broken seal after the GCM check) and
// one user's keys for the owner. Synthetic data only.
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, login, fetchJson, intent, cookieOf, proofFor, USER_PW } from './helpers.js';
import {
  enableDrive, mkdir, uploadFile, uploadRealFile, node, driveKeys, sealed, openStored, getChunk,
} from './drive-helpers.js';
import { newReverse, grantOf, send, received, openLinkPriv, driveOf, dirStub } from './reverse-helpers.js';
import {
  keyBytes, deriveKek, deriveUserKey, deriveFieldKey, keyFingerprint, keyCheckValue, saltCheckValue, openAtRest, isAtRest, newSalt,
} from '../public/js/drivekeys.js';
import { b64urlFromBytes, randomBytes, fromUtf8 } from '../public/js/bytes.js';
import { importFileKey, decryptChunk } from '../public/js/files.js';
import { openUpload } from '../public/js/reversekeys.js';
import { API_CSP } from '../src/lib/http.js';

const OWNER_PW = 'owner-password';
const STEP = { current: proofFor(OWNER_PW) };
let oc;
let ownerId;
beforeAll(async () => {
  oc = await owner();
  ownerId = (await (await fetchJson('/api/private/me', { cookie: oc })).json()).user.id;
});

const K = '/api/private/admin/keys';
const post = (path, body = {}, cookie = oc, headers = intent) => fetchJson(path, { method: 'POST', cookie, headers, body });
const status = async () => (await fetchJson(K, { cookie: oc })).json();
const adminAudit = async (q = '') => (await (await fetchJson(`/api/private/admin/audit?limit=500${q}`, { cookie: oc })).json()).rows;
const errorOf = async (r) => (await r.json()).error;
const show = async (id = null) => (await (await post(id ? `${K}/subs/${id}/show` : `${K}/root/show`, STEP)).json()).key;
const kitMaterial = async () => (await (await post(`${K}/kit`, STEP)).json()).material;
/** A new sub-MEK from a generated candidate → its id. */
async function addSub(body = {}) {
  const c = await (await post(`${K}/candidate`, { purpose: 'sub', ...STEP })).json();
  const r = await post(`${K}/subs`, { candidate: c.id, ...STEP, ...body });
  expect(r.status, await r.clone().text()).toBe(200);
  return (await r.json()).id;
}
/** Drive the re-seal job to its end → its final state. */
async function runJob() {
  let job = null;
  for (let n = 0; n < 200; n++) {
    ({ job } = await (await post(`${K}/jobs/step`)).json());
    if (!job || job.finished) break;
  }
  return job;
}
const usage = async () => (await (await fetchJson(`${K}/usage`, { cookie: oc })).json()).counts;
const impersonate = async (uid) => cookieOf(await fetchJson(`/api/private/admin/users/${uid}/impersonate`, { method: 'POST', cookie: oc, headers: intent }));

describe('the keyring (Admin → Security → Keys)', () => {
  it('is created on first need; the status shows fingerprints and dates, never a key; owner only', async () => {
    const st = await status();
    expect(st).toMatchObject({ ok: true, ready: true, lost: false, root: { fp: expect.any(String), changing: false }, current: expect.any(String) });
    expect(st.subs).toHaveLength(1);
    expect(st.subs[0]).toMatchObject({ id: st.current, status: 'current', until: null, opens: true });
    const root = await show();
    const sub = await show(st.current);
    expect(JSON.stringify(st)).not.toContain(root);
    expect(JSON.stringify(st)).not.toContain(sub);
    expect(await keyFingerprint(keyBytes(root))).toBe(st.root.fp);
    // A user, the owner acting as a user, another site, no intent: refused.
    const u = await makeUser('keys-noaccess');
    expect((await fetchJson(K, { cookie: u.cookie })).status).toBe(403);
    expect((await post(`${K}/root/show`, { current: proofFor(USER_PW) }, u.cookie)).status).toBe(403);
    const ic = await impersonate(u.id);
    expect(await errorOf(await fetchJson(K, { cookie: ic }))).toBe('impersonating');
    expect((await post(`${K}/root/show`, STEP, oc, { ...intent, 'sec-fetch-site': 'cross-site' })).status).toBe(403);
    expect((await post(`${K}/root/show`, STEP, oc, {})).status).toBe(400);
    await fetchJson('/api/private/admin/unimpersonate', { method: 'POST', cookie: ic, headers: intent });
  });

  it('every change and every view needs the step-up; the admin audit has fingerprints, never a key', async () => {
    const noStep = await post(`${K}/root/show`);
    expect([noStep.status, await errorOf(noStep)]).toEqual([400, 'reauth_required']);
    expect((await post(`${K}/root/show`, { current: proofFor('not the password') })).status).toBe(403);
    for (const p of [`${K}/candidate`, `${K}/subs`, `${K}/kit`, `${K}/root`, `${K}/export`]) {
      const r = await post(p, { purpose: 'sub', key: b64urlFromBytes(randomBytes(32)) });
      expect(r.status, p).toBe(400);
      expect(await errorOf(r), p).toMatch(/reauth_required|invalid_key/);
    }
    const root = await show();
    const st = await status();
    const rows = await adminAudit();
    const viewed = rows.filter((r) => r.action === 'keys.viewed');
    expect(viewed.length).toBeGreaterThan(0);
    expect(viewed.some((r) => r.detail.includes(st.root.fp))).toBe(true);
    for (const r of rows) expect(`${r.detail}`).not.toContain(root);
  });

  it('derivations: KEK = HKDF(root ‖ sub-MEK, user salt, "secbin-kek/v1\\n<userId>"); the field keys come from the root and the salt', async () => {
    const u = await makeUser('keys-derive');
    await enableDrive(u.id, { reverseEnabled: true });
    const k = await driveKeys(u.cookie, { fresh: true });
    const m = await kitMaterial();
    const salt = m.salts[u.id].salt;
    const sub = m.subs.find((s) => s.id === k.current);
    const kek = await deriveKek(keyBytes(m.root.key), keyBytes(sub.key), salt, u.id);
    expect([...kek]).toEqual([...k.keks.get(k.current)]);
    // Another user's id or salt gives another KEK.
    expect([...await deriveKek(keyBytes(m.root.key), keyBytes(sub.key), salt, ownerId)]).not.toEqual([...kek]);
    expect([...await deriveKek(keyBytes(m.root.key), keyBytes(sub.key), newSalt(), u.id)]).not.toEqual([...kek]);
    // A link key is stored at rest under the field key HKDF(HKDF(root, salt, "secbin-user/v1\n<id>"), "secbin-atrest/v1\nlinkKey").
    const link = await newReverse(u.cookie);
    expect(link.res.status).toBe(201);
    const stored = await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec('SELECT priv FROM reverse WHERE id = ?', link.id).one().priv);
    expect(isAtRest(stored)).toBe(true);
    const fk = await deriveFieldKey(await deriveUserKey(keyBytes(m.root.key), salt, u.id), 'linkKey');
    expect(JSON.parse(await openAtRest(fk, { userId: u.id, field: 'linkKey', ref: link.id }, stored))).toEqual(link.body.priv);
  });

  it('rotation: new items use the new sub-MEK; old ones keep theirs and still open; a re-seal moves them; the content never changes', async () => {
    const u = await makeUser('keys-rotate');
    await enableDrive(u.id, { reverseEnabled: true });
    const A = (await driveKeys(u.cookie, { fresh: true })).current;
    const d = await mkdir(u.cookie);
    const f = await uploadFile(u.cookie, d.id, 100);
    const link = await newReverse(u.cookie);
    const staleFolder = await sealed(u.cookie, 'dir'); // sealed by a browser that has not reloaded
    const B = await addSub({ rotate: true, note: 'rotation test' });
    expect((await status()).current).toBe(B);
    const k = await driveKeys(u.cookie, { fresh: true });
    expect(k.current).toBe(B);
    expect([...k.keks.keys()].sort()).toEqual([A, B].sort()); // the sub-MEKs its items use, and the current one
    const stale = await mkdir(u.cookie, 'root', { fields: staleFolder });
    expect([stale.res.status, await errorOf(stale.res)]).toEqual([409, 'mek_not_current']);
    const fresh = await mkdir(u.cookie);
    expect((await (await node(u.cookie, fresh.id)).json()).node.mek).toBe(B);
    const old = (await (await node(u.cookie, f.id)).json()).node;
    expect(old.mek).toBe(A);
    const oldOpen = await openStored(u.cookie, old);
    expect([...oldOpen.dek]).toEqual([...f.fields.dekBytes]);
    expect((await usage())[A]).toBeGreaterThanOrEqual(3);
    // Re-seal everything under A: the server opens and seals each item itself.
    const start = await post(`${K}/jobs`, { from: A, ...STEP });
    expect(start.status).toBe(200);
    const job = await runJob();
    expect(job).toMatchObject({ finished: true, failed: 0, result: { ok: true } });
    expect((await usage())[A] ?? 0).toBe(0);
    const moved = (await (await node(u.cookie, f.id)).json()).node;
    expect(moved.mek).toBe(B);
    expect(moved.ks).not.toBe(old.ks); // a fresh per-item salt
    expect(moved.ch).toBe(old.ch); // the ciphertext is untouched
    const opened = await openStored(u.cookie, moved);
    expect([...opened.dek]).toEqual([...f.fields.dekBytes]);
    expect([...opened.name]).toEqual([...oldOpen.name]);
    const g = await getChunk(u.cookie, f.id, 0);
    expect(new Uint8Array(await g.arrayBuffer())).toEqual(f.chunks[0]);
    const lk = (await (await fetchJson('/api/private/drive/reverse', { cookie: u.cookie })).json()).reverse.find((x) => x.id === link.id);
    expect(lk.mek).toBe(B);
    expect(await openLinkPriv(u.cookie, link.id, lk.priv, lk.mek)).toBeTruthy();
    // Logged by fingerprint only.
    expect((await adminAudit()).some((r) => r.action === 'keys.rotated' && r.detail.includes(B))).toBe(true);
  });

  it('deleting a sub-MEK: never while an item uses it (a re-seal first), never the current one or the last', async () => {
    const u = await makeUser('keys-delete');
    await enableDrive(u.id);
    const A = (await status()).current;
    const f = await uploadFile(u.cookie, 'root', 10);
    const B = await addSub({ rotate: true });
    const inUse = await fetchJson(`${K}/subs/${A}`, { method: 'DELETE', cookie: oc, headers: intent, body: STEP });
    expect([inUse.status, await errorOf(inUse)]).toEqual([409, 'in_use']);
    const cur = await fetchJson(`${K}/subs/${B}`, { method: 'DELETE', cookie: oc, headers: intent, body: STEP });
    expect([cur.status, await errorOf(cur)]).toEqual([409, 'current_key']);
    expect((await post(`${K}/jobs`, { from: A, remove: true, ...STEP })).status).toBe(200);
    const job = await runJob();
    expect(job.result).toMatchObject({ ok: true, removed: true });
    const st = await status();
    expect(st.subs.map((s) => s.id)).not.toContain(A);
    expect(st.subs.find((s) => s.id === B)).toMatchObject({ status: 'current', until: null });
    const n = (await (await node(u.cookie, f.id)).json()).node;
    expect(n.mek).toBe(B);
    expect([...(await openStored(u.cookie, n)).dek]).toEqual([...f.fields.dekBytes]);
    expect((await driveKeys(u.cookie, { fresh: true })).raw.missing).toEqual([]);
    expect((await adminAudit()).some((r) => r.action === 'keys.removed' && r.detail.includes(A))).toBe(true);
  });

  it('dates: scheduled sub-MEKs, set as current, and a timeline that always has one open-ended key and no gap', async () => {
    const before = await status();
    const t = before.now;
    const S = await addSub({ from: t + 3600, note: 'next hour' });
    let st = await status();
    expect(st.current).toBe(before.current); // not yet
    expect(st.subs.find((s) => s.id === S)).toMatchObject({ status: 'scheduled', from: t + 3600, until: null });
    expect(st.subs.find((s) => s.id === before.current).until).toBe(t + 3600);
    // A gap, or no open-ended key: refused.
    const gap = await fetchJson(`${K}/subs/${S}`, { method: 'PATCH', cookie: oc, headers: intent, body: { from: t + 7200, ...STEP } });
    expect([gap.status, await errorOf(gap)]).toEqual([409, 'invalid_dates']);
    const closed = await fetchJson(`${K}/subs/${S}`, { method: 'PATCH', cookie: oc, headers: intent, body: { until: t + 9000, ...STEP } });
    expect([closed.status, await errorOf(closed)]).toEqual([409, 'invalid_dates']);
    expect((await post(`${K}/subs/${S}/current`, STEP)).status).toBe(200);
    st = await status();
    expect(st.current).toBe(S);
    expect(st.subs.find((s) => s.id === S)).toMatchObject({ status: 'current', until: null });
    expect((await adminAudit()).some((r) => r.action === 'keys.current' && r.detail.includes(S))).toBe(true);
  });

  it('keys the owner enters or generates: a candidate is used once, by its own session, within 10 minutes; weak or repeated keys are refused', async () => {
    const c = await (await post(`${K}/candidate`, { purpose: 'sub', ...STEP })).json();
    expect(c).toMatchObject({ id: expect.any(String), key: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/), fp: expect.any(String) });
    // Another owner session cannot use it.
    const other = await login('owner', OWNER_PW);
    const elsewhere = await post(`${K}/subs`, { candidate: c.id, ...STEP }, other);
    expect([elsewhere.status, await errorOf(elsewhere)]).toEqual([410, 'candidate_expired']);
    expect((await post(`${K}/subs`, { candidate: c.id, rotate: true, ...STEP })).status).toBe(200);
    expect(await errorOf(await post(`${K}/subs`, { candidate: c.id, ...STEP }))).toBe('candidate_expired'); // once
    // Entered keys: any of hex, base64 or base64url, 32 bytes; never all one byte; never one that is already a sub-MEK.
    expect(await errorOf(await post(`${K}/subs`, { key: 'A'.repeat(43), ...STEP }))).toBe('invalid_key');
    expect(await errorOf(await post(`${K}/subs`, { key: 'not a key', ...STEP }))).toBe('invalid_key');
    const hex = Array.from(randomBytes(32), (b) => b.toString(16).padStart(2, '0')).join('');
    const r = await post(`${K}/subs`, { key: hex, rotate: true, ...STEP });
    expect(r.status).toBe(200);
    const again = await post(`${K}/subs`, { key: hex, ...STEP });
    expect([again.status, await errorOf(again)]).toEqual([409, 'same_key']);
    // Nothing generated or entered is ever logged.
    const rows = await adminAudit();
    for (const x of rows) {
      expect(x.detail).not.toContain(c.key);
      expect(x.detail).not.toContain(hex);
    }
  });

  it('changing the root MEK: every item, link key and field-layer value is re-sealed; the old root goes when it is done', async () => {
    const u = await makeUser('keys-root');
    await enableDrive(u.id, { reverseEnabled: true });
    const f = await uploadFile(u.cookie, 'root', 50);
    const link = await newReverse(u.cookie);
    const ip = '198.51.100.201';
    const got = await send(link, await grantOf(link, { ip }), { ip, path: 'from-outside.txt' });
    const oldKek = (await driveKeys(u.cookie, { fresh: true })).raw.keys;
    const oldRoot = (await status()).root.fp;
    const c = await (await post(`${K}/candidate`, { purpose: 'root', ...STEP })).json();
    const ch = await post(`${K}/root`, { candidate: c.id, ...STEP });
    expect(ch.status).toBe(200);
    // While it runs: the session gets both KEKs (the previous root's as kekOld); a new item uses the new root.
    const mid = await driveKeys(u.cookie, { fresh: true });
    expect(mid.raw.changing).toBe(true);
    expect(mid.raw.keys.find((x) => x.mekId === mid.current).kekOld).toBe(oldKek.find((x) => x.mekId === mid.current).kek);
    const during = await mkdir(u.cookie);
    expect(during.res.status).toBe(201);
    // The key kit waits for the end of the change.
    expect(await errorOf(await post(`${K}/kit`, STEP))).toBe('root_changing');
    const job = await runJob();
    expect(job).toMatchObject({ kind: 'root', finished: true, failed: 0, result: { ok: true } });
    const st = await status();
    expect(st.root).toMatchObject({ fp: c.fp, changing: false, oldFp: null });
    expect(st.root.fp).not.toBe(oldRoot);
    const k = await driveKeys(u.cookie, { fresh: true });
    expect(k.raw.changing).toBe(false);
    expect(k.raw.keys.find((x) => x.mekId === k.current).kek).not.toBe(oldKek.find((x) => x.mekId === k.current).kek);
    // Every item opens under the new KEKs, with the same DEK.
    const n = (await (await node(u.cookie, f.id)).json()).node;
    expect([...(await openStored(u.cookie, n)).dek]).toEqual([...f.fields.dekBytes]);
    expect(await openStored(u.cookie, (await (await node(u.cookie, during.id)).json()).node)).toBeTruthy();
    // The link key and the received file (field layer) too.
    const rec = await received(u.cookie);
    const { privateKey } = await openLinkPriv(u.cookie, link.id, rec.keys[0].priv, rec.keys[0].mek);
    expect((await openUpload(privateKey, link.id, rec.items.find((i) => i.id === got.node))).path).toBe('from-outside.txt');
    expect((await adminAudit()).some((r) => r.action === 'keys.root_change_done' && r.detail.includes(oldRoot))).toBe(true);
  });
});

describe('the key routes carry the isolation headers of every Worker response (src/lib/http.js withBaselineHeaders)', () => {
  it('the session\'s keys, the keyring, the kits, Import / export and the upgrade: COOP/CORP same-origin, XFO DENY, nosniff, no referrer, the API CSP, never stored', async () => {
    const u = await makeUser('keys-headers');
    await enableDrive(u.id);
    const cases = [
      ['POST drive/keys (200, the KEKs)', await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: u.cookie, body: {} })],
      ['POST drive/kit (400, no step-up)', await post('/api/private/drive/kit', {}, u.cookie)],
      ['POST drive/kit/verify (200)', await post('/api/private/drive/kit/verify', { keks: {} }, u.cookie)],
      ['GET drive/migrate (200)', await fetchJson('/api/private/drive/migrate', { cookie: u.cookie })],
      ['GET admin/keys (200)', await fetchJson(K, { cookie: oc })],
      ['GET admin/keys/usage (200)', await fetchJson(`${K}/usage`, { cookie: oc })],
      ['POST admin/keys/root/show (200, a key)', await post(`${K}/root/show`, STEP)],
      ['POST admin/keys/kit (400, no step-up)', await post(`${K}/kit`)],
      ['POST admin/keys/export (200)', await post(`${K}/export`, { root: true, ...STEP })],
      ['GET admin/drive/migration (200)', await fetchJson('/api/private/admin/drive/migration', { cookie: oc })],
      ['GET admin/keys (403, a user)', await fetchJson(K, { cookie: u.cookie })],
    ];
    for (const [what, res] of cases) {
      expect(res.headers.get('cross-origin-opener-policy'), what).toBe('same-origin');
      expect(res.headers.get('cross-origin-resource-policy'), what).toBe('same-origin');
      expect(res.headers.get('x-frame-options'), what).toBe('DENY');
      expect(res.headers.get('x-content-type-options'), what).toBe('nosniff');
      expect(res.headers.get('referrer-policy'), what).toBe('no-referrer');
      expect(res.headers.get('content-security-policy'), what).toBe(API_CSP);
      expect(res.headers.get('cache-control'), what).toBe('no-store');
      await res.arrayBuffer();
    }
  });
});

describe('the key kit (secbin-key-kit/1)', () => {
  it('holds the root MEK, every sub-MEK with its dates and every user salt; the download is recorded for the fresh-kit notice', async () => {
    const m = await kitMaterial();
    const st = await status();
    expect(m.root).toMatchObject({ key: await show(), fp: st.root.fp });
    expect(m.subs.map((s) => s.id).sort()).toEqual(st.subs.map((s) => s.id).sort());
    for (const s of m.subs) expect(s).toMatchObject({ key: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/), from: expect.any(Number) });
    expect(m.salts[ownerId]).toMatchObject({ salt: expect.any(String), username: 'owner' });
    expect(st.kitFresh).toBe(true);
    // A new account (a new salt) makes the kit stale.
    await makeUser('keys-kit-stale');
    expect((await status()).kitFresh).toBe(false);
    const rows = (await adminAudit()).filter((r) => r.action === 'keys.kit_exported');
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) expect(r.detail).not.toContain(m.root.key);
  });

  it('verify: check values only, read-only, rate limited per session', async () => {
    const m = await kitMaterial();
    const body = { root: await keyCheckValue(keyBytes(m.root.key), 'mek'), subs: {}, salts: {} };
    for (const s of m.subs) body.subs[s.id] = await keyCheckValue(keyBytes(s.key), 'mek');
    for (const [uid, v] of Object.entries(m.salts)) body.salts[uid] = await saltCheckValue(v.salt, uid);
    const before = await status();
    const other = await login('owner', OWNER_PW);
    const ok = await (await post(`${K}/verify`, body, other)).json();
    expect(ok).toMatchObject({ complete: true, root: 'match', salts: { match: Object.keys(m.salts).length, mismatch: 0, absent: 0 } });
    expect(ok.subs.every((s) => s.result === 'match')).toBe(true);
    const bad = await (await post(`${K}/verify`, { ...body, root: await keyCheckValue(randomBytes(32), 'mek'), subs: {} }, other)).json();
    expect(bad).toMatchObject({ complete: false, root: 'mismatch' });
    expect(bad.subs.every((s) => s.result === 'absent')).toBe(true);
    // A key sent instead of a check value opens nothing (it is compared, never used).
    expect((await (await post(`${K}/verify`, { root: m.root.key }, other)).json()).root).toBe('mismatch');
    expect(await status()).toMatchObject({ root: before.root, current: before.current });
    let last;
    for (let i = 0; i < 30; i++) last = await post(`${K}/verify`, body, other);
    expect([last.status, await errorOf(last)]).toEqual([429, 'rate_limited']);
    expect((await post(`${K}/verify`, body)).status).toBe(200); // another session has its own budget
  });

  it('restore: only what is lost comes back (a sub-MEK, a salt, the root); working keys are never replaced', async () => {
    const u = await makeUser('keys-restore');
    await enableDrive(u.id);
    const f = await uploadFile(u.cookie, 'root', 10);
    const m = await kitMaterial();
    const k0 = await driveKeys(u.cookie, { fresh: true });
    const restore = (body) => post(`${K}/restore`, body);
    // Nothing lost: nothing to do.
    expect(await (await restore({ root: m.root, subs: m.subs, salts: m.salts })).json()).toMatchObject({ changed: false, root: 'same' });
    // Working keys are kept, whatever the file holds.
    const foreign = { root: { key: b64urlFromBytes(randomBytes(32)) }, subs: m.subs.map((s) => ({ ...s, key: b64urlFromBytes(randomBytes(32)) })) };
    const kept = await (await restore(foreign)).json();
    expect(kept.root).toBe('kept');
    expect(kept.subs.every((s) => ['kept', 'conflict'].includes(s.result))).toBe(true);
    const useRoot = await restore({ ...foreign, useRoot: true });
    expect([useRoot.status, await errorOf(useRoot)]).toEqual([409, 'in_use']); // not on an instance with items
    // A lost sub-MEK and a lost salt.
    await runInDurableObject(dirStub(), (i, s) => {
      s.storage.sql.exec('DELETE FROM meks WHERE id = ?', k0.current);
      s.storage.sql.exec('DELETE FROM user_salts WHERE user_id = ?', u.id);
    });
    const lost = await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: u.cookie, body: {} });
    expect([lost.status, await errorOf(lost)]).toEqual([409, 'salt_missing']);
    const plan = await (await restore({ root: m.root, subs: m.subs, salts: m.salts })).json();
    expect(plan).toMatchObject({ dryRun: true, changed: true, salts: { restored: 1 } });
    expect(plan.subs.find((s) => s.id === k0.current).result).toMatch(/^added/);
    expect((await restore({ root: m.root, subs: m.subs, salts: m.salts, dryRun: false })).status).toBe(400); // the step-up
    const done = await (await restore({ root: m.root, subs: m.subs, salts: m.salts, dryRun: false, ...STEP })).json();
    expect(done).toMatchObject({ dryRun: false, changed: true });
    const k1 = await driveKeys(u.cookie, { fresh: true });
    expect(k1.raw.keys.find((x) => x.mekId === k0.current).kek).toBe(k0.raw.keys.find((x) => x.mekId === k0.current).kek);
    expect([...(await openStored(u.cookie, (await (await node(u.cookie, f.id)).json()).node)).dek]).toEqual([...f.fields.dekBytes]);
    // A lost root MEK: never replaced silently; the kit brings it back.
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec("DELETE FROM meta WHERE k = 'mek.root'"));
    expect(await status()).toMatchObject({ ready: false, lost: true });
    expect(await errorOf(await fetchJson('/api/private/drive/keys', { method: 'POST', cookie: u.cookie, body: {} }))).toBe('keys_missing');
    expect((await (await restore({ root: m.root, dryRun: false, ...STEP })).json()).root).toBe('restored');
    expect((await status()).ready).toBe(true);
    expect((await driveKeys(u.cookie, { fresh: true })).raw.keys).toEqual(k1.raw.keys);
    expect((await adminAudit()).some((r) => r.action === 'keys.restored')).toBe(true);
  });
});

describe('the personal kit (secbin-user-kit/2)', () => {
  it('download after the step-up: the id, username, user salt and the KEK of every sub-MEK in use; the user’s own activity', async () => {
    const u = await makeUser('ukit-dl');
    await enableDrive(u.id);
    await uploadFile(u.cookie, 'root', 10);
    const noStep = await post('/api/private/drive/kit', {}, u.cookie);
    expect([noStep.status, await errorOf(noStep)]).toEqual([400, 'reauth_required']);
    const r = await (await post('/api/private/drive/kit', { current: proofFor(USER_PW) }, u.cookie)).json();
    const k = await driveKeys(u.cookie, { fresh: true });
    expect(r.kit).toMatchObject({ id: u.id, username: 'ukit-dl', current: k.current });
    expect(r.kit.keks.map((x) => x.kek)).toEqual(k.raw.keys.map((x) => x.kek));
    expect(r.kit.keks.every((x) => x.kekOld === undefined)).toBe(true);
    const m = await kitMaterial();
    expect(r.kit.userSalt).toBe(m.salts[u.id].salt);
    const act = (await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json()).rows;
    expect(act.some((x) => x.action === 'drive.kit_exported')).toBe(true);
  });

  it('verify: read-only check values, rate limited; restore: the salt only when the account has none, and only if it opens the Drive', async () => {
    const u = await makeUser('ukit-verify');
    await enableDrive(u.id);
    await uploadFile(u.cookie, 'root', 10);
    const kit = (await (await post('/api/private/drive/kit', { current: proofFor(USER_PW) }, u.cookie)).json()).kit;
    const checks = { keks: {}, salt: await saltCheckValue(kit.userSalt, u.id) };
    for (const x of kit.keks) checks.keks[x.mekId] = await keyCheckValue(keyBytes(x.kek), 'kek');
    const ok = await (await post('/api/private/drive/kit/verify', checks, u.cookie)).json();
    expect(ok).toMatchObject({ complete: true, salt: 'match' });
    expect(ok.keks.find((x) => x.mekId === kit.current)).toMatchObject({ result: 'match', current: true, inUse: true });
    const bad = await (await post('/api/private/drive/kit/verify', { keks: { [kit.current]: await keyCheckValue(randomBytes(32), 'kek') }, salt: await saltCheckValue(newSalt(), u.id) }, u.cookie)).json();
    expect(bad).toMatchObject({ complete: false, salt: 'mismatch' });
    // Restore: the salt is there, so it is kept (same or not).
    const restore = (salt) => post('/api/private/drive/kit/restore', { salt, current: proofFor(USER_PW) }, u.cookie);
    expect((await (await restore(kit.userSalt)).json()).salt).toBe('same');
    expect((await (await restore(newSalt())).json()).salt).toBe('kept');
    await runInDurableObject(dirStub(), (i, s) => s.storage.sql.exec('DELETE FROM user_salts WHERE user_id = ?', u.id));
    expect((await (await restore(newSalt())).json()).salt).toBe('wrong'); // does not open the Drive's items
    expect((await (await restore(kit.userSalt)).json()).salt).toBe('restored');
    expect((await driveKeys(u.cookie, { fresh: true })).raw.keys.map((x) => x.kek)).toEqual(kit.keks.map((x) => x.kek));
    // The items the server can open itself are not handed out for a browser re-seal.
    const items = await fetchJson(`/api/private/drive/kit/items?mek=${kit.current}`, { cookie: u.cookie });
    expect([items.status, await errorOf(items)]).toEqual([409, 'readable']);
    let last;
    for (let i = 0; i < 30; i++) last = await post('/api/private/drive/kit/verify', checks, u.cookie);
    expect([last.status, await errorOf(last)]).toEqual([429, 'rate_limited']);
  });
});

describe('Import / export: the keys parts (secbin-keys-export/1)', () => {
  let u;
  let real;
  beforeAll(async () => {
    u = await makeUser('keys-port');
    await enableDrive(u.id);
    real = await uploadRealFile(u.cookie, 'root', new TextEncoder().encode('the quarterly figures, synthetic'));
  });

  it('exports only the chosen parts, after the step-up; the audit has counts, never a key', async () => {
    const st = await status();
    expect((await post(`${K}/export`, { root: true })).status).toBe(400);
    const doc = (await (await post(`${K}/export`, { root: true, subs: [st.current], salts: [u.id], users: [{ id: u.id, keks: true, deks: 'all' }], ...STEP })).json()).document;
    expect(doc).toMatchObject({ format: 'secbin-keys-export/1', root: { key: await show() }, subs: [{ id: st.current }], salts: { [u.id]: expect.any(String) } });
    expect(doc.users[0]).toMatchObject({ id: u.id, username: 'keys-port' });
    // A KEK for every sub-MEK (the session gets only those its items use, and the current one).
    expect(doc.users[0].keks.map((x) => x.mekId).sort()).toEqual(st.subs.map((x) => x.id).sort());
    expect(doc.users[0].keks.map((x) => x.kek)).toEqual(expect.arrayContaining((await driveKeys(u.cookie, { fresh: true })).raw.keys.map((x) => x.kek)));
    expect(doc.users[0].deks).toEqual([{ id: real.id, dek: b64urlFromBytes(real.dek) }]);
    const only = (await (await post(`${K}/export`, { salts: [u.id], ...STEP })).json()).document;
    expect(only.root).toBeUndefined();
    expect(only.subs).toBeUndefined();
    expect(only.users).toEqual([]);
    const listed = (await (await post(`${K}/export`, { users: [{ id: u.id, keks: false, deks: [real.id] }], ...STEP })).json()).document;
    expect(listed.users[0].keks).toBeUndefined();
    expect(listed.users[0].deks).toHaveLength(1);
    const rows = await adminAudit();
    const ex = rows.filter((r) => r.action === 'keys.exported');
    expect(ex.length).toBe(3);
    for (const r of rows) expect(r.detail).not.toContain(doc.root.key);
    expect(rows.some((r) => r.action === 'drive.keys_viewed' && r.subject_id === u.id)).toBe(true);
  });

  it('import: a KEK only verifies; a DEK restores a broken seal after it opened the first chunk; a salt only when missing', async () => {
    const doc = (await (await post(`${K}/export`, { salts: [u.id], users: [{ id: u.id, keks: true, deks: 'all' }], ...STEP })).json()).document;
    const imp = (body) => post(`${K}/import`, { document: doc, ...body });
    let r = await (await imp({})).json();
    expect(r.users[0]).toMatchObject({ keks: { match: doc.users[0].keks.length, mismatch: 0 }, deks: { working: 1, restored: 0 } });
    expect(r.keys.salts).toMatchObject({ same: 1, restored: 0 });
    // A tampered KEK is only reported.
    const tampered = { ...doc, users: [{ ...doc.users[0], keks: doc.users[0].keks.map((x) => ({ ...x, kek: b64urlFromBytes(randomBytes(32)) })) }] };
    r = await (await post(`${K}/import`, { document: tampered, take: { keks: true } })).json();
    expect(r.users[0].keks).toMatchObject({ match: 0, mismatch: doc.users[0].keks.length });
    // A broken DEK seal (damaged in storage): the import brings it back.
    await runInDurableObject(driveOf(u.id), (i, s) => s.storage.sql.exec('UPDATE nodes SET dek = ? WHERE id = ?', JSON.stringify({ iv: 'A'.repeat(16), ct: 'B'.repeat(64) }), real.id));
    const wrong = { ...doc, users: [{ ...doc.users[0], deks: [{ id: real.id, dek: b64urlFromBytes(randomBytes(32)) }] }] };
    expect((await (await post(`${K}/import`, { document: wrong, take: { deks: true } })).json()).users[0].deks).toMatchObject({ failed: 1, restored: 0 });
    r = await (await imp({ take: { deks: true } })).json();
    expect(r).toMatchObject({ dryRun: true });
    expect(r.users[0].deks).toMatchObject({ restored: 1 });
    expect((await imp({ take: { deks: true }, dryRun: false })).status).toBe(400); // the step-up
    r = await (await imp({ take: { deks: true }, dryRun: false, ...STEP })).json();
    expect(r.users[0].deks).toMatchObject({ restored: 1 });
    const n = (await (await node(u.cookie, real.id)).json()).node;
    const opened = await openStored(u.cookie, n);
    expect([...opened.dek]).toEqual([...real.dek]);
    const chunk = new Uint8Array(await (await getChunk(u.cookie, real.id, 0)).arrayBuffer());
    expect(fromUtf8(await decryptChunk(await importFileKey(b64urlFromBytes(opened.dek)), 0, 1, chunk))).toBe('the quarterly figures, synthetic');
    // A salt comes back only when the account has none.
    const other = { ...doc, salts: { [u.id]: newSalt() } };
    expect((await (await post(`${K}/import`, { document: other, take: { salts: true } })).json()).keys.salts).toMatchObject({ kept: 1, restored: 0 });
    expect((await adminAudit()).some((r2) => r2.action === 'drive.keys_imported' && r2.subject_id === u.id)).toBe(true);
  });

  it('one user’s keys for the owner (masked in the page): their salt and KEKs, or their files’ DEKs with names', async () => {
    const view = (body) => post(`${K}/users/${u.id}/view`, body);
    expect((await view({ what: 'keks' })).status).toBe(400);
    const k = await (await view({ what: 'keks', ...STEP })).json();
    expect(k).toMatchObject({ userId: u.id, username: 'keys-port', current: (await status()).current });
    expect(k.keks.map((x) => x.kek)).toEqual(expect.arrayContaining((await driveKeys(u.cookie, { fresh: true })).raw.keys.map((x) => x.kek)));
    const d = await (await view({ what: 'deks', ...STEP })).json();
    expect(d.files.find((x) => x.id === real.id)).toMatchObject({ dek: b64urlFromBytes(real.dek) });
    expect((await adminAudit()).filter((r) => r.action === 'drive.keys_viewed' && r.subject_id === u.id).length).toBeGreaterThanOrEqual(2);
    // Not for users of other roles' surfaces: a user cannot.
    expect((await post(`${K}/users/${u.id}/view`, { what: 'keks', current: proofFor(USER_PW) }, u.cookie)).status).toBe(403);
  });
});

void env;
