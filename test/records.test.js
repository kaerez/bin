// records.test.js — sign-in and viewer records sealed at rest (SECURITY.md,
// "Records at rest"; src/lib/records.js): the read receipts' opener details, the sign-in
// entries of the activity log and the Guard's addresses. Round trip and AAD
// binding; nothing readable in the stored rows (SQLite read directly); the
// per-address throttles still work on the keyed hashes; a root change and its
// undo keep every record readable; an instance without a keyring writes in
// the clear, flagged, and the background pass seals those rows later.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { env, runInDurableObject } from 'cloudflare:test';
import { owner, makeUser, fetchJson, createNote, openNote, freshIp, proofFor, OWNER_STEP } from './helpers.js';
import { invalidateGuardCaches } from '../src/lib/guard.js';
import { GUARD_SHARDS, guardShardIndex as at } from '../src/guard-do.js';
import { deriveRecordKey, tableKey, sealRecord, openRecord, wrapRecordKey, unwrapRecordKey, isSealedRecord, guardTag, recordNonce } from '../src/lib/records.js';
import { randomBytes, b64urlFromBytes, bytesFromB64url } from '../public/js/bytes.js';
import { keyFingerprint } from '../public/js/drivekeys.js';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';
const dirOf = (name = 'directory') => env.DIRECTORY.get(env.DIRECTORY.idFromName(name));
const shards = () => Array.from({ length: GUARD_SHARDS }, (_, i) => env.GUARD.get(env.GUARD.idFromName(`shard-${i}`)));
const now = () => Math.floor(Date.now() / 1000);

let oc;
beforeAll(async () => { oc = await owner(); });

/** Open a note from `ip` with a browser's headers (a read receipt with every detail). */
async function openAs(n, ip) {
  const head = await (await fetchJson(`/api/paste/${n.id}`, { ip })).json();
  const { deriveAccess } = await import('../public/js/crypto.js');
  const a = await deriveAccess({ adata: head.adata, fragment: n.fragment, password: '' });
  return fetchJson(`/api/paste/${n.id}/open`, { method: 'POST', ip, headers: { 'x-link-proof': a.linkProof, 'x-key-proof': a.keyProof, 'user-agent': UA, 'accept-language': 'he-IL,he;q=0.9' } });
}

const labs = new Set();
/** A Directory of its own (no keyring until `keys`), with an owner and one share of theirs in the index. */
async function lab(name, { keys = true } = {}) {
  labs.add(name);
  const ownerId = `own${name}`.replace(/[^A-Za-z0-9]/g, '').padEnd(16, 'x').slice(0, 16);
  const shareId = `sh${name}`.replace(/[^A-Za-z0-9]/g, '').padEnd(21, 'y').slice(0, 21);
  await runInDurableObject(dirOf(name), async (d) => {
    const t = now();
    d.sql.exec("INSERT OR IGNORE INTO users (id, username, role, pw_salt, pw_t, pw_verifier, created, updated) VALUES (?, ?, 'owner', 's', 3, 'v', ?, ?)", ownerId, `o-${name}`.slice(0, 60), t, t);
    d.sql.exec("INSERT OR IGNORE INTO shares (id, user_id, kind, created, expires, status) VALUES (?, ?, 'paste', ?, ?, 'active')", shareId, ownerId, t, t + 86400);
    if (keys) await d.ensureKeys();
  });
  return { stub: dirOf(name), ownerId, shareId };
}
const rows = (stub, q, ...args) => runInDurableObject(stub, (d) => d.sql.exec(q, ...args).toArray());

describe('records.js', () => {
  it('seals and opens a value; the AAD binds the table, the column, the row nonce and the owner columns', () => {
    const rk = deriveRecordKey(randomBytes(32));
    const k = tableKey(rk, 'opens');
    const where = { table: 'opens', col: 'ip', rn: recordNonce(), bind: ['share-1', 'user-1'] };
    const v = sealRecord(k, where, '203.0.113.9');
    expect(isSealedRecord(v)).toBe(true);
    expect(v).not.toContain('203.0.113.9');
    expect(openRecord(k, where, v)).toBe('203.0.113.9');
    // Two seals of one value differ (a random IV each), and so do two rows' nonces.
    expect(sealRecord(k, where, '203.0.113.9')).not.toBe(v);
    expect(recordNonce()).not.toBe(where.rn);
    for (const other of [{ ...where, rn: recordNonce() }, { ...where, col: 'city' }, { ...where, bind: ['share-2', 'user-1'] }, { ...where, bind: ['share-1', 'user-2'] }, { ...where, bind: ['share-1'] }]) {
      expect(() => openRecord(k, other, v)).toThrow();
    }
    // Another table's key (the same record key) does not open it either, nor another root's record key.
    expect(() => openRecord(tableKey(rk, 'activity'), { ...where, table: 'activity' }, v)).toThrow();
    expect(() => openRecord(tableKey(deriveRecordKey(randomBytes(32)), 'opens'), where, v)).toThrow();
    // A cut ciphertext or a changed byte is refused.
    expect(() => openRecord(k, where, v.slice(0, -2))).toThrow();
    expect(() => openRecord(k, where, `${v.slice(0, -1)}${v.endsWith('A') ? 'B' : 'A'}`)).toThrow();
    // An empty value round-trips too (most sign-in entries have no detail).
    const e = sealRecord(k, where, '');
    expect(isSealedRecord(e)).toBe(true);
    expect(openRecord(k, where, e)).toBe('');
    expect(() => openRecord(k, { ...where, col: 'city' }, e)).toThrow();
    // null and '' are different owner values.
    const w2 = { table: 'activity', col: 'detail', rn: recordNonce(), bind: [null, 'u', 'login'] };
    const v2 = sealRecord(tableKey(rk, 'activity'), w2, 'x');
    expect(() => openRecord(tableKey(rk, 'activity'), { ...w2, bind: ['', 'u', 'login'] }, v2)).toThrow();
  });

  it('an earlier root\'s record key is wrapped under the root, bound to its id', () => {
    const root = randomBytes(32);
    const rk = deriveRecordKey(randomBytes(32));
    const w = wrapRecordKey(root, 'kidA', rk);
    expect([...unwrapRecordKey(root, 'kidA', w)]).toEqual([...rk]);
    expect(() => unwrapRecordKey(root, 'kidB', w)).toThrow();
    expect(() => unwrapRecordKey(randomBytes(32), 'kidA', w)).toThrow();
  });
});

describe('sign-in and viewer records at rest', () => {
  it('a read receipt stores no address, location, browser or language in the clear; the viewers see them opened', async () => {
    const u = await makeUser('rec-sender');
    const n = await createNote(u.cookie, { views: 5, bar: true });
    const ip = '192.0.2.231';
    expect((await openAs(n, ip)).status).toBe(200);
    const [row] = await rows(dirOf(), 'SELECT * FROM opens WHERE share_id = ?', n.id);
    const text = JSON.stringify(row);
    for (const s of [ip, 'Chrome', 'Windows', 'he-IL']) expect(text).not.toContain(s);
    for (const c of ['ip', 'country', 'region', 'city', 'browser', 'browser_ver', 'os', 'langs']) expect(isSealedRecord(row[c])).toBe(true);
    const [{ root }] = await rows(dirOf(), "SELECT json_extract(v, '$.fp') AS root FROM meta WHERE k = 'mek.root'");
    expect(row.rk).toBe(root);
    expect(row.ip_h).toMatch(/^[A-Za-z0-9_-]{24}$/);
    // The admin sees every detail, opened.
    const adm = await (await fetchJson(`/api/private/admin/shares/${n.id}/opens`, { cookie: oc })).json();
    expect(adm.rows[0]).toMatchObject({ ip, browser: 'Chrome', browser_ver: '140', os: 'Windows 10/11', langs: 'he-IL, he' });
  });

  it('a sign-in entry\'s detail is sealed; My activity and the admin audit show it opened', async () => {
    const u = await makeUser('rec-login');
    await runInDurableObject(dirOf(), (d) => d.adminLog({ subject: u.id, action: 'passkey.added', detail: 'name=Dana\'s phone' }, u.id));
    const [row] = await rows(dirOf(), "SELECT * FROM activity WHERE subject_id = ? AND action = 'passkey.added'", u.id);
    expect(row.detail).not.toContain('Dana');
    expect(isSealedRecord(row.detail)).toBe(true);
    const mine = await (await fetchJson('/api/private/me/activity', { cookie: u.cookie })).json();
    expect(mine.rows.find((r) => r.action === 'passkey.added').detail).toBe('name=Dana\'s phone');
    expect(mine.rows.find((r) => r.action === 'passkey.added').rk).toBeUndefined();
    const audit = await (await fetchJson(`/api/private/admin/audit?subject=${u.id}`, { cookie: oc })).json();
    expect(audit.rows.find((r) => r.action === 'passkey.added').detail).toBe('name=Dana\'s phone');
    // The login itself is a sign-in record too; other entries are stored as they are.
    const all = await rows(dirOf(), 'SELECT action, rk, detail FROM activity WHERE subject_id = ?', u.id);
    expect(all.find((r) => r.action === 'login').rk).toBeTruthy();
    expect(all.find((r) => r.action === 'user.created')).toMatchObject({ rk: null });
  });

  it('a sealed value moved to another row or column does not open (shown as unreadable, never as the other row\'s)', async () => {
    const { stub, shareId, ownerId } = await lab('rec-aad');
    await runInDurableObject(stub, async (d) => {
      await d.recordOpen(shareId, { ip: '192.0.2.1', city: 'Haifa' });
      await d.recordOpen(shareId, { ip: '192.0.2.2', city: 'Eilat' });
      await d.adminLog({ subject: ownerId, action: 'login', detail: 'passkey=Laptop' }, ownerId);
      await d.adminLog({ subject: ownerId, action: 'login', detail: 'passkey=Phone' }, ownerId);
      const [a, b] = d.sql.exec('SELECT id, ip, city FROM opens WHERE share_id = ? ORDER BY id', shareId).toArray();
      d.sql.exec('UPDATE opens SET ip = ?, city = ? WHERE id = ?', a.ip, a.ip, b.id); // row a's address into row b, and into its city
      const [x, y] = d.sql.exec("SELECT id, detail FROM activity WHERE action = 'login' ORDER BY id").toArray();
      d.sql.exec('UPDATE activity SET detail = ? WHERE id = ?', x.detail, y.id);
      // Every sealed row has its own nonce.
      expect(new Set(d.sql.exec('SELECT rn FROM opens WHERE share_id = ?', shareId).toArray().map((r) => r.rn)).size).toBe(2);
      const r = await d.shareOpens(null, shareId, { admin: true });
      const moved = r.rows.find((o) => o.unreadable);
      expect(moved).toMatchObject({ ip: '', city: '', unreadable: true });
      expect(r.rows.find((o) => !o.unreadable)).toMatchObject({ ip: '192.0.2.1', city: 'Haifa' });
      const log = await d.audit({ subject: ownerId });
      expect(log.filter((e) => e.action === 'login').map((e) => e.detail)).toEqual(['(unreadable: its key is not available)', 'passkey=Laptop']);
    });
  });

  it('a sealed row moved to another share, account or action does not open (the owner columns are bound)', async () => {
    const { stub, shareId, ownerId } = await lab('rec-owner');
    const other = 'shotherotherotherother'.slice(0, 21);
    await runInDurableObject(stub, async (d) => {
      const t = now();
      d.sql.exec("INSERT OR IGNORE INTO shares (id, user_id, kind, created, expires, status) VALUES (?, ?, 'paste', ?, ?, 'active')", other, ownerId, t, t + 86400);
      d.sql.exec("INSERT OR IGNORE INTO users (id, username, role, pw_salt, pw_t, pw_verifier, created, updated) VALUES ('usrotherotherxx1', 'rec-owner-2', 'user', 's', 3, 'v', ?, ?)", t, t);
      await d.recordOpen(shareId, { ip: '192.0.2.77', city: 'Haifa' });
      await d.adminLog({ subject: ownerId, action: 'passkey.added', detail: 'name=Secret' }, ownerId);
      // The receipt moved to another share (and another sender); the entry to another subject, actor or action.
      d.sql.exec('UPDATE opens SET share_id = ? WHERE share_id = ?', other, shareId);
      const moved = await d.shareOpens(null, other, { admin: true });
      expect(moved.rows[0]).toMatchObject({ ip: '', city: '', unreadable: true });
      d.sql.exec('UPDATE opens SET share_id = ?, user_id = ? WHERE share_id = ?', shareId, 'usrotherotherxx1', other);
      expect((await d.shareOpens(null, shareId, { admin: true })).rows[0].unreadable).toBe(true);
      d.sql.exec('UPDATE opens SET user_id = ? WHERE share_id = ?', ownerId, shareId);
      expect((await d.shareOpens(null, shareId, { admin: true })).rows[0]).toMatchObject({ ip: '192.0.2.77', city: 'Haifa' }); // back where it was: it opens
      const entry = () => d.sql.exec("SELECT id FROM activity WHERE detail LIKE 'r1.%' ORDER BY id DESC LIMIT 1").one().id;
      const id = entry();
      const detailOf = async () => (await d.audit({})).find((e) => e.id === id).detail;
      expect(await detailOf()).toBe('name=Secret');
      for (const [col, v] of [['subject_id', 'usrotherotherxx1'], ['actor_id', 'usrotherotherxx1'], ['action', 'passkey.removed']]) {
        const was = d.sql.exec(`SELECT ${col} AS v FROM activity WHERE id = ?`, id).one().v;
        d.sql.exec(`UPDATE activity SET ${col} = ? WHERE id = ?`, v, id);
        expect(await detailOf()).toBe('(unreadable: its key is not available)');
        d.sql.exec(`UPDATE activity SET ${col} = ? WHERE id = ?`, was, id);
      }
      expect(await detailOf()).toBe('name=Secret');
    });
  });

  it('a record is written sealed in one statement: nothing pending, and an object restarted right after the write loses nothing', async () => {
    const { stub, shareId, ownerId } = await lab('rec-restart');
    await runInDurableObject(stub, async (d) => {
      await d.adminLog({ subject: ownerId, action: 'login', detail: 'passkey=Right before the restart' }, ownerId);
      await d.recordOpen(shareId, { ip: '192.0.2.88', browser: 'Firefox' });
      // Already sealed as written: a nonce, the key id and a sealed value, no pending mark.
      const a = d.sql.exec("SELECT detail, rk, rn FROM activity WHERE action = 'login' ORDER BY id DESC LIMIT 1").one();
      expect(isSealedRecord(a.detail) && /^[A-Za-z0-9_-]{22}$/.test(a.rn) && !!a.rk).toBe(true);
      const o = d.sql.exec('SELECT ip, rk, rn FROM opens WHERE share_id = ?', shareId).one();
      expect(isSealedRecord(o.ip) && !!o.rn && !!o.rk).toBe(true);
    });
    await runInDurableObject(stub, (i, s) => { try { s.abort('restart'); } catch { /* the instance ends here */ } }).catch(() => {});
    await runInDurableObject(dirOf('rec-restart'), async (d) => {
      expect((await d.audit({ subject: ownerId })).find((e) => e.action === 'login').detail).toBe('passkey=Right before the restart');
      expect((await d.shareOpens(null, shareId, { admin: true })).rows[0]).toMatchObject({ ip: '192.0.2.88', browser: 'Firefox' });
    });
  });

  it('the pass reads only unsealed sign-in rows (partial indexes), never the rest of the log', async () => {
    const { UNSEALED_ACTIVITY, UNSEALED_OPENS } = await import('../src/directory-do.js');
    const { stub, ownerId } = await lab('rec-index', { keys: false });
    await runInDurableObject(stub, async (d) => {
      const t = now();
      for (let i = 0; i < 2000; i++) d.sql.exec("INSERT INTO activity (ts, actor_id, subject_id, action, detail) VALUES (?, ?, ?, 'share.created', 'id=x')", t, ownerId, ownerId);
      await d.adminLog({ subject: ownerId, action: 'login', detail: 'passkey=Old' }, ownerId);
      const plan = (q) => d.sql.exec(`EXPLAIN QUERY PLAN ${q}`).toArray().map((r) => r.detail).join(' | ');
      expect(plan(`SELECT id FROM activity WHERE ${UNSEALED_ACTIVITY} ORDER BY id LIMIT 500`)).toMatch(/USING (COVERING )?INDEX activity_unsealed/);
      expect(plan(`SELECT id FROM activity WHERE ${UNSEALED_ACTIVITY} ORDER BY id LIMIT 500`)).not.toMatch(/TEMP B-TREE/);
      expect(plan(`SELECT id FROM opens WHERE ${UNSEALED_OPENS} ORDER BY id LIMIT 500`)).toMatch(/USING (COVERING )?INDEX opens_unsealed/);
      const c = d.sql.exec(`SELECT id, rk, detail FROM activity WHERE ${UNSEALED_ACTIVITY} ORDER BY id LIMIT 500`);
      expect(c.toArray()).toHaveLength(1);
      expect(c.rowsRead).toBeLessThan(10); // not the 2000 other entries
    });
  });

  it('the per-address throttle of read receipts works on the keyed hash', async () => {
    const { stub, shareId } = await lab('rec-hmac');
    await runInDurableObject(stub, async (d) => {
      for (let i = 0; i < 3; i++) await d.recordOpen(shareId, { ip: '198.51.100.77' });
      await d.recordOpen(shareId, { ip: '198.51.100.78' });
      const stored = d.sql.exec('SELECT ip, ip_h FROM opens WHERE share_id = ?', shareId).toArray();
      expect(stored).toHaveLength(2); // one per address per minute
      expect(new Set(stored.map((r) => r.ip_h)).size).toBe(2);
      expect(JSON.stringify(stored)).not.toContain('198.51.100.7');
      expect(d.sql.exec('SELECT opens_total FROM shares WHERE id = ?', shareId).one().opens_total).toBe(4); // every open counted
    });
  });

  it('the Guard blocks a network by the keyed hash; no address in its rows; the admin sees it opened and the audit seals it', async () => {
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.invalid.max': 3, 'guard.invalid.windowSec': 600, 'guard.invalid.blockSec': 600, ...OWNER_STEP } });
    invalidateGuardCaches();
    const n = await createNote(oc, { text: 'x', bar: true, password: 'pw-123456789' });
    const ip = freshIp();
    for (let i = 0; i < 2; i++) expect((await openNote(n.id, n.fragment, 'wrong', { ip })).res.status).toBe(403);
    expect((await openNote(n.id, n.fragment, 'wrong', { ip })).res.status).toBe(429);
    expect((await fetchJson(`/api/paste/${n.id}`, { ip })).status).toBe(429);
    // Stored: a tag and a sealed address, nothing readable.
    const stored = (await Promise.all(shards().map((s) => runInDurableObject(s, (g) => g.sql.exec('SELECT * FROM blocks UNION ALL SELECT scope, key, 0, 0, addr, rk FROM tracking').toArray())))).flat();
    expect(JSON.stringify(stored)).not.toContain(ip);
    const mine = stored.filter((r) => r.scope === 'invalid' && isSealedRecord(r.addr));
    expect(mine.length).toBeGreaterThan(0);
    for (const r of mine) expect(r.key).toMatch(/^h:[A-Za-z0-9_-]{24}$/);
    // The admin's view opens it; unblocking lets the network in again, and the audit entry is sealed.
    const g = await (await fetchJson('/api/private/admin/guard', { cookie: oc })).json();
    const b = g.blocks.find((x) => x.addr === `${ip}/32` && x.scope === 'invalid');
    expect(b.key).toMatch(/^h:/);
    expect(b.rk).toBeUndefined();
    expect((await fetchJson('/api/private/admin/guard/unblock', { method: 'POST', cookie: oc, body: { scope: 'invalid', key: b.key } })).status).toBe(200);
    expect((await openNote(n.id, n.fragment, 'pw-123456789', { ip })).res.status).toBe(200);
    const [entry] = await rows(dirOf(), "SELECT detail, rk FROM activity WHERE action = 'guard.unblocked' ORDER BY id DESC LIMIT 1");
    expect(entry.detail).not.toContain(ip);
    const audit = await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json();
    expect(audit.rows.find((r) => r.action === 'guard.unblocked').detail).toBe(`invalid ${ip}/32`);
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.invalid.max': 60, 'guard.invalid.windowSec': 600, 'guard.invalid.blockSec': 1800, ...OWNER_STEP } });
    invalidateGuardCaches();
  });

  it('login failures from one network are still counted and blocked (login scope)', async () => {
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.login.max': 3, 'guard.login.windowSec': 600, 'guard.login.blockSec': 600, ...OWNER_STEP } });
    invalidateGuardCaches();
    await makeUser('rec-victim', 'rec-victim-password');
    const ip = freshIp();
    const tryLogin = () => fetchJson('/api/auth/login', { method: 'POST', ip, body: { username: 'rec-victim', proof: proofFor('bad') } });
    const codes = [];
    for (let i = 0; i < 4; i++) codes.push((await tryLogin()).status);
    expect(codes.slice(0, 2)).toEqual([401, 401]);
    expect(codes.slice(2)).toEqual([429, 429]);
    // The block is keyed by the network's tag and holds its address sealed only.
    const stored = (await Promise.all(shards().map((s) => runInDurableObject(s, (g) => g.sql.exec("SELECT * FROM blocks WHERE scope = 'login'").toArray())))).flat();
    expect(JSON.stringify(stored)).not.toContain(ip);
    expect(stored.some((r) => /^h:/.test(r.key) && isSealedRecord(r.addr))).toBe(true);
    // Another network is not blocked.
    expect((await fetchJson('/api/auth/login', { method: 'POST', ip: freshIp(), body: { username: 'rec-victim', proof: proofFor('rec-victim-password') } })).status).toBe(200);
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.login.max': 10, 'guard.login.windowSec': 600, 'guard.login.blockSec': 900, ...OWNER_STEP } });
    invalidateGuardCaches();
  });
});

const readAll = (d, shareId, ownerId) => Promise.all([d.shareOpens(null, shareId, { admin: true }), d.audit({ subject: ownerId })]);

describe('root MEK changes', () => {
  const newRoot = () => b64urlFromBytes(randomBytes(32));

  it('records sealed under an earlier root stay readable after the change is done; the pass re-seals them under the new root', async () => {
    const { stub, shareId, ownerId } = await lab('rec-rotate');
    await runInDurableObject(stub, async (d) => {
      await d.recordOpen(shareId, { ip: '192.0.2.10', browser: 'Firefox' });
      await d.adminLog({ subject: ownerId, action: 'login', detail: 'passkey=Before' }, ownerId);
      const kidA = d.sql.exec("SELECT rk FROM opens WHERE share_id = ?", shareId).one().rk;
      const keyB = newRoot();
      expect((await d.mekChangeRoot(ownerId, { key: keyB })).ok).toBe(true);
      await d.recordOpen(shareId, { ip: '192.0.2.11', browser: 'Safari' });
      await d.adminLog({ subject: ownerId, action: 'login', detail: 'passkey=During' }, ownerId);
      // The change is done: the old root is gone (its record key is kept, sealed under the new root).
      expect((await d.mekRootDone(ownerId)).done).toBe(true);
      expect(d.sql.exec("SELECT COUNT(*) AS c FROM meta WHERE k = 'mek.rootOld'").one().c).toBe(0);
      expect(d.sql.exec('SELECT kid FROM record_keys').toArray().map((r) => r.kid)).toEqual([kidA]);
      const [opens, log] = await readAll(d, shareId, ownerId);
      expect(opens.rows.map((r) => [r.ip, r.browser])).toEqual([['192.0.2.11', 'Safari'], ['192.0.2.10', 'Firefox']]);
      expect(log.filter((e) => e.action === 'login').map((e) => e.detail)).toEqual(['passkey=During', 'passkey=Before']);
      // The pass: every row under the new root's key now; still readable.
      await d.alarm();
      const kidB = await keyFingerprint(bytesFromB64url(keyB));
      expect(new Set(d.sql.exec('SELECT rk FROM opens WHERE share_id = ?', shareId).toArray().map((r) => r.rk))).toEqual(new Set([kidB]));
      expect(new Set(d.sql.exec("SELECT rk FROM activity WHERE action = 'login'").toArray().map((r) => r.rk))).toEqual(new Set([kidB]));
      const [again, log2] = await readAll(d, shareId, ownerId);
      expect(again.rows.map((r) => r.ip)).toEqual(['192.0.2.11', '192.0.2.10']);
      expect(log2.filter((e) => e.action === 'login').map((e) => e.detail)).toEqual(['passkey=During', 'passkey=Before']);
    });
  });

  it('an undone root change ("Go back") keeps what was sealed under the root that was new', async () => {
    const { stub, shareId, ownerId } = await lab('rec-undo');
    await runInDurableObject(stub, async (d) => {
      await d.adminLog({ subject: ownerId, action: 'login', detail: 'passkey=First' }, ownerId);
      expect((await d.mekChangeRoot(ownerId, { key: newRoot() })).ok).toBe(true);
      await d.adminLog({ subject: ownerId, action: 'login', detail: 'passkey=UnderNew' }, ownerId);
      await d.recordOpen(shareId, { ip: '192.0.2.20', os: 'Linux' });
      const kidNew = d.sql.exec("SELECT json_extract(v, '$.fp') AS fp FROM meta WHERE k = 'mek.root'").one().fp;
      const sealedRow = d.sql.exec('SELECT ip, rk FROM opens WHERE share_id = ?', shareId).one();
      expect(sealedRow.rk).toBe(kidNew);
      expect(isSealedRecord(sealedRow.ip)).toBe(true);
      expect((await d.mekRootSwap(ownerId)).ok).toBe(true);
      // The root that was new goes (its record key stays, sealed under the root); what it sealed is still read.
      expect((await d.mekRootDone(ownerId)).done).toBe(true);
      expect(d.sql.exec('SELECT kid FROM record_keys').toArray().map((r) => r.kid)).toContain(kidNew);
      const [opens, log] = await readAll(d, shareId, ownerId);
      expect(opens.rows[0]).toMatchObject({ ip: '192.0.2.20', os: 'Linux' });
      expect(log.filter((e) => e.action === 'login').map((e) => e.detail)).toEqual(['passkey=UnderNew', 'passkey=First']);
    });
  });
});

describe('no keyring yet (an instance from before the Drive)', () => {
  it('records are written in the clear, flagged; once there is a keyring the pass seals them and they read the same', async () => {
    const { stub, shareId, ownerId } = await lab('rec-nokeys', { keys: false });
    await runInDurableObject(stub, async (d) => {
      expect(d.sql.exec("SELECT COUNT(*) AS c FROM meta WHERE k = 'mek.root'").one().c).toBe(0);
      await d.recordOpen(shareId, { ip: '192.0.2.40', browser: 'Edge' });
      await d.recordOpen(shareId, { ip: '192.0.2.40', browser: 'Edge' }); // the throttle works without a keyring too
      await d.adminLog({ subject: ownerId, action: 'login', detail: 'passkey=Old' }, ownerId);
      const [o] = d.sql.exec('SELECT ip, browser, ip_h, rk FROM opens WHERE share_id = ?', shareId).toArray();
      expect(o).toMatchObject({ ip: '192.0.2.40', browser: 'Edge', rk: null });
      expect(o.ip_h).toMatch(/^[A-Za-z0-9_-]{24}$/);
      expect(d.sql.exec("SELECT detail, rk FROM activity WHERE action = 'login'").one()).toEqual({ detail: 'passkey=Old', rk: null });
      // The keyring arrives; new records are sealed at once, the earlier ones by the pass.
      expect((await d.ensureKeys()).created).toBe(true);
      await d.adminLog({ subject: ownerId, action: 'login', detail: 'passkey=New' }, ownerId);
      expect(d.sql.exec("SELECT COUNT(*) AS c FROM activity WHERE action = 'login' AND rk IS NULL").one().c).toBe(1);
      await d.alarm();
      const sealedRow = d.sql.exec('SELECT * FROM opens WHERE share_id = ?', shareId).one();
      expect(JSON.stringify(sealedRow)).not.toContain('192.0.2.40');
      expect(isSealedRecord(sealedRow.browser)).toBe(true);
      expect(sealedRow.ip_h).toBe(o.ip_h);
      for (const r of d.sql.exec("SELECT detail, rk FROM activity WHERE action = 'login'").toArray()) {
        expect(isSealedRecord(r.detail)).toBe(true);
        expect(r.rk).toBeTruthy();
      }
      const [opens, log] = await readAll(d, shareId, ownerId);
      expect(opens.rows[0]).toMatchObject({ ip: '192.0.2.40', browser: 'Edge' });
      expect(log.filter((e) => e.action === 'login').map((e) => e.detail)).toEqual(['passkey=New', 'passkey=Old']);
    });
  });
});

describe('Guard rows from before the tags', () => {
  // The lab Directories above share the Guard shards with the real one (a deployment has one
  // Directory): their alarms' passes, with their own secrets, must not run in these tests.
  beforeAll(() => Promise.all([...labs].map((name) => runInDurableObject(dirOf(name), (d) => d.ctx.storage.deleteAlarm()))));
  // Nor the real Directory's own alarm between "after the upgrade" and the pass these tests run by hand.
  const holdPass = () => runInDurableObject(dirOf(), (d) => d.ctx.storage.deleteAlarm());
  afterAll(() => runInDurableObject(dirOf(), (d) => d.ctx.storage.setAlarm(Date.now() + 3600 * 1000)));
  /** The Guard shards as the release before left them: no "legacy.done" (nothing re-keyed yet); `seed` writes rows there in the same step. */
  const upgraded = (seed = {}) => Promise.all(shards().map((s, i) => runInDurableObject(s, (g) => {
    g.sql.exec("DELETE FROM meta WHERE k = 'legacy.done'");
    seed[i]?.(g.sql);
  })));
  const doneFlags = () => Promise.all(shards().map((s) => runInDurableObject(s, (g) => g.sql.exec("SELECT COUNT(*) AS c FROM meta WHERE k = 'legacy.done'").one().c)));
  const tagOf = (legacy) => runInDurableObject(dirOf(), async (d) => guardTag(bytesFromB64url((await d.guardKeys()).tag), legacy));

  it('a block made before applies at once after the upgrade (legacy lookup), and after the pass as its tagged row', async () => {
    const ip = '203.0.113.201';
    const legacy = `${ip}/32`;
    const t = now();
    await holdPass();
    // A block the release before left: keyed by the address, in the shard of the address.
    await upgraded({ [at(legacy)]: (sql) => sql.exec("INSERT OR REPLACE INTO blocks (scope, key, until, since) VALUES ('invalid', ?, ?, ?)", legacy, t + 600, t) });
    invalidateGuardCaches();
    const n = await createNote(oc, { text: 'x', bar: true });
    // Right after the deploy, before any pass: still blocked.
    expect((await fetchJson(`/api/paste/${n.id}`, { ip })).status).toBe(429);
    expect(await doneFlags()).toEqual(Array(GUARD_SHARDS).fill(0));
    // The pass re-keys it (to its tag's shard) and marks every shard done.
    await runInDurableObject(dirOf(), (d) => d.alarm());
    expect(await doneFlags()).toEqual(Array(GUARD_SHARDS).fill(1));
    const stored = (await Promise.all(shards().map((s) => runInDurableObject(s, (g) => g.sql.exec("SELECT * FROM blocks WHERE scope = 'invalid'").toArray())))).flat();
    expect(JSON.stringify(stored)).not.toContain(ip);
    const tag = await tagOf(legacy);
    const row = stored.find((r) => r.key === tag);
    expect(row).toMatchObject({ until: t + 600 });
    expect(isSealedRecord(row.addr)).toBe(true);
    // Still blocked, now through the tag alone (the legacy lookup has stopped).
    invalidateGuardCaches();
    expect((await fetchJson(`/api/paste/${n.id}`, { ip })).status).toBe(429);
    const g = await (await fetchJson('/api/private/admin/guard', { cookie: oc })).json();
    expect(g.blocks.find((x) => x.key === tag).addr).toBe(legacy);
    expect((await fetchJson('/api/private/admin/guard/unblock', { method: 'POST', cookie: oc, body: { scope: 'invalid', key: tag } })).status).toBe(200);
    expect((await fetchJson(`/api/paste/${n.id}`, { ip })).status).toBe(200);
  });

  it('failures counted before the upgrade still count toward the block before the pass', async () => {
    expect((await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.invalid.max': 3, 'guard.invalid.windowSec': 600, 'guard.invalid.blockSec': 600, ...OWNER_STEP } })).status).toBe(200);
    const ip = '203.0.113.202';
    const legacy = `${ip}/32`;
    const t = now();
    await holdPass();
    await upgraded({ [at(legacy)]: (sql) => sql.exec("INSERT OR REPLACE INTO tracking (scope, key, count, start, expires) VALUES ('invalid', ?, 2, ?, ?)", legacy, t - 10, t + 590) });
    invalidateGuardCaches();
    const n = await createNote(oc, { text: 'x', bar: true, password: 'pw-123456789' });
    // Two failures before the upgrade, one after: the third blocks.
    expect((await openNote(n.id, n.fragment, 'wrong', { ip })).res.status).toBe(429);
    expect((await fetchJson(`/api/paste/${n.id}`, { ip })).status).toBe(429);
    // The legacy counter was taken over by the tagged row (not counted twice); the block is the tag's.
    expect(await runInDurableObject(shards()[at(legacy)], (g) => g.sql.exec("SELECT COUNT(*) AS c FROM tracking WHERE key = ?", legacy).one().c)).toBe(0);
    const tag = await tagOf(legacy);
    const g = await (await fetchJson('/api/private/admin/guard', { cookie: oc })).json();
    expect(g.blocks.find((x) => x.key === tag && x.scope === 'invalid').addr).toBe(legacy);
    await runInDurableObject(dirOf(), (d) => d.alarm());
    expect(await doneFlags()).toEqual(Array(GUARD_SHARDS).fill(1));
    expect((await fetchJson('/api/private/admin/guard/unblock', { method: 'POST', cookie: oc, body: { scope: 'invalid', key: tag } })).status).toBe(200);
    await fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.invalid.max': 60, 'guard.invalid.windowSec': 600, 'guard.invalid.blockSec': 1800, ...OWNER_STEP } });
    invalidateGuardCaches();
  });
});

describe('the Guard routes and the pass (review of #86)', () => {
  const setInvalid = (max) => fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { 'guard.invalid.max': max, 'guard.invalid.windowSec': 600, 'guard.invalid.blockSec': 600, ...OWNER_STEP } });
  const guardView = async () => (await fetchJson('/api/private/admin/guard', { cookie: oc })).json();
  const lastAudit = async (action) => (await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json()).rows.find((r) => r.action === action)?.detail;
  const block = (key, seconds = 600) => fetchJson('/api/private/admin/guard/block', { method: 'POST', cookie: oc, body: { scope: 'invalid', key, seconds } });
  const unblock = (key) => fetchJson('/api/private/admin/guard/unblock', { method: 'POST', cookie: oc, body: { scope: 'invalid', key } });

  it('F1 / F7: a typed address is normalised as the Guard keys it; a block with no row yet keeps it for the view and the audit', async () => {
    invalidateGuardCaches();
    const n = await createNote(oc, { text: 'x', bar: true });
    const ip = '198.51.100.241';
    // A bare IPv4 address, no row for it anywhere: the block holds it as "/32".
    expect((await block(ip)).status).toBe(200);
    expect((await fetchJson(`/api/paste/${n.id}`, { ip })).status).toBe(429);
    const b = (await guardView()).blocks.find((x) => x.scope === 'invalid' && x.addr === `${ip}/32`);
    expect(b.key).toMatch(/^h:/);
    expect(await lastAudit('guard.blocked')).toBe(`invalid ${ip}/32 600s`);
    // Unblocking the bare address works too, and the audit names it.
    expect((await unblock(ip)).status).toBe(200);
    expect((await fetchJson(`/api/paste/${n.id}`, { ip })).status).toBe(200);
    expect(await lastAudit('guard.unblocked')).toBe(`invalid ${ip}/32`);
    // A bare IPv6 address: the Guard's prefix (a /64 by default) — another address in it is blocked too.
    expect((await block('2001:DB8:77::5')).status).toBe(200);
    expect((await fetchJson(`/api/paste/${n.id}`, { ip: '2001:db8:77::9' })).status).toBe(429);
    expect((await guardView()).blocks.some((x) => x.addr === '2001:db8:77:0:0:0:0:0/64')).toBe(true);
    expect((await unblock('2001:db8:77:0::1')).status).toBe(200);
    expect((await fetchJson(`/api/paste/${n.id}`, { ip: '2001:db8:77::9' })).status).toBe(200);
  });

  it('F1: "Block 24h" on a row not re-keyed yet (its key is the address) keeps the address', async () => {
    const ip = '198.51.100.242';
    const legacy = `${ip}/32`;
    const t = now();
    await runInDurableObject(shards()[at(legacy)], (g) => {
      g.sql.exec("INSERT OR REPLACE INTO tracking (scope, key, count, start, expires) VALUES ('invalid', ?, 1, ?, ?)", legacy, t, t + 600);
      g.sql.exec("DELETE FROM meta WHERE k = 'legacy.done'");
    });
    invalidateGuardCaches();
    const row = (await guardView()).tracking.find((x) => x.key === legacy);
    expect(row.addr).toBe(legacy);
    expect((await block(row.key, 86400)).status).toBe(200);
    const b = (await guardView()).blocks.find((x) => x.scope === 'invalid' && x.addr === legacy);
    expect(b.key).toMatch(/^h:/);
    expect(await lastAudit('guard.blocked')).toBe(`invalid ${legacy} 86400s`);
    expect((await unblock(b.key)).status).toBe(200);
    await runInDurableObject(dirOf(), (d) => d.alarm());
  });

  it('F2: a failure between the pass taking a legacy counter and adding it to the tag is counted once', async () => {
    expect((await setInvalid(6)).status).toBe(200);
    await runInDurableObject(dirOf(), (d) => d.ctx.storage.deleteAlarm());
    const ip = '198.51.100.243';
    const legacy = `${ip}/32`;
    const t = now();
    const tag = guardTag(bytesFromB64url(await runInDurableObject(dirOf(), async (d) => (await d.guardKeys()).tag)), legacy);
    await runInDurableObject(shards()[at(legacy)], (g) => {
      g.sql.exec("DELETE FROM meta WHERE k = 'legacy.done'");
      g.sql.exec("INSERT OR REPLACE INTO tracking (scope, key, count, start, expires) VALUES ('invalid', ?, 2, ?, ?)", legacy, t - 10, t + 590);
    });
    invalidateGuardCaches();
    // The pass's first half: the legacy counter is read and deleted in one Guard transaction.
    const taken = await shards()[at(legacy)].takeLegacy([{ scope: 'invalid', key: legacy }]);
    expect(taken).toMatchObject([{ scope: 'invalid', key: legacy, count: 2 }]);
    // A failure in between: nothing to carry any more, one on the tag.
    const n = await createNote(oc, { text: 'x', bar: true, password: 'pw-123456789' });
    expect((await openNote(n.id, n.fragment, 'wrong', { ip })).res.status).toBe(403);
    // The second half: added to the tag's counter.
    await shards()[at(tag)].apply({ adopt: taken.map((r) => ({ ...r, t: 'tracking', key: tag, addr: null, rk: null })) });
    const count = await runInDurableObject(shards()[at(tag)], (g) => g.sql.exec("SELECT count FROM tracking WHERE scope = 'invalid' AND key = ?", tag).one().count);
    expect(count).toBe(3); // 2 before + 1, not 5
    // 3 more failures reach the rule's 6.
    const codes = [];
    for (let i = 0; i < 3; i++) codes.push((await openNote(n.id, n.fragment, 'wrong', { ip })).res.status);
    expect(codes).toEqual([403, 403, 429]);
    expect((await unblock(ip)).status).toBe(200);
    expect((await setInvalid(60)).status).toBe(200);
    await runInDurableObject(dirOf(), (d) => d.alarm());
  });

  it('8: a row keyed by an address written after a shard is done (a Worker of the release before) is enforced, and re-keyed by the pass', async () => {
    await runInDurableObject(dirOf(), (d) => d.alarm());
    const ip = '198.51.100.244';
    const legacy = `${ip}/32`;
    const s = shards()[at(legacy)];
    expect(await runInDurableObject(s, (g) => g.sql.exec("SELECT COUNT(*) AS c FROM meta WHERE k = 'legacy.done'").one().c)).toBe(1);
    invalidateGuardCaches();
    const n = await createNote(oc, { text: 'x', bar: true });
    expect((await fetchJson(`/api/paste/${n.id}`, { ip })).status).toBe(200); // this isolate now holds "done" for the shard
    // The release before blocks it (its Guard key is the address): the shard is not done any more.
    await s.block('invalid', legacy, now() + 600);
    expect(await runInDurableObject(s, (g) => g.sql.exec("SELECT COUNT(*) AS c FROM meta WHERE k = 'legacy.done'").one().c)).toBe(0);
    // The Directory was asked to run its pass soon.
    const alarm = await runInDurableObject(dirOf(), (d) => d.ctx.storage.getAlarm());
    expect(alarm - Date.now()).toBeLessThan(5000);
    // Once this isolate's "done" goes stale (CACHE_MS; here at once), the block applies.
    invalidateGuardCaches();
    expect((await fetchJson(`/api/paste/${n.id}`, { ip })).status).toBe(429);
    // The pass re-keys it and marks the shard done again; still blocked, now by its tag.
    await runInDurableObject(dirOf(), (d) => d.alarm());
    expect(await runInDurableObject(s, (g) => g.sql.exec("SELECT COUNT(*) AS c FROM meta WHERE k = 'legacy.done'").one().c)).toBe(1);
    expect(await runInDurableObject(s, (g) => g.sql.exec('SELECT COUNT(*) AS c FROM blocks WHERE key = ?', legacy).one().c)).toBe(0);
    invalidateGuardCaches();
    expect((await fetchJson(`/api/paste/${n.id}`, { ip })).status).toBe(429);
    expect((await unblock(ip)).status).toBe(200);
  });

  it('7: a Drive upload session keeps the network only as a keyed hash', async () => {
    const { receiver, newReverse, begin, driveOf } = await import('./reverse-helpers.js');
    const u = await receiver('rec-net');
    const r = await newReverse(u.cookie);
    const ip = '198.51.100.245';
    expect((await begin(r, { ip })).status).toBe(200);
    const [row] = await runInDurableObject(driveOf(u.id), (i, st) => st.storage.sql.exec('SELECT net FROM rsessions WHERE rid = ?', r.id).toArray());
    // Not the unkeyed hash of the address the release before stored.
    const unkeyed = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(`secbin-reverse/v1 net\n${r.id}\n${ip}/32`)));
    expect(row.net).toBeTruthy();
    expect(row.net).not.toBe(b64urlFromBytes(unkeyed.subarray(0, 3)));
    expect(row.net).not.toContain(ip);
  });
});
