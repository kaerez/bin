// records.test.js — sign-in and viewer records sealed at rest (SECURITY.md,
// "Records at rest"; src/lib/records.js): the read receipts' opener details, the sign-in
// entries of the activity log and the Guard's addresses. Round trip and AAD
// binding; nothing readable in the stored rows (SQLite read directly); the
// per-address throttles still work on the keyed hashes; a root change and its
// undo keep every record readable; an instance without a keyring writes in
// the clear, flagged, and the background pass seals those rows later.
import { describe, it, expect, beforeAll } from 'vitest';
import { env, runInDurableObject } from 'cloudflare:test';
import { owner, makeUser, fetchJson, createNote, openNote, freshIp, proofFor, OWNER_STEP } from './helpers.js';
import { invalidateGuardCaches } from '../src/lib/guard.js';
import { GUARD_SHARDS } from '../src/guard-do.js';
import { deriveRecordKey, tableKey, sealRecord, openRecord, wrapRecordKey, unwrapRecordKey, isSealedRecord, guardTag, importTagKey } from '../src/lib/records.js';
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

/** A Directory of its own (no keyring until `keys`), with an owner and one share of theirs in the index. */
async function lab(name, { keys = true } = {}) {
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
  it('seals and opens a value; the AAD binds the table, the column and the row', async () => {
    const rk = await deriveRecordKey(randomBytes(32));
    const k = await tableKey(rk, 'opens');
    const where = { table: 'opens', col: 'ip', id: 7 };
    const v = await sealRecord(k, where, '203.0.113.9');
    expect(isSealedRecord(v)).toBe(true);
    expect(v).not.toContain('203.0.113.9');
    expect(await openRecord(k, where, v)).toBe('203.0.113.9');
    // Two seals of one value differ (a random IV each).
    expect(await sealRecord(k, where, '203.0.113.9')).not.toBe(v);
    for (const other of [{ ...where, id: 8 }, { ...where, col: 'city' }]) await expect(openRecord(k, other, v)).rejects.toThrow();
    // Another table's key (the same record key) does not open it either.
    await expect(openRecord(await tableKey(rk, 'activity'), { ...where, table: 'activity' }, v)).rejects.toThrow();
    // Nor another root's record key.
    await expect(openRecord(await tableKey(await deriveRecordKey(randomBytes(32)), 'opens'), where, v)).rejects.toThrow();
  });

  it('an earlier root\'s record key is wrapped under the root, bound to its id', async () => {
    const root = randomBytes(32);
    const rk = await deriveRecordKey(randomBytes(32));
    const w = await wrapRecordKey(root, 'kidA', rk);
    expect([...await unwrapRecordKey(root, 'kidA', w)]).toEqual([...rk]);
    await expect(unwrapRecordKey(root, 'kidB', w)).rejects.toThrow();
    await expect(unwrapRecordKey(randomBytes(32), 'kidA', w)).rejects.toThrow();
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
      const r = await d.shareOpens(null, shareId, { admin: true });
      const moved = r.rows.find((o) => o.unreadable);
      expect(moved).toMatchObject({ ip: '', city: '', unreadable: true });
      expect(r.rows.find((o) => !o.unreadable)).toMatchObject({ ip: '192.0.2.1', city: 'Haifa' });
      const log = await d.audit({ subject: ownerId });
      expect(log.filter((e) => e.action === 'login').map((e) => e.detail)).toEqual(['(unreadable: its key is not available)', 'passkey=Laptop']);
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
  it('the pass re-keys a block made before (to its tag\'s shard), seals its address, and the block still applies', async () => {
    const ip = '203.0.113.201';
    const legacy = `${ip}/32`;
    const t = now();
    // A block the release before left: keyed by the address, in the shard of the address.
    const { guardShardIndex } = await import('../src/guard-do.js');
    await runInDurableObject(shards()[guardShardIndex(legacy)], (g) => g.sql.exec("INSERT OR REPLACE INTO blocks (scope, key, until, since) VALUES ('invalid', ?, ?, ?)", legacy, t + 600, t));
    await runInDurableObject(dirOf(), (d) => d.alarm());
    const stored = (await Promise.all(shards().map((s) => runInDurableObject(s, (g) => g.sql.exec("SELECT * FROM blocks WHERE scope = 'invalid'").toArray())))).flat();
    expect(JSON.stringify(stored)).not.toContain(ip);
    const tag = await runInDurableObject(dirOf(), async (d) => guardTag(await importTagKey(bytesFromB64url((await d.guardKeys()).tag)), legacy));
    const row = stored.find((r) => r.key === tag);
    expect(row).toMatchObject({ until: t + 600 });
    expect(isSealedRecord(row.addr)).toBe(true);
    // Still blocked, through the Worker's own lookup.
    invalidateGuardCaches();
    const n = await createNote(oc, { text: 'x', bar: true });
    expect((await fetchJson(`/api/paste/${n.id}`, { ip })).status).toBe(429);
    const g = await (await fetchJson('/api/private/admin/guard', { cookie: oc })).json();
    expect(g.blocks.find((x) => x.key === tag).addr).toBe(legacy);
    expect((await fetchJson('/api/private/admin/guard/unblock', { method: 'POST', cookie: oc, body: { scope: 'invalid', key: tag } })).status).toBe(200);
    expect((await fetchJson(`/api/paste/${n.id}`, { ip })).status).toBe(200);
  });
});
