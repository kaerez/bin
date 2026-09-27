// read-receipts.test.js — every open is recorded; the sender always sees the
// time, and only the details the admin allows (receipt* limits); the admin
// sees everything; receipts follow the log's retention and clearing.
import { describe, it, expect, beforeAll } from 'vitest';
import { env, runInDurableObject } from 'cloudflare:test';
import { owner, makeUser, fetchJson, createNote, openNote, proofFor } from './helpers.js';

let oc;
beforeAll(async () => { oc = await owner(); });
const limits = (scope, patch) => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope, channel: 'all', patch } });

describe('read receipts', () => {
  it('records opens; the sender sees times plus allowed details, the admin all', async () => {
    const u = await makeUser('rr-sender');
    const n = await createNote(u.cookie, { views: 5, bar: true });
    const ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36';
    for (const ip of ['198.51.100.201', '198.51.100.202']) {
      const head = await (await fetchJson(`/api/paste/${n.id}`, { ip })).json();
      const { deriveAccess } = await import('../public/js/crypto.js');
      const a = await deriveAccess({ adata: head.adata, fragment: n.fragment, password: '' });
      const r = await fetchJson(`/api/paste/${n.id}/open`, { method: 'POST', ip, headers: { 'x-link-proof': a.linkProof, 'x-key-proof': a.keyProof, 'user-agent': ua, 'accept-language': 'he-IL,he;q=0.9,en-US;q=0.8' } });
      expect(r.status).toBe(200);
    }
    // A wrong-proof attempt is not an open.
    expect((await openNote(n.id, n.fragment, '', { tamper: true })).res.status).toBe(403);

    const mine = await (await fetchJson(`/api/private/shares/${n.id}/opens`, { cookie: u.cookie })).json();
    expect(mine.total).toBe(2);
    expect(mine.fields).toEqual([]);
    expect(Object.keys(mine.rows[0])).toEqual(['ts']); // times only by default

    expect((await limits(u.id, { receiptBrowser: true, receiptLanguages: true })).status).toBe(200);
    const more = await (await fetchJson(`/api/private/shares/${n.id}/opens`, { cookie: u.cookie })).json();
    expect(more.fields).toEqual(['receiptBrowser', 'receiptLanguages']);
    expect(more.rows[0]).toMatchObject({ browser: 'Chrome', browser_ver: '140', langs: 'he-IL, he, en-US' });
    expect(more.rows[0].ip).toBeUndefined();

    const adm = await (await fetchJson(`/api/private/admin/shares/${n.id}/opens`, { cookie: oc })).json();
    expect(adm.rows[0]).toMatchObject({ ip: '198.51.100.202', browser: 'Chrome', os: 'Windows 10/11' });

    const list = await (await fetchJson('/api/private/shares', { cookie: u.cookie })).json();
    expect(list.rows.find((r) => r.id === n.id).opens).toBe(2);

    // Someone else's share: not found.
    const other = await makeUser('rr-other');
    expect((await fetchJson(`/api/private/shares/${n.id}/opens`, { cookie: other.cookie })).status).toBe(404);

    // Clearing the sender's log clears the receipts too.
    const c = await fetchJson('/api/private/admin/logs/clear', { method: 'POST', cookie: oc, body: { current: proofFor('owner-password'), scope: 'user', user: u.id } });
    expect((await c.json()).receipts).toBe(2);
    expect((await (await fetchJson(`/api/private/shares/${n.id}/opens`, { cookie: u.cookie })).json()).total).toBe(0);
  });
});

const dir = () => env.DIRECTORY.get(env.DIRECTORY.idFromName('directory'));

describe('read receipts under load', () => {
  it('repeat opens from one address are counted but stored once per minute', async () => {
    const u = await makeUser('rr-repeat');
    const n = await createNote(u.cookie, { views: 10, bar: true });
    for (let i = 0; i < 5; i++) expect((await openNote(n.id, n.fragment, '', { ip: '203.0.113.77' })).res.status).toBe(200);
    const mine = await (await fetchJson(`/api/private/shares/${n.id}/opens`, { cookie: u.cookie })).json();
    expect(mine.rows).toHaveLength(1); // one stored receipt per address per minute
    expect(mine.total).toBe(5); // every open counted
    const list = await (await fetchJson('/api/private/shares', { cookie: u.cookie })).json();
    expect(list.rows.find((r) => r.id === n.id).opens).toBe(5); // My shares shows the full count
  });

  it('a burst is capped per minute, and the first receipts are kept for good', async () => {
    const u = await makeUser('rr-burst');
    const n = await createNote(u.cookie, { bar: true });
    await runInDurableObject(dir(), async (d) => {
      for (let i = 0; i < 40; i++) await d.recordOpen(n.id, { ip: `192.0.2.${i + 1}` });
      const stored = d.sql.exec('SELECT COUNT(*) AS c FROM opens WHERE share_id = ?', n.id).one().c;
      expect(stored).toBe(30); // OPENS_PER_MINUTE
      expect(d.sql.exec('SELECT opens_total FROM shares WHERE id = ?', n.id).one().opens_total).toBe(40);
      // Age them, then add 1000 more (as if over many minutes): the first 100 stay.
      d.sql.exec('UPDATE opens SET ts = ts - 3600 WHERE share_id = ?', n.id);
      const first = d.sql.exec('SELECT id FROM opens WHERE share_id = ? ORDER BY id LIMIT 30', n.id).toArray().map((r) => r.id);
      for (let i = 0; i < 1000; i++) {
        d.sql.exec("INSERT INTO opens (share_id, user_id, ts, ip) VALUES (?, ?, ?, 'x')", n.id, u.id, Math.floor(Date.now() / 1000) - 7200);
      }
      await d.recordOpen(n.id, { ip: '198.18.0.1' });
      const kept = d.sql.exec('SELECT id FROM opens WHERE share_id = ? ORDER BY id', n.id).toArray().map((r) => r.id);
      expect(kept.length).toBe(1000);
      expect(first.every((id) => kept.includes(id))).toBe(true);
    });
  });

  it('receipts go when their share row is pruned', async () => {
    const u = await makeUser('rr-prune');
    const n = await createNote(u.cookie, { views: 1, bar: true });
    expect((await openNote(n.id, n.fragment, '', { ip: '203.0.113.90' })).res.status).toBe(200);
    await runInDurableObject(dir(), async (d) => {
      expect(d.sql.exec('SELECT COUNT(*) AS c FROM opens WHERE share_id = ?', n.id).one().c).toBe(1);
      d.sql.exec("UPDATE shares SET status = 'burned', expires = 1 WHERE id = ?", n.id);
      await d.alarm();
      expect(d.sql.exec('SELECT COUNT(*) AS c FROM opens WHERE share_id = ?', n.id).one().c).toBe(0);
    });
  });
});
