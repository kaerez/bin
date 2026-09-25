// read-receipts.test.js — every open is recorded; the sender always sees the
// time, and only the details the admin allows (receipt* limits); the admin
// sees everything; receipts follow the log's retention and clearing.
import { describe, it, expect, beforeAll } from 'vitest';
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
