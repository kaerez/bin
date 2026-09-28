// setup-candidate.test.js — the set-up page's proposed Drive keys
// (POST /api/auth/setup/candidate, docs/DRIVE.md §3 "Set-up"; SECURITY.md
// "Set-up keys") in a storage of its own, before and after the owner exists:
//  - a network gets a few proposals per window (the Guard's setup-candidate
//    scope), and no proposal is written to the admin audit;
//  - the chosen pair is made in the same transaction as the owner: when the
//    keyring cannot be written, neither is the owner (the token stays
//    unspent), and a retry makes both, with exactly the pair shown;
//  - a spent setup token, or any token once the owner exists, gets no
//    proposal (410 token_used), even on an instance with no keyring.
// Synthetic data only.
import { env, runInDurableObject } from 'cloudflare:test';
import { describe, it, expect } from 'vitest';
import worker from '../src/index.js';
import { AUTHN, ORIGIN, fetchJson, intent, salt16, proofFor, freshIp } from './helpers.js';
import { dirStub } from './reverse-helpers.js';
import { SETUP_CANDIDATE } from '../src/lib/guard.js';

const errorOf = async (r) => (await r.json()).error;
const cand = (ip, token = AUTHN) => fetchJson('/api/auth/setup/candidate', { method: 'POST', headers: intent, body: { token }, ip });
const setupWith = (keys, ip) => fetchJson('/api/auth/setup', { method: 'POST', ip, body: { token: AUTHN, username: 'owner', salt: salt16(), t: 3, proof: proofFor('owner-password'), keys } });
const sql = (q, ...args) => runInDurableObject(dirStub(), (inst, state) => state.storage.sql.exec(q, ...args).toArray());
const count = async (q, ...args) => (await sql(q, ...args))[0].c;

describe('set-up proposals: rate limit, audit, atomic set-up, spent tokens', () => {
  it('a network gets SETUP_CANDIDATE.max − 1 proposals per window, then 429; none is in the admin audit', async () => {
    const ip = freshIp();
    for (let i = 0; i < SETUP_CANDIDATE.max - 1; i++) expect((await cand(ip)).status, `call ${i + 1}`).toBe(200);
    const r = await cand(ip);
    expect([r.status, await errorOf(r)]).toEqual([429, 'rate_limited']);
    // Another network is not held up; the candidates stay a single pair.
    expect((await cand(freshIp())).status).toBe(200);
    expect(await count("SELECT COUNT(*) AS c FROM mek_candidates WHERE sid = 'setup:'")).toBe(2);
    expect(await count("SELECT COUNT(*) AS c FROM activity WHERE action = 'keys.candidate'")).toBe(0);
  });

  it('the chosen pair is made with the owner, in one transaction: when the keyring cannot be written, no owner either; a retry makes both', async () => {
    const ip = freshIp();
    const p = await (await cand(ip)).json();
    // The keyring's write fails (a trigger aborts it): the set-up fails as a whole.
    await sql("CREATE TRIGGER fail_meks BEFORE INSERT ON meks BEGIN SELECT RAISE(ABORT, 'forced'); END");
    const failed = await setupWith({ mode: 'generated', root: p.root.id, sub: p.sub.id }, ip).catch((e) => e);
    expect(failed instanceof Error || failed.status >= 500).toBe(true);
    expect(await count("SELECT COUNT(*) AS c FROM users WHERE role = 'owner'")).toBe(0);
    expect(await count("SELECT COUNT(*) AS c FROM meta WHERE k LIKE 'authn_used:%' OR k = 'mek.root'")).toBe(0);
    expect((await (await fetchJson('/api/auth/setup')).json()).enabled).toBe(true);
    // The same pair still works once the store does.
    await sql('DROP TRIGGER fail_meks');
    const r = await setupWith({ mode: 'generated', root: p.root.id, sub: p.sub.id }, ip);
    expect(r.status, await r.clone().text()).toBe(200);
    expect(await r.json()).toMatchObject({ ok: true, keys: 'created' });
    const root = JSON.parse((await sql("SELECT v FROM meta WHERE k = 'mek.root'"))[0].v);
    expect(root.fp).toBe(p.root.fp);
    expect((await sql('SELECT fp FROM meks')).map((x) => x.fp)).toEqual([p.sub.fp]);
    expect(await count("SELECT COUNT(*) AS c FROM activity WHERE action = 'keys.created' AND detail LIKE '%shown and chosen%'")).toBe(1);
    expect(await count("SELECT COUNT(*) AS c FROM mek_candidates WHERE sid = 'setup:'")).toBe(0);
  });

  it('a spent token, or a new one once the owner exists, gets no proposal (410 token_used), even with no keyring', async () => {
    // An instance whose keyring was never made (set up before the Drive): the rows removed here.
    await sql("DELETE FROM meta WHERE k IN ('mek.root', 'mek.ever', 'mek.version')");
    await sql('DELETE FROM meks');
    const spent = await cand(freshIp());
    expect([spent.status, await errorOf(spent)]).toEqual([410, 'token_used']);
    const NEW = 'a-new-setup-token-for-recovery-0123456789';
    const other = await worker.fetch(new Request(`${ORIGIN}/api/auth/setup/candidate`, {
      method: 'POST', headers: { 'content-type': 'application/json', ...intent, 'cf-connecting-ip': freshIp() }, body: JSON.stringify({ token: NEW }),
    }), { ...env, AUTHN: NEW }, { waitUntil() {} });
    expect([other.status, await errorOf(other)]).toEqual([410, 'token_used']);
    expect(await count("SELECT COUNT(*) AS c FROM mek_candidates WHERE sid = 'setup:'")).toBe(0);
  });
});
