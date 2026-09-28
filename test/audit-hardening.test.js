// audit-hardening.test.js — regression tests for findings of the security
// audit: the account lockout no longer reveals which usernames exist (unknown
// names lock the same way); an IP block rule cannot lock out the owner adding
// it; the public profile answers "off" without the Directory when disabled.
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, freshIp, proofFor, OWNER_STEP } from './helpers.js';
import { invalidateGuardCaches } from '../src/lib/guard.js';

let oc;
beforeAll(async () => { oc = await owner(); });
const settings = (patch) => fetchJson('/api/private/admin/settings', { method: 'PATCH', cookie: oc, body: { ...patch, ...OWNER_STEP } });
const login = (username, pw) => fetchJson('/api/auth/login', { method: 'POST', ip: freshIp(), body: { username, proof: proofFor(pw) } });
const recovery = (username) => fetchJson('/api/auth/recovery', { method: 'POST', ip: freshIp(), body: { username, code: 'AAAA-BBBB-CCCC-DDDD' } });

describe('account lockout and username enumeration', () => {
  it('locks an unknown username exactly like a real one', async () => {
    expect((await settings({ 'lockout.max': 3, 'lockout.windowSec': 600, 'lockout.lockSec': 600 })).status).toBe(200);
    invalidateGuardCaches();
    await makeUser('enum-real', 'enum-real-password');
    const statuses = async (name) => { const out = []; for (let i = 0; i < 4; i++) out.push((await login(name, 'wrong-password')).status); return out; };
    const real = await statuses('enum-real');
    const ghost = await statuses('enum-nobody');
    expect(real).toEqual([401, 401, 401, 423]);
    expect(ghost).toEqual(real);
    // Case does not matter for the unknown name either (like usernames).
    expect((await login('ENUM-NOBODY', 'x')).status).toBe(423);
    // Recovery-code logins share the same counter and answers.
    expect((await recovery('enum-nobody')).status).toBe(423);
    expect((await recovery('enum-real')).status).toBe(423);
    // Error bodies are the same shape.
    const a = await (await login('enum-real', 'x')).json();
    const b = await (await login('enum-nobody', 'x')).json();
    expect(Object.keys(a).sort()).toEqual(Object.keys(b).sort());
    expect(a.error).toBe(b.error);
    await settings({ 'lockout.max': 10, 'lockout.windowSec': 600, 'lockout.lockSec': 900 });
    invalidateGuardCaches();
  });
});

describe('IP rules', () => {
  it('refuse a block rule covering the owner adding it, unless an allow rule covers them', async () => {
    const add = (cidr, action, ip) => fetchJson('/api/private/admin/ip-rules', { method: 'POST', cookie: oc, ip, body: { cidr, action, ...OWNER_STEP } });
    const r = await add('192.0.2.0/24', 'block', '192.0.2.77');
    expect(r.status).toBe(409);
    expect((await r.json()).error).toBe('blocks_yourself');
    expect((await add('192.0.2.77', 'allow', '192.0.2.77')).status).toBe(201);
    expect((await add('192.0.2.0/24', 'block', '192.0.2.77')).status).toBe(201);
    // A block that does not cover the caller is unaffected.
    expect((await add('198.18.0.0/15', 'block', '192.0.2.77')).status).toBe(201);
    const rules = (await (await fetchJson('/api/private/admin/ip-rules', { cookie: oc, ip: '192.0.2.77' })).json()).rules;
    for (const x of rules.filter((y) => ['192.0.2.0/24', '192.0.2.77/32', '192.0.2.77', '198.18.0.0/15'].includes(y.cidr))) {
      await fetchJson(`/api/private/admin/ip-rules/${x.id}`, { method: 'DELETE', cookie: oc, ip: '192.0.2.77', headers: { 'x-secbin-intent': '1' } });
    }
    invalidateGuardCaches();
  });
});

describe('public profile', () => {
  it('answers "off" when public sharing is disabled', async () => {
    expect(await (await fetchJson('/api/public/profile')).json()).toEqual({ enabled: false });
  });
});
