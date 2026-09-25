// password-policy.test.js — the admin sets the password policy globally and
// per user (pw* limits); /me hands it to the browser, which enforces it. The
// owner always gets the built-in policy.
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson } from './helpers.js';

let oc;
beforeAll(async () => { oc = await owner(); });
const limits = (scope, patch) => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope, channel: 'all', patch } });
const policy = async (cookie) => (await (await fetchJson('/api/private/me', { cookie })).json()).passwordPolicy;

describe('password policy', () => {
  it('global default, per-user override, owner exempt, validated', async () => {
    const u = await makeUser('pp-user');
    const v = await makeUser('pp-other');
    expect(await policy(u.cookie)).toEqual({ pwMinLength: 12, pwUpper: false, pwLower: false, pwDigit: false, pwSymbol: false });
    expect((await limits('global', { pwMinLength: 16, pwDigit: true })).status).toBe(200);
    expect(await policy(u.cookie)).toMatchObject({ pwMinLength: 16, pwDigit: true });
    expect((await limits(v.id, { pwMinLength: 20, pwSymbol: true })).status).toBe(200);
    expect(await policy(v.cookie)).toMatchObject({ pwMinLength: 20, pwDigit: true, pwSymbol: true });
    expect(await policy(oc)).toEqual({ pwMinLength: 12, pwUpper: false, pwLower: false, pwDigit: false, pwSymbol: false });
    for (const bad of [{ pwMinLength: 11 }, { pwMinLength: 129 }, { pwMinLength: null }, { pwUpper: 'yes' }]) {
      expect((await limits('global', bad)).status).toBe(400);
    }
    expect((await limits('global', { pwMinLength: 'inherit', pwDigit: 'inherit' })).status).toBe(200);
  });
});
