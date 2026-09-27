// export-all.test.js — every part of an export is optional and chosen twice:
// when exporting and again when importing. Parts: settings, roles (Default +
// custom), IP rules, the panel's Turnstile keys, the public account; the
// owner's row (its passkeys and recovery codes only); per user: credentials,
// role, API keys (they keep working), passkeys (only on the same hostname) and
// recovery codes.
//
// The import rule (AGENTS.md): an existing account, the owner included, never
// has its password, recovery codes, API keys, passkeys or "Password and
// passkey" choice changed or removed; only its role is set (never the
// owner's) and the imported passkeys are added, when those parts are chosen.
import { describe, it, expect, beforeAll } from 'vitest';
import { owner, makeUser, fetchJson, freshIp, proofFor, ORIGIN, USER_PW } from './helpers.js';
import { SoftAuthenticator } from './soft-authenticator.js';
import { b64urlFromBytes, randomBytes } from '../public/js/bytes.js';

let oc;
beforeAll(async () => { oc = await owner(); });
const CURRENT = proofFor('owner-password');
const post = (path, body, cookie = oc) => fetchJson(path, { method: 'POST', body, cookie, ip: freshIp() });
const exportDoc = async (opts) => { const r = await post('/api/private/admin/export', { current: CURRENT, ...opts }); expect(r.status).toBe(200); return (await r.json()).document; };
const importDoc = (document, decisions, dryRun = true) => post('/api/private/admin/import', { current: CURRENT, document, decisions, dryRun });
const del = (id) => fetchJson(`/api/private/admin/users/${id}`, { method: 'DELETE', cookie: oc, headers: { 'x-secbin-intent': '1' } });
const login = async (username, password) => (await post('/api/auth/login', { username, proof: proofFor(password) }, undefined));
const detail = async (id) => (await fetchJson(`/api/private/admin/users/${id}`, { cookie: oc })).json();
const limits = (uid, patch) => fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: uid, channel: 'all', patch } });
const ALL = ['credentials', 'role', 'apiKeys', 'passkeys', 'recoveryCodes'];

/** Register a passkey for `cookie` (with its password) → { auth, codes }. */
async function register(cookie, password = USER_PW, name = 'Laptop') {
  const auth = new SoftAuthenticator();
  const o = await (await post('/api/private/me/passkeys/options', {}, cookie)).json();
  const r = await post('/api/private/me/passkeys', { challengeId: o.challengeId, credential: await auth.create(o.publicKey, ORIGIN), name, current: proofFor(password) }, cookie);
  expect(r.status).toBe(201);
  return { auth, codes: (await r.json()).codes };
}
/** Usernameless sign-in with `auth` → the account's username, or null. */
async function passkeyLogin(auth) {
  const o = await (await post('/api/auth/passkey/options', {}, undefined)).json();
  const r = await post('/api/auth/passkey/login', { challengeId: o.challengeId, credential: await auth.get(o.publicKey, ORIGIN) }, undefined);
  return r.status === 200 ? (await r.json()).user.username : null;
}
const recovery = async (username, code) => (await post('/api/auth/recovery', { username, code }, undefined)).status;
/** A passkey as a file holds it (the public key is never used by these tests). */
const fileKey = (name, id = b64urlFromBytes(randomBytes(32))) => ({ id, handle: null, name, publicKey: 'AAAA', alg: -7, signCount: 0, transports: [], backupEligible: false, backedUp: false, created: 1, lastUsed: null });

describe('choosing parts', () => {
  it('exports only the system parts asked for', async () => {
    const d = await exportDoc({ system: { ipRules: true, turnstile: true } });
    expect(Object.keys(d.system).sort()).toEqual(['ipRules', 'turnstile']);
    const r = await exportDoc({ system: { roles: true } });
    expect(Object.keys(r.system).sort()).toEqual(['limits', 'quotas', 'roles', 'viewerRules']);
  });

  it('imports only the system parts chosen, and refuses a part the file lacks', async () => {
    const r = await fetchJson('/api/private/admin/turnstile', { method: 'PUT', cookie: oc, body: { sitekey: '0x4AAAAAAAexportsite', secret: '0x4AAAAAAAexportsecret1', current: CURRENT } });
    expect(r.status).toBe(200);
    const doc = await exportDoc({ system: true });
    expect(doc.system.turnstile).toEqual({ sitekey: '0x4AAAAAAAexportsite', secret: '0x4AAAAAAAexportsecret1' });
    await fetchJson('/api/private/admin/turnstile', { method: 'PUT', cookie: oc, body: { clear: true, current: CURRENT } });
    const p = await (await importDoc(doc, { system: { turnstile: true }, users: {} })).json();
    expect(p.plan.system.parts).toEqual(['turnstile']);
    expect((await importDoc(doc, { system: { turnstile: true }, users: {} }, false)).status).toBe(200);
    expect(await (await fetchJson('/api/private/admin/turnstile', { cookie: oc })).json()).toMatchObject({ sitekey: '0x4AAAAAAAexportsite', secretSet: true });
    await fetchJson('/api/private/admin/turnstile', { method: 'PUT', cookie: oc, body: { clear: true, current: CURRENT } });
    const small = await exportDoc({ system: { ipRules: true } });
    expect((await importDoc(small, { system: { settings: true }, users: {} })).status).toBe(400);
  });

  it('the public account travels on its own', async () => {
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: 'public-user-0000', channel: 'all', patch: { maxViews: 4 } } });
    const doc = await exportDoc({ system: { public: true } });
    expect(doc.system.public.limits.all.maxViews).toBe(4);
    await fetchJson('/api/private/admin/limits', { method: 'PATCH', cookie: oc, body: { scope: 'public-user-0000', channel: 'all', patch: { maxViews: 9 } } });
    expect((await importDoc(doc, { system: { public: true }, users: {} }, false)).status).toBe(200);
    const d = await (await fetchJson('/api/private/admin/users/public-user-0000', { cookie: oc })).json();
    expect(d.limits.all.maxViews).toBe(4);
  });
});

describe('new accounts: created from the chosen parts', () => {
  it('keys, passkeys and recovery codes keep working after a round trip', async () => {
    const u = await makeUser('ea-full');
    await limits(u.id, { apiEnabled: true });
    const key = (await (await post('/api/private/me/keys', { name: 'cli', scopes: ['policy'], current: proofFor(USER_PW) }, u.cookie)).json()).key;
    const { auth, codes } = await register(u.cookie);
    const doc = await exportDoc({ system: { roles: true }, users: [u.id], parts: ALL });
    const e = doc.users[0];
    expect(Object.keys(e).sort()).toEqual(['apiKeys', 'credentials', 'passkeys', 'recoveryCodes', 'role', 'username']);
    expect(e.apiKeys).toHaveLength(1);
    expect(e.apiKeys[0]).toMatchObject({ name: 'cli', scopes: ['policy'] });
    expect(JSON.stringify(e)).not.toContain(key); // the hash only
    expect(Object.keys(e.passkeys).sort()).toEqual(['keys', 'mfa']);
    expect(e.passkeys.keys).toHaveLength(1);
    expect(e.passkeys.keys[0].handle).toBe(auth.userHandle); // the handle it was registered under
    expect(e.recoveryCodes).toHaveLength(20);
    expect((await del(u.id)).status).toBe(200);

    // Credentials only: no keys, no passkeys.
    const partial = await (await importDoc(doc, { system: false, users: { 'ea-full': { parts: ['credentials'] } } })).json();
    expect(partial.plan.users[0].changes).toEqual(['credentials']);
    // Everything.
    const plan = await (await importDoc(doc, { system: { roles: true }, users: { 'ea-full': {} } })).json();
    expect(plan.plan.errors).toEqual([]);
    expect(plan.plan.users[0].changes).toEqual(['credentials', `role user ${u.id}`, '1 API key', '1 passkey ("Laptop")', '20 recovery codes']);
    expect(plan.plan.warnings.join(' ')).toMatch(/API key will work here/);
    expect((await importDoc(doc, { system: { roles: true }, users: { 'ea-full': {} } }, false)).status).toBe(200);
    expect((await fetchJson('/api/private/policy', { headers: { authorization: `Bearer ${key}` } })).status).toBe(200);
    expect(await passkeyLogin(auth)).toBe('ea-full');
    expect(await recovery('ea-full', codes[0])).toBe(200);
    expect((await login('ea-full', USER_PW)).status).toBe(200);
    const audit = (await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json()).rows;
    expect(audit.some((r) => r.action === 'user.imported' && r.detail === `create: role=user ${u.id} apiKeys=1 passkeys+1 recoveryCodes=20`)).toBe(true);
    expect(audit.some((r) => r.action === 'passkeys.imported' && r.detail === 'import: added 1: Laptop')).toBe(true);
    expect(JSON.stringify(audit)).not.toMatch(new RegExp(`${e.recoveryCodes[0]}|${e.credentials.verifier}|${e.apiKeys[0].hash}`)); // never secrets
  });

  it('passkeys and recovery codes are separate parts, chosen per user', async () => {
    const a = await makeUser('ea-sep-a');
    const b = await makeUser('ea-sep-b');
    const ra = await register(a.cookie);
    const rb = await register(b.cookie);
    // "Password and passkey" on for b.
    expect((await post('/api/private/me/second-factor', { on: true, current: proofFor(USER_PW) }, b.cookie)).status).toBe(200);
    const doc = await exportDoc({ users: [a.id, b.id], parts: ALL });
    await del(a.id);
    await del(b.id);
    // a: credentials + recovery codes (no passkeys); b: credentials + passkeys (no codes).
    const dec = { system: false, users: { 'ea-sep-a': { parts: ['credentials', 'recoveryCodes'] }, 'ea-sep-b': { parts: ['credentials', 'passkeys'] } } };
    const plan = (await (await importDoc(doc, dec)).json()).plan;
    expect(plan.users.find((x) => x.username === 'ea-sep-a').changes).toEqual(['credentials', '20 recovery codes']);
    expect(plan.users.find((x) => x.username === 'ea-sep-b').changes).toEqual(['credentials', '1 passkey ("Laptop"), "Password and passkey" on']);
    expect((await importDoc(doc, dec, false)).status).toBe(200);
    expect(await recovery('ea-sep-a', ra.codes[0])).toBe(200);
    expect(await passkeyLogin(ra.auth)).toBeNull(); // not imported
    expect(await recovery('ea-sep-b', rb.codes[0])).toBe(401); // not imported
    expect(await passkeyLogin(rb.auth)).toBe('ea-sep-b');
    // b's choice came with it: the password alone is not enough.
    const pw = await (await login('ea-sep-b', USER_PW)).json();
    expect(pw.secondFactor).toBeTruthy();
    expect((await detail(await idOf('ea-sep-b'))).passkeys).toMatchObject({ count: 1, recoveryLeft: 0, mfa: true });
    expect((await detail(await idOf('ea-sep-a'))).passkeys).toMatchObject({ count: 0, recoveryLeft: 19, mfa: false }); // one code spent above
  });

  it('a new account gets only as many passkeys as its role allows; recovery codes held elsewhere are skipped', async () => {
    const u = await makeUser('ea-cap-src');
    await limits(u.id, { passkeysMax: 2 });
    const { codes } = await register(u.cookie);
    const doc = await exportDoc({ users: [u.id], parts: ALL });
    doc.users[0].passkeys.keys.push(fileKey('Two'), fileKey('Three'));
    // Imported under another name while the original still exists.
    const dec = { system: false, users: { 'ea-cap-src': { as: 'ea-cap-new', parts: ['credentials', 'role', 'passkeys', 'recoveryCodes'] } } };
    const plan = (await (await importDoc(doc, dec)).json()).plan;
    expect(plan.errors).toEqual([]);
    const e = plan.users[0];
    expect(e.changes).toEqual(['credentials', `role user ${u.id}`, '2 passkeys ("Two", "Three")', '0 recovery codes']);
    expect(e.skipped).toEqual([
      'passkey "Laptop": already registered to another account here (a passkey belongs to one account)',
      '20 recovery codes: already belong to another account here',
    ]);
    doc.users[0].passkeys.keys.push(fileKey('Four'));
    const p2 = (await (await importDoc(doc, dec)).json()).plan;
    expect(p2.users[0].skipped).toContain('passkey "Four": does not fit (this account can have up to 2 passkeys)');
    expect((await importDoc(doc, dec, false)).status).toBe(200);
    expect((await detail(await idOf('ea-cap-new'))).passkeys).toMatchObject({ count: 2, recoveryLeft: 0 });
    expect(await recovery('ea-cap-src', codes[0])).toBe(200); // still the original's
  });

  it('refuses API keys that belong to another account here; warns about another hostname', async () => {
    const a = await makeUser('ea-a');
    await limits(a.id, { apiEnabled: true });
    await post('/api/private/me/keys', { name: 'k', current: proofFor(USER_PW) }, a.cookie);
    const doc = await exportDoc({ users: [a.id], parts: ['credentials', 'apiKeys', 'passkeys'] });
    doc.users[0].username = 'ea-b';
    const p = await (await importDoc(doc, { system: false, users: { 'ea-b': {} } })).json();
    expect(p.plan.errors.join(' ')).toMatch(/already belongs to another account/);
    doc.origin = 'https://elsewhere.example';
    doc.users[0].apiKeys = [];
    doc.users[0].passkeys.keys = [fileKey('x')];
    const w = await (await importDoc(doc, { system: false, users: { 'ea-b': {} } })).json();
    expect(w.plan.errors).toEqual([]);
    expect(w.plan.warnings.join(' ')).toMatch(/"ea-b": passkeys were registered for elsewhere.example and will not work on secbin.test \(recovery codes do\)/);
  });
});

const idOf = async (name) => (await (await fetchJson('/api/private/admin/users', { cookie: oc })).json()).users.find((u) => u.username === name)?.id;

describe('existing accounts: only the role and added passkeys', () => {
  it('never changes the password, recovery codes, API keys, passkeys or second-step choice; adds passkeys and sets the role', async () => {
    // The file: "ea-src" with its own password, passkey, recovery codes, API key, "Password and passkey" on.
    const src = await makeUser('ea-src', 'source-password-1');
    await limits(src.id, { apiEnabled: true });
    await post('/api/private/me/keys', { name: 'src-key', current: proofFor('source-password-1') }, src.cookie);
    const s = await register(src.cookie, 'source-password-1', 'Source key');
    expect((await post('/api/private/me/second-factor', { on: true, current: proofFor('source-password-1') }, src.cookie)).status).toBe(200);
    const doc = await exportDoc({ system: { roles: true }, users: [src.id], parts: ALL });
    await del(src.id); // its passkey is free to move

    // The target: "ea-dst" with a password, a passkey (its own user handle), codes, a key.
    const dst = await makeUser('ea-dst', 'target-password-1');
    await limits(dst.id, { apiEnabled: true });
    const dstKey = (await (await post('/api/private/me/keys', { name: 'dst-key', current: proofFor('target-password-1') }, dst.cookie)).json()).key;
    const t = await register(dst.cookie, 'target-password-1', 'Target key');
    expect(t.auth.userHandle).not.toBe(s.auth.userHandle);
    const before = await detail(dst.id);
    const snapshot = async () => (await exportDoc({ users: [dst.id], parts: ['credentials', 'apiKeys', 'passkeys', 'recoveryCodes'] })).users[0];
    const was = await snapshot();

    const dec = { system: { roles: true }, users: { 'ea-src': { as: 'ea-dst', action: 'update' } } };
    const plan = (await (await importDoc(doc, dec)).json()).plan;
    expect(plan.errors).toEqual([]);
    expect(plan.users[0]).toMatchObject({ username: 'ea-src', as: 'ea-dst', action: 'update', role: `user ${src.id}` });
    expect(plan.users[0].changes).toEqual([`role user ${dst.id} → user ${src.id}`, 'adds 1 passkey ("Source key"); its passkeys stay']);
    expect(plan.users[0].skipped).toEqual([
      'password and disabled flag: an existing account keeps its own',
      'API keys: an existing account keeps its own',
      'recovery codes: an existing account keeps its own',
      '"Password and passkey" choice: an existing account keeps its own',
    ]);
    expect((await importDoc(doc, dec, false)).status).toBe(200);

    const after = await detail(dst.id);
    expect(after.role.name).toBe(`user ${src.id}`);
    // Byte for byte: the same password verifier, API keys and recovery codes; its passkey kept, one added.
    const now = await snapshot();
    expect(now.credentials).toEqual(was.credentials);
    expect(now.apiKeys).toEqual(was.apiKeys);
    expect(now.recoveryCodes).toEqual(was.recoveryCodes);
    expect(now.recoveryCodes.some((h) => doc.users[0].recoveryCodes.includes(h))).toBe(false);
    expect(now.passkeys.mfa).toBe(was.passkeys.mfa);
    expect(now.passkeys.keys.filter((k) => was.passkeys.keys.some((w) => w.id === k.id))).toEqual(was.passkeys.keys);
    expect(now.passkeys.keys.map((k) => k.id).sort()).toEqual([...was.passkeys.keys.map((k) => k.id), s.auth.id].sort());
    expect(after.passkeys).toEqual({ count: 2, recoveryLeft: before.passkeys.recoveryLeft, mfa: false });
    expect(after.keys.map((k) => k.name)).toEqual(['dst-key']);
    expect((await fetchJson('/api/private/me', { cookie: dst.cookie })).status).toBe(200); // sessions stay
    expect((await login('ea-dst', 'target-password-1')).status).toBe(200); // password alone, as before
    expect((await login('ea-dst', 'source-password-1')).status).toBe(401);
    expect(await recovery('ea-dst', s.codes[0])).toBe(401); // the file's codes were not taken
    expect(await recovery('ea-dst', t.codes[0])).toBe(200); // its own still work
    expect((await fetchJson('/api/private/policy', { headers: { authorization: `Bearer ${dstKey}` } })).status).toBe(200);
    // Both passkeys sign in to the account, each checked against the user handle it was registered under.
    expect(await passkeyLogin(t.auth)).toBe('ea-dst');
    expect(await passkeyLogin(s.auth)).toBe('ea-dst');
    // Exporting the account again keeps each passkey's own handle.
    const again = await exportDoc({ users: [dst.id], parts: ['passkeys'] });
    expect(again.users[0].passkeys.keys.map((k) => k.handle).sort()).toEqual([s.auth.userHandle, t.auth.userHandle].sort());
    const audit = (await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json()).rows;
    expect(audit.some((r) => r.action === 'user.imported' && r.detail === `update from=ea-src: role=user ${src.id} passkeys+1; skipped 4`)).toBe(true);
  });

  it('without the role part only passkeys are added; without the passkeys part only the role is set', async () => {
    const x = await makeUser('ea-part-x');
    const y = await makeUser('ea-part-y');
    await limits(y.id, { maxViews: 5 }); // y's own role
    const doc = await exportDoc({ users: [y.id], parts: ['role', 'passkeys'] });
    doc.users[0].passkeys.keys = [fileKey('Added')];
    const roleOnly = { system: false, users: { 'ea-part-y': { as: 'ea-part-x', action: 'update', parts: ['role'] } } };
    const p1 = (await (await importDoc(doc, roleOnly)).json()).plan.users[0];
    expect(p1.changes).toEqual([`role Default → user ${y.id}`]);
    expect(p1.skipped).toEqual([]);
    expect((await importDoc(doc, roleOnly, false)).status).toBe(200);
    expect((await detail(x.id)).passkeys.count).toBe(0);
    expect((await detail(x.id)).role.name).toBe(`user ${y.id}`);
    const keysOnly = { system: false, users: { 'ea-part-y': { as: 'ea-part-x', action: 'update', parts: ['passkeys'] } } };
    expect((await importDoc(doc, keysOnly, false)).status).toBe(200);
    const d = await detail(x.id);
    expect(d.passkeys.count).toBe(1);
    expect(d.role.name).toBe(`user ${y.id}`);
    // Again: the passkey is already this account's — skipped, not an error.
    const p3 = (await (await importDoc(doc, keysOnly)).json()).plan;
    expect(p3.errors).toEqual([]);
    expect(p3.users[0].changes).toEqual([]);
    expect(p3.users[0].skipped).toContain('passkey "Added": already registered to this account');
  });

  it('duplicate credential ids are skipped: on this account, on another account, twice in the file', async () => {
    const a = await makeUser('ea-dup-a');
    const b = await makeUser('ea-dup-b');
    const ra = await register(a.cookie, USER_PW, 'A key');
    const shared = fileKey('Shared');
    const doc = await exportDoc({ users: [a.id, b.id], parts: ['passkeys'] });
    const ea = doc.users.find((u) => u.username === 'ea-dup-a');
    const eb = doc.users.find((u) => u.username === 'ea-dup-b');
    ea.passkeys.keys.push(shared);
    eb.passkeys.keys = [{ ...ea.passkeys.keys[0], name: 'A key copy' }, shared];
    const dec = { system: false, users: { 'ea-dup-a': { action: 'update' }, 'ea-dup-b': { action: 'update' } } };
    const plan = (await (await importDoc(doc, dec)).json()).plan;
    expect(plan.errors).toEqual([]);
    const pa = plan.users.find((u) => u.username === 'ea-dup-a');
    const pb = plan.users.find((u) => u.username === 'ea-dup-b');
    expect(pa.changes).toEqual(['adds 1 passkey ("Shared"); its passkeys stay']);
    expect(pa.skipped).toContain('passkey "A key": already registered to this account');
    expect(pb.changes).toEqual([]);
    expect(pb.skipped).toEqual(expect.arrayContaining([
      'passkey "A key copy": already registered to another account here (a passkey belongs to one account)',
      'passkey "Shared": already taken by another account in this import',
    ]));
    expect((await importDoc(doc, dec, false)).status).toBe(200);
    expect((await detail(a.id)).passkeys.count).toBe(2);
    expect((await detail(b.id)).passkeys.count).toBe(0);
    expect(await passkeyLogin(ra.auth)).toBe('ea-dup-a');
  });

  it('respects the passkey limit of the account\'s role: what does not fit is listed and skipped', async () => {
    const u = await makeUser('ea-limit');
    await limits(u.id, { passkeysMax: 2 });
    await register(u.cookie, USER_PW, 'Mine');
    const doc = await exportDoc({ users: [u.id], parts: ['passkeys'] });
    doc.users[0].passkeys.keys = [fileKey('One'), fileKey('Two'), fileKey('Three')];
    const dec = { system: false, users: { 'ea-limit': { action: 'update' } } };
    const plan = (await (await importDoc(doc, dec)).json()).plan;
    expect(plan.errors).toEqual([]);
    expect(plan.users[0].changes).toEqual(['adds 1 passkey ("One"); its passkeys stay']);
    expect(plan.users[0].skipped).toEqual([
      'passkey "Two": does not fit (this account can have up to 2 passkeys)',
      'passkey "Three": does not fit (this account can have up to 2 passkeys)',
      '"Password and passkey" choice: an existing account keeps its own',
    ]);
    expect((await importDoc(doc, dec, false)).status).toBe(200);
    expect((await detail(u.id)).passkeys.count).toBe(2);
  });
});

describe('the owner', () => {
  it('its row exports only its passkeys and/or recovery codes, each chosen separately (never its password, role or API keys)', async () => {
    await register(oc, 'owner-password', 'Owner row key');
    const pk = await exportDoc({ owner: ['passkeys'], users: [] });
    expect(Object.keys(pk.owner)).toEqual(['passkeys']);
    expect(Object.keys(pk.owner.passkeys)).toEqual(['keys']); // its "Password and passkey" choice never travels
    expect(pk.owner.passkeys.keys.map((k) => k.name)).toContain('Owner row key');
    const rc = await exportDoc({ owner: ['recoveryCodes'], users: [] });
    expect(Object.keys(rc.owner)).toEqual(['recoveryCodes']);
    const left = (await (await fetchJson('/api/private/me/passkeys', { cookie: oc })).json()).recoveryLeft;
    expect(rc.owner.recoveryCodes).toHaveLength(left);
    expect(rc.owner.recoveryCodes.every((h) => /^[0-9a-f]{64}$/.test(h))).toBe(true); // hashes only
    const both = await exportDoc({ owner: ['passkeys', 'recoveryCodes', 'credentials', 'role', 'apiKeys'], users: [] });
    expect(Object.keys(both.owner)).toEqual(['passkeys', 'recoveryCodes']);
    expect(JSON.stringify(both)).not.toMatch(/verifier|salt|apiKeys|"role"/);
    expect((await exportDoc({ users: [] })).owner).toBeUndefined(); // off unless asked
    expect((await exportDoc({ owner: [], users: [] })).owner).toBeUndefined();
    const audit = (await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json()).rows;
    expect(audit.some((r) => r.action === 'export.created' && new RegExp(`owner=passkeys\\(\\d+\\)\\+recoveryCodes\\(${left}\\)`).test(r.detail))).toBe(true);
  });

  it('the owner gets passkeys added only: its password, recovery codes, passkeys and second-step choice stay', async () => {
    const one = await register(oc, 'owner-password', 'Owner one');
    const two = await register(oc, 'owner-password', 'Owner two');
    const old = await (await post('/api/private/me/recovery-codes', { current: CURRENT })).json();
    expect(old.codes).toHaveLength(20);
    const doc = await exportDoc({ owner: ['passkeys', 'recoveryCodes'], users: [] });
    expect(doc.owner.passkeys.keys.map((k) => k.name)).toEqual(expect.arrayContaining(['Owner one', 'Owner two']));

    // Remove "Owner two" and get new recovery codes: the file's codes are not the owner's any more.
    const rm = await post(`/api/private/me/passkeys/${two.auth.id}/remove`, { current: CURRENT });
    expect(rm.status).toBe(200);
    expect(await passkeyLogin(two.auth)).toBeNull();
    const fresh = await (await post('/api/private/me/recovery-codes', { current: CURRENT })).json();
    expect(fresh.codes).toHaveLength(20);
    const before = await (await fetchJson('/api/private/me/passkeys', { cookie: oc })).json();
    const beforeIds = before.passkeys.map((k) => k.id).sort();
    const hashesBefore = (await exportDoc({ owner: ['recoveryCodes'], users: [] })).owner.recoveryCodes;
    expect(hashesBefore.some((h) => doc.owner.recoveryCodes.includes(h))).toBe(false);

    const dec = { system: false, owner: { passkeys: true, recoveryCodes: true }, users: {} };
    const plan = (await (await importDoc(doc, dec)).json()).plan;
    expect(plan.errors).toEqual([]);
    expect(plan.owner.as).toBe('owner');
    expect(plan.owner.changes).toEqual(['adds 1 passkey ("Owner two"); your passkeys, password and recovery codes stay']);
    expect(plan.owner.skipped).toContain('passkey "Owner one": already registered to this account');
    expect(plan.owner.skipped).toContain('recovery codes: an existing account keeps its own');
    expect((await importDoc(doc, dec, false)).status).toBe(200);

    // Passkeys: added, none removed.
    const after = await (await fetchJson('/api/private/me/passkeys', { cookie: oc })).json();
    expect(after.passkeys.map((k) => k.id).sort()).toEqual([...beforeIds, two.auth.id].sort());
    expect(await passkeyLogin(two.auth)).toBe('owner');
    expect(await passkeyLogin(one.auth)).toBe('owner');
    // Recovery codes: exactly the owner's own, untouched; the file's do not work.
    expect((await exportDoc({ owner: ['recoveryCodes'], users: [] })).owner.recoveryCodes).toEqual(hashesBefore);
    expect(after.recoveryLeft).toBe(before.recoveryLeft);
    expect(after.mfa).toBe(before.mfa);
    expect(await recovery('owner', old.codes[0])).toBe(401);
    expect(await recovery('owner', fresh.codes[0])).toBe(200);
    // Password and role: unchanged.
    expect((await login('owner', 'owner-password')).status).toBe(200);
    expect((await (await fetchJson('/api/private/me', { cookie: oc })).json()).user.role).toBe('owner');
    const audit = (await (await fetchJson('/api/private/admin/audit', { cookie: oc })).json()).rows;
    expect(audit.some((r) => r.action === 'passkeys.imported' && r.detail === 'import (owner passkeys): added 1: Owner two')).toBe(true);
    expect(audit.some((r) => r.action === 'user.imported' && /^owner: passkeys\+1; skipped \d+$/.test(r.detail))).toBe(true);
    expect(audit.some((r) => r.action === 'recovery.imported')).toBe(false);
  });

  it('the owner row with only recovery codes chosen changes nothing', async () => {
    const doc = await exportDoc({ owner: ['recoveryCodes'], users: [] });
    doc.owner.recoveryCodes = ['0'.repeat(64), '1'.repeat(64)]; // codes the owner does not have
    const before = (await exportDoc({ owner: ['recoveryCodes'], users: [] })).owner.recoveryCodes;
    const dec = { system: false, owner: { recoveryCodes: true }, users: {} };
    const plan = (await (await importDoc(doc, dec)).json()).plan;
    expect(plan.errors).toEqual([]);
    expect(plan.owner).toEqual({ as: 'owner', changes: [], skipped: ['recovery codes: an existing account keeps its own'] });
    expect((await importDoc(doc, dec, false)).status).toBe(200);
    expect((await exportDoc({ owner: ['recoveryCodes'], users: [] })).owner.recoveryCodes).toEqual(before);
    // A file without an owner row cannot be imported onto the owner.
    expect((await importDoc({ ...doc, owner: undefined }, dec)).status).toBe(400);
    expect((await importDoc(doc, { system: false, owner: { passkeys: true }, users: {} })).status).toBe(400); // not in the file
  });

  it('a user entry imported onto the owner never sets its role or password; it can add passkeys', async () => {
    const u = await makeUser('ea-to-owner');
    await limits(u.id, { maxViews: 2 });
    const doc = await exportDoc({ users: [u.id], parts: ALL });
    doc.users[0].passkeys.keys = [fileKey('From a user')];
    const dec = { system: false, users: { 'ea-to-owner': { as: 'owner', action: 'update' } } };
    const plan = (await (await importDoc(doc, dec)).json()).plan;
    expect(plan.errors).toEqual([]);
    expect(plan.users[0]).toMatchObject({ action: 'update', owner: true, changes: ['adds 1 passkey ("From a user"); its passkeys stay'] });
    expect(plan.users[0].skipped).toEqual(expect.arrayContaining([
      'password and disabled flag: an existing account keeps its own',
      'recovery codes: an existing account keeps its own',
      'role: the owner always has the Owner role',
    ]));
    // Even a role that does not exist here is no problem: it is not applied.
    doc.users[0].role = 'Nowhere';
    expect((await (await importDoc(doc, dec)).json()).plan.errors).toEqual([]);
    expect((await importDoc(doc, dec, false)).status).toBe(200);
    const me = await (await fetchJson('/api/private/me', { cookie: oc })).json();
    expect(me.user.role).toBe('owner');
    expect((await login('owner', 'owner-password')).status).toBe(200);
    expect((await login('owner', USER_PW)).status).toBe(401);
  });
});

describe('validation', () => {
  it('validates the new parts', async () => {
    const u = await makeUser('ea-val');
    const base = await exportDoc({ users: [u.id], parts: ALL });
    const key = fileKey('x');
    for (const [i, mutate] of [
      (d) => { d.users[0].apiKeys = [{ hash: 'zz', name: 'k', created: 1, expires: null, lastUsed: null, scopes: ['notes'] }]; },
      (d) => { d.users[0].apiKeys = [{ hash: 'a'.repeat(64), name: 'k', created: 1, expires: null, lastUsed: null, scopes: ['admin'] }]; },
      (d) => { d.users[0].recoveryCodes = ['nope']; },
      (d) => { d.users[0].recoveryCodes = Array.from({ length: 21 }, (_, j) => j.toString(16).padStart(64, '0')); },
      (d) => { d.users[0].passkeys.recoveryCodes = []; }, // the combined part is gone
      (d) => { d.users[0].passkeys.handle = null; }, // handles are per passkey
      (d) => { d.users[0].passkeys = { keys: [] }; }, // a user's passkeys carry the second-step choice
      (d) => { d.users[0].passkeys.keys = [{ ...key, id: 'short' }]; },
      (d) => { d.users[0].passkeys.keys = [{ ...key, alg: 1 }]; },
      (d) => { d.users[0].passkeys.keys = [{ ...key, handle: 'bad handle' }]; },
      (d) => { const { handle, ...rest } = key; d.users[0].passkeys.keys = [rest]; expect(handle).toBeNull(); },
      (d) => { d.users[0].passkeys.keys = [key, key]; },
      (d) => { d.users[0].passkeys.keys = Array.from({ length: 11 }, (_, j) => fileKey(`k${j}`)); },
      (d) => { d.owner = { passkeys: { mfa: true, keys: [] } }; }, // the owner's choice never travels
      (d) => { d.owner = { passkeys: { keys: [{ ...key, publicKey: '!!' }] } }; },
      (d) => { d.system = { turnstile: { sitekey: 'bad key', secret: 'x' } }; },
      (d) => { d.system = { limits: { all: {}, api: {} } }; }, // the Default role goes as a whole
    ].entries()) {
      const d = structuredClone(base);
      mutate(d);
      expect([i, (await importDoc(d, { system: false, users: {} })).status]).toEqual([i, 400]);
    }
    const noParts = await exportDoc({ users: [u.id], parts: ['credentials'] });
    expect((await importDoc(noParts, { system: false, users: { 'ea-val': { parts: ['role'] } } })).status).toBe(400); // not in the file
    expect((await importDoc(base, { system: false, users: { 'ea-val': { parts: [] } } })).status).toBe(400);
    expect((await importDoc(base, { system: false, users: { 'ea-val': { parts: ['config'] } } })).status).toBe(400);
  });
});
