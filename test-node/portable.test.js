// portable.test.js — the export document's validation (src/lib/portable.js),
// directly: per-user parts (credentials, role, API keys, passkeys, recovery
// codes), the owner's row (passkeys, recovery codes), and the import decisions (per-user action and
// parts, owner part). The Directory-side rules are covered in
// test/export-all.test.js and test/import-export.test.js.
import { describe, it, expect } from 'vitest';
import { validateExport, validateDecisions, PortableError, USER_PARTS, OWNER_PARTS, EXPORT_FORMAT } from '../src/lib/portable.js';

const key = (id, extra = {}) => ({ id, handle: 'aGFuZGxl', name: `key ${id.slice(0, 4)}`, publicKey: 'AAAA', alg: -7, signCount: 0, transports: ['internal'], backupEligible: false, backedUp: false, created: 1, lastUsed: null, ...extra });
const K1 = 'A'.repeat(22);
const K2 = 'B'.repeat(22);
const H = (c) => c.repeat(64);
const doc = () => ({
  format: EXPORT_FORMAT,
  created: 1,
  origin: 'https://bin.example',
  owner: { passkeys: { keys: [key(K1)] }, recoveryCodes: [H('d'), H('d'), H('e')] },
  users: [
    { username: 'alice', credentials: { salt: 'A'.repeat(22), t: 3, verifier: H('a'), disabled: false }, role: 'Editors', apiKeys: [], passkeys: { mfa: true, keys: [key(K2)] }, recoveryCodes: [H('b'), H('b'), H('c')] },
    { username: 'bob', role: 'Default' },
  ],
});
const bad = (mutate, re) => {
  const d = doc();
  mutate(d);
  expect(() => validateExport(d)).toThrow(PortableError);
  if (re) expect(() => validateExport(d)).toThrow(re);
};

describe('validateExport', () => {
  it('accepts the parts separately and returns a clean copy', () => {
    expect(USER_PARTS).toEqual(['credentials', 'role', 'apiKeys', 'passkeys', 'recoveryCodes']);
    expect(OWNER_PARTS).toEqual(['passkeys', 'recoveryCodes']);
    const v = validateExport(doc());
    expect(v.owner).toEqual({ passkeys: { keys: [key(K1)] }, recoveryCodes: [H('d'), H('e')] }); // de-duplicated
    expect(v.users[0].passkeys).toEqual({ mfa: true, keys: [key(K2)] });
    expect(v.users[0].recoveryCodes).toEqual([H('b'), H('c')]); // de-duplicated
    expect(v.users[0].role).toBe('Editors');
    expect(v.users[1]).toEqual({ username: 'bob', role: 'Default' });
    // A passkey may carry no handle (never registered with one).
    expect(validateExport({ ...doc(), owner: { passkeys: { keys: [key(K1, { handle: null })] } } }).owner.passkeys.keys[0].handle).toBeNull();
  });

  it('takes the user ids of the file (for the page\'s id lists) and drops them: an import never uses them', () => {
    const d = doc();
    d.owner.id = 'O'.repeat(16);
    d.users[0].id = 'A'.repeat(16);
    const v = validateExport(d);
    expect(v.owner.id).toBeUndefined();
    expect(v.users[0].id).toBeUndefined();
    expect(v.users[1]).toEqual({ username: 'bob', role: 'Default' });
    bad((x) => { x.users[0].id = 'short'; }, /users\[0\]: invalid user id/);
    bad((x) => { x.users[0].id = 7; }, /users\[0\]: invalid user id/);
    bad((x) => { x.users[0].id = 'A'.repeat(15) + '!'; }, /invalid user id/);
    bad((x) => { x.owner.id = 'O'.repeat(17); }, /owner: invalid user id/);
    // An id alone is not a part.
    bad((x) => { x.users[1] = { id: 'B'.repeat(16), username: 'bob' }; }, /nothing to import/);
    bad((x) => { x.owner = { id: 'O'.repeat(16) }; }, /owner: nothing to import/);
  });

  it('refuses the old shapes and anything malformed', () => {
    bad((d) => { d.users[1] = { username: 'bob', config: { role: 'Default' } }; }, /unexpected field "config"/);
    bad((d) => { d.users[0].passkeys.recoveryCodes = []; }, /unexpected field "recoveryCodes"/);
    bad((d) => { d.users[0].passkeys.handle = 'x'; }, /unexpected field "handle"/);
    bad((d) => { delete d.users[0].passkeys.mfa; }, /missing "mfa"/);
    bad((d) => { d.owner.passkeys.mfa = false; }, /unexpected field "mfa"/);
    bad((d) => { d.owner.recoveryCodes = ['x']; }, /owner.recoveryCodes: invalid code hash/);
    bad((d) => { d.owner.recoveryCodes = 'x'; }, /owner.recoveryCodes/);
    bad((d) => { d.owner.credentials = {}; }, /unexpected field "credentials"/);
    bad((d) => { d.owner.role = 'Default'; }, /unexpected field "role"/);
    bad((d) => { d.owner.apiKeys = []; }, /unexpected field "apiKeys"/);
    bad((d) => { d.owner = {}; }, /owner: nothing to import/);
    bad((d) => { d.users[1] = { username: 'bob' }; }, /nothing to import/);
    bad((d) => { d.users[1].role = 'owner'; }, /Owner role/);
    bad((d) => { d.users[1].role = ' '; }, /invalid role/);
    bad((d) => { d.users[0].recoveryCodes = ['x']; }, /invalid code hash/);
    bad((d) => { d.users[0].recoveryCodes = Array.from({ length: 21 }, (_, i) => i.toString(16).padStart(64, '0')); }, /at most 20/);
    bad((d) => { d.users[0].passkeys.keys = [key(K2), key(K2)]; }, /appears twice/);
    bad((d) => { d.users[0].passkeys.keys = [key(K2, { handle: 'not b64!' })]; }, /invalid user handle/);
    bad((d) => { d.users[0].passkeys.keys = [key(K2, { handle: 'A'.repeat(65) })]; }, /invalid user handle/);
    bad((d) => { d.users[0].passkeys.keys = Array.from({ length: 11 }, (_, i) => key(String(i).padStart(22, 'C'))); }, /at most 10/);
    bad((d) => { d.owner.passkeys.keys = [key('short')]; }, /invalid credential id/);
  });
});

describe('validateDecisions', () => {
  const v = validateExport(doc());
  it('defaults: create, every part in the file; the owner part only when chosen', () => {
    const d = validateDecisions({ system: false, users: { alice: {}, bob: { as: 'robert', action: 'update', parts: ['role'] } } }, v);
    expect(d.ownerParts.size).toBe(0);
    expect(d.users.get('alice')).toEqual({ as: 'alice', action: 'create', parts: new Set(['credentials', 'role', 'apiKeys', 'passkeys', 'recoveryCodes']) });
    expect(d.users.get('bob')).toEqual({ as: 'robert', action: 'update', parts: new Set(['role']) });
    expect([...validateDecisions({ system: false, owner: true, users: {} }, v).ownerParts]).toEqual(['passkeys', 'recoveryCodes']);
    expect([...validateDecisions({ system: false, owner: { passkeys: true }, users: {} }, v).ownerParts]).toEqual(['passkeys']);
    expect([...validateDecisions({ system: false, owner: { passkeys: false, recoveryCodes: true }, users: {} }, v).ownerParts]).toEqual(['recoveryCodes']);
    expect(validateDecisions({ system: false, owner: false, users: {} }, v).ownerParts.size).toBe(0);
    // Per-user parts: only those chosen, in the canonical order.
    expect([...validateDecisions({ system: false, users: { alice: { parts: ['recoveryCodes', 'credentials'] } } }, v).users.get('alice').parts]).toEqual(['credentials', 'recoveryCodes']);
  });

  it('refuses what the file lacks and malformed choices', () => {
    const no = (d, re, docIn = v) => expect(() => validateDecisions(d, docIn)).toThrow(re);
    const withoutOwner = validateExport({ ...doc(), owner: undefined });
    no({ system: false, owner: true, users: {} }, /no owner part/, withoutOwner);
    no({ system: false, owner: { passkeys: true }, users: {} }, /no "passkeys" part/, withoutOwner);
    no({ system: false, owner: { recoveryCodes: true }, users: {} }, /no "recoveryCodes" part/, withoutOwner);
    no({ system: false, owner: { recoveryCodes: true }, users: {} }, /no "recoveryCodes" part/, validateExport({ ...doc(), owner: { passkeys: { keys: [] } } }));
    no({ system: false, owner: { credentials: true }, users: {} }, /unexpected field/);
    no({ system: false, owner: 'yes', users: {} }, /decisions.owner must be/);
    no({ system: false, users: { alice: { action: 'overwrite' } } }, /action must be/);
    no({ system: false, users: { alice: { overwrite: true } } }, /unexpected field "overwrite"/);
    no({ system: false, users: { bob: { parts: ['passkeys'] } } }, /parts must be some of role/);
    no({ system: false, users: { alice: { parts: [] } } }, /nothing chosen/);
    no({ system: false, users: { alice: { as: 'carol', parts: ['role'] }, bob: { as: 'Carol' } } }, /imported as/);
    no({ system: false, users: { alice: { as: 'bad name!' } } }, /invalid target username/);
  });
});
