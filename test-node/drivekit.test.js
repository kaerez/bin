// drivekit.test.js — the Drive recovery kit's file (public/js/drivekit.js,
// docs/DRIVE.md §3): one module for the owner kit and (later) the user kit;
// the kind, the account and the origin are bound into the AAD; the KDF is
// fixed; any change fails; an empty passphrase goes through Argon2id too.
import { describe, it, expect } from 'vitest';
import { sealDriveKit, parseDriveKit, openDriveKit, KIT_FORMATS, kitKindFor } from '../public/js/drivekit.js';

const O = 'https://bin.example';
const P = { v: 1, dk: 'x'.repeat(43) };

describe('drivekit', () => {
  it('round trip for both kinds, with the exact file format', async () => {
    for (const kind of ['owner', 'user']) {
      const text = await sealDriveKit(kind, P, { accountId: 'acc1', origin: O, passphrase: 'pp' });
      const env = JSON.parse(text);
      expect(env.format).toBe(KIT_FORMATS[kind]);
      expect(Object.keys(env).sort()).toEqual(['ct', 'format', 'iv', 'm', kind === 'owner' ? 'ownerId' : 'userId', 'salt', 't'].sort());
      expect(env.m).toBe(65536);
      expect(env.t).toBe(3);
      const parsed = parseDriveKit(text);
      expect(parsed.kind).toBe(kind);
      expect(await openDriveKit(parsed, { kind, accountId: 'acc1', origin: O, passphrase: 'pp' })).toEqual(P);
    }
    expect(kitKindFor('owner')).toBe('owner');
    expect(kitKindFor('user')).toBe('user');
  }, 30000);

  it('refuses the other kind, another account, another origin, a wrong passphrase, a change, more KDF work', async () => {
    const text = await sealDriveKit('owner', P, { accountId: 'acc1', origin: O, passphrase: '' });
    const env = parseDriveKit(text);
    await expect(openDriveKit(env, { kind: 'user', accountId: 'acc1', origin: O, passphrase: '' })).rejects.toMatchObject({ check: 'kind' });
    await expect(openDriveKit(env, { kind: 'owner', accountId: 'acc2', origin: O, passphrase: '' })).rejects.toMatchObject({ check: 'owner' });
    await expect(openDriveKit(env, { kind: 'owner', accountId: 'acc1', origin: 'https://other.example', passphrase: '' })).rejects.toMatchObject({ check: 'auth' });
    await expect(openDriveKit(env, { kind: 'owner', accountId: 'acc1', origin: O, passphrase: 'x' })).rejects.toMatchObject({ check: 'auth' });
    expect(await openDriveKit(env, { kind: 'owner', accountId: 'acc1', origin: O, passphrase: '' })).toEqual(P); // the empty passphrase
    const raw = JSON.parse(text);
    expect(() => parseDriveKit(JSON.stringify({ ...raw, t: 30 }))).toThrow(/not a Drive recovery kit/);
    expect(() => parseDriveKit(JSON.stringify({ ...raw, extra: 1 }))).toThrow();
    expect(() => parseDriveKit('not json')).toThrow();
    const iv = raw.iv.split('');
    iv[0] = iv[0] === 'A' ? 'B' : 'A';
    await expect(openDriveKit(parseDriveKit(JSON.stringify({ ...raw, iv: iv.join('') })), { kind: 'owner', accountId: 'acc1', origin: O, passphrase: '' })).rejects.toMatchObject({ check: 'auth' });
  }, 30000);
});
