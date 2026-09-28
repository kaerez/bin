// drivekit.test.js — the Drive kits' file (public/js/drivekit.js, docs/
// DRIVE.md §3.1): one module for the personal kit (secbin-user-kit/2) and the
// key kit (secbin-key-kit/1); the kind, the account and the origin are bound
// into the AAD; the KDF is fixed; any change fails; an empty passphrase goes
// through Argon2id too; the payload's version is the kind's.
import { describe, it, expect } from 'vitest';
import { sealDriveKit, parseDriveKit, openDriveKit, KIT_FORMATS } from '../public/js/drivekit.js';

const O = 'https://bin.example';
const PAYLOAD = { user: { v: 2, userId: 'acc1', userSalt: 'x'.repeat(43), keks: [] }, key: { v: 1, ownerId: 'acc1', root: { key: 'x'.repeat(43) }, subs: [], salts: {} } };

describe('drivekit', () => {
  it('round trip for both kinds, with the exact file format', async () => {
    expect(KIT_FORMATS).toEqual({ user: 'secbin-user-kit/2', key: 'secbin-key-kit/1' });
    for (const kind of ['user', 'key']) {
      const text = await sealDriveKit(kind, PAYLOAD[kind], { accountId: 'acc1', origin: O, passphrase: 'pp' });
      const env = JSON.parse(text);
      expect(env.format).toBe(KIT_FORMATS[kind]);
      expect(Object.keys(env).sort()).toEqual(['ct', 'format', 'iv', 'm', kind === 'key' ? 'ownerId' : 'userId', 'salt', 't'].sort());
      expect(env.m).toBe(65536);
      expect(env.t).toBe(3);
      const parsed = parseDriveKit(text);
      expect(parsed.kind).toBe(kind);
      expect(await openDriveKit(parsed, { kind, accountId: 'acc1', origin: O, passphrase: 'pp' })).toEqual(PAYLOAD[kind]);
    }
  }, 30000);

  it('refuses the other kind, another account, another origin, a wrong passphrase, a change, more KDF work, an old payload', async () => {
    const text = await sealDriveKit('key', PAYLOAD.key, { accountId: 'acc1', origin: O, passphrase: '' });
    const env = parseDriveKit(text);
    await expect(openDriveKit(env, { kind: 'user', accountId: 'acc1', origin: O, passphrase: '' })).rejects.toMatchObject({ check: 'kind' });
    await expect(openDriveKit(env, { kind: 'key', accountId: 'acc2', origin: O, passphrase: '' })).rejects.toMatchObject({ check: 'owner' });
    await expect(openDriveKit(env, { kind: 'key', accountId: 'acc1', origin: 'https://other.example', passphrase: '' })).rejects.toMatchObject({ check: 'auth' });
    await expect(openDriveKit(env, { kind: 'key', accountId: 'acc1', origin: O, passphrase: 'x' })).rejects.toMatchObject({ check: 'auth' });
    expect(await openDriveKit(env, { kind: 'key', accountId: 'acc1', origin: O, passphrase: '' })).toEqual(PAYLOAD.key); // the empty passphrase
    const raw = JSON.parse(text);
    expect(() => parseDriveKit(JSON.stringify({ ...raw, t: 30 }))).toThrow(/not a Drive kit/);
    expect(() => parseDriveKit(JSON.stringify({ ...raw, extra: 1 }))).toThrow();
    expect(() => parseDriveKit(JSON.stringify({ ...raw, format: 'secbin-owner-kit/1' }))).toThrow(); // the release before's owner kit
    expect(() => parseDriveKit('not json')).toThrow();
    const iv = raw.iv.split('');
    iv[0] = iv[0] === 'A' ? 'B' : 'A';
    await expect(openDriveKit(parseDriveKit(JSON.stringify({ ...raw, iv: iv.join('') })), { kind: 'key', accountId: 'acc1', origin: O, passphrase: '' })).rejects.toMatchObject({ check: 'auth' });
    // A payload of another version is not taken.
    const old = parseDriveKit(await sealDriveKit('user', { v: 1, dk: 'x' }, { accountId: 'acc1', origin: O, passphrase: '' }));
    await expect(openDriveKit(old, { kind: 'user', accountId: 'acc1', origin: O, passphrase: '' })).rejects.toMatchObject({ check: 'payload' });
  }, 30000);
});
