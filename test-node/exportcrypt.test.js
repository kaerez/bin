// exportcrypt.test.js — the encrypted admin-export envelope: round trip with
// real Argon2id, wrong passphrase / any tampering refused, fixed KDF
// parameters (a crafted file cannot request unbounded work).
import { describe, it, expect } from 'vitest';
import { sealExport, openExport, ExportCryptError, ENVELOPE_FORMAT } from '../public/js/exportcrypt.js';

const DOC = { format: 'secbin-export/v1', created: 1, users: [{ username: 'alice', credentials: { salt: 'A'.repeat(22), t: 3, verifier: 'a'.repeat(64), disabled: false } }] };
const PASS = 'correct horse battery';

describe('export envelope', () => {
  it('round-trips and never contains the plaintext', async () => {
    const text = await sealExport(DOC, PASS);
    expect(JSON.parse(text).format).toBe(ENVELOPE_FORMAT);
    expect(text).not.toContain('alice');
    expect(await openExport(text, PASS)).toEqual(DOC);
    // NFC and NFD spellings of the passphrase are the same key.
    const t2 = await sealExport(DOC, 'café-passphrase');
    expect(await openExport(t2, 'café-passphrase')).toEqual(DOC);
  }, 60000);

  it('refuses a short passphrase, a wrong one, tampering and foreign KDF parameters', async () => {
    await expect(sealExport(DOC, 'short')).rejects.toThrow(ExportCryptError);
    const text = await sealExport(DOC, PASS);
    await expect(openExport(text, 'wrong passphrase!')).rejects.toThrow(/Wrong passphrase/);
    const env = JSON.parse(text);
    const flip = (s) => (s[5] === 'A' ? `${s.slice(0, 5)}B${s.slice(6)}` : `${s.slice(0, 5)}A${s.slice(6)}`);
    for (const mutate of [
      (e) => { e.ct = flip(e.ct); },
      (e) => { e.iv = flip(e.iv); },
      (e) => { e.kdf.salt = flip(e.kdf.salt); },
    ]) {
      const e = structuredClone(env);
      mutate(e);
      await expect(openExport(JSON.stringify(e), PASS)).rejects.toThrow(ExportCryptError);
    }
    for (const mutate of [(e) => { e.kdf.m = 1 << 30; }, (e) => { e.kdf.t = 100; }, (e) => { e.extra = 1; }, (e) => { e.format = 'x'; }]) {
      const e = structuredClone(env);
      mutate(e);
      await expect(openExport(JSON.stringify(e), PASS)).rejects.toThrow(/not a secbin export/);
    }
    await expect(openExport('not json', PASS)).rejects.toThrow(/not a secbin export/);
  }, 120000);
});
