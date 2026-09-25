// vectors.test.js — the frozen protocol-v2 vectors (test/genvectors.mjs), run
// in PLAIN NODE against the VENDORED modules. The pinned values are identical
// to test-node/crypto.test.js; passing here proves the shipped copies (incl.
// the vendored hash-wasm Argon2id) reproduce the protocol byte-for-byte in
// Node, so the CLI is a conforming second client. Round trips additionally
// exercise Node's CompressionStream and the server-side proof check.
import { describe, it, expect } from 'vitest';
import {
  encryptPaste, deriveAccess, openPaste, keySchedule, aesGcmEncrypt, aesGcmDecrypt, proofHash,
  PasswordRequired,
} from '../vendor/crypto.js';
import { argon2idRaw } from '../vendor/kdf.js';
import { buildAAD, validateCreate, validatePaste } from '../vendor/format.js';
import { hex, b64urlFromBytes, utf8, fromUtf8 } from '../vendor/bytes.js';

const seq = (start, n) => Uint8Array.from({ length: n }, (_, i) => (start + i) & 0xff);
const fill = (v, n) => new Uint8Array(n).fill(v);
const unhex = (h) => Uint8Array.from((h.match(/../g) || []).map((b) => parseInt(b, 16)));

// ── Fixed inputs shared by the frozen vectors (test/genvectors.mjs) ──────────
const F = seq(0, 32);
const CEK = seq(0x20, 32);
const ivc = fill(0x11, 12);
const ivw = fill(0x22, 12);
const salt = fill(0x33, 16);
const VEC_PLAINTEXT = 'secbin vector — zero knowledge ✓';

// FROZEN vectors — same pinned values as test-node/crypto.test.js. Never
// hand-edit; regenerate with test/genvectors.mjs only alongside a SPEC change.
const VECTORS = {
  nopw: {
    adata: { alg: 'A256GCM', kdf: 'hkdf', iter: 0, comp: 'none', fmt: 'plaintext', bar: false,
             ivc: b64urlFromBytes(ivc), ivw: b64urlFromBytes(ivw), skdf: '' },
    password: '',
    aadHex: '73656362696e2f76320a616c673d4132353647434d0a6b64663d686b64660a697465723d300a636f6d703d6e6f6e650a666d743d706c61696e746578740a6261723d300a6976633d455245524552455245524552455245520a6976773d496949694969496949694969496949690a736b64663d0a',
    pwIkmHex: '',
    linkProof: '_Vnj_mPEy7Rfo4gcxzAQVj7qk5pcmYuf_zr4zhxPpvI',
    keyProof: 'PUtbfpZsnAofo48AgCujYJgXpTyWEwjA6FP_pqoyJf4',
    lh: 'FmBQhWBJ-cjh0vXydV6MCOtjOgXU_VBPZEi-17n2EZg',
    kh: 'PiuWCHxXmt9k8y4XvYGKmDPWJWfeAJDEyAt4fofi1xM',
    wkHex: 'd9e7a014c3a392c5966af7779d60e3bc2e9686650a869c23c4094d31877c8f7d2989219dc8beed306c706b03a65fc772',
    ctHex: '405811c70399338336f6bcb6bfd2c568f53db90206cf40be135ac57b48bb16302ff78e4a501cf3a0e065dd6b175eda39f7ddc9f6',
  },
  pw: {
    adata: { alg: 'A256GCM', kdf: 'argon2id-hkdf', iter: 3, comp: 'none', fmt: 'plaintext', bar: false,
             ivc: b64urlFromBytes(ivc), ivw: b64urlFromBytes(ivw), skdf: b64urlFromBytes(salt) },
    password: 'correct horse',
    aadHex: '73656362696e2f76320a616c673d4132353647434d0a6b64663d6172676f6e3269642d686b64660a697465723d330a636f6d703d6e6f6e650a666d743d706c61696e746578740a6261723d300a6976633d455245524552455245524552455245520a6976773d496949694969496949694969496949690a736b64663d4d7a4d7a4d7a4d7a4d7a4d7a4d7a4d7a4d7a4d7a4d770a',
    pwIkmHex: '5058052c0eae847dbbc4aed52f04a94eb2391d2b7f9e8e8d364212d56b1c0594',
    linkProof: '_Vnj_mPEy7Rfo4gcxzAQVj7qk5pcmYuf_zr4zhxPpvI',
    keyProof: 'bXLv8D9lrS25K7LB5QL58cg4Uhu3dR7mYX6HSm_9MZw',
    lh: 'FmBQhWBJ-cjh0vXydV6MCOtjOgXU_VBPZEi-17n2EZg',
    kh: 'RuZY6BzxAcm5y7XoUGG4hsII0R6yHvK9yDWu5RiZ-3U',
    wkHex: '84bcabc0071dec1b956778fa4b1f2acb0f3e42bae809d5a4839d1a2bd142d8c1643ebe3a621d6673736f924d858f7d04',
    ctHex: '405811c70399338336f6bcb6bfd2c568f53db90206cf40be135ac57b48bb16302ff78e4a3284e62245cce0f81ad31500db7818a1',
  },
};

describe('frozen v2 test vectors (plain Node, vendored modules)', () => {
  it('vendored Argon2id matches the phc-winner-argon2 reference vector', async () => {
    const out = await argon2idRaw(utf8('password'), utf8('somesalt'), { t: 2, mKiB: 65536, p: 1 });
    expect(hex(out)).toBe('09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7');
  });

  for (const [name, v] of Object.entries(VECTORS)) {
    it(`${name}: AAD, password key, proofs, wrap and ciphertext match`, async () => {
      const aad = buildAAD(v.adata);
      expect(hex(aad)).toBe(v.aadHex);
      const pwIkm = v.password ? await argon2idRaw(utf8(v.password), salt, { t: v.adata.iter }) : new Uint8Array(0);
      expect(hex(pwIkm)).toBe(v.pwIkmHex);
      const { kek, linkProof, keyProof } = await keySchedule(F, pwIkm);
      expect(b64urlFromBytes(linkProof)).toBe(v.linkProof);
      expect(b64urlFromBytes(keyProof)).toBe(v.keyProof);
      expect(await proofHash(v.linkProof)).toBe(v.lh);
      expect(await proofHash(v.keyProof)).toBe(v.kh);
      const wk = await aesGcmEncrypt(kek, ivw, CEK, aad);
      expect(hex(wk)).toBe(v.wkHex);
      expect(hex(await aesGcmDecrypt(kek, ivw, wk, aad))).toBe(hex(CEK));
      const key = await crypto.subtle.importKey('raw', CEK, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
      expect(hex(await aesGcmEncrypt(key, ivc, utf8(VEC_PLAINTEXT), aad))).toBe(v.ctHex);
      expect(fromUtf8(await aesGcmDecrypt(key, ivc, unhex(v.ctHex), aad))).toBe(VEC_PLAINTEXT);
    });
  }
});

// Simulates the server: releases the paste only for matching proof hashes.
async function serverOpen(body, access) {
  const clean = validateCreate(body);
  const ok = (await proofHash(access.linkProof)) === clean.acc.lh && (await proofHash(access.keyProof)) === clean.acc.kh;
  if (!ok) return null;
  const { acc: _acc, ...paste } = clean;
  return validatePaste(paste);
}

describe('round-trips in Node (gzip via native CompressionStream)', () => {
  it('no-password note round-trips and emits a valid v2 create body', async () => {
    const text = 'hello from the CLI runtime';
    const { body, fragment } = await encryptPaste({ text });
    expect(() => validateCreate(body)).not.toThrow();
    const access = await deriveAccess({ adata: body.adata, fragment });
    expect((await openPaste({ paste: await serverOpen(body, access), access })).text).toBe(text);
  });

  it('compressible content takes the gzip path and round-trips', async () => {
    const text = 'z'.repeat(50000);
    const { body, fragment } = await encryptPaste({ text });
    expect(body.adata.comp).toBe('gzip');
    const access = await deriveAccess({ adata: body.adata, fragment });
    expect((await openPaste({ paste: await serverOpen(body, access), access })).text).toBe(text);
  });

  it('password shares need the password; a wrong one fails the key proof only', async () => {
    const { body, fragment } = await encryptPaste({ text: 'view me safely', password: 'pw', bar: true, views: 2, t: 1 });
    await expect(deriveAccess({ adata: body.adata, fragment })).rejects.toBeInstanceOf(PasswordRequired);
    const bad = await deriveAccess({ adata: body.adata, fragment, password: 'nope' });
    expect(await proofHash(bad.linkProof)).toBe(body.acc.lh);
    expect(await serverOpen(body, bad)).toBeNull();
    const good = await deriveAccess({ adata: body.adata, fragment, password: 'pw' });
    expect((await openPaste({ paste: await serverOpen(body, good), access: good })).text).toBe('view me safely');
  });
});
