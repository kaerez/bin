// exportcrypt.js — the encrypted envelope for admin exports
// ("secbin-export-enc/v1"). An export can hold password verifiers and the
// whole system configuration, so it only ever leaves the browser encrypted:
//
//   key = Argon2id(UTF8(NFC(passphrase)), salt16, m = 64 MiB, t = 3, p = 1) → 32 B
//   ct  = AES-256-GCM(key, iv12, UTF8(JSON(document)), AAD = header)
//   header = "secbin-export-enc/v1\nargon2id\nm=65536\nt=3\np=1\nsalt=<b64url>\niv=<b64url>\n"
//
// The KDF parameters are fixed (a crafted file cannot ask for unbounded work)
// and bound into the AAD, so any change to the file fails authentication.

import { argon2idRaw } from './kdf.js';
import { b64urlFromBytes, bytesFromB64url, randomBytes, utf8, fromUtf8 } from './bytes.js';

export const ENVELOPE_FORMAT = 'secbin-export-enc/v1';
export const MIN_PASSPHRASE = 12;
const KDF = Object.freeze({ alg: 'argon2id', m: 65536, t: 3, p: 1 });
const B64_RE = /^[A-Za-z0-9_-]+$/;

export class ExportCryptError extends Error {
  constructor(message) { super(message); this.name = 'ExportCryptError'; }
}

const header = (salt, iv) => `${ENVELOPE_FORMAT}\n${KDF.alg}\nm=${KDF.m}\nt=${KDF.t}\np=${KDF.p}\nsalt=${salt}\niv=${iv}\n`;

async function keyFrom(passphrase, saltBytes) {
  const raw = await argon2idRaw(utf8(String(passphrase).normalize('NFC')), saltBytes, { t: KDF.t, mKiB: KDF.m, p: KDF.p });
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

/** Encrypt a plaintext export document → the envelope as pretty JSON text. */
export async function sealExport(doc, passphrase) {
  if (typeof passphrase !== 'string' || passphrase.length < MIN_PASSPHRASE) {
    throw new ExportCryptError(`Use a passphrase of at least ${MIN_PASSPHRASE} characters.`);
  }
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const s = b64urlFromBytes(salt);
  const i = b64urlFromBytes(iv);
  const key = await keyFrom(passphrase, salt);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: utf8(header(s, i)) }, key, utf8(JSON.stringify(doc))));
  return JSON.stringify({ format: ENVELOPE_FORMAT, kdf: { ...KDF, salt: s }, iv: i, ct: b64urlFromBytes(ct) }, null, 2);
}

/** Parse + decrypt an envelope (untrusted text) → the document object. */
export async function openExport(text, passphrase) {
  let env;
  try { env = JSON.parse(text); } catch { throw new ExportCryptError('This is not a secbin export file.'); }
  const ok = env && typeof env === 'object' && !Array.isArray(env)
    && Object.keys(env).sort().join() === 'ct,format,iv,kdf'
    && env.format === ENVELOPE_FORMAT
    && env.kdf && typeof env.kdf === 'object' && Object.keys(env.kdf).sort().join() === 'alg,m,p,salt,t'
    && env.kdf.alg === KDF.alg && env.kdf.m === KDF.m && env.kdf.t === KDF.t && env.kdf.p === KDF.p
    && typeof env.kdf.salt === 'string' && env.kdf.salt.length === 22 && B64_RE.test(env.kdf.salt)
    && typeof env.iv === 'string' && env.iv.length === 16 && B64_RE.test(env.iv)
    && typeof env.ct === 'string' && env.ct.length >= 24 && B64_RE.test(env.ct);
  if (!ok) throw new ExportCryptError('This is not a secbin export file, or it was made by an incompatible version.');
  const key = await keyFrom(passphrase, bytesFromB64url(env.kdf.salt));
  let pt;
  try {
    pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytesFromB64url(env.iv), additionalData: utf8(header(env.kdf.salt, env.iv)) }, key, bytesFromB64url(env.ct));
  } catch {
    throw new ExportCryptError('Wrong passphrase, or the file was modified.');
  }
  try { return JSON.parse(fromUtf8(new Uint8Array(pt))); } catch { throw new ExportCryptError('The decrypted export is not valid.'); }
}
