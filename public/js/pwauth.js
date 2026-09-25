// pwauth.js — account passwords, stretched in the browser with Argon2id
// (64 MiB, t=3, p=1) so the server never receives the password itself — only
// d = Argon2id(NFC(password), salt), which it stores as SHA-256("secbin-auth/v2" ‖ d).
// The minimum length is enforced here: the server cannot see the password.

import { argon2idRaw } from './kdf.js';
import { ARGON2 } from './format.js';
import { utf8, b64urlFromBytes, bytesFromB64url, randomBytes } from './bytes.js';
import { prelogin } from './api.js';

export const MIN_PASSWORD = 12;
export const MAX_PASSWORD = 256;

export function checkNewPassword(pw, confirm) {
  if (typeof pw !== 'string' || pw.length < MIN_PASSWORD) return `Use at least ${MIN_PASSWORD} characters.`;
  if (pw.length > MAX_PASSWORD) return `Use at most ${MAX_PASSWORD} characters.`;
  if (confirm !== undefined && pw !== confirm) return 'The passwords do not match.';
  return null;
}

export async function stretch(password, saltB64, t = ARGON2.tDefault) {
  const d = await argon2idRaw(utf8(password.normalize('NFC')), bytesFromB64url(saltB64), { t });
  return b64urlFromBytes(d);
}

/** A fresh credential for setting a password: { salt, t, proof }. */
export async function newCredential(password) {
  const salt = b64urlFromBytes(randomBytes(16));
  const t = ARGON2.tDefault;
  return { salt, t, proof: await stretch(password, salt, t) };
}

/** Look up the account's salt (fake for unknown users) and stretch → proof. */
export async function loginProof(username, password) {
  const { salt, t } = await prelogin(username);
  return stretch(password, salt, t);
}

/** Random hex secret (for AUTHN / SIG / ENC) — generated locally, never sent. */
export function randomHex(bytes = 32) {
  return Array.from(randomBytes(bytes), (b) => b.toString(16).padStart(2, '0')).join('');
}
