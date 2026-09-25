// pwauth.js — account passwords, stretched in the browser with Argon2id
// (64 MiB, t=3, p=1) so the server never receives the password itself — only
// d = Argon2id(NFC(password), salt), which it stores as SHA-256("secbin-auth/v2" ‖ d).
// The password policy is enforced here, and only here: the server cannot see
// the password. It is configured by the admin (globally and per user) as the
// pw* limits; the owner always gets DEFAULT_POLICY.

import { argon2idRaw } from './kdf.js';
import { ARGON2 } from './format.js';
import { utf8, b64urlFromBytes, bytesFromB64url, randomBytes } from './bytes.js';
import { prelogin } from './api.js';

export const MIN_PASSWORD = 12;
export const MAX_PASSWORD = 256;

/** The built-in policy (and the owner's): 12 characters, nothing else required. */
export const DEFAULT_POLICY = Object.freeze({ pwMinLength: MIN_PASSWORD, pwUpper: false, pwLower: false, pwDigit: false, pwSymbol: false });

const CLASSES = [
  ['pwUpper', /\p{Lu}/u, 'an upper-case letter'],
  ['pwLower', /\p{Ll}/u, 'a lower-case letter'],
  ['pwDigit', /\p{Nd}/u, 'a digit'],
  ['pwSymbol', /[^\p{L}\p{N}\s]/u, 'a symbol'],
];

/** A policy from limits (missing or invalid keys fall back to the defaults). */
export function policyOf(limits) {
  const l = limits && typeof limits === 'object' ? limits : {};
  const min = Number.isInteger(l.pwMinLength) ? Math.min(Math.max(l.pwMinLength, MIN_PASSWORD), MAX_PASSWORD) : MIN_PASSWORD;
  return { pwMinLength: min, pwUpper: l.pwUpper === true, pwLower: l.pwLower === true, pwDigit: l.pwDigit === true, pwSymbol: l.pwSymbol === true };
}

/** "At least 14 characters, including an upper-case letter and a digit." */
export function describePolicy(policy = DEFAULT_POLICY) {
  const p = policyOf(policy);
  const need = CLASSES.filter(([k]) => p[k]).map(([, , t]) => t);
  const list = need.length > 1 ? `${need.slice(0, -1).join(', ')} and ${need.at(-1)}` : need[0];
  return `At least ${p.pwMinLength} characters${list ? `, including ${list}` : ''}.`;
}

/** null when `pw` satisfies the policy (and matches `confirm`), else a message. */
export function checkNewPassword(pw, confirm, policy = DEFAULT_POLICY) {
  const p = policyOf(policy);
  if (typeof pw !== 'string') return describePolicy(p);
  const len = [...pw.normalize('NFC')].length; // characters, not UTF-16 units
  if (len < p.pwMinLength) return `Use at least ${p.pwMinLength} characters.`;
  if (len > MAX_PASSWORD) return `Use at most ${MAX_PASSWORD} characters.`;
  const missing = CLASSES.filter(([k, re]) => p[k] && !re.test(pw)).map(([, , t]) => t);
  if (missing.length) return `The password needs ${missing.join(', ')}. ${describePolicy(p)}`;
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
