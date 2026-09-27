// portable.js — the admin export/import document ("secbin-export/v1") and its
// fail-closed validation. The document is only ever stored or transmitted
// encrypted (public/js/exportcrypt.js: passphrase → Argon2id → AES-256-GCM in
// the browser); the Worker sees it in plaintext only inside an owner's
// authenticated export/import request, and re-validates every field on import
// with the same checkers the admin API uses.
//
// What it can hold (every part is optional, chosen at export and again at
// import):
//   system  — settings; the Default role (global limits for the all and API
//             channels, quotas, viewer rules) together with the custom roles;
//             IP rules; the Turnstile keys set in the admin panel (site key
//             and secret); the public account's own limits, quotas and rules;
//   owner   — the owner's row, each part independent: `passkeys` ({ keys }:
//             public keys, each with its user handle; the owner's
//             "Password and passkey" choice never travels) and
//             `recoveryCodes` (the code hashes). Never the owner's password,
//             role or API keys. On import the owner always exists, so only
//             its passkeys can be added; its recovery codes are never taken;
//   users[] — per user, each part independent (username is always present):
//             `credentials` (salt, t, verifier, disabled), `role` (the role's
//             name, "Default" for the Default role), `apiKeys` (the stored
//             hashes, names, scopes and dates: the keys keep working),
//             `passkeys` ({ mfa: the "Password and passkey" choice, keys:
//             public keys, each with the WebAuthn user handle it was
//             registered under }) and `recoveryCodes` (the code hashes).
//             Passkeys work only under the same hostname; recovery codes
//             work anywhere.
// Never: sessions, shares, usage counters or the activity log.
//
// Import rule (confirmed by the maintainer): an import never removes or
// overwrites an existing account's credentials. An account that already
// exists (the owner included) only gets its role set (if chosen; never for
// the owner, who always has the Owner role) and the imported passkeys added
// (if chosen); new accounts are created from the chosen parts. The rules are
// applied in Directory.importData (src/directory-do.js).

import { checkSetting, checkLimit, checkQuota, checkViewerRule, API_SCOPES } from './settings.js';
import { upgradeUrlRules } from '../../public/js/sharetypes.js';
import { normalizeRule } from './ip.js';
import { ARGON2 } from '../../public/js/format.js';

export const EXPORT_FORMAT = 'secbin-export/v1';
export const MAX_EXPORT_USERS = 5000;
export const MAX_IMPORT_BYTES = 8 * 1024 * 1024;
export const USERNAME_RE = /^[A-Za-z0-9][A-Za-z0-9._@-]{2,63}$/;
const B64_16_RE = /^[A-Za-z0-9_-]{22}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;

export class PortableError extends Error {
  constructor(message) { super(message); this.name = 'PortableError'; }
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

/** Exactly these keys (required ∪ optional), all own; anything else is refused. */
function keys(v, where, required, optional = []) {
  if (!isObj(v)) throw new PortableError(`${where} must be an object`);
  const allowed = new Set([...required, ...optional]);
  for (const k of Object.keys(v)) if (!allowed.has(k)) throw new PortableError(`${where}: unexpected field "${String(k).slice(0, 40)}"`);
  for (const k of required) if (!Object.prototype.hasOwnProperty.call(v, k)) throw new PortableError(`${where}: missing "${k}"`);
}

function list(v, where, max) {
  if (!Array.isArray(v)) throw new PortableError(`${where} must be a list`);
  if (v.length > max) throw new PortableError(`${where}: at most ${max} entries`);
  return v;
}

const short = (k) => String(k).slice(0, 60);
const wrap = (where, fn) => {
  try { return fn(); } catch (e) { throw new PortableError(`${where}: ${String(e.message).slice(0, 200)}`); }
};

function limitsBlock(v, where) {
  keys(v, where, ['all', 'api']);
  const out = { all: {}, api: {} };
  for (const ch of ['all', 'api']) {
    keys(v[ch], `${where}.${ch}`, [], Object.keys(v[ch] ?? {}));
    // Link rules from files made before scheme:name:// / scheme:name: are upgraded first.
    for (const [k, val] of Object.entries(v[ch])) out[ch][k] = wrap(`${where}.${ch}.${short(k)}`, () => checkLimit(k, k === 'urlRules' ? upgradeUrlRules(val) : val, ch));
  }
  return out;
}

const quotas = (v, where) => list(v, where, 50).map((q, i) => wrap(`${where}[${i}]`, () => checkQuota(q)));
const viewerRules = (v, where) => list(v, where, 200).map((r, i) => wrap(`${where}[${i}]`, () => checkViewerRule(r)));

function ipRule(r, where) {
  keys(r, where, ['cidr', 'action'], ['expires', 'note']);
  const cidr = normalizeRule(r.cidr);
  if (!cidr) throw new PortableError(`${where}: invalid address or range`);
  if (r.action !== 'allow' && r.action !== 'block') throw new PortableError(`${where}: action must be allow or block`);
  const expires = r.expires ?? null;
  if (expires !== null && !Number.isSafeInteger(expires)) throw new PortableError(`${where}: invalid expiry`);
  const raw = r.note ?? '';
  if (typeof raw !== 'string') throw new PortableError(`${where}: invalid note`);
  // Same cleaning as the admin API's notes (control characters → spaces, trimmed).
  // eslint-disable-next-line no-control-regex
  const note = raw.replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  if (note.length > 100) throw new PortableError(`${where}: notes are up to 100 characters`);
  return { cidr, action: r.action, expires, note };
}

export const MAX_ROLES = 200;
/** The parts of a user entry, each independent. */
export const USER_PARTS = ['credentials', 'role', 'apiKeys', 'passkeys', 'recoveryCodes'];
/** The parts of the owner's row (never its password, role or API keys). */
export const OWNER_PARTS = ['passkeys', 'recoveryCodes'];
export const MAX_FILE_PASSKEYS = 10;
export const MAX_FILE_RECOVERY_CODES = 20;
const ROLE_NAME_MAX = 64;

function role(v, i) {
  const where = `system.roles[${i}]`;
  keys(v, where, ['name', 'ownQuotas', 'limits', 'quotas', 'viewerRules']);
  // eslint-disable-next-line no-control-regex
  if (typeof v.name !== 'string' || !v.name.trim() || v.name.length > ROLE_NAME_MAX || /[\u0000-\u001f\u007f]/.test(v.name)) throw new PortableError(`${where}: invalid name`);
  if (['owner', 'default'].includes(v.name.trim().toLowerCase())) throw new PortableError(`${where}: "${v.name}" is a built-in role`);
  if (typeof v.ownQuotas !== 'boolean') throw new PortableError(`${where}: ownQuotas must be true or false`);
  return {
    name: v.name.trim(),
    ownQuotas: v.ownQuotas,
    limits: limitsBlock(v.limits, `${where}.limits`),
    quotas: quotas(v.quotas, `${where}.quotas`),
    viewerRules: viewerRules(v.viewerRules, `${where}.viewerRules`),
  };
}

/** The parts of `system`, each optional; `parts` lists those present. */
export const SYSTEM_PARTS = ['settings', 'roles', 'ipRules', 'turnstile', 'public'];
const has = (v, k) => Object.prototype.hasOwnProperty.call(v, k);
const TURNSTILE_KEY_RE = /^[A-Za-z0-9_-]{10,100}$/;

function system(v) {
  keys(v, 'system', [], ['settings', 'limits', 'quotas', 'viewerRules', 'ipRules', 'roles', 'turnstile', 'public']);
  const out = { parts: [] };
  if (has(v, 'settings')) {
    keys(v.settings, 'system.settings', [], Object.keys(v.settings ?? {}));
    const settings = {};
    for (const [k, val] of Object.entries(v.settings)) settings[k] = wrap(`system.settings.${short(k)}`, () => checkSetting(k, val));
    if (settings['session.idleSec'] !== undefined && settings['session.absSec'] !== undefined && settings['session.idleSec'] > settings['session.absSec']) {
      throw new PortableError('system.settings: the idle timeout cannot exceed the absolute timeout');
    }
    out.settings = settings;
    out.parts.push('settings');
  }
  // The roles part: the Default role (limits, quotas, viewer rules — all
  // three together) and, optionally, the custom roles.
  const def = ['limits', 'quotas', 'viewerRules'].filter((k) => has(v, k));
  if (def.length && def.length < 3) throw new PortableError('system: limits, quotas and viewerRules (the Default role) go together');
  if (def.length || has(v, 'roles')) {
    if (!def.length) throw new PortableError('system: the custom roles need the Default role (limits, quotas, viewerRules) with them');
    out.limits = limitsBlock(v.limits, 'system.limits');
    out.quotas = quotas(v.quotas, 'system.quotas');
    out.viewerRules = viewerRules(v.viewerRules, 'system.viewerRules');
    out.roles = v.roles === undefined ? [] : uniqueRoles(list(v.roles, 'system.roles', MAX_ROLES).map(role));
    out.parts.push('roles');
  }
  if (has(v, 'ipRules')) {
    out.ipRules = list(v.ipRules, 'system.ipRules', 1000).map((r, i) => ipRule(r, `system.ipRules[${i}]`));
    out.parts.push('ipRules');
  }
  if (has(v, 'turnstile')) {
    if (v.turnstile !== null) {
      keys(v.turnstile, 'system.turnstile', ['sitekey', 'secret']);
      if (!TURNSTILE_KEY_RE.test(String(v.turnstile.sitekey)) || !TURNSTILE_KEY_RE.test(String(v.turnstile.secret))) throw new PortableError('system.turnstile: invalid keys');
    }
    out.turnstile = v.turnstile === null ? null : { sitekey: v.turnstile.sitekey, secret: v.turnstile.secret };
    out.parts.push('turnstile');
  }
  if (has(v, 'public')) {
    keys(v.public, 'system.public', ['limits', 'quotas', 'viewerRules']);
    out.public = {
      limits: limitsBlock(v.public.limits, 'system.public.limits'),
      quotas: quotas(v.public.quotas, 'system.public.quotas'),
      viewerRules: viewerRules(v.public.viewerRules, 'system.public.viewerRules'),
    };
    out.parts.push('public');
  }
  return out;
}

// ── per-user API keys and passkeys ───────────────────────────────────────────
const HEX64 = /^[0-9a-f]{64}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const intOrNull = (x) => x === null || Number.isSafeInteger(x);
function labelOf(v, where) {
  // eslint-disable-next-line no-control-regex
  if (typeof v !== 'string' || !v.trim() || v.length > 100 || /[\u0000-\u001f\u007f]/.test(v)) throw new PortableError(`${where}: invalid name`);
  return v;
}

function apiKey(k, where) {
  keys(k, where, ['hash', 'name', 'created', 'expires', 'lastUsed', 'scopes']);
  if (typeof k.hash !== 'string' || !HEX64.test(k.hash)) throw new PortableError(`${where}: invalid key hash`);
  if (!Number.isSafeInteger(k.created) || !intOrNull(k.expires) || !intOrNull(k.lastUsed)) throw new PortableError(`${where}: invalid dates`);
  if (!Array.isArray(k.scopes) || !k.scopes.length || k.scopes.some((x) => !API_SCOPES.includes(x))) throw new PortableError(`${where}: invalid scopes`);
  return { hash: k.hash, name: labelOf(k.name, where), created: k.created, expires: k.expires, lastUsed: k.lastUsed, scopes: API_SCOPES.filter((x) => k.scopes.includes(x)) };
}

function passkeyKey(p, w) {
  keys(p, w, ['id', 'handle', 'name', 'publicKey', 'alg', 'signCount', 'transports', 'backupEligible', 'backedUp', 'created', 'lastUsed']);
  if (typeof p.id !== 'string' || p.id.length < 16 || p.id.length > 1400 || !B64URL.test(p.id)) throw new PortableError(`${w}: invalid credential id`);
  if (p.handle !== null && (typeof p.handle !== 'string' || p.handle.length > 64 || !B64URL.test(p.handle))) throw new PortableError(`${w}: invalid user handle`);
  if (typeof p.publicKey !== 'string' || p.publicKey.length > 2000 || !B64URL.test(p.publicKey)) throw new PortableError(`${w}: invalid public key`);
  if (![-7, -8, -257].includes(p.alg)) throw new PortableError(`${w}: unsupported algorithm`);
  if (!Number.isSafeInteger(p.signCount) || p.signCount < 0) throw new PortableError(`${w}: invalid counter`);
  if (!Array.isArray(p.transports) || p.transports.length > 10 || p.transports.some((t) => typeof t !== 'string' || !/^[a-z-]{1,20}$/.test(t))) throw new PortableError(`${w}: invalid transports`);
  if (typeof p.backupEligible !== 'boolean' || typeof p.backedUp !== 'boolean') throw new PortableError(`${w}: invalid flags`);
  if (!Number.isSafeInteger(p.created) || !intOrNull(p.lastUsed)) throw new PortableError(`${w}: invalid dates`);
  return { id: p.id, handle: p.handle, name: labelOf(p.name, w), publicKey: p.publicKey, alg: p.alg, signCount: p.signCount, transports: p.transports, backupEligible: p.backupEligible, backedUp: p.backedUp, created: p.created, lastUsed: p.lastUsed };
}

/** A user's passkeys ({ mfa, keys }) or the owner's ({ keys }: its second-step choice never travels). */
function passkeyBlock(v, where, owner = false) {
  keys(v, where, owner ? ['keys'] : ['mfa', 'keys']);
  if (!owner && typeof v.mfa !== 'boolean') throw new PortableError(`${where}: mfa must be true or false`);
  const ks = list(v.keys, `${where}.keys`, MAX_FILE_PASSKEYS).map((p, i) => passkeyKey(p, `${where}.keys[${i}]`));
  if (new Set(ks.map((p) => p.id)).size !== ks.length) throw new PortableError(`${where}.keys: a passkey appears twice`);
  return owner ? { keys: ks } : { mfa: v.mfa, keys: ks };
}

function recoveryCodes(v, where) {
  const codes = list(v, where, MAX_FILE_RECOVERY_CODES);
  if (codes.some((c) => typeof c !== 'string' || !HEX64.test(c))) throw new PortableError(`${where}: invalid code hash`);
  return [...new Set(codes)];
}

function uniqueRoles(roles) {
  const seen = new Set();
  for (const r of roles) {
    const k = r.name.toLowerCase();
    if (seen.has(k)) throw new PortableError(`system.roles: "${r.name}" appears twice`);
    seen.add(k);
  }
  return roles;
}

/** A user's role, by name ("Default" for the Default role; never the Owner role). */
function roleName(v, where) {
  // eslint-disable-next-line no-control-regex
  if (typeof v !== 'string' || !v.trim() || v.length > ROLE_NAME_MAX || /[\u0000-\u001f\u007f]/.test(v)) throw new PortableError(`${where}: invalid role`);
  if (v.trim().toLowerCase() === 'owner') throw new PortableError(`${where}: the Owner role belongs to the owner only`);
  return v.trim();
}

function user(v, i) {
  const where = `users[${i}]`;
  keys(v, where, ['username'], USER_PARTS);
  if (typeof v.username !== 'string' || !USERNAME_RE.test(v.username)) throw new PortableError(`${where}: invalid username`);
  const out = { username: v.username };
  if (v.credentials !== undefined) {
    const c = v.credentials;
    keys(c, `${where}.credentials`, ['salt', 't', 'verifier', 'disabled']);
    if (typeof c.salt !== 'string' || !B64_16_RE.test(c.salt)) throw new PortableError(`${where}.credentials: invalid salt`);
    if (c.t !== ARGON2.tDefault) throw new PortableError(`${where}.credentials: time cost must be ${ARGON2.tDefault}`);
    if (typeof c.verifier !== 'string' || !HEX64_RE.test(c.verifier)) throw new PortableError(`${where}.credentials: invalid verifier`);
    if (typeof c.disabled !== 'boolean') throw new PortableError(`${where}.credentials: disabled must be true or false`);
    out.credentials = { salt: c.salt, t: c.t, verifier: c.verifier, disabled: c.disabled };
  }
  if (v.role !== undefined) out.role = roleName(v.role, `${where}.role`);
  if (v.apiKeys !== undefined) out.apiKeys = list(v.apiKeys, `${where}.apiKeys`, 1000).map((k, j) => apiKey(k, `${where}.apiKeys[${j}]`));
  if (v.passkeys !== undefined) out.passkeys = passkeyBlock(v.passkeys, `${where}.passkeys`);
  if (v.recoveryCodes !== undefined) out.recoveryCodes = recoveryCodes(v.recoveryCodes, `${where}.recoveryCodes`);
  if (!USER_PARTS.some((k) => out[k] !== undefined)) throw new PortableError(`${where}: nothing to import`);
  return out;
}

function ownerEntry(v) {
  keys(v, 'owner', [], OWNER_PARTS);
  const out = {};
  if (v.passkeys !== undefined) out.passkeys = passkeyBlock(v.passkeys, 'owner.passkeys', true);
  if (v.recoveryCodes !== undefined) out.recoveryCodes = recoveryCodes(v.recoveryCodes, 'owner.recoveryCodes');
  if (!OWNER_PARTS.some((k) => out[k] !== undefined)) throw new PortableError('owner: nothing to import');
  return out;
}

/** Validate an untrusted export document → a clean copy, or throw PortableError. */
export function validateExport(doc) {
  keys(doc, 'document', ['format', 'created', 'users'], ['system', 'origin', 'owner']);
  if (doc.format !== EXPORT_FORMAT) throw new PortableError(`not a ${EXPORT_FORMAT} document`);
  if (!Number.isSafeInteger(doc.created) || doc.created < 0) throw new PortableError('document: invalid creation time');
  if (doc.origin !== undefined && (typeof doc.origin !== 'string' || doc.origin.length > 200)) throw new PortableError('document: invalid origin');
  const users = list(doc.users, 'users', MAX_EXPORT_USERS).map(user);
  const seen = new Set();
  for (const u of users) {
    const k = u.username.toLowerCase();
    if (seen.has(k)) throw new PortableError(`users: "${u.username}" appears twice`);
    seen.add(k);
  }
  const out = { format: EXPORT_FORMAT, created: doc.created, users };
  if (doc.origin !== undefined) out.origin = doc.origin;
  if (doc.system !== undefined) out.system = system(doc.system);
  if (doc.owner !== undefined) out.owner = ownerEntry(doc.owner);
  return out;
}

/** true / false / { part: bool } → the chosen parts, each of which the document must hold. */
function chosenParts(v, where, all, inDoc, what) {
  const out = new Set();
  if (v === true) {
    if (!inDoc.length) throw new PortableError(`the document has no ${what}`);
    for (const k of inDoc) out.add(k);
  } else if (isObj(v)) {
    keys(v, where, [], all);
    for (const [k, on] of Object.entries(v)) {
      if (typeof on !== 'boolean') throw new PortableError(`${where}.${k} must be true or false`);
      if (on && !inDoc.includes(k)) throw new PortableError(`the document has no "${k}" part`);
      if (on) out.add(k);
    }
  } else if (v !== false && v !== undefined) throw new PortableError(`${where} must be true, false or a list of parts`);
  return out;
}

/**
 * Validate the import decisions:
 *   { system: bool | { part: bool }, owner?: bool | { passkeys?, recoveryCodes? },
 *     users: { [username]: { as?, action?: "create" | "update", parts? } } }.
 * A user absent from `users` is skipped. `action` is what the owner expects:
 * "create" (the default) a new account, or "update" one that exists (its role
 * and added passkeys only); the plan refuses a mismatch with what is there.
 * `owner` applies the file's owner row to this server's owner: its passkeys
 * are added; its recovery codes, if chosen, are listed as skipped.
 */
export function validateDecisions(d, doc) {
  keys(d, 'decisions', ['system', 'users'], ['owner']);
  const systemParts = chosenParts(d.system, 'decisions.system', SYSTEM_PARTS, doc.system ? doc.system.parts : [], 'system configuration');
  const ownerParts = chosenParts(d.owner, 'decisions.owner', OWNER_PARTS, OWNER_PARTS.filter((k) => doc.owner?.[k] !== undefined), 'owner part');
  keys(d.users, 'decisions.users', [], Object.keys(d.users ?? {}));
  const names = new Set(doc.users.map((u) => u.username));
  const out = { system: systemParts.size > 0, systemParts, ownerParts, users: new Map() };
  const targets = new Set();
  for (const [name, choice] of Object.entries(d.users)) {
    if (!names.has(name)) throw new PortableError(`decisions.users: "${name.slice(0, 64)}" is not in the document`);
    keys(choice, `decisions.users.${name}`, [], ['as', 'action', 'parts']);
    const as = choice.as === undefined ? name : choice.as;
    if (typeof as !== 'string' || !USERNAME_RE.test(as)) throw new PortableError(`decisions.users.${name}: invalid target username`);
    const action = choice.action === undefined ? 'create' : choice.action;
    if (action !== 'create' && action !== 'update') throw new PortableError(`decisions.users.${name}: action must be "create" or "update"`);
    if (targets.has(as.toLowerCase())) throw new PortableError(`two users would be imported as "${as}"`);
    targets.add(as.toLowerCase());
    // parts: which of the user's parts to take (default: all of them).
    const u = doc.users.find((x) => x.username === name);
    const inDoc = USER_PARTS.filter((k) => u[k] !== undefined);
    let parts = inDoc;
    if (choice.parts !== undefined) {
      if (!Array.isArray(choice.parts) || choice.parts.some((k) => !inDoc.includes(k))) throw new PortableError(`decisions.users.${name}: parts must be some of ${inDoc.join(', ') || 'nothing'}`);
      parts = inDoc.filter((k) => choice.parts.includes(k));
    }
    if (!parts.length) throw new PortableError(`decisions.users.${name}: nothing chosen to import`);
    out.users.set(name, { as, action, parts: new Set(parts) });
  }
  return out;
}
