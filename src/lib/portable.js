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
//   users[] — per user: `credentials` (username is always present; salt, t,
//             verifier, disabled) and/or `config` ({ role }: the role's name,
//             "Default" for the Default role), `apiKeys` (the stored hashes,
//             names, scopes and dates: the keys keep working) and `passkeys`
//             (public keys, the second-step choice, recovery-code hashes;
//             passkeys work only under the same hostname). Files from before
//             roles carry per-user limits in `config`; they are accepted and
//             ignored.
// Never: the owner account, sessions, shares, usage counters or the activity log.

import { checkSetting, checkLimit, checkQuota, checkViewerRule } from './settings.js';
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
/** The parts of a user entry. */
export const USER_PARTS = ['credentials', 'config', 'apiKeys', 'passkeys'];
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
const API_SCOPES = ['notes', 'files', 'policy'];
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

function passkeyBlock(v, where) {
  keys(v, where, ['mfa', 'handle', 'keys', 'recoveryCodes']);
  if (typeof v.mfa !== 'boolean') throw new PortableError(`${where}: mfa must be true or false`);
  if (v.handle !== null && (typeof v.handle !== 'string' || v.handle.length > 64 || !B64URL.test(v.handle))) throw new PortableError(`${where}: invalid user handle`);
  const ks = list(v.keys, `${where}.keys`, 10).map((p, i) => {
    const w = `${where}.keys[${i}]`;
    keys(p, w, ['id', 'name', 'publicKey', 'alg', 'signCount', 'transports', 'backupEligible', 'backedUp', 'created', 'lastUsed']);
    if (typeof p.id !== 'string' || p.id.length < 16 || p.id.length > 1400 || !B64URL.test(p.id)) throw new PortableError(`${w}: invalid credential id`);
    if (typeof p.publicKey !== 'string' || p.publicKey.length > 2000 || !B64URL.test(p.publicKey)) throw new PortableError(`${w}: invalid public key`);
    if (![-7, -8, -257].includes(p.alg)) throw new PortableError(`${w}: unsupported algorithm`);
    if (!Number.isSafeInteger(p.signCount) || p.signCount < 0) throw new PortableError(`${w}: invalid counter`);
    if (!Array.isArray(p.transports) || p.transports.length > 10 || p.transports.some((t) => typeof t !== 'string' || !/^[a-z-]{1,20}$/.test(t))) throw new PortableError(`${w}: invalid transports`);
    if (typeof p.backupEligible !== 'boolean' || typeof p.backedUp !== 'boolean') throw new PortableError(`${w}: invalid flags`);
    if (!Number.isSafeInteger(p.created) || !intOrNull(p.lastUsed)) throw new PortableError(`${w}: invalid dates`);
    return { id: p.id, name: labelOf(p.name, w), publicKey: p.publicKey, alg: p.alg, signCount: p.signCount, transports: p.transports, backupEligible: p.backupEligible, backedUp: p.backedUp, created: p.created, lastUsed: p.lastUsed };
  });
  const codes = list(v.recoveryCodes, `${where}.recoveryCodes`, 20);
  if (codes.some((c) => typeof c !== 'string' || !HEX64.test(c))) throw new PortableError(`${where}.recoveryCodes: invalid code hash`);
  if (new Set(ks.map((p) => p.id)).size !== ks.length) throw new PortableError(`${where}.keys: a passkey appears twice`);
  return { mfa: v.mfa, handle: v.handle, keys: ks, recoveryCodes: [...new Set(codes)] };
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

function user(v, i) {
  const where = `users[${i}]`;
  keys(v, where, ['username'], ['credentials', 'config', 'apiKeys', 'passkeys']);
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
  if (v.config !== undefined) {
    if (isObj(v.config) && Object.prototype.hasOwnProperty.call(v.config, 'role')) {
      keys(v.config, `${where}.config`, ['role']);
      if (typeof v.config.role !== 'string' || !v.config.role.trim() || v.config.role.length > ROLE_NAME_MAX) throw new PortableError(`${where}.config: invalid role`);
      out.config = { role: v.config.role.trim() };
    } else {
      // Before roles: per-user limits, quotas and viewer rules. Checked, then ignored.
      keys(v.config, `${where}.config`, ['limits', 'quotas', 'viewerRules']);
      limitsBlock(v.config.limits, `${where}.config.limits`);
      quotas(v.config.quotas, `${where}.config.quotas`);
      viewerRules(v.config.viewerRules, `${where}.config.viewerRules`);
      out.config = { legacy: true };
    }
  }
  if (v.apiKeys !== undefined) out.apiKeys = list(v.apiKeys, `${where}.apiKeys`, 1000).map((k, j) => apiKey(k, `${where}.apiKeys[${j}]`));
  if (v.passkeys !== undefined) out.passkeys = passkeyBlock(v.passkeys, `${where}.passkeys`);
  if (!out.credentials && !out.config && !out.apiKeys && !out.passkeys) throw new PortableError(`${where}: nothing to import`);
  return out;
}

/** Validate an untrusted export document → a clean copy, or throw PortableError. */
export function validateExport(doc) {
  keys(doc, 'document', ['format', 'created', 'users'], ['system', 'origin']);
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
  return out;
}

/**
 * Validate the import decisions: { system: bool, users: { [username]: { as?, overwrite? } } }.
 * A user absent from `users` is skipped.
 */
export function validateDecisions(d, doc) {
  keys(d, 'decisions', ['system', 'users']);
  // system: true (every part in the file), false, or { part: bool } for some.
  let sysParts = [];
  if (d.system === true) sysParts = doc.system ? doc.system.parts : [];
  else if (isObj(d.system)) {
    keys(d.system, 'decisions.system', [], SYSTEM_PARTS);
    for (const [k, on] of Object.entries(d.system)) {
      if (typeof on !== 'boolean') throw new PortableError(`decisions.system.${k} must be true or false`);
      if (on && !(doc.system && doc.system.parts.includes(k))) throw new PortableError(`the document has no "${k}" part`);
      if (on) sysParts.push(k);
    }
  } else if (d.system !== false) throw new PortableError('decisions.system must be true, false or a list of parts');
  if (d.system === true && !doc.system) throw new PortableError('the document has no system configuration');
  keys(d.users, 'decisions.users', [], Object.keys(d.users ?? {}));
  const names = new Set(doc.users.map((u) => u.username));
  const out = { system: sysParts.length > 0, systemParts: new Set(sysParts), users: new Map() };
  const targets = new Set();
  for (const [name, choice] of Object.entries(d.users)) {
    if (!names.has(name)) throw new PortableError(`decisions.users: "${name.slice(0, 64)}" is not in the document`);
    keys(choice, `decisions.users.${name}`, [], ['as', 'overwrite', 'parts']);
    const as = choice.as === undefined ? name : choice.as;
    if (typeof as !== 'string' || !USERNAME_RE.test(as)) throw new PortableError(`decisions.users.${name}: invalid target username`);
    if (choice.overwrite !== undefined && typeof choice.overwrite !== 'boolean') throw new PortableError(`decisions.users.${name}: overwrite must be true or false`);
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
    out.users.set(name, { as, overwrite: choice.overwrite === true, parts: new Set(parts) });
  }
  return out;
}
