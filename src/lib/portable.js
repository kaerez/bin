// portable.js — the admin export/import document ("secbin-export/v1") and its
// fail-closed validation. The document is only ever stored or transmitted
// encrypted (public/js/exportcrypt.js: passphrase → Argon2id → AES-256-GCM in
// the browser); the Worker sees it in plaintext only inside an owner's
// authenticated export/import request, and re-validates every field on import
// with the same checkers the admin API uses.
//
// What it can hold:
//   system  — settings, the Default role (global limits for the all and API
//             channels, quotas, viewer rules), IP rules, and the custom roles
//             (each with its own limits, quotas and viewer rules);
//   users[] — per user: `credentials` (username is always present; salt, t,
//             verifier, disabled) and/or `config` ({ role }: the role's name,
//             "Default" for the Default role). Files from before roles carry
//             per-user limits in `config`; they are accepted and ignored.
// Never: the owner account, sessions, API keys, shares, usage counters or the
// activity log.

import { checkSetting, checkLimit, checkQuota, checkViewerRule } from './settings.js';
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
    for (const [k, val] of Object.entries(v[ch])) out[ch][k] = wrap(`${where}.${ch}.${short(k)}`, () => checkLimit(k, val, ch));
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

function system(v) {
  keys(v, 'system', ['settings', 'limits', 'quotas', 'viewerRules', 'ipRules'], ['roles']);
  keys(v.settings, 'system.settings', [], Object.keys(v.settings ?? {}));
  const settings = {};
  for (const [k, val] of Object.entries(v.settings)) settings[k] = wrap(`system.settings.${short(k)}`, () => checkSetting(k, val));
  if (settings['session.idleSec'] !== undefined && settings['session.absSec'] !== undefined && settings['session.idleSec'] > settings['session.absSec']) {
    throw new PortableError('system.settings: the idle timeout cannot exceed the absolute timeout');
  }
  return {
    settings,
    limits: limitsBlock(v.limits, 'system.limits'),
    quotas: quotas(v.quotas, 'system.quotas'),
    viewerRules: viewerRules(v.viewerRules, 'system.viewerRules'),
    ipRules: list(v.ipRules, 'system.ipRules', 1000).map((r, i) => ipRule(r, `system.ipRules[${i}]`)),
    roles: v.roles === undefined ? [] : uniqueRoles(list(v.roles, 'system.roles', MAX_ROLES).map(role)),
  };
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
  keys(v, where, ['username'], ['credentials', 'config']);
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
  if (!out.credentials && !out.config) throw new PortableError(`${where}: nothing to import (no credentials or config)`);
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
  if (typeof d.system !== 'boolean') throw new PortableError('decisions.system must be true or false');
  if (d.system && !doc.system) throw new PortableError('the document has no system configuration');
  keys(d.users, 'decisions.users', [], Object.keys(d.users ?? {}));
  const names = new Set(doc.users.map((u) => u.username));
  const out = { system: d.system, users: new Map() };
  const targets = new Set();
  for (const [name, choice] of Object.entries(d.users)) {
    if (!names.has(name)) throw new PortableError(`decisions.users: "${name.slice(0, 64)}" is not in the document`);
    keys(choice, `decisions.users.${name}`, [], ['as', 'overwrite']);
    const as = choice.as === undefined ? name : choice.as;
    if (typeof as !== 'string' || !USERNAME_RE.test(as)) throw new PortableError(`decisions.users.${name}: invalid target username`);
    if (choice.overwrite !== undefined && typeof choice.overwrite !== 'boolean') throw new PortableError(`decisions.users.${name}: overwrite must be true or false`);
    if (targets.has(as.toLowerCase())) throw new PortableError(`two users would be imported as "${as}"`);
    targets.add(as.toLowerCase());
    out.users.set(name, { as, overwrite: choice.overwrite === true });
  }
  return out;
}
