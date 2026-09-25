// config.js — tolerant readers for the deployment's environment variables.
//
// Every variable is optional. A missing, empty or malformed value never throws:
// the feature that needs it is simply unavailable and the API says so clearly
// (e.g. setup disabled, "server not configured"). Values are secrets — never
// log or echo them.

const HEX64 = /^[0-9a-f]{64}$/i;

/** AUTHN (owner setup/recovery token): ≥ 32 characters, else null (setup disabled). */
export function authnToken(env) {
  const v = typeof env?.AUTHN === 'string' ? env.AUTHN.trim() : '';
  return v.length >= 32 && v.length <= 1024 ? v : null;
}

const keyCache = new Map();

/**
 * SIG / ENC session keys: each exactly 64 hex chars (32 bytes, e.g. from
 * `openssl rand -hex 32`) and different from each other. Returns
 * { sig: Uint8Array, enc: Uint8Array } or null when unconfigured/invalid.
 */
export function sessionKeys(env) {
  const sig = typeof env?.SIG === 'string' ? env.SIG.trim() : '';
  const enc = typeof env?.ENC === 'string' ? env.ENC.trim() : '';
  if (!HEX64.test(sig) || !HEX64.test(enc) || sig.toLowerCase() === enc.toLowerCase()) return null;
  const cacheKey = `${sig}:${enc}`;
  let v = keyCache.get(cacheKey);
  if (!v) {
    v = { sig: fromHex(sig), enc: fromHex(enc), id: cacheKey };
    keyCache.clear();
    keyCache.set(cacheKey, v);
  }
  return v;
}

function fromHex(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

/** "true" (any case, surrounding whitespace ignored) → true; anything else → false. */
export function envFlag(env, name) {
  const v = env?.[name];
  return typeof v === 'string' ? v.trim().toLowerCase() === 'true' : v === true;
}

/** Brute-force-protection kill switches (default: protections ON). */
export function bfpDisabled(env) {
  const all = envFlag(env, 'DISABLE_BFP');
  return { all, setup: all || envFlag(env, 'DISABLE_BFP_SETUP') };
}

/**
 * A required Cloudflare binding (KV, R2, Durable Object namespace). A missing
 * or wrong-typed binding is a deployment error: answer a clear 503 naming the
 * binding instead of throwing a TypeError deep inside a handler.
 */
const BINDING_SHAPE = {
  PASTES: 'get', FILES: 'put', BURN: 'idFromName', FILESHARE: 'idFromName', DIRECTORY: 'idFromName', GUARD: 'idFromName',
};

export class BindingMissing extends Error {
  constructor(name) {
    super(`binding ${name} is not configured`);
    this.name = 'BindingMissing';
    this.binding = name;
  }
}

export function binding(env, name) {
  const b = env?.[name];
  const method = BINDING_SHAPE[name];
  if (!b || (method && typeof b[method] !== 'function')) throw new BindingMissing(name);
  return b;
}
