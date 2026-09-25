// store.js — storage layer for notes. Unlimited-view notes live in KV (native
// TTL); view-limited notes live in the BurnPaste Durable Object (atomic open);
// file shares live in FileShare DOs + R2 (see fileshare-do.js). The stored
// delete-token hash (`dth`) and access-proof hashes (`acc`) are kept alongside
// the paste and never returned to a reader. See SPEC.md §7–§9.

import { expireSeconds } from '../../public/js/format.js';
import { binding } from './config.js';

export const MAX_BODY = 4 * 1024 * 1024; // 4 MiB request-body cap

// SQLite-backed DO storage caps a serialized value at ~2 MB — below what
// MAX_CT_B64 admits — so view-limited records are capped with headroom and the
// create path can answer a clean 413 instead of storage.put throwing.
export const MAX_BURN_RECORD = 1900000;

export function ttlSeconds(expire) {
  return expireSeconds(expire) ?? 0;
}

// ── KV (unlimited-view notes) ─────────────────────────────────────────────────

// Best-effort only: KV is eventually consistent; the 128-bit CSPRNG id is what
// guarantees uniqueness.
export async function kvExists(env, id) {
  return (await binding(env, 'PASTES').get(id)) !== null;
}

/** record = { paste, dth, acc }; ttl in seconds (≥ 60). */
export async function kvPut(env, id, record, ttl) {
  await binding(env, 'PASTES').put(id, JSON.stringify(record), ttl > 0 ? { expirationTtl: ttl } : {});
}

/** Returns { paste, dth, acc } or null. Corrupt and pre-v2 records are treated as missing. */
export async function kvGet(env, id) {
  const raw = await binding(env, 'PASTES').get(id);
  if (raw === null) return null;
  try {
    const rec = JSON.parse(raw);
    if (rec && typeof rec === 'object' && rec.paste && rec.acc && rec.paste.v === 2) return rec;
  } catch { /* fall through */ }
  return null;
}

export async function kvDelete(env, id) {
  await binding(env, 'PASTES').delete(id);
}

// ── Durable Objects ───────────────────────────────────────────────────────────

export function burnStub(env, id) {
  const ns = binding(env, 'BURN');
  return ns.get(ns.idFromName(id));
}

export function fileStub(env, id) {
  const ns = binding(env, 'FILESHARE');
  return ns.get(ns.idFromName(id));
}
