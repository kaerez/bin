// tracker.js — the anonymous-creator identifier used for public-access limits
// (only when the admin enabled public access and a tracker-based counting mode;
// see SECURITY.md "Public access"). The id is random, issued by the server, and
// kept in four places: the HttpOnly cookie and the ETag of GET /api/public/t
// (both handled by the browser), plus localStorage and IndexedDB (here). On
// every visit all copies are sent; the server returns the one that wins, and
// every missing or corrupt copy is re-seeded from it. In "ip" mode nothing is
// stored and any old copies are removed.

import { ApiError } from './api.js';

const KEY = 'secbin_aid';
const ID_RE = /^[A-Za-z0-9_-]{32}$/;

const lsGet = () => { try { return localStorage.getItem(KEY); } catch { return null; } };
const lsSet = (v) => { try { if (v) localStorage.setItem(KEY, v); else localStorage.removeItem(KEY); } catch { /* storage off */ } };

function idb(mode, fn) {
  return new Promise((resolve) => {
    let req;
    try { req = indexedDB.open('secbin', 1); } catch { resolve(null); return; }
    req.onupgradeneeded = () => { req.result.createObjectStore('kv'); };
    req.onerror = () => resolve(null);
    req.onsuccess = () => {
      try {
        const tx = req.result.transaction('kv', mode);
        const r = fn(tx.objectStore('kv'));
        tx.oncomplete = () => { req.result.close(); resolve(r && 'result' in r ? r.result : null); };
        tx.onerror = () => { req.result.close(); resolve(null); };
      } catch { resolve(null); }
    };
  });
}
const idbGet = () => idb('readonly', (s) => s.get(KEY));
const idbSet = (v) => idb('readwrite', (s) => (v ? s.put(v, KEY) : s.delete(KEY)));

/** Resolve (and re-seed) the tracker → { mode, aid } — aid is null in "ip" mode. Throws ApiError. */
export async function ensureTracker() {
  const copies = [];
  const ls = lsGet();
  if (ls && ID_RE.test(ls)) copies.push(`ls=${ls}`);
  else if (ls) copies.push('ls=corrupt');
  const db = await idbGet();
  if (typeof db === 'string' && ID_RE.test(db)) copies.push(`idb=${db}`);
  else if (db) copies.push('idb=corrupt');
  // "no-cache": the browser revalidates its stored copy with If-None-Match
  // (the ETag copy); a 304 hands back the cached body.
  const res = await fetch('/api/public/t', {
    cache: 'no-cache', credentials: 'same-origin', redirect: 'error',
    headers: copies.length ? { 'x-secbin-aid-copies': copies.join(';') } : {},
  });
  let data = null;
  try { data = await res.json(); } catch { /* handled below */ }
  if (!res.ok || !data || typeof data !== 'object') {
    throw new ApiError((data && data.message) || `Request failed (${res.status}).`, res.status, data && data.error);
  }
  const aid = typeof data.aid === 'string' && ID_RE.test(data.aid) ? data.aid : null;
  lsSet(aid);
  await idbSet(aid);
  return { mode: data.mode, aid };
}
