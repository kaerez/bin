// publicapi.js — /api/public/*: anonymous share creation for the built-in
// public account, when the admin has enabled it (off by default). Creation
// reuses the account handlers (src/routes/private.js) with the public account
// as the creator; the only differences are who is counted for the quotas and
// that nothing here ever signs anyone in.
//
// Counting ("public.tracking", see src/lib/settings.js):
//   tracker          — a random, HMAC-tagged id the server issues (stateless
//                      until it first creates a share); the browser keeps it
//                      in four places (the __Host-secbin_aid cookie, the ETag
//                      of GET /api/public/t, localStorage, IndexedDB). A
//                      missing or corrupt copy is re-seeded from the others;
//                      an unresolvable tie (two ids that both created shares)
//                      blocks the browser.
//   ip               — a keyed hash of the network (IPv6 per guard.v6Prefix).
//   both-permissive  — both; refused only when both are over a quota.
//   both-restrictive — both; refused when either is over a quota.

import { json, err, methodNotAllowed, decodePathSegment, assertNotCrossSite } from '../lib/http.js';
import { directory, ipContext, isBlocked, recordFailure } from '../lib/guard.js';
import { parseId } from '../lib/ids.js';
import { createNote, initFile, putChunk, finalizeFile } from './private.js';
import { PUBLIC_ID } from '../directory-do.js';
import { requireTurnstile, TURNSTILE_ACTIONS } from '../lib/turnstile.js';

export const TRACKER_COOKIE = '__Host-secbin_aid';
const TRACKER_RE = /^[A-Za-z0-9_-]{32}$/;
const TRACKER_MAX_AGE = 400 * 86400; // browsers cap cookie lifetimes at 400 days

const usesTracker = (mode) => mode !== 'ip';
const usesIp = (mode) => mode !== 'tracker';

function cookieValue(request, name) {
  for (const part of (request.headers.get('cookie') || '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return '';
}

/** "ls=<id>;idb=<id>" (the client's own copies) → [{ src, value }], one per source. */
function clientCopies(request) {
  const out = [];
  const seen = new Set();
  for (const part of (request.headers.get('x-secbin-aid-copies') || '').slice(0, 200).split(';')) {
    const [src, value] = part.split('=');
    if ((src === 'ls' || src === 'idb') && value && !seen.has(src)) { seen.add(src); out.push({ src, value: value.trim() }); }
  }
  return out;
}

const trackerCookie = (id) => `${TRACKER_COOKIE}=${id}; Max-Age=${TRACKER_MAX_AGE}; Path=/; Secure; HttpOnly; SameSite=Strict`;

async function blocked(env, g) {
  const b = await isBlocked(env, g, 'invalid');
  return b.blocked ? err(429, 'blocked', 'Too many invalid requests from your network. Try again later.') : null;
}

export async function handlePublicApi(request, env, url) {
  const p = url.pathname;
  const dir = directory(env);

  if (p === '/api/public/profile') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    const prof = await dir.publicProfile();
    if (!prof.enabled) return json({ enabled: false });
    return json(prof);
  }

  const g = await ipContext(env, request);
  const stop = await blocked(env, g);
  if (stop) return stop;
  const settings = g.settings;
  if (!settings['public.enabled']) return err(403, 'public_disabled', 'Anonymous sharing is not enabled on this server.');
  const mode = settings['public.tracking'];

  // ── the tracker: resolve every copy, re-seed them all ────────────────────
  if (p === '/api/public/t') {
    if (request.method !== 'GET') return methodNotAllowed('GET');
    if (!usesTracker(mode)) return json({ mode, aid: null });
    const etag = (request.headers.get('if-none-match') || '').replace(/^W\//, '').replace(/"/g, '').trim();
    const candidates = [
      { src: 'cookie', value: cookieValue(request, TRACKER_COOKIE) },
      { src: 'etag', value: etag },
      ...clientCopies(request),
    ];
    const r = await dir.resolveTracker({ candidates });
    if (!r.ok) {
      if (r.error === 'tracker_conflict') await recordFailure(env, g, 'invalid');
      return err(r.status, r.error, r.message);
    }
    const headers = {
      'set-cookie': trackerCookie(r.id),
      etag: `"${r.id}"`,
      // Kept by the browser and revalidated on every visit: the ETag is one of
      // the copies. `private` keeps it out of shared caches.
      'cache-control': 'private, no-cache, max-age=31536000',
      vary: 'Cookie',
    };
    if (etag === r.id && r.status === 'ok') return new Response(null, { status: 304, headers });
    const res = json({ mode, aid: r.id, status: r.status });
    // set, not append: the JSON default is no-store, which would stop the
    // browser from keeping the ETag copy.
    for (const [k, v] of Object.entries(headers)) res.headers.set(k, v);
    return res;
  }

  // ── creation (the account handlers, as the public account) ───────────────
  const subjects = async () => {
    const keys = [];
    if (usesTracker(mode)) {
      // The id arrives twice — the HttpOnly cookie and a header set by the
      // page — and both must agree (a cross-site form cannot set the header).
      const c = cookieValue(request, TRACKER_COOKIE);
      const h = request.headers.get('x-secbin-aid') || '';
      if (!TRACKER_RE.test(c) || c !== h) return { error: err(428, 'tracker_required', 'Reload the page to continue.') };
      const t = await dir.trackerSubject(c, g.key);
      if (!t.ok) return { error: err(t.status, t.error, t.message) };
      keys.push(t.subject);
    }
    if (usesIp(mode)) keys.push(await dir.ipSubject(g.key));
    return { keys, mode: mode === 'both-permissive' ? 'all' : 'any' };
  };
  const asPublic = async () => {
    const s = await subjects();
    if (s.error) return s;
    // Labels are the sender's private notes; anonymous senders have none.
    return { a: { user: { id: PUBLIC_ID, role: 'public' }, channel: 'all', subjects: s, noLabel: true } };
  };

  if (p === '/api/public/paste' || p === '/api/public/file') {
    if (request.method !== 'POST') return methodNotAllowed('POST');
    assertNotCrossSite(request);
    // Chunks and finalize ride on the upload token; only starting a share is checked.
    await requireTurnstile(env, request, TURNSTILE_ACTIONS.public);
    const { a, error } = await asPublic();
    if (error) return error;
    const res = await (p.endsWith('paste') ? createNote(request, env, a) : initFile(request, env, a));
    // The admin's "shares" count per tracker: successful creations only.
    if (res.status === 201) {
      const t = a.subjects.keys.find((k) => k.startsWith('pub:t:'));
      if (t) await dir.trackerUsed(t);
    }
    return res;
  }
  const fm = p.match(/^\/api\/public\/file\/([^/]+)\/(chunk|finalize)(?:\/(\d{1,6}))?$/);
  if (fm) {
    const id = decodePathSegment(fm[1]);
    const info = id && parseId(id);
    if (!info || !info.file) return err(404, 'not_found', 'Not found.');
    // The upload token is the capability here; the quota was charged at init.
    const a = { user: { id: PUBLIC_ID, role: 'public' }, channel: 'all', noLabel: true };
    if (fm[2] === 'chunk' && fm[3] !== undefined) {
      if (request.method !== 'PUT') return methodNotAllowed('PUT');
      return putChunk(request, env, a, id, Number(fm[3]));
    }
    if (fm[2] === 'finalize' && fm[3] === undefined) {
      if (request.method !== 'POST') return methodNotAllowed('POST');
      return finalizeFile(request, env, a, id);
    }
  }
  return err(404, 'not_found', 'Not found.');
}
