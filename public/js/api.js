// api.js — same-origin fetch client (connect-src 'self') for the public share
// API, the auth API and the signed-in /api/private API. Real HTTP status codes;
// success bodies are shape-checked at this trust boundary so a server/proxy
// regression fails closed as a protocol error instead of leaking into UI state.

export class ApiError extends Error {
  constructor(message, status, code, extra) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code || null;
    this.extra = extra || {};
  }
}

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const malformed = () => new ApiError('Malformed response from the server.', 502, 'malformed');
const INTENT = { 'x-secbin-intent': '1' };

async function readJson(res) {
  try { return await res.json(); } catch { return null; }
}

async function request(path, { method = 'GET', body, headers = {}, raw = false } = {}) {
  const init = { method, headers: { ...headers }, cache: 'no-store', credentials: 'same-origin', redirect: 'manual' };
  if (body !== undefined) {
    init.headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetch(path, init);
  if (res.type === 'opaqueredirect') throw new ApiError('Please log in.', 401, 'unauthenticated');
  if (raw && res.ok) return res;
  const data = await readJson(res);
  if (!res.ok) {
    const d = isPlainObject(data) ? data : {};
    throw new ApiError(typeof d.message === 'string' && d.message ? d.message : `Request failed (${res.status}).`, res.status, typeof d.error === 'string' ? d.error : null, d);
  }
  if (!isPlainObject(data)) throw malformed();
  return data;
}

const enc = encodeURIComponent;

// ── public share API ──────────────────────────────────────────────────────────
export const fetchConfig = () => request('/api/config');
export const fetchHead = (kind, id) => request(`/api/${kind}/${enc(id)}`);

/** Open a note or file share with its access proofs (the only way to get ciphertext). */
export const openShare = (kind, id, { linkProof, keyProof }) =>
  request(`/api/${kind}/${enc(id)}/open`, { method: 'POST', headers: { 'x-link-proof': linkProof, 'x-key-proof': keyProof } });

/**
 * "Delete now" as a recipient (the sender allowed it): the same two access
 * proofs as opening; spends no view.
 */
export const expireShare = (kind, id, { linkProof, keyProof }) =>
  request(`/api/${kind}/${enc(id)}/expire`, { method: 'POST', headers: { 'x-link-proof': linkProof, 'x-key-proof': keyProof } });

/** One encrypted chunk of a file share, under a download grant. */
export async function fetchChunk(id, i, grant) {
  const res = await request(`/api/file/${enc(id)}/chunk/${i}`, { headers: { 'x-download-grant': grant }, raw: true });
  return new Uint8Array(await res.arrayBuffer());
}

/** Delete with the delete token (header, never URL). */
export const deleteShare = (kind, id, token) =>
  request(`/api/${kind}/${enc(id)}`, { method: 'DELETE', headers: { 'x-delete-token': token } });

// ── auth ─────────────────────────────────────────────────────────────────────
export const session = () => request('/api/auth/session');
export const setupStatus = () => request('/api/auth/setup');
export const setup = (body) => request('/api/auth/setup', { method: 'POST', body });
export const prelogin = (username) => request('/api/auth/prelogin', { method: 'POST', body: { username } });
export const login = (username, proof) => request('/api/auth/login', { method: 'POST', body: { username, proof } });
export const logout = () => request('/api/auth/logout', { method: 'POST', headers: INTENT });

// ── signed-in ────────────────────────────────────────────────────────────────
export const me = () => request('/api/private/me');
export const changePassword = (body) => request('/api/private/me/password', { method: 'POST', body });
export const myActivity = (before) => request(`/api/private/me/activity${before ? `?before=${enc(before)}` : ''}`);
export const listKeys = () => request('/api/private/me/keys');
export const createKey = (name, expiresInSec) => request('/api/private/me/keys', { method: 'POST', body: { name, expiresInSec } });
export const revokeKey = (id) => request(`/api/private/me/keys/${enc(id)}`, { method: 'DELETE', headers: INTENT });

export async function createNote(paste, label) {
  const d = await request('/api/private/paste', { method: 'POST', body: { paste, label } });
  if (typeof d.id !== 'string' || typeof d.deletetoken !== 'string') throw malformed();
  return d;
}

export const initFileShare = (body) => request('/api/private/file', { method: 'POST', body });
export const finalizeFileShare = (id, uploadToken, paste, label) =>
  request(`/api/private/file/${enc(id)}/finalize`, { method: 'POST', headers: { 'x-upload-token': uploadToken }, body: { paste, label } });

export const listShares = (qs = '') => request(`/api/private/shares${qs}`);
export const updateShare = (id, body) => request(`/api/private/shares/${enc(id)}`, { method: 'PATCH', body });
export const revokeShare = (id) => request(`/api/private/shares/${enc(id)}/revoke`, { method: 'POST', headers: INTENT });

// ── admin ────────────────────────────────────────────────────────────────────
const A = '/api/private/admin';
export const admin = {
  overview: () => request(`${A}/overview`),
  settings: (patch) => request(`${A}/settings`, { method: 'PATCH', body: patch }),
  limits: (scope, channel, patch) => request(`${A}/limits`, { method: 'PATCH', body: { scope, channel, patch } }),
  quotas: (scope, list) => request(`${A}/quotas`, { method: 'PUT', body: { scope, list } }),
  viewerRules: (scope, list) => request(`${A}/viewer-rules`, { method: 'PUT', body: { scope, list } }),
  users: () => request(`${A}/users`),
  user: (id) => request(`${A}/users/${enc(id)}`),
  createUser: (body) => request(`${A}/users`, { method: 'POST', body }),
  updateUser: (id, body) => request(`${A}/users/${enc(id)}`, { method: 'PATCH', body }),
  deleteUser: (id, revokeShares) => request(`${A}/users/${enc(id)}${revokeShares ? '?revokeShares=1' : ''}`, { method: 'DELETE', headers: INTENT }),
  setPassword: (id, body) => request(`${A}/users/${enc(id)}/password`, { method: 'POST', body }),
  unlock: (id) => request(`${A}/users/${enc(id)}/unlock`, { method: 'POST', headers: INTENT }),
  impersonate: (id) => request(`${A}/users/${enc(id)}/impersonate`, { method: 'POST', headers: INTENT }),
  revokeUserKey: (id, keyId) => request(`${A}/users/${enc(id)}/keys/${enc(keyId)}`, { method: 'DELETE', headers: INTENT }),
  unimpersonate: () => request(`${A}/unimpersonate`, { method: 'POST', headers: INTENT }),
  audit: (before, user) => request(`${A}/audit?${new URLSearchParams({ ...(before ? { before } : {}), ...(user ? { user } : {}) })}`),
  guard: () => request(`${A}/guard`),
  unblock: (scope, key) => request(`${A}/guard/unblock`, { method: 'POST', body: { scope, key } }),
  block: (scope, key, seconds) => request(`${A}/guard/block`, { method: 'POST', body: { scope, key, seconds } }),
  ipRules: () => request(`${A}/ip-rules`),
  addIpRule: (body) => request(`${A}/ip-rules`, { method: 'POST', body }),
  removeIpRule: (id) => request(`${A}/ip-rules/${enc(id)}`, { method: 'DELETE', headers: INTENT }),
  shares: (qs) => request(`${A}/shares?${qs}`),
  updateShare: (id, patch) => request(`${A}/shares/${enc(id)}`, { method: 'PATCH', body: patch }),
  revokeShare: (id) => request(`${A}/shares/${enc(id)}/revoke`, { method: 'POST', headers: INTENT }),
  lockShare: (id, locked) => request(`${A}/shares/${enc(id)}/lock`, { method: 'POST', body: { locked } }),
};

/** Binary chunk upload (kept separate: `request` is JSON-only). */
export async function uploadChunk(id, i, bytes, uploadToken) {
  const res = await fetch(`/api/private/file/${enc(id)}/chunk/${i}`, {
    method: 'PUT', body: bytes, cache: 'no-store', credentials: 'same-origin', redirect: 'manual',
    headers: { 'content-type': 'application/octet-stream', 'x-upload-token': uploadToken },
  });
  if (res.type === 'opaqueredirect') throw new ApiError('Please log in.', 401, 'unauthenticated');
  const data = await readJson(res);
  if (!res.ok) throw new ApiError((data && data.message) || `Upload failed (${res.status}).`, res.status, data && data.error);
  return data;
}
