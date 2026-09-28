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
// A Turnstile token (public/js/turnstile.js), where the server asks for one.
const human = (token) => (token ? { 'x-secbin-turnstile': token } : {});

async function readJson(res) {
  try { return await res.json(); } catch { return null; }
}

async function request(path, { method = 'GET', body, headers = {}, raw = false, signal } = {}) {
  const init = { method, headers: { ...headers }, cache: 'no-store', credentials: 'same-origin', redirect: 'manual', ...(signal ? { signal } : {}) };
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

/** Chunk `i` of file `ref` of a Drive share (manifest v3), under a download grant. */
export async function fetchRefChunk(id, ref, i, grant) {
  const res = await request(`/api/file/${enc(id)}/chunk/${ref}/${i}`, { headers: { 'x-download-grant': grant }, raw: true });
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
export const login = (username, proof, turnstile) => request('/api/auth/login', { method: 'POST', headers: human(turnstile), body: { username, proof } });
export const logout = () => request('/api/auth/logout', { method: 'POST', headers: INTENT });
// Passkeys (public/js/passkeys.js does the WebAuthn part).
export const passkeyLoginOptions = () => request('/api/auth/passkey/options', { method: 'POST', body: {} });
export const passkeyLogin = (challengeId, credential, turnstile) => request('/api/auth/passkey/login', { method: 'POST', headers: human(turnstile), body: { challengeId, credential } });
export const recoveryLogin = (username, code, turnstile) => request('/api/auth/recovery', { method: 'POST', headers: human(turnstile), body: { username, code } });
export const secondFactor = (body) => request('/api/auth/second-factor', { method: 'POST', body });

// ── signed-in ────────────────────────────────────────────────────────────────
export const me = () => request('/api/private/me');
export const changePassword = (body, turnstile) => request('/api/private/me/password', { method: 'POST', headers: human(turnstile), body });
export const myActivity = (before) => request(`/api/private/me/activity${before ? `?before=${enc(before)}` : ''}`);
export const listKeys = () => request('/api/private/me/keys');
// Changes to one's own account carry a confirmation `step`: { current } (a
// password proof) or { reauth: { challengeId, credential } } (a passkey), and
// a Turnstile token (one per request) when the server has the human check on.
export const reauthOptions = () => request('/api/private/me/reauth', { method: 'POST', body: {} });
export const changeUsername = (username, step, turnstile) => request('/api/private/me/username', { method: 'POST', headers: human(turnstile), body: { username, ...step } });
export const createKey = (name, expiresInSec, scopes, step, turnstile) => request('/api/private/me/keys', { method: 'POST', headers: human(turnstile), body: { name, expiresInSec, scopes, ...step } });
export const updateKey = (id, patch, step, turnstile) => request(`/api/private/me/keys/${enc(id)}`, { method: 'PATCH', headers: human(turnstile), body: { ...patch, ...step } });
export const revokeKey = (id, step, turnstile) => request(`/api/private/me/keys/${enc(id)}`, { method: 'DELETE', headers: { ...INTENT, ...human(turnstile) }, body: { ...step } });
export const myPasskeys = () => request('/api/private/me/passkeys');
export const passkeyRegisterOptions = () => request('/api/private/me/passkeys/options', { method: 'POST', body: {} });
export const addPasskey = (body, turnstile) => request('/api/private/me/passkeys', { method: 'POST', headers: human(turnstile), body });
export const removePasskey = (id, step, turnstile) => request(`/api/private/me/passkeys/${enc(id)}/remove`, { method: 'POST', headers: human(turnstile), body: { ...step } });
export const regenerateRecoveryCodes = (step, turnstile) => request('/api/private/me/recovery-codes', { method: 'POST', headers: human(turnstile), body: { ...step } });
export const setSecondFactor = (on, step, turnstile) => request('/api/private/me/second-factor', { method: 'POST', headers: human(turnstile), body: { on, ...step } });

export async function createNote(paste, label) {
  const d = await request('/api/private/paste', { method: 'POST', body: { paste, label } });
  if (typeof d.id !== 'string' || typeof d.deletetoken !== 'string') throw malformed();
  return d;
}

export const initFileShare = (body) => request('/api/private/file', { method: 'POST', body });
export const finalizeFileShare = (id, uploadToken, paste, label) =>
  request(`/api/private/file/${enc(id)}/finalize`, { method: 'POST', headers: { 'x-upload-token': uploadToken }, body: { paste, label } });

export const listShares = (qs = '') => request(`/api/private/shares${qs}`);
export const shareOpens = (id) => request(`/api/private/shares/${encodeURIComponent(id)}/opens`);
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
  roles: () => request(`${A}/roles`),
  role: (id) => request(`${A}/roles/${enc(id)}`),
  createRole: (body) => request(`${A}/roles`, { method: 'POST', body }),
  updateRole: (id, patch) => request(`${A}/roles/${enc(id)}`, { method: 'PATCH', body: patch }),
  deleteRole: (id) => request(`${A}/roles/${enc(id)}`, { method: 'DELETE', headers: INTENT }),
  setUserRole: (id, roleId) => request(`${A}/users/${enc(id)}/role`, { method: 'PUT', body: { roleId } }),
  user: (id) => request(`${A}/users/${enc(id)}`),
  createUser: (body) => request(`${A}/users`, { method: 'POST', body }),
  updateUser: (id, body) => request(`${A}/users/${enc(id)}`, { method: 'PATCH', body }),
  deleteUser: (id, revokeShares) => request(`${A}/users/${enc(id)}${revokeShares ? '?revokeShares=1' : ''}`, { method: 'DELETE', headers: INTENT }),
  setPassword: (id, body) => request(`${A}/users/${enc(id)}/password`, { method: 'POST', body }),
  unlock: (id) => request(`${A}/users/${enc(id)}/unlock`, { method: 'POST', headers: INTENT }),
  impersonate: (id) => request(`${A}/users/${enc(id)}/impersonate`, { method: 'POST', headers: INTENT }),
  createUserKey: (id, body) => request(`${A}/users/${enc(id)}/keys`, { method: 'POST', body }),
  updateUserKey: (id, keyId, patch) => request(`${A}/users/${enc(id)}/keys/${enc(keyId)}`, { method: 'PATCH', body: patch }),
  revokeUserKey: (id, keyId) => request(`${A}/users/${enc(id)}/keys/${enc(keyId)}`, { method: 'DELETE', headers: INTENT }),
  resetPasskeys: (id) => request(`${A}/users/${enc(id)}/passkeys`, { method: 'POST', headers: INTENT, body: {} }),
  unimpersonate: () => request(`${A}/unimpersonate`, { method: 'POST', headers: INTENT }),
  clearLogs: (body) => request(`${A}/logs/clear`, { method: 'POST', body }),
  audit: (before, user) => request(`${A}/audit?${new URLSearchParams({ ...(before ? { before } : {}), ...(user ? { user } : {}) })}`),
  guard: () => request(`${A}/guard`),
  turnstile: () => request(`${A}/turnstile`),
  setTurnstile: (body) => request(`${A}/turnstile`, { method: 'PUT', body }),
  unblock: (scope, key) => request(`${A}/guard/unblock`, { method: 'POST', body: { scope, key } }),
  block: (scope, key, seconds) => request(`${A}/guard/block`, { method: 'POST', body: { scope, key, seconds } }),
  ipRules: () => request(`${A}/ip-rules`),
  addIpRule: (body) => request(`${A}/ip-rules`, { method: 'POST', body }),
  removeIpRule: (id) => request(`${A}/ip-rules/${enc(id)}`, { method: 'DELETE', headers: INTENT }),
  shares: (qs) => request(`${A}/shares?${qs}`),
  publicAccess: () => request(`${A}/public`),
  tracker: (id, action) => request(`${A}/public/trackers/${enc(id)}`, { method: 'POST', body: { action } }),
  exportData: (body) => request(`${A}/export`, { method: 'POST', body }),
  importData: (body) => request(`${A}/import`, { method: 'POST', body }),
  updateShare: (id, patch) => request(`${A}/shares/${enc(id)}`, { method: 'PATCH', body: patch }),
  shareOpens: (id) => request(`${A}/shares/${enc(id)}/opens`),
  revokeShare: (id) => request(`${A}/shares/${enc(id)}/revoke`, { method: 'POST', headers: INTENT }),
  lockShare: (id, locked) => request(`${A}/shares/${enc(id)}/lock`, { method: 'POST', body: { locked } }),
};

// ── Drive (docs/DRIVE.md §6; public/js/driveclient.js does the crypto) ──────
const D = '/api/private/drive';
export const drive = {
  state: () => request(D),
  // The user's KEKs for this session (the server derives them; docs/DRIVE.md §3).
  keys: () => request(`${D}/keys`),
  node: (id) => request(`${D}/nodes/${enc(id)}`),
  mkdir: (body) => request(`${D}/folders`, { method: 'POST', headers: INTENT, body }),
  createFile: (body) => request(`${D}/files`, { method: 'POST', headers: INTENT, body }),
  putChunk: (id, i, bytes, uploadToken, signal) => putChunkTo(`${D}/files/${enc(id)}/chunk/${i}`, bytes, uploadToken, signal),
  finalize: (id, uploadToken) => request(`${D}/files/${enc(id)}/finalize`, { method: 'POST', headers: { ...INTENT, 'x-upload-token': uploadToken } }),
  async chunk(id, i, signal) {
    const res = await request(`${D}/files/${enc(id)}/chunk/${i}`, { raw: true, signal });
    return new Uint8Array(await res.arrayBuffer());
  },
  update: (id, patch) => request(`${D}/nodes/${enc(id)}`, { method: 'PATCH', headers: INTENT, body: patch }),
  remove: (id) => request(`${D}/nodes/${enc(id)}`, { method: 'DELETE', headers: INTENT }),
  share: (body) => request(`${D}/shares`, { method: 'POST', headers: INTENT, body }),
  shares: (id) => request(`${D}/nodes/${enc(id)}/shares`),
  // Reverse shares (docs/REVERSE.md §6.1) and the files they received.
  createReverse: (body) => request(`${D}/reverse`, { method: 'POST', headers: INTENT, body }),
  reverse: (folder) => request(`${D}/reverse${folder ? `?folder=${enc(folder)}` : ''}`),
  received: (after = null) => request(`${D}/received${after ? `?after=${enc(after)}` : ''}`),
  acceptReceived: (id, body) => request(`${D}/received/${enc(id)}`, { method: 'POST', headers: INTENT, body }),
  // Received files the browser could not take in: recorded (they leave the queue), listed, put back.
  receivedFailed: (id, reason) => request(`${D}/received/${enc(id)}/failed`, { method: 'POST', headers: INTENT, body: { reason } }),
  receivedFailedList: (after = null) => request(`${D}/received?failed=1${after ? `&after=${enc(after)}` : ''}`),
  receivedRetry: (id) => request(`${D}/received/${enc(id)}/failed`, { method: 'DELETE', headers: INTENT }),
  // The personal kit (docs/DRIVE.md §3.1): its content (with the step-up), a read-only check, a restore.
  kit: (step) => request(`${D}/kit`, { method: 'POST', headers: INTENT, body: { ...step } }),
  kitVerify: (body) => request(`${D}/kit/verify`, { method: 'POST', headers: INTENT, body }),
  kitRestore: (body) => request(`${D}/kit/restore`, { method: 'POST', headers: INTENT, body }),
  kitItems: (mek, after = null) => request(`${D}/kit/items?mek=${enc(mek)}${after ? `&after=${enc(after)}` : ''}`),
  kitItemsPut: (body) => request(`${D}/kit/items`, { method: 'PUT', headers: INTENT, body }),
  // The upgrade of a Drive made before the key model v2 (docs/DRIVE.md §3.3): own, or (the owner) a user's.
  migrate: (uid = null) => request(uid ? `${A}/drive/migrate/${enc(uid)}` : `${D}/migrate`),
  migrateItems: (after = null, uid = null) => request(`${uid ? `${A}/drive/migrate/${enc(uid)}` : `${D}/migrate`}/items${after ? `?after=${enc(after)}` : ''}`),
  migratePut: (body, uid = null) => request(uid ? `${A}/drive/migrate/${enc(uid)}` : `${D}/migrate`, { method: 'PUT', headers: INTENT, body }),
  migrateFinish: (uid = null) => request(`${uid ? `${A}/drive/migrate/${enc(uid)}` : `${D}/migrate`}/finish`, { method: 'POST', headers: INTENT, body: {} }),
  migrateEscrow: (uid) => request(`${A}/drive/migrate/${enc(uid)}/escrow`, { method: 'POST', headers: INTENT, body: {} }),
  migration: () => request(`${A}/drive/migration`),
};

// ── the Drive keyring (Admin → Security → Keys; docs/DRIVE.md §3, §3.1) ───────
const K = `${A}/keys`;
export const keysApi = {
  status: () => request(K),
  usage: () => request(`${K}/usage`),
  candidate: (purpose, step) => request(`${K}/candidate`, { method: 'POST', headers: INTENT, body: { purpose, ...step } }),
  add: (body) => request(`${K}/subs`, { method: 'POST', headers: INTENT, body }),
  edit: (id, body) => request(`${K}/subs/${enc(id)}`, { method: 'PATCH', headers: INTENT, body }),
  setCurrent: (id, step) => request(`${K}/subs/${enc(id)}/current`, { method: 'POST', headers: INTENT, body: { ...step } }),
  show: (id, step) => request(id ? `${K}/subs/${enc(id)}/show` : `${K}/root/show`, { method: 'POST', headers: INTENT, body: { ...step } }),
  remove: (id, step) => request(`${K}/subs/${enc(id)}`, { method: 'DELETE', headers: INTENT, body: { ...step } }),
  changeRoot: (body) => request(`${K}/root`, { method: 'POST', headers: INTENT, body }),
  startJob: (body) => request(`${K}/jobs`, { method: 'POST', headers: INTENT, body }),
  stepJob: () => request(`${K}/jobs/step`, { method: 'POST', headers: INTENT, body: {} }),
  cancelJob: () => request(`${K}/jobs`, { method: 'DELETE', headers: INTENT, body: {} }),
  kit: (step) => request(`${K}/kit`, { method: 'POST', headers: INTENT, body: { ...step } }),
  verify: (body) => request(`${K}/verify`, { method: 'POST', headers: INTENT, body }),
  restore: (body) => request(`${K}/restore`, { method: 'POST', headers: INTENT, body }),
  exportKeys: (body) => request(`${K}/export`, { method: 'POST', headers: INTENT, body }),
  importKeys: (body) => request(`${K}/import`, { method: 'POST', headers: INTENT, body }),
  userView: (uid, body) => request(`${K}/users/${enc(uid)}/view`, { method: 'POST', headers: INTENT, body }),
};

// ── reverse shares: the anonymous uploader (docs/REVERSE.md §6.2) ────────────
const R = (id) => `/api/reverse/${enc(id)}`;
const grantH = (grant) => ({ 'x-reverse-grant': grant });
export const reverseApi = {
  open: (id, linkProof) => request(`${R(id)}/open`, { method: 'POST', headers: { ...INTENT, 'x-link-proof': linkProof } }),
  begin: (id, { linkProof, keyProof, turnstile }) => request(`${R(id)}/begin`, {
    method: 'POST', headers: { ...INTENT, 'x-link-proof': linkProof, ...(keyProof ? { 'x-key-proof': keyProof } : {}), ...human(turnstile) },
  }),
  createFile: (id, grant, body, signal) => request(`${R(id)}/files`, { method: 'POST', headers: grantH(grant), body, signal }),
  putChunk: (id, node, i, bytes, uploadToken, signal) => putChunkTo(`${R(id)}/files/${enc(node)}/chunk/${i}`, bytes, uploadToken, signal),
  finalize: (id, grant, node, uploadToken) => request(`${R(id)}/files/${enc(node)}/finalize`, { method: 'POST', headers: { ...INTENT, ...grantH(grant), 'x-upload-token': uploadToken } }),
  cancel: (id, grant, node, uploadToken) => request(`${R(id)}/files/${enc(node)}`, { method: 'DELETE', headers: { ...INTENT, ...grantH(grant), 'x-upload-token': uploadToken } }),
  done: (id, grant) => request(`${R(id)}/done`, { method: 'POST', headers: { ...INTENT, ...grantH(grant) } }),
};

/** Binary chunk upload (kept separate: `request` is JSON-only). */
export const uploadChunk = (id, i, bytes, uploadToken) => putChunkTo(`/api/private/file/${enc(id)}/chunk/${i}`, bytes, uploadToken);

async function putChunkTo(path, bytes, uploadToken, signal) {
  const res = await fetch(path, {
    method: 'PUT', body: bytes, cache: 'no-store', credentials: 'same-origin', redirect: 'manual',
    headers: { 'content-type': 'application/octet-stream', 'x-upload-token': uploadToken },
    ...(signal ? { signal } : {}),
  });
  if (res.type === 'opaqueredirect') throw new ApiError('Please log in.', 401, 'unauthenticated');
  const data = await readJson(res);
  if (!res.ok) throw new ApiError((data && data.message) || `Upload failed (${res.status}).`, res.status, data && data.error);
  return data;
}

// ── public (anonymous) creation, when the admin has enabled it ──────────────
// The tracker id (public/js/tracker.js) goes in X-Secbin-Aid next to its
// HttpOnly cookie; the server requires both to match.
let publicAid = '';
export const setPublicAid = (aid) => { publicAid = typeof aid === 'string' ? aid : ''; };
const aidHeaders = () => (publicAid ? { 'x-secbin-aid': publicAid } : {});
// Starting a public share needs a Turnstile token when the server has it on.
let publicHuman = async () => null;
export const setPublicHumanCheck = (take) => { publicHuman = typeof take === 'function' ? take : async () => null; };
const publicHeaders = async () => ({ ...aidHeaders(), ...human(await publicHuman()) });
const P = '/api/public';
export const publicProfile = () => request(`${P}/profile`);
export const publicApi = {
  async createNote(paste) {
    const d = await request(`${P}/paste`, { method: 'POST', headers: await publicHeaders(), body: { paste } });
    if (typeof d.id !== 'string' || typeof d.deletetoken !== 'string') throw malformed();
    return d;
  },
  initFileShare: async (body) => request(`${P}/file`, { method: 'POST', headers: await publicHeaders(), body }),
  finalizeFileShare: (id, uploadToken, paste) =>
    request(`${P}/file/${enc(id)}/finalize`, { method: 'POST', headers: { 'x-upload-token': uploadToken }, body: { paste } }),
  uploadChunk: (id, i, bytes, uploadToken) => putChunkTo(`${P}/file/${enc(id)}/chunk/${i}`, bytes, uploadToken),
  deleteShare,
};
