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

// CAPTCHA grants (src/lib/human.js) for shares that have the CAPTCHA, by share
// id: sent with every call about that share, renewed from the responses.
const humanGrants = new Map();
let onHumanGrant = () => {};
/** Use `grant` (or none: null) for the calls about share `id`. */
export function setHumanGrant(id, grant) {
  if (typeof grant === 'string' && grant) humanGrants.set(id, grant);
  else humanGrants.delete(id);
}
export const humanGrantOf = (id) => humanGrants.get(id) ?? null;
/** `fn(id, grant)` is called when the server renews a grant (the page keeps it for the tab). */
export const setHumanGrantListener = (fn) => { onHumanGrant = typeof fn === 'function' ? fn : () => {}; };
const humanHeaders = (id) => (humanGrants.has(id) ? { 'x-secbin-human': humanGrants.get(id) } : {});
function renewedHuman(id, res) {
  const g = res.headers && typeof res.headers.get === 'function' ? res.headers.get('x-secbin-human') : null;
  if (id && g && /^h1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(g)) { humanGrants.set(id, g); onHumanGrant(id, g); }
}

async function request(path, { method = 'GET', body, headers = {}, raw = false, signal, human: humanId } = {}) {
  const init = { method, headers: { ...headers, ...(humanId ? humanHeaders(humanId) : {}) }, cache: 'no-store', credentials: 'same-origin', redirect: 'manual', ...(signal ? { signal } : {}) };
  if (body !== undefined) {
    init.headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await fetch(path, init);
  if (res.type === 'opaqueredirect') throw new ApiError('Please log in.', 401, 'unauthenticated');
  if (humanId) renewedHuman(humanId, res);
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
export const fetchHead = (kind, id) => request(`/api/${kind}/${enc(id)}`, { human: id });

/** Open a note or file share with its access proofs (the only way to get ciphertext). */
export const openShare = (kind, id, { linkProof, keyProof }) =>
  request(`/api/${kind}/${enc(id)}/open`, { method: 'POST', headers: { 'x-link-proof': linkProof, 'x-key-proof': keyProof }, human: id });

/**
 * "Delete now" as a recipient (the sender allowed it): the same two access
 * proofs as opening; spends no view.
 */
export const expireShare = (kind, id, { linkProof, keyProof }) =>
  request(`/api/${kind}/${enc(id)}/expire`, { method: 'POST', headers: { 'x-link-proof': linkProof, 'x-key-proof': keyProof }, human: id });

/**
 * A CAPTCHA grant for share `id` (the check page): with a Turnstile `token`
 * a new one; without, the grant held for `id` renewed (a keep-alive) →
 * { grant, expires } (grant null while the server has no CAPTCHA).
 */
export async function shareHuman(kind, id, token = null) {
  const d = await request(`/api/${kind}/${enc(id)}/human`, { method: 'POST', headers: { ...INTENT, ...human(token) }, human: token ? null : id });
  if (d.grant !== null && typeof d.grant !== 'string') throw malformed();
  if (d.grant) setHumanGrant(id, d.grant);
  return d;
}

/** One encrypted chunk of a file share, under a download grant. */
export async function fetchChunk(id, i, grant) {
  const res = await request(`/api/file/${enc(id)}/chunk/${i}`, { headers: { 'x-download-grant': grant }, raw: true, human: id });
  return new Uint8Array(await res.arrayBuffer());
}

/** Chunk `i` of file `ref` of a Drive share (manifest v3), under a download grant. */
export async function fetchRefChunk(id, ref, i, grant) {
  const res = await request(`/api/file/${enc(id)}/chunk/${ref}/${i}`, { headers: { 'x-download-grant': grant }, raw: true, human: id });
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

/** `extra`: { captcha } (true / false; left out: the role's default). */
export async function createNote(paste, label, extra = {}) {
  const d = await request('/api/private/paste', { method: 'POST', body: { paste, label, ...extra } });
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
  setKeys: (body) => request(`${D}/keys`, { method: 'PUT', headers: INTENT, body }),
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
  // The owner acting as this user: their escrow wrap and the owner's sealed escrow key (admin audit).
  impersonationEscrow: () => request(`${D}/escrow`, { method: 'POST', headers: INTENT, body: {} }),
  // The owner's recovery kit (made and read in the browser only): record a
  // download / use / check (admin audit), a check's live escrow wraps, and
  // sealed escrow keys put back from the kit.
  kit: (body) => request(`${D}/kit`, { method: 'POST', headers: INTENT, body }),
  kitProbe: () => request(`${D}/kit/probe`),
  kitKeys: (body) => request(`${D}/kit/keys`, { method: 'PUT', headers: INTENT, body }),
  // The owner, with no kit and no way to open their Drive: start it over (new keys).
  startOver: (body) => request(`${D}/start-over`, { method: 'POST', headers: INTENT, body }),
  // The Drive the owner had before starting over (an archive, sealed under the old DK).
  archive: (gen, after) => request(`${D}/archive/${enc(gen)}${after ? `?after=${enc(after)}` : ''}`),
  archiveNodes: (gen, body) => request(`${D}/archive/${enc(gen)}/nodes`, { method: 'PUT', headers: INTENT, body }),
  archiveFinish: (gen, body) => request(`${D}/archive/${enc(gen)}/finish`, { method: 'POST', headers: INTENT, body }),
  archiveDelete: (gen, body) => request(`${D}/archive/${enc(gen)}`, { method: 'DELETE', headers: INTENT, body }),
  // The owner, for a user: open their escrow wrap (admin audit) / write their `pw` wrap after a reset.
  escrow: (userId, reason) => request(`${A}/drive/escrow/${enc(userId)}`, { method: 'POST', headers: INTENT, body: { reason } }),
  setUserKeys: (userId, body) => request(`${A}/drive/keys/${enc(userId)}`, { method: 'PUT', headers: INTENT, body }),
};

// ── reverse shares: the anonymous uploader (docs/REVERSE.md §6.2) ────────────
const R = (id) => `/api/reverse/${enc(id)}`;
const grantH = (grant) => ({ 'x-reverse-grant': grant });
export const reverseApi = {
  open: (id, linkProof) => request(`${R(id)}/open`, { method: 'POST', headers: { ...INTENT, 'x-link-proof': linkProof } }),
  // `humanGrant`: a CAPTCHA grant from human() (the check page), when the link has the CAPTCHA.
  begin: (id, { linkProof, keyProof, turnstile, humanGrant }) => request(`${R(id)}/begin`, {
    method: 'POST', headers: { ...INTENT, 'x-link-proof': linkProof, ...(keyProof ? { 'x-key-proof': keyProof } : {}), ...human(turnstile), ...(humanGrant ? { 'x-secbin-human': humanGrant } : {}) },
  }),
  human: (id, token) => request(`${R(id)}/human`, { method: 'POST', headers: { ...INTENT, ...human(token) } }),
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
