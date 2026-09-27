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

// ── CSRF token and the page's session ────────────────────────────────────────
// Every state-changing request of a signed-in page carries a CSRF token in
// X-Secbin-CSRF (src/lib/csrf.js), and the token a page sends is the one of
// the session the page was loaded for, not whatever the (shared) cookie holds
// now. The dashboard chrome records that session when the page loads
// (bindSession, from /api/private/me: the user id, the impersonation state and
// the token); a page that has not recorded one records the current session
// before its first change. So when another tab signs in as someone else, or
// starts or ends impersonation, this page's token no longer matches and the
// server refuses the change (403 csrf_mismatch, before changing anything).
// The page then asks /api/private/me who the browser is signed in as now:
//   • the same user, in the same impersonation state (e.g. signed out and in
//     again, or a password change): it takes the new token and retries once;
//   • anyone else: it does not retry. It stops acting for any session
//     (every later change is refused here, without a request) and shows
//     SESSION_CHANGED with a Reload button (onSessionChanged). A page loaded
//     for one user never changes another user's account.
// The header goes only where the server checks it (/api/private and logout);
// anonymous routes have no session and ignore it.
export const CSRF_COOKIE = '__Host-secbin_csrf';
const CSRF_HEADER = 'x-secbin-csrf';
const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
export const SESSION_CHANGED = 'Your session changed in another tab; reload the page.';

/** The token in the browser's cookie ('' when there is none): the current session's, not necessarily the page's. */
export function csrfToken() {
  let jar;
  try { jar = document.cookie || ''; } catch { return ''; }
  for (const part of jar.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === CSRF_COOKIE) {
      const v = part.slice(i + 1).trim();
      return TOKEN_RE.test(v) ? v : '';
    }
  }
  return '';
}

/** null (none recorded yet), { userId, impersonatedBy, token }, or { ended: true }. */
let page = null;
let sessionChangedHandler = () => {};
const who = (profile) => ({
  userId: isPlainObject(profile) && isPlainObject(profile.user) && typeof profile.user.id === 'string' ? profile.user.id : null,
  impersonatedBy: isPlainObject(profile) && typeof profile.impersonatedBy === 'string' ? profile.impersonatedBy : null,
});
const tokenFrom = (profile) => (isPlainObject(profile) && typeof profile.csrf === 'string' && TOKEN_RE.test(profile.csrf) ? profile.csrf : '');

/** Record the session this page is for, from a /api/private/me profile. */
export function bindSession(profile) {
  const w = who(profile);
  page = w.userId ? { ...w, token: tokenFrom(profile) } : { ended: true };
}

/** Stop acting for any session: every later change from this page is refused here, without a request. */
export function forgetSession() { page = { ended: true }; }

/** `fn()` runs when the page finds that the browser is now signed in as someone else. */
export function onSessionChanged(fn) { sessionChangedHandler = typeof fn === 'function' ? fn : () => {}; }

/** The error for a page whose session is gone (the message pages show, with a Reload button). */
export const isSessionChanged = (e) => e instanceof ApiError && e.extra.sessionChanged === true;
function sessionChanged() {
  const first = !page?.ended;
  forgetSession();
  if (first) { try { sessionChangedHandler(); } catch { /* the error below still reaches the page */ } }
  return new ApiError(SESSION_CHANGED, 403, 'csrf_mismatch', { sessionChanged: true });
}

const needsCsrf = (path, method) => STATE_CHANGING.has(method) && (path.startsWith('/api/private/') || path === '/api/auth/logout');

/**
 * Send `init` to `path`. A signed-in state-changing request carries the
 * page's token; if the server refuses it (403 csrf_mismatch, which it answers
 * before changing anything), /api/private/me says who is signed in now (a 401
 * there is the normal signed-out flow): the page's own user and impersonation
 * state → one retry with the new token; anyone else, or a second refusal →
 * SESSION_CHANGED, and no retry.
 */
async function send(path, init) {
  if (!needsCsrf(path, init.method)) return fetch(path, init);
  if (!page) bindSession(await request('/api/private/me'));
  if (page.ended) throw sessionChanged();
  const withToken = (token) => {
    const headers = { ...init.headers };
    if (token) headers[CSRF_HEADER] = token; else delete headers[CSRF_HEADER];
    return fetch(path, { ...init, headers });
  };
  const res = await withToken(page.token);
  if (!(await isCsrfMismatch(res))) return res;
  const bound = page;
  const now = await request('/api/private/me');
  const w = who(now);
  if (page !== bound || page.ended || w.userId !== bound.userId || w.impersonatedBy !== bound.impersonatedBy) throw sessionChanged();
  bound.token = tokenFrom(now);
  const again = await withToken(bound.token);
  if (await isCsrfMismatch(again)) throw sessionChanged();
  return again;
}

async function isCsrfMismatch(res) {
  if (res.status !== 403) return false;
  try {
    const d = await res.clone().json();
    return isPlainObject(d) && d.error === 'csrf_mismatch';
  } catch {
    return false;
  }
}

async function request(path, { method = 'GET', body, headers = {}, raw = false } = {}) {
  const init = { method, headers: { ...headers }, cache: 'no-store', credentials: 'same-origin', redirect: 'manual' };
  if (body !== undefined) {
    init.headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await send(path, init);
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

/** Binary chunk upload (kept separate: `request` is JSON-only). */
export const uploadChunk = (id, i, bytes, uploadToken) => putChunkTo(`/api/private/file/${enc(id)}/chunk/${i}`, bytes, uploadToken);

async function putChunkTo(path, bytes, uploadToken) {
  const res = await send(path, {
    method: 'PUT', body: bytes, cache: 'no-store', credentials: 'same-origin', redirect: 'manual',
    headers: { 'content-type': 'application/octet-stream', 'x-upload-token': uploadToken },
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
