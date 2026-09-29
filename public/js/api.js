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

// Signed-in activity: every successful /api/private request may slide the
// session's idle window (src/lib/auth.js), so the session-timeout warning
// (public/dashboard/js/session-timeout.js) restarts its clock on each one.
const activity = new Set();
/** Call `fn(path)` after each successful /api/private request; returns the unsubscribe. */
export function onPrivateActivity(fn) {
  activity.add(fn);
  return () => activity.delete(fn);
}
const touched = (path, res) => {
  if (res.ok && path.startsWith('/api/private/')) for (const fn of activity) { try { fn(path); } catch { /* a listener's bug is not the request's */ } }
};

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
// anonymous routes have no session and ignore it. That includes the reverse-
// share uploader (reverseApi, /api/reverse/…): it sends no token and never
// asks /api/private/me, whatever this page has recorded. The Drive's own
// reverse-share calls (drive.createReverse, acceptReceived, receivedFailed,
// receivedRetry) are under /api/private and carry the page's token.
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

/**
 * Whether `profile` (a /api/private/me answer) is the session this page acts
 * for: the same user in the same impersonation state. False once the page has
 * stopped acting for any session, or before it has recorded one.
 */
export function isPageSession(profile) {
  if (!page || page.ended) return false;
  const w = who(profile);
  return !!w.userId && w.userId === page.userId && w.impersonatedBy === page.impersonatedBy;
}

/** The browser is now signed in as someone else: stop acting for any session and say so (onSessionChanged). */
export function endPageSession() { sessionChanged(); }

/** `fn()` runs when the page finds that the browser is now signed in as someone else. */
export function onSessionChanged(fn) { sessionChangedHandler = typeof fn === 'function' ? fn : () => {}; }

/** The error for a page whose session is gone (the message pages show, with a Reload button). */
export const isSessionChanged = (e) => e instanceof ApiError && e.extra.sessionChanged === true;
/** The event a page's other modules listen for (the Drive drops its keys): `secbin:session-changed` on window. */
export const SESSION_CHANGED_EVENT = 'secbin:session-changed';
function sessionChanged() {
  const first = !page?.ended;
  forgetSession();
  if (first) {
    try { sessionChangedHandler(); } catch { /* the error below still reaches the page */ }
    try { globalThis.dispatchEvent?.(new Event(SESSION_CHANGED_EVENT)); } catch { /* no window (a worker, a test) */ }
  }
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

async function request(path, { method = 'GET', body, headers = {}, raw = false, signal, human: humanId } = {}) {
  const init = { method, headers: { ...headers, ...(humanId ? humanHeaders(humanId) : {}) }, cache: 'no-store', credentials: 'same-origin', redirect: 'manual', ...(signal ? { signal } : {}) };
  if (body !== undefined) {
    init.headers['content-type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  const res = await send(path, init);
  if (res.type === 'opaqueredirect') throw new ApiError('Please log in.', 401, 'unauthenticated');
  touched(path, res);
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

/** Keep a file share's download window open longer (at most ten times; spends no view). */
export async function extendDownloads(id, grant) {
  const d = await request(`/api/file/${enc(id)}/extend`, { method: 'POST', headers: { 'x-download-grant': grant }, human: id });
  if (!Number.isFinite(d.grantExpires) || !Number.isInteger(d.extensionsLeft)) throw malformed();
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
/** Set-up's proposed Drive keys (a root MEK and a first sub-MEK, for the setup token's holder) → { root, sub, expires }. */
export const setupCandidate = (token) => request('/api/auth/setup/candidate', { method: 'POST', headers: INTENT, body: { token } });
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
/**
 * Pause (`on`) or resume a Receive link (docs/API.md, /api/private/receive/<id>/pause | resume).
 * Resuming reopens it, so it is confirmed: `step` ({ current } or { reauth }; {} while the owner acts as the user).
 */
export const pauseReceive = (id, on, step = {}) => request(`/api/private/receive/${enc(id)}/${on ? 'pause' : 'resume'}`,
  { method: 'POST', headers: INTENT, ...(on ? {} : { body: step }) });

// ── admin ────────────────────────────────────────────────────────────────────
const A = '/api/private/admin';
export const admin = {
  overview: () => request(`${A}/overview`),
  // `step`: { current } or { reauth }, for a change that weakens a security control (the server says when).
  settings: (patch, step = {}) => request(`${A}/settings`, { method: 'PATCH', body: { ...patch, ...step } }),
  limits: (scope, channel, patch, step = {}) => request(`${A}/limits`, { method: 'PATCH', body: { scope, channel, patch, ...step } }),
  quotas: (scope, list, step = {}) => request(`${A}/quotas`, { method: 'PUT', body: { scope, list, ...step } }),
  viewerRules: (scope, list) => request(`${A}/viewer-rules`, { method: 'PUT', body: { scope, list } }),
  users: () => request(`${A}/users`),
  roles: () => request(`${A}/roles`),
  role: (id) => request(`${A}/roles/${enc(id)}`),
  createRole: (body) => request(`${A}/roles`, { method: 'POST', body }),
  // These may loosen what users get (a looser role or quota list): the server asks for `step` then.
  updateRole: (id, patch, step = {}) => request(`${A}/roles/${enc(id)}`, { method: 'PATCH', body: { ...patch, ...step } }),
  deleteRole: (id, step = {}) => request(`${A}/roles/${enc(id)}`, { method: 'DELETE', headers: INTENT, body: { ...step } }),
  setUserRole: (id, roleId, step = {}) => request(`${A}/users/${enc(id)}/role`, { method: 'PUT', body: { roleId, ...step } }),
  user: (id) => request(`${A}/users/${enc(id)}`),
  createUser: (body) => request(`${A}/users`, { method: 'POST', body }),
  updateUser: (id, body) => request(`${A}/users/${enc(id)}`, { method: 'PATCH', body }),
  deleteUser: (id, revokeShares) => request(`${A}/users/${enc(id)}${revokeShares ? '?revokeShares=1' : ''}`, { method: 'DELETE', headers: INTENT }),
  setPassword: (id, body) => request(`${A}/users/${enc(id)}/password`, { method: 'POST', body }),
  // Lifting a lockout, a Guard block, a block rule or a browser id's block: `step` (the server asks for it).
  unlock: (id, step = {}) => request(`${A}/users/${enc(id)}/unlock`, { method: 'POST', headers: INTENT, body: { ...step } }),
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
  unblock: (scope, key, step = {}) => request(`${A}/guard/unblock`, { method: 'POST', body: { scope, key, ...step } }),
  block: (scope, key, seconds) => request(`${A}/guard/block`, { method: 'POST', body: { scope, key, seconds } }),
  ipRules: () => request(`${A}/ip-rules`),
  addIpRule: (body) => request(`${A}/ip-rules`, { method: 'POST', body }),
  removeIpRule: (id, step = {}) => request(`${A}/ip-rules/${enc(id)}`, { method: 'DELETE', headers: INTENT, body: { ...step } }),
  shares: (qs) => request(`${A}/shares?${qs}`),
  publicAccess: () => request(`${A}/public`),
  tracker: (id, action, step = {}) => request(`${A}/public/trackers/${enc(id)}`, { method: 'POST', body: { action, ...step } }),
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
  keys: () => request(`${D}/keys`, { method: 'POST', headers: INTENT, body: {} }),
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
  // The personal kit (docs/DRIVE.md §3.1): its state (the key version, the last download), its
  // content (with the step-up) and a read-only check, each POST with the CAPTCHA token when the
  // server has one (a restore is the owner's: keysApi).
  kitStatus: () => request(`${D}/kit`),
  kit: (step, turnstile) => request(`${D}/kit`, { method: 'POST', headers: { ...INTENT, ...human(turnstile) }, body: { ...step } }),
  kitVerify: (body, turnstile) => request(`${D}/kit/verify`, { method: 'POST', headers: { ...INTENT, ...human(turnstile) }, body }),
  // The upgrade of a Drive made before the key model v2 (docs/DRIVE.md §3.3): own, or (the owner) a user's.
  migrate: (uid = null) => request(uid ? `${A}/drive/migrate/${enc(uid)}` : `${D}/migrate`),
  migrateItems: (after = null, uid = null) => request(`${uid ? `${A}/drive/migrate/${enc(uid)}` : `${D}/migrate`}/items${after ? `?after=${enc(after)}` : ''}`),
  migratePut: (body, uid = null) => request(uid ? `${A}/drive/migrate/${enc(uid)}` : `${D}/migrate`, { method: 'PUT', headers: INTENT, body }),
  migrateFinish: (uid = null) => request(`${uid ? `${A}/drive/migrate/${enc(uid)}` : `${D}/migrate`}/finish`, { method: 'POST', headers: INTENT, body: {} }),
  migrateEscrow: (uid, step) => request(`${A}/drive/migrate/${enc(uid)}/escrow`, { method: 'POST', headers: INTENT, body: { ...step } }),
  // Links of the release before that the old key does not open: ended, their keys removed (the step-up).
  migrateRetire: (ids, step, uid = null) => request(`${uid ? `${A}/drive/migrate/${enc(uid)}` : `${D}/migrate`}/retire`, { method: 'POST', headers: INTENT, body: { ids, ...step } }),
  migration: () => request(`${A}/drive/migration`),
  // The owner's archive of the release before (a start over): what it holds; deleted (the step-up, the username typed).
  archive: () => request(`${A}/drive/archive`),
  deleteArchive: (body) => request(`${A}/drive/archive`, { method: 'DELETE', headers: INTENT, body }),
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
  cancelJob: (step) => request(`${K}/jobs`, { method: 'DELETE', headers: INTENT, body: { ...step } }),
  // A root change that could not finish: go back to the previous root, or drop it (the typed fingerprint).
  undoRoot: (step) => request(`${K}/root/undo`, { method: 'POST', headers: INTENT, body: { ...step } }),
  dropOldRoot: (body) => request(`${K}/root/drop-old`, { method: 'POST', headers: INTENT, body }),
  kit: (step) => request(`${K}/kit`, { method: 'POST', headers: INTENT, body: { ...step } }),
  verify: (body) => request(`${K}/verify`, { method: 'POST', headers: INTENT, body }),
  restore: (body) => request(`${K}/restore`, { method: 'POST', headers: INTENT, body }),
  exportKeys: (body) => request(`${K}/export`, { method: 'POST', headers: INTENT, body }),
  // A keys export checked against this server, read-only (check values, and the DEKs for their files' first chunk).
  verifyExport: (body) => request(`${K}/export/verify`, { method: 'POST', headers: INTENT, body }),
  importKeys: (body) => request(`${K}/import`, { method: 'POST', headers: INTENT, body }),
  userView: (uid, body) => request(`${K}/users/${enc(uid)}/view`, { method: 'POST', headers: INTENT, body }),
  // A user's personal kit (opened in the owner's browser): only what the server lost comes back.
  userKitRestore: (uid, body) => request(`${K}/users/${enc(uid)}/kit-restore`, { method: 'POST', headers: INTENT, body }),
};

// ── reverse shares: the anonymous uploader (docs/REVERSE.md §6.2) ────────────
const R = (id) => `/api/reverse/${enc(id)}`;
const grantH = (grant) => ({ 'x-reverse-grant': grant });
export const reverseApi = {
  open: (id, linkProof) => request(`${R(id)}/open`, { method: 'POST', headers: { ...INTENT, 'x-link-proof': linkProof } }),
  // `humanGrant`: a CAPTCHA grant from human() (the check page), when the link has the CAPTCHA.
  // `type`: what the session sends (files, note, url, secret: public/js/receivekinds.js).
  begin: (id, { linkProof, keyProof, turnstile, humanGrant, type = 'files' }) => request(`${R(id)}/begin`, {
    method: 'POST', headers: { ...INTENT, 'x-link-proof': linkProof, ...(keyProof ? { 'x-key-proof': keyProof } : {}), ...human(turnstile), ...(humanGrant ? { 'x-secbin-human': humanGrant } : {}) },
    body: { type },
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
  const res = await send(path, {
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
