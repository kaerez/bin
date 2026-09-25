// filepolicy.js — the admin's file policy for file shares: which file types
// may be shared (allow list or block list of extensions / MIME globs) and how
// deep folders may nest. Shared by the Worker (validates declarations), the
// browser composer and the CLI (enforce before encrypting; vendored copy).
//
// File names and types are end-to-end encrypted, so the server cannot see
// them. When — and only when — a type or depth policy applies to the sender,
// the client declares the de-duplicated set of { ext, mime } pairs and the
// maximum folder depth at upload init; the server checks them against the
// policy and does not store them. A modified client could lie; the declaration
// makes the policy enforceable for honest clients and auditable, not
// cryptographically guaranteed. See SECURITY.md §3.

export const FILE_TYPE_MODES = ['any', 'allow', 'block'];
export const MAX_RULES = 200;
export const MAX_DECLARED_TYPES = 1000;
export const MAX_FOLDER_DEPTH = 64;

const EXT_RE = /^[a-z0-9][a-z0-9_+-]{0,31}$/;
const MIME_RE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}\/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}$/;
const MIME_GLOB_RE = /^[a-z0-9][a-z0-9!#$&^_.+-]{0,62}\/(\*|[a-z0-9][a-z0-9!#$&^_.+-]{0,62})$/;

/** "ext:pdf" | "mime:image/*" → { kind, value }, or null if malformed. */
export function parseRule(rule) {
  if (typeof rule !== 'string') return null;
  const m = /^(ext|mime):(.+)$/.exec(rule.trim().toLowerCase());
  if (!m) return null;
  const value = m[1] === 'ext' ? m[2].replace(/^\./, '') : m[2];
  if (m[1] === 'ext' ? !EXT_RE.test(value) : !MIME_GLOB_RE.test(value)) return null;
  return { kind: m[1], value };
}

/** Canonical rule list, or throws with a clear message (admin input). */
export function normalizeRules(list) {
  if (!Array.isArray(list)) throw new Error('rules must be a list');
  if (list.length > MAX_RULES) throw new Error(`at most ${MAX_RULES} rules`);
  const out = [];
  for (const r of list) {
    const p = parseRule(r);
    if (!p) throw new Error(`invalid rule "${String(r).slice(0, 80)}" — use ext:pdf or mime:image/png or mime:image/*`);
    const s = `${p.kind}:${p.value}`;
    if (!out.includes(s)) out.push(s);
  }
  return out;
}

/** Lower-case extension of the last path segment ("" when there is none). */
export function fileExt(path) {
  const name = String(path).split('/').pop();
  const i = name.lastIndexOf('.');
  if (i <= 0 || i === name.length - 1) return '';
  const ext = name.slice(i + 1).toLowerCase();
  return EXT_RE.test(ext) ? ext : '';
}

/** Folder depth of a share path: "a.txt" → 0, "x/y/a.txt" → 2; a directory entry counts itself. */
export function pathDepth(path, isDir = false) {
  const segs = String(path).split('/').filter(Boolean).length;
  return isDir ? segs : Math.max(0, segs - 1);
}

/** Declaration for a list of { path, type, dir? } entries: { types:[{ext,mime}], depth }. */
export function declare(entries) {
  const seen = new Set();
  const types = [];
  let depth = 0;
  for (const e of entries) {
    depth = Math.max(depth, pathDepth(e.path, !!e.dir));
    if (e.dir) continue;
    const t = { ext: fileExt(e.path), mime: String(e.type || 'application/octet-stream').toLowerCase() };
    const k = `${t.ext}\n${t.mime}`;
    if (!seen.has(k)) { seen.add(k); types.push(t); }
  }
  return { types, depth };
}

function matches(t, rule) {
  const r = typeof rule === 'string' ? parseRule(rule) : rule;
  if (!r) return false;
  if (r.kind === 'ext') return t.ext === r.value;
  if (r.value.endsWith('/*')) return t.mime.startsWith(r.value.slice(0, -1));
  return t.mime === r.value;
}

/**
 * Types (from a declaration) that the policy refuses. mode "any" refuses
 * nothing; "allow" refuses types matching no rule; "block" refuses types
 * matching any rule.
 */
export function refusedTypes(mode, rules, types) {
  if (mode !== 'allow' && mode !== 'block') return [];
  const parsed = (rules || []).map(parseRule).filter(Boolean);
  return types.filter((t) => {
    const hit = parsed.some((r) => matches(t, r));
    return mode === 'allow' ? !hit : hit;
  });
}

/** Validate a client's declared types (untrusted input); returns them normalized or null. */
export function checkDeclaredTypes(v) {
  if (!Array.isArray(v) || v.length > MAX_DECLARED_TYPES) return null;
  const out = [];
  for (const t of v) {
    if (!t || typeof t !== 'object') return null;
    const ext = typeof t.ext === 'string' ? t.ext.toLowerCase() : null;
    const mime = typeof t.mime === 'string' ? t.mime.toLowerCase() : null;
    if (ext === null || (ext !== '' && !EXT_RE.test(ext)) || mime === null || !MIME_RE.test(mime)) return null;
    out.push({ ext, mime });
  }
  return out;
}

/** A short human description of a refused type, e.g. ".exe (application/x-msdownload)". */
export const describeType = (t) => `${t.ext ? `.${t.ext}` : '(no extension)'} (${t.mime})`;
