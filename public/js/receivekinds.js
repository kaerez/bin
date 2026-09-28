// receivekinds.js — what a "Receive" link (a reverse share, docs/REVERSE.md
// §3.1) may be sent, shared by the Worker, the uploader's page and the Drive:
// files (as before), a note (plain text, Markdown or code), a link (one URL)
// and a credential (the regular credential share's fields). No DOM here.
//
// The kinds of a send are the kinds of regular shares: `files`, `note`, `url`
// and `secret` (fmt "url" and "secret" of a regular share, public/js/
// sharetypes.js). A link accepts a non-empty set of them (`accept`, stored
// with its limits); links made before this option accept files only. The
// uploader's browser declares the kind of a send when it starts the upload
// session (`begin`): the server checks it against the link and the link
// user's role, counts it in the quotas, and holds a note, link or credential
// to one item of bounded size. It never sees the content or the item's kind
// at rest: a received note, link or credential is stored like a received
// file, its content encrypted as file chunks and its kind (`kind`, and `fmt`
// and `title` for a note) inside the metadata the uploader seals to the
// link's key. A modified uploader could declare "note" and send anything; the
// user's browser shows a received item as its sealed metadata says, always
// through the inert viewers of regular shares.

import { utf8, fromUtf8 } from './bytes.js';
import { parseShareUrl, parseSecret, buildSecret, MAX_URL_LENGTH, SECRET_FIELDS } from './sharetypes.js';

/** Every kind a link may accept, in the order the pages list them. */
export const RECEIVE_KINDS = Object.freeze(['files', 'note', 'url', 'secret']);
/** What a link made before this option accepts. */
export const DEFAULT_ACCEPT = Object.freeze(['files']);
/** The kinds that are one item of their own (a note, a link, a credential). */
export const ITEM_KINDS = Object.freeze(['note', 'url', 'secret']);

/** The words the pages use: the tab, the Drive's label, "… from <date>". */
export const KIND_LABELS = Object.freeze({ files: 'Files', note: 'Note', url: 'Link', secret: 'Credential' });
/** In a sentence ("This link does not accept notes."). */
export const KIND_PLURALS = Object.freeze({ files: 'files', note: 'notes', url: 'links', secret: 'credentials' });

/**
 * The role options that allow each kind (src/lib/settings.js LIMITS),
 * mirroring the regular shares' `files`, `text`, `url` and `secret`.
 */
export const KIND_OPTIONS = Object.freeze({ files: 'reverseFiles', note: 'reverseText', url: 'reverseUrl', secret: 'reverseSecret' });

/** The quota action of a send (public/js/quotakinds.js). */
export const KIND_ACTIONS = Object.freeze({ files: 'receive-file', note: 'receive-note', url: 'receive-url', secret: 'receive-secret' });

/**
 * The note formats (a regular note's fmt: plain text, Markdown or code). Plain
 * text that looks like code is highlighted, as the regular viewer does.
 */
export const NOTE_FORMATS = Object.freeze(['plaintext', 'markdown', 'code']);
export const NOTE_FORMAT_LABELS = Object.freeze({ plaintext: 'Plain text', markdown: 'Markdown', code: 'Code' });

/**
 * The largest item of each kind (its plaintext, in bytes). A note: 2 MiB, about
 * what a regular note's ciphertext cap (MAX_CT_B64) holds uncompressed and what
 * the in-browser text viewer shows; a link: MAX_URL_LENGTH (the stored form is
 * ASCII); a credential: the regular credential's fields (SECRET_FIELDS), as
 * JSON with room for any escaping (a UTF-16 unit is at most 6 bytes in JSON).
 */
export const ITEM_MAX_BYTES = Object.freeze({
  note: 2 * 1024 * 1024,
  url: MAX_URL_LENGTH,
  secret: 6 * Object.values(SECRET_FIELDS).reduce((a, b) => a + b, 0) + 256,
});
/** The longest note title (characters). */
export const MAX_TITLE = 200;

/** Is `k` a kind a link can accept? */
export const isKind = (k) => typeof k === 'string' && RECEIVE_KINDS.includes(k);

/**
 * A link's accepted kinds as sent → the list in RECEIVE_KINDS order, or throws
 * Error with a readable message (not a list, an unknown kind, empty).
 */
export function normalizeAccept(v) {
  if (!Array.isArray(v) || v.length > RECEIVE_KINDS.length * 2) throw new Error('accept must be a list of files, note, url and secret.');
  for (const k of v) if (!isKind(k)) throw new Error('accept must be a list of files, note, url and secret.');
  const out = RECEIVE_KINDS.filter((k) => v.includes(k));
  if (!out.length) throw new Error('A link must accept at least one of files, note, url and secret.');
  return out;
}

/** A link's stored accepted kinds (its limits' `accept`) → the list; files only when it has none (made before). */
export function acceptOf(opts) {
  try { return opts && opts.accept !== undefined && opts.accept !== null ? normalizeAccept(opts.accept) : [...DEFAULT_ACCEPT]; } catch { return [...DEFAULT_ACCEPT]; }
}

/** The kinds of `accept` that the resolved role limits `L` allow now. */
export const allowedKinds = (accept, L) => accept.filter((k) => L && L[KIND_OPTIONS[k]] === true);

/**
 * The kinds that changing a link's accepted kinds from `prev` to `next` adds
 * and that weaken it: files, links and credentials (a note is plain text,
 * shown inertly — less than a file could carry). Such a change needs the step-up
 * as the other weakening changes do (src/routes/reverse.js weakening).
 */
export function widening(prev, next) {
  return next.filter((k) => !prev.includes(k) && k !== 'note');
}

// ── an item's content (the uploader's browser, and the user's) ─────────────

/**
 * What the uploader typed → { bytes (the content), meta (what goes into the
 * sealed metadata besides type / mtime / size), type } or throws Error with a
 * readable message. `note`: { text, fmt, title }; `url`: { url } (checked as a
 * recipient checks a link: any scheme but the forbidden ones — the link user's
 * URL rules apply when it is shown); `secret`: the credential's fields.
 */
export function encodeItem(kind, v = {}) {
  let text;
  let meta;
  let type = 'text/plain';
  if (kind === 'note') {
    text = String(v.text ?? '');
    if (!text.trim()) throw new Error('Write the note first.');
    const fmt = NOTE_FORMATS.includes(v.fmt) ? v.fmt : 'plaintext';
    const title = String(v.title ?? '').trim();
    if (title.length > MAX_TITLE) throw new Error(`The title is at most ${MAX_TITLE} characters.`);
    meta = { kind, fmt, ...(title ? { title } : {}) };
    if (fmt === 'markdown') type = 'text/markdown';
  } else if (kind === 'url') {
    if (!String(v.url ?? '').trim()) throw new Error('Enter the link to send.');
    text = parseShareUrl(v.url, { recipient: true }).href;
    meta = { kind };
  } else if (kind === 'secret') {
    const fields = {};
    for (const k of Object.keys(SECRET_FIELDS)) if (typeof v[k] === 'string') fields[k] = k === 'password' || k === 'notes' ? v[k] : v[k].trim();
    text = buildSecret(fields);
    meta = { kind };
    type = 'application/json';
  } else {
    throw new Error('Unknown kind.');
  }
  const bytes = utf8(text);
  if (bytes.length > ITEM_MAX_BYTES[kind]) throw new Error(`This ${KIND_LABELS[kind].toLowerCase()} is too long (at most ${ITEM_MAX_BYTES[kind]} bytes).`);
  return { bytes, meta, type };
}

/**
 * An item's kind marker from sealed metadata (the Drive's, or the uploader's)
 * → { kind, fmt?, title? } for a note, link or credential, or null for a file.
 * Anything malformed is a file (shown and downloaded as bytes, never rendered).
 */
export function itemOf(meta) {
  if (!meta || typeof meta !== 'object' || !ITEM_KINDS.includes(meta.kind)) return null;
  if (meta.kind !== 'note') return { kind: meta.kind };
  const fmt = NOTE_FORMATS.includes(meta.fmt) ? meta.fmt : 'plaintext';
  const title = typeof meta.title === 'string' && meta.title.trim() ? meta.title.trim().slice(0, MAX_TITLE) : null;
  return { kind: 'note', fmt, ...(title ? { title } : {}) };
}

/** The date part of a default name: the local date and time, e.g. "2026-09-28 14:03" (no "/": names cannot have one). */
export function nameDate(sec) {
  const d = new Date((Number.isSafeInteger(sec) && sec > 0 ? sec : Math.floor(Date.now() / 1000)) * 1000);
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

/**
 * The Drive name of a received item: a note's title, else "Note from <date>",
 * "Link from <date>" or "Credential from <date>" (the time the server received
 * it, in this browser's time zone).
 */
export function itemName(item, createdSec) {
  if (item.kind === 'note' && item.title) return item.title;
  return `${KIND_LABELS[item.kind]} from ${nameDate(createdSec)}`;
}

/** The extension a download (or a ZIP entry) of an item gets: .md for Markdown, .json for a credential as stored, else .txt. */
export function itemExt(item, { stored = false } = {}) {
  if (item.kind === 'note' && item.fmt === 'markdown') return '.md';
  if (item.kind === 'secret' && stored) return '.json';
  return '.txt';
}
/** `name` with the item's extension (unless it already ends with it). */
export function withExt(name, ext) {
  return name.toLowerCase().endsWith(ext) ? name : `${name}${ext}`;
}

const SECRET_EXPORT = [['title', 'Title'], ['username', 'User name'], ['password', 'Password'], ['url', 'Sign-in URL'], ['totp', 'One-time-code seed'], ['notes', 'Notes']];
/** The first lines of a credential's text export. */
export const SECRET_EXPORT_WARNING = 'This file holds a credential in plain text: anyone who can read the file can use it. Keep it somewhere safe and delete it when you no longer need it.';

/**
 * A download of an item → { filename, text }: a note as its text (.md or
 * .txt), a link as a text file with the URL only (never an Internet Shortcut:
 * the shell opens a .url file's target, and a link may name any scheme), a
 * credential as a plain-text export that says so at the top. Throws Error when
 * a link or credential does not parse (the Drive then offers the raw bytes).
 */
export function itemExport(item, name, bytes) {
  const text = fromUtf8(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes));
  if (item.kind === 'note') return { filename: withExt(name, itemExt(item)), text };
  if (item.kind === 'url') return { filename: withExt(name, '.txt'), text: `${parseShareUrl(text, { recipient: true }).href}\n` };
  const sec = parseSecret(text);
  const lines = [SECRET_EXPORT_WARNING, ''];
  for (const [k, label] of SECRET_EXPORT) {
    if (sec[k] === undefined) continue;
    lines.push(k === 'notes' ? `${label}:\n${sec[k]}` : `${label}: ${sec[k]}`);
  }
  return { filename: withExt(name, '.txt'), text: `${lines.join('\n')}\n` };
}
