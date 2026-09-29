// quotakinds.js — what a role quota counts (Admin → Roles → Quotas), shared by
// the server (validation, counting, refusal messages, audit) and the admin
// and account pages (the editor's groups, the labels).
//
// Every counted action is one of ACTIONS; a quota's kind covers one or more of
// them (KINDS[kind].covers). The groups:
//   Outgoing shares — `all` (every note, link, credential, file share and
//     Drive share; the key and its reach are unchanged), `text` (notes, links
//     and credentials: the reach it always had), `files` (file shares and
//     Drive shares: the reach it always had), and one kind per share type:
//     `note` (plain text, Markdown or code), `url`, `secret`, `file`, `drive`.
//   Drive — `drive-upload`: each file added to the Drive by an upload (a
//     folder upload counts each file); `drive-bytes`: the bytes those files
//     hold (each file's size, counted when its upload is reserved), and those
//     of each file received through a Receive link (Drive storage too:
//     counted when it is finished); a received file never counts under
//     `drive-upload` (the Receive kinds count its session).
//   Receive — `receive` (every receive action), `receive-link` (a new Receive
//     link), `receive-upload` (an upload session through one of the user's
//     links, of any kind — counted for the user, never the anonymous
//     uploader), and one kind per kind of send, as the session declares it
//     (public/js/receivekinds.js): `receive-file` (a session that sends
//     files), `receive-note`, `receive-url`, `receive-secret`.
// `all` never covers Drive uploads or Receive.

/** The actions of an upload session through a Receive link, one per kind of send. */
export const RECEIVE_UPLOAD_ACTIONS = ['receive-file', 'receive-note', 'receive-url', 'receive-secret'];
/** Every counted action. */
export const ACTIONS = ['note', 'url', 'secret', 'file', 'drive', 'drive-upload', 'drive-bytes', 'receive-link', ...RECEIVE_UPLOAD_ACTIONS];

/**
 * Each kind: `label` (the editor, the account page), `what` (in a sentence:
 * "Quota reached: 10 <what> per 1d."), `covers` (the actions it counts) and
 * `gui` (only ever done in the web app with a session, never with an API key:
 * an "API only" quota of this kind could count nothing) and `bytes` (its max
 * and its count are bytes, not a number of actions: the editor shows MiB or
 * GiB, the messages a size).
 */
export const KINDS = Object.freeze({
  all: { label: 'All outgoing shares', what: 'outgoing shares', covers: ['note', 'url', 'secret', 'file', 'drive'] },
  text: { label: 'Notes, links and credentials', what: 'notes, links and credentials', covers: ['note', 'url', 'secret'] },
  note: { label: 'Notes', what: 'notes', covers: ['note'] },
  url: { label: 'Links', what: 'links', covers: ['url'] },
  secret: { label: 'Credentials', what: 'credentials', covers: ['secret'] },
  files: { label: 'File and Drive shares', what: 'file and Drive shares', covers: ['file', 'drive'] },
  file: { label: 'File shares', what: 'file shares', covers: ['file'] },
  drive: { label: 'Drive shares', what: 'Drive shares', covers: ['drive'], gui: true },
  'drive-upload': { label: 'Files uploaded', what: 'files uploaded to the Drive', covers: ['drive-upload'], gui: true },
  'drive-bytes': { label: 'Bytes uploaded', what: 'uploaded to the Drive', covers: ['drive-bytes'], gui: true, bytes: true },
  receive: { label: 'All receive', what: 'Receive links and uploads received', covers: ['receive-link', ...RECEIVE_UPLOAD_ACTIONS], gui: true },
  'receive-link': { label: 'New links', what: 'new Receive links', covers: ['receive-link'], gui: true },
  'receive-upload': { label: 'Uploads received', what: 'uploads received', covers: [...RECEIVE_UPLOAD_ACTIONS], gui: true },
  'receive-file': { label: 'Uploads with files', what: 'uploads with files received', covers: ['receive-file'], gui: true },
  'receive-note': { label: 'Notes received', what: 'notes received', covers: ['receive-note'], gui: true },
  'receive-url': { label: 'Links received', what: 'links received', covers: ['receive-url'], gui: true },
  'receive-secret': { label: 'Credentials received', what: 'credentials received', covers: ['receive-secret'], gui: true },
});

/** The editor's groups (an <optgroup> each), in order. */
export const QUOTA_GROUPS = Object.freeze([
  { label: 'Outgoing shares', kinds: ['all', 'text', 'note', 'url', 'secret', 'files', 'file', 'drive'] },
  { label: 'Drive', kinds: ['drive-upload', 'drive-bytes'] },
  { label: 'Receive', kinds: ['receive', 'receive-link', 'receive-upload', 'receive-file', 'receive-note', 'receive-url', 'receive-secret'] },
]);

/** Every kind a quota may have. */
export const QUOTA_KINDS = Object.freeze(QUOTA_GROUPS.flatMap((g) => g.kinds));

/**
 * The kinds the public (anonymous) account's quotas may have: what it can do
 * — notes, links, credentials and file shares. It has no Drive, so no Drive
 * shares, Drive uploads (files or bytes) or Receive.
 */
export const PUBLIC_QUOTA_KINDS = Object.freeze(['all', 'text', 'note', 'url', 'secret', 'files', 'file']);

/** Does a quota of `kind` count `action`? */
export const quotaCovers = (kind, action) => !!KINDS[kind] && KINDS[kind].covers.includes(action);

/** The action a share creation is: its format (a note) or kind (a file share, a Drive share). */
export function shareAction({ kind, fmt, drive = false }) {
  if (kind === 'files') return drive ? 'drive' : 'file';
  return fmt === 'url' ? 'url' : fmt === 'secret' ? 'secret' : 'note';
}

/** The label of `kind` (the key itself for one this release does not know). */
export const kindLabel = (kind) => KINDS[kind]?.label ?? String(kind);
/** `kind` in a sentence. */
export const kindWhat = (kind) => KINDS[kind]?.what ?? String(kind);

/** Is `kind` counted in bytes (its max, its count)? */
export const isBytesKind = (kind) => !!KINDS[kind]?.bytes;

/** The largest max a quota counted in bytes may have (1 PiB); other kinds go up to 10 000 000. */
export const MAX_QUOTA_BYTES = 2 ** 50;

/** A size as the pages show one (common.js formatBytes, 1024-based): "0 B", "512 KB", "1.5 GB", "2.0 TB". */
export function sizeText(n) {
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${i === 0 ? v : v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`;
}

/** An amount of `kind` in a sentence: a count ("10") or, for a kind counted in bytes, a size ("1.0 GB"). */
export const quotaAmount = (kind, n) => (isBytesKind(kind) ? sizeText(n) : String(n));
