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
//     folder upload counts each file); files taken in from Receive links are
//     not counted here.
//   Receive — `receive` (both below), `receive-link` (a new Receive link),
//     `receive-upload` (an upload session that sends files through one of the
//     user's links, counted for the user, never the anonymous uploader).
// `all` never covers Drive uploads or Receive.

/** Every counted action. */
export const ACTIONS = ['note', 'url', 'secret', 'file', 'drive', 'drive-upload', 'receive-link', 'receive-upload'];

/**
 * Each kind: `label` (the editor, the account page), `what` (in a sentence:
 * "Quota reached: 10 <what> per 1d."), `covers` (the actions it counts) and
 * `gui` (only ever done in the web app with a session, never with an API key:
 * an "API only" quota of this kind could count nothing).
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
  receive: { label: 'All receive', what: 'Receive links and uploads received', covers: ['receive-link', 'receive-upload'], gui: true },
  'receive-link': { label: 'New links', what: 'new Receive links', covers: ['receive-link'], gui: true },
  'receive-upload': { label: 'Uploads received', what: 'uploads received', covers: ['receive-upload'], gui: true },
});

/** The editor's groups (an <optgroup> each), in order. */
export const QUOTA_GROUPS = Object.freeze([
  { label: 'Outgoing shares', kinds: ['all', 'text', 'note', 'url', 'secret', 'files', 'file', 'drive'] },
  { label: 'Drive', kinds: ['drive-upload'] },
  { label: 'Receive', kinds: ['receive', 'receive-link', 'receive-upload'] },
]);

/** Every kind a quota may have. */
export const QUOTA_KINDS = Object.freeze(QUOTA_GROUPS.flatMap((g) => g.kinds));

/**
 * The kinds the public (anonymous) account's quotas may have: what it can do
 * — notes, links, credentials and file shares. It has no Drive, so no Drive
 * shares, Drive uploads or Receive.
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
