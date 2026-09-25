// get — open a note or file share from its share URL and decrypt it locally.
//
// Mirrors the browser viewer (public/js/view.js), SPEC.md §5.4:
//   1. GET the head {v, adata, meta} (never ciphertext, never spends a view)
//      and validate it fail-closed;
//   2. derive the access proofs from the #fragment (+ Argon2id password) —
//      locally, no request;
//   3. for a view-limited share, confirm on a TTY (unless --yes);
//   4. POST …/open with the proofs. The server checks the link proof and the
//      key proof BEFORE it releases ciphertext or spends a view, so a wrong
//      link or password gets 403 and the share is untouched;
//   5. decrypt. File shares then fetch only the chunks covering the requested
//      entries under the short-lived download grant and write them under
//      --out with the confinement rules in extract.js.
// Anything that can fail locally (URL, flags, an unwritable --out) fails before
// step 4, while the view is still unspent.
import { lstat, open, unlink } from 'node:fs/promises';
import process from 'node:process';
import { parseArgs } from 'node:util';
import { deriveAccess, openPaste } from '../../vendor/crypto.js';
import { checkPath, chunkCount, ManifestError, paddedLength, validateManifest } from '../../vendor/files.js';
import { FormatError, validateHead, validatePaste } from '../../vendor/format.js';
import { describeHost, parseSecret, parseShareUrl as parseLinkUrl, SECRET_FIELDS, ShareTypeError, totpCode } from '../../vendor/sharetypes.js';
import { ApiError, Client } from '../client.js';
import { UsageError } from '../errors.js';
import { freshFolder, OverwriteError, preflight, prepareRoot, writeDir, writeFile } from '../extract.js';
import { formatBytes } from '../format-bytes.js';
import { ShareReader } from '../reader.js';
import { resolveSecret } from '../secret.js';
import { CLEAR_LINE } from '../tui/anim.js';
import { kindOf, parseShareUrl } from '../url.js';

const OPTIONS = {
  out: { type: 'string', short: 'o' },
  yes: { type: 'boolean', default: false, short: 'y' },
  'password-env': { type: 'string' },
  list: { type: 'boolean', default: false, short: 'l' },
  path: { type: 'string', short: 'p' },
  force: { type: 'boolean', default: false },
  field: { type: 'string' },
};

// --field for a credential share: one of its fields, or "code" (the current one-time code).
const FIELD_NAMES = [...Object.keys(SECRET_FIELDS), 'code'];

// Escape C0/C1 controls (and DEL) so decrypted, sender-controlled text shown
// as a status line cannot inject terminal escape sequences.
// eslint-disable-next-line no-control-regex
const safeLine = (s) => String(s).replace(/[\u0000-\u001f\u007f-\u009f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
// For multi-line values shown on a terminal: like safeLine, but keeps newlines and tabs.
// eslint-disable-next-line no-control-regex
const safeText = (s) => String(s).replace(/[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);

/**
 * The text `get` prints for a decrypted note. Typed shares are validated
 * fail-closed like the web viewer: a link is printed, never opened, with its
 * real host on stderr; a credential is JSON unless one --field is asked for.
 * This runs after the view is spent, so it never throws: anything unexpected
 * is reported on stderr and the content is still printed.
 */
async function renderNote(fmt, text, field, io, tty) {
  if (fmt === 'url') {
    let u;
    try { u = parseLinkUrl(text); } catch (e) {
      if (!(e instanceof ShareTypeError)) throw e;
      io.stderr(`warning: this link share does not hold a valid link (${e.message}); printing it as text\n`);
      return tty ? `${safeText(text)}\n` : text;
    }
    const h = describeHost(u);
    io.stderr(`link to ${h.ascii}${h.idn ? ` (displayed as ${safeLine(h.unicode)} — international characters can imitate another site)` : ''}${h.insecure ? ' — not HTTPS' : ''}\n`);
    return `${u.href}\n`;
  }
  if (fmt !== 'secret') return text;
  let sec;
  try { sec = parseSecret(text); } catch (e) {
    if (!(e instanceof ShareTypeError)) throw e;
    io.stderr(`warning: ${e.message} Printing it as text.\n`);
    return tty ? `${safeText(text)}\n` : text;
  }
  // JSON.stringify escapes C0 controls; also escape DEL and C1 (e.g. CSI).
  const json = `${JSON.stringify(sec, null, 2).replace(/[\u007f-\u009f]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)}\n`;
  if (field === undefined) {
    if (sec.totp !== undefined) io.stderr('contains a one-time-code seed: --field code prints the current code\n');
    return json;
  }
  if (field === 'code') {
    if (sec.totp !== undefined) {
      try {
        const { code, remaining } = await totpCode(sec.totp);
        io.stderr(`valid for ${remaining}s\n`);
        return `${code}\n`;
      } catch (e) {
        if (!(e instanceof ShareTypeError)) throw e;
        io.stderr(`warning: ${e.message}\n`);
      }
    }
    io.stderr('warning: no usable one-time-code seed; printing the whole credential instead\n');
    return json;
  }
  if (sec[field] === undefined) {
    io.stderr(`warning: this credential has no "${field}" field; printing the whole credential instead\n`);
    return json;
  }
  return tty ? `${safeText(sec[field])}\n` : `${sec[field]}\n`;
}

const GRANT_RE = /^[A-Za-z0-9_-]{43}$/;
const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function promptPassword(io) {
  if (!io.stdinIsTTY) {
    throw new UsageError('this share is password-protected — pass it with --password-env <VAR> (no TTY to prompt on)');
  }
  return io.promptHidden('Password: ');
}

/** "--path dir/sub/" → "dir/sub", validated like a manifest path. */
function normalizeSubpath(raw) {
  const p = raw.replace(/^(\.\/)+/, '').replace(/\/+$/, '');
  try {
    return checkPath(p);
  } catch {
    throw new UsageError(`invalid --path "${raw}" (a relative path inside the share, e.g. docs/readme.txt or docs)`);
  }
}

function confirmQuestion(meta, what, listing) {
  const pre = listing ? 'Listing opens the share. ' : '';
  if (meta.views === 1) return `${pre}Opening ${what} uses its only view — it is deleted afterwards. Continue? [y/N] `;
  if (meta.left === 1) return `${pre}This is the last remaining view (${meta.views ?? '?'} in total) — opening deletes the share. Continue? [y/N] `;
  return `${pre}Opening uses 1 of the ${meta.left} remaining views. Continue? [y/N] `;
}

function reportLeft(io, meta, last = 'that was the last view — the share is now deleted') {
  if (!Number.isInteger(meta.left)) return;
  io.stderr(meta.left === 0 ? `${last}\n` : `${meta.left} view${meta.left === 1 ? '' : 's'} left\n`);
}

/** Entries to fetch for --path (or everything), with their output-relative paths. */
function select(entries, sub, limited) {
  if (sub === undefined) return entries.map((e) => ({ entry: e, rel: e.path }));
  const cut = sub.includes('/') ? sub.lastIndexOf('/') + 1 : 0; // keep the selected item's own name
  const hit = entries.filter((e) => e.path === sub || e.path.startsWith(sub + '/'));
  if (hit.length === 0) {
    throw new UsageError(`no file or folder "${sub}" in this share (see --list)${limited ? ' — note: opening it used a view' : ''}`);
  }
  return hit.map((e) => ({ entry: e, rel: e.path.slice(cut) }));
}

function printList(io, entries) {
  const rows = entries.map((e) => (e.dir
    ? ['-', 'folder', e.path + '/']
    : [formatBytes(e.size), e.type, e.path]));
  const w0 = Math.max(...rows.map((r) => r[0].length));
  const w1 = Math.max(...rows.map((r) => r[1].length));
  // Paths and types were validated by validateManifest (no control characters),
  // so printing them cannot inject terminal escapes.
  io.stdout(rows.map((r) => `${r[0].padStart(w0)}  ${r[1].padEnd(w1)}  ${r[2]}`).join('\n') + '\n');
}

export async function cmdGet(args, io) {
  let values, positionals;
  try {
    ({ values, positionals } = parseArgs({ args, options: OPTIONS, allowPositionals: true, strict: true }));
  } catch (e) {
    throw new UsageError(e.message);
  }
  if (positionals.length !== 1) {
    throw new UsageError('usage: secbin get <share-url | -> (use "-" to read the URL from stdin)');
  }

  let rawUrl = positionals[0];
  if (rawUrl === '-') {
    rawUrl = (await io.readStdin()).toString('utf8').trim();
    if (!rawUrl) throw new UsageError('no share URL on stdin');
  }
  const { server, id, fragment } = parseShareUrl(rawUrl);
  const kind = kindOf(id);
  if (kind === 'paste' && (values.list || values.path !== undefined || values.force)) {
    throw new UsageError('--list, --path and --force apply to file shares only');
  }
  if (values.field !== undefined && !FIELD_NAMES.includes(values.field)) {
    throw new UsageError(`invalid --field "${values.field.slice(0, 40)}" (one of: ${FIELD_NAMES.join(', ')})`);
  }
  if (kind === 'file' && values.field !== undefined) throw new UsageError('--field applies to credential shares only');
  if (values.list && (values.out !== undefined || values.force)) {
    throw new UsageError('--list prints the file list only; it takes no --out / --force');
  }
  const sub = values.path === undefined ? undefined : normalizeSubpath(values.path);
  const client = new Client(server, io.fetch);
  const fromEnv = values['password-env'] !== undefined;
  let password = await resolveSecret({ envVar: values['password-env'], promptWanted: false, io });

  // 1. Head (never spends a view) + fail-closed validation.
  const head = validateHead(await client.head(kind, id));
  if ((head.adata.fmt === 'files') !== (kind === 'file')) throw new FormatError('the share type does not match its link');
  const needsPassword = head.adata.kdf === 'argon2id-hkdf';
  const limited = head.adata.bar && Number.isInteger(head.meta.left);

  // 2. Access proofs (local).
  if (needsPassword && password === '') password = await promptPassword(io);
  let access = await deriveAccess({ adata: head.adata, fragment, password });

  // 3. Confirm spending a view (skippable; auto-skipped without a TTY).
  if (limited && !values.yes && io.stdinIsTTY) {
    const ok = await io.confirm(confirmQuestion(head.meta, kind === 'file' ? 'these files' : 'this note', values.list));
    if (!ok) {
      io.stderr('aborted — the share was NOT opened and still exists.\n');
      return 0;
    }
  }

  // 4. Open. A wrong password is refused by the server without spending a
  // view; on a TTY (password typed, not scripted) ask once more.
  const openShare = async () => {
    try {
      return await client.open(kind, id, access);
    } catch (e) {
      if (!(e instanceof ApiError && e.code === 'bad_password' && needsPassword && io.stdinIsTTY && !fromEnv)) throw e;
      io.stderr('wrong password — try again (the share was not opened).\n');
      password = await io.promptHidden('Password: ');
      access = await deriveAccess({ adata: head.adata, fragment, password });
      return client.open(kind, id, access);
    }
  };

  if (kind === 'paste' && values.field !== undefined && head.adata.fmt !== 'secret') {
    throw new UsageError('--field applies to credential shares only');
  }
  const code = kind === 'paste'
    ? await getNote({ io, values, openShare, access: () => access })
    : await getFiles({ io, values, client, id, sub, limited, openShare, access: () => access });
  // Only while the share still exists (not after its last view). Reading the
  // link from stdin keeps its #key out of shell history.
  if (head.meta.deletable === true && !(limited && head.meta.left <= 1)) {
    io.stderr('the sender lets you delete this share now: run  secbin delete --now -  and paste the link (then Ctrl-D)\n');
  }
  return code;
}

async function getNote({ io, values, openShare, access }) {
  // Open --out BEFORE the open request: an unwritable path must fail while
  // the note (and its view) still exists, not after the only copy is spent.
  let outFile = null;
  let created = false;
  if (values.out !== undefined) {
    created = await lstat(values.out).then(() => false, () => true);
    try {
      // 0600: the decrypted note is a secret; don't create it world-readable.
      outFile = await open(values.out, 'w', 0o600);
    } catch (e) {
      throw new UsageError(`cannot write --out ${values.out}: ${e.code ?? e.message}`);
    }
  }
  let written = false;
  try {
    const paste = validatePaste(await openShare());
    const out = await openPaste({ paste, access: access() });
    // Escaping is for a terminal only; --out files get the exact value.
    out.text = await renderNote(paste.adata.fmt, out.text, values.field, io, !outFile && io.stdoutIsTTY === true);
    if (outFile) {
      try {
        await outFile.writeFile(out.text);
        written = true;
      } catch (e) {
        // The view is already spent; the plaintext may be the only copy left.
        // Never swallow it — fall back to stdout so nothing is lost.
        io.stderr(`warning: writing --out ${values.out} failed (${e.code ?? e.message}); printing to stdout instead.\n`);
        io.stdout(out.text);
      }
    } else {
      io.stdout(out.text);
    }
    reportLeft(io, paste.meta);
    return 0;
  } finally {
    if (outFile) {
      await outFile.close();
      // Nothing was opened (wrong password, gone, …): don't leave an empty file behind.
      if (!written && created) await unlink(values.out).catch(() => {});
    }
  }
}

async function getFiles({ io, values, client, id, sub, limited, openShare, access }) {
  const platform = io.platform ?? process.platform;
  // Create/verify the output folder before the open request, like --out above.
  let root = null;
  if (!values.list) {
    try {
      root = await prepareRoot(values.out ?? '.');
    } catch (e) {
      if (e instanceof UsageError) throw e;
      throw new UsageError(`cannot use --out ${values.out ?? '.'}: ${e.code ?? e.message}`);
    }
  }

  const res = await openShare();
  if (!isPlainObject(res) || !GRANT_RE.test(res.grant ?? '') || !Number.isSafeInteger(res.chunks) || !Number.isSafeInteger(res.padded)) {
    throw new ApiError('Malformed response from the server.', 502, 'malformed');
  }
  const paste = validatePaste(res.paste);
  if (paste.adata.fmt !== 'files') throw new FormatError('not a file share');
  const { text } = await openPaste({ paste, access: access() });
  let manifest;
  try {
    manifest = validateManifest(JSON.parse(text));
  } catch (e) {
    throw new ManifestError(e instanceof ManifestError ? e.message : 'malformed manifest');
  }
  // The server's stream geometry must match what the (authenticated) manifest implies.
  if (res.chunks !== chunkCount(manifest.total) || res.padded !== paddedLength(manifest.total)) {
    throw new ManifestError('the server’s chunk layout does not match the manifest');
  }
  const lastView = 'that was the last view — the share can no longer be opened'
    + (Number.isSafeInteger(res.grantExpires) ? ` (this download window closes at ${new Date(res.grantExpires * 1000).toISOString()})` : '');

  const selection = select(manifest.entries, sub, limited);
  if (values.list) {
    printList(io, selection.map((s) => s.entry));
    const nf = selection.filter((s) => !s.entry.dir).length;
    io.stderr(`${nf} file${nf === 1 ? '' : 's'}, ${formatBytes(selection.reduce((n, s) => n + (s.entry.size ?? 0), 0))}\n`);
    reportLeft(io, paste.meta, lastView);
    return 0;
  }

  const plan = selection.map((s) => ({ rel: s.rel, dir: !!s.entry.dir }));
  try {
    await preflight(root, plan, { force: values.force, platform });
  } catch (e) {
    // A view-limited share's view is already spent: refusing now could lose
    // the only copy. Never overwrite — save into a new, empty folder instead.
    if (!(limited && e instanceof OverwriteError)) throw e;
    const fresh = await freshFolder(root, `secbin-${id}`, platform);
    io.stderr(`warning: ${e.paths.length} file${e.paths.length === 1 ? '' : 's'} already exist in ${root}; this share's view is already spent, so saving into ${fresh} instead (use --force to overwrite)\n`);
    root = fresh;
    await preflight(root, plan, { force: values.force, platform });
  }
  const reader = await ShareReader.create({ client, id, grant: res.grant, chunks: res.chunks, manifest });
  const total = selection.reduce((n, s) => n + (s.entry.size ?? 0), 0);
  const progress = io.stderrIsTTY === true && total > 0;
  let done = 0;
  const onBytes = (n) => {
    done += n;
    if (progress) io.stderr(`${CLEAR_LINE}downloading and decrypting… ${Math.floor((done / total) * 100)}% (${formatBytes(done)} of ${formatBytes(total)})`);
  };
  let files = 0;
  try {
    for (const s of selection) {
      if (s.entry.dir) {
        await writeDir(root, s.rel, platform);
      } else {
        await writeFile(root, s.rel, reader.stream(s.entry), { force: values.force, mtime: s.entry.mtime, platform, onBytes });
        files++;
      }
    }
  } finally {
    if (progress) io.stderr(CLEAR_LINE);
  }
  io.stderr(`saved ${files} file${files === 1 ? '' : 's'} (${formatBytes(total)}) to ${root}\n`);
  reportLeft(io, paste.meta, lastView);
  return 0;
}

// Exported for tests.
export { select as selectEntries };
