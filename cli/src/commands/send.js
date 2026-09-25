// send — share files and folders end to end encrypted (SPEC.md §12). A port of
// the dashboard's uploadFiles() (public/dashboard/js/create.js):
//
//   walk (no symlinks) → layout + encrypted manifest (names, folders, types,
//   sizes, mtimes — all inside the manifest) → POST /api/private/file (the
//   server learns only the padded total, the view limit, the expiry and — for
//   limit checks — the file count and largest file size) → each 8 MiB chunk of
//   the packed, zero-padded stream is read from disk at its offset, encrypted
//   and PUT → finalize with the manifest paste.
//
// Files are streamed chunk by chunk (never loaded whole). Everything that can
// fail locally (walk, names, sizes, the password, manifest encryption) happens
// before the first request. A failed upload is deleted with its delete token so
// no half-written share lingers until the server's upload deadline.
import { parseArgs } from 'node:util';
import { encryptPaste, MAX_PLAINTEXT } from '../../vendor/crypto.js';
import {
  buildManifest, checkMime, CHUNK, encryptChunk, importFileKey, layout, ManifestError, readStreamChunk,
} from '../../vendor/files.js';
import { refuseInlineApiKey, resolveApiKey } from '../apikey.js';
import { ApiError, Client } from '../client.js';
import { UsageError } from '../errors.js';
import { formatBytes } from '../format-bytes.js';
import { lifecycleLine, parseExpire, parseLabel, parseViews } from '../lifecycle.js';
import { renderQr } from '../qr.js';
import { newPassword } from '../secret.js';
import { CLEAR_LINE } from '../tui/anim.js';
import { buildShareUrl, isIdOfClass, requireServer } from '../url.js';
import { collect, fileSource, showPath } from '../walk.js';

const OPTIONS = {
  views: { type: 'string' },
  expire: { type: 'string' },
  label: { type: 'string' },
  mime: { type: 'string', multiple: true, default: [] },
  password: { type: 'boolean', default: false },
  'password-env': { type: 'string' },
  server: { type: 'string', short: 's' },
  'api-key-file': { type: 'string' },
  json: { type: 'boolean', default: false, short: 'j' },
  qr: { type: 'boolean', default: false, short: 'q' },
};

/** Apply `--mime <share-path>=<type>` overrides (validated with checkMime). */
function applyMimeOverrides(files, overrides) {
  const byPath = new Map(files.map((f) => [f.path, f]));
  for (const o of overrides) {
    const eq = o.lastIndexOf('='); // MIME types contain no "=", paths may
    if (eq <= 0) throw new UsageError(`invalid --mime "${o}" (expected <path-in-share>=<type/subtype>)`);
    const p = o.slice(0, eq);
    const type = o.slice(eq + 1).trim().toLowerCase();
    try {
      checkMime(type);
    } catch {
      throw new UsageError(`invalid MIME type in --mime "${o}" (expected type/subtype, e.g. text/plain)`);
    }
    const f = byPath.get(p);
    if (!f) throw new UsageError(`--mime: no file "${showPath(p)}" in the share (use the path as shown by \`secbin get --list\`, e.g. dir/file.txt)`);
    f.type = type;
  }
}

/** Retry a chunk once on a transient failure (network / 5xx), like the web client. */
async function putWithRetry(client, id, i, ct, token) {
  try {
    await client.putChunk(id, i, ct, token);
  } catch (e) {
    if (!(e instanceof ApiError) || (e.status !== 0 && e.status < 500)) throw e;
    await new Promise((r) => setTimeout(r, 1000));
    await client.putChunk(id, i, ct, token);
  }
}

export async function cmdSend(args, io) {
  refuseInlineApiKey(args);
  let values, positionals;
  try {
    ({ values, positionals } = parseArgs({ args, options: OPTIONS, allowPositionals: true, strict: true }));
  } catch (e) {
    throw new UsageError(e.message);
  }
  if (positionals.length === 0) throw new UsageError('usage: secbin send <file|dir>… [flags]');
  if (values.password && values['password-env'] !== undefined) {
    throw new UsageError('--password and --password-env are mutually exclusive');
  }
  const views = parseViews(values.views);
  const expire = parseExpire(values.expire);
  const label = parseLabel(values.label);
  const server = requireServer(values.server, io.env);
  const apiKey = await resolveApiKey({ file: values['api-key-file'], io });

  // ── everything local first ────────────────────────────────────────────────
  const { files, dirs } = await collect(positionals, io);
  applyMimeOverrides(files, values.mime);
  let l;
  try {
    l = layout(files.map((f) => ({ path: f.path, type: f.type, size: f.size, mtime: f.mtime })), dirs);
  } catch (e) {
    if (e instanceof ManifestError) throw new UsageError(`cannot build the share: ${e.message}`);
    throw e;
  }
  // No viewer policy: the admin's policy is not readable with an API key, so
  // CLI shares are download-only in the web viewer (view: null).
  const manifest = buildManifest({ entries: l.entries, total: l.total, view: null });
  const manifestText = JSON.stringify(manifest);
  if (new TextEncoder().encode(manifestText).length > MAX_PLAINTEXT) {
    throw new UsageError('too many files or too long paths: the encrypted file list would exceed 1 MiB');
  }
  const password = await newPassword({ envVar: values['password-env'], promptWanted: values.password, io });
  const { body, fragment } = await encryptPaste({
    text: manifestText, fmt: 'files', password, bar: views !== null, views: views ?? undefined, expire,
  });

  // ── upload ────────────────────────────────────────────────────────────────
  const client = new Client(server, io.fetch, { apiKey });
  // files/maxFile are declared so the server can apply per-account limits;
  // names, types and individual sizes stay inside the encrypted manifest.
  const init = await client.initFile({
    views, expire, padded: l.padded, files: files.length, maxFile: Math.max(0, ...files.map((f) => f.size)),
  });
  if (!isIdOfClass(init.id, 'f')) throw new ApiError('Malformed response from the server.', 502, 'malformed');

  const progress = io.stderrIsTTY === true;
  let fin;
  try {
    // The chunk count is implied by the padded length we sent; a server that
    // disagrees is not speaking this protocol.
    if (init.chunks !== l.chunks) throw new ApiError('Malformed response from the server.', 502, 'malformed');
    const key = await importFileKey(manifest.fk);
    const sources = files.map((f, i) => fileSource(f, l.entries[i].off));
    for (let i = 0; i < init.chunks; i++) {
      if (progress) {
        io.stderr(`${CLEAR_LINE}encrypting and uploading… ${Math.floor((i / init.chunks) * 100)}% (${formatBytes(Math.min(i * CHUNK, l.total))} of ${formatBytes(l.total)})`);
      }
      const ct = await encryptChunk(key, i, init.chunks, await readStreamChunk(sources, i, l.total));
      await putWithRetry(client, init.id, i, ct, init.uploadtoken);
    }
    if (progress) io.stderr(`${CLEAR_LINE}sealing the manifest…`);
    fin = await client.finalizeFile(init.id, init.uploadtoken, body, label);
  } catch (e) {
    // Best effort: remove the half-finished upload (and its stored chunks) now
    // rather than leaving it until the server's upload deadline.
    await client.deleteShare('file', init.id, init.deletetoken).catch(() => {});
    throw e;
  } finally {
    if (progress) io.stderr(CLEAR_LINE);
  }

  const url = buildShareUrl(server, init.id, fragment);
  const expires = Number.isSafeInteger(fin.expires) ? fin.expires : null;
  if (values.json) {
    io.stdout(JSON.stringify({ url, id: init.id, deletetoken: init.deletetoken, expires, views }) + '\n');
  } else {
    io.stdout(url + '\n');
    io.stderr(`delete token: ${init.deletetoken}\n`);
    const nf = files.length;
    io.stderr(`${nf} file${nf === 1 ? '' : 's'}${dirs.length ? ` and ${dirs.length} empty folder${dirs.length === 1 ? '' : 's'}` : ''}, ${formatBytes(l.total)}\n`);
    io.stderr(`${lifecycleLine({ what: 'the files', views, expire })}\n`);
  }
  if (values.qr) {
    const qr = renderQr(url);
    if (qr) io.stderr(qr);
  }
  return 0;
}
