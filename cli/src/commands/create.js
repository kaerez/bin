// create — encrypt a note locally, POST only ciphertext to the account API
// (API key), print the share URL.
//
// The lifecycle is chosen per note: --views (default 1; "unlimited" makes an
// ordinary KV note, bar:false) and --expire (default 24h). The server enforces
// the account's limits and refuses — never silently lowers — a request beyond
// them.
//
// stdout carries ONLY the share URL (or the --json object), so
// `secbin create | pbcopy` copies just the link; the delete token, lifecycle
// note, and optional --qr code go to stderr. The fragment secret F never leaves
// the process except inside the printed URL.
import { readFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { encryptPaste, MAX_PLAINTEXT } from '../../vendor/crypto.js';
import { FORMATS } from '../../vendor/format.js';
import { refuseInlineApiKey, resolveApiKey } from '../apikey.js';
import { ApiError, Client } from '../client.js';
import { UsageError } from '../errors.js';
import { lifecycleLine, parseExpire, parseLabel, parseViews } from '../lifecycle.js';
import { renderQr } from '../qr.js';
import { newPassword } from '../secret.js';
import { buildShareUrl, isIdOfClass, requireServer } from '../url.js';

// Notes are text; "files" is the file-share manifest format (`secbin send`).
const NOTE_FORMATS = FORMATS.filter((f) => f !== 'files');

const OPTIONS = {
  text: { type: 'string', short: 't' },
  file: { type: 'string', short: 'f' },
  fmt: { type: 'string', default: 'plaintext' },
  views: { type: 'string' },
  expire: { type: 'string' },
  label: { type: 'string' },
  password: { type: 'boolean', default: false },
  'password-env': { type: 'string' },
  server: { type: 'string', short: 's' },
  'api-key-file': { type: 'string' },
  json: { type: 'boolean', default: false, short: 'j' },
  qr: { type: 'boolean', default: false, short: 'q' },
};

/** Encrypt + upload a note. Shared with the wizard. Returns { url, id, deletetoken, expires }. */
export async function createNote({ server, apiKey, text, password, fmt, views, expire, label, io }) {
  const bar = views !== null;
  const { body, fragment } = await encryptPaste({
    text, password, fmt, bar, expire, views: bar ? views : undefined,
  });
  const client = new Client(server, io.fetch, { apiKey });
  const { id, deletetoken, expires } = await client.createNote(body, label);
  // The id goes into the printed URL: accept only the storage class we asked for.
  if (!isIdOfClass(id, bar ? 'b' : 'k')) throw new ApiError('Malformed response from the server.', 502, 'malformed');
  return { url: buildShareUrl(server, id, fragment), id, deletetoken, expires: Number.isSafeInteger(expires) ? expires : null };
}

export async function cmdCreate(args, io) {
  refuseInlineApiKey(args);
  let values;
  try {
    // allowPositionals: false → parseArgs throws on any positional.
    ({ values } = parseArgs({ args, options: OPTIONS, allowPositionals: false, strict: true }));
  } catch (e) {
    throw new UsageError(e.message);
  }

  if (!NOTE_FORMATS.includes(values.fmt)) {
    throw new UsageError(`invalid --fmt "${values.fmt}" (one of: ${NOTE_FORMATS.join(', ')})`);
  }
  if (values.password && values['password-env'] !== undefined) {
    throw new UsageError('--password and --password-env are mutually exclusive');
  }
  if (values.text !== undefined && values.file !== undefined) {
    throw new UsageError('--text and --file are mutually exclusive');
  }
  const views = parseViews(values.views);
  const expire = parseExpire(values.expire);
  const label = parseLabel(values.label);
  const server = requireServer(values.server, io.env);
  const apiKey = await resolveApiKey({ file: values['api-key-file'], io });

  let raw;
  if (values.text !== undefined) {
    raw = Buffer.from(values.text, 'utf8');
  } else if (values.file !== undefined) {
    try {
      raw = await readFile(values.file);
    } catch (e) {
      throw new UsageError(`cannot read --file ${values.file}: ${e.code ?? e.message}`);
    }
  } else {
    if (io.stdinIsTTY) {
      throw new UsageError('no input: pipe content on stdin, or pass --text <string> / --file <path>');
    }
    raw = await io.readStdin();
  }
  if (raw.byteLength === 0) throw new UsageError('refusing to create an empty note');
  if (raw.byteLength > MAX_PLAINTEXT) {
    throw new UsageError('input too large (max 1 MiB before compression — use `secbin send` for files)');
  }
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
  } catch {
    throw new UsageError('input is not valid UTF-8 (notes are text — use `secbin send` for binary files)');
  }

  const password = await newPassword({ envVar: values['password-env'], promptWanted: values.password, io });

  const { url, id, deletetoken, expires } = await createNote({
    server, apiKey, text, password, fmt: values.fmt, views, expire, label, io,
  });

  if (values.json) {
    io.stdout(JSON.stringify({ url, id, deletetoken, expires, views }) + '\n');
  } else {
    io.stdout(url + '\n');
    io.stderr(`delete token: ${deletetoken}\n`);
    io.stderr(`${lifecycleLine({ what: 'the note', views, expire })}\n`);
  }
  if (values.qr) {
    const qr = renderQr(url);
    if (qr) io.stderr(qr);
  }
  return 0;
}
