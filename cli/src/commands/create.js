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
import { buildSecret, parseShareUrl as parseLinkUrl, SECRET_FIELDS, ShareTypeError, urlRulesOf } from '../../vendor/sharetypes.js';
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
  'recipient-can-delete': { type: 'boolean', default: false },
};

// Hidden prompts for the secret fields that must not echo; the rest are one line each.
const SECRET_PROMPTS = [
  ['title', 'Title', false], ['username', 'User name', false], ['password', 'Password', true],
  ['url', 'Sign-in URL', false], ['totp', 'One-time-code seed or otpauth:// URI', true], ['notes', 'Notes', false],
];

/** A credential share's plaintext from a JSON object (file/stdin) — never argv. */
function secretFromJson(text) {
  let d;
  try { d = JSON.parse(text); } catch { throw new UsageError('--fmt secret reads a JSON object of fields from --file or stdin'); }
  if (!d || typeof d !== 'object' || Array.isArray(d)) throw new UsageError('--fmt secret reads a JSON object of fields from --file or stdin');
  const unknown = Object.keys(d).filter((k) => !Object.hasOwn(SECRET_FIELDS, k));
  if (unknown.length) throw new UsageError(`unknown secret field(s): ${unknown.map((k) => JSON.stringify(k.slice(0, 40))).join(', ')} (allowed: ${Object.keys(SECRET_FIELDS).join(', ')})`);
  return buildSecret(d);
}

async function secretFromPrompts(io) {
  io.stderr('Credential share — leave a field empty to skip it.\n');
  const fields = {};
  for (const [k, label, hidden] of SECRET_PROMPTS) {
    fields[k] = hidden ? await io.promptHidden(`${label}: `) : await io.promptLine(`${label}: `);
  }
  return buildSecret(fields);
}

/**
 * Validate and normalize a typed payload ("url" / "secret"); other formats
 * pass through. `urlRules` are the account's (the server cannot check links).
 */
function typedPayload(fmt, text, urlRules) {
  try {
    if (fmt === 'url-syntax') return parseLinkUrl(text, { recipient: true }).href;
    if (fmt === 'url') return parseLinkUrl(text, { rules: urlRulesOf(urlRules) }).href;
    if (fmt === 'secret') return secretFromJson(text);
  } catch (e) {
    if (e instanceof ShareTypeError) throw new UsageError(e.message);
    throw e;
  }
  return text;
}

/** Encrypt + upload a note. Shared with the wizard. Returns { url, id, deletetoken, expires }. */
export async function createNote({ server, apiKey, text, password, fmt, views, expire, label, deletable = false, io }) {
  const bar = views !== null;
  const { body, fragment } = await encryptPaste({
    text, password, fmt, bar, expire, views: bar ? views : undefined, deletable,
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
  // Command-line arguments are visible to other local processes and land in
  // shell history: never take credentials from them.
  if (values.fmt === 'secret' && values.text !== undefined) {
    throw new UsageError('--fmt secret does not take --text (arguments are visible to other processes): use --file, stdin, or the prompts');
  }
  const views = parseViews(values.views);
  const expire = parseExpire(values.expire);
  const label = parseLabel(values.label);
  const server = requireServer(values.server, io.env);
  const apiKey = await resolveApiKey({ file: values['api-key-file'], io });

  let raw;
  let prompted = null;
  if (values.fmt === 'secret' && values.file === undefined && io.stdinIsTTY) {
    try {
      prompted = await secretFromPrompts(io);
    } catch (e) {
      if (e instanceof ShareTypeError) throw new UsageError(e.message);
      throw e;
    }
    raw = Buffer.from(prompted, 'utf8');
  } else if (values.text !== undefined) {
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
  let urlRules;
  if (values.fmt === 'url' && prompted === null) {
    // Syntax and forbidden schemes first (no request for a link that can never
    // be shared), then the account's own rules.
    typedPayload('url-syntax', text);
    urlRules = (await new Client(server, io.fetch, { apiKey }).policy())?.urlRules;
  }
  if (prompted === null) text = typedPayload(values.fmt, text, urlRules);

  const password = await newPassword({ envVar: values['password-env'], promptWanted: values.password, io });

  const { url, id, deletetoken, expires } = await createNote({
    server, apiKey, text, password, fmt: values.fmt, views, expire, label, deletable: values['recipient-can-delete'], io,
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
