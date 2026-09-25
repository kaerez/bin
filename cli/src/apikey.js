// apikey.js — resolve the account API key used for share creation.
//
// Keys come from $SECBIN_API_KEY or --api-key-file <path>, never a bare flag
// value: argv is visible to every local process and lands in shell history. A
// key file readable by other users is refused (world) or warned about (group),
// the same hygiene ssh applies to private keys. The key itself is never
// printed, not even in error messages.
import { open } from 'node:fs/promises';
import process from 'node:process';
import { UsageError } from './errors.js';

export const API_KEY_RE = /^sbk_[A-Za-z0-9_-]{43}$/;
const MAX_KEY_FILE = 4096;

const HOW_TO_GET = 'create one in the dashboard under Account → API keys (if your admin enabled API access)';

/** Reject `--api-key <value>` with a helpful message before parseArgs sees it. */
export function refuseInlineApiKey(args) {
  if (args.some((a) => a === '--api-key' || a.startsWith('--api-key='))) {
    throw new UsageError('--api-key is not supported: keys on the command line leak into shell history and process listings — use SECBIN_API_KEY or --api-key-file <path>');
  }
}

async function readKeyFile(path, io) {
  let fh;
  try {
    fh = await open(path, 'r');
  } catch (e) {
    throw new UsageError(`cannot read --api-key-file ${path}: ${e.code ?? e.message}`);
  }
  try {
    const st = await fh.stat();
    if (!st.isFile()) throw new UsageError(`--api-key-file ${path} is not a regular file`);
    if ((io.platform ?? process.platform) !== 'win32') {
      if (st.mode & 0o007) {
        throw new UsageError(`--api-key-file ${path} is accessible by other users — run: chmod 600 ${path} (or use SECBIN_API_KEY)`);
      }
      if (st.mode & 0o070) io.stderr(`warning: --api-key-file ${path} is accessible by its group — consider: chmod 600 ${path}\n`);
    }
    const buf = Buffer.alloc(MAX_KEY_FILE + 1);
    const { bytesRead } = await fh.read(buf, 0, buf.length, 0);
    if (bytesRead > MAX_KEY_FILE) throw new UsageError(`--api-key-file ${path} is too large to be an API key`);
    return buf.subarray(0, bytesRead).toString('utf8').trim();
  } finally {
    await fh.close();
  }
}

/**
 * The API key for create/send: --api-key-file wins over $SECBIN_API_KEY.
 * Throws a UsageError (exit 2) when none is configured or it is malformed.
 */
export async function resolveApiKey({ file, io }) {
  let key;
  let source;
  if (file !== undefined) {
    key = await readKeyFile(file, io);
    source = `the key in ${file}`;
  } else {
    key = io.env.SECBIN_API_KEY;
    source = 'SECBIN_API_KEY';
    if (key === undefined || key === '') {
      throw new UsageError(`creating shares needs an API key — set SECBIN_API_KEY or pass --api-key-file <path>; ${HOW_TO_GET}`);
    }
    key = key.trim();
  }
  if (!API_KEY_RE.test(key)) {
    throw new UsageError(`${source} is not a valid API key (expected "sbk_" followed by 43 characters)`);
  }
  return key;
}
