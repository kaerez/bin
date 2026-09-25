// cli.js — command dispatch, help/version, and error → exit-code mapping.
//
// Exit codes: 0 ok · 1 crypto/API error · 2 usage error · 130 aborted.
// All I/O flows through an injectable `io` object so the command logic is
// testable without spawning processes or a TTY.
import { createRequire } from 'node:module';
import process from 'node:process';
import { DecryptError, PasswordRequired } from '../vendor/crypto.js';
import { ManifestError } from '../vendor/files.js';
import { FormatError } from '../vendor/format.js';
import { ApiError } from './client.js';
import { cmdCreate } from './commands/create.js';
import { cmdDelete } from './commands/delete.js';
import { cmdGet } from './commands/get.js';
import { cmdSend } from './commands/send.js';
import { cmdUpdate, cmdVersion } from './commands/update.js';
import { AbortError, UsageError } from './errors.js';
import { UnsafePathError } from './extract.js';
import { confirm, promptHidden, promptLine, promptMultiline } from './prompt.js';
import { copyToClipboard } from './tui/clipboard.js';
import { readKey, releaseKeys } from './tui/keys.js';
import { center } from './tui/screen.js';
import { runWizard } from './wizard.js';

export const VERSION = createRequire(import.meta.url)('../package.json').version;

const HELP = `secbin ${VERSION} — zero-knowledge encrypted notes and file sharing

Everything is encrypted locally (AES-256-GCM; passwords via Argon2id). The key
travels in the share URL's #fragment and never reaches the server, which only
stores ciphertext. Shares are view-limited and self-destruct when they expire.

Usage:
  secbin                             interactive: write a note, get its link + QR
  secbin create [flags]              encrypt stdin, --text, or --file as a note
  secbin send <file|dir>… [flags]    share files and folders (recursive)
  secbin get <share-url | ->         open a note or file share ("-" reads the URL from stdin)
  secbin view <share-url | ->        alias for get
  secbin delete <share-url | id>     delete a share with its delete token
  secbin delete --now <share-url|->  as a recipient, delete a share whose sender allows it
  secbin update                      update the global npm installation
  secbin version, -v                 show the version and check for updates

create / send flags:
  --views <n|unlimited>  views before the share is deleted (default 1; max 100000)
  --expire <n>m|h|d      lifetime, 1m … 365d (default 24h)
  --label <text>         label in your account's share list — NOT ENCRYPTED:
                         visible to the server and its administrators
  --password             prompt for a password (hidden, asked twice)
  --password-env <VAR>   read the password from an environment variable
  --api-key-file <path>  read the API key from a file (default: $SECBIN_API_KEY)
  -q, --qr               also print a scannable QR code (to stderr)
  -j, --json             print {url, id, deletetoken, expires, views} as JSON
  --recipient-can-delete let whoever opens the share delete it at once
                         ("delete now"; the administrator must allow it)
create only:
  -t, --text <string>    use the given string as the note content
  -f, --file <path>      read content from a file instead of stdin
  --fmt <fmt>            plaintext (default) | code | markdown | url | secret
                         url: one http(s) link · secret: a credential — a JSON
                         object {title, username, password, url, totp, notes}
                         from --file or stdin, or asked for on a terminal
send only:
  --mime <path>=<type>   override the detected type of a file in the share (repeatable)
  Symlinks are skipped, never followed. Names, folders and types stay encrypted;
  the file count and largest file size are declared to the server for limit checks.
get flags:
  -o, --out <path>       note: write to a file (0600) · files: output folder (default .)
  -l, --list             file share: print the file list instead of downloading
  -p, --path <sub>       file share: download only this file or folder
  --force                file share: overwrite existing files
  -y, --yes              skip the "this uses a view" confirmation
  --password-env <VAR>   read the password from an environment variable
  --field <name>         credential share: print one field (title, username,
                         password, url, totp, notes) or "code" (the current
                         one-time code) instead of the JSON
delete flags:
  --token-env <VAR>      read the delete token from an environment variable
  --now                  recipient delete (see above); --password-env <VAR> for
                         a password-protected share
Global:
  -s, --server <url>     server origin for create/send, and delete by bare id
                         (default $SECBIN_SERVER — required, there is no built-in
                         server); get/delete take it from the share URL
  -h, --help             show this help (also after a command)
  -V, --version          print the version

Creating shares needs an account API key (Dashboard → Account → API keys):
  export SECBIN_SERVER=https://secbin.example.com SECBIN_API_KEY=sbk_…
"create" is assumed when stdin is piped with no command, or when --text is given:
  git diff | secbin
  secbin -t "meet at 6"

The share URL (including its secret #fragment) is visible to other local
processes when passed as an argument; prefer  echo <url> | secbin get -
on shared machines. Exit codes: 0 ok · 1 crypto/API error · 2 usage error · 130 aborted.
`;

export function defaultIo() {
  const io = {
    stdout: (s) => { process.stdout.write(s); },
    stderr: (s) => { process.stderr.write(s); },
    env: process.env,
    fetch: globalThis.fetch.bind(globalThis),
    stdinIsTTY: Boolean(process.stdin.isTTY),
    stdoutIsTTY: Boolean(process.stdout.isTTY),
    stderrIsTTY: Boolean(process.stderr.isTTY),
    columns: () => process.stderr.columns ?? 80,
    rows: () => process.stderr.rows ?? 24,
    readStdin: async () => {
      const chunks = [];
      for await (const chunk of process.stdin) chunks.push(chunk);
      return Buffer.concat(chunks);
    },
    promptHidden: (question) => promptHidden(question),
    promptLine: (question) => promptLine(question),
    promptMultiline: (prompt) => promptMultiline({ prompt }),
    confirm: (question) => confirm(question),
    readKey: () => readKey(),
    // Hand stdin back after a readKey-driven screen (menu, result screen) so
    // the readline-based prompts get a clean stream — see tui/keys.js.
    releaseKeys: () => releaseKeys(),
    // Swallow keystrokes during a non-interactive stretch (the wizard intro):
    // raw mode stops the terminal echoing them over the animation, and the
    // discard listener keeps them from buffering into the first menu read.
    // Ctrl+C is re-raised as a real SIGINT so aborting still works (the
    // bin/secbin.js handler restores the terminal). Returns an unmute fn.
    muteInput: () => {
      if (!process.stdin.isTTY) return () => {};
      const discard = (buf) => {
        if (buf.includes(0x03)) process.kill(process.pid, 'SIGINT');
      };
      process.stdin.setRawMode(true);
      process.stdin.resume();
      process.stdin.on('data', discard);
      // Unmute only removes the discard listener. Raw mode and flow stay on:
      // the menu's key reader takes over immediately, and toggling the conpty
      // console mode in between races its async mode application (see
      // tui/keys.js). bin/secbin.js restores the terminal on exit.
      return () => {
        process.stdin.off('data', discard);
      };
    },
  };
  io.copy = (text) => copyToClipboard(text, io);
  return io;
}

function apiMessage(e) {
  const m = e.message; // already sanitized by client.js
  switch (e.code) {
    case 'bad_link': return 'the link is incomplete or corrupted (the share was not opened)';
    case 'bad_password': return 'wrong password (the share was not opened)';
    case 'bad_token': return 'wrong delete token (nothing was deleted)';
    case 'bad_grant': return 'the download window has expired — open the link again (this uses another view if the share is view-limited)';
    case 'blocked': return 'blocked — too many invalid requests from your network; try again later';
    case 'unauthenticated':
    case 'invalid_api_key': return `the server rejected the API key: ${m} (check SECBIN_API_KEY / --api-key-file)`;
    case 'api_key_not_allowed': return `the server refused the API key here: ${m}`;
    default: break;
  }
  switch (e.status) {
    case 0: return m; // network-level: timeout / unreachable (no HTTP status)
    case 401: return `authentication failed: ${m} (check SECBIN_API_KEY / --api-key-file)`;
    case 403: return `refused by the server: ${m}`;
    case 404: return 'not found — wrong URL, or the share has expired';
    case 410: return 'gone — the share has expired, has no views left, or was deleted';
    case 413: return `too large for the server: ${m}`;
    case 429: return `limit reached: ${m}`;
    case 400: return `rejected by the server: ${m}`;
    default: return `${m} (HTTP ${e.status})`;
  }
}

async function dispatch(argv, io) {
  const [command, ...rest] = argv;
  if (command === '--help' || command === '-h') {
    io.stdout(HELP);
    return 0;
  }
  if (command === '--version' || command === '-V') {
    io.stdout(VERSION + '\n');
    return 0;
  }
  // `secbin create --help` should show help, not exit 2 with "Unknown option".
  if (rest.includes('--help') || rest.includes('-h')) {
    io.stdout(HELP);
    return 0;
  }
  switch (command) {
    case 'create': return cmdCreate(rest, io);
    case 'send': return cmdSend(rest, io);
    case 'get':
    case 'view': return cmdGet(rest, io);
    case 'delete': return cmdDelete(rest, io);
    case 'update': return cmdUpdate(rest, io);
    case 'version': return cmdVersion(rest, io);
    case '-v': return cmdVersion(rest, io);
    default: {
      // Default command is create when stdin is piped (`cat notes.md | secbin`)
      // or when the content is inline (`secbin -t "hi"` / `secbin -f notes.md`
      // — no stdin needed for either).
      const inlineInput = argv.some((a) => a === '--text' || a.startsWith('--text=')
        || a === '--file' || a.startsWith('--file=') || /^-[a-z]*[tf]/.test(a));
      if ((command === undefined || command.startsWith('-')) && (!io.stdinIsTTY || inlineInput)) {
        return cmdCreate(argv, io);
      }
      // Bare `secbin` on a terminal: the interactive wizard.
      if (command === undefined) {
        return runWizard(io);
      }
      throw new UsageError(`unknown command "${String(command).slice(0, 40)}" (expected create, send, get/view, delete, update, or version)`);
    }
  }
}

/** Run the CLI. Returns the process exit code; never throws. */
export async function run(argv, io = defaultIo()) {
  try {
    return await dispatch(argv, io);
  } catch (e) {
    // Bare `secbin` on a TTY ran the wizard, whose screens are centered —
    // its error lines are centered to match; plain commands stay left-aligned.
    const wizard = argv[0] === undefined && io.stdinIsTTY && typeof io.columns === 'function';
    const fail = (message, code) => {
      io.stderr((wizard ? center(message, io.columns()) : message) + '\n');
      return code;
    };
    if (e instanceof AbortError) return fail(`secbin: ${e.message}`, 130);
    if (e instanceof UsageError) return fail(`secbin: ${e.message}`, 2);
    if (e instanceof ApiError) return fail(`secbin: ${apiMessage(e)}`, 1);
    if (e instanceof PasswordRequired) {
      return fail('secbin: this share requires a password (use --password-env)', 1);
    }
    if (e instanceof DecryptError) {
      return fail('secbin: decryption failed — the link is wrong, or the share was tampered with', 1);
    }
    if (e instanceof FormatError) {
      return fail(`secbin: the server returned a malformed share (${e.message})`, 1);
    }
    if (e instanceof ManifestError) {
      return fail(`secbin: the file share is malformed or was tampered with (${e.message})`, 1);
    }
    if (e instanceof UnsafePathError) return fail(`secbin: ${e.message} — nothing more was written`, 1);
    return fail(`secbin: ${e.message}`, 1);
  }
}
