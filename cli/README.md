<div align="center">

<h1 align="center"><strong>secbin</strong> — from your terminal</h1>

<p align="center">Zero-knowledge, end-to-end encrypted notes and file sharing with view limits and expiry.</p>

<p align="center">
  <a href="https://github.com/kaerez/bin#readme">Project README</a> ·
  <a href="https://github.com/kaerez/bin/blob/main/SPEC.md">Protocol</a> ·
  <a href="https://github.com/kaerez/bin/blob/main/SECURITY.md">Security</a> ·
  <a href="https://github.com/kaerez/bin/issues">Report a bug</a>
</p>

</div>

Command-line client for [secbin](https://github.com/kaerez/bin), a self-hosted, zero-knowledge,
end-to-end encrypted pastebin and file-sharing service. Content is encrypted locally
**before** any network request is made. It uses AES-256-GCM, and passwords are stretched
with Argon2id. The decryption key travels only in the share URL's `#fragment`, which is
never sent to the server. The CLI implements the same protocol (v2) as the web client and
ships byte-identical copies of its crypto modules, verified against the same pinned test
vectors.

The CLI has no runtime dependencies. It uses Node ≥ 20 built-ins (WebCrypto,
`CompressionStream`, `fetch`, `node:util` `parseArgs`) plus the vendored WebAssembly
Argon2id build from the repository.

## Install

The CLI is installed from a clone of the repository. The name `secbin` on the public npm
registry belongs to an unrelated package, so do not use `npm install -g secbin`.

```bash
git clone https://github.com/kaerez/bin.git
npm install -g ./bin/cli          # puts `secbin` on your PATH
# or run it without installing:
npx ./bin/cli --help
```

## Configuration

secbin is self-hosted, so **there is no built-in default server**.

| Setting | Meaning |
| --- | --- |
| `SECBIN_SERVER` / `-s, --server <origin>` | The server origin, e.g. `https://secbin.example.com`. **Required** for `create`, `send`, and `delete <bare-id>`. `get` and `delete <url>` take the origin from the share URL. |
| `SECBIN_API_KEY` / `--api-key-file <path>` | Your account API key (`sbk_…`), **required** to create shares. Get one from **Dashboard → Account → API keys**; this is only available if your admin enabled API access. The key file must not be accessible to other users (`chmod 600`). The key is never accepted as a plain flag value, and it is sent only as `Authorization: Bearer …` to the creation endpoints. |
| `SECBIN_NO_ANIMATION=1` | Disables non-essential TUI motion (intro, shine, spinner) while keeping colors. `NO_COLOR` disables colors. |

```bash
export SECBIN_SERVER=https://secbin.example.com
export SECBIN_API_KEY=sbk_...          # or: --api-key-file ~/.config/secbin/key
```

HTTPS is enforced for every server except `localhost`, `127.0.0.1` and `[::1]` (for
`wrangler dev`). The CLI never follows HTTP redirects, because a redirect would replay
secret headers to another host.

Opening or deleting a share needs **no** account and no API key. The link (plus the
password, if one was set) or the delete token is the capability.

## Usage

### Interactive: just type `secbin`

On a terminal, a bare `secbin` opens a full-screen menu. The menu offers three actions:

- **Create a note**: write a note, press **Ctrl+Q** to seal it, and optionally add a
  password. The result screen shows the share link, a terminal QR code and the delete
  token. Press **c** to copy the link or **t** to copy the token. Copying uses the
  platform's clipboard tool, fed over stdin, with an OSC 52 fallback for SSH.
  - Wizard notes use the defaults: one view, and they expire after 24 hours if unopened.
  - Creating needs `SECBIN_API_KEY`. The wizard asks for the server if `SECBIN_SERVER`
    is not set.
- **View a note**: paste a share URL. You are asked to confirm before a view-limited note
  is opened. For file shares, use `secbin get`.
- **Delete a share**: paste the share URL, then the delete token.

All decoration is drawn on stderr. Only machine-readable output goes to stdout, so
`secbin | pbcopy` still copies just the link.

### Scripting

```bash
# A one-time note from stdin (create is the default when stdin is piped)
git diff | secbin
secbin -t "meet at 6"

# Three views, one week, password-protected, machine-readable output
secbin create --file secrets.txt --views 3 --expire 7d --password --json

# Share a folder and a file (recursive; symlinks are skipped)
secbin send ./reports invoice.pdf --views unlimited --expire 30d --label "Q3 handoff"

# Open a note, or download a file share
secbin get 'https://secbin.example.com/p/<id>#<key>'
secbin get 'https://secbin.example.com/p/<id>#<key>' --out ./downloads
echo '<url>' | secbin get - --list

# Delete early with the token printed at creation
SB_TOKEN=... secbin delete '<share-url>' --token-env SB_TOKEN
```

### `secbin create [flags]`

Encrypts a note from stdin, `--text` or `--file` (UTF-8 text, up to 1 MiB before
compression) and uploads only ciphertext. The share URL goes to **stdout**. The delete token
and a one-line summary of the share's lifecycle go to **stderr**.

| Flag | Meaning |
| --- | --- |
| `-t, --text <string>` | Use the given string as the note content (it lands in argv and shell history) |
| `-f, --file <path>` | Read the content from a file instead of stdin |
| `--fmt <fmt>` | `plaintext` (default), `code`, `markdown`, `url` or `secret` (see below); this affects rendering |
| `--recipient-can-delete` | Let whoever opens the share delete it at once ("delete now"). The administrator must allow it. Also on `send`. |
| `--views <n\|unlimited>` | Views before the note is deleted. The default is `1` and the maximum is `100000`. `unlimited` keeps the note until it expires. |
| `--expire <n>m\|h\|d` | Lifetime from `1m` to `365d` (default `24h`) |
| `--label <text>` | A label in your account's share list (up to 100 characters). It is **not encrypted**: the server and its administrators can see it. |
| `--password` | Prompt for a password (hidden, asked twice, up to 128 characters) |
| `--password-env <VAR>` | Read the password from an environment variable |
| `--api-key-file <path>` | Read the API key from a file instead of `$SECBIN_API_KEY` |
| `-s, --server <origin>` | Server origin (default `$SECBIN_SERVER`) |
| `-q, --qr` | Also print a scannable QR code to stderr |
| `-j, --json` | Print `{url, id, deletetoken, expires, views}` as JSON (`views: null` = unlimited) |

Your account's limits (maximum views, maximum expiry, quotas) are enforced by the server. A
request beyond them is refused with the server's reason; it is never silently shortened.

**Links and credentials** (if your administrator allows them):

```sh
secbin create --fmt url --text https://example.com/report     # one http(s) link
secbin create --fmt secret --file cred.json                   # {"title","username","password","url","totp","notes"}
secbin create --fmt secret                                    # on a terminal: asks for each field, hiding the password and seed
```

A credential is never taken from the command line (`--text` is refused with `--fmt secret`):
arguments are visible to other local processes and land in shell history. Unknown fields,
invalid links and malformed one-time-code seeds are refused before anything is sent.

### `secbin send <file|dir>… [flags]`

Shares files and folders. Directory arguments are walked recursively. A directory `dir`
becomes `dir/…` in the share, and a file argument keeps just its name. Empty folders are
preserved. **Symbolic links are never followed.** Links, sockets and devices are skipped
with a warning. Two inputs that map to the same path in the share are rejected.

Files are streamed from disk one 8 MiB chunk at a time. They are never loaded whole. All
files are packed into one zero-padded stream, and each chunk is encrypted with AES-256-GCM
under a per-share key before upload. A progress line is shown when stderr is a terminal.
If an upload fails, the half-finished share is deleted.

The MIME type of each file is detected from its magic bytes, then its extension, and falls
back to `application/octet-stream`. You can override it per file with
`--mime <path-in-share>=<type>`, e.g. `--mime reports/q3.txt=text/markdown`. Shares sent from
the CLI are download-only in the web viewer. The admin's inline-preview policy cannot be
read with an API key, so the CLI does not enable previews.

Flags: `--views`, `--expire`, `--label`, `--password`, `--password-env`, `--api-key-file`,
`--server`, `--mime` (repeatable), `-q/--qr` and `-j/--json`, as for `create`. The share URL
goes to stdout, and the delete token goes to stderr.

### `secbin get <share-url | ->` (alias: `view`)

Opens a note or a file share. Pass `-` to read the URL from stdin. The CLI follows the same
steps as the browser:

1. It fetches the share's public head. This never contains ciphertext and never spends a view.
2. It derives two access proofs locally, from the `#fragment` and the Argon2id-stretched
   password if one is set.
3. For view-limited shares, it asks for confirmation on a TTY (`--yes` skips this; it is
   skipped automatically without a TTY).
4. It sends the proofs to the server. The server checks them **before** it releases any
   ciphertext or spends a view. A wrong link or wrong password is refused, and the share
   is untouched. When a typed password is wrong, you are asked once more on a TTY.

For **notes**, the plaintext goes to stdout, or to `--out <file>` with mode `0600`. The
file is opened before the view is spent, so an unwritable path fails first.

A **link** share prints the validated link on stdout and its real host on stderr (with a
warning for internationalized look-alike names or plain HTTP); it is never opened for you. A
**credential** share prints its fields as JSON, or one field with `--field <name>`
(`title`, `username`, `password`, `url`, `totp`, `notes`) or `--field code` for the current
one-time code. Control characters are escaped before anything reaches a terminal. If the
payload is malformed or the field is missing, the whole content is still printed (the view is
already spent) with a warning.

For **file shares**, the files are written under `--out <dir>` (default: the current
directory). Only the chunks that cover the selected files are downloaded.

| Flag | Meaning |
| --- | --- |
| `-o, --out <path>` | Note: output file. File share: output folder (created with mode `0700`). |
| `-l, --list` | File share: print the file list (size, type, path) and exit. **Opening the share to list it uses a view.** |
| `-p, --path <sub>` | File share: download only this file or folder. The selected item keeps its own name, so `--path docs/img` writes `img/…`. |
| `--force` | File share: overwrite existing regular files |
| `-y, --yes` | Skip the "this uses a view" confirmation |
| `--password-env <VAR>` | Read the password from an environment variable. Otherwise you are prompted on a TTY. |
| `--field <name>` | Credential share: print one field, or `code` for the current one-time code |

Downloads are confined to the output folder. Every target must resolve inside `--out`.
Every path component below it is checked right before use, and a symbolic link found there
is never written through, even with `--force`. Existing files are only replaced with
`--force`. Without it, an unlimited share refuses the download. A view-limited share has
already spent its view by then, so it saves into a new folder `secbin-<id>` inside `--out`
instead. Files are created with mode `0600`, and an interrupted file is removed rather
than left truncated.

### `secbin delete <share-url | id>`

Deletes a note or file share with its delete token. The token is prompted for (hidden),
or read with `--token-env <VAR>`. It is sent only in the `X-Delete-Token` header, never in
a URL. A bare id needs `--server` or `SECBIN_SERVER`.

`secbin delete --now <share-url | ->` deletes a share **as its recipient**, when the sender
allowed it (`--recipient-can-delete`): no token, but the full link and, if set, the password
(`--password-env <VAR>` or a prompt). It spends no view.

### `secbin update` / `secbin version`

These commands only trust an npm release that meets all three conditions:
- its package metadata points to `github.com/kaerez/bin`;
- it carries an npm provenance attestation;
- it has a sha512 integrity hash.

npm accepts a provenance attestation only for a package built by CI in the repository the
package names, so a look-alike package that merely claims this repository is refused. Anything
else is refused and never installed.

`update` downloads exactly the version it verified, never a moving `@latest` tag, and checks
the tarball against the verified integrity hash. It then installs that file with lifecycle
scripts disabled (`--ignore-scripts`). `secbin version` always prints the installed version,
and only warns when no verified release can be found. Until such a release exists, update by
pulling the repository and re-running `npm install -g ./cli`.
`secbin --version` prints the installed version without any network access.

## What the server can and cannot see

| The server sees | The server never sees |
| --- | --- |
| Ciphertext, the padded total size and chunk count | The `#fragment` key, passwords, the plaintext |
| View limit, expiry, the declared format (`plaintext`/`code`/`markdown`/`files`), and your optional **label** (unencrypted) | Note content |
| For `send`: the **number of files** and the **largest file size**, declared for your account's limit checks; if the administrator set a file policy for your account, also the **set of file types** (extension + MIME) and the **deepest folder level** — checked, not stored | File and folder names, the folder structure, MIME types, individual sizes, mtimes (all inside the encrypted manifest) |
| The SHA-256 of the two access proofs, and whether a password was used | Anything that would let it decrypt the share, or test password guesses offline, without the fragment |
| Your account (via the API key) for shares you create | Who opens a link (beyond normal network metadata) |

## Security notes

- **The share URL is the secret.** Anyone with the full URL, plus the password if one is
  set, can open the share. Command-line arguments are visible to other local processes; on
  shared machines, prefer `echo '<url>' | secbin get -`.
- **Passwords, delete tokens and API keys are never accepted as plain flag values.** They
  come only from a hidden prompt, an environment variable or a `0600` key file.
- `--text` puts the note itself in argv. Pipe stdin or use `--file` for anything sensitive.
- Server error messages are stripped of control characters before they are printed, so a
  hostile server cannot inject terminal escapes.
- See the project's [`SECURITY.md`](https://github.com/kaerez/bin/blob/main/SECURITY.md)
  for the full threat model.

**Exit codes:** `0` ok · `1` crypto/API/refused-for-safety error · `2` usage error (bad
flags, missing server/key, refusing to overwrite) · `130` aborted.

## How it relates to the repo

This package lives in the [`cli/`](https://github.com/kaerez/bin/tree/main/cli)
subdirectory. The modules in `vendor/` are byte-identical copies of the repository's
`public/js/{bytes,format,crypto,kdf,files,zip,mime}.js`:

- `public/js/vendor/argon2.js` (and its license) is copied to `vendor/vendor/`.
- `qrcode.js` is vendored as `qrcode.cjs` for Node's CommonJS loader.
- `LICENSE` is synced from the repository root.

A test fails on any drift, and `node scripts/sync-shared.mjs` re-aligns the copies.
Packing (`npm pack` / `npm publish`) runs a prepack gate that repeats this check and runs
the test suite, so it must run from a full clone of the repository.

Tests: `npx vitest run --config cli/vitest.config.js` from the repository root.

## License

[MIT](./LICENSE) © 2026 nxfu. The vendored hash-wasm Argon2 build is MIT-licensed; see
`vendor/vendor/argon2.LICENSE`.
