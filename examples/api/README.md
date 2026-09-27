# REST API examples

Reference clients for every use of an API key: creating an end-to-end encrypted note or file
share (the parts that need encryption), and managing your own shares — listing them, one
share, read receipts, labels, extensions, revocation — plus reading your policy and deleting
with a delete token. See [`docs/API.md`](../../docs/API.md) for every endpoint, the scopes, and
the same calls as short curl, Node.js and Python snippets.

| File | Does | Needs |
| --- | --- | --- |
| [`create-note.mjs`](./create-note.mjs) | create a note (`notes` scope); `--encrypt-only` prints the request body for curl | Node.js 22, run from a clone of this repository |
| [`create_note.py`](./create_note.py) | create a note (`notes` scope) | Python 3 with `requests` and `cryptography` (and `argon2-cffi` for password-protected notes) |
| [`create-files.mjs`](./create-files.mjs) | share files and folders (`files` scope); `--encrypt-only <dir>` writes the request bodies for curl | Node.js 22, run from a clone of this repository |
| [`create_files.py`](./create_files.py) | share files and folders (`files` scope) | as `create_note.py`, which it imports (keep them together) |
| [`shares.mjs`](./shares.mjs) | `list`, `show`, `receipts` (`read` scope); `label`, `extend`, `revoke` (`manage`); `policy` (`policy`); `delete` with the delete token (no key) | Node.js 22, no dependencies |
| [`shares.py`](./shares.py) | the same, in Python | Python 3 with `requests` |

All read the API key from `SECBIN_API_KEY` (and the creation examples an optional password
from `SECBIN_NOTE_PASSWORD`, `delete` the token from `SECBIN_DELETE_TOKEN`) — never from the
command line. The creation examples print the link on stdout and the delete token on stderr;
`shares.*` print the server's answers as JSON lines. A key only ever reaches its own user's
shares, and labels are **not encrypted**.
