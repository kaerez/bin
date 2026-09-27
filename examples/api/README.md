# REST API examples

Reference clients for the parts of the API that need encryption: creating an end-to-end
encrypted note or file share with an API key. Everything else (listing your shares, read
receipts, labels, extensions, revocation, deletion) is a plain HTTP call — see
[`docs/API.md`](../../docs/API.md) for every endpoint, the scopes, and examples in curl,
Node.js and Python.

| File | Does | Needs |
| --- | --- | --- |
| [`create-note.mjs`](./create-note.mjs) | create a note (`notes` scope); `--encrypt-only` prints the request body for curl | Node.js 22, run from a clone of this repository |
| [`create_note.py`](./create_note.py) | create a note (`notes` scope) | Python 3 with `requests` and `cryptography` (and `argon2-cffi` for password-protected notes) |
| [`create-files.mjs`](./create-files.mjs) | share files and folders (`files` scope); `--encrypt-only <dir>` writes the request bodies for curl | Node.js 22, run from a clone of this repository |
| [`create_files.py`](./create_files.py) | share files and folders (`files` scope) | as `create_note.py`, which it imports (keep them together) |

All read the API key from `SECBIN_API_KEY` and an optional password from
`SECBIN_NOTE_PASSWORD` — never from the command line. They print the link on stdout and the
delete token on stderr.
