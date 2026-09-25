# REST API examples

Reference clients that create an end-to-end encrypted note with an API key. See
[`docs/API.md`](../../docs/API.md) for keys, scopes and endpoints.

| File | Needs |
| --- | --- |
| [`create-note.mjs`](./create-note.mjs) | Node.js 22, run from a clone of this repository |
| [`create_note.py`](./create_note.py) | Python 3 with `cryptography` (and `argon2-cffi` for password-protected notes) |

Both read the API key from `SECBIN_API_KEY` and an optional note password from
`SECBIN_NOTE_PASSWORD` — never from the command line.
