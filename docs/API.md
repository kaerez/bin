# secbin REST API (API keys)

API keys let scripts and tools **create shares** without a browser session. They cannot sign
in, list or change anything else: the account's session is the only way to manage shares, keys
or settings. The CLI ([`cli/`](../cli/README.md)) uses exactly this API.

> The content of every share is **encrypted by the client before it is sent** (SPEC.md §2–§5).
> The server stores ciphertext and never sees the key, which travels only in the link's
> `#fragment`. So a raw `curl` can call the endpoints that carry no content, but creating a note
> needs a client that encrypts — use the [`secbin` CLI](../cli/README.md) or the examples in
> [`examples/api/`](../examples/api/).

## Keys and scopes

Create a key on **Account → API keys** (if the administrator allows API keys for your account).
The key is shown once; store it in a secrets manager (for example Vault or AWS Secrets Manager),
never in source code or on a command line. Send it as:

```
Authorization: Bearer sbk_…
```

Each key has **scopes** — give it only what it needs:

| Scope | Allows |
| --- | --- |
| `notes` | `POST /api/private/paste` — notes of every format (text, link, credential) |
| `files` | `POST /api/private/file`, `PUT …/chunk/:i`, `POST …/finalize` — file shares |
| `policy` | `GET /api/private/policy` — what your client must check before creating (link rules) |

A request outside the key's scopes gets `403 scope_denied`. Keys can expire, can be revoked at
any time, and stop working at once when the administrator turns API use off for the account or
disables it. API creations count against both the account's quotas and its API-only limits.

## Endpoints

| Method & path | Scope | Body → result |
| --- | --- | --- |
| `GET /api/private/policy` | `policy` | → `{ url, urlRules }` — whether link shares are allowed and which links (SPEC.md §5.6) |
| `POST /api/private/paste` | `notes` | `{ paste, label? }` → `201 { id, deletetoken, expires }` — `paste` is the encrypted create body (SPEC.md §5.2) |
| `POST /api/private/file` | `files` | `{ views, expire, padded, files?, maxFile?, types?, depth? }` → `201 { id, uploadtoken, deletetoken, chunks }` (SPEC.md §12) |
| `PUT /api/private/file/:id/chunk/:i` | `files` | encrypted chunk bytes, header `X-Upload-Token` |
| `POST /api/private/file/:id/finalize` | `files` | `{ paste, label? }` with `X-Upload-Token` — the encrypted manifest |

The share link is `https://<server>/p/<id>#<fragment>`, where `fragment` is the base64url
32-byte secret your client generated. Anyone with the link (and the password, if set) can open
the share, subject to its view limit and expiry. The `deletetoken` deletes it:
`DELETE /api/paste/:id` (or `/api/file/:id`) with header `X-Delete-Token` — no API key needed.

`label` is **not encrypted** — it is visible to the server and the administrators.

Errors are JSON `{ "error": "<code>", "message": "…" }` with real HTTP status codes; the codes
are listed in SPEC.md §10.

## Examples

A request without content (works with plain `curl`):

```sh
curl -H "Authorization: Bearer $SECBIN_API_KEY" https://bin.example.com/api/private/policy
```

Create a note — Node.js 22, from a clone of this repository (it uses the same protocol module as
the browser):

```sh
export SECBIN_API_KEY=sbk_...   # from your secrets manager
echo "the secret" | node examples/api/create-note.mjs https://bin.example.com --views 1 --expire 24h
```

Create a note — Python 3 (standalone, `pip install cryptography argon2-cffi`):

```sh
echo "the secret" | python3 examples/api/create_note.py https://bin.example.com --views 1
SECBIN_NOTE_PASSWORD='…' python3 examples/api/create_note.py https://bin.example.com < note.txt
```

Both print the link on stdout and the delete token on stderr. For files and folders use the CLI:
`secbin send <path>`.

## Security notes

- Treat a key like a password: it can create shares under your name until it expires or is
  revoked. Prefer short lifetimes and the narrowest scopes.
- Keys are stored only as hashes; the server cannot show a key again.
- Every key creation, revocation and use for creating a share is recorded in your activity log.
