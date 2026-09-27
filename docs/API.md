# secbin REST API (API keys)

API keys let scripts and tools work with secbin without a browser session: **create shares**
and, when the key allows it, **list your shares and their read receipts** and **label, extend
and revoke** them. A key never signs in and never reaches the account itself (profile,
password, passkeys, API keys, activity) or the admin panel. The CLI
([`cli/`](../cli/README.md)) uses exactly this API.

> The content of every share is **encrypted by the client before it is sent** (SPEC.md §2–§5).
> The server stores ciphertext and never sees the key, which travels only in the link's
> `#fragment`. So creating a note or a file share needs a client that encrypts — the
> [`secbin` CLI](../cli/README.md) or the examples in [`examples/api/`](../examples/api/) —
> while listing, receipts, labels, extensions, revocation and deletion work with plain `curl`.

## Keys and scopes

Create a key on **Account → API keys** (if the administrator allows API keys for your account;
the administrator can also create one for you under Admin → Users). The key is shown once;
store it in a secrets manager (for example Vault or AWS Secrets Manager), never in source code or
on a command line. Send it as:

```
Authorization: Bearer sbk_…
```

Each key has **scopes** — give it only what it needs:

| Scope | Allows |
| --- | --- |
| `notes` | `POST /api/private/paste` — notes of every format (text, link, credential) |
| `files` | `POST /api/private/file`, `PUT …/chunk/:i`, `POST …/finalize` — file shares |
| `policy` | `GET /api/private/policy` — what your client must check before creating (link rules) |
| `read` | `GET /api/private/shares`, `GET /api/private/shares/:id`, `GET /api/private/shares/:id/opens` — your shares and their read receipts |
| `manage` | `PATCH /api/private/shares/:id` (label, views, expiry), `POST /api/private/shares/:id/revoke` |

A key created without a choice of scopes gets `notes`, `files` and `policy` (creation only):
`read` and `manage` must be chosen explicitly. Scopes can be changed later (Account → API keys →
Edit; changing a key needs your password or a passkey). Keys can expire, can be revoked at any
time, and stop working at once when the administrator turns API use off for the account or
disables it.

What a key can reach is always **your own shares only** — never another user's, whatever its
scopes — under the same rules as the dashboard's **My shares** page:

- Shares the administrator has **locked** cannot be labelled, extended or revoked (`423
  share_locked`), exactly as in the dashboard.
- Views and expiry can only **grow**, within your account's limits. Through an API key the
  account's **API limits** apply (Admin → Roles → the API column), as they do when creating.
- Creations through a key count against both the account's quotas and its API-only quotas.
- Every change made with a key (label, extension, revocation) is recorded in your activity log
  with the key's id (`apikey=<id>`; never the key itself); creations are recorded as usual.

## Endpoints

All bodies and results are JSON unless stated. `:id` is a share id (`k…`/`b…` notes, `f…` file
shares).

| Method & path | Scope | Body → result |
| --- | --- | --- |
| `GET /api/private/policy` | `policy` | → `{ url, urlRules }` — whether link shares are allowed and which links (SPEC.md §5.6) |
| `POST /api/private/paste` | `notes` | `{ paste, label? }` → `201 { id, deletetoken, expires }` — `paste` is the encrypted create body (SPEC.md §5.2) |
| `POST /api/private/file` | `files` | `{ views, expire, padded, files?, maxFile?, types?, depth?, deletable? }` → `201 { id, uploadtoken, deletetoken, chunks }` (SPEC.md §12) |
| `PUT /api/private/file/:id/chunk/:i` | `files` | encrypted chunk bytes (`application/octet-stream`), header `X-Upload-Token` → `{ ok }` |
| `POST /api/private/file/:id/finalize` | `files` | `{ paste, label? }` with `X-Upload-Token` — the encrypted manifest → `{ ok, id, expires }` |
| `GET /api/private/shares?q=&status=&offset=` | `read` | → `{ rows, total }`: 50 per page, newest first; `q` matches the label, `status` is one of `active`, `revoked`, `expired`, `consumed`, `deleted`, `ended` |
| `GET /api/private/shares/:id` | `read` | → `{ share }` (one row, as below) |
| `GET /api/private/shares/:id/opens` | `read` | → `{ total, fields, rows: [{ ts, …}] }` — read receipts, newest first (at most 200); `fields` lists the details the administrator lets your account see (`receiptIp`, `receiptLocation`, `receiptBrowser`, `receiptOs`, `receiptLanguages`); times are always there |
| `PATCH /api/private/shares/:id` | `manage` | `{ label?, views?, expires? }` → `{ ok }` — `views`: a larger view limit (view-limited shares only; `null` = unlimited, if allowed); `expires`: a later expiry (unix seconds, at most 365 days ahead) |
| `POST /api/private/shares/:id/revoke` | `manage` | header `X-Secbin-Intent: 1`, no body → `{ ok }` — destroys the content at once; the row stays as `revoked` |
| `DELETE /api/paste/:id`, `DELETE /api/file/:id` | none | header `X-Delete-Token` → `{ status: "deleted", id }` — the delete token is the capability, no API key; `423 share_locked` for a locked share |

A share row is `{ id, kind, label, created, expires, views_total, left, opens, status, locked }`:
`kind` is `text`, `url`, `secret` or `files`; `views_total` the view limit (`null` =
unlimited) and `left` the views left (`null` when unlimited or not active); `opens` counts every
open; `locked` is `1` when the administrator has locked it. Times are unix seconds.

The share link is `https://<server>/p/<id>#<fragment>`, where `fragment` is the base64url
32-byte secret your client generated. Anyone with the link (and the password, if set) can open
the share, subject to its view limit and expiry.

`label` is **not encrypted** — it is visible to the server and the administrators.

### Errors

Errors are JSON `{ "error": "<code>", "message": "…" }` with real HTTP status codes (all codes:
SPEC.md §10). The ones specific to keys and shares:

| Status | `error` | When |
| --- | --- | --- |
| 401 | `invalid_api_key` | malformed, unknown, expired or revoked key, or API use is off for the account |
| 403 | `scope_denied` | the key lacks the scope the route needs (the message names it) |
| 403 | `api_key_not_allowed` | a route keys never reach (account, keys, admin panel) |
| 403 | `account_disabled` | the account is disabled |
| 404 | `not_found` | no such share **of yours** (another user's share answers the same) |
| 423 | `share_locked` | the administrator has locked the share |
| 409 | `not_active` | extending a share that is no longer active |
| 400 | `invalid`, `invalid_views`, `invalid_expiry`, `invalid_label` | nothing to change, a smaller or invalid value, a label over 100 characters |
| 400 | `missing_intent` | revoke without `X-Secbin-Intent: 1` |
| 403 | `too_many_views`, `unlimited_views_disabled`, `expiry_too_long` | beyond the account's limits (for a key: its API limits); `max` is attached |
| 403 | `bad_token` | wrong delete token |
| 429 | `quota_exceeded`, `blocked` | a creation quota, or too many invalid requests from your network |

## Examples

The same examples are on **Account → API keys → Using the API**, with your server's address
filled in. They read the key from `SECBIN_API_KEY`, a share id from `SHARE_ID` and a delete
token from `SECBIN_DELETE_TOKEN`; replace `https://bin.example.com` with your server. On a
shared machine, prefer passing headers from a file (`curl -H @headers.txt`) so the key does not
appear in the process list.

Ready-made scripts for every use case are in [`examples/api/`](../examples/api/):
`create-note.mjs` / `create_note.py` and `create-files.mjs` / `create_files.py` create shares,
and `shares.mjs` / `shares.py` list, show, read receipts of, label, extend and revoke your
shares, read your policy, and delete with a delete token. The [`secbin` CLI](../cli/README.md)
does the same from the command line: `secbin create`, `send`, `list`, `show`, `receipts`,
`label`, `extend`, `revoke` and `delete`.

### Create a note

Scope: `notes`.

curl:

```sh
# curl cannot encrypt: encrypt locally first (Node.js 22, from a clone of the repository).
# It prints "fragment: <F>" on stderr; the link is https://bin.example.com/p/<id>#<F>
echo "the secret" | node examples/api/create-note.mjs --encrypt-only --views 1 > note.json
curl -sS -H "Authorization: Bearer $SECBIN_API_KEY" -H "Content-Type: application/json" \
  --data @note.json https://bin.example.com/api/private/paste
```

Node.js:

```sh
# From a clone of the repository (it uses the browser's own protocol module); reads SECBIN_API_KEY
echo "the secret" | node examples/api/create-note.mjs https://bin.example.com --views 1 --expire 24h
```

Python:

```sh
# pip install requests cryptography argon2-cffi; reads SECBIN_API_KEY
echo "the secret" | python3 examples/api/create_note.py https://bin.example.com --views 1 --expire 24h
```

### Share files (the upload flow)

Scope: `files`.

curl:

```sh
# curl cannot encrypt: prepare the encrypted upload locally first (Node.js 22, from a clone).
# It writes upload/init.json, upload/chunk-<i>.bin and upload/finalize.json and prints
# "fragment: <F>" on stderr; the link is https://bin.example.com/p/<id>#<F>
node examples/api/create-files.mjs --encrypt-only upload report.pdf --views 3 --expire 7d
H="Authorization: Bearer $SECBIN_API_KEY"
init=$(curl -sS -H "$H" -H "Content-Type: application/json" --data @upload/init.json https://bin.example.com/api/private/file)
id=$(echo "$init" | jq -r .id); tok=$(echo "$init" | jq -r .uploadtoken)
echo "delete token: $(echo "$init" | jq -r .deletetoken)"
for f in upload/chunk-*.bin; do i=${f##*-}; i=${i%.bin}
  curl -sS -X PUT -H "$H" -H "X-Upload-Token: $tok" -H "Content-Type: application/octet-stream" \
    --data-binary @"$f" "https://bin.example.com/api/private/file/$id/chunk/$i"
done
curl -sS -H "$H" -H "X-Upload-Token: $tok" -H "Content-Type: application/json" \
  --data @upload/finalize.json "https://bin.example.com/api/private/file/$id/finalize"
```

Node.js:

```sh
# Files and folders, from a clone of the repository; reads SECBIN_API_KEY
node examples/api/create-files.mjs https://bin.example.com report.pdf --views 3 --expire 7d
```

Python:

```sh
# pip install requests cryptography argon2-cffi (create_note.py must sit next to it); reads SECBIN_API_KEY
python3 examples/api/create_files.py https://bin.example.com report.pdf --views 3 --expire 7d
```

### List your shares

Scope: `read`.

curl:

```sh
curl -sS -H "Authorization: Bearer $SECBIN_API_KEY" "https://bin.example.com/api/private/shares?status=active"
# one share (views left, expiry, opens):
curl -sS -H "Authorization: Bearer $SECBIN_API_KEY" "https://bin.example.com/api/private/shares/$SHARE_ID"
```

Node.js:

```js
// list-shares.mjs (run: node list-shares.mjs)
const res = await fetch('https://bin.example.com/api/private/shares?status=active', {
  headers: { authorization: `Bearer ${process.env.SECBIN_API_KEY}` },
});
if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.json()).error}`);
const { rows, total } = await res.json();
for (const s of rows) console.log(s.id, s.kind, s.status, s.left ?? 'unlimited', s.opens, s.label);
console.log(`${rows.length} of ${total}`);
```

Python:

```python
# list_shares.py (run: python3 list_shares.py)
import os, requests

res = requests.get("https://bin.example.com/api/private/shares", params={"status": "active"}, timeout=30,
                   headers={"Authorization": f"Bearer {os.environ['SECBIN_API_KEY']}"})
res.raise_for_status()
data = res.json()
for s in data["rows"]:
    print(s["id"], s["kind"], s["status"], s["left"], s["opens"], s["label"])
print(len(data["rows"]), "of", data["total"])
```

### Read receipts (who opened a share, when)

Scope: `read`.

curl:

```sh
curl -sS -H "Authorization: Bearer $SECBIN_API_KEY" "https://bin.example.com/api/private/shares/$SHARE_ID/opens"
```

Node.js:

```js
// receipts.mjs (run: SHARE_ID=... node receipts.mjs)
const res = await fetch(`https://bin.example.com/api/private/shares/${process.env.SHARE_ID}/opens`, {
  headers: { authorization: `Bearer ${process.env.SECBIN_API_KEY}` },
});
if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.json()).error}`);
const { total, fields, rows } = await res.json();
console.log(`${total} opens; details: ${fields.join(', ') || 'times only'}`);
for (const r of rows) console.log(new Date(r.ts * 1000).toISOString(), r.country ?? '', r.browser ?? '');
```

Python:

```python
# receipts.py (run: SHARE_ID=... python3 receipts.py)
import os, time, requests

res = requests.get(f"https://bin.example.com/api/private/shares/{os.environ['SHARE_ID']}/opens", timeout=30,
                   headers={"Authorization": f"Bearer {os.environ['SECBIN_API_KEY']}"})
res.raise_for_status()
data = res.json()
print(data["total"], "opens; details:", ", ".join(data["fields"]) or "times only")
for r in data["rows"]:
    print(time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(r["ts"])), r.get("country", ""), r.get("browser", ""))
```

### Label a share

Scope: `manage`.

curl:

```sh
# the label is NOT encrypted: the server and its administrators can read it
curl -sS -X PATCH -H "Authorization: Bearer $SECBIN_API_KEY" -H "Content-Type: application/json" \
  --data '{"label":"quarterly report"}' "https://bin.example.com/api/private/shares/$SHARE_ID"
```

Node.js:

```js
// label.mjs (run: SHARE_ID=... node label.mjs) — the label is NOT encrypted
const res = await fetch(`https://bin.example.com/api/private/shares/${process.env.SHARE_ID}`, {
  method: 'PATCH',
  headers: { authorization: `Bearer ${process.env.SECBIN_API_KEY}`, 'content-type': 'application/json' },
  body: JSON.stringify({ label: 'quarterly report' }),
});
console.log(res.status, await res.json());
```

Python:

```python
# label.py (run: SHARE_ID=... python3 label.py) — the label is NOT encrypted
import os, requests

res = requests.patch(f"https://bin.example.com/api/private/shares/{os.environ['SHARE_ID']}", timeout=30,
                     json={"label": "quarterly report"},
                     headers={"Authorization": f"Bearer {os.environ['SECBIN_API_KEY']}"})
print(res.status_code, res.json())
```

### Extend a share (more views, later expiry)

Scope: `manage`.

curl:

```sh
# views and expiry only grow; views only for view-limited shares; expires is in unix seconds
curl -sS -X PATCH -H "Authorization: Bearer $SECBIN_API_KEY" -H "Content-Type: application/json" \
  --data "{\"views\":5,\"expires\":$(( $(date +%s) + 7 * 86400 ))}" "https://bin.example.com/api/private/shares/$SHARE_ID"
```

Node.js:

```js
// extend.mjs (run: SHARE_ID=... node extend.mjs) — views and expiry only grow
const expires = Math.floor(Date.now() / 1000) + 7 * 86400; // unix seconds
const res = await fetch(`https://bin.example.com/api/private/shares/${process.env.SHARE_ID}`, {
  method: 'PATCH',
  headers: { authorization: `Bearer ${process.env.SECBIN_API_KEY}`, 'content-type': 'application/json' },
  body: JSON.stringify({ views: 5, expires }),
});
console.log(res.status, await res.json());
```

Python:

```python
# extend.py (run: SHARE_ID=... python3 extend.py) — views and expiry only grow
import os, time, requests

res = requests.patch(f"https://bin.example.com/api/private/shares/{os.environ['SHARE_ID']}", timeout=30,
                     json={"views": 5, "expires": int(time.time()) + 7 * 86400},  # unix seconds
                     headers={"Authorization": f"Bearer {os.environ['SECBIN_API_KEY']}"})
print(res.status_code, res.json())
```

### Revoke a share

Scope: `manage`.

curl:

```sh
# the content is destroyed at once; the share stays in your list as "revoked"
curl -sS -X POST -H "Authorization: Bearer $SECBIN_API_KEY" -H "X-Secbin-Intent: 1" \
  "https://bin.example.com/api/private/shares/$SHARE_ID/revoke"
```

Node.js:

```js
// revoke.mjs (run: SHARE_ID=... node revoke.mjs)
const res = await fetch(`https://bin.example.com/api/private/shares/${process.env.SHARE_ID}/revoke`, {
  method: 'POST',
  headers: { authorization: `Bearer ${process.env.SECBIN_API_KEY}`, 'x-secbin-intent': '1' },
});
console.log(res.status, await res.json());
```

Python:

```python
# revoke.py (run: SHARE_ID=... python3 revoke.py)
import os, requests

res = requests.post(f"https://bin.example.com/api/private/shares/{os.environ['SHARE_ID']}/revoke", timeout=30,
                    headers={"Authorization": f"Bearer {os.environ['SECBIN_API_KEY']}", "X-Secbin-Intent": "1"})
print(res.status_code, res.json())
```

### Delete with the delete token (no API key)

Scope: none — no API key, the delete token is the capability.

curl:

```sh
# the delete token is the capability; notes are /api/paste/<id>, file shares /api/file/<id>
curl -sS -X DELETE -H "X-Delete-Token: $SECBIN_DELETE_TOKEN" "https://bin.example.com/api/paste/$SHARE_ID"
```

Node.js:

```js
// delete.mjs (run: SHARE_ID=... SECBIN_DELETE_TOKEN=... node delete.mjs)
const id = process.env.SHARE_ID;
const kind = id.startsWith('f') ? 'file' : 'paste'; // file shares' ids start with "f"
const res = await fetch(`https://bin.example.com/api/${kind}/${id}`, {
  method: 'DELETE',
  headers: { 'x-delete-token': process.env.SECBIN_DELETE_TOKEN },
});
console.log(res.status, await res.json());
```

Python:

```python
# delete.py (run: SHARE_ID=... SECBIN_DELETE_TOKEN=... python3 delete.py)
import os, requests

sid = os.environ["SHARE_ID"]
kind = "file" if sid.startswith("f") else "paste"  # file shares' ids start with "f"
res = requests.delete(f"https://bin.example.com/api/{kind}/{sid}", timeout=30,
                      headers={"X-Delete-Token": os.environ["SECBIN_DELETE_TOKEN"]})
print(res.status_code, res.json())
```

### Read your policy (what to check before creating)

Scope: `policy`.

curl:

```sh
curl -sS -H "Authorization: Bearer $SECBIN_API_KEY" https://bin.example.com/api/private/policy
```

Node.js:

```js
// policy.mjs (run: node policy.mjs)
const res = await fetch('https://bin.example.com/api/private/policy', {
  headers: { authorization: `Bearer ${process.env.SECBIN_API_KEY}` },
});
console.log(res.status, await res.json()); // { url, urlRules }
```

Python:

```python
# policy.py (run: python3 policy.py)
import os, requests

res = requests.get("https://bin.example.com/api/private/policy", timeout=30,
                   headers={"Authorization": f"Bearer {os.environ['SECBIN_API_KEY']}"})
print(res.status_code, res.json())  # {"url": ..., "urlRules": [...]}
```
## Not with API keys: the Drive

The Drive (`/api/private/drive*`, [`docs/DRIVE.md`](./DRIVE.md) §6) is for signed-in sessions
only: an API key gets `403 api_key_not_allowed`, whatever its scopes. Its routes, for reference:

| Method & path | Body → result |
| --- | --- |
| `GET /api/private/drive` | → `{ enabled, capacity, maxFile, used, driveSalt, wraps, escrowPub, escrowPriv? }` (`capacity` / `maxFile` null = no limit) |
| `PUT /api/private/drive/keys` | `{ driveSalt?, set?, remove?, escrowPriv?, escrowPub? }` — key wraps (not while impersonating; the escrow keys owner only) |
| `GET /api/private/drive/nodes/:id` | → `{ node, children, path }` (`root` is the top folder) |
| `PATCH /api/private/drive/nodes/:id` | `{ parent?, name?, meta? }` — move / rename |
| `DELETE /api/private/drive/nodes/:id` | header `X-Secbin-Intent: 1` — recursive; ends every share of it |
| `GET /api/private/drive/nodes/:id/shares` | → `{ shares }` — the active shares of the item |
| `POST /api/private/drive/folders` | `{ id?, parent, name, meta? }` → `201 { id }` |
| `POST /api/private/drive/files` | `{ id?, parent, name, meta?, size, fk }` → `201 { id, uploadToken, chunks }` |
| `PUT /api/private/drive/files/:id/chunk/:i` | encrypted chunk bytes (exact size), header `X-Upload-Token` |
| `POST /api/private/drive/files/:id/finalize` | header `X-Upload-Token` → `{ ok }` |
| `GET /api/private/drive/files/:id/chunk/:i` | → the ciphertext chunk |
| `POST /api/private/drive/shares` | `{ nodes (file ids), views, expire, deletable?, label?, paste, acc?, types?, depth? }` → `201 { id, deletetoken, expires }` |
| `POST /api/private/admin/drive/escrow/:userId` | owner only: `{ reason }` → `{ wrap, wraps }` (logged) |
| `PUT /api/private/admin/drive/keys/:userId` | owner only, after a password reset: `{ driveSalt, set: [{ kind: 'pw', ref: 'pw', data }] }` (logged) |

`name`, `meta` and `fk` are `{ iv, ct }` values encrypted in the browser; the server never sees
names, types or keys. A Drive share is opened like a file share (`POST /api/file/:id/open`, which
then also returns `refs: [{ chunks, size }]`), and its chunks are read with
`GET /api/file/:id/chunk/:ref/:i` and the download grant.

## Security notes

- Treat a key like a password: it acts as you within its scopes until it expires or is revoked.
  Prefer short lifetimes and the narrowest scopes; keep `read` and `manage` for the tools that
  need them.
- Keys are stored only as hashes; the server cannot show a key again.
- Every key creation, change and revocation, every share created with a key and every change a
  key makes to a share is recorded in your activity log (and the administrator's audit log).
- Read receipts can contain personal data about the people who opened a share (network address,
  location, browser, languages — only the details the administrator enables). Treat what you
  fetch as sensitive: keep it only as long as you need it and protect it like the key itself.
