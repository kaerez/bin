# secbin REST API (API keys)

API keys let scripts and tools work with secbin without a browser session: **create shares**
and, when the key allows it, **list your shares and their read receipts** and **label, extend
and revoke** them, and **list, change, move, pause, resume and revoke your "Receive" links**
(below). A key never signs in and never reaches the account itself (profile,
password, passkeys, API keys, activity) or the admin panel. The CLI
([`cli/`](../cli/README.md)) uses exactly this API.

> The content of every note and file share is **encrypted by the client before it is sent**
> (SPEC.md §2–§5). The server stores ciphertext and never sees the key, which travels only in
> the link's `#fragment`. Drive shares and "Receive" links (made in the Drive page, not
> with an API key) are different: the server holds the keys of Drive files, so it can decrypt
> them and what those links receive ([DRIVE.md](DRIVE.md) §2). So creating a note or a file
> share needs a client that encrypts — the
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
| `read` | `GET /api/private/shares`, `GET /api/private/shares/:id`, `GET /api/private/shares/:id/opens` — your shares and their read receipts; `GET /api/private/receive`, `GET /api/private/receive/:id`, `GET /api/private/receive/:id/opens` — your Receive links and their receipts |
| `manage` | `PATCH /api/private/shares/:id` (label, views, expiry; a Receive link's other details too, except the changes that weaken it: below), `POST /api/private/shares/:id/revoke`; `PATCH /api/private/receive/:id`, `POST /api/private/receive/:id/pause`, `…/revoke` (and `…/resume`, which weakens a link: refused for a key) |

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

### Browser sessions: `X-Secbin-CSRF`

API-key requests **never** need a CSRF token. It applies only to requests authenticated by the
browser's session cookie, for example a script running in the signed-in dashboard.
Such a request that changes something (`POST`, `PUT`, `PATCH` or `DELETE` on
`/api/private/*`, the Drive's `/api/private/drive/*` and `/api/private/admin/drive/*`
included, and `POST /api/auth/logout`) must send:

```
X-Secbin-CSRF: <token>
```

- **The token:** the value of the `__Host-secbin_csrf` cookie, or `csrf` in
  `GET /api/private/me`.
- **Lifetime:** it belongs to the session and changes only when the session does (sign-in,
  sign-out, a password change, impersonation start or end).
- **Shape first:** such a request also needs a JSON body, a chunk
  (`application/octet-stream`, as in file and Drive uploads) or `X-Secbin-Intent: 1` (and the
  intent header on a `DELETE`). Without it the request is refused before the token is looked
  at: `415 unsupported_media_type` for a body of another type, else `400 missing_intent`.
- **Refusal:** a missing or stale token gets `403 csrf_mismatch` and nothing changes. Fetch
  `/api/private/me` for the current token and send the request again, after checking that
  `/me` still names the account (and impersonation state) the script meant to act for.
- **Other routes:** reads (`GET`) and the anonymous routes (share open and delete, public
  creation, login, setup) never need it.
- **Owner switch:** the owner can turn the requirement off in Admin → Settings → CSRF tokens.
  The header is then ignored; the JSON / `X-Secbin-Intent` and cross-site rules still apply.

## Endpoints

All bodies and results are JSON unless stated. `:id` is a share id (`k…`/`b…` notes, `f…` file
shares).

| Method & path | Scope | Body → result |
| --- | --- | --- |
| `GET /api/private/policy` | `policy` | → `{ url, urlRules }` — whether link shares are allowed and which links (SPEC.md §5.6) |
| `POST /api/private/paste` | `notes` | `{ paste, label?, captcha? }` → `201 { id, deletetoken, expires, captcha }` — `paste` is the encrypted create body (SPEC.md §5.2); `captcha`: see below |
| `POST /api/private/file` | `files` | `{ views, expire, padded, files?, maxFile?, types?, depth?, deletable?, captcha? }` → `201 { id, uploadtoken, deletetoken, chunks, captcha }` (SPEC.md §12) |
| `PUT /api/private/file/:id/chunk/:i` | `files` | encrypted chunk bytes (`application/octet-stream`), header `X-Upload-Token` → `{ ok }` |
| `POST /api/private/file/:id/finalize` | `files` | `{ paste, label? }` with `X-Upload-Token` — the encrypted manifest → `{ ok, id, expires, captcha }` |
| `GET /api/private/shares?q=&status=&expiry=&offset=` | `read` | → `{ rows, total }`: 50 per page, newest first; `q` matches the label, `status` is one of `active`, `revoked`, `expired`, `consumed`, `deleted`, `ended`; `expiry=none`: only the Receive links with no expiry, `expiry=set`: only shares that expire. A row's `expires` is `null` for a Receive link with no expiry |
| `GET /api/private/shares/:id` | `read` | → `{ share }` (one row, as below) |
| `GET /api/private/shares/:id/opens` | `read` | → `{ total, fields, rows: [{ ts, …}] }` — read receipts, newest first (at most 200); `fields` lists the details the administrator lets your account see (`receiptIp`, `receiptLocation`, `receiptBrowser`, `receiptOs`, `receiptLanguages`); times are always there |
| `PATCH /api/private/shares/:id` | `manage` | `{ label?, views?, expires? }` → `{ ok }` — `views`: a larger view limit (view-limited shares only; `null` = unlimited, if allowed); `expires`: a later expiry (unix seconds, at most 365 days ahead). A Receive link (kind `reverse`) takes more, below |
| `POST /api/private/shares/:id/revoke` | `manage` | header `X-Secbin-Intent: 1`, no body → `{ ok }` — destroys the content at once; the row stays as `revoked` |
| `DELETE /api/paste/:id`, `DELETE /api/file/:id` | none | header `X-Delete-Token` → `{ status: "deleted", id }` — the delete token is the capability, no API key; `423 share_locked` for a locked share |

A share row is `{ id, kind, label, created, expires, views_total, left, opens, status, locked, captcha }`:
`kind` is `text`, `url`, `secret` or `files`; `views_total` the view limit (`null` =
unlimited) and `left` the views left (`null` when unlimited or not active); `opens` counts every
open; `locked` is `1` when the administrator has locked it; `captcha` is `true` when recipients
must pass a CAPTCHA first. Times are unix seconds.

### CAPTCHA (`captcha`)

Whether recipients must pass a CAPTCHA (Cloudflare Turnstile) in a browser before anything of
the share is served is your role's decision (Admin → Roles, "CAPTCHA on shares"):

- **Allow CAPTCHA (user chooses per share):** send `captcha: true` or `false`; left out, the
  role's default for new shares applies.
- **Require CAPTCHA for all shares:** every share has it, whatever you send.
- **Disable CAPTCHA:** none; `captcha: true` is refused (`403 captcha_disabled`).

The result's `captcha` says what the share got. The flag is set when the share is created. While
the server has no Turnstile keys it is stored but not asked for.

A share with the CAPTCHA can be opened in a browser only. Every recipient route
(`GET /api/paste/:id`, `/api/file/:id`, `…/open`, `…/expire`, `…/chunk/…`) answers
`403 captcha_required` ("This share requires a CAPTCHA; open it in a browser") without a grant
from the share's CAPTCHA page, and nothing is spent: an API client or `secbin get` cannot open
it. The grant route is `POST /api/(paste|file)/:id/human` with `X-Secbin-Intent: 1` and a
Turnstile token (`X-Secbin-Turnstile`) for the action `share-open`, which only the page's
widget produces. At most 30 such checks per network per 10 minutes (`429 rate_limited`), and
a failed token counts as an invalid request. The share's CAPTCHA page (`/p/:id?check`,
`/r/:id?check`) is served only to this site's own document navigations; any other request is
redirected to the share's page without being counted.

While Turnstile is configured, a recipient route without a grant answers the same `403
captcha_required` for an id whose share does not exist or has ended, so it tells nothing about
an id before the check. A share without the CAPTCHA answers as usual.

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
| 403 | `csrf_mismatch` | browser session only (never an API key): a change without the session's `X-Secbin-CSRF` token (see above) |
| 403 | `too_many_views`, `unlimited_views_disabled`, `expiry_too_long` | beyond the account's limits (for a key: its API limits); `max` is attached |
| 403 | `bad_token` | wrong delete token |
| 403 | `bad_password` | a wrong share password (`open`, "delete now"); with `until` (unix seconds) when this failure locked the share's password |
| 429 | `password_locked` | too many wrong passwords were tried for this share, from any network: its password is locked until `until` (unix seconds; also `Retry-After`), even the right one. "Too many wrong passwords for this share. Try again at 2030-01-01 00:00 UTC." Nothing is opened or spent, and it is not counted as an invalid request |
| 400 | `invalid_captcha` | `captcha` is not `true` or `false` |
| 403 | `captcha_disabled` | `captcha: true` while your role has the CAPTCHA off |
| 403 | `captcha_required` | a recipient route of a share with the CAPTCHA — or of a missing or ended share, while Turnstile is on — without a grant (open it in a browser) |
| 429 | `rate_limited` | too many requests from your network: CAPTCHA checks on the share CAPTCHA routes (30 per 10 minutes); rejected CAPTCHA tokens on sign-in, account changes and anonymous creation (60 per 10 minutes; accepted tokens are never counted); sign-in prelogins (`POST /api/auth/prelogin`, 600 per 10 minutes, and 20 per username); chunk fetches of shares that have ended (600 per 10 minutes); attempts on shares whose password is locked (120 per 10 minutes); the anonymous tracker (`GET /api/public/t`, 600 per 10 minutes). `Retry-After` says when to try again |
| 410 | `gone` | the share has ended (expired, used up, revoked or deleted) — also for a chunk fetch with a download grant of a share that ended during the download, which is never counted as an invalid request; and "delete now" (`POST /api/(paste\|file)/:id/expire`) for an id that was never a share, which is counted |
| 403 | `bad_grant` | a chunk fetch without a valid download grant, whatever the chunk index (counted as an invalid request); with a valid grant an index out of range is `404` |
| 429 | `quota_exceeded`, `blocked` | a creation quota, or too many invalid requests from your network |

`429 quota_exceeded` names the quota it reached: `{ error: "quota_exceeded", message: "Quota
reached: 10 notes per 1d via the API.", quota: { channel, kind, n, unit, max } }`. `channel` is
`all` (GUI and API together) or `api` (API only); `kind` is what it counts — outgoing shares:
`all` (every note, link, credential, file share and Drive share), `text` (notes, links and
credentials), `note` (plain text, Markdown or code), `url`, `secret`, `files` (file and Drive
shares), `file`, `drive`; the Drive: `drive-upload` (each file uploaded), `drive-bytes` (the
bytes uploaded, and those of each file received through a Receive link once it is finished:
`max` and the count are bytes, and the message names a size, e.g. "Quota reached: 1.0 GB
uploaded to the Drive per 1d."; a received file never counts under `drive-upload`); Receive: `receive` (all below),
`receive-link` (a new reverse share), `receive-upload` (an upload session through one of your
links, whatever it sends), and by what a session sends: `receive-file` (files),
`receive-note`, `receive-url`, `receive-secret`. A key only ever meets the outgoing kinds (the
Drive and Receive are for browser sessions). The message's words for each kind: outgoing
shares; notes, links and credentials; notes; links; credentials; file and Drive shares; file
shares; Drive shares; files uploaded to the Drive; uploaded to the Drive (after the size);
Receive links and uploads received; new Receive links; uploads received; uploads with files
received; notes received; links received; credentials received.

The role's file rules (file types, folder depth) on the Drive's routes, for browser sessions:

| Status | `error` | Body, besides `error` and `message` |
| --- | --- | --- |
| 400 | `declaration_required` | `policy: { mode, rules, maxFolderDepth }` — the role has a type policy: send the file's `types` |
| 400 | `invalid_declaration` | — `types` is not exactly one `{ ext, mime }` |
| 403 | `file_type_not_allowed` | `refused: [{ ext, mime }]` — "This file type may not be uploaded to your Drive: .exe (application/x-msdownload)." (a take-in: "added to"); checked on the declaration, then on the file's stored name and metadata (no `refused` then): "The declared file type does not match the file’s stored type, …", "This file type may not be …", "This file’s type cannot be checked against your role’s file-type rules, …" |
| 403 | `folder_too_deep` | `max` — "Folders may be nested at most 2 levels deep in your Drive." (a new folder, an upload into a folder deeper than that, a move, a take-in) |

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
| `GET /api/private/drive` | → `{ enabled, capacity, maxFile, used, current, received, receivedFailed, migration, kit }` (`kit`: the personal kit's state, left out while the owner acts as the user; `current`: the current sub-MEK's id; `migration`: null, or what the upgrade of a Drive made before the key model v2 still has to do; `capacity` / `maxFile` null = no limit) |
| `POST /api/private/drive/keys` | `{}` → `{ userId, current, changing, keys: [{ mekId, fp, from, until, kek, kekOld? }], missing, broken }` — the session's KEKs, derived by the server (docs/DRIVE.md §3); the browser keeps them in the page's memory only. `503 keys_missing`, `409 salt_missing`; the owner acting as the user gets the user's (in the admin audit) |
| `POST /api/private/drive/kit` · `…/kit/verify` | the personal kit: its content after `current` / `reauth`; a read-only check by check values. Not while impersonating |
| `POST /api/private/drive/kit/restore` · `GET`, `PUT …/kit/items` | `403 owner_only` for everyone: only the owner restores from a personal kit (`POST /api/private/admin/keys/users/<userId>/kit-restore`, [docs/DRIVE.md](./DRIVE.md) §3.1) |
| `GET /api/private/drive/migrate` · `GET …/migrate/items` · `PUT …/migrate` · `POST …/migrate/finish` · `POST …/migrate/retire` | the one-time upgrade of the user's own Drive made before the key model v2 (docs/DRIVE.md §3.3): `409 already_upgraded` once it is done; `retire` (`{ ids, current \| reauth }`) ends the links of the release before that the old key does not open. Not while impersonating |
| `GET /api/private/drive/nodes/:id` | → `{ node, children, path }` (`root` is the top folder) |
| `PATCH /api/private/drive/nodes/:id` | `{ parent?, name?, meta?, ks?, mek? }` — move / rename (a new name comes with the item's own `ks` and `mek`: `409 stale_keys`, `400 bad_seal`; a move past the role's folder depth: `403 folder_too_deep`; a file's new name or metadata is held to the role's file-type rule on what it would store, `403 file_type_not_allowed`, unless it keeps its type; `meta: null` for a file: `400 invalid`) |
| `DELETE /api/private/drive/nodes/:id` | header `X-Secbin-Intent: 1` — recursive; ends every share of it |
| `GET /api/private/drive/nodes/:id/shares` | → `{ shares }` — the active shares of the item |
| `POST /api/private/drive/folders` | `{ id, parent, name, meta?, ks, mek }` → `201 { id }` (`403 folder_too_deep` past the role's folder depth) |
| `POST /api/private/drive/files` | `{ id, parent, name, meta, dek, ks, mek, size, types? }` → `201 { id, uploadToken, chunks }`; `types: [{ ext, mime }]` (the file's type) when the role has a type policy (`400 declaration_required`, `403 file_type_not_allowed`); `403 folder_too_deep` into a folder deeper than the role allows; counted by the quotas of kind `drive-upload` (one) and `drive-bytes` (`size`) together (`429 quota_exceeded`), both given back when the Drive refuses the file or the upload never completes (deleted unfinished, or purged) |
| `PUT /api/private/drive/files/:id/chunk/:i` | encrypted chunk bytes (exact size), header `X-Upload-Token` |
| `POST /api/private/drive/files/:id/finalize` | header `X-Upload-Token` → `{ ok, ch }` (`409 busy` while a chunk is still being written) |
| `GET /api/private/drive/files/:id/chunk/:i` | → the ciphertext chunk |
| `POST /api/private/drive/shares` | `{ nodes (file ids), views, expire, deletable?, label?, paste, acc?, types?, depth?, captcha? }` → `201 { id, deletetoken, expires, captcha }` (`captcha` as above) |
| `POST /api/private/drive/reverse` | `{ id, folder, priv, mek, lh, expire, views?, password?, note?, label?, maxFiles?, maxBytes?, maxFileBytes?, types?, accept?, captcha?, current? \| reauth? }` → `201 { id, expires, views, captcha, accept }` (`expire: "never"`: no expiry, `expires: null`; below) — a reverse share (upload link; [`REVERSE.md`](./REVERSE.md) §6.1), confirmed with the password or a passkey; `409 exists` when any account holds the id; `captcha`: uploaders pass a CAPTCHA first (the role's "CAPTCHA on reverse shares": allow / require / off, as above); counted by the quotas of kind `receive-link` and `receive` (`429 quota_exceeded`; given back when the creation does not complete) |
| `GET /api/private/drive/reverse` | `?folder=:id` → `{ reverse }` — the Drive's reverse shares |
| `GET /api/private/drive/received` | `?after=:next` → `{ items, keys, more, next }` — received files not yet taken into the Drive (500 per page); `?failed=1` → the ones that could not be taken in (`{ items: [{ id, rs, label, size, created, failed, reason }], more, next }`) |
| `POST /api/private/drive/received/:id` | `{ parent, name, meta, dek, ks, mek, types? }` → `{ ok }` — a received file re-sealed into the Drive under the user's current KEK; held to the role's Drive rules as an upload (`types` with a type policy; `403 file_type_not_allowed`, `403 folder_too_deep`) |
| `POST /api/private/drive/received/:id/failed` | `{ reason }` (`unreadable`, `name`, `place`, `type`: the role's file-type rules refuse it in the Drive) → `{ ok, received, failed }` — the browser could not take it in (it leaves the queue); `DELETE` puts it back |
| `GET /api/private/admin/keys` · `…/usage`; `POST …/candidate`, `…/subs`, `PATCH`/`DELETE …/subs/:id`, `POST …/subs/:id/current`, `…/subs/:id/show`, `…/root`, `…/root/show`, `…/root/undo`, `…/root/drop-old`, `…/jobs`, `…/jobs/step`, `DELETE …/jobs`, `…/kit`, `…/verify`, `…/restore`, `…/export`, `…/import`, `…/users/:userId/view` | owner only: the Drive keyring (Admin → Security → Keys; docs/DRIVE.md §3, §3.2), every change (and the restore and import previews) with `current` / `reauth` and in the admin audit by fingerprint; `409 migration_pending` for a root change while a Drive still waits for its upgrade |
| `GET /api/private/admin/drive/migration` · `POST …/drive/migrate/:userId/escrow` · `GET`, `PUT …/drive/migrate/:userId[/items]` · `POST …/finish` · `POST …/retire` | owner only: the Drives waiting for their upgrade (disabled accounts too), and the upgrade of a user's Drive through the escrow of the release before (the escrow with `current` / `reauth`; in the admin audit) |
| `GET`, `DELETE /api/private/admin/drive/archive` | owner only: the owner's Drive archive of the release before (a start over); deleted with `{ confirm: <username>, current \| reauth }` (its R2 objects go, its paused links end; in the admin audit) |

`name`, `meta` and `dek` are sealed in the browser under the user's KEK (docs/DRIVE.md §3). The
Drive is not end-to-end encrypted: the server derives every KEK, so it can open them. A Drive share is opened like a file share (`POST /api/file/:id/open`, which
then also returns `refs: [{ chunks, size }]` and `kinds: { note, url, secret }`, what the
sender's role allowed it to share as notes, links and credentials when it was made: the
recipient's page shows an entry as one only where that is `true`), and its chunks are read with
`GET /api/file/:id/chunk/:ref/:i` and the download grant.

Reverse shares ("Receive" links) are listed, changed and revoked with the share routes above
(kind `reverse`) and with their own routes ([Receive links](#receive-links-reverse-shares),
below); an API key with `read` / `manage` can do that, not create one. On create,
`expire: "never"` makes a link with no expiry (only where the role's `reverseNoExpiry` allows it)
and `views` (1–100 000, or `null` / absent: unlimited, where `reverseAllowUnlimitedViews`
allows it; at most `reverseMaxViews`) limits the upload sessions; `expire` is held to
`reverseMaxExpireSec` (not the regular `maxExpireSec`), and a password is required or refused as
`reversePassword` says (`403 password_required_by_role` / `password_disabled`). `accept` says
what the link takes — a non-empty list of `files`, `note`, `url`, `secret` (absent: `["files"]`),
each allowed by the role's `reverseFiles`, `reverseText`, `reverseUrl`, `reverseSecret`
(`403 receive_kind_disabled`, with `kinds`). The response's
`expires` is `null` for a link with no expiry.

`PATCH /api/private/shares/:id` of a Receive link takes, besides `label`, and only where the
role's `reverseEdit` allows it (`403 reverse_edit_disabled`; for an API key, the API limits of
Admin → Roles apply on top):

| Field | Meaning |
|---|---|
| `expires` | a time (unix seconds, within 365 days and `reverseMaxExpireSec`), or `null`: no expiry (`reverseNoExpiry`, else `403 no_expiry_disabled`). As for other shares an expiry can only be extended (`400`); a link with none can be given one |
| `views` | the new total of views (a view: one upload session granted), or `null`: unlimited. It may be raised or lowered, never below the views already used (`400`, with `used`) |
| `maxFiles`, `maxBytes`, `maxFileBytes`, `types` | the limits, as on create (`maxBytes` at most `reverseMaxBytes`; `null` is that limit, or none) |
| `accept` | what it takes: a non-empty list of `files`, `note`, `url`, `secret`. Each kind it adds must be allowed by the role (for an API key, by the API limits too: `403 receive_kind_disabled`); a kind it already has may stay. Adding `files`, `url` or `secret` weakens it (below); adding `note`, or removing any, does not |
| `captcha` | `true` / `false`, within `reverseCaptcha` (`403 captcha_required_by_role` / `captcha_disabled`) |
| `password` | `{ salt, t, ph }` made in the browser from the link's key (docs/REVERSE.md §3), or `null`: none — within `reversePassword`. The password is not sent; the server, which holds the keys that open the link's key, can test guesses at it |
| `note` | `{ iv, ct }` sealed in the browser with the link's key, or `null`: none. Not end-to-end: the server can open it, as it can the link's uploads |
| `folder` | the Drive folder it receives into from now on: a folder id of your own Drive (`"root"`: its top folder), no deeper than the role's folder depth (`maxFolderDepth`; for a key, its API limit: `403 folder_too_deep` with `max`). A folder that is not in your Drive — another user's, a deleted one, an unknown id, or a received item not yet taken in — is `404 folder_not_found`; a file `400 not_a_folder`; a folder that could not hold what the link has waiting `409 folder_full`. What the link received and your Drive has not taken in yet (waiting, failed or still uploading) moves with it and is taken in there. Not weakening. Logged as `folder=<id>` |
| `current` / `reauth` | the confirmation a weakening change needs (below) |

A change that **weakens** a link — its password removed or changed, its CAPTCHA turned off, no
expiry, unlimited views, files, links or credentials it did not accept, or its own file limits
loosened (`types` removed or less restrictive: the mode changed, a type added to an allow list or
dropped from a block list; `maxFiles`, `maxBytes` or `maxFileBytes` raised or removed; `weakens`
names them `types`, `maxFiles`, `maxBytes`, `maxFileBytes`) — needs what creating one needs: the password proof (`current`) or a
passkey (`reauth`) in the same body (`400 reauth_required`, `403 wrong_password` /
`reauth_failed`, counted as failed confirmations), and is refused for an API key even with
`manage` (`403 step_up_required`, with `weakens`); the owner acting as the user confirms nothing.
Tightening needs no confirmation and works with an API key: adding a password to a link with
none, turning the CAPTCHA on, an expiry (extended within the role, or given to a link with none),
fewer views or more within the role's limit, tighter file limits (fewer types, lower limits), the
label.

→ `{ ok, expires, views, left, used, accept, folder }` (`expires` `null`: none). A revoked or ended link can only
be relabelled (`409 not_active`); a locked one not at all (`423`). The owner changing another
user's link directly (Admin → Shares) may change its label, expiry and views only (`403
user_only` otherwise: its folder too), and a link with no expiry only where that user's role allows it. The
anonymous uploader's routes (`/api/reverse/:id/open`, `begin`, `human`, `files`, chunks,
`finalize`, `done`) take no account at all: see [`REVERSE.md`](./REVERSE.md) §6.2.

## Receive links (reverse shares)

A "Receive" link (`/r/<id>#<key>`, [`REVERSE.md`](./REVERSE.md)) lets anyone send notes, links,
credentials and files into a folder of your Drive. It is **made in the Drive page** (Drive →
Receive…); a key can list it, read its receipts, change it, move it to another folder, pause and
revoke it (resuming needs the browser: below). The same routes work for a signed-in browser
session (with its CSRF token, above). Every route but revoke needs a role with the Drive and
reverse shares (`403 reverse_disabled` otherwise), and every route reaches only your own links
(`404 not_found` for anything else, a regular share included).

| Method & path | Scope | Body → result |
| --- | --- | --- |
| `GET /api/private/receive?q=&status=&expiry=&offset=` | `read` | → `{ rows: [link], total }`: 50 per page, newest first; `q` matches the label, `status` is one of `active`, `revoked`, `expired`, `ended`; `expiry=none` / `set` as for shares |
| `GET /api/private/receive/:id` | `read` | → `{ link }` |
| `GET /api/private/receive/:id/opens` | `read` | → `{ total, fields, rows: [{ ts, …}] }` — its receipts: one per **upload session** started (a view of the link), newest first (at most 200), with the details the administrator lets your account see, exactly as a share's read receipts (`fields` above) |
| `PATCH /api/private/receive/:id` | `manage` | the fields of a Receive link's change (above: label, expiry, views, limits, `accept`, CAPTCHA, password, note, `folder`) → `{ ok, expires, views, left, used, accept, folder }`. A change that **weakens** the link is `403 step_up_required` (with `weakens`) for a key, whatever else it sends |
| `POST /api/private/receive/:id/pause` | `manage` | header `X-Secbin-Intent: 1`, no body → `{ ok, paused: true }` — it takes no new upload session until resumed: the sender's page says it is not accepting files right now (`409 paused`); sessions open now end and their unfinished uploads are deleted (their reservations given back); what it received stays and is taken in as before |
| `POST /api/private/receive/:id/resume` | `manage` | header `X-Secbin-Intent: 1` → `{ ok, paused: false }` — it takes uploads again. Resuming reopens the link to anonymous senders, so it **weakens** it: an API key gets `403 step_up_required` (`weakens: ["paused"]`); a browser session sends the step-up in a JSON body (`{ current }` or `{ reauth }`: `400 reauth_required` without it). A link paused by an owner's start over in the release before cannot be resumed: `409 not_paused` |
| `POST /api/private/receive/:id/revoke` | `manage` | header `X-Secbin-Intent: 1` → `{ ok }` — uploads stop for good; what it received stays in your Drive. Like `/api/private/shares/:id/revoke`, it needs no role option: ending a link is always yours to do |

A link is `{ id, label, created, expires, status, locked, captcha, paused, held, opens, views,
used, left, received: { files, bytes }, folder, accept, password, note, maxFiles, maxBytes,
maxFileBytes, types, pending, failed, uploading }`: `expires` `null` for no expiry; `status` as in the share
index (`active`, `revoked`, `expired`, `ended`); `paused` is `true` while it takes no uploads and
`held` when you paused it (you can resume it); `opens` counts its upload sessions (its receipts);
`views` is its views (`null`: unlimited), `used` and `left` the views used and left; `folder` the
id of the Drive folder it receives into (`"root"`: the top folder; its name stays encrypted);
`accept` what it takes (`files`, `note`, `url`, `secret`); `password` and `note` say only
**whether** it has them (neither is ever returned, nor is its key); `pending` / `failed` the items
waiting to be taken in / that could not be; `uploading` its uploads in progress, `{ files, bytes
(sent so far), size (reserved), held (reserved and not sent, up to each one's next chunk), since
}` — what is using space (the Drive counts what they sent). A link that has left the Drive (ended more than 30
days ago) has the index's fields only (`folder: null`).

Pausing and resuming need no `reverseEdit` (like the label and revoking); both need an active link
that is not locked (`409 not_active`, `423 share_locked`). Pausing is a tightening and works with a
key; resuming is a weakening change and does not. Everything else follows the rules of
`PATCH /api/private/shares/:id` above: the role's options for the channel the change comes
through (for a key, the account's **API limits** of Admin → Roles: `reverseEdit`, the kinds,
expiry, views and folder depth), the step-up rule, the lock. Every change is in your activity log
(`share.updated` with `paused`, `resumed`, `folder=<id>`, …; `share.revoked`), with the key's id
(`apikey=<id>`) when a key made it.

**Why a key cannot create one:** a link's private key is made in the Drive page and sealed there
under your Drive keys (so that the Drive can take in what it receives), and an API key never gets
those keys; creating a link also needs your password or a passkey, which a key cannot give, as
for the changes that weaken a link. `POST /api/private/receive` is `405`, and
`POST /api/private/drive/reverse` with a key `403 api_key_not_allowed`.

| Status | `error` | When |
| --- | --- | --- |
| 403 | `reverse_disabled` | your role does not allow reverse shares (or has no Drive) |
| 403 | `step_up_required` | a change that weakens the link, or resuming it, with an API key (`weakens` lists what) |
| 403 | `reverse_edit_disabled` | your role (for a key: its API limits) does not allow changing a link after it is made |
| 403 | `receive_kind_disabled` | `accept` adds a kind your role (or its API limits) does not allow (`kinds`) |
| 403 | `folder_too_deep` | `folder` is deeper than your role's folder depth (`max`) |
| 404 | `folder_not_found` | `folder` is not a folder of your Drive (another user's, deleted, unknown, a received item) |
| 400 | `not_a_folder` | `folder` is a file |
| 409 | `folder_full` | `folder` could not hold what the link has waiting |
| 409 | `not_active` | the link has ended (only its label can change) |
| 409 | `not_paused` | resuming a link you did not pause |
| 423 | `share_locked` | the administrator has locked it |

### List your Receive links

Scope: `read`.

curl:

```sh
curl -sS -H "Authorization: Bearer $SECBIN_API_KEY" "https://bin.example.com/api/private/receive?status=active"
# one link (its folder, what it accepts, views, receipts count), and its receipts:
curl -sS -H "Authorization: Bearer $SECBIN_API_KEY" "https://bin.example.com/api/private/receive/$LINK_ID"
curl -sS -H "Authorization: Bearer $SECBIN_API_KEY" "https://bin.example.com/api/private/receive/$LINK_ID/opens"
```

Node.js:

```js
// receive-links.mjs (run: node receive-links.mjs)
const res = await fetch('https://bin.example.com/api/private/receive?status=active', {
  headers: { authorization: `Bearer ${process.env.SECBIN_API_KEY}` },
});
if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.json()).error}`);
const { rows, total } = await res.json();
for (const l of rows) console.log(l.id, l.paused ? 'paused' : l.status, l.accept.join(','), `${l.opens} sessions`, l.received.files, l.label);
console.log(`${rows.length} of ${total}`);
```

Python:

```python
# receive_links.py (run: python3 receive_links.py)
import os, requests

res = requests.get("https://bin.example.com/api/private/receive", params={"status": "active"}, timeout=30,
                   headers={"Authorization": f"Bearer {os.environ['SECBIN_API_KEY']}"})
res.raise_for_status()
data = res.json()
for l in data["rows"]:
    print(l["id"], "paused" if l["paused"] else l["status"], ",".join(l["accept"]), l["opens"], "sessions", l["label"])
print(len(data["rows"]), "of", data["total"])
```

### Pause a Receive link

Scope: `manage`. Paused, it takes no uploads (sessions open now end); what it received stays.
Resuming it reopens it to anonymous senders, so it is done in the browser (My shares or the
Drive, with your password or a passkey): an API key gets `403 step_up_required`.

curl:

```sh
curl -sS -X POST -H "Authorization: Bearer $SECBIN_API_KEY" -H "X-Secbin-Intent: 1" \
  "https://bin.example.com/api/private/receive/$LINK_ID/pause"
```

Node.js:

```js
// pause.mjs (run: LINK_ID=... node pause.mjs)
const res = await fetch(`https://bin.example.com/api/private/receive/${process.env.LINK_ID}/pause`, {
  method: 'POST',
  headers: { authorization: `Bearer ${process.env.SECBIN_API_KEY}`, 'x-secbin-intent': '1' },
});
console.log(res.status, await res.json()); // { ok: true, paused: true }
```

Python:

```python
# pause.py (run: LINK_ID=... python3 pause.py)
import os, requests

res = requests.post(f"https://bin.example.com/api/private/receive/{os.environ['LINK_ID']}/pause", timeout=30,
                    headers={"Authorization": f"Bearer {os.environ['SECBIN_API_KEY']}", "X-Secbin-Intent": "1"})
print(res.status_code, res.json())
```

### Change or move a Receive link

Scope: `manage`. The folder id is a folder of your own Drive (`"root"`: its top folder; a link's
`folder` above says where it receives into now). A change that weakens the link (no expiry,
unlimited views, its CAPTCHA off, its password removed or changed, files, links or credentials it
did not accept, its file types or size limits loosened) is `403 step_up_required`: make it in the
browser.

curl:

```sh
# fewer views, a label, and another folder (what it has waiting moves with it)
curl -sS -X PATCH -H "Authorization: Bearer $SECBIN_API_KEY" -H "Content-Type: application/json" \
  --data "{\"views\":10,\"label\":\"scans 2026\",\"folder\":\"$FOLDER_ID\"}" \
  "https://bin.example.com/api/private/receive/$LINK_ID"
```

Node.js:

```js
// move.mjs (run: LINK_ID=... FOLDER_ID=... node move.mjs)
const res = await fetch(`https://bin.example.com/api/private/receive/${process.env.LINK_ID}`, {
  method: 'PATCH',
  headers: { authorization: `Bearer ${process.env.SECBIN_API_KEY}`, 'content-type': 'application/json' },
  body: JSON.stringify({ folder: process.env.FOLDER_ID }),
});
console.log(res.status, await res.json()); // 403 folder_too_deep / 404 folder_not_found when refused
```

Python:

```python
# move.py (run: LINK_ID=... FOLDER_ID=... python3 move.py)
import os, requests

res = requests.patch(f"https://bin.example.com/api/private/receive/{os.environ['LINK_ID']}", timeout=30,
                     json={"folder": os.environ["FOLDER_ID"]},
                     headers={"Authorization": f"Bearer {os.environ['SECBIN_API_KEY']}"})
print(res.status_code, res.json())
```

Revoking works as for shares: `POST /api/private/receive/:id/revoke` (or
`/api/private/shares/:id/revoke`) with `X-Secbin-Intent: 1`.

## Security notes

- Treat a key like a password: it acts as you within its scopes until it expires or is revoked.
  Prefer short lifetimes and the narrowest scopes; keep `read` and `manage` for the tools that
  need them.
- Keys are stored only as hashes; the server cannot show a key again.
- Every response (API answers, chunks, errors and redirects as well as pages) carries
  `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload` and a
  `Permissions-Policy` that turns off every powerful browser feature.
- Every key creation, change and revocation, every share created with a key and every change a
  key makes to a share is recorded in your activity log (and the administrator's audit log).
- Read receipts can contain personal data about the people who opened a share (network address,
  location, browser, languages — only the details the administrator enables), and a Receive
  link's receipts the same about the people who sent to it. Treat what you fetch as sensitive:
  keep it only as long as you need it and protect it like the key itself.
