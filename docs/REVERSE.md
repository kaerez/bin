# Reverse shares ("Receive files"): design and interface contract

Status: the contract reverse shares are built against (task #24). It builds on the Drive
([`DRIVE.md`](./DRIVE.md)); a change to anything here is a coordinated change: update it first.

## 1. What it is

- A **user** whose role allows it creates a **reverse share** on one of their Drive folders: a
  link (`/r/<id>#<key>`) that lets anyone, with no account, upload files and folders to them.
- Uploads land in the chosen Drive folder. The user sees them there like any other file, the next
  time their Drive is unlocked (until then: "N new received files").
- An optional **password** gates the anonymous uploader only. It never protects the data (always
  encrypted to the user's key) and the user never needs it.
- Revoking, expiring or using up a reverse share stops uploads; files already received stay in the
  Drive. Deleting the folder ends its reverse shares.
- Reverse shares are listed in My shares and Admin → Shares with `kind = 'reverse'`, and in the
  Drive's "Receive files…" dialog of the folder.
- Terminology: the person who owns the Drive is the **user**; "owner" means the admin.

## 2. What the server sees

- Visible: the reverse share's id, folder id, label, limits, times, status, counters (files and
  bytes received), each received file's ciphertext size and chunk count, the uploader's network
  address (as for every request, for the Guard), and whether a password is set.
- Never visible: file contents, names, types, folder structure of an upload, the note to the
  uploader, the link key (the public key, only in the URL fragment), the password, the reverse
  share's private key, any file key.

## 3. Keys (client side only)

All base64url, no padding. `public/js/reversekeys.js` implements this section.

- **Link key pair:** each reverse share has its own **ECDH P-256** key pair, made in the user's
  browser. The raw public key (65 bytes, uncompressed) is the URL fragment: `/r/<id>#<b64url(pub)>`
  (87 characters). The browser chooses `id` (`r` + 16 random bytes, 23 characters), so the sealed
  values below can be bound to it.
- **Private key:** PKCS#8, sealed with DK's **`files`** sub-key (docs/DRIVE.md §3) as a sealed
  field `{ iv, ct }` with field `reversePriv` and node id `<id>` (AAD
  `secbin-drive/v1\nreversePriv\n<id>\n`). Only the user's unlocked Drive opens it. The user's
  browser rebuilds the link from it (the public point is part of the private key), so the link
  can be shown again later.
- **Link proof:** `HKDF(ikm = pub, salt = "", info = "secbin-reverse/v1 link-proof")`; the server
  stores only `lh = b64url(SHA-256(proof))`, sent by the uploader in `X-Link-Proof`. A guess at
  the id alone gets nothing (not even whether a password is set).
- **Note to the uploader** (optional, ≤ 1000 characters): AES-256-GCM under
  `HKDF(pub, "", "secbin-reverse/v1 note")`, AAD `secbin-reverse/v1\nnote\n<id>\n`, stored as
  `{ iv, ct }`. Only link holders can read it.
- **Password** (optional): the user's browser picks a 16-byte `salt` and Argon2id cost `t`
  (default 3, 64 MiB, p = 1, as notes). `proof = HKDF(ikm = Argon2id(NFC(password), salt, t),
  salt = pub, info = "secbin-reverse/v1 pw-proof")`; the server stores `salt`, `t` and
  `ph = b64url(SHA-256(proof))`. Because `pub` is only in the link, a copy of the server's data
  alone does not allow an offline guess at the password. The uploader sends the proof in
  `X-Key-Proof`.
- **Each uploaded file** (in the uploader's browser):
  - `fk` = 32 random bytes; chunks are encrypted exactly like Drive files
    (`encryptChunk(fk, i, n, plain)`, `n = ceil(size / 8 MiB)`, chunk `i` exactly
    `min(8 MiB, size − i · 8 MiB) + 16` bytes, no padding);
  - `mk` = 32 random bytes (the metadata key); the node id (16 random bytes, 22 characters) is
    chosen by the uploader;
  - `name` = AES-GCM(`mk`, the file's **relative path** — `a.txt` or `folder/sub/a.txt`, ≤ 2048
    bytes, `checkPath` rules), AAD `secbin-reverse/v1\nname\n<nodeId>\n`;
  - `meta` = AES-GCM(`mk`, JSON `{ type, mtime, size }`), AAD `secbin-reverse/v1\nmeta\n<nodeId>\n`;
  - the **wrap** of `fk ‖ mk` to the link public key: an ephemeral ECDH P-256 key pair,
    `shared = ECDH(ephemeral, pub)`, `kek = HKDF(shared, salt = epk, info = "secbin-reverse/v1
    kek")`, AES-GCM over the 64 bytes with AAD `secbin-reverse/v1\nwrap\n<id>\n<nodeId>\n`;
    `data = "1.<epk>.<iv>.<ct>"`. It is stored in the node's `fk` field in a new form:
    `{ kind: 'rs', data }` (a normal Drive file's `fk` is `{ iv, ct }`).
- **The user's side:** when the Drive is unlocked, the browser lists the received items, opens
  each reverse share's private key with DK, unwraps `fk ‖ mk`, opens the path and metadata,
  creates (or reuses, by name) the upload's folders under the target folder, and **re-wraps**
  the file into the normal Drive format — `name` (the leaf name) and `meta` under DK's `names`
  key, `fk` under DK's `files` key, all bound to the node id — then `POST`s it (§6). From then on
  it is an ordinary Drive file; the content chunks are never re-encrypted. An item that cannot be
  opened is left as received (the Drive shows how many; the user may delete them).

## 4. Storage (server)

- **Directory:** the `shares` row (`kind = 'reverse'`, the user, label, created, expires, status,
  lock, `lh`) maps the id to its user; it is what My shares and Admin → Shares list.
- **The user's Drive DO** (docs/DRIVE.md §4), new tables and one column:
  - `reverse(id, folder, priv, lh, ph, salt, t, note, opts, files, bytes, created, expires,
    status)`: `opts` is JSON `{ maxFiles, maxBytes, maxFileBytes, types }`; `files` / `bytes`
    count reserved uploads (a purged or cancelled upload gives its share back).
  - `rsessions(hash, rid, expires, files, bytes)`: upload sessions; `hash` = SHA-256 of the
    session grant (256 bits); `files` / `bytes` = finalized in the session, not yet logged.
  - `nodes.rs`: the reverse share of a **received** file that the user's browser has not yet
    re-wrapped. Received files are left out of folder listings, shares and moves until then.
- Received files are ordinary `nodes` rows (kind `file`, parent = the target folder), R2 objects
  under `d/<userId>/<nodeId>/<i>`, counted in the Drive's capacity from the moment they are
  reserved. Upload tokens are stored hashed (`upload_hash`), and a pending upload with no chunk for
  the role's `filePendingSec` is purged by the Drive's alarm, as for the user's own uploads.
- Hard ceilings: 1 000 reverse shares per Drive (ended ones are dropped once all their received
  files are re-wrapped), 100 open sessions per reverse share, 10 000 files per reverse share.

## 5. Options and role options

- **Per reverse share** (chosen by the user): expiry (the role's `maxExpireSec` applies, at most
  365 days); maximum number of files (`maxFiles`, 1–10 000 or none); maximum total bytes
  (`maxBytes`); maximum file size (`maxFileBytes`); allowed file types (`types: { mode: 'allow' |
  'block', rules }`, the file-policy rules of `public/js/filepolicy.js`); a label (plain text, for
  the user's own lists); an optional note to the uploader (encrypted, §3); an optional password.
- **Role options** (Admin → Roles, Drive section; `LIMITS` in `src/lib/settings.js`):
  `reverseEnabled` (bool, default **false**; also needs `driveEnabled`), `reverseMaxActive`
  (active reverse shares at once, default 10, null = no limit up to 1 000), `reverseMaxBytes`
  (maximum total bytes per reverse share, default 1 GiB, null = no limit; a share's `maxBytes`
  may not exceed it and defaults to it). The owner: allowed, no limits. The public account: none.
- **Always:** the user's Drive capacity (`driveMaxBytes`) and largest file (`driveMaxFileBytes`),
  and the Drive's hard ceilings, apply to every upload.
- File types are declared by the uploader's browser (`declare()`), checked by the server against
  the share's rules and refused on a mismatch, as for file shares: a modified client could lie.

## 6. API

### 6.1 The user (session only, like the Drive; `403 reverse_disabled` unless the role allows it)

| Method and path | Purpose |
|---|---|
| `POST /api/private/drive/reverse` | create: `{ id, folder, priv: {iv, ct}, lh, password?: { salt, t, ph }, note?: {iv, ct}, label?, expire, maxFiles?, maxBytes?, maxFileBytes?, types? }` → `201 { id, expires }` (409 when the id is taken) |
| `GET /api/private/drive/reverse` | every reverse share of the Drive: `{ reverse: [row] }`; `?folder=<nodeId>` for one folder's |
| `GET /api/private/drive/received` | received files not yet re-wrapped (at most 500): `{ items: [{ id, parent, rs, name, meta, fk: { kind: 'rs', data }, size, chunks, created }], keys: [{ id, priv }], more }` |
| `POST /api/private/drive/received/<nodeId>` | re-wrapped: `{ parent, name, meta, fk }` (normal sealed fields; `parent` a folder) → `{ ok }` |
| `DELETE /api/private/drive/nodes/<nodeId>` | discard a received file (as any Drive item) |
| `POST /api/private/shares/<id>/revoke` | revoke (My shares); `PATCH /api/private/shares/<id>` changes the label or extends the expiry |

A row: `{ id, folder, label, created, expires, status, locked, priv, password: bool, note: bool,
maxFiles, maxBytes, maxFileBytes, types, files, bytes }` (`status`: `active`, `revoked`, `expired`,
`used` — no files or bytes left —, `ended`). `GET /api/private/drive` adds `received` (the number
of received files not yet re-wrapped). `GET /api/private/me` has `caps.reverseEnabled`.

### 6.2 The uploader (anonymous; `/api/reverse/<id>/…`)

Every route refuses cross-site callers (`Sec-Fetch-Site`) before any Guard accounting; a blocked
network is refused up front; every failure a guesser produces (unknown id, wrong link proof, wrong
password, bad grant or token) counts in the Guard's `invalid` scope, like invalid fetches. POSTs
without a JSON body carry `X-Secbin-Intent: 1`.

| Method and path | Headers | Purpose |
|---|---|---|
| `POST …/open` | `X-Link-Proof` | `{ note, password: null \| { salt, t }, expires, limits: { maxFiles, maxBytes, maxFileBytes, types, filesLeft, bytesLeft } }` |
| `POST …/begin` | `X-Link-Proof`, `X-Key-Proof` (password only), `X-Secbin-Turnstile` (when configured) | a session: `{ grant, expires }` |
| `POST …/files` | `X-Reverse-Grant`; JSON `{ id, name, meta, size, wrap, types? }` | reserve one file → `201 { id, uploadToken, chunks }` (limits, capacity) |
| `PUT …/files/<nodeId>/chunk/<i>` | `X-Upload-Token`; `application/octet-stream` | chunk `i`, exact size |
| `POST …/files/<nodeId>/finalize` | `X-Reverse-Grant`, `X-Upload-Token` | `{ ok }` |
| `DELETE …/files/<nodeId>` | `X-Reverse-Grant`, `X-Upload-Token` | cancel an unfinished upload (its reservation is given back) |
| `POST …/done` | `X-Reverse-Grant` | end the session: `{ files, bytes }` (logged) |

Errors: `404 not_found` (never a reverse share), `410 gone` (revoked, expired, used up, its folder
deleted, or the user's role no longer allows it), `423 share_locked` (the admin locked it),
`403 bad_link`, `401 password_required` (the password is needed; `{ salt, t }` in the body),
`403 bad_password`, `403 bad_grant`, `403 turnstile_*`, `413 file_too_large` / `share_full` /
`drive_full`, `409 too_many_files`, `403 file_type_not_allowed`, `429 blocked`.

## 7. Audit log

In the user's activity log (and the admin's audit): `share.created` (`kind=reverse`) and
`share.revoked` as for every share; `reverse.received` (`id`, `files`, `bytes`: count and size
only), written when a session ends (`done`) or its unlogged uploads are found when it lapses;
`reverse.bad_password` (`id`; at most one entry per share per minute).

## 8. UI

- **Drive → Receive files…** (toolbar; the selected folder, else the open one): a dialog with the
  options of §5, then the link with copy and a QR code, and the folder's reverse shares (label,
  created, expiry, files and bytes received, status) with Show link and Revoke.
- The unlock prompt says how many received files are waiting; once unlocked the browser
  re-wraps them (a status line; then the folder shows them).
- **Uploader page** `/r/<id>#<key>` (`public/r/index.html`, `public/js/reverse.js`): the note,
  the limits, a password field when needed, the human check (Turnstile, always visible when
  configured; the upload button stays disabled until it passes: `humanCheck` of
  `public/js/turnstile.js`), a file picker, a folder picker, drag and drop of files and folders,
  and progress. DOM only through `h()`; the page gets the Turnstile CSP when Turnstile is on and
  the strict one otherwise, and is never cached by the service worker.
- My shares / Admin → Shares: kind "receive"; views column shows the files received; revoke, lock
  and extend (expiry only) as for other shares.
