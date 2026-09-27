# Drive: design and interface contract

Status: the contract the Drive is built against (server, keys and client, UI). A change to
anything in this file is a coordinated change: update it first.

## 1. What it is

- Each **user** (not the public account) whose role allows it has a **Drive**: a private folder
  tree of files and folders, end-to-end encrypted like everything else, within a role capacity.
- A drive file or folder can be **shared** any number of times. Each share has the same options as
  a file share (views, expiry, password, "delete now", label), obeys the same role limits and
  quotas, and shows in My shares. When a share expires, is used up, revoked or deleted, **only the
  share goes; the drive data stays**. Shares reference the drive's stored ciphertext; nothing is
  copied or re-encrypted.
- Deleting a drive item ends every share that references it (recipients get "gone").
- Later (task #24, reverse share): anonymous uploads land in a drive folder the user chooses.
- Terminology: the person who owns a drive is the **user**; "owner" means the admin.

## 2. What the server sees

Visible to the server: the tree's shape (node ids, parent ids, file/folder), each file's exact
ciphertext size and chunk count, timestamps, and which shares reference which nodes.
Never visible: names, file types, contents, file keys, the Drive key.

## 3. Keys (client side only)

- **DK** — the Drive key: 32 random bytes per user, created in the browser the first time the
  user opens the Drive. Never sent to the server in the clear.
- Sub-keys, by HKDF-SHA-256 from DK (salt empty, info as given):
  - `secbin-drive/v1 names` → AES-256-GCM key for node names (field `name`) and file metadata
    (field `meta`: JSON `{ type, mtime, size }`; `size` lets the client check the server's);
  - `secbin-drive/v1 files` → AES-256-GCM key that wraps each file key (field `fk`).
- **fk** — per file, 32 random bytes; content chunks are encrypted exactly like file-share chunks
  (`encryptChunk(fk, i, n, plain)` from `public/js/files.js`, AAD `(i, n)`), with no padding:
  `n = ceil(size / 8 MiB)` (an empty file has no chunks) and chunk `i` is exactly
  `min(8 MiB, size − i · 8 MiB) + 16` bytes, where `size` is the file's plaintext size.
- Encrypted fields use `{ iv, ct }` (base64url, 12-byte IV, AES-256-GCM). AAD is
  `secbin-drive/v1\n<field>\n<nodeId>\n` so a value cannot be moved to another node or field.
  Because the AAD needs the node id before anything is sealed, **the browser chooses node ids**
  (16 random bytes, base64url: 22 characters) and sends them when it creates a node (§6).
- A wrap's `data` is an opaque string (≤ 1024 characters) of base64url segments joined by `.`:
  `1.<iv>.<ct>`, or for `escrow` `1.<epk>.<kid>.<iv>.<ct>`. Its AAD is the field AAD above with
  field `wrap:<kind>` and node id `ref` (for `escrow`: `escrow:<kid>`), so a wrap cannot be moved
  to another kind or ref. `escrowPriv` is `1.<iv>.<ct>` under the `files` key, field
  `escrowPriv`, node id `drive`. `driveSalt` is 16 bytes, base64url.
- **Wraps of DK** (the server stores them, cannot open them). The browser unlocks DK with the
  first one that works:
  1. `pw` — password: `Argon2id(NFC(password), driveSalt, m = 64 MiB, t = 3, p = 1)` (a second
     derivation with a Drive-only 16-byte salt; the login proof is a different Argon2 output and
     never unlocks the Drive) → HKDF `secbin-drive/v1 kek-pw` → AES-GCM wrap of DK.
  2. `recovery` — one per recovery code: HKDF over the code's normalised text (as the server
     normalises it: upper case, no spaces or dashes, O → 0, I/L → 1),
     `secbin-drive/v1 kek-recovery` → wrap; `ref` = the code's existing server-side hash
     (hex `SHA-256("secbin-recovery/v1:" ‖ code)`). Regenerating recovery codes replaces these
     wraps; a code spent at sign-in has its wrap removed; removing the last passkey (which drops
     the codes) removes them all.
  3. `passkey` — one per passkey that supports the WebAuthn **PRF** extension: PRF output for the
     fixed salt `SHA-256("secbin-drive/v1 prf")` → HKDF `secbin-drive/v1 kek-prf` → wrap;
     `ref` = the credential id. Passkeys without PRF are simply not listed.
  4. `escrow` — **owner escrow**: ECDH P-256 between an ephemeral key and the owner's escrow
     public key → HKDF (salt = the ephemeral public key, raw) `secbin-drive/v1 kek-escrow` →
     wrap; stored with the ephemeral public key and `kid` (the first 16 bytes of SHA-256 over
     the owner's raw public key), `ref` = `escrow`. A wrap for an older owner key is replaced
     on the next unlock.
     The owner's escrow private key (PKCS#8) is stored encrypted under the **owner's own DK**
     (`escrowPriv` field of the owner's drive). The owner can therefore open any user's Drive:
     every escrow unwrap is logged (`drive.escrow_used`, with the user and the reason).
- **Unlock at sign-in:** after a successful password, passkey or recovery-code sign-in, the login
  page fetches the wraps and unlocks DK with what it has (password → `pw`; passkey with PRF →
  `passkey`; recovery code → `recovery`), then keeps DK in the tab's `sessionStorage`
  (`secbin_dk`, base64url, with the user id in `secbin_dk_uid` so another account's page — e.g.
  while impersonating — never uses it) until sign-out or the tab closes. If none works, the
  Drive page asks. The first time (no wraps yet) DK is created then, which needs the password;
  a Drive whose root has content but no wraps is never given a new key.
- **Keeping wraps current (always in the browser that has DK):**
  - password change by the user → new `pw` wrap (new driveSalt);
  - admin password reset by the owner → the owner's browser opens the user's `escrow` wrap
    (needs the owner's DK unlocked) and writes a fresh `pw` wrap for the new password; if the
    owner's Drive is locked, the reset still works and the user unlocks with a recovery code,
    passkey or (later) escrow; the new `pw` wrap is written with
    `PUT /api/private/admin/drive/keys/<userId>` (§6);
  - new passkey with PRF → add its wrap (PRF requested at registration; an authenticator that
    only evaluates PRF on use gets its wrap at its next sign-in); passkey removed → its wrap
    removed by the server (the browser also asks, idempotently);
  - new recovery codes → replace `recovery` wraps (without DK in the tab, the old codes' wraps
    are still removed);
  - a sign-in whose password the server accepted but whose `pw` wrap did not open (after a reset
    without escrow), when another wrap opened DK → a fresh `pw` wrap;
  - escrow public key present and no `escrow` wrap (or one for an older owner key) → add it on
    the next unlock.
- The owner's escrow key pair is created the first time the owner opens their Drive.
- **Client modules:** `public/js/drivekeys.js` (the keys and wraps above, the tab's copy),
  `public/js/driveclient.js` (`openDrive`, `unlockDrive`, `unlockDriveWithPasskey`, the
  `DriveClient` methods, `DriveLocked` / `DriveDisabled`, and the upkeep helpers used by the
  login, Account and Admin pages; the interface the Drive page uses is §8.1),
  `public/js/refsmanifest.js` (manifest v3, §7).

## 4. Storage (server)

- A **Drive Durable Object per user**: `env.DRIVE.idFromName('drive:' + userId)` (new SQLite DO
  class `Drive`, binding `DRIVE`, a `new_sqlite_classes` wrangler migration). Tables:
  - `nodes(id TEXT PRIMARY KEY, parent TEXT, kind TEXT CHECK(kind IN ('dir','file')),
    name TEXT NOT NULL /* JSON {iv,ct} */, meta TEXT /* JSON {iv,ct}: type, mtime */,
    size INTEGER NOT NULL DEFAULT 0, chunks INTEGER NOT NULL DEFAULT 0, fk TEXT /* JSON {iv,ct} */,
    state TEXT NOT NULL CHECK(state IN ('pending','ready')), done INTEGER NOT NULL DEFAULT 0,
    upload_hash TEXT, created INTEGER NOT NULL, updated INTEGER NOT NULL)`; the root has
    `parent = NULL` and id `root`; a folder cannot become its own descendant.
  - `wraps(kind TEXT, ref TEXT, data TEXT, PRIMARY KEY(kind, ref))` and `meta(k, v)` for
    `driveSalt`, `escrowPriv` (owner only).
  - `refs(share_id TEXT, node_id TEXT)`: which shares reference which nodes.
- R2 objects: `d/<userId>/<nodeId>/<i>` (never under `f/`). Only the Drive DO deletes them.
- The owner's escrow **public** key lives in the Directory (`meta` key `drive.escrowPub`, JWK).
- Pending uploads older than the role's `filePendingSec` are purged by the Drive DO's alarm.

## 5. Role options (Admin → Roles; `LIMITS` in `src/lib/settings.js`)

- `driveEnabled` (bool, default **false**); `driveMaxBytes` (bytes, capacity, default 1 GiB,
  null = no limit up to a hard 100 GiB); `driveMaxFileBytes` (bytes, nullable, default null).
- Drive shares obey the same share options as file shares: `files`, `maxViews`,
  `allowUnlimitedViews`, `maxExpireSec`, `maxFilesPerShare`, `openerDelete`, file-type rules,
  quotas (kind `files`), receipts. The owner has no limits. The public account has no Drive.
- New keys join the Default role (a Directory migration materialises them) and appear in the
  role editors under a **Drive** section.

## 6. API (session only; not with API keys; never while impersonating for key operations)

All bodies JSON unless stated; errors `{ error, message }` as elsewhere.

| Method and path | Purpose |
|---|---|
| `GET /api/private/drive` | `{ enabled, capacity, used, driveSalt, wraps: [{kind, ref, data}], escrowPub, escrowPriv? }` (`escrowPriv` for the owner only; `capacity` null = no limit; `driveSalt`, `escrowPub` null until set). A role without a Drive: `{ enabled: false }`, or an error with code `drive_disabled` (any 404, or a 403 other than `impersonating`, reads the same) |
| `PUT /api/private/drive/keys` | set wraps: `{ driveSalt?, set: [{kind, ref, data}], remove: [{kind, ref}], escrowPriv?, escrowPub? }` (the last two owner only) |
| `GET /api/private/drive/nodes/<id>` | the node and its children: `{ node, children: [...], path: [...ancestors] }` (`root` for the top; `path` root first, the node itself may be included). Each node: `{ id, parent, kind: 'dir' \| 'file', name, meta?, fk?, size, chunks, state, created, updated }` with the sealed fields as stored (`{ iv, ct }` objects or their JSON text), `size` in plaintext bytes, times in seconds; children include `meta` and `fk` for files (else the client fetches each file node). 404 for an unknown id |
| `POST /api/private/drive/folders` | `{ id, parent, name }` → `{ id }` (`id` chosen by the browser, §3; 409 if taken) |
| `POST /api/private/drive/files` | `{ id, parent, name, meta, size, fk }` → `{ id, uploadToken, chunks }` (`size` = plaintext bytes, `chunks = ceil(size / 8 MiB)`, §3; capacity checked) |
| `PUT /api/private/drive/files/<id>/chunk/<i>` | `application/octet-stream`, header `X-Upload-Token`; exact size check |
| `POST /api/private/drive/files/<id>/finalize` | header `X-Upload-Token` → `{ ok }` |
| `GET /api/private/drive/files/<id>/chunk/<i>` | ciphertext chunk for the user |
| `PATCH /api/private/drive/nodes/<id>` | `{ parent?, name? }` move / rename → `{ ok }`; 409 when `parent` is the node or inside it; the root cannot be moved, renamed or deleted |
| `DELETE /api/private/drive/nodes/<id>` | recursive; ends referencing shares; frees capacity; also used by the client to drop a failed upload's `pending` node |
| `POST /api/private/drive/shares` | `{ nodes: [file ids], views, expire, deletable?, label?, types?, depth?, paste, acc }` → `{ id, deletetoken }`: `nodes` lists **files** (the browser flattens folders), and `refs[i]` is `nodes[i]`; `types` / `depth` are the file-policy declaration, sent only when a policy applies (as for file shares); `paste` is the `encryptPaste` body (`acc` is also inside it) |
| `GET /api/private/drive/nodes/<id>/shares` | shares referencing the node — for a folder, every share that references a file under it: `{ shares: [{ id, label, kind: 'drive', created, expires, views_total, left, status, locked }] }` (My shares' row fields; `views_total` / `left` null = unlimited) |
| `POST /api/private/admin/drive/escrow/<userId>` | owner: `{ reason }` → `{ wrap, wraps }` (`wrap` = the user's `escrow` wrap or null), logged `drive.escrow_used` |
| `PUT /api/private/admin/drive/keys/<userId>` | owner, after resetting the user's password: `{ driveSalt, set: [{ kind: 'pw', ref: 'pw', data }] }` (only a `pw` wrap, nothing removed), logged `drive.pw_rewrapped` |

While the owner impersonates a user, key operations (`PUT /api/private/drive/keys` and the two
admin routes) answer 403 `{ error: 'impersonating' }`; the client never sends them then. State-
changing routes carry the usual intent header (`public/js/api.js`) and upload / finalize the
`X-Upload-Token` header. Drive shares are revoked with the existing
`POST /api/private/shares/<id>/revoke` (the share ends, the drive data stays) and appear in My
shares and Admin → Shares with `kind = 'drive'`.

## 7. Drive shares

- A drive share is a **FileShare** DO record with `refs: [{ key: 'd/<uid>/<node>', chunks, size }]`
  instead of its own uploaded stream. It is created active (no upload step). Its purge never
  touches `d/` objects. The Directory `shares` row has `kind = 'drive'`.
- The share's encrypted paste (the manifest, sealed with the share's own link key and optional
  password, exactly as for file shares) is **manifest v3**:
  `{ v: 3, kind: 'refs', entries: [{ path, size, type, mtime, ref, fk }], dirs: [...], view }` where
  `ref` indexes `refs` and `fk` is that file's key (base64url). Folders are flattened to paths
  (`dirs` lists every folder, so empty ones survive; duplicate names get " (2)"…). `view` is the
  sender's viewer-policy snapshot as in v2 (`{ rules, maxBytes }` or null; optional on read).
  `public/js/refsmanifest.js` builds and validates it. The share id starts with `f` and its paste
  has `fmt: 'files'`, like a file share, so the viewer opens it the same way.
- Recipients open it like a file share (`POST /api/file/<id>/open`); the response adds
  `refs: [{ chunks, size }]`. Chunks: `GET /api/file/<id>/chunk/<ref>/<i>` with the download
  grant. `public/js/downloads.js` and the viewer read v3 manifests (per-file keys and chunk
  sequences), including preview, single-file download and zip.
- Deleting a drive node revokes every share whose `refs` include it (or a descendant).

## 8. UI

- **Dashboard → Drive** (`/dashboard/drive/`), shown when the role allows it:
  - left pane: the folder tree, **collapsed by default**; a **+** (−) button expands (collapses)
    a folder's sub-folders; selecting a folder shows its content in the right pane;
  - right pane: the folder's files and folders (name, size, modified), with upload (files and
    folders, drag and drop), new folder, rename, move, delete, download, and **Share…** (the
    composer's share options), and each item's shares (with revoke);
  - capacity bar (used of total);
  - an unlock prompt (password, passkey or recovery code) when the tab has no DK.
- The same tree component (`public/js/tree.js`: WAI-ARIA tree with `aria-expanded`, keyboard
  support, collapsed by default, + to expand, right-pane contents) replaces the folder lists in
  the composer's file list and the recipient's file view (task #23, item 15).
- The owner's Admin → Users shows each user's Drive usage; there is no admin file browser.

### 8.1 The page and the client (as integrated)

The Drive page (`public/dashboard/drive/index.html`, `public/dashboard/js/drive.js` →
`drive-app.js`) uses the real client (`public/js/driveclient.js`) and nothing else; there is no
stand-in. What each side relies on:

- **"Collapsed by default"** means: the root ("My Drive" / "All files") is open and shows its
  top-level folders, and every folder under it is closed. The + / − toggle is a pointer target
  only (`aria-hidden`); the state is `aria-expanded` on the treeitem, and the keyboard uses → / ←.
  In the composer and the recipient view the tree appears only when there are folders; a flat
  list of files stays a flat list (a single file stays the file card).
- **Nav:** the **drive** link is shown exactly when `/api/private/me` has
  `caps.driveEnabled === true`; hidden otherwise.
- **The account:** `drive.js` passes `user = { id, role, impersonating }` (from the profile:
  `impersonating = !!impersonatedBy`) to `openDrive({ user })`, `unlockDrive(creds, { user })` and
  `unlockDriveWithPasskey({ user })`, so the client needs no session lookup. While the owner
  impersonates a user, the tab's key slot keeps the owner's own DK (`secbin_dk_uid`), so the
  user's Drive shows the unlock prompt; a Drive with no key yet cannot be set up then
  (`DriveLocked` reason `impersonating`).
- **Opening:** `openDrive()` resolves to a `DriveClient` or throws `DriveDisabled` (the page says
  "Drive is not enabled for your account") or `DriveLocked` with `reason` and `credentialIds`
  (the passkeys with a Drive wrap). Reason `setup` (no wraps yet): the prompt is "Set up your
  Drive" and offers only the password (only the password can create DK). Otherwise it offers the
  password, a recovery code, and "Unlock with a passkey" when `credentialIds` is not empty and
  the browser has WebAuthn. `unlockDrive({ password } | { code })` and
  `unlockDriveWithPasskey()` resolve to the client; a wrong secret is `DriveLocked` reason
  `wrong` ("That does not unlock your Drive"). A `DriveLocked` from `list()` (the tab's key does
  not open this Drive; the client has dropped it) returns the page to the prompt.
- **Passkeys and PRF:** one helper for the sign-in and the Drive page: `public/js/passkeys.js`
  (`usePasskeyPrf` at sign-in, `passkeyPrfOnly` for the Drive's local assertion, both asking for
  `extensions.prf.eval.first = DRIVE_PRF_SALT` from `drivekeys.js`), and the credential id is
  `credential.rawId` as base64url everywhere (the `passkey` wrap's `ref`). The PRF output never
  leaves the browser.
- `list(id)` → `{ node, path, children }`: `path` is `[{ id, name }]` from the root (`id` `root`,
  name "Drive", shown as "My Drive") down to and including the node; `children` are decoded
  nodes `{ id, parent, kind: 'dir' | 'file', name, type, mtime, size, chunks, created, updated }`
  (pending uploads left out, folders first). `mtime` is the file's own time in ms (from its
  sealed metadata; 0 for folders), `updated` the server's time in s; "Modified" shows a file's
  `mtime`, else `updated`. A name that does not decrypt is `null` (shown as "(unnamed)").
- `usage()` → `{ used, capacity }` in bytes (`capacity: null` = no limit).
- **Transfers** report `onProgress(bytesDone, total)` (plaintext bytes) and take an `AbortSignal`
  `signal` (the page's Cancel); an abort rejects with an `AbortError`:
  `upload(parent, file, { onProgress, signal })`,
  `uploadTree(parent, [{ path, file } | { path, dir: true }], { onProgress, signal })` (dropped
  empty folders are kept as `{ path, dir: true }`), `download(id, { onProgress, signal })` → a
  handle whose `save()` streams the file to disk or a download, and
  `downloadFolder(id, { onProgress, signal })` (a ZIP).
- `mkdir(parent, name)` → the new id; `rename(id, name)`, `move(id, parent)`, `remove(id)`.
- `share(ids, { views, expire, password, deletable, label, limits, view })` → `{ url, id,
  deletetoken }`: `ids` may be files and folders (the client flattens them to files for the
  server); `views` is a number or `null` (unlimited), `expire` the composer's string form
  (`"24h"`, `"30m"`, `"7d"`); `limits` is the profile's `limits` (the client applies the
  file-type and folder-depth policy and declares `types` / `depth`, as the composer does);
  `view` is the viewer snapshot `{ rules, maxBytes }` from the profile's `viewer` when the
  sender ticks "Allow recipients to view files in the browser" (shown when the viewer is
  enabled), else `null`. The page checks `maxViews`, `allowUnlimitedViews`, `maxExpireSec`,
  `openerDelete` and `files` like the composer; the server enforces them again.
- `shares(id)` → the server's rows (§6), shown with their label, type ("drive"), created,
  expiry, views and status; revoke uses `POST /api/private/shares/<id>/revoke`.
- Names typed in the UI are trimmed and NFC-normalised; empty, `.`/`..`, `/`, `\`, control
  characters and more than 255 UTF-8 bytes are refused (as `checkName` in the client), and so is
  a name already used in the same folder when creating or renaming (the server cannot check
  encrypted names). Uploads keep the file's own name; a duplicate name in a folder is allowed.

## 9. Security notes

- Owner escrow means the owner can decrypt every user's Drive: this is a deliberate choice by
  the maintainer, and every use is logged (`drive.escrow_used`).
- DK in `sessionStorage` is readable by script on the origin; the CSP and Trusted Types are what
  keep other script out, as for the rest of the app.
- Capacity, sizes and chunk counts are enforced server-side; names and types are not (they are
  encrypted), so file-type rules for drive shares are enforced by the client, as for file shares.

## 10. What the server must provide (shard A checklist)

The browser side (shards B and C) is integrated and tested against an in-memory stand-in of the
API (`test-dom/drive-fake-server.js`); the server has to match it:

1. **`/api/private/me`**: `caps.driveEnabled` (boolean) — the role's `driveEnabled` (the owner
   always true, the public account false). The nav and the page read only this.
2. **Login responses** (password, recovery code, passkey, second step) keep `user: { id, role }`,
   and `/api/auth/session` keeps `user` and `impersonatedBy`: the sign-in unlock and the tab key's
   user binding use them.
3. **`GET /api/private/drive`** exactly as §6, including `{ enabled: false }` (or
   `drive_disabled`) for a role without a Drive, `capacity: null` for no limit, `escrowPub` for
   every user once the owner has one, `escrowPriv` for the owner only.
4. **`PUT /api/private/drive/keys`**: `set` / `remove` by `(kind, ref)` (removing a missing wrap
   is not an error); kinds `pw` (ref `pw`), `recovery` (ref = the code's server-side hash, hex
   `SHA-256("secbin-recovery/v1:" ‖ normalised code)`, as `src/directory-do.js` stores it),
   `passkey` (ref = the credential id, base64url, as stored for the passkey), `escrow` (ref
   `escrow`); `data` a string of at most 1024 characters; `driveSalt` 16 bytes base64url;
   `escrowPriv` / `escrowPub` from the owner only (the public key into the Directory, §4);
   403 `impersonating` while impersonating.
5. **Wrap housekeeping on the server:** deleting a passkey (by the user or the owner) removes
   its `passkey` wrap; deleting a user deletes their Drive (nodes, wraps, R2 `d/<uid>/…`).
   Recovery-code regeneration, spent codes and the codes dropped with the last passkey are
   handled by the browser (§3); where the server itself drops recovery codes without a browser
   in the loop (e.g. an admin action), it should drop their `recovery` wraps too.
6. **Node ids from the browser:** `POST /api/private/drive/folders` and `/files` take `id`
   (`/^[A-Za-z0-9_-]{22}$/`, 409 when taken), check that `parent` is one of the user's folders,
   and echo `id`.
7. **Files:** `POST /api/private/drive/files` answers `chunks = ceil(size / 8 MiB)` (the client
   refuses anything else) and an `uploadToken`; checks `driveMaxBytes` (capacity, counting
   pending uploads) and `driveMaxFileBytes`. `PUT …/chunk/<i>` accepts exactly
   `min(8 MiB, size − i · 8 MiB) + 16` bytes with the right `X-Upload-Token` (4xx otherwise; the
   client retries a 5xx once). `POST …/finalize` checks every chunk is there → `{ ok }`. A
   zero-byte file has no chunks and finalizes at once. `GET …/chunk/<i>` returns the raw bytes.
8. **Nodes:** `GET /api/private/drive/nodes/<id>` as §6 (node shape, `path` root first, times in
   seconds, children with `meta` and `fk`); `PATCH` refuses cycles (409) and root changes;
   `DELETE` is recursive, works on pending nodes, frees capacity, and ends every share that
   references a removed file.
9. **Shares:** `POST /api/private/drive/shares` with `nodes` = the user's **ready file** ids
   (`refs[i]` = `nodes[i]`), `views`, `expire`, `paste` (+ `acc`), optional `deletable`, `label`,
   `types`, `depth` → `{ id, deletetoken }` with an `f…` id, creating an active FileShare with
   `refs` (§7) and a Directory row of kind `drive`; the same role checks as a file share
   (`files`, `maxViews`, `allowUnlimitedViews`, `maxExpireSec`, `maxFilesPerShare`,
   `openerDelete`, the declared file-type / depth policy, quotas of kind `files`, receipts).
   `GET /api/private/drive/nodes/<id>/shares` returns My-shares rows (§6), for a folder those of
   the files under it. The existing revoke, My shares and Admin → Shares routes handle kind
   `drive` (ending a share never touches `d/` objects).
10. **Recipients:** `POST /api/file/<id>/open` for a drive share adds `refs: [{ chunks, size }]`
    (in `nodes` order), and `GET /api/file/<id>/chunk/<ref>/<i>` serves chunk `i` of file `ref`
    under the download grant (`X-Download-Grant`), as `public/js/downloads.js` fetches it.
11. **Owner routes:** `POST /api/private/admin/drive/escrow/<userId>` `{ reason }` →
    `{ wrap, wraps }` (404 or 409 when the user has no Drive or no escrow wrap), logged
    `drive.escrow_used` with the reason; `PUT /api/private/admin/drive/keys/<userId>` with only
    a `pw` wrap and `driveSalt`, logged `drive.pw_rewrapped`. Owner only, never while
    impersonating.
12. **Role options** (§5) with a Directory migration materialising them in the Default role and
    the role editors' **Drive** section; the `/dashboard/drive/` page itself needs nothing more
    than the existing dashboard handling (signed-in only).

The end-to-end suite for the integrated Drive (the unlock at sign-in and on the page, the tree,
every action, shares and revoke, the recipient's view of a drive share) waits for these routes.
