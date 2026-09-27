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
  - `secbin-drive/v1 names` → AES-256-GCM key for node names (and file type/mtime metadata);
  - `secbin-drive/v1 files` → AES-256-GCM key that wraps each file key.
- **fk** — per file, 32 random bytes; content chunks are encrypted exactly like file-share chunks
  (`encryptChunk(fk, i, n, plain)` from `public/js/files.js`, AAD `(i, n)`), with no padding.
- Encrypted fields use `{ iv, ct }` (base64url, 12-byte IV, AES-256-GCM). AAD is
  `secbin-drive/v1\n<field>\n<nodeId>\n` so a value cannot be moved to another node or field.
- **Wraps of DK** (the server stores them, cannot open them). The browser unlocks DK with the
  first one that works:
  1. `pw` — password: `Argon2id(NFC(password), driveSalt, m = 64 MiB, t = 3, p = 1)` (a second
     derivation with a Drive-only 16-byte salt; the login proof is a different Argon2 output and
     never unlocks the Drive) → HKDF `secbin-drive/v1 kek-pw` → AES-GCM wrap of DK.
  2. `recovery` — one per recovery code: HKDF over the code's normalised text,
     `secbin-drive/v1 kek-recovery` → wrap; `ref` = the code's existing server-side hash.
     Regenerating recovery codes replaces these wraps.
  3. `passkey` — one per passkey that supports the WebAuthn **PRF** extension: PRF output for the
     fixed salt `SHA-256("secbin-drive/v1 prf")` → HKDF `secbin-drive/v1 kek-prf` → wrap;
     `ref` = the credential id. Passkeys without PRF are simply not listed.
  4. `escrow` — **owner escrow**: ECDH P-256 between an ephemeral key and the owner's escrow
     public key → HKDF `secbin-drive/v1 kek-escrow` → wrap; stored with the ephemeral public key.
     The owner's escrow private key (PKCS#8) is stored encrypted under the **owner's own DK**
     (`escrowPriv` field of the owner's drive). The owner can therefore open any user's Drive:
     every escrow unwrap is logged (`drive.escrow_used`, with the user and the reason).
- **Unlock at sign-in:** after a successful password, passkey or recovery-code sign-in, the login
  page fetches the wraps and unlocks DK with what it has (password → `pw`; passkey with PRF →
  `passkey`; recovery code → `recovery`), then keeps DK in the tab's `sessionStorage`
  (`secbin_dk`, base64url) until sign-out or the tab closes. If none works, the Drive page asks.
- **Keeping wraps current (always in the browser that has DK):**
  - password change by the user → new `pw` wrap (new driveSalt);
  - admin password reset by the owner → the owner's browser opens the user's `escrow` wrap
    (needs the owner's DK unlocked) and writes a fresh `pw` wrap for the new password; if the
    owner's Drive is locked, the reset still works and the user unlocks with a recovery code,
    passkey or (later) escrow;
  - new passkey with PRF → add its wrap; passkey removed → its wrap removed by the server;
  - new recovery codes → replace `recovery` wraps;
  - escrow public key present and no `escrow` wrap → add it on the next unlock.
- The owner's escrow key pair is created the first time the owner opens their Drive.

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
| `GET /api/private/drive` | `{ enabled, capacity, used, driveSalt, wraps: [{kind, ref, data}], escrowPub, escrowPriv? }` (`escrowPriv` for the owner only) |
| `PUT /api/private/drive/keys` | set wraps: `{ driveSalt?, set: [{kind, ref, data}], remove: [{kind, ref}], escrowPriv?, escrowPub? }` (the last two owner only) |
| `GET /api/private/drive/nodes/<id>` | the node and its children: `{ node, children: [...], path: [...ancestors] }` (`root` for the top) |
| `POST /api/private/drive/folders` | `{ parent, name }` → `{ id }` |
| `POST /api/private/drive/files` | `{ parent, name, meta, size, fk }` → `{ id, uploadToken, chunks }` (capacity checked) |
| `PUT /api/private/drive/files/<id>/chunk/<i>` | `application/octet-stream`, header `X-Upload-Token`; exact size check |
| `POST /api/private/drive/files/<id>/finalize` | header `X-Upload-Token` → `{ ok }` |
| `GET /api/private/drive/files/<id>/chunk/<i>` | ciphertext chunk for the user |
| `PATCH /api/private/drive/nodes/<id>` | `{ parent?, name? }` move / rename |
| `DELETE /api/private/drive/nodes/<id>` | recursive; ends referencing shares; frees capacity |
| `POST /api/private/drive/shares` | `{ nodes: [ids], views, expire, deletable?, label?, paste, acc }` → `{ id, deletetoken }` |
| `GET /api/private/drive/nodes/<id>/shares` | shares referencing the node |
| `POST /api/private/admin/drive/escrow/<userId>` | owner: `{ reason }` → the user's escrow wrap and wraps list, logged `drive.escrow_used` |

## 7. Drive shares

- A drive share is a **FileShare** DO record with `refs: [{ key: 'd/<uid>/<node>', chunks, size }]`
  instead of its own uploaded stream. It is created active (no upload step). Its purge never
  touches `d/` objects. The Directory `shares` row has `kind = 'drive'`.
- The share's encrypted paste (the manifest, sealed with the share's own link key and optional
  password, exactly as for file shares) is **manifest v3**:
  `{ v: 3, kind: 'refs', entries: [{ path, size, type, mtime, ref, fk }], dirs: [...] }` where
  `ref` indexes `refs` and `fk` is that file's key (base64url). Folders are flattened to paths.
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

## 9. Security notes

- Owner escrow means the owner can decrypt every user's Drive: this is a deliberate choice by
  the maintainer, logged on every use, and needs Legal / Compliance review before production.
- DK in `sessionStorage` is readable by script on the origin; the CSP and Trusted Types are what
  keep other script out, as for the rest of the app.
- Capacity, sizes and chunk counts are enforced server-side; names and types are not (they are
  encrypted), so file-type rules for drive shares are enforced by the client, as for file shares.
