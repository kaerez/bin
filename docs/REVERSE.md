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
  values below can be bound to it. The server claims the id in the share index before anything
  else (§6.1): an id that any account already holds is refused (`409 exists`), and an index row
  never moves to another account. An id that was ever a reverse share stays refused for good,
  also after its index row is pruned or its account deleted: the Directory keeps
  `SHA-256("secbin/reverse-id\0" ‖ id)` of every reverse share it activates (`reverse_ids`,
  nothing else), so an old link never opens a later share.
- **Private key:** PKCS#8, sealed with DK's **`files`** sub-key (docs/DRIVE.md §3) as a sealed
  field `{ iv, ct }` with field `reversePriv` and node id `<id>` (AAD
  `secbin-drive/v1\nreversePriv\n<id>\n`). Only the user's unlocked Drive opens it. The user's
  browser rebuilds the link from it (the public point is part of the private key), so the link
  can be shown again later.
- **Link proof:** `HKDF(ikm = pub, salt = "", info = "secbin-reverse/v1 link-proof")`; the server
  stores only `lh = b64url(SHA-256(proof))`, sent by the uploader in `X-Link-Proof`. The id alone
  opens nothing and does not reveal the note or whether a password is set, but the status codes do
  tell a reverse-share id from an unknown one: an unknown id gets `404`, a reverse share `400
  missing_proof` (open / begin without a proof), `403 bad_grant` (the other routes), `423` when
  locked or `410` when ended. Ids are 128-bit random and every `404` counts in the Guard, so this
  does not help to find ids.
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
- **The user's side:** when the Drive is unlocked, the browser lists the received items (page by
  page, `next`), opens each reverse share's private key with DK, unwraps `fk ‖ mk`, opens the path
  and metadata, creates (or reuses, by name) the upload's folders under the target folder (a file
  whose name the folder already has becomes "name (2).ext", as for the user's own uploads), and
  **re-wraps** the file into the normal Drive format — `name` (the leaf name) and `meta` under
  DK's `names` key, `fk` under DK's `files` key, all bound to the node id — then `POST`s it (§6).
  From then on it is an ordinary Drive file; the content chunks are never re-encrypted.
  - **Names** are cleaned, not refused (`files.js` `cleanName`, shared with the Drive and file
    shares): the bidi overrides, embeddings and isolates (U+202A–U+202E, U+2066–U+2069), U+200B,
    U+FEFF, U+0085, U+2028 and U+2029 are removed, then NFC. Hebrew, Arabic and other scripts,
    ZWNJ / ZWJ and LRM / RLM / ALM stay as they are. A file whose name changed gets
    `renamed: true` in its sealed metadata, and the Drive shows it as renamed. Names are displayed
    in a bidi isolate with the extension as its own left-to-right isolate (`common.js` `nameEl`).
  - **Folders:** a path creates at most **8** folder levels below the link's folder (and never
    more than the Drive's 64 levels in all), and one take-in creates at most **200** new folders;
    past either, the file goes into the deepest of its folders that is allowed or exists. The
    browser does this on its own at every unlock, so it flattens rather than asks: a confirmation
    would interrupt every unlock, put names an anonymous uploader chose in front of the user, and
    hold the items behind it; flattening never drops a file, only folder levels, and bounds the
    folders an uploader can make the user's browser create.
  - **Failures:** an item that cannot be taken in (it does not open with the link's key, its name
    or path cannot be used, or the Drive refuses its place) is recorded on the server
    (`POST …/received/<id>/failed`, with a reason). It leaves the queue, so it never holds up the
    items behind it, and the Drive lists it ("Review them": the link's label, size, time and why)
    with **Delete** and **Try again**. A network or server error leaves the item for the next
    unlock.

## 4. Storage (server)

- **Directory:** the `shares` row (`kind = 'reverse'`, the user, label, created, expires, status,
  lock, `lh`) maps the id to its user; it is what My shares and Admin → Shares list.
- **The user's Drive DO** (docs/DRIVE.md §4), new tables and one column:
  - `reverse(id, folder, priv, lh, ph, salt, t, note, opts, files, bytes, created, expires,
    status, ended)`: `opts` is JSON `{ maxFiles, maxBytes, maxFileBytes, types }`; `files` /
    `bytes` count reserved uploads (a purged or cancelled upload gives its share back).
  - `rsessions(hash, rid, expires, files, bytes)`: upload sessions; `hash` = SHA-256 of the
    session grant (256 bits); `files` / `bytes` = finalized in the session, not yet logged.
  - `nodes.rs`: the reverse share of a **received** file that the user's browser has not yet
    re-wrapped. Received files are left out of folder listings, shares and moves until then.
  - `nodes.rsess`: the session that reserved a received file, until it is finalized (its
    chunks keep that session open); only that session may finalize or cancel it.
  - `nodes.rfail` / `nodes.rwhy`: when and why the user's browser could not take it in
    (`unreadable`, `name`, `place`).
  - `reverse.sealed`: the sealed paths, metadata and wraps received (they count towards the
    link's byte limit); `reverse.pwfails`, `pwsince`, `pwlock`: wrong passwords in the current
    window and the lock after too many.
  - `rsessions.net`: 24 bits of SHA-256 over the link id and the uploader's network (the Guard's
    key, an IPv4 address or an IPv6 prefix), for the per-network session cap; no key is involved
    and the address is not stored (about 256 IPv4 addresses share each value);
    `rsessions.started`: when the session began.
- Received files are ordinary `nodes` rows (kind `file`, parent = the target folder), R2 objects
  under `d/<userId>/<nodeId>/<i>`, counted in the Drive's capacity from the moment they are
  reserved. Until it is re-wrapped, a received file also counts its sealed path, metadata and
  wrap (the uploader chose them: at most 1400 + 1024 characters and the fixed-size wrap), so an
  uploader cannot store data outside the capacity; once re-wrapped (name ≤ 512, meta ≤ 1024,
  fk ≤ 128 characters) it counts like any Drive file. Upload tokens are stored hashed (`upload_hash`), and a pending upload with no chunk for
  the role's `filePendingSec` is purged by the Drive's alarm, as for the user's own uploads.
- A session with no unfinished file lapses **10 minutes** after its last activity; while it has a
  file reserved and not finished it lasts the role's `filePendingSec` from its last activity (the
  file reserved, a chunk of it), never past the share's expiry and never more than **24 hours**
  after it began. The deadline slides both ways: once nothing is unfinished (its last file
  finished or was cancelled) the session is idle again and lapses 10 minutes later, giving its
  per-network slot back. A reserved file must be finished within 24 hours of its reservation, however
  often its chunks are re-sent; the alarm purges it after that and gives its reservation back.
- Hard ceilings: 1 000 reverse shares per Drive (an ended one is dropped 30 days after it ended —
  as long as the share index keeps its row — once all its received files are re-wrapped or
  deleted), **5 open sessions per uploader network** and 100 per reverse share, 10 000 files
  per reverse share.

## 5. Options and role options

- **Per reverse share** (chosen by the user): expiry (the role's `maxExpireSec` applies, at most
  365 days); maximum number of files (`maxFiles`, 1–10 000 or none); maximum total bytes
  (`maxBytes`: each file's content plus its sealed path, metadata and wrap, about 2.5 KB, so empty
  files count too); maximum file size (`maxFileBytes`); allowed file types (`types: { mode: 'allow' |
  'block', rules }`, the file-policy rules of `public/js/filepolicy.js`); a label (plain text, for
  the user's own lists); an optional note to the uploader (encrypted, §3); an optional password.
- **Role options** (Admin → Roles, Drive section; `LIMITS` in `src/lib/settings.js`):
  `reverseEnabled` (bool, default **false**; also needs `driveEnabled`), `reverseMaxActive`
  (active reverse shares at once, default 10, null = no limit up to 1 000), `reverseMaxBytes`
  (maximum total bytes per reverse share, default 1 GiB, null = no limit; a share's `maxBytes`
  may not exceed it and defaults to it; lowering it applies to existing shares at once: each is
  held to the smaller of its own `maxBytes` and the role's current value, and `open` reports that
  value). The owner: allowed, no limits. The public account: none.
- **Always:** the user's Drive capacity (`driveMaxBytes`) and largest file (`driveMaxFileBytes`),
  and the Drive's hard ceilings, apply to every upload.
- File types are declared by the uploader's browser (`declare()`), checked by the server against
  the share's rules and refused on a mismatch, as for file shares: a modified client could lie.

## 6. API

### 6.1 The user (session only, like the Drive; `403 reverse_disabled` unless the role allows it)

| Method and path | Purpose |
|---|---|
| `POST /api/private/drive/reverse` | create: `{ id, folder, priv: {iv, ct}, lh, password?: { salt, t, ph }, note?: {iv, ct}, label?, expire, maxFiles?, maxBytes?, maxFileBytes?, types?, current? \| reauth? }` → `201 { id, expires }`. The id is claimed in the share index first, in one step with the role's checks and the count of active reverse shares (`reverseMaxActive` holds under concurrent creates): `409 exists` when any account holds the id, `409 too_many_reverse`; `409 drive_not_set_up` when the Drive has no key yet (the link's private key is sealed with it). A link adds key material to the Drive, so the user confirms it with the password proof (`current`) or a passkey (`reauth`, from `POST /api/private/me/reauth`), as for API keys: `400 reauth_required`, `403 wrong_password` / `reauth_failed` (counted as failed confirmations; the claim is released). The owner acting as the user sends neither (§6.3) |
| `GET /api/private/drive/reverse` | every reverse share of the Drive: `{ reverse: [row] }`; `?folder=<nodeId>` for one folder's |
| `GET /api/private/drive/received` | received files waiting to be re-wrapped, oldest first, 500 per page: `{ items: [{ id, parent, rs, name, meta, fk: { kind: 'rs', data }, size, chunks, created }], keys: [{ id, priv }], more, next }`; `?after=<next>` for the next page. `?failed=1`: the ones the browser could not take in instead, `{ items: [{ id, rs, label, size, created, failed, reason }], more, next }` |
| `POST /api/private/drive/received/<nodeId>` | re-wrapped: `{ parent, name, meta, fk }` (normal sealed fields; `parent` a folder) → `{ ok }`; logged as `drive.received_taken_in` (§7) |
| `POST /api/private/drive/received/<nodeId>/failed` | the browser could not take it in: `{ reason: 'unreadable' \| 'name' \| 'place' }` → `{ ok, received, failed }`; it leaves the queue. `DELETE` (with `X-Secbin-Intent`) puts it back (try again). Logged as `drive.received_failed` / `drive.received_retried` (§7) |
| `DELETE /api/private/drive/nodes/<nodeId>` | discard a received file (as any Drive item) |
| `POST /api/private/shares/<id>/revoke` | revoke (My shares); `PATCH /api/private/shares/<id>` changes the label or extends the expiry |

A row: `{ id, folder, label, created, expires, status, locked, priv, password: bool, note: bool,
maxFiles, maxBytes, maxFileBytes, types, files, bytes, pending }` (`status` as the share index
has it: `active`, `revoked`, `expired`, `ended`; `pending` = received files waiting to be
re-wrapped, `failed` = those the browser could not take in). `GET /api/private/drive` adds
`received` (waiting) and `receivedFailed`.
`GET /api/private/me` has `caps.reverseEnabled`. My shares and Admin → Shares rows of kind
`reverse` carry `received: { files, bytes }`; `PATCH /api/private/shares/<id>` accepts `label`
and a later `expires` (not `views`).

### 6.2 The uploader (anonymous; `/api/reverse/<id>/…`)

Every route refuses cross-site callers (`Sec-Fetch-Site`) before any Guard accounting; a blocked
network is refused up front; every failure a guesser produces (unknown id, wrong link proof, wrong
password, bad grant or token) counts in the Guard's `invalid` scope, like invalid fetches. POSTs
without a JSON body carry `X-Secbin-Intent: 1`.

| Method and path | Headers | Purpose |
|---|---|---|
| `POST …/open` | `X-Link-Proof` | `{ note, password: null \| { salt, t }, expires, limits: { maxFiles, maxBytes, maxFileBytes, types, filesLeft, bytesLeft } }` |
| `POST …/begin` | `X-Link-Proof`, `X-Key-Proof` (password only), `X-Secbin-Turnstile` (when configured) | a session: `{ grant, expires }`. The human check comes before the password: without a valid token no guess is answered. The password is checked in the user's Drive with a lockout per link: 10 wrong ones within 15 minutes, from any networks, lock it for 15 minutes (`429 password_locked { until }`, the right password too; `open` shows `password.lockedUntil`) |
| `POST …/files` | `X-Reverse-Grant`; JSON `{ id, name, meta, size, wrap, types? }` | reserve one file → `201 { id, uploadToken, chunks }` (limits, capacity) |
| `PUT …/files/<nodeId>/chunk/<i>` | `X-Upload-Token`; `application/octet-stream` | chunk `i`, exact size |
| `POST …/files/<nodeId>/finalize` | `X-Reverse-Grant`, `X-Upload-Token` | `{ ok }` (only the session that reserved the file: else `403 bad_grant`) |
| `DELETE …/files/<nodeId>` | `X-Reverse-Grant`, `X-Upload-Token` | cancel an unfinished upload (its reservation is given back; only the session that reserved it) |
| `POST …/done` | `X-Reverse-Grant` | end the session: `{ files, bytes }` (logged) |

Errors: `404 not_found` (never a reverse share), `410 gone` (revoked, expired, its folder
deleted, or the user's role no longer allows it; a late visitor with the right link proof is not
counted by the Guard), `409 paused` (`open` / `begin` with the right link proof, while the
owner's Drive is started over and the link's key is in the archive: §9), `423 share_locked` (the
admin locked it),
`403 bad_link`, `401 password_required` (the password is needed; `{ salt, t }` in the body),
`403 bad_password`, `403 bad_grant`, `403 bad_token`, `403 turnstile_*`, `413 file_too_large` /
`share_full` / `drive_full`, `409 too_many_files` (none left: `open` shows `filesLeft: 0`),
`400 declaration_required` / `403 file_type_not_allowed`, `429 busy` (too many open sessions from
this network, or on the link), `429 password_locked`, `429 blocked`.

### 6.3 The owner acting as the user ("Log in as")

By the maintainer's rule, the owner impersonating a user can do everything the user can with
reverse shares: create (without a confirmation, as for every other change to the account), list
them with their sealed keys, take in received files, extend and revoke. In the Drive page this
works exactly as for the user once the impersonating tab holds the user's Drive key (docs/DRIVE.md
§3). The user's own activity shows these actions as theirs (`share.created`,
`drive.received_taken_in`, `drive.received_failed`, `drive.received_retried`, `share.revoked`,
no actor); the owner-only admin audit keeps the real
actor (`imp = 1`, not `adm`), exactly as for the Drive actions taken while impersonating
(docs/DRIVE.md §9).

The server cannot tell whether a new link's `priv` is sealed with the user's Drive key. So the
owner acting as the user (or anyone holding that impersonation session) can also create, through
the API, a link in the user's name whose private key they keep: files sent to it are encrypted to
that key and can be read by whoever holds it, without owner escrow and without the user's Drive
key. The user's browser cannot open that link's private key: the Drive shows no link for it, and
its received files are listed as failed (they do not open). The creation is in the admin audit
with the real actor.

## 7. Audit log

In the user's activity log (and the admin's audit): `share.created` (`kind=reverse`) and
`share.revoked` as for every share; `reverse.received` (`id`, `files`, `bytes`: count and size
only), for the sessions that end (`done`) or lapse with unlogged uploads — **one entry per link
per hour**, which adds up the files and bytes of every session in that hour, so anonymous uploads
cannot push other entries out of the log; `reverse.bad_password` (`id`; at most one entry per
share per minute); the Drive actions on received files, `drive.received_taken_in` (taken into
the Drive), `drive.received_failed` (could not be taken in) and `drive.received_retried` (put
back to try again), each with the link's `id` and `files`, logged like the other Drive actions
(docs/DRIVE.md §9: the user's own, or the owner's while acting as the user with `imp = 1`) —
**one entry per link, per actor, per hour**, adding up the files, since the uploaders decide how
many files arrive.

## 8. UI

- **Drive → Receive files…** (toolbar; the selected folder, else the open one): a dialog with the
  options of §5 and the account password (or, left empty, a passkey when the account has one;
  hidden while the owner acts as the user), then the link with copy and a QR code, and the folder's reverse shares (label,
  created, expiry, files and bytes received, status) with Show link and Revoke.
- The unlock prompt says how many received files are waiting; once unlocked the browser
  re-wraps them (a status line: added, renamed, placed higher up, and the ones that could not be
  added with **Review them**, a dialog to delete them or try again; then the folder shows them).
- **Uploader page** `/r/<id>#<key>` (`public/r/index.html`, `public/js/reverse.js`): the note,
  the limits, a password field when needed, the human check (Turnstile, always visible when
  configured; the upload button stays disabled until it passes: `humanCheck` of
  `public/js/turnstile.js`), a file picker, a folder picker, drag and drop of files and folders,
  and progress. DOM only through `h()`; the page gets the Turnstile CSP when Turnstile is on and
  the strict one otherwise, and is never cached by the service worker. With Turnstile on,
  Cloudflare's script runs on this page and could read `location.hash`, which holds the link key
  (enough to read the note and to upload to the link, not to read anything received), and the
  files being sent before they are encrypted — the same trade-off as on the other pages that load
  it (SECURITY.md, *Cloudflare Turnstile*).
- My shares / Admin → Shares: kind "receive" (filter value `reverse`); the views column shows the
  files received; revoke, lock and extend (expiry only) as for other shares.
- Empty folders in an upload are not sent (only files are received; their paths make the folders).

## 9. The owner starting over (docs/DRIVE.md §3.2)

- The owner's links' private keys are sealed under the owner's DK. When the owner starts over
  without a recovery kit, the old DK goes into the archive with the rest of the Drive, so every
  link of the owner's Drive is tied to that archive (`reverse.agen = gen`; a link an earlier
  archive already holds stays with it) and the active ones are **paused** (`status = 'paused'`):
  - `open` and `begin` answer `409 paused` once the link proof matches (no session, no human
    check, no password check); the uploader page shows "This link is not accepting files right
    now"; any other uploader route answers as for an ended session (`403 bad_grant`, counted);
  - the links' open sessions end at once (what they received is logged as `reverse.received`),
    and their unfinished uploads are deleted, giving their allowance back;
  - the items they received stay in the archive (`archive_nodes`, with `rs`, `rfail`, `rwhy`)
    exactly as they arrived, sealed to the link's key; they are not offered for taking in;
  - the share index keeps the link `active` (My shares shows it as paused); it can still be
    revoked or extended; it is never dropped while its archive exists.
- **Restore** (a kit for the old DK, "Restore from kit"): the archive's received items come back
  as they are (`PUT …/archive/<gen>/nodes` with `{ id }` only; any sealed field for them is
  refused, `400 received_as_is`), and `POST …/archive/<gen>/finish` carries every link's private
  key re-sealed by the browser from the kit's DK to the Drive's DK now (`reverse`; one per link
  of the archive, `409 reverse_keys_required` otherwise). The links leave the archive and the
  paused ones resume; their kept items are taken in like any received file at the next unlock.
  Until finish, a restored received item whose link is still tied to the archive is neither
  listed nor accepted (`409 not_received`).
- **Delete the old Drive archive**: its paused links are revoked (the share index too) and the
  items they received are deleted with the archive (R2 included).
- Logged, one entry per link, the owner as the actor (the owner's activity and the admin
  audit): `reverse.paused`, `reverse.resumed`, `reverse.revoked` (`reason=archive_deleted`).
- No other user's link, session or received item is touched by any of this.

