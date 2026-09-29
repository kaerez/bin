# Reverse shares ("Receive"): design and interface contract

Status: the contract reverse shares are built against (task #24). It builds on the Drive
([`DRIVE.md`](./DRIVE.md)); a change to anything here is a coordinated change: update it first.

## 1. What it is

- A **user** whose role allows it creates a **reverse share** on one of their Drive folders: a
  link (`/r/<id>#<key>`) that lets anyone, with no account, send them files and folders — and,
  as the user chooses per link, a **note**, a **link** or a **credential**, the types regular
  shares carry (§3.1).
- Uploads land in the chosen Drive folder. The user sees them there like any other file, the next
  time their Drive page opens (it takes them in).
- An optional **password** gates the anonymous uploader only. It never protects the data (always
  encrypted to the link's key) and the user never needs it.
- An upload is encrypted in the uploader's browser to the link's key, until the user's browser
  takes it into the Drive; from then on it is a Drive file, sealed under the user's KEK. It is
  **not end-to-end against the server** at any point: the link's private key is sealed under
  the user's KEK, which the server derives (docs/DRIVE.md §2), so the server can open an upload
  before it is taken in too. A copy of R2 or of the Drive object alone cannot.
- Revoking, expiring or using up a reverse share stops uploads; files already received stay in the
  Drive. Deleting the folder ends its reverse shares. Where the role allows it, a link can have
  **no expiry** (it takes files until it is revoked, its views run out or its folder is deleted)
  and a **views** limit (§5); the user can change a link after making it (§6.1), move it to
  another folder of their Drive, and pause and resume it.
- Reverse shares are listed in My shares and Admin → Shares with `kind = 'reverse'`, and in the
  Drive's "Receive…" dialog of the folder.
- Terminology: the person who owns the Drive is the **user**; "owner" means the admin.

## 2. What the server sees

- Visible: the reverse share's id, folder id, label, limits, times, status, counters (files and
  bytes received), what it accepts (files, notes, links, credentials: §3.1), each received file's
  ciphertext size and chunk count, the uploader's network address (as for every request, for the
  Guard), and whether a password is set.
- **Receipts:** each upload session granted (a view, §5) is recorded for the user as a share's
  opening is for its sender (SECURITY.md, *Read receipts*): the time, and what the uploader's
  request itself revealed — the network address, Cloudflare's coarse location, the browser and
  system, the languages — kept in the Directory's `opens` with the same throttles, limits,
  retention and clearing as every read receipt; the user sees the time and only the details the
  owner lets the account see, the owner everything. The uploader page says so.
- The **kind of each send** (files, a note, a link or a credential), as the uploader's browser
  declares it when the session starts: the server checks it against the link and the user's role
  and counts it in the quotas, and keeps it with the session (`rsessions.kind`) until the session
  ends. Each item it reserves keeps that declared kind too, sealed at rest with the item's wrap
  (the field layer; never in plain text), until the user's browser takes it in (§3). Where the
  owner set a quota of a kind per kind of send (`receive-note`, `receive-url`, `receive-secret`,
  `receive-file`), the Directory keeps **counts only** — how many sessions of that kind the user
  received in each quota window, no content, no link or sender — each count row until 400 days
  after its window's first count (the same pruning as every quota; a window longer than that
  starts again from zero). A received item itself carries no plaintext kind: a note, link or
  credential is stored like a received file, and what it is stays inside the metadata the
  uploader seals to the link's key. The size of an item's ciphertext is visible, as for every
  file.
- Never sent in plain text: file contents, names, types, folder structure of an upload, a received
  note's text, format and title, a received link, a received credential, the note
  to the uploader, the link key (the public key, only in the URL fragment), the password, the
  reverse share's private key, any file key. The server can still open them (all but the
  password itself, which it can only test guesses against): the link's private key is sealed
  under the user's KEK, which the server derives (§1, §3).

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
- **Private key:** PKCS#8, sealed under `HKDF(KEK of the current sub-MEK, "",
  "secbin-reverse-link/v1")` as `{ iv, ct }` with AAD
  `"secbin-reverse-link/v1\n<userId>\n<mekId>\n<id>"` (docs/DRIVE.md §3), sent with `mek`; the
  Worker checks it opens under the current KEK and stores it at rest under the user's field key
  (field `linkKey`). The user's session gets it back without the field layer and opens it with
  the KEK; the user's browser rebuilds the link from it (the public point is part of the private
  key), so the link can be shown again later. The server re-seals it on its own with the rest of
  the Drive (a sub-MEK re-seal, a root change).
- **Link proof:** `HKDF(ikm = pub, salt = "", info = "secbin-reverse/v1 link-proof")`; the server
  stores only `lh = b64url(SHA-256(proof))`, sent by the uploader in `X-Link-Proof`. The id alone
  opens nothing and does not reveal the note or whether a password is set, but the status codes do
  tell a reverse-share id from an unknown one: an unknown id gets `404`, a reverse share `400
  missing_proof` (open / begin without a proof), `403 bad_grant` (the other routes), `423` when
  locked or `410` when ended. Ids are 128-bit random and every `404` counts in the Guard, so this
  does not help to find ids.
- **Note to the uploader** (optional, ≤ 1000 characters): AES-256-GCM under
  `HKDF(pub, "", "secbin-reverse/v1 note")`, AAD `secbin-reverse/v1\nnote\n<id>\n`, stored as
  `{ iv, ct }`. Link holders can read it, and so can the server (it can unseal the link's key):
  like the Drive, it is not end-to-end.
- **Password** (optional; added, changed or removed later from the user's browser, which
  rebuilds `pub` from the link's private key): the user's browser picks a 16-byte `salt` and Argon2id cost `t`
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
  - `meta` = AES-GCM(`mk`, JSON `{ type, mtime, size }` — for a note, link or credential also
    its kind marker, §3.1), AAD `secbin-reverse/v1\nmeta\n<nodeId>\n`;
  - the **wrap** of `fk ‖ mk` to the link public key: an ephemeral ECDH P-256 key pair,
    `shared = ECDH(ephemeral, pub)`, `kek = HKDF(shared, salt = epk, info = "secbin-reverse/v1
    kek")`, AES-GCM over the 64 bytes with AAD `secbin-reverse/v1\nwrap\n<id>\n<nodeId>\n`;
    `data = "1.<epk>.<iv>.<ct>"`. It is stored in the node's `fk` field in a new form:
    `{ kind: 'rs', data }` (a normal Drive file's `fk` is `{ iv, ct }`).
- **The user's side:** when the Drive page opens, the browser lists the received items (page by
  page, `next`; the Worker takes the field layer off), opens each reverse share's private key with
  the KEK, unwraps `fk ‖ mk`, opens the path
  and metadata, creates (or reuses, by name) the upload's folders under the target folder (a file
  whose name the folder already has becomes "name (2).ext", as for the user's own uploads), and
  **takes it in**: `name` (the leaf name), `meta` and `fk` (now the file's DEK) sealed under the
  current KEK with a new per-item salt, exactly like a new Drive file — then `POST`s it (§6; the
  Worker checks the seals). From then on it is an ordinary Drive file; the content chunks are
  never re-encrypted.
  - **Names** are cleaned, not refused (`files.js` `cleanName`, shared with the Drive and file
    shares): the bidi overrides, embeddings and isolates (U+202A–U+202E, U+2066–U+2069), U+200B,
    U+FEFF, U+0085, U+2028 and U+2029 are removed, then NFC. Hebrew, Arabic and other scripts,
    ZWNJ / ZWJ and LRM / RLM / ALM stay as they are. A file whose name changed gets
    `renamed: true` in its sealed metadata, and the Drive shows it as renamed. Names are displayed
    in a bidi isolate with the extension as its own left-to-right isolate (`common.js` `nameEl`).
  - **Folders:** a path creates at most **8** folder levels below the link's folder (and never
    more than the Drive's 64 levels in all), and one take-in creates at most **200** new folders;
    past either, the file goes into the deepest of its folders that is allowed or exists. The
    browser does this on its own every time the Drive opens, so it flattens rather than asks: a confirmation
    would interrupt every opening, put names an anonymous uploader chose in front of the user, and
    hold the items behind it; flattening never drops a file, only folder levels, and bounds the
    folders an uploader can make the user's browser create.
  - **The link's rules, on what really arrived:** the uploader's browser declares a file's type
    and a send's kind to the server, and a modified one could lie. The user's browser, which
    opens the item, holds it to the link's rules as they are at take-in (the server lists them with
    each link's key, `accept` already narrowed to what the user's role allows **now**): its kind
    (a file, or the sealed marker of a note, link or credential) to the kind its session declared
    (`declared`, which the server sealed with the item) and to what the link accepts (reason
    `kind`), a note, link or credential's size to its kind's cap (`size`), a file's real name and
    type to the link's file types (`type`, `filepolicy.js`), its size to the link's largest file
    (`size`). A mismatch is never
    added to the Drive: it fails as below. (A link narrowed while items wait fails those of the
    kinds it no longer accepts, and a link the role now allows no kind for accepts nothing;
    widened again, **Try again** takes them in.) The server holds the take-in to the declared kind
    too: it opens the item's wrap (sealed at rest; one stored in plain text is refused and listed
    as `unsealed`, failed as `kind`) and answers `409 kind_not_accepted` unless the declared kind
    is one the link accepts and the user's role allows now.
  - **The role's Drive rules** apply on top of the link's own type rules: the take-in declares
    the file's type (as a Drive upload does; a note, link or credential by its stored name and
    type too) and a type the role refuses in the Drive is not taken in (reason `type`); a path makes folders only down to the role's `maxFolderDepth`
    (flattened past it), and a link folder already deeper than that takes nothing in (reason
    `place`). docs/DRIVE.md §5.
  - **Failures:** an item that cannot be taken in (it does not open with the link's key, its name
    or path cannot be used, the Drive refuses its place, it breaks the link's rules, or the role's
    file types refuse it) is recorded on the server (`POST …/received/<id>/failed`, with a reason).
    It leaves the queue, so it never holds up the items behind it, and the Drive lists it ("Review
    them": the link's label, size, time and why) with **Delete** and **Try again**. A network or
    server error leaves the item for the next time the Drive opens.

### 3.1 Notes, links and credentials

`public/js/receivekinds.js` implements this section.

- **What a link accepts** (`accept`, in its limits): a non-empty set of `files`, `note`, `url`
  and `secret` (the types of regular shares: a note in plain text, Markdown or code; one link; a
  credential). Links made before this option have none stored and accept `files` only.
- **A send is one upload session of one kind.** The uploader's page offers the accepted kinds as
  tabs; `begin` declares the kind (`{ type }`; none: files, as every client before). The server
  holds a note, link or credential session to exactly **one** item of its kind's size (below);
  what the item really is the server cannot see, so the user's browser holds it to the declared
  kind and the size at take-in (§3) — a modified uploader that declares one kind and sends
  another, or a larger item, gets it refused there, never added. Its content is its plaintext:
  - a note: its text (UTF-8), at most 2 MiB (about what a regular note's ciphertext cap holds
    uncompressed, and what the text viewer shows);
  - a link: the normalized URL (`sharetypes.js` `parseShareUrl`, as a recipient reads one: any
    scheme but the forbidden ones, no user name or password in it), at most 2048 characters;
  - a credential: the regular credential's JSON `{ v: 1, title?, username?, password?, url?,
    notes?, totp? }`, at most the regular fields' limits.
  It is encrypted exactly like a file (one chunk under a fresh `fk`); its sealed path is its
  kind's name ("Note"); its sealed metadata adds the **kind marker** `{ kind: 'note' | 'url' |
  'secret', fmt? ('plaintext' | 'markdown' | 'code', a note), title? (a note, ≤ 200 characters) }`.
  The link's file types and largest file apply to files only; every item counts towards the
  link's most files and total bytes, like a file.
- **Taken in** (§3), a note, link or credential goes into the link's folder itself (never a
  sub-folder), named after a note's title or "Note from <date>", "Link from <date>",
  "Credential from <date>" (the time the server received it, in the user's time zone; "/" and "\"
  in a title become "-"), and keeps its marker (`kind`, and a note's `fmt`) in the Drive's sealed
  metadata. The Drive lists it with its kind's icon and label and opens it in the viewer of
  regular shares (`public/js/typedview.js`): a note rendered (Markdown through the safe subset,
  code highlighted, Raw), a link spelled out with its warnings and — only when the user's own URL
  rules (`urlRules`) allow it and the scheme is one a page may open — **Open** behind a
  confirmation, a credential masked with Reveal and Copy. A marker or content that does not parse
  is never rendered as a link or credential.
- Like all Drive content they are **not end-to-end**: the server holds the keys (§1). The uploader
  page says so on the credential form ("The recipient's server can decrypt this").

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
    taken in. Received files are left out of folder listings, shares and moves until then. Their
    uploader-sealed path, metadata and wrap are stored at rest under the user's field key (field
    `received`, docs/DRIVE.md §3).
  - `nodes.rsess`: the session that reserved a received file, until it is finalized (its
    chunks keep that session open); only that session may finalize or cancel it.
  - `nodes.rfail` / `nodes.rwhy`: when and why the user's browser could not take it in
    (`unreadable`, `name`, `place`).
  - `reverse.sealed`: the sealed paths, metadata and wraps received (they count towards the
    link's byte limit); `reverse.pwfails`, `pwsince`, `pwlock`: wrong passwords in the current
    window and the lock after too many.
  - `reverse.opts.accept`: what the link accepts (§3.1; none: files only, every link before);
    `rsessions.kind`: what the session sends, as declared at `begin` (a Drive-DO column; a
    session from before sends files).
  - `rsessions.net`: 24 bits of SHA-256 over the link id and the uploader's network (the Guard's
    key, an IPv4 address or an IPv6 prefix), for the per-network session cap; no key is involved
    and the address is not stored (about 256 IPv4 addresses share each value);
    `rsessions.started`: when the session began.
  - `reverse.captcha`: uploaders pass the CAPTCHA first (links made before the option existed:
    1); `rhuman(j, exp)`: the random ids of the CAPTCHA grants a session start has used, until
    they lapse (each grant starts one session).
  - `reverse.views` / `reverse.used`: the link's views (null: unlimited — every link made before
    this option) and the views used (counted for every link from then on, unlimited ones too).
  - `reverse.held`: when the user paused the link (null: not paused; §5).
  - `reverse.expires` of a link with **no expiry** is `NO_EXPIRY` (253402300799, the last second
    of 9999: `src/lib/settings.js`), in the Drive and in the share index alike, so every
    "expired?" check reads it as not expired and nothing treats it as 0; the API always shows
    `expires: null` instead. The share index's `ended` column says when a share stopped being
    active: an ended link with no expiry leaves the index 30 days after it ended (every other
    share, 30 days after its expiry, as before).
- The share index row has `captcha` too (My shares and Admin → Shares show it).
- Received files are ordinary `nodes` rows (kind `file`, parent = the target folder), R2 objects
  under `d/<userId>/<nodeId>/<i>`. A reservation is **not** charged its size: the Drive counts a
  received upload's content as its chunks arrive (`nodes.got`, the plaintext bytes of the chunks
  received; each new chunk must fit, checked again as it is recorded: `413 drive_full`), and the
  whole file once it is finished. At the reservation the whole file must fit the space left
  (`413 drive_full`), a check only. What a link's uploads in progress have reserved and not sent,
  counting each one's next chunk only (8 MiB at most), may not pass 40 MiB (`RECEIVE_HOLD_MAX`: a
  chunk for each of the 5 uploads one network may run at once): past it a reservation gets `429
  busy`. So an uploader who reserves and sends nothing cannot fill the Drive; one who sends data
  fills it only with what it sent, within the link's limits. Until it is taken in, a received file also counts its sealed path, metadata and
  wrap as stored (the uploader chose them: at most 1400 + 1024 characters and the fixed-size
  wrap, plus the field layer), so an uploader cannot store data outside the capacity; once taken
  in (name ≤ 512, meta ≤ 1024, DEK ≤ 128 characters, and its salt) it counts like any Drive file. Upload tokens are stored hashed (`upload_hash`), and a pending upload with no chunk for
  **10 minutes** (`RECEIVE_IDLE_SEC`, or the role's `filePendingSec` when shorter) is
  **released**: its chunk after that answers `410 released` (never counted by the Guard), the
  Drive's alarm purges it and gives its reservation back (`rgone.released` keeps its token for
  that answer), and its session, while it is open, may reserve the file again — the uploader page
  sends it again once. Past `RECEIVE_MAX_SEC` (24 hours) a reservation is purged whatever its
  chunks (`410 gone`).
- A session with no unfinished file lapses **10 minutes** after its last activity; while it has a
  file reserved and not finished it lasts the role's `filePendingSec` from its last activity (the
  file reserved, a chunk of it), never past the share's expiry and never more than **24 hours**
  after it began. The deadline slides both ways: once nothing is unfinished (its last file
  finished or was cancelled) the session is idle again and lapses 10 minutes later, giving its
  per-network slot back. A file released for want of data (above) leaves its session as it was:
  open until its deadline, so the uploader can reserve the file again. A reserved file must be finished within 24 hours of its reservation, however
  often its chunks are re-sent; the alarm purges it after that and gives its reservation back.
- Hard ceilings: 1 000 reverse shares per Drive (an ended one is dropped 30 days after it ended —
  as long as the share index keeps its row — once all its received files are taken in or
  deleted), **5 open sessions per uploader network** and 100 per reverse share, 10 000 files
  per reverse share, 40 MiB reserved and not sent per reverse share (above).

## 5. Options and role options

- **Per reverse share** (chosen by the user): expiry (the role's `reverseMaxExpireSec` applies, at
  most 365 days), or **none** where the role's `reverseNoExpiry` allows it; **views** (1–100 000,
  at most `reverseMaxViews`, or unlimited where `reverseAllowUnlimitedViews` allows it); maximum number of files (`maxFiles`, 1–10 000 or none); maximum total bytes
  (`maxBytes`: each file's content plus its sealed path, metadata and wrap, about 2.5 KB, so empty
  files count too); maximum file size (`maxFileBytes`); allowed file types (`types: { mode: 'allow' |
  'block', rules }`, the file-policy rules of `public/js/filepolicy.js`, for files only); what it
  accepts (`accept`, §3.1: files, notes, links, credentials, each as the role allows; files by
  default); a label (plain text, for
  the user's own lists); an optional note to the uploader (encrypted, §3); an optional password
  (as the role's `reversePassword` says).
- **Pause:** the user can pause a link (My shares, the Drive's lists, or the API) and resume it
  later. Paused, it takes no upload session: `open` and `begin` answer `409 paused` once the link
  proof matched (the uploader page says it is not accepting files right now; like a late visitor
  of an ended link, never counted by the Guard); the sessions open at that moment end (what they
  finished is logged and kept, a session that sent nothing gives its quota back) and their
  unfinished uploads are deleted, their reservations given back. What it received stays and is
  taken in as before. Pausing and resuming need no `reverseEdit` (like the label and revoking),
  only an active link that is not locked; a link paused by an owner's start over in the previous
  release (§9) cannot be resumed. Pausing tightens the link and needs nothing more; **resuming**
  reopens an upload channel the user closed, so it is a weakening change: the password proof or a
  passkey (`current` / `reauth`, as §6.1 says), refused for an API key (`403 step_up_required`,
  `weakens: ["paused"]`); the owner acting as the user confirms nothing.
- **Late requests are not guesses.** The Drive keeps, for 24 hours, the hashes of the session
  grants and upload tokens of every session or upload that ended — done, lapsed, paused, revoked,
  released, its folder deleted (the uploads in progress there too), the item deleted on its own
  (`rgone`). When the user's **account is deleted**, its Drive hands those hashes (and those of the
  sessions and uploads still open) to the Directory first, with their link ids
  (`reverse_late`, each for at most a day, at most 20 000 per account): once the account and its
  Drive are gone, a request to one of its links that carries one is answered `410` and never
  counted. An uploader whose session ended under it (a pause, a revoke) still
  sends what it had under way: a finalize, the next reservation, a chunk, `done`. Such a request,
  carrying a grant or token the link issued, is answered `409 paused` while the link is paused,
  `410` once it has ended, else `403 bad_grant`, and is never counted in the Guard; only an
  unknown or forged grant or token is (as a wrong link proof is).
- **Its folder:** the user can move a link to another folder of their own Drive (the Edit form,
  or the API): not another user's, not a deleted one, not a file or a received item, and no
  deeper than the role's `maxFolderDepth` (`403 folder_too_deep`, by the Drive's own depth rule, as
  on create; for an API key its API limit). New uploads land there, and what it received and the
  user's browser has not taken in yet (waiting, failed, or still uploading) moves with it, so it
  is taken in there: the Drive takes an item in only into its link's folder **as it is on the
  server now**, or a folder below it (a path's folders) — a browser that listed the item before
  the move is refused (`409 folder_moved`, with the folder) and leaves the item for the next
  take-in, which places it in the new folder. Not a weakening change.
- **A view** of a reverse share is one upload session granted: the link proof, the CAPTCHA (when
  the link has it) and the password (when it has one) all passed, and `begin` answered with a
  grant. Opening the page (`open`) is not a view, and a start that fails (no or a wrong link
  proof, no or a wrong password, a CAPTCHA missing or spent, a busy link) spends none. When the
  views run out, `open` and `begin` answer `410 gone` (as a used-up share); sessions already
  started keep going and may finish their uploads. The count is taken in the user's Drive
  object in one step with the session it grants, so concurrent starts never get more sessions
  than the views. A used-up link stays active (My shares: "0 left of N"): the user can raise its
  views and it takes uploads again.
- **Role options** (Admin → Roles, Drive section; `LIMITS` in `src/lib/settings.js`):
  `reverseEnabled` (bool, default **false**; also needs `driveEnabled`), `reverseMaxActive`
  (active reverse shares at once, default 10, null = no limit up to 1 000), `reverseMaxBytes`
  (maximum total bytes per reverse share, default 1 GiB, null = no limit; a share's `maxBytes`
  may not exceed it and defaults to it; lowering it applies to existing shares at once: each is
  held to the smaller of its own `maxBytes` and the role's current value, and `open` reports that
  value), `reverseCaptcha` (`allow` / `require` / `off`, default **`require`**: every link had
  the check before this option existed) and `reverseCaptchaDefault` (`on` / `off`, default
  `on`: the "Require CAPTCHA to send files" box's starting state under `allow`),
  `reverseMaxExpireSec` (the longest expiry of a link, null = up to 365 days; migration 17 gave
  every role that had a regular `maxExpireSec` the same value here, since that one held reverse
  links until then), `reverseNoExpiry` (links with no expiry, default **false**),
  `reverseMaxViews` (null = up to 100 000), `reverseAllowUnlimitedViews` (default true: every
  link was unlimited before), `reversePassword` (`allow` / `require` / `off`, default `allow`)
  with `reversePasswordDefault` (`on` / `off`, default `off`: the password box's starting state
  under `allow`), and `reverseEdit` (default true: the user may change a link after making it —
  its expiry, views, limits, CAPTCHA, password and note; the label and revoking are always
  allowed. Regular shares have no separate "extend" option, so changing expiry or views is part
  of `reverseEdit`), and what links may accept, mirroring the regular shares' `files`, `text`,
  `url` and `secret`: `reverseFiles` (files and folders, default **true**), `reverseText` (notes,
  default **true**), `reverseUrl` (links, default **false**) and `reverseSecret` (credentials,
  default **false**) — migration 18 gave the Default role these values. The server checks them
  when a link is made (every kind it accepts), when one is changed (the kinds a change adds; a
  kind the link has may stay) and at every upload — `open`, `begin` and each reservation — with
  the role as it is then: a link accepts what it was made to accept **and** its user's role still
  allows; one left with nothing takes no uploads (`410`). The expiry, views, `reverseEdit` and
  kind options can be restricted further for
  API keys (Admin → Roles, API limits), which reach reverse shares through
  `/api/private/shares` and `/api/private/receive`. The owner: allowed, no limits (CAPTCHA `allow`, box on; password
  `allow`, box off; no expiry and unlimited views allowed; editing allowed; every kind). The
  public account: none.
- **The CAPTCHA** (Cloudflare Turnstile; SECURITY.md, *CAPTCHA on shares*): per link, when the
  role allows a choice (`captcha: true|false` on create; `require` forces it on, `off` refuses
  `true` with `403 captcha_disabled`). Changed later (where `reverseEdit` allows) within the same
  mode: `require` refuses turning it off, `off` refuses turning it on. Inactive (not asked for)
  while the server has no Turnstile keys.
- **Always:** the user's Drive capacity (`driveMaxBytes`) and largest file (`driveMaxFileBytes`),
  and the Drive's hard ceilings, apply to every upload.
- File types are declared by the uploader's browser (`declare()`), checked by the server against
  the share's rules and refused on a mismatch, as for file shares: a modified client could lie.

## 6. API

### 6.1 The user (session only, like the Drive; `403 reverse_disabled` unless the role allows it)

| Method and path | Purpose |
|---|---|
| `POST /api/private/drive/reverse` | create: `{ id, folder, priv: {iv, ct}, mek, lh, password?: { salt, t, ph }, note?: {iv, ct}, label?, expire, views?, maxFiles?, maxBytes?, maxFileBytes?, types?, accept?, captcha?, current? \| reauth? }` → `201 { id, expires, views, captcha, accept }` (`expire: "never"`: no expiry, `expires: null`; `views` absent or null: unlimited; `accept` absent or null: files only; the role's options of §5 apply: `403 no_expiry_disabled`, `expiry_too_long`, `too_many_views`, `unlimited_views_disabled`, `password_required_by_role`, `password_disabled`, `receive_kind_disabled` with `kinds`; `403 folder_too_deep` with `max` when the folder is deeper than the role's `maxFolderDepth`, by the Drive's own depth rule (docs/DRIVE.md §5: a file at its folder's level), so nothing it received could be placed). The id is claimed in the share index first, in one step with the role's checks and the count of active reverse shares (`reverseMaxActive` holds under concurrent creates): `409 exists` when any account holds the id, `409 too_many_reverse`; `409 mek_not_current` / `400 bad_seal` when `priv` is not sealed under the current KEK (with `mek`, the sub-MEK it is sealed under). A link adds key material to the Drive, so the user confirms it with the password proof (`current`) or a passkey (`reauth`, from `POST /api/private/me/reauth`), as for API keys: `400 reauth_required`, `403 wrong_password` / `reauth_failed` (counted as failed confirmations; the claim is released). The owner acting as the user sends neither (§6.3) |
| `GET /api/private/drive/reverse` | every reverse share of the Drive: `{ reverse: [row] }`; `?folder=<nodeId>` for one folder's |
| `GET /api/private/drive/received` | received files waiting to be taken in, oldest first, 500 per page: `{ items: [{ id, parent, rs, name, meta, fk: { kind: 'rs', data }, size, chunks, created, declared }], keys: [{ id, priv, mek, types, maxFileBytes, accept }], more, next }` (`declared`: the kind the item's session declared, `files` for items from before; each link's rules come with its key, `accept` narrowed to what the user's role allows now: the browser holds what it opens to them, §3) (an item whose field layer does not open comes with `unreadable: true` and no fields — `unsealed: true` too when a field is stored in plain text: the browser records it as failed, `kind` for an unsealed one); `?after=<next>` for the next page. `?failed=1`: the ones the browser could not take in instead, `{ items: [{ id, rs, label, size, created, failed, reason }], more, next }` |
| `POST /api/private/drive/received/<nodeId>` | taken in: `{ parent, name, meta, dek, ks, mek, types? }` (sealed under the current KEK, checked; `parent` a folder: the link's folder as it is now, or one below it, else `409 folder_moved` with `folder` — the browser leaves the item for the next take-in; `types` and the depth as for a Drive upload, docs/DRIVE.md §5; `409 kind_not_accepted` when the kind its session declared is not one the link accepts and the role allows now, or its wrap is not sealed at rest) → `{ ok }`; logged as `drive.received_taken_in` (§7) |
| `POST /api/private/drive/received/<nodeId>/failed` | the browser could not take it in: `{ reason: 'unreadable' \| 'name' \| 'place' \| 'type' \| 'size' \| 'kind' }` → `{ ok, received, failed }`; it leaves the queue. `DELETE` (with `X-Secbin-Intent`) puts it back (try again). Logged as `drive.received_failed` / `drive.received_retried` (§7) |
| `DELETE /api/private/drive/nodes/<nodeId>` | discard a received file (as any Drive item) |
| `POST /api/private/shares/<id>/revoke` | revoke (My shares) |
| `GET /api/private/receive` · `GET …/receive/<id>` · `GET …/receive/<id>/opens` | the Receive links' API (a session, or an API key with `read`; docs/API.md): the links (`{ rows, total }`, `?q=&status=&expiry=&offset=`), one (`{ link }`) — the index and the Drive together, never its key, note or password (only whether it has them) — and its receipts (one per upload session, as a share's read receipts). `403 reverse_disabled` unless the role allows reverse shares |
| `PATCH /api/private/receive/<id>` | as `PATCH /api/private/shares/<id>` below (a session, or an API key with `manage`) |
| `POST /api/private/receive/<id>/pause` · `…/resume` | pause or resume it (`X-Secbin-Intent`; a session or an API key with `manage`) → `{ ok, paused }`; resume weakens the link: a JSON body `{ current \| reauth }` (the step-up: `400 reauth_required`, `403 wrong_password` / `reauth_failed`; none while the owner acts as the user), `403 step_up_required` for an API key; `409 not_active` (ended), `409 not_paused` (resuming a link the user did not pause), `423` (locked). Logged as `share.updated` with `paused` / `resumed` |
| `POST /api/private/receive/<id>/revoke` | revoke (as `/api/private/shares/<id>/revoke`; like it, whatever the role's reverse shares now: ending a link is always the user's to do) |
| `PATCH /api/private/shares/<id>` | change it (My shares' Edit; a session, or an API key with `manage`): `{ label?, expires? (a time, or null: none), views? (null: unlimited), maxFiles?, maxBytes?, maxFileBytes?, types?, accept?, captcha?, password? ({ salt, t, ph } or null), note? ({ iv, ct } or null), folder? }` → `{ ok, expires, views, left, used, accept, folder }`. Everything but the label needs `reverseEdit` (`403 reverse_edit_disabled`) and an active link (`409 not_active`), and each value its own option (§5). **Expiry** follows the rule of regular shares — it can only be extended (`400`) — except that any link may be made indefinite (`reverseNoExpiry`) and one with no expiry may be given one. **Views** may be raised or lowered, never below the views already used (`400`, with `used`). The password and the note are made in the user's browser from the link's key (§3), which the session's KEK opens: neither is sent in plain text, but the server, which holds the keys that open the link's key, can read the note and test guesses at the password (not end-to-end, like the uploads). A change that **weakens** the link — its password removed or changed (not added where it had none), its CAPTCHA turned off, no expiry, unlimited views, `accept` gaining files, links or credentials (each a new way for an anonymous sender to reach the user: a file of any type, a link to follow, a secret entrusted to a channel that is not end-to-end; a **note** is plain text shown inertly, less than a file carries, so adding one is not weakening, nor is removing any kind), or its own file limits loosened — `types` removed or less restrictive (the mode changed, a type added to an allow list or dropped from a block list), `maxFiles`, `maxBytes` (null: the role's `reverseMaxBytes`, compared as that) or `maxFileBytes` raised or removed (`weakens`: `types`, `maxFiles`, `maxBytes`, `maxFileBytes`); more views or a later expiry (the Extend of every share) are not — needs the password proof (`current`) or a passkey (`reauth`), as creating a link does (`400 reauth_required`, `403 wrong_password` / `reauth_failed`), and is refused for API keys (`403 step_up_required`, with `weakens`); the owner acting as the user confirms nothing. Tightening needs no confirmation. The lock is checked before anything is written; the Drive is changed first and put back if the index then refuses (a lock in between), so the two never differ. The index and the Drive change together; the index holds the CAPTCHA the uploader's `begin` checks. An undo whose old folder was deleted meanwhile keeps the link and its waiting items in the new folder (that move stands, logged `folder=<id> kept`; the answer says `kept: ["folder"]`). The owner changing a user's link directly (Admin → Shares) may change its label, expiry and views only (`403 user_only`), and a link with no expiry only where the user's role allows it. **Folder** (`folder`: a folder id of the user's own Drive, `root` its top folder): as §5 says — `404 folder_not_found` (not in the Drive: another user's, deleted, unknown, a received item), `400 not_a_folder`, `403 folder_too_deep` with `max`, `409 folder_full`; the link's waiting items move with it (`nodes.parent`, in one step with the link), and an undo (the index refused the change) moves them back. Logged as `folder=<id>` |

A row: `{ id, folder, label, created, expires (null: none), status, locked, priv, password: bool, note: bool,
captcha: bool, views (null: unlimited), used, left, maxFiles, maxBytes, maxFileBytes, types, accept, files, bytes, pending, held, uploading }` (`uploading`: its uploads in progress,
`{ files, bytes (sent so far), size (reserved), held (reserved and not sent, up to each one's next
chunk), since }`; `files` / `bytes` count them too, as reserved; `status` as the share index
has it: `active`, `revoked`, `expired`, `ended`, or `paused` while it takes no uploads — `held`:
the user paused it; `pending` = received files waiting to be taken in, `failed` = those the
browser could not take in). `GET /api/private/drive` adds
`received` (waiting) and `receivedFailed`.
`GET /api/private/me` has `caps.reverseEnabled`. My shares and Admin → Shares rows of kind
`reverse` carry `received: { files, bytes }`, `views_total` / `left` / `used` (their views), `paused` (and `held`
when the user paused it), `opens` (its receipts: upload sessions) and
`expires: null` for a link with no expiry; both lists filter with `expiry=none` (only those) or
`expiry=set`.

### 6.2 The uploader (anonymous; `/api/reverse/<id>/…`)

Every route refuses cross-site callers (`Sec-Fetch-Site`) before any Guard accounting; a blocked
network is refused up front; every failure a guesser produces (unknown id, wrong link proof, wrong
password, bad grant or token) counts in the Guard's `invalid` scope, like invalid fetches. POSTs
without a JSON body carry `X-Secbin-Intent: 1`.

| Method and path | Headers | Purpose |
|---|---|---|
| `POST …/open` | `X-Link-Proof` | `{ note, password: null \| { salt, t }, expires (null: none), captcha, accept, limits: { maxFiles, maxBytes, maxFileBytes, types, filesLeft, bytesLeft } }` (`captcha`: the link has the CAPTCHA and the server has Turnstile keys; `accept`: what it takes now — what it accepts that its user's role allows). Not a view; `410` once the views are used up, or when the role allows nothing it accepts. The views are not shown to the uploader |
| `POST …/human` | `X-Secbin-Turnstile` (action `reverse-upload`) | a CAPTCHA grant for this link: `{ grant, expires }` (10 minutes, bound to the uploader's network; `{ grant: null }` when the link needs none). Needs no link proof. A link whose views are used up (or that ended) answers `410` before any CAPTCHA check, and gets no grant |
| `POST …/begin` | `X-Link-Proof`, `X-Key-Proof` (password only), `X-Secbin-Human` (a grant) or `X-Secbin-Turnstile` (a token), when the link has the CAPTCHA; an optional JSON body `{ type: 'files' \| 'note' \| 'url' \| 'secret' }` (none: files) | a session of that kind: `{ grant, expires }` — one view (§5); a kind the link (or its user's role, now) does not take: `403 kind_not_accepted` (`kind`), before the views, the CAPTCHA and the password: with its views used up, `410` before the CAPTCHA and the password are looked at. The CAPTCHA comes before the password: without it no guess is answered (`403 captcha_required`). A grant starts one session, whatever the answer (a wrong password spends it too). The password is checked in the user's Drive with a lockout per link: 10 wrong ones within 15 minutes, from any networks, lock it for 15 minutes (`429 password_locked { until }`, the right password too; `open` shows `password.lockedUntil`) |
| `POST …/files` | `X-Reverse-Grant`; JSON `{ id, name, meta, size, wrap, types? }` | reserve one file → `201 { id, uploadToken, chunks }` (limits; the whole file must fit the Drive's space left, nothing of it is charged yet, §4; `types` for a files session only). The session's kind must still be one the link and its user's role take (`403 kind_not_accepted`); a note, link or credential session reserves one item (`409 one_item`) of at most its kind's size (`413 item_too_large`); `429 busy` when the link's uploads in progress have 40 MiB reserved and not sent (§4); `429 not_accepting` when the file could not fit the user's `drive-bytes` quota |
| `PUT …/files/<nodeId>/chunk/<i>` | `X-Upload-Token`; `application/octet-stream` | chunk `i`, exact size; counted in the Drive as it arrives (`413 drive_full` when it does not fit); `410 released` when the file had no chunk for 10 minutes (reserve it again, §4) |
| `POST …/files/<nodeId>/finalize` | `X-Reverse-Grant`, `X-Upload-Token` | `{ ok }` (only the session that reserved the file: else `403 bad_grant`); its size counts under the user's `drive-bytes` quota now (`429 not_accepting` past it: nothing counted, the file stays unfinished and the uploader cancels it) |
| `DELETE …/files/<nodeId>` | `X-Reverse-Grant`, `X-Upload-Token` | cancel an unfinished upload (its reservation is given back; only the session that reserved it) |
| `POST …/done` | `X-Reverse-Grant` | end the session: `{ files, bytes }` (logged; one that sent nothing gives its quota back) |

Errors: `404 not_found` (never a reverse share), `410 gone` (revoked, expired, its views used up,
its folder deleted, or the user's role no longer allows it; a late visitor with the right link proof is not
counted by the Guard), `409 paused` (`open` / `begin` with the right link proof, for a link an owner's start over paused
in the previous release: §9), `423 share_locked` (the
admin locked it),
`403 bad_link`, `401 password_required` (the password is needed; `{ salt, t }` in the body),
`403 bad_password`, `403 bad_grant`, `403 bad_token`, `403 captcha_required`, `403 turnstile_*`, `413 file_too_large` /
`share_full` / `drive_full`, `410 released` (a chunk of a file released for want of data: send
it again, §4), `409 too_many_files` (none left: `open` shows `filesLeft: 0`),
`400 declaration_required` / `403 file_type_not_allowed`, `429 busy` (too many open sessions from
this network, or on the link; `files`: the link's uploads in progress have 40 MiB reserved and
not sent), `429 not_accepting` (`begin`: the user's quota of upload sessions
received, kind `receive-upload` or `receive`, is reached; `files` and `finalize`: the file could
not fit, or no longer fits, the user's `drive-bytes` quota; the answer is only "This link can’t
accept more uploads right now. Try again later.", with nothing of the quota), `429 password_locked`, `429 rate_limited` (more than 30 CAPTCHA
checks from this network within 10 minutes, on `human` or a `begin` with a token; a failed token
counts as an invalid request), `429 blocked`.

**Quotas.** The user's role quotas of kind `receive-upload` and `receive` count each upload
session through the user's links, whatever it sends, and one kind per kind of send counts it too:
`receive-file` (a session that sends files), `receive-note`, `receive-url`, `receive-secret` —
for the user (never the uploader): at `begin`, before the
password is checked. A session that does not start (wrong password, busy, paused) or that ends
having sent no file — `done`, or lapsing — is given back; one that sent a file stays counted. A
new link counts under `receive-link` and `receive` (given back when its creation does not
complete). A file received is **Drive storage**: its size counts under the user's `drive-bytes`
quotas when it is finished (checked at its reservation, counted at its finalize: `429
not_accepting`, neutral, past it), never under `drive-upload` (the Receive kinds above count its
session). Taking it in counts nothing more.

### 6.3 The owner acting as the user ("Log in as")

By the maintainer's rule, the owner impersonating a user can do everything the user can with
reverse shares: create (without a confirmation, as for every other change to the account), list
them with their sealed keys, take in received files, extend and revoke. In the Drive page this
works exactly as for the user, with the user's keys the server hands the owner's session
(docs/DRIVE.md §3). The user's own activity shows these actions as theirs (`share.created`,
`drive.received_taken_in`, `drive.received_failed`, `drive.received_retried`, `share.revoked`,
no actor); the owner-only admin audit keeps the real
actor (`imp = 1`, not `adm`), exactly as for the Drive actions taken while impersonating
(docs/DRIVE.md §9).

The owner acting as the user (or anyone holding that impersonation session) can also create,
through the API, a link in the user's name whose private key they also keep: files sent to it can
be read by whoever holds that key. The creation is in the admin audit with the real actor.

## 7. Audit log

In the user's activity log (and the admin's audit): `share.created` (`kind=reverse`) and
`share.revoked` as for every share; `share.updated` for a change (the names of what changed:
`label`, `expires=…`, `views=…`, `captcha=on|off`, `password=set|removed`, `note=set|removed`,
`limits`, `accept=…`, `folder=<id>` — the folder by its node id, its name stays encrypted —,
`paused`, `resumed`; `apikey=<id>` when a key made it); `reverse.received` (`id`, `files`, `bytes`: count and size
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

- **Drive → Receive…** (toolbar; the selected folder, else the open one; disabled until the open
  folder has listed, so the dialog always names its folder): a dialog with the
  options of §5 — "What senders can send" (a box per kind the role allows, files ticked; each with
  what it means), "Accept files for", "No expiry" (shown where the role allows it), "Views" with
  ∞ (unlimited, pre-set where the role allows it), the password box (as `reversePassword` says:
  a choice pre-set from its default, ticked and disabled, or hidden) —, "Require CAPTCHA to send files" (as the role says: a choice, ticked and disabled,
  or hidden) and the account password (or, left empty, a passkey when the account has one;
  hidden while the owner acts as the user), then the link with copy and a QR code, and the folder's reverse shares (label,
  created, expiry, files and bytes received, status) with Copy link, Revoke, Edit and Pause /
  Resume. The "Received" cell also names the uploads in progress, with what they sent so far of
  the size they reserved ("uploading now: 1 file, 8.0 MB of 20 MB sent"), so the user sees what
  is using space; they are not counted as received until they finish.
- When the Drive page opens, the browser takes the received files in (a status line: added,
  renamed, placed higher up, and the ones that could not be
  added with **Review them**, a dialog to delete them or try again; then the folder shows them).
- **Uploader page** `/r/<id>#<key>` (`public/r/index.html`, `public/js/reverse.js`): the note,
  the limits, a password field when needed, and one tab per kind the link accepts (an ARIA
  tablist; none when it takes files only): **Files** — a file picker, a folder picker, drag and
  drop of files and folders; **Note** — an optional title, the format (Plain text, Markdown, Code)
  and the text; **Link** — the address, with its destination spelled out as the composer does;
  **Credential** — the regular credential fields (the password and the seed masked, with Show),
  under the warning that the recipient's server can decrypt it; and progress. It says that a send
  is recorded for the recipient and the administrator (a receipt, §2), as a share page says an
  opening is. The heading and the
  page title name what can be sent ("Send a note or files"). DOM only through `h()`; always the strict CSP (no third-party
  script, whatever the server's Turnstile keys), never cached by the service worker.
- **A link with the CAPTCHA:** the uploader page takes the key out of the address bar, removes
  the tab's Drive keys, seals the link's key alone for this tab under a random page key held in
  an HttpOnly cookie, and goes to the link's check page (`/r/<id>?check`, `public/js/check.js`,
  "Complete the CAPTCHA to send files", the Turnstile CSP); Continue there stays disabled until
  the CAPTCHA passes, gets a grant and returns to the uploader page, which opens the key again
  (SECURITY.md, *CAPTCHA on shares*). Each send uses the grant; after it, or after a wrong
  password, the page offers "Complete the CAPTCHA again" (the files are chosen again then).
- My shares / Admin → Shares: kind "receive" (filter value `reverse`); "No expiry" in the Expires
  column and an Expiry filter (any / no expiry / with an expiry); the views column shows the files
  received and the views left; the Opened column its receipts ("2 upload sessions", a table of
  when each started and the details the account may see); revoke and lock as for other shares.
  My shares has **Pause** / **Resume** for a Receive link (a "paused" badge while it is), and the
  Drive's lists have them too; Resume first asks for the account password (or, left empty, a
  passkey), never while the owner acts as the user. My shares has **Edit** for a
  Receive link (where `reverseEdit` allows it; `public/dashboard/js/reverse-edit.js`), an inline
  row like the regular shares' Extend: the expiry (keep, extend — or give one to a link with
  none —, or none), the views (raise, lower to the views used, or unlimited), the limits and
  file types, the folder it receives into ("Choose another folder…": the Drive's folder tree, the
  new folder's path announced, "Keep the current folder" to undo; a folder past the role's depth
  refused before anything is sent), the CAPTCHA, the password (keep, change or add, remove) and
  the note (keep, replace or add, remove), each as the role allows. After a move, the folders'
  Shares and Receive… lists show the link under its new folder. The password and the note are sealed in the
  browser, which opens the Drive's keys for it only when one of them changes. While the changes
  weaken the link (the password removed or changed, the CAPTCHA off, no expiry, unlimited views,
  its file types or size limits loosened)
  the form shows "Your account password (to confirm it is you)" (or a passkey), as the Receive…
  dialog does; never while the owner acts as the user. The same **Edit**
  is in the Drive, on each link of the Receive… dialog's list and of a folder's Shares dialog (the
  dialog shows the form; saving closes it). Admin → Shares changes a Receive link's views and
  expiry (or none) only.
- Empty folders in an upload are not sent (only files are received; their paths make the folders).
- My shares' and the Drive's **Edit** shows "What senders can send" too; a kind the role no longer
  allows can only be turned off. Adding files, links or credentials shows the account password
  field (the step-up), adding a note does not.
- **The Drive** lists a received note, link or credential with its icon and label ("Note",
  "Link", "Credential"); its name opens it in its viewer (§3.1). Rename, move, delete and Share…
  work as for files. **Download** saves text: a note as `.md` (Markdown) or `.txt`, a link as
  `.txt` holding the URL (never a `.url` Internet Shortcut: the shell follows a shortcut's target,
  and a link may name any scheme), a credential as a plain-text export that says at its top what
  it holds — after a confirmation. A folder's ZIP holds notes and links as stored (`.md` /
  `.txt`) and leaves credentials out (the page says how many). An item larger than its kind's
  cap is never shown in a viewer (Download only).
  **Share…** carries them as what they are: the Drive share's manifest marks each entry with its
  kind (`item: { kind, fmt? }`, docs/DRIVE.md §7) and the recipient's page opens it in the same
  viewers (the sender's URL rules unknown there, as for a regular link share); the user's browser
  shares a link or a credential only where the account may share links or credentials (`url`,
  `secret`, `text`: the server cannot see what an item is). The server records on the Drive share
  what the sender's role allowed when it was made (`kinds: { note, url, secret }`, returned by
  `open`), and the recipient's page opens an entry as a note, link or credential only where that
  allows it (otherwise the entry is a plain file there: Download only, no Open, no card), and
  never past its kind's size. A credential's Download there asks first, as in the Drive; **ZIPs
  never include credentials** (a Drive folder's, a Drive share's "Download all" or folder): each
  leaves in plain text only on its own, after its confirmation, and the page says how many were
  left out.

## 9. Links of the previous release

- A link made before the Drive key model v2 has its private key sealed under the old Drive key
  (`reverse.mek` is null). The Drive's upgrade (docs/DRIVE.md §3.3) re-seals it under the user's
  KEK in the browser that opens the old key, and the server checks it and stores it at rest under
  the field layer; until then the Drive shows no link for it, and its received files wait (they
  are not marked as failed).
- A link an owner's start over paused in the previous release stays paused (`open` and `begin`
  answer `409 paused`; the uploader page says it is not accepting files right now), with its
  received items kept in that archive as they arrived; nothing opens or restores the archive any
  more. It can still be revoked; revoking it ends it as any link.
