# Changelog

All notable changes to secbin are documented here. The format follows [Keep a Changelog], and
the project adheres to [Semantic Versioning]. The paste format is versioned separately from the
application (see [`SPEC.md`](./SPEC.md), currently **v2**).

secbin is maintained by KSEC - Erez Kalman at <https://github.com/kaerez/bin> and is based on
[binthere](https://github.com/nxfu/binthere) by nxfu. The upstream history is kept below the
secbin entries.

## [Unreleased] — secbin 2.0.0

**Breaking:** protocol v2. Links created by earlier versions (v1, `binthere/v1` labels) can no
longer be opened, and the v1 anonymous endpoint (`POST /api/paste`) is gone (`410`).

### Security

- **Security audit W3, part A (authentication and authorization).**
  - **A looser role needs the owner's step-up.** Giving a user a role that is looser for them
    (any role option, on either channel, or the quota list they are counted against) and deleting
    a role whose users would fall back to a looser Default role now need the owner's password or
    a passkey (`400 reauth_required` with what loosens; in the `DELETE`'s JSON body for a
    deletion). A tighter or equal role needs nothing.
  - **Quota changes that loosen need it too:** a quota removed, raised or given a shorter period,
    for the Default role, a custom role or the public account, and a role switching between its
    own quota list and Default's when the other list allows more.
  - **Per-network limits before the Directory** for anonymous calls that reached it unlimited:
    refused API keys (`api-key`: 600 per 10 minutes, counted only on a refusal; past that the
    network's API-key requests are refused before the lookup), usernameless passkey challenges
    (`passkey-options`: 600 per 10 minutes, every request) and passkey sign-ins or second steps
    with a made-up, expired or used challenge (`auth-challenge`: 120 per 10 minutes). `429
    rate_limited` with `Retry-After`; the owner sees and lifts them in Admin → Security.
  - **Lifting a control needs the step-up:** removing a block rule, lifting a Guard block or
    clearing a network's count, unlocking a locked account, and unblocking or forgetting an
    anonymous browser id (as adding an allow rule already did). Placing a block needs nothing.
  - **More options count as weakening:** `reverseEnabled`, `driveEnabled`, `text`,
    `reverseText`, `viewer` and the read-receipt details (`receiptIp`, `receiptLocation`,
    `receiptBrowser`, `receiptOs`, `receiptLanguages`) turned on; a higher or removed
    `apiMaxKeys` and `reverseMaxActive`; a higher `passkeysMax`; a longer `fileGrantSec` and
    `files.grantSec`; `public.tracking` towards both-permissive; `public.notice` off or its text
    emptied; a longer `public.trackerIdleSec`. Every setting and role option is now classified,
    with the reason for those that are not (`NOT_WEAKENING_SETTINGS`, `NOT_WEAKENING_LIMITS`),
    and a test fails for an option added without one.
  - **The sign-in limit is checked and counted at once:** each password, passkey, recovery-code
    or second-step sign-in (and each set-up token) is counted against the network in the same
    Guard call that checks its block, before the Directory is asked, and given back when it did
    not fail. Concurrent wrong passwords from one network can no longer get more than
    `guard.login.max` evaluated per window.
  - **Failed sign-ins and failed step-ups are logged:** `login.failed` (wrong password, passkey,
    recovery code or second step; the owner's included) and `stepup.failed`, added up per
    account and action per hour (how many, how, when the last was and, for a sign-in, from which
    address), sealed like the other sign-in records. An unknown username is recorded under a
    keyed hash only, with the same refusal as a real one; past 100 such entries an hour they
    share one. They follow the log's retention (the owner's entries the owner's limits).
    Directory migration 20 rebuilds the index of unsealed sign-in rows for the two actions.
  - **Credential resets revoke API keys:** an admin password reset and an owner recovery revoke
    the account's API keys (passkeys and recovery codes are kept on a reset). A user's own
    password change offers "Also revoke my API keys", ticked by default (`revokeKeys`).
  - **A password change keeps the session's absolute end**, as impersonation does.
  - **An import refuses a custom role named "Public"** (any case, trimmed) and a user's role
    "Public", as the admin panel does.

- **Share passwords have a per-share lockout** (security audit W3, B-1). Wrong passwords were
  limited only per network, so guesses spread over many networks (the /64s of one IPv6 /48, for
  example) were never refused. Now each share counts its wrong passwords from any network:
  `share.pwMaxFails` (default 20) within `share.pwWindowSec` (default 15 minutes) lock its
  password for `share.pwLockSec` (default 15 minutes), twice as long on each lock after the
  first (up to 64 times, at most 30 days); the right password, once accepted, clears the count.
  While it is locked every attempt, on `open` and on "delete now", is refused before its password
  is checked, the right one too: `429 password_locked` with `until` and "Too many wrong passwords
  for this share. Try again at …". The wrong password that locks it answers `403 bad_password`
  with `until`. Each lock is in the share user's activity (`share.password_locked`: the share,
  until when, which lock). Every kind is covered (notes, view-limited notes, file shares, Drive
  shares; the count lives with the proof check, atomically), shares without a password are not
  counted, and the three values are owner settings (Admin → Settings → Share password lockout;
  loosening them needs the step-up). Attempts on a locked share are never invalid fetches, since
  the right password may be among them, and have a per-network limit of their own
  (`password-locked`: 120 per 10 minutes, then `429 rate_limited`). Invalid requests from IPv6 are
  also counted per /48 (`invalid-wide`: 16 times `guard.invalid.max` in the same window), next to
  the /64. The right key for a share that has ended, and the right password, are still never
  counted.
- **"Delete now" on a made-up id is counted** (B-2): `POST /api/(paste|file)/<id>/expire` for an
  id that was never a share answers the same counted `410 gone` as the other routes (it answered
  `403 not_allowed`, uncounted). Ids that were shares are not counted with their right key.
- **The chunk route no longer tells a share's layout** (B-3): the download grant is checked before
  the index, so without a valid grant every chunk request (file shares, and each file of a Drive
  share) gets the same counted `403 bad_grant`; an out-of-range index is `404` only with a valid
  grant.
- **The note renderers run in linear time** (B-4): the Markdown link pattern retried from every
  `[` to the end of the paragraph, so a note of 300 000 `[` froze the recipient's tab for about
  35 seconds. Links are now found by a linear scan that gives the same result, and the code
  highlighter's heuristic (long words) and tokenizer (unclosed strings with escapes, unclosed
  block comments) had the same issue and no longer do. The rendering of normal notes is
  unchanged.
- **`GET /api/public/t` has a per-network limit** (B-5): at most 600 calls per 10 minutes
  (`tracker-fetch`, then `429 rate_limited`), since every call reaches the Directory.
- **`secbin get` escapes terminal control characters in notes** (B-7): printed to a terminal,
  plain, Markdown and code notes have their C0 and C1 control characters, ESC and DEL escaped
  (`\u001b`), newlines and tabs kept (a CRLF line end is shown as a newline), so a note cannot
  write the clipboard (OSC 52), retitle the window or redraw the screen. `--raw` prints the exact
  text; a pipe and `--out` always get it.
- **A Receive link can no longer fill the Drive without sending data** (security audit W3,
  C-2). A reservation counted its whole size in the user's Drive at once, and lasted the role's
  `filePendingSec` (a day with a chunk now and then), so anyone holding a link could reserve the
  space left, send nothing, and have every upload of the user's refused (`413 drive_full`),
  with nothing showing why. Now a received upload counts in the Drive only as its chunks arrive
  (each must fit: `413 drive_full`), with its sealed fields from the reservation, where the whole
  file must merely fit the space left; what a link's uploads in progress have reserved and not
  sent, counting each one's next chunk, may not pass 40 MiB (a chunk for each of the 5 uploads a
  network may run; `429 busy`); a reservation with no chunk started for 10 minutes is released
  (the start of each chunk request is stored before its body is read, so a slow sender's chunk
  still arriving never is). Its late chunks get `410 released`, never counted as guesses; the
  session may reserve it again, and the uploader page sends the file again once. The Drive's Receive… list and the Receive API
  (`uploading`) show each link's uploads in progress with what they sent so far of the size
  they reserved. Large multi-chunk uploads work as before.
- **A rename is held to the role's file-type rule** (C-1): the Drive checked the rule on what it
  stores at upload and take-in, but a rename (or a new metadata type) could turn `report.pdf`
  into `tool.exe`. `PATCH /api/private/drive/nodes/<id>` now opens the new name and metadata as
  they will be stored and applies the same check (`403 file_type_not_allowed`), written only if
  the item is still as checked; a file's metadata can no longer be removed (`meta: null`: `400`);
  the Drive page refuses such a rename first, with the reason. A file already in the Drive that
  keeps its type can still be renamed.
- **Deleting a link's folder, or the account, no longer counts uploaders as guessing** (C-3): the
  upload tokens of uploads in progress in a deleted folder (or a pending item deleted on its own)
  are kept as late ones, as on a revoke, and an account deletion keeps its links' late hashes in
  the Directory for a day (`reverse_late`: hashes and link ids only), so late chunks, finalizes
  and `done` get an uncounted `410` and a genuine uploader's network is never blocked.
- **Loosening a Receive link's own file limits needs the step-up** (C-4): removing or loosening its
  file types, and raising or removing its most files, total bytes or largest file, are weakening
  changes — the password or a passkey in the browser, `403 step_up_required` (with `weakens`) for
  an API key, as for the other weakening changes. Tightening them needs nothing.
- **Files received count under `drive-bytes`** (C-5): a file received through a Receive link is
  Drive storage, so its size counts under the user's quotas of kind `drive-bytes` when it is
  finished (checked when it is reserved; past the quota the uploader gets the neutral `429
  not_accepting`). It never counts under `drive-upload`: the Receive kinds count its session.
- **"Go back" on a root change re-checks the sub-MEKs** (C-6) after sealing them again and before
  it writes (`409 changed`), as the change itself does, so a sub-MEK added at the same moment is
  never left under the root that goes.
- **The owner acting as a user gets no personal-kit state** (audit kg F4): `GET
  /api/private/drive` leaves `kit` out while impersonating (the page already hid it).
- **Link keys stored in plain text are refused** (audit RT2-4): like a received item's fields, a
  link key is always stored sealed at rest; one found in plain text is never handed out or
  re-sealed (the link shows no key), and a root change no longer seals a plain value at rest.
- **Sign-in and viewer records are sealed at rest.** Read receipts (the opener's address,
  location, browser, system and languages), the detail of the activity log's sign-in entries
  (sign-ins, sign-outs, lockouts, passkeys added or removed, blocked and unblocked addresses) and
  the addresses the brute-force guard tracks are sealed with AES-256-GCM (a random IV per value,
  the table, column, a random row nonce and the row's owner columns as AAD) under a record key
  derived from the Drive's root MEK (HKDF, `secbin-records/v1`), with the key id stored per row.
  A record is sealed before the step that writes it and written sealed in one statement: it is
  never stored empty or pending. The throttles compare keyed
  hashes of addresses instead of the addresses; the guard's rows are keyed by one, so Admin →
  Security shows the address the server opens for the owner (`addr`) and the row's key is a
  hash (unblocking by the address still works). A root change, "Go back", a restored root or a
  dropped previous root keep the earlier record keys sealed under the root, so every record stays
  readable, and a background pass seals them again under the current key. An instance with no
  keyring yet writes records in the clear, as before, and the pass seals them once a keyring
  exists; it also seals the rows stored before this release (Directory migration 19) and
  re-keys the guard's earlier rows. Until a guard shard's earlier rows are re-keyed, lookups
  check the address too, so blocks and failure counts from before the upgrade keep applying,
  including rows an older Worker writes during the rollout. Admin → Security's block and unblock
  take an address as typed ("1.2.3.4", a bare IPv6 address, a CIDR block) and key it as the guard
  does, and a block with no row yet keeps that address for the view and the audit. A Drive
  Receive upload session keeps the uploader's network only as a keyed hash.
  The server can derive the key: this protects a copy of the stored rows, not the server
  (SECURITY.md, "Records at rest"). Records are not exported.
- **An uploader's late requests are never counted as guesses:** after a Receive link is paused,
  revoked or ends, the requests its uploaders still send with the grant or upload token the link
  gave them (a finalize, the next file, a chunk, `done`) are answered (`409 paused`, `410`) without
  a Guard count, so pausing or revoking a link can no longer get its senders' network blocked.
  Only unknown or forged ids, grants and tokens count.
- **Take-in holds received items to their link's rules** (audit A-3): the uploader's browser only
  declares a file's type and a send's kind to the server, so the user's browser now checks the
  real, decrypted name and type against the link's file types, a file's size against its largest
  file, and each item's kind against what the link accepts. A mismatch is never added to the
  Drive: it is recorded as failed (new reasons `type`, `size`, `kind`) and listed, to delete.
  Each item is also held to the kind its session declared (the server seals that kind with the
  item until it is taken in), a note, link or credential to its kind's size, and the link's
  kinds to what the user's role allows at take-in, so a modified uploader cannot pass a file off
  as a note to escape the file limits and quotas, or send a kind the role has since dropped.
- **Drive shares of notes, links and credentials are held to the sender's role on the
  recipient's side:** the server records what the sender's role allowed when the share was made
  (`kinds`, returned by `open`), and the recipient's page shows an entry as a note, link or
  credential only where that allows it (otherwise a plain file, Download only). Item viewers never
  read or render an item larger than its kind can be. A credential's Download on a Drive share's
  page asks first, as in the Drive, and ZIPs (Drive folders, a Drive share's "Download all" and
  folders) leave credentials out and say how many.
- **A Receive link cannot be made on a folder deeper than the role's folder depth limit**
  (`maxFolderDepth`, by the Drive's own depth rule; `403 folder_too_deep` with `max`): nothing it
  received could be placed there. A link's folder moved deeper later takes nothing in.
- **The server holds a take-in to the declared kind too:** `409 kind_not_accepted` unless the
  kind the item's session declared is one its link accepts and the user's role allows at
  take-in; a link the role now allows no kind for takes nothing in (the browser no longer reads
  an empty list as "files"). A received item's fields stored in plain text at rest are refused
  (no fallback), failed as `kind`.
- **Per-network limits and the invalid-fetch rule, from the security audit of `main`:**
  - **The share CAPTCHA page** (`/p|r/<id>?check`) is served and counted only for this site's
    own document navigations (`Sec-Fetch-Dest: document`, `Sec-Fetch-Site: same-origin` or
    `none`). Another site's `<img>`, `<iframe>` or link is redirected back to the share's page
    uncounted. Before, such requests used up the network's 60 check pages per 10 minutes.
  - **Chunk downloads of a share that ended mid-download** (revoked, deleted, used up, expired)
    answer `410 gone` without counting as invalid requests when the share index knows the id,
    as the extend route already did. Before, the recipient's correct grant was counted, and at
    60 counts the whole network was blocked from every share.
    Those uncounted answers have a generous per-network limit of their own (`ended-chunks`:
    600 per 10 minutes, then `429 rate_limited`), never an invalid fetch.
  - **Turnstile's siteverify** is behind a per-network limit on sign-in, account changes and
    anonymous creation (`turnstile-verify`): after 60 rejected tokens in 10 minutes a network's
    tokens get `429 rate_limited` with `Retry-After`, before any call to Cloudflare. Accepted
    tokens are never counted, so a busy network's sign-ins never use it up. A missing or
    over-long token and a cross-site request are refused before anything is counted. The share
    CAPTCHA routes keep `captcha-verify`.
  - **`POST /api/auth/prelogin`** is limited per network (`prelogin`: 600 per 10 minutes) and
    per network and username (`prelogin-user`: 20 per 10 minutes, under a keyed hash of the
    name). Only well-formed same-origin requests count, the refusal is the same for every
    username (the fake salt stays), and only prelogin is refused: no account is locked. Heavy
    abuse from one network can delay password sign-in on that network; passkeys and recovery
    codes are unaffected, and the owner can lift the block.
  - **Anonymous trackers:**
    - A new id is kept only once it has created a share; a refused create gives the row and
      the network's allowance back.
    - New ids are also counted per IPv6 /48 (`public-trackers`: 16 × `public.newTrackersPerIp`
      per window), once their create has succeeded: refused creates from one /64 never block
      its /48.
    - A full table (200 000) removes its 1 000 least recently seen unblocked ids, with their
      usage counters (`tracker.evicted`), instead of answering `429 busy` to every new sender.
  - **HSTS and the Permissions-Policy** are on every Worker response (API answers, JSON, chunks,
    errors and redirects), not only on pages.
  - The owner sees and lifts the new `turnstile-verify`, `prelogin`, `prelogin-user`,
    `public-trackers` and `ended-chunks` blocks with the others.

- **Impersonation no longer extends the owner's session.** Starting an impersonation and
  "Return to admin" each issue a new session that keeps the absolute end of the owner's sign-in
  (`session.absSec` counts from the sign-in, and a new session never ends later than the one it
  replaces), and revoke the session they replace, so a copy of the old cookie stops working.
  Cycling "Log in as" and "Return to admin" kept a stolen owner session alive indefinitely and
  left each replaced session valid until its own timeout.
- **Admin changes that weaken a security control need the owner's password or a passkey**:
  turning CSRF tokens off or anonymous sharing on; loosening the account lockout, the per-IP
  brute-force rules, the IPv6 tracking prefix, the owner's session timeouts, the
  new-anonymous-sender allowance or the log retention (Settings, the Owner role, the Public
  role); in a role (the public account's too, and its API restrictions), loosening passkeys,
  the password policy, session timeouts or log retention, the CAPTCHA and uploader-password
  options and their defaults, longer or unlimited expiry and views, links with no expiry, and
  allowing file, link or credential shares (`files`, `url`, `secret`), Receive links that take
  files, links or credentials (`reverseFiles`, `reverseUrl`, `reverseSecret`), API keys, more
  file types or more links; and adding an
  allow IP rule. Missing, the server answers `400 reauth_required` with what the change weakens, and
  the admin panel then shows the confirmation field; tightening asks for nothing (SECURITY.md
  "admin changes that weaken a control").
- **The owner's own username changes only on Account** (with the password or a passkey):
  `PATCH /api/private/admin/users/<owner>` with a username answers `403 use_account_page`, as
  the owner's own password already did.
- **Separate keys for the prelogin fake salt, the anonymous tracker's tag and the public quota
  subjects** (HKDF-SHA-256 from the Directory's secret, one `info` each). They shared one HMAC
  key, so a prelogin request for a crafted username returned a valid tracker tag, and anyone
  could mint tracker ids the server accepted as its own. Tracker ids issued before this release
  no longer verify: browsers get a new id on their next visit, and the anonymous per-id and
  per-network counters start again.
- **Migration 17 on a multi-version upgrade:** a Directory from before migration 16 now keeps
  each role's `maxExpireSec` as its `reverseMaxExpireSec` (the Default role had been left at
  "no limit"). The step is corrected in place; a Directory that already ran it is unchanged.
- **CI:** every GitHub Action is pinned to a full commit SHA (its tag in a comment).
- **Received names are cleaned first, then checked again (ZIP slip).** The viewer checked a
  file or Drive share's paths before removing their hidden characters and never after, so a
  modified sender could write `.`, U+200B, `.` (which becomes `..`) or a leading U+200B segment
  (which becomes `/`) and get `../` or absolute members into **Download all** / **Download
  folder** ZIPs. Every received path is now cleaned and then validated (`files.js`
  `cleanPath` / `cleanEntries`); such a path, or two names that clean to the same path, refuse
  the manifest. The ZIP writer (`zip.js` `memberName`) cleans and checks each member name again
  right before writing it and refuses `..`, absolute paths, drive letters, backslashes, empty
  segments and duplicates, for file shares, Drive shares and Drive folders. `secbin get` now
  also saves and lists names cleaned (it kept the hidden characters on disk), reports how many
  were renamed, cleans `--path`, and refuses to write a name that still holds them.

- **The Drive personal kit has the CAPTCHA, and says when it is out of date** (docs/DRIVE.md
  §3.1). With Turnstile on, the Account page's personal kit card has its own widget: Download
  and Verify stay disabled until it has passed, and `POST /api/private/drive/kit` and
  `…/kit/verify` need a fresh token for `account` (checked before the step-up); without
  Turnstile keys nothing changes. The Directory now counts every key change (the **key
  version**: a sub-MEK added, rotated, deleted, made current or its dates edited, a root change
  or its undo, a restore that writes a key); both kit files hold it, both kit cards show
  "Version N, <date>", and Verify compares a file's version with the server's. Each
  personal-kit download is recorded (its date, version and the sub-MEKs it holds; removed with
  the account): after a key change, or once a scheduled sub-MEK the kit lacks has started, the
  Account page and the Drive page say "Your Drive’s keys were updated. Download a new personal
  kit and keep it safe.", with no key detail, until the user downloads a new one; the kit card
  shows the last download. The owner acting as the user cannot download one, so cannot clear
  the notice (`GET /api/private/drive/kit`; `kit` in `GET /api/private/drive`).
- **Set-up proposes the Drive keys for the owner to choose.** The set-up page shows the root
  MEK and first sub-MEK the server generated (`POST /api/auth/setup/candidate`, with the setup
  token), masked until Show, with "Use these", "Generate again" and "Enter manually", as
  Security → Keys' key chooser does (shared: `public/js/keychoice.js`). Nothing is stored until
  the set-up sends the chosen pair; a pair no longer kept (10 minutes, or replaced) is refused
  before the owner account is made. Proposals need an unspent token and no owner yet (`410
  token_used`), are limited to 20 per network per 10 minutes, and are not logged (only the
  adopted pair is, as `keys.created`). The chosen or entered keys are written in the same
  transaction as the owner. Copying a key clears the clipboard after 60 s where the page may
  read it back; this site's Permissions-Policy denies that, so the page says to clear it.

- **Every step-up takes a passkey: Admin → Import / export (the account and system export and
  import) and Admin → Audit → Clear logs** confirm with the owner's password or, the field left
  empty, a fresh passkey assertion (`POST /api/private/me/reauth`, then `{ reauth }`), verified
  as every other step-up; a failed passkey counts like a wrong password (the account's lockout
  and the network's login failures). The import's preview and its apply each ask again. They
  took the password only.

- **Drive key model v2** (docs/DRIVE.md §2, §3; SECURITY.md "Drive keys"). **Drive files are no
  longer end-to-end encrypted:** they are still encrypted in the browser (a random DEK per file;
  the DEK, name and metadata sealed under the user's KEK with a random per-item salt), but the
  server derives every KEK — `HKDF(root MEK ‖ sub-MEK, user salt, "secbin-kek/v1\n<userId>")` —
  from keys it keeps in the Directory, so the server, and anyone with a copy of the Directory's
  storage, can decrypt every Drive file. A leak of R2 or of a Drive object without the Directory
  reveals nothing. Notes and file shares stay end-to-end; Drive shares (Drive ciphertext whose
  DEK is also sealed under the KEK) and reverse-share uploads (the link's private key is sealed
  under the KEK) are not end-to-end against the server either, and the uploader's page, the
  Drive page, the glossary and the docs say so.
  - The Drive opens right after sign-in: no set-up, unlock or recovery screens, and passwords,
    passkeys and recovery codes play no part in it. The owner acting as a user gets the user's
    keys (`drive.keys_used`, admin audit only).
  - The KEKs are asked for at every page load (`POST /api/private/drive/keys`, with the CSRF
    token) and kept in the page's memory only: never written to or read from browser storage, so
    a key planted there is ignored; the slots of the release before are removed. The old Drive
    key of the release before (only while a Drive waits for its upgrade) is used only once its
    check value is the server's.
  - Removed: the Drive key wraps (password, recovery code, passkey, escrow, hand-over), the key
    check value, the Drive salt, the owner's escrow and signing keys with their pins, rotation,
    "Trust the new key", owner resets and the automatic re-wrap, the owner recovery kit,
    starting over and the archive routes, the owner setting up a user's Drive, and their routes,
    pages and tests.
  - **Admin → Security → Keys:** the root MEK and the sub-MEKs (generated by the server or
    entered by hand; Show, add, rotate, edit dates, set current, re-seal, delete after a
    re-seal, change the root), each with the step-up and in the admin audit by fingerprint; the
    server re-seals items itself (a job with progress). The set-up page makes the first keys.
  - **Kits:** the personal kit (`secbin-user-kit/2`, every user, on Account) and the key kit
    (`secbin-key-kit/1`, the owner): download with the step-up, a read-only verify of a
    selected file with a date, and a restore of only what the server lost.
  - **Only the owner restores from a personal kit:** the Account page's Restore section is gone
    for every account (the owner's own included; Download and Verify stay), and its routes
    (`POST /api/private/drive/kit/restore`, `GET`/`PUT …/kit/items`) answer `403 owner_only` to
    everyone, so no user can change what opens a Drive. Admin → Security → Keys has "Restore a
    user's personal kit" instead (`POST /api/private/admin/keys/users/<userId>/kit-restore`):
    the user chosen, the kit opened in the owner's browser for that user only (`400
    kit_mismatch` for another user's), the step-up for every call, the same rules as before (the
    salt only when missing and only if it opens the Drive; items under a lost sub-MEK re-sealed
    under the current one, server-side and compare-and-set; a working key never replaced), in
    the admin audit by ids and counts (`drive.kit_restored`, `drive.salt_restored`) and no
    longer in the user's activity. The Drive page's "salt missing" notice no longer points to a
    restore on Account.
  - **Import / export → Drive keys:** the root MEK, sub-MEKs, user salts and chosen users'
    KEKs and DEKs in a file of their own; imports never replace working keys (a KEK only
    verifies; a DEK restores a broken seal after the GCM check).
  - Every seal a browser sends is checked in the Worker; each file stores a ciphertext hash;
    reverse-link keys and received items are also sealed at rest under a per-user field key.
  - **The upgrade of existing Drives** (docs/DRIVE.md §3.3): each Drive made by the release
    before is re-sealed once, in the user's browser at sign-in (or with a recovery kit of that
    release) or in the owner's through the escrow of that release (with the step-up; disabled
    accounts too), resumably, and the old wraps and escrow keys are removed only after the
    server verified that every item opens under the new keys, and after the last Drive is done
    or the last account still waiting is deleted. A link whose old key does not open is
    retired by its user (the step-up); a finished upgrade stays finished; the old Drive key
    leaves the tab once nothing waits; an AUTHN owner recovery keeps the owner's old wraps
    while a Drive waits; the owner can delete the archive of a start over (not counted in the
    capacity any more).
  - **Keyring jobs, after the security audit:** every Drive that can hold a sealed value is part
    of every job and count (a Drive with only a reverse link included); a root change seals
    nothing new under the previous root (`409 stale_keys`), checks every Drive before the
    previous root goes, waits while a Drive still has something of the release before, and one
    that cannot finish is run again, undone, or its previous root dropped with its fingerprint
    typed (the key kit holds both roots meanwhile); re-seals never revert a rename made
    meanwhile; a restore or an import adds a sub-MEK or a salt only when it opens something
    there; cancelling a job and the restore and import previews need the step-up; a generated
    key is used only for its purpose and deleted when unused. A download checks the file's
    ciphertext hash. An open Drive drops its keys when the session ends or the browser is now
    signed in as someone else.
  - **After the re-audit:** a key kit's previous root MEK is put back only when it opens
    something here (else it is reported `unused`), and "Go back to the previous root" leads only
    to a root this server worked with or one that opens items here (`409 unproven_root`);
    removing the previous root takes its count of unreadable items from the root change's own
    check, kept with the root change (a cleared job no longer resets it to 0), says it on the
    button, in the answer and in the admin audit, and waits for a re-seal when there is no check
    yet (`409 not_checked`); Admin → Security → Keys and Import / export drop the key values they
    show when the session ends or changes; a Drive holding something of the release before with
    no upgrade record waits for its upgrade; a passkey the owner removes, or codes the owner
    replaces, lose their old wrap at once even while Drives wait (Account says those Drives can
    still be upgraded with the owner's other sign-in methods and the escrow), while the wraps an
    AUTHN owner recovery kept stay until nothing waits; My shares, the page descriptions, API.md
    and the architecture notes say which shares are end-to-end and which are not.
- **CAPTCHA on shares and reverse shares** (role options; SECURITY.md "CAPTCHA on shares",
  docs/API.md, docs/REVERSE.md §5–§8, docs/DRIVE.md §5, §7): Admin → Roles has, for every
  non-public role, "CAPTCHA on shares" (notes, file shares, Drive shares) and — while the role
  has the Drive and reverse shares — "CAPTCHA on reverse shares": radio buttons "Allow CAPTCHA
  (user chooses per share)", "Require CAPTCHA for all shares" ("…for all reverse shares") and
  "Disable CAPTCHA", and under "Allow" a "Default for new shares: CAPTCHA on / off". Options
  `shareCaptcha` / `shareCaptchaDefault` and `reverseCaptcha` / `reverseCaptchaDefault`
  (Directory migration 15): the Owner role is locked at "allow" (the box starts off for shares,
  on for reverse shares); the Default role holds allow / off for shares and require / on for
  reverse shares (every reverse link had the human check before); custom roles inherit; the
  Public role has none. They travel in an export's roles part.
  - **Per share:** "Require CAPTCHA to open" in the composer and the Drive's Share dialog,
    "Require CAPTCHA to send files" in Receive files, `captcha: true|false` on every create
    route, `--captcha` / `--no-captcha` in the CLI's `create` and `send` — pre-set from the
    role's default under "allow", ticked and disabled under "require", hidden under "off". The
    server applies the role: "require" is on whatever is asked; "off" refuses `captcha: true`
    (`403 captcha_disabled`). The flag is stored in the share's record and index row; My shares
    and Admin → Shares show a CAPTCHA badge, and `share.created` logs it.
  - **Recipients:** a protected share's head, open, "delete now" and every chunk answer
    `403 captcha_required` ("This share requires a CAPTCHA; open it in a browser") until a
    CAPTCHA grant is presented: `POST /api/(paste|file)/<id>/human` with a Turnstile token for
    the new action `share-open` issues one (HMAC-signed, bound to the share and the caller's
    network, 10 minutes, sliding while used, at most 12 hours). Nothing is spent and nothing is
    counted as an invalid fetch without it; views are spent only by the open that follows. The
    CLI's `get` prints that message.
  - **Reverse shares:** starting an upload session needs a grant (`POST /api/reverse/<id>/human`,
    action `reverse-upload`) or a token only when the link has the flag, still before the
    password; each grant starts one session (a wrong password spends it). Links without it have
    no check (before, every link had it while Turnstile was on).
  - **The key never meets Cloudflare's script:** `/p/<id>` and `/r/<id>` now always have the
    strict CSP (the uploader page had the Turnstile CSP whenever Turnstile was on) and are
    served by the Worker with a per-navigation page key; a protected share's page takes the key
    out of the address bar, seals it (with the tab's Drive keys) in `sessionStorage` and goes to
    its check page (`/p/<id>?check`, `/r/<id>?check`, the Turnstile CSP), which never holds a key
    that opens it; back on the strict page the key is opened, put back and the share opened.
    Without `sessionStorage` or a page key a protected share is not opened.
  - **Inactive without Turnstile keys:** the flag is saved but not asked for; the role editor,
    the composer and the dialogs say so.
  - **The page key is random and bound to the browser** (security audit F1): it is 32 random
    bytes made on each strict navigation (`Sec-Fetch-Site` none or same-origin), written into
    the page and into an HttpOnly, Secure, SameSite=Strict cookie for the share's path (15
    minutes); the return from the check gets it again only with that cookie, which the same
    response clears (one use). It was derived from the id and a nonce the check page could read,
    so a script there could have had it fetched from outside the browser. The sealed record holds
    the link's key alone: the tab's Drive keys are removed before the check and never carried
    through it (the Drive asks to be unlocked again). The check page has `worker-src 'none'` and
    COOP `same-origin-allow-popups` and registers no service worker; a page opened from another
    site reloads itself once for a key.
  - **Metering and uniform answers** (audit F2–F4): at most 30 CAPTCHA checks per network per 10
    minutes reach siteverify (`429 rate_limited`), a failed token counts as an invalid request,
    the check page is behind the Guard's block and a rate limit and looks nothing up, and a
    missing or ended share answers `403 captcha_required` without a grant, like a protected one.
  - **Re-audit fixes (N1–N3, N6):**
    - a Drive key read from the tab's `sessionStorage` is used only once proven against the
      server's key check value, and a planted key is removed (with the Drive key model v2, above,
      the KEKs are never stored: this now applies to the old Drive key of a Drive waiting for its
      upgrade, proven against `GET …/drive/migrate`'s `kcv`); the return from a CAPTCHA page also
      removes any Drive key slot found in the tab;
    - every Worker response carries COOP and CORP `same-origin`, `X-Frame-Options: DENY`,
      `nosniff` and `no-referrer`, and anything that is not HTML
      `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; sandbox`;
    - the service worker serves a cached copy only when its SHA-256 is in the build's integrity
      manifest (generated into `sw.js` by `tools/sw-manifest.mjs`), rebuilt with the build's own
      headers; a copy that does not match is deleted and the request fails;
    - the page-key cookie is named by its nonce (`__Secure-secbin_pk_<n>`), so two tabs of one
      share keep their own; at most 4 per share path.
  - **Wording:** the UI calls the Turnstile check "CAPTCHA" everywhere (Admin → Security →
    CAPTCHA, the waiting and load-failure notes on login, Account and the home page).
- **CSRF tokens (defence in depth)**, on top of the SameSite=Strict session cookie, the
  `Sec-Fetch-Site` check, the JSON / `X-Secbin-Intent` requirement and the absence of CORS
  (all kept as they were).
  - **The token:** stateless and bound to the session, an HMAC of the session id and version
    under a subkey of `SIG`. It is the same for every tab and request of a session and changes
    with it (sign-in, sign-out, a session-version bump, impersonation start or end).
  - **Delivery:** in a readable `__Host-secbin_csrf` cookie (Secure, SameSite=Strict, `Path=/`)
    whenever the session cookie is set or refreshed and on every signed-in page load, and in
    `GET /api/private/me` (`csrf`). The cookie never outlives the session cookie.
  - **The check:** every cookie-authenticated `POST`/`PUT`/`PATCH`/`DELETE` (and sign-out) must
    send it in `X-Secbin-CSRF`. It is compared timing-safely. A mismatch gets
    `403 csrf_mismatch`.
  - **Order:** before anything else runs, the cross-site check, then the request shape (a JSON
    body, a chunk or `X-Secbin-Intent`; `415` / `400 missing_intent` as before), then the token.
    A refused request has changed nothing, counted no failure and spent no Turnstile token.
    Every route with a human check also checks its request body before verifying the Turnstile
    token (for a public share, the content type and declared size).
  - **Exempt:** API keys (the CLI) and the anonymous routes.
  - **The client** (`public/js/api.js`) acts for the session its page was loaded for: it sends
    that session's token, recorded from `/api/private/me` at load. On a mismatch it asks
    `/api/private/me` who is signed in now and retries once only for the same user in the same
    impersonation state. Otherwise (another user signed in, impersonation started or ended in
    another tab) it does not retry and shows "Your session changed in another tab; reload the
    page." with a Reload button, so a stale tab never changes another user's account. Sign-out
    uses the same path and no longer hides a failure. A dashboard page restored from the
    back-forward cache re-checks its session.
  - **Owner switch:** Admin → Settings → CSRF tokens (`csrfTokens`, on by default). Changes are
    audited as `settings.csrf`; the setting is exported and imported with the settings, and the
    import preview warns when it would be turned off.
  - **Tighter guards:** `POST /api/private/me/reauth` and `POST /api/private/me/passkeys/options`
    now need a JSON body (`{}`), like every other change. `POST /api/auth/passkey/options` now
    has the cross-site check and needs a JSON body (`{}`), like the other auth routes.
  - **The Drive:** every cookie-authenticated change under `/api/private/drive/*` and
    `/api/private/admin/drive/*` (keys, folders, files, chunk uploads, finalize, rename / move,
    delete, shares, the impersonation escrow, the owner's kit, kit keys, start over, archive and
    the admin escrow and keys routes) goes through the same checks in `authenticate()`. The Drive
    client sends the page's token through `api.js`; a raw chunk upload passes the shape check as
    `application/octet-stream`, and finalize (no body) with the intent header. The kit check
    `kit/probe`, which records escrow use in the admin audit, is now `POST` (`{}`, intent header)
    instead of `GET`.
  - **Reverse shares:** every cookie-authenticated change goes through the same checks in
    `authenticate()`, before the step-up and before the id is claimed: creating a link, taking a
    received file in, marking it failed and retrying it, and extending, revoking and locking a
    link through My shares and Admin → Shares. The Drive page sends the page's token through
    `api.js`. The anonymous uploader (`/r/<id>` and `/api/reverse/<id>/…`: open, begin, reserve,
    chunk, finalize, cancel, done) is exempt: it reads no session, and keeps its own guards (link
    proof, session grant and upload token, Turnstile, the password lockout, the Guard). The
    workerd sweep reads `src/routes/reverse.js` and fails if a cookie-authenticated reverse route
    or method is missing from it.
  - **Tests:** workerd, DOM and end-to-end suites (`test/csrf.test.js`, `test-dom/csrf.test.js`,
    `test-e2e/csrf.mjs`).
- **Reverse shares when the owner starts over** (docs/REVERSE.md §9, docs/DRIVE.md §3.2): the
  owner's reverse links are **paused**, not revoked — no new session or upload (`409 paused`,
  once the link proof matches; the uploader page says "This link is not accepting files right
  now"), their open sessions end and unfinished uploads go, and the items they received stay in
  the archive exactly as they arrived, with the links' private keys still sealed under the old
  Drive key. A restore with a kit for the old Drive brings the items back as they are, re-seals
  each link's key under the Drive's key now (`reverse` in `POST …/archive/<gen>/finish`) and
  resumes the links; the kept items are then taken in. Deleting the archive revokes the paused
  links and deletes their received items. `reverse.paused`, `reverse.resumed` and
  `reverse.revoked` (`reason=archive_deleted`) in the owner's activity and the admin audit. No
  other user's link changes. My shares shows a paused link as paused.
- **Reverse shares, security audit round 4** (docs/REVERSE.md §3, §4, §5; SECURITY.md
  "Reverse shares"):
  - an upload session's deadline slides both ways: once nothing is unfinished (a file finished
    or cancelled) it is idle again and lapses after 10 minutes, giving its per-network slot back
    (it used to stay open for the role's `filePendingSec` after its first file); still at most 24
    hours in all;
  - lowering a role's `reverseMaxBytes` applies to existing links (the smaller of the link's own
    limit and the role's current one);
  - a reverse-share id is never claimed again, even after its index row is pruned or its account
    deleted (a permanent SHA-256 tombstone of the id), so an old link never opens a later share;
  - taking received files into the Drive, marking them failed and putting them back are logged
    as Drive actions (`drive.received_taken_in`, `drive.received_failed`,
    `drive.received_retried`; one entry per link, per actor, per hour); creating, revoking and
    all three while the owner acts as the user are logged exactly like the Drive actions (the
    user's own in their activity, the owner as the real actor in the admin audit: `imp`, not
    `adm`); a reverse share needs a set-up Drive (`409 drive_not_set_up`), and follows the
    Drive's rules (no hand-over wrap; the escrow wrap always present);
  - documented: one network can keep a password-gated link locked (the lockout is per link on
    purpose), and uploaders of a limited link can infer other uploads from `filesLeft` /
    `bytesLeft`.
- **Reverse shares, security audit round 3** (docs/REVERSE.md §3, §4, §6, §7; SECURITY.md
  "Reverse shares"):
  - a link's id is claimed in the share index before anything else, in one step with the role's
    checks and the active-links count: another account can no longer take over an id (`409
    exists`), and `reverseMaxActive` holds under concurrent creates; no share index row ever
    moves to another account or gets another link hash;
  - received files that cannot be taken in are recorded as failed on the server and leave the
    queue (`GET /received` pages with `after` / `next`), so they never hold up later files; the
    Drive lists them ("Review them") to delete or try again;
  - the human check comes before the password on `begin`, and each link has its own lockout
    (10 wrong passwords in 15 minutes, from any networks: 15 minutes);
  - an upload session with nothing unfinished lapses after 10 minutes idle; at most 5 open
    sessions per network per link (and still 100 per link);
  - `reverse.received` is one log entry per link per hour, adding up that hour's sessions;
  - received names are cleaned as everywhere (`cleanName`; Hebrew, Arabic, ZWNJ / ZWJ and LRM /
    RLM stay) and a renamed file is marked; a received path creates at most 8 folder levels and a
    take-in at most 200 new folders (deeper files go into the deepest folder allowed);
  - finalize and cancel accept only the session that reserved the file; a file's sealed fields
    count towards the link's byte limit (empty files included); a reservation must finish within
    24 hours however often its chunks are re-sent;
  - documentation: the status codes do tell a reverse-share id from an unknown one; the owner
    acting as the user can create a link whose key the owner keeps; with Turnstile on, its script
    can read the link key on the uploader page.
- **Owner recovery kit, starting over, Drives the owner sets up** (docs/DRIVE.md §3, §3.1, §3.2;
  SECURITY.md "Drive keys"):
  - **owner recovery kit**: a file (`secbin-owner-kit/1`) with the owner's Drive key and a
    snapshot of every escrow key (current, signing, earlier), made and read only in the browser
    (Argon2id with the export's parameters over an optional passphrase, AES-256-GCM, the format,
    owner id and origin in the AAD); the same kit, status, check and restore on the export screen
    and the owner's Drive page (one module, `public/js/drivekit.js`, with a `user` kind for a
    later user kit; a kit of the other kind is refused). Download is always available and needs
    the step-up (`drive.kit_exported`, with the version); the pages show the escrow key's version,
    fingerprint and date and the latest kit, and ask for a fresh kit after a rotation (announced
    once, then a static notice) or when none was downloaded. **Verify kit** checks a file the
    owner selects, read-only (format and owner, the tag, the Drive key, the current, signing and
    earlier keys, the version, a live opening of one user's escrow wrap per key), with a verdict
    (`drive.kit_verified`). **Restore from kit** (also from the Drive page's unlock screen) brings
    back the owner's Drive with a fresh password key, the escrow access on current and past keys,
    and sealed escrow keys the server lost (only for its own public keys and kids in use, with the
    step-up; `drive.kit_used`, `drive.kit_keys_restored`). Failed openings are throttled. The kit
    is never part of an export;
  - **AUTHN owner recovery** still removes the owner's passkeys and recovery codes; it now also
    drops their Drive wraps and marks the owner's Drive stale, and changes no key;
  - **only an explicit rotation makes an escrow key or signing key** (besides the first creation
    and starting over): "restore the escrow public key" no longer makes a signing key, and the
    owner's first set-up happens only when no escrow or signing key exists anywhere. The escrow
    key has a version (1, then one more per new pair);
  - **starting over without a kit**, only when nothing the owner signs in with opens the Drive,
    with the typed username and the step-up: new Drive key, escrow pair and signing key; the old
    Drive is **archived** as it was (sealed under the old Drive key, counted in the storage),
    restorable with a kit for it (items re-sealed under the current key, " (2)" for a clashing
    top-level name, the old escrow keys back for users still on them) and deleted only by
    "Delete the old Drive archive" (typed username, step-up). `drive.owner_reset`,
    `drive.archive_restored`, `drive.archive_deleted`;
  - **maintainer-accepted weakening:** after a start over, users' browsers move their Drives to
    the new escrow key **automatically**, once per owner reset (an epoch one more than the pinned
    one, the key signed by the reset's signing key; every time, with no time limit), with a
    one-time notice and `drive.escrow_rewrapped` in the user's activity and the admin audit.
    This is not limited to a window after a real reset: anyone able to change the server's
    responses can report a fabricated reset at any time (and again at each later epoch), and so
    can anyone with access to the Worker's `AUTHN` secret configuration (AUTHN recovery, then a
    start over); every other unsigned change keeps the notice and "Trust the new key";
  - **Drives the owner sets up**: creating an account (or resetting the password of a user with no
    Drive yet) with the owner's Drive unlocked sets the user's Drive up in the owner's browser
    (`pw` and `escrow` wraps, the pin; `drive.created_by_owner`); otherwise it waits for the
    user's first sign-in, and the create form says which. For a role without the Drive the
    owner's browser makes no Drive request (the create response says whether the role has one)
    and the form says "Drive is not enabled for this role, so no Drive was created."; the
    server's `409 drive_disabled` stays as a guard. Imports and impersonation never do;
  - **the Drive key never changes**: a password change opens the Drive key first (the old
    password or the passkey's PRF) and writes the new password wrap at once; an admin reset asks
    the owner to unlock their own Drive inline and re-wraps through the escrow (or continues
    without, with a warning). A new password wrap is accepted only with the Drive key's check
    value (`kcv`, HMAC under the key's "files" sub-key), kept since the first set-up.
- **Drive, security audit round 5** (docs/DRIVE.md §3, §3.1, §3.2, §6; SECURITY.md "Drive keys"):
  - a user's browser never treats a missing pin, a missing escrow wrap or an escrow wrap for
    another key than the pinned one as a first use: it shows a tamper notice and re-wraps
    nothing (only the genuine first set-up pins); a signing key is never added to a pin silently;
  - the Drive key's check value is required at every first set-up (the user's own, one the
    owner makes, the owner's own, starting over) and with every later wrap or pin, and is never
    taken from a later change; a Drive without one takes no key;
  - replacing a passkey, recovery-code or escrow wrap needs the step-up, as removing one does;
  - first set-ups and starting over are atomic (a compare-and-set in the Drive object, one key
    check value, one archive, one reset epoch): of two at once, the second gets `409`, and a
    browser that lost a first set-up opens the Drive that won;
  - a Drive with content (or keys) but no wrap takes no first set-up (`409 drive_keyless`): only
    a kit restore or starting over, each with the step-up;
  - the owner's own Drive takes no escrow wrap; the admin escrow route returns only the escrow
    wrap; a user's move to a reset's key is recorded once per epoch, and `escrowReset` and the
    kit check (`kit/probe`, 30 per session per 10 minutes) are rate limited.
- **Drive, security audit round 2** (docs/DRIVE.md §3, §6, §10; SECURITY.md "Drive keys"):
  - the owner's escrow key pair changes only with the owner's password or a passkey (the first
    one excepted), and a new escrow key must be signed by the owner's signing key (ECDSA P-256,
    sealed under the owner's Drive key); the owner's browser checks the server's escrow public
    key and signature against its own keys and alerts on a mismatch; each user's browser pins the
    escrow key and the signing key, re-wraps by itself only to a key the pinned signing key
    signed, and otherwise shows a notice ("Trust the new key");
  - every user's Drive has an escrow wrap for the current escrow key: a Drive is set up only
    once the owner's escrow key exists ("Drive is not ready yet" before), only with an escrow wrap
    and a wrap of the user's own, and the escrow wrap cannot be removed; no change leaves only
    the escrow wrap; rotating the escrow key (with the owner's password) keeps the old private key
    sealed under the owner's Drive key until no user's wrap needs it;
  - no server-held key exists for any Drive: the one-time hand-over wrap and its server-held key
    are gone, and a regression test checks that the server stores no key that opens a Drive;
  - removing a key wrap, replacing the password wrap or the Drive salt needs the password or a
    passkey (not for the first set-up or a stale password wrap), and no change leaves a Drive
    with content and no wrap;
  - a recovery code spent at sign-in loses its Drive wrap on the server; a password change marks
    the old password wrap stale, and an admin reset removes it when another wrap remains;
  - finalize waits for chunk writes in flight (`409 busy`), so a late retry can no longer delete
    a chunk of a finished file;
  - an item with 100 or more shares lists them again (batched lookups), and ended shares leave
    the Drive's share records;
  - sealed names and metadata are capped at 512 / 1024 characters and count towards the
    capacity;
  - a file whose sealed metadata is missing or disagrees with the server's size is unreadable,
    never an empty file;
  - deleting an account removes its Drive and ends its shares first, retried, and keeps the
    account if that fails;
  - the Account page keeps the tab's Drive key out of `sessionStorage` while the Turnstile
    script may load; login and the public composer clear it first.
- **File and folder names: real names in every script, no extension spoofing.** Names in
  Hebrew (niqqud included), Arabic, Persian (ZWNJ), emoji sequences (ZWJ) and with LRM / RLM
  marks are kept exactly as they are in file shares, the viewer, the CLI and the Drive. Only
  the characters that can disguise a name are removed (bidi overrides, embeddings and isolates,
  U+200B, U+FEFF, U+0085, U+2028, U+2029; then NFC; `files.js` `cleanName`), and the sender is
  told when a name changed (a received one is marked "renamed"): `invoice<U+202E>fdp.exe`
  becomes `invoicefdp.exe`. Every name is shown in a bidi isolate with its extension as its own
  left-to-right isolate (`common.js` `nameEl`): the Drive's tree, table and dialogs, the
  composer's file list, the viewer, downloads and ZIPs. A share id is never moved to another
  account when it is recorded again.
- **The Drive sets itself up at the first sign-in.** Once the Drive is enabled and the owner's
  escrow key exists, a user's first sign-in creates their Drive key in the browser with the
  password wrap, the escrow wrap (and a passkey wrap with PRF), with no prompt.
- **Log in as: the user's whole Drive.** The owner acting as a user opens that user's Drive with
  the owner escrow (the owner's own Drive unlocked in the tab) and can browse, upload, download,
  move, rename, delete, share and revoke; the user's key stays in its own tab slot and goes when
  the impersonation ends. A user who has not signed in since the Drive was enabled has no Drive,
  and none is created: the page says so. The user's own key wraps are never removed or replaced
  then.
- **Drive actions are in the user's activity**, like every other action (node ids only): keys
  changed, folders, uploads, file reads (throttled: one row per file per minute, at most 30 a
  minute), renames and moves, deletions and Drive shares. What the owner does while logged in as
  the user shows there as the user's own, with no trace of the impersonation; the owner-only
  admin audit has the owner as the real actor, and the owner's escrow use.
- **The user's own activity no longer lists the start and end of an impersonation**
  (`impersonate.start`, `impersonate.end`); they stay in the owner-only admin audit.
- **Nothing the Worker serves is stored in Cloudflare's cache** (with Workers Caching on, see
  Changed): the top-level fetch handler adds `Cloudflare-CDN-Cache-Control: no-store` to every
  response it returns, errors and exceptions included, and `Cache-Control: no-store` to any
  response without one of its own (the asset server's `307` for `/index.html` and the bare
  `404` when the assets binding is missing had none, and would have been cached
  heuristically). The home page and the anonymous tracker keep their browser caching. A
  workerd test walks 148 routes, methods and outcomes (API-key calls to My shares and the
  Account page's human checks included) and checks every response.
- **Human check on every Account change:** with Turnstile on, changing the username, adding or
  removing a passkey, the "password and passkey" choice, new recovery codes, and creating,
  changing or revoking an API key now need a fresh Turnstile token (action `account`), like the
  password change already did (`password`). Each card of the Account page has its own
  always-visible widget; its buttons (the table rows' Remove and Revoke included) stay disabled
  until the check passes, and again after each use. The token is checked before the password or
  passkey confirmation; adding a passkey is checked on the step that stores it. API-key calls,
  the owner's admin panel and challenge requests need no token; nothing changes while Turnstile
  is off.
- **Security audit fixes** (OWASP-style review of the whole code base; no Critical or High
  findings):
  - cross-site requests to the public share routes are refused before any Guard accounting
    (another site could get a visitor's network blocked); the passkey challenge POSTs refuse
    cross-site callers like every other POST;
  - the account lockout no longer reveals which usernames exist: unknown names lock the same way;
  - an IP block rule covering the owner's own address is refused unless an allow rule covers them;
  - a chunk written to R2 for an upload that ended meanwhile is deleted instead of left orphaned;
  - `/api/config` is cached per isolate, and `/api/public/profile` answers "off" without reaching
    the Directory, so anonymous floods do not all land on the single Directory object;
  - the CLI escapes C1 control characters in sender-chosen file names before printing them.
- **Link, receipt and log hardening** (from a review of the new features):
  - recipients can open only web, mail, phone and SMS links; any other app link a sender's rules
    allow (`vscode:`, `ssh:`, `smb:`…) is shown in full with Copy only;
  - the full link is always shown;
  - read receipts are throttled (one stored per address per minute, 30 per share per minute), keep the
    first 100 for good, are deleted with their share, and are announced on every view;
  - log pruning never removes the owner's own actions or server-wide configuration changes,
    and it is cheaper (time indexes; only accounts with their own limits are visited);
  - a second preview can no longer render under the first one's title;
  - a corrupt saved accessibility setting can no longer stop the widget from saving;
  - opening an ended share (expired, used up, revoked or deleted) is exempt from the invalid-fetch
    guard only with its correct link (`#` key); a wrong key is counted, as for a live share.
- **Passkey and sign-in hardening** (from a review of the new features):
  - usernameless sign-in challenges are no longer stored, so a flood of requests cannot push out
    other people's pending sign-ins;
  - stored challenges are capped per account;
  - removing an account's passkeys from the admin panel (the owner's included) needs the
    admin's own password;
  - an admin password reset keeps the account's passkeys and recovery codes (passwords and
    passkeys are separate), and an import never removes or overwrites an existing account's
    credentials (see Changed);
  - a recovery code alone always signs in, whatever the passkey mode or the user's "passkey
    after password" choice (Turnstile, per-IP blocking and the lockout still apply);
  - the second step respects the account lockout;
  - of two simultaneous sign-ins presenting the same signature counter, only one succeeds;
  - Account lists the passkeys and codes that still work after a password change;
  - every change to one's own account (password, username, passkeys, recovery codes, the second
    step, API keys) is confirmed with the password or a passkey, asked again each time; the
    owner changes other users' keys and passkeys without it;
  - a warning is logged when only one Turnstile key is set.

### Added

- **An API for "Receive" links** (docs/API.md, *Receive links*): `GET /api/private/receive`,
  `…/receive/<id>` and `…/<id>/opens` (scope `read`: the links with their folder, what they
  accept, limits, views and counters, never their key, note or password), `PATCH …/<id>`
  (`manage`: the changes of My shares' Edit, weakening ones refused for keys with `403
  step_up_required` as before), `POST …/<id>/pause`, `…/resume` (not with a key) and `…/revoke`
  (`manage`). The role's reverse shares (not to revoke), API use, the lock and the API limits (`reverseEdit`, the kinds, expiry,
  views, folder depth) apply; a key still cannot create a link (its key is sealed under the
  user's Drive keys, which a key never gets, and creating one needs the step-up). A session can
  use the same routes (with its CSRF token).
- **Pause and resume a Receive link** (My shares, the Drive's Receive… and Shares lists, the API):
  paused, it takes no upload session (`409 paused` on `open` and `begin`, never counted by the
  Guard), the sessions open then end and their unfinished uploads are deleted; what it received
  stays and is taken in. Needs no `reverseEdit`. Resuming reopens the link, so it asks for the
  password or a passkey (refused for an API key). Logged as `share.updated … paused` / `resumed`.
- **Receipts for Receive links:** each upload session granted (a view) is recorded like a share's
  opening — the time, and the uploader's network address, location, browser, system and
  languages, shown to the user as far as the owner allows (`receipt*` options) and to the owner
  in full — in the same `opens` records, with the same throttles, limits, retention and clearing.
  My shares and Admin → Shares show them ("2 upload sessions"); the uploader page says that
  sending is recorded.
- **Move a Receive link to another folder** (its Edit, in My shares and the Drive, or `folder` in
  the API): any folder of the user's own Drive within the role's folder depth (`403
  folder_too_deep`; `404 folder_not_found` for a folder that is not theirs, deleted or a received
  item; `400 not_a_folder`); what it received and has not been taken in yet moves with it and is
  taken in there — the server holds each take-in to the link's folder as it is now (`409
  folder_moved` for a page that listed it before the move: it is added there next time); the
  folders' Shares and Receive… lists follow. Logged as `folder=<id>`.
- **"Receive" links take what regular shares carry** (docs/REVERSE.md §3.1): besides files, a
  link may accept a **note** (plain text, Markdown or code, with an optional title), a **link**
  and a **credential** (the regular credential's fields), as the user chooses when making it
  ("What senders can send") or later (Edit). Links made before accept files only.
  - Role options `reverseFiles`, `reverseText`, `reverseUrl`, `reverseSecret` (Default: files and
    notes on, links and credentials off, as for regular shares; the Owner: all; not for the public
    account; restrictable for API keys; in import / export like every role option). Directory
    migration 18 gives the Default role their values. The server checks them on create, on each
    kind an Edit adds, and at every upload — `open`, `begin` and each reservation — with the role
    as it is then.
  - The uploader page offers the accepted kinds as tabs, with the composer's note formats, the link
    field (destination spelled out) and the credential form, under the warning that the
    recipient's server can decrypt it. Each send is one upload session of one kind, declared at
    `begin` (`{ type }`; `403 kind_not_accepted`): one view, counted under `receive`,
    `receive-upload` and a new quota kind per kind of send — `receive-file`, `receive-note`,
    `receive-url`, `receive-secret` — given back as before when it sends nothing. A note, link or
    credential session carries one item (`409 one_item`) of bounded size (`413 item_too_large`);
    the file types and the largest file apply to files only; the password and the CAPTCHA gate
    every kind.
  - Taken in, each becomes a Drive item of its own kind (its kind in the sealed metadata; the
    server sees the kind of a send, never its content), in the link's folder, named after a note's
    title or "Note / Link / Credential from <date>". The Drive lists it with an icon and a label
    and opens it with the regular shares' viewers (`public/js/typedview.js`, shared with the share
    page): a note rendered, a link under the user's URL rules, a credential masked. Download saves
    text (`.md` / `.txt`; a link as `.txt`, never a `.url` shortcut; a credential as a plain-text
    export after a confirmation); Share… carries them as what they are (the manifest's `item`),
    where the account may share links and credentials.
  - The server keeps each item's declared kind sealed with it until it is taken in; the user's
    browser fails an item whose sealed kind differs from what its session declared, that exceeds
    its kind's cap, or that the link no longer accepts under the user's role as it is then
    (reason `kind` / `size`). Viewers never render an item past its kind's cap. A Drive share
    records what the sender's role allowed (`kinds`) and its recipient's page shows items as what
    they are only where that allows (otherwise as plain files). A credential leaves in plain text only on its own, after a confirmation
    (in the Drive and on a Drive share's page); ZIPs leave credentials out.
  - Adding files, links or credentials to what a link accepts weakens it: it needs the account
    password or a passkey, and an API key cannot do it (`403 step_up_required`, `weakens:
    ["accept"]`). Adding a note does not.
  - The CLI does not send to Receive links; it is unchanged.

- **Drive quota: bytes uploaded** (`drive-bytes`, Admin → Roles → Quotas → Drive → "Bytes
  uploaded"; README "Quotas", docs/DRIVE.md §5, docs/API.md). The bytes uploaded to the Drive
  per period: each file's size, counted with the file (`drive-upload`, unchanged) in one atomic
  Directory step when its upload is reserved (one refused, neither counted), and given back as
  `drive-upload` is (the Drive refuses the file, or the upload is deleted unfinished or purged).
  Web only, as `drive-upload`; not for the public account; files taken in from Receive links are
  not counted. Its max is in bytes, up to 1 PiB, and the editor takes it in MiB or GiB; the
  refusal and the Account page name a size: "Quota reached: 1.0 GB uploaded to the Drive per
  1d."
- **The Drive follows the role's file rules** (docs/DRIVE.md §5, SECURITY.md "File policy"):
  the file-type rules (`fileTypeMode` / `fileTypeRules`) and the folder-depth limit
  (`maxFolderDepth`) now apply to Drive uploads, new folders and moves, not only to Drive
  shares. An upload declares its file's type, as a file share does (`types`, checked at the
  reservation: `400 declaration_required`, `403 file_type_not_allowed`), and the server enforces
  the rule from the stored metadata too: the sealed name's extension and the metadata's type,
  which the Worker opens in memory to check the seal (never logged), must pass the rules and
  match the declaration, so a modified client that declares a false type is refused (uploads and
  take-ins alike); the depth is checked by
  the Drive against its own tree (`403 folder_too_deep`). The Drive page checks both first and
  says why (a whole batch before any of it is sent). Files taken in from a Receive link keep the
  link's own type rules and are held to the role's Drive rules too (a refused type is recorded as
  failed with the new reason `type`; paths are flattened to the depth limit), so a Receive link
  cannot bring into the Drive what the role refuses there. Files already in a Drive are not
  deleted by a new or tighter rule.
- **Admin → Import / export: user id lists for the account export and import**, as the Drive
  keys card has had (`public/dashboard/js/id-list.js`, now shared by both cards). Export: each
  row shows the user's id; a search by user name or id, Select all / Deselect all of the rows
  shown, "Choose from an id list" (an uploaded plain text list, one id per line, or a JSON
  array) and "Download the chosen ids"; the per-part checkboxes and their bulk toggles are as
  before. Import: each row shows the id in the file; an uploaded id list takes over the accounts
  it names (by the id in the file, or the id of the account here that the row updates) with
  their usual action and skips the others, and "Download the ids in the file". An id list holds
  user ids only, never keys, passwords or other credentials, and only chooses rows: an existing
  account still only gets its role set and passkeys added. The export document now carries each
  user's id (`users[].id`, `owner.id`: the id on the exporting server); an import accepts it and
  never uses it (a created account gets a new id).

- **Admin → Import / export → Drive keys: Verify** (docs/DRIVE.md §3.2): a saved Drive keys
  export is decrypted in the browser and checked against this server, read-only, after the
  step-up (`POST /api/private/admin/keys/export/verify`): the root MEK, the sub-MEKs (match,
  differs, unknown here, missing from the file), each user's salt and KEKs (as check values,
  never the keys), and each DEK on its file's first chunk; a date shows whether the file holds
  the sub-MEK in effect then. The result list ends in "Everything in this file matches this
  server" or what does not; no key is returned, and the admin audit (`keys.export_verified`)
  has the root's fingerprint and counts only. The export's labels now say that "Download the
  chosen ids" saves a list of user ids with no keys, and what "Build the export" and "Encrypt
  and download" each do.

- **"Receive" links (reverse shares) get the options of regular shares** (docs/REVERSE.md §5,
  §6.1; SECURITY.md "Reverse shares"), each a role option (Admin → Roles, Drive; the server
  checks every one on create and on every change, API keys included):
  - **No expiry** (`reverseNoExpiry`, off in the Default role, allowed for the owner): the link
    takes files until it is revoked. Stored as a far-future time in the share index and the
    Drive, shown as `expires: null` by the API and as "No expiry" in the Drive, My shares and
    Admin → Shares, which filter by it (`expiry=none`). An ended one leaves the index 30 days
    after it ended (the index's new `ended` column).
  - **Views** (`reverseMaxViews`, `reverseAllowUnlimitedViews`): a view is one upload session
    granted (after the link proof, the CAPTCHA and the password); once they are used up the link
    takes no new sessions (`410`), sessions already started finish. Counted atomically in the
    user's Drive; failed starts spend none.
  - **Their own longest expiry** (`reverseMaxExpireSec`, instead of the regular `maxExpireSec`;
    migration 17 copies each role's `maxExpireSec` into it, so no link can live longer than
    before), the **uploader password** as a mode (`reversePassword` allow / require / off, with
    `reversePasswordDefault`), and **editing** (`reverseEdit`).
  - **Edit in My shares** (`PATCH /api/private/shares/:id`): the expiry (extended, made none, or
    given one), the views (raised, or lowered never below those used), the limits and file
    types, the CAPTCHA, and the password and the note (both sealed in the browser with the
    link's key and not sent in plain text; like the uploads, not end-to-end). A change that
    weakens a link (its password removed or changed, the CAPTCHA off, no expiry, unlimited
    views) needs the account password or a passkey, as creating one does, and API keys cannot
    make it (`403 step_up_required`); tightening works everywhere. The same Edit is in the Drive's
    Receive… and Shares dialogs. The owner can change a link's views and expiry in
    Admin → Shares. The Drive's Receive… dialog offers "No expiry", views and the role's password
    mode. Links made before keep working: no views limit, their expiry and their password.

- **Quota kinds for every share, the Drive and Receive** (Admin → Roles → Quotas; README
  "Quotas", docs/API.md). The kind select is grouped: *Outgoing shares* — All outgoing shares
  (`all`, unchanged), Notes, links and credentials (`text`, unchanged), Notes (`note`: plain
  text, Markdown or code), Links (`url`), Credentials (`secret`), File and Drive shares (`files`,
  unchanged), File shares (`file`), Drive shares (`drive`); *Drive* — Files uploaded
  (`drive-upload`: each file uploaded, a folder upload counting every file, not files taken in
  from Receive links; given back when the Drive refuses the file or the upload never completes,
  deleted unfinished or purged); *Receive* — All receive (`receive`), New links
  (`receive-link`) and Uploads received (`receive-upload`: each upload session that sends files
  through one of the user's links, counted for the user when it starts and given back when it
  does not start or ends having sent no file). `all` never counts Drive uploads or Receive.
  - Existing quotas keep their reach: `all`, `text` (notes, links and credentials) and `files`
    (file shares and Drive shares) count exactly what they counted before; the new kinds narrow.
  - At a `receive-upload` or `receive` quota the uploader gets `429 not_accepting` ("This link
    can’t accept more uploads right now. Try again later."), with nothing of the quota.
  - The Public role's editor offers, and the server accepts for the public account (the API and
    imports), only the outgoing kinds it can use (notes, links, credentials, file shares). Drive
    shares, Drive uploads and Receive are web-app only: their quotas take no "API only" channel
    (the editor disables it; the server refuses it).
  - `quota_exceeded` messages name each kind ("Quota reached: 3 uploads received per 1d."), the
    Account page lists them the same way, and `quotas.updated` in the audit spells every quota
    out ("10 notes per 1d via the API [note]"), in several entries when the list is long.

- **WCAG 2.2 conformance audit** ([docs/WCAG22.md](docs/WCAG22.md)): every success criterion at
  A, AA and AAA with a verdict, evidence and the pages it concerns. On that evidence (Chromium,
  automated and manual checks; screen-reader testing by people still to come) the pages meet
  WCAG 2.1 and 2.2 A and AA (with the optional Turnstile CAPTCHA, a third-party component,
  covered by a statement of partial conformance), and 23 of the 31 AAA criteria (not 2.2.3, no
  timing: expiry is the product; not 3.1.5, reading level; six do not apply). The default
  accessibility statement
  now says so, with its limits. Fixes and additions:
  - a warning two minutes before a session times out, with "Stay signed in" (any number of
    times); after it ends, "Sign in again" in a new tab keeps what was typed; the login page and
    Account state the timeouts (2.2.1, 2.2.5, 2.2.6);
  - a warning five minutes before a file share's download window closes, with "Keep downloads
    open": `POST /api/file/:id/extend` with the download grant moves the window's end by the
    role's window from now, at most ten times per grant, never past the share's expiry, spending
    no view; after the last view the purge waits for an extended window (2.2.1), so a one-view
    share's ciphertext can stay up to ten more windows after its only view (SECURITY.md); an id
    that was never a share counts as invalid, as on the chunk route, and is answered from the
    share index without creating a FileShare object;
  - "Stop the countdown" on every per-second countdown; toasts stay until the next key press or
    click (2.2.2);
  - wherever the Turnstile CAPTCHA is used, the note under its button links to the
    site's contact for anyone who cannot complete it (3.3.8);
  - text colours at least 7:1 and field borders at least 3:1 in both themes; the dark theme's
    error toast (3.7:1) fixed (1.4.3, 1.4.6, 1.4.11);
  - visible labels on every field, with the same words as the field's name (2.5.3, 3.3.2);
  - the accessibility button no longer hides the focused control (the page scrolls it clear,
    the toast moves up, the button sits below dialogs); a shorter editor on short screens
    (2.4.11, 2.4.12); focus outlines in forced colours (2.4.7);
  - dialogs and the settings panel close on click, not on mouse-down (2.5.2); 24 px Drive
    checkbox targets (2.5.8); reflow fixes at 320 px (1.4.10); view titles (2.4.2); a view
    change keeps focus the person placed (2.4.3); queued admin renders (no duplicate ids);
  - the widget's "Large buttons and links" (44 px) and "Text spacing" modes (2.5.5, 1.4.8);
  - a glossary and a site map on the accessibility page, self-describing link texts and "opens
    in a new tab" notices (3.1.3, 3.1.4, 2.4.5, 2.4.9, 3.2.5); a PDF preview page gives its text.
  - the Drive's notices ("Drive is not ready yet", the owner's "hasn't signed in since the Drive
    was enabled", "not enabled") are announced through the page's status line, which is in the
    page from the start, and the sign-in says "Signing in…" to screen readers while it (and the
    Drive's automatic set-up or unlock) runs (4.1.3); the glossary's "Drive" and "Escrow key"
    say that the administrator can open every Drive with the escrow key (3.1.3);
  - the impersonation banner no longer covers the focused control at 400 % zoom (2.4.11); the
    Drive page's footer is its contentinfo landmark, as on every other page (1.3.1);
  - the intermittent 2.4.12 overlap at 320×256 explained (a text field already in view is left
    under the accessibility button by the browser and scrolled clear by the page in the next
    frame, before it is painted); the audit's check now waits for that frame, tests every point
    of each overlap with a fixed or sticky element, also at 400 % zoom, and fails on any (2.4.12).
  - the owner recovery kit, starting over and the archive (from `main`): each kit form's message
    is said by a status line that is in the page before it; the passphrase warning describes the
    passphrase field while it shows; the kit card and the archive box are regions named by their
    headings; the reset's "unlock your own Drive" field has a visible label and its "Continue
    without unlocking" box is described by its warning; the create-user form's Drive note is also
    said through the toast; a user's automatic move to a reset's escrow key is said by the Drive
    page's status line, which now stays in place through the unlock screen and the Drive (4.1.3,
    1.3.1, 3.3.2); starting over and deleting the archive mark the field at fault invalid and
    described by the error (3.3.1); after an unlock, a restore, a start over or an archive
    deletion, focus goes to a heading instead of the page (2.4.3).
  - a toast at the top of a short screen no longer covers the controls Tab reaches next: it
    moves to the other edge, or is put away when it would cover focus at both (2.4.11, 2.4.12).
  - reverse shares (from `main`): the uploader page's "Sent …" and the Drive's received-files
    line are said by status lines present from the start, and the unlock screen's count of waiting
    files by the page's status line (4.1.3); the uploader's drop zone is a named group, not a Tab
    stop, its buttons being the keyboard way (4.1.2); focus goes to "Cancel" while sending and to
    "Choose files" after it (2.4.3); an ended or paused link names itself in the page title (2.4.2);
    the uploader page has the same footer as every other page, after `<main>` (1.3.1, 3.2.3); in the
    "Receive files…" dialog the file-type list has a visible label (3.3.2), "Copy link" keeps its
    words in its name (2.5.3), "Accept files for" is no longer cut off with text spacing (1.4.12),
    and "Show more" in the review keeps focus (2.4.3); the CAPTCHA's container draws a focus
    ring while focus is in the widget, set from the page's focus changes as `:focus-within` does
    not match inside the widget's frame (2.4.7).
  - the Drive: received files taken in while a folder opens no longer send it back to the folder
    being left (the refresh re-lists the folder being opened and keeps its focus) (3.2.5, 2.4.3).
  - a Drive dialog opening puts away a toast from before it, and received files taken in while a
    dialog is open raise none (the Drive's status line says it), so nothing outside the modal
    dialog is shown or read.
  - contrast in every frame: entrances, dialogs, the view exit and the install banner move without
    fading; the countdown's last minutes are bold instead of pulsing to half opacity; the theme
    flip's wave has a hard edge and the fallback switches palettes at once (1.4.3, 2.2.2);
  - buttons (`.cta`, `.send`) and the toast no longer fade their opacity: a button enabled (the
    CAPTCHA passed, files chosen) was drawn part-way transparent for 0.2 s, 2.24:1 on "Send
    files" in the light theme (1.4.3); the CAPTCHA check page (`/check/`, from `main`) has every
    page's footer, the glossary link included, after `<main>` (1.3.1, 3.2.3); Admin renders start at
    once when none is in flight, so rows being replaced cannot be clicked (3.2.5).
  - security review of this change (F1–F8):
    - a sender creating a view-limited file share is told that downloads can outlast the last
      view (the recipient can keep a download window open up to 10 more times, never past the
      expiry), and every extension is recorded in the share owner's activity log
      (`share.download_extended`: share id, extension number, new end);
    - `POST /api/file/:id/extend` has its own per-network limit (`download-extend`, 120 calls per
      10 minutes, then 429 `rate_limited`), checked before the Directory, so a loop of calls past
      the tenth extension (409) ends there; a 409 or a 410 on a share that has ended, with a
      valid grant, is never counted as invalid;
    - when the grant table is full, a grant living on an extension gives way to a new open;
    - the session and download-window warnings go by the server's clock (`now` in `/me`'s
      `session` and in the open and extend answers);
    - when a session ends the page locks (hidden and inert; the tab's Drive keys cleared, an open
      Drive closed, password fields emptied, the toast put away; "Log out" replaces "Close") and
      unlocks only for the same user; another account signed in meanwhile gets "session changed";
    - the CAPTCHA's focus listeners are shared and removed with the last widget (`remove()`);
    - toasts, with their text, also go when the page is left or its history moves.
  - Admin: a tab opened while the page is still loading stays open (the default tab no longer
    replaces it when the loading finishes) (3.2.5).
  - the light theme's red (destructive actions and errors) is a shade darker, so an armed or
    hovered danger button ("Start over", "Delete archive", every "click again to confirm") keeps
    7:1 on its tinted fill (6.5:1 before) (1.4.6).


- **Drive keys and client library** (docs/DRIVE.md §3, §6, §7): `public/js/drivekeys.js` (the
  Drive key, its sub-keys, sealed fields bound to their node, and the `pw`, `recovery`,
  `passkey` (WebAuthn PRF) and owner `escrow` wraps), `public/js/driveclient.js` (unlock, list,
  folders, chunked uploads, rename, move, delete, download, ZIP, Drive shares) and
  `public/js/refsmanifest.js` (manifest v3). Sign-in unlocks the Drive for the tab with the
  password, a passkey's PRF output or a recovery code (never blocking the sign-in); Account
  keeps the wraps current on a password change, new recovery codes and added or removed
  passkeys; an owner's password reset re-keys the user's Drive through the escrow when the
  owner's Drive is unlocked; sign-out forgets the key. The viewer and downloads read manifest v3
  (Drive shares: per-file keys and chunk sequences) for preview, single-file download and ZIP.
- **Drive UI** (`/dashboard/drive/`, docs/DRIVE.md §8): the folder tree (collapsed by default,
  + / − per folder, lazy per-folder loading) beside the selected folder's content (name, size,
  modified) with checkbox selection; toolbar: upload files, upload folder, drag and drop, new
  folder, rename, move (a folder-tree picker), delete (confirmed; shares of it end), download
  (file raw, folder as ZIP) and **Share…** (views / ∞, expiry, password, "Delete now", label;
  the link with copy and QR); each item's shares with revoke; a capacity bar; upload and
  download progress with cancel; an unlock prompt (password, passkey with PRF, recovery code);
  "Drive is not enabled for your account" when the role has none; on phones the tree folds
  into a "Folders" toggle. The nav shows **drive** only when the profile's
  `caps.driveEnabled` is true. The page runs on the real Drive client (docs/DRIVE.md §8.1):
  the unlock prompt becomes "Set up your Drive" (password only) the first time, offers the
  passkey only when one has a Drive wrap (the sign-in's PRF helper), and returns when the tab's
  key does not open the Drive; transfers report bytes and can be cancelled (downloads too);
  dropped empty folders are kept; an upload whose name the folder already has becomes
  "name (2).ext"…; while the owner impersonates a user whose Drive has no key yet, the page says
  "The user hasn’t signed in since the Drive was enabled" instead of the prompt; the manual end-to-end
  script is `test-e2e/drive-int.mjs` (see `test-e2e/README.md`, not run in CI); Share… applies
  the file-type and folder-depth policy and can allow in-browser viewing, like the composer. My shares and Admin → Shares name drive shares
  "drive".
- **Reverse shares ("Receive files…")** (docs/REVERSE.md): a user whose role allows it
  (`reverseEnabled`, off by default, with the Drive; `reverseMaxActive`, default 10;
  `reverseMaxBytes`, default 1 GiB; Directory migration 14 fills the Default role) creates an
  upload link on a Drive folder: `/r/<id>#<key>`, with copy and a QR code. Anyone with it can
  send files and folders into that folder without an account (file and folder pickers, drag and
  drop, progress, the human check when Turnstile is on, Send disabled until it passes). Each
  link has its own ECDH P-256 key pair made in the user's browser: the public key is the link's
  fragment, the private key is sealed with the user's Drive key. The uploader's browser encrypts
  each file like a Drive file and seals its path, type and key to the link's key; the user's
  browser re-wraps received files into the Drive when it is unlocked (folders rebuilt from the
  paths, clashing names get " (2)"). Options: expiry, most files, most bytes, largest file, file
  types, a label, an encrypted note to the uploader, and an optional password that only gates
  the uploader (Argon2id proof; the server keeps a hash; wrong ones count against the network's
  Guard and are logged). Creating a link needs the account password or a passkey; the owner
  acting as the user can do everything the user can, logged as the user's own action with the
  owner as the real actor in the admin audit. Everything counts towards the Drive's capacity,
  including a received file's sealed path and metadata until it is re-wrapped. Links are listed
  in the dialog, in My shares (type "receive", files received) and Admin → Shares (filter
  `reverse`); revoking, expiry, an admin lock or deleting the folder stops uploads, and files
  already received stay. Logged: `share.created` / `share.revoked`, `reverse.received` (count
  and size only), `reverse.bad_password`.
- **Folder tree component** (`public/js/tree.js`): a WAI-ARIA tree (roving tabindex, arrow
  keys, Home/End, Enter/Space, `*`, type-ahead; `aria-expanded`/`aria-selected`/levels) with a
  right-pane folder browser. The composer's file list and the recipient's file view now show
  folders this way — collapsed by default, a folder's content on the right, breadcrumbs back
  up — keeping remove, type, preview, per-file / per-folder download and download-all. The
  composer's file list is no longer a live region (it re-renders on every change); its total
  line announces changes instead, and removing an item keeps focus on the next row.
- **API key scopes `read` and `manage`** (#31): besides creating (`notes`, `files`, `policy`),
  a key can list the user's shares, one share and its read receipts (`read`: `GET
  /api/private/shares`, `GET …/shares/:id` — new — and `GET …/shares/:id/opens`) and label,
  extend and revoke them (`manage`: `PATCH …/shares/:id`, `POST …/shares/:id/revoke`) — only
  the key user's own shares, under the owner's share locks and, for extensions, the account's
  API limits; changes made with a key are logged with its id. Both are opt-in: a key created
  without a choice still gets the creation scopes only. Account → API keys and Admin → Users
  offer and list the new scopes; exports and imports carry them. `docs/API.md` and the
  Account page's "Using the API" help document every endpoint a key can use, with examples for
  every use case in curl, Node.js and Python (new `examples/api/create-files.mjs` /
  `create_files.py` for the file upload flow, `--encrypt-only` modes for curl, and
  `shares.mjs` / `shares.py` for list, show, receipts, label, extend, revoke, policy and delete;
  the Python examples use `requests`). The CLI gains `secbin list`, `show`, `receipts` (`read`)
  and `label`, `extend`, `revoke` (`manage`). Existing keys keep exactly the creation scopes
  they had. A `read` key can fetch read receipts, which include the recipients' network
  addresses and locations when the owner enables those details.

- **The owner's own activity-log retention** (Admin → Roles → Owner → "Your activity log"):
  `log.ownerMaxAgeSec` and `log.ownerMaxEntries` limit the entries about the owner and those the
  owner made (admin actions, impersonation). Both default to keep forever, as before. Server-wide
  configuration changes (settings, roles and limits, IP rules, exports and imports, Turnstile,
  the public account's configuration) are still never deleted automatically; clearing by hand is
  unchanged. The settings travel in the settings part of an export and are validated on import.
- **Drive — server** ([docs/DRIVE.md](./docs/DRIVE.md)): a `Drive` Durable Object per user (folder
  tree, key wraps, share references; wrangler migration `v3`); the `/api/private/drive*` routes
  (session only: folders, files with exact-size chunked uploads, move with cycle refusal, rename,
  recursive delete that frees capacity, removes the R2 objects and ends the shares, key wraps, the
  owner's escrow key); the owner's escrow route (`POST /api/private/admin/drive/escrow/<userId>`,
  with a reason, logged `drive.escrow_used`) and password re-wrap after a reset
  (`PUT /api/private/admin/drive/keys/<userId>`, logged `drive.pw_rewrapped`); the pending-upload
  purge; and **Drive shares**: file shares that reference Drive files (`refs`;
  `GET /api/file/<id>/chunk/<ref>/<i>`), kind "drive" in My shares and Admin → Shares, with the
  same limits and quotas as file shares. Role options `driveEnabled` (off by default),
  `driveMaxBytes` (1 GiB) and `driveMaxFileBytes` (Admin → Roles → Drive; Directory migration 13).
  Admin → Users shows each user's Drive usage. Deleting an account deletes its Drive. Drive
  content is not exported.
- **Export / import everything, part by part.**
  - System parts: settings, roles, IP rules, the panel's Turnstile keys (with the secret; off by
    default) and the public account.
  - Per user: credentials, role, API keys (the same keys keep working), passkeys (only on the
    same hostname; with the "Password and passkey" choice) and recovery codes (hashes; they work
    anywhere). Passkeys and recovery codes are separate parts, each optional.
  - The owner is one of the rows: its passkeys and recovery codes can be exported (off by
    default), never its password, role or API keys.
  - Each part is ticked per user, in a table of users × parts with "Select all" / "Deselect all"
    for the users and for every part, when exporting and again when importing, with a note on
    what each part holds.
  - The preview lists, per account, what changes and what is skipped and why (a passkey already
    registered here, one that does not fit the role's passkey limit, recovery codes that belong
    to another account), and warns about keys that keep working, passkeys from another hostname
    and Turnstile keys; API keys that already belong to another account are refused.
  - Each passkey carries the WebAuthn user handle it was registered under, so a passkey added to
    an account with another handle still signs in without a username.

- **Link rules say the form of a scheme:** `scheme:name://` allows links written with `//`
  (http and https are always written this way) and `scheme:name:` allows links without it
  (`tel:`, `mailto:`). A bare `scheme:name` is no longer accepted. Saved rules and older
  export files are rewritten to allow exactly what they allowed (`scheme:tel` → `scheme:tel:`,
  `scheme:https` → `scheme:https://`, other schemes → both forms).

- **Roles** (Admin → Roles, next to Users). Every user has exactly one role, Default unless
  given another.
  - **Owner** is built in and locked (everything allowed, no limits; the owner's only).
  - **Default** is built in, cannot be deleted, and holds a value for every option.
  - **Custom roles** can be created, renamed, duplicated (Default too) and deleted. Their users
    return to Default when a role is deleted. Options a role leaves on "same as Default" follow
    Default.
  - A role covers every limit, the API restrictions, quotas (Default's or its own list), viewer
    rules and the largest previewable file, the password policy, passkeys (mode and how many)
    and user session timeouts.
  - The role is chosen per user in Users. The Defaults & quotas tab is gone (its options are
    the Default role's), and so are all per-user settings.
  - **Upgrade note:** existing per-user overrides are removed (one audit entry says how many).
  - Export and import carry roles: `system.roles`, and each user's `role`. Export files from
    before per-user parts (`config`, the combined passkeys-and-codes part) are refused.

- **Account:** change your username; edit an API key's name and scopes; confirm changes with a
  passkey instead of the password; how you sign in is a choice under Passkeys: "Password or
  Passkey" (default) or "Password and passkey". A recovery code always signs in on its own.
- **Admin → Users:** the owner creates, edits and revokes a user's API keys (a new key is shown
  once).
- **Signed in:** opening the home page or the login page goes straight to the dashboard.
- **Footer:** "Private · Encrypted in your browser · Notes & files" appears once, in every page's
  footer, the same on every page (it was in the page body, and differed between pages). That
  notes and file shares are end-to-end encrypted is said where it applies: the landing page, the
  composer's introduction, the viewer (a note; a file share; a share from a Drive, which is
  not end-to-end) and the glossary ("Encrypted in your browser", "End-to-end encrypted").
- **Link rules editor:** the tester is always shown, including while the rules are inherited. It
  names the rule that allows a link, or says why it is refused (e.g. an incomplete `https://`),
  and flags patterns that are not anchored. A help panel explains schemes and the regex engine
  (JavaScript `RegExp`, case-insensitive, matched against the whole link). The default is
  unchanged: http and https only.
- **Admin → Users** no longer lists the owner (whose account is on Account).
- **Admin → Public access** no longer offers settings that cannot apply to the anonymous account
  (API keys, read receipts, log limits, password policy, passkeys); the server refuses them too.
- **Admin → Security → Human check:** set or remove the Turnstile site key and secret key in the
  panel (with your password or a passkey). The deployment's keys still win.
- **Passwords the owner sets** (setup, the owner's own, a new user's, a reset) no longer follow the
  password policy, which applies to users changing their own. The length counts every
  character as typed. The impersonation banner is shorter.

- **Progress bars for previews and downloads:** viewing a file opens the preview at once, with a
  bar and percentage while it is fetched and decrypted, then a busy "Preparing the preview…"
  step until it shows. Downloads use the same bar and finish at 100%. Screen readers hear it
  once per quarter, not on every change.
- **Accessibility (WCAG 2.2 AA):**
  - Skip links and a focusable main landmark on every page.
  - Fixes from an axe-core audit: labels for the admin number fields, keyboard-focusable
    secret boxes on setup, 24 px checkboxes, a darker "ok" colour, and underlined links in text.
  - A **Hebrew/English accessibility preferences widget**: high contrast, text size, readable
    font, stop animations, focus highlight, and mark headings or links.
  - An **accessibility statement** at `/accessibility/`, edited as a whole under Admin →
    Settings → Accessibility (title, commitment, standard and status, review date, what has
    been done, known limitations, reporting contact, coordinator): plain-text, validated
    settings, English only by default, with an optional second language (code and direction).
    It travels in the Settings part of an export.
- **Passkeys:** sign in with a passkey instead of a password (no username needed), or require one
  after the password; up to 10 per account. The first passkey comes with 20 one-time recovery
  codes that work wherever a passkey does. The admin decides per user or globally whether passkeys
  may sign in alone, only as a second step, or not at all, and can remove a user's passkeys. The
  server verifies WebAuthn itself (origin, RP ID, user verification, signature, counter; no
  dependency).
- **Cloudflare Turnstile (optional):** when `TURNSTILE_SITEKEY` and `TURNSTILE_SECRET` are both
  set, login, password changes and anonymous share creation need a human check, usually
  invisible. The server verifies each token once, for this hostname and that form's action,
  and refuses the request if Cloudflare cannot be reached. The widget's script is allowed only
  on the pages that show it; `/p/*` links keep the strict policy.
- **API key scopes and REST documentation:** each key is limited to any of notes, files and
  policy (chosen at creation, shown in Account and the admin's key list; `403 scope_denied`
  otherwise). Account has an "Using the API" section with a curl example; `docs/API.md` and
  `examples/api/` (Python and Node) show how to create an encrypted note without the CLI.
- **Read receipts:** every open of a share is recorded; My shares shows each open's time, plus
  the address, location, browser, system and languages where the admin allows it per account
  (the admin always sees all). Kept as long as the activity log; recipients are told before
  opening.
- **Activity-log retention and clearing:** global maximum age and size (Settings) and per-user
  limits; entries about the owner are exempt. The owner can clear all entries, one account's or
  those older than a date (password required; leaves no record).
- **URL rules for link shares** (Defaults & quotas, or per user): allow schemes such as `tel:`,
  `mailto:` or `sms:` besides http(s), or only links matching regular expressions, with a live
  tester in the editor. Checked by the sender's browser and the CLI (new
  `GET /api/private/policy`); dangerous schemes (`javascript:`, `data:`, `file:`…) are refused on
  both sides whatever the rules say.
- **Password policy** (Defaults & quotas, or per user): minimum length and required character
  classes (upper-case, lower-case, digit, symbol), shown next to every password field and
  enforced in the browser (the server never sees passwords). The owner keeps the built-in policy.
- **Public (anonymous) sharing**, off by default (Admin → Public access): a built-in `(public)`
  account with its own limits and quotas (notes only, ≤ 10 views, ≤ 7 days and 10 per day by
  default); a composer on the home page with an editable notice and the delete token on
  success; counting per browser tracker (cookie + ETag + localStorage + IndexedDB, self-healing,
  blocked on unresolvable conflicts, new senders rate-limited per network on first
  creation), per network, or both (permissive / restrictive); tracker administration (unblock, block, forget).
- **Works without WebAssembly** (iOS/macOS Lockdown Mode, including Chrome on iOS): Argon2id
  falls back to a pure-JavaScript build (@noble/hashes, pinned) with the same output, and a
  progress bar shows slow derivations.
- **Encrypted admin import/export** (Admin → Import / export): system configuration and/or
  selected users, part by part (see "Export / import everything"), never the owner's password,
  sessions or shares; encrypted in the browser with a passphrase; imports are decrypted locally,
  previewed, then applied all-or-nothing, with per-user skip/create/update/rename. Both require
  the owner's password again.
- **Link and credential shares** (`fmt` `url` / `secret`), off until the administrator allows
  them globally or per user:
  - links: http(s) only, no embedded credentials; the recipient sees the real host (punycode,
    look-alike and plain-HTTP warnings) and confirms before opening — never a redirect;
  - credentials: title, user name, password, sign-in URL, notes and a one-time-code seed; masked
    until revealed, with copy buttons and live RFC 6238 codes;
  - CLI: `create --fmt url|secret` (credentials from a file, stdin or hidden prompts, never
    argv), `get` prints links without opening them and credentials as escaped JSON or one
    `--field`.
- **"Delete now"**: if the administrator allows it and the sender opts in
  (`--recipient-can-delete` in the CLI), whoever opens a share can delete it for everyone — it
  needs both access proofs, spends no view, is refused while the share is locked, and appears
  in the sender's activity. CLI: `secbin delete --now <url>`.

- **Admin share management** (Admin → Shares):
  - every user's shares, filtered by users, type, status, label, lock, and a creation or expiry
    date or date/time range, with correct totals;
  - the owner can change labels, views and expiry, revoke, and lock/unlock;
  - a locked share is frozen for its sender and its delete token;
  - direct admin changes are logged in the audit log but not in the user's own activity.
- **File policy**, globally or per user (Admin → Users → Manage, or Defaults):
  - an allow list or block list of file types (`ext:pdf`, `mime:image/*`) and a maximum folder
    depth (which the API channel can only tighten);
  - the composer and `secbin send` check it before encrypting, naming the offending files;
  - the file types and folder depth are declared to the server only when a policy applies
    (see SECURITY.md); the owner is exempt.
- The admin limits editor refreshes its "effective" values after a save.
- **Directory schema migrations**: versioned, idempotent and tested, for Directories created by
  older releases.
- **Installable app (PWA)**: a web app manifest (`/manifest.webmanifest`, `standalone`,
  192/512 and maskable 512 icons generated by `tools/icons.mjs`) and a service worker
  (`/sw.js`) that keeps the static shell available offline. It is network-first, caches only
  same-origin static assets and the landing page in a versioned cache, and never intercepts or
  caches `/api/*`, `/p/*`, dashboard pages or any URL with a query string. Every page shows a
  dismissible **install banner** (Install / Not now on Chromium; "Tap Share, then Add to Home
  Screen" on iOS/iPadOS) that never appears inside the installed app; the dismissal is kept in
  the `secbin_pwa_dismiss` cookie for a year. The CSP gains `manifest-src 'self'`.
- **CI**: GitHub Actions runs a dependency audit, lint, the frozen-vector byte diff, all four
  test projects and the Python vector cross-check on every push and PR. CodeQL
  (`security-extended`) runs on PRs and weekly. Dependabot is grouped and weekly.

- **Accounts, built in** (Cloudflare Access is no longer required): one owner/admin created or
  recovered at `/dashboard/setup` with the single-use `AUTHN` secret (a new value is needed for
  every recovery; setup is cleanly disabled when `AUTHN` is absent). Users, disable/enable,
  delete (optionally revoking their shares), password reset without the current password,
  unlock, and **log in as** (impersonation) with an audit trail that records the real actor.
- **Sessions**: `__Host-` HttpOnly SameSite=Strict cookie holding a JWS (HS256, `SIG`) inside a
  JWE (A256GCM, `ENC`); admin-configurable idle and absolute timeouts; server-side revocation.
- **Capabilities, limits and quotas** per user and as global defaults (notes/files on/off, max
  views, unlimited views, max expiry, max share size, max file size, max files per share,
  viewer, API keys + max count); quotas per s/m/h/d/mo/y for all/notes/files; API-channel
  limits and quotas that can only narrow.
- **API keys** for the CLI (creation endpoints only), managed on the Account page.
- **Encrypted file and folder sharing** on R2: drag-and-drop of files and folders, file and
  folder pickers, auto-detected (editable) MIME types, packed + padded chunked stream so the
  server learns no names, types, structure or per-file sizes. Recipients browse a tree and
  download any file raw, any folder as a ZIP, or everything.
- **Safe in-browser viewer** (admin-governed, sender opt-in): text/Markdown/code, sniffed raster
  images with pre-decode size checks (SVG never rendered), hardened vendored pdf.js (no PDF
  scripting), audio/video.
- **My shares**: list, labels, raise views / extend expiry within limits, revoke now.
- **Brute-force protection**: per-IP scopes for login, setup and invalid fetches (unknown ids,
  wrong `#` keys, wrong passwords, bad grants/tokens), admin-configured rules, blocks/tracking
  view, manual IPv4/IPv6/CIDR allow/block rules, account lockout (owner exempt),
  `DISABLE_BFP` / `DISABLE_BFP_SETUP` kill switches.
- **Access proofs**: the server verifies link and password proofs before releasing ciphertext or
  spending a view; heads no longer contain the wrapped key (no offline password guessing from a
  link alone).
- Footer links: **Source** and **Threat Model** (kaerez/bin).
- Test projects for Node (`test-node/`) and new workerd suites (notes, files, auth, admin,
  shares); vectors cross-checked in Python.

### Fixed

- **Drive → Receive…** stays disabled until the open folder has listed: clicked before, it opened
  a dialog titled "Receive into “”".
- **Admin → Users** no longer lists the users twice when the panel is rendered again while a
  render is still loading (e.g. the tab clicked just after creating a user).
- **Admin:** global settings (share-size cap, viewer switch and size, limits, quotas) never apply
  to the owner; the owner's own password can no longer be reset from the admin UI/API (use
  Account); every limit and setting shows its default, and "Max API keys" can be "no limit";
  expired, used-up, revoked or deleted shares no longer count as invalid fetches; the settings
  explain per-IP protection versus account lockout; IP rules accept ranges (`a-b`) as well as
  CIDR; every save confirms with a clear toast (errors in red).
- **Admin shares filter with many users:** filtering the admin share list by about 100 or more
  users no longer fails with a server error (SQLite's bound-parameter limit). The user ids are
  now bound as one JSON array parameter, and the server takes up to 500 of them (before, only
  the first 100 counted); order, totals and paging are unchanged.
- **iOS:** icons no longer blow up to full width when a stale stylesheet is served (intrinsic
  SVG sizes), and the service worker now always revalidates static assets with the server
  (cache version 2 drops the old cache).
- **Accessibility (from an audit of the Chromium accessibility tree, axe-core, keyboard-only
  use, forced colours, 320 px reflow, reduced motion and right-to-left text, #29):**
  - **Landmarks and structure:** one `main`, `banner`, `contentinfo` (the footer now follows
    `<main>`) and named navigation on every page; column headers of action columns are named
    ("Actions", for screen readers only).
  - **Tabs** (composer and admin) follow the ARIA pattern: one Tab stop, arrow keys (mirrored
    right to left), Home / End, and every tab controls a labelled tab panel.
  - **Password dialog:** everything behind it is inert (no focus, no clicks, out of the
    accessibility tree), Tab stays inside, Escape closes and focus returns to the opener.
  - **Form errors are tied to their fields** (`aria-invalid` and `aria-describedby`, focus
    moved to the field) on login, setup, the share-password dialog, the viewer's password
    prompt and the account's username and password forms.
  - **Focus is kept** when a list or editor re-renders: after Apply / Revoke on My shares,
    after creating, disabling or deleting users and roles, after dismissing the install
    banner; opening a user or role editor moves focus to its heading.
  - **Live regions** exist before they speak and do not chatter: upload, download, preview
    and slow key-derivation progress are announced at the start and at each quarter, and the
    file list is no longer a live region.
  - **Forced colours (Windows High Contrast):** focus rings are outlines (the box-shadow rings
    vanished there), and the selected tab, pressed toggles, the current page and the widget's
    switches keep a visible state.
  - **Reduced motion:** the widget's "Stop animations" now also stops the theme wave, the
    composer's send animation and smooth scrolling started from script, like the system
    setting; admin editors no longer smooth-scroll when either asks for reduced motion.
  - **Widget in Hebrew:** the panel opens next to its button, and the switches are mirrored.
  - **Target size:** checkboxes keep a 24 px target with the widget's "Smaller" text.
  - **Statement defaults:** the review note says what was tested, and the limitation "Not yet
    tested with every combination of screen reader and browser" is removed.
- **Install banner:** a floating, dismissable card placed where the browser's Share button is —
  top on iPad and in Chrome/Edge on iPhone, bottom in Safari/Firefox on iPhone and for the
  Chromium install prompt — with per-browser Add to Home Screen instructions (iOS 26 "⋯" menu
  included).

### Changed

- **"Receive files" is now "Receive"** wherever it is shown: the Drive's **Receive…** button and
  its "Receive into “…”" dialog, the role options, the glossary and the docs (the entries below
  keep the name each release had).

- **My activity shows only the user's own actions:** admin actions on the account (created,
  disabled, enabled, role or limits changed, password reset) are in the owner-only admin audit and
  no longer appear in the user's own activity.
- **Log in as covers the whole account:** acting as a user, the owner can now do everything the
  user can, the Drive included. The Account page shows every form (username, password,
  passkeys, recovery codes, the sign-in choice, API keys) without the "confirm it's you"
  fields: none of these changes asks for a password or passkey while impersonating (the
  owner's session is the authority). A password the owner sets there is exempt from the
  password policy and ends the user's sessions, not the owner's; new recovery codes are shown to
  the owner; existing passkeys and recovery codes stay unless removed. The human check applies
  as on any Account change. The admin panel (and so minting keys for the owner) and nested
  impersonation stay refused, and `POST /api/private/me/reauth` answers 409 `not_needed`. The
  banner stays in view while scrolling, and the Account page is titled with the user's name.
  Impersonation is invisible to the user (the user's activity shows the actions as theirs), and
  the owner-only admin audit keeps the start, end and real actor.
- **Smart Placement and Workers Caching** are on in `wrangler.toml` (and
  `wrangler.toml.example`): `[placement] mode = "smart"` runs the fetch handler where it is
  fastest overall (near the Directory Durable Object for most API calls), and
  `[cache] enabled = true` sets the default caching for fetch-handler responses. No
  per-entrypoint override is set (the default export is the only fetch entrypoint), and no
  Worker response opts into the cache (see Security).
- **Accessibility statement:** the default text and the admin help no longer name a country or a
  national standard; the default states WCAG 2.2 AA as the minimum and AAA wherever possible.
- **Imports never remove or overwrite an existing account's credentials** (the owner's
  included). An account that already exists only gets its role set (if that part is chosen;
  never the owner's) and the imported passkeys added (if that part is chosen); its password,
  disabled flag, recovery codes, API keys, passkeys, "Password and passkey" choice and sessions
  stay. The parts that cannot apply are shown but disabled on the import screen. New accounts
  are created from the chosen parts. "Overwrite" is gone; the per-user action is "create" or
  "update existing", and a mismatch with what is there is refused.
- **The accessibility statement is admin-edited and English only by default** (#35): the text
  moved from `public/accessibility/index.html` into settings (Admin → Settings →
  Accessibility, which also holds the contact and coordinator); the built-in Hebrew version
  is gone (add Hebrew, or any language, as the second language). `/api/config` serves the
  whole statement, which the page renders as text only (no HTML). The statement travels in
  the settings part of an export / import (re-validated there), and "Restore the default
  statement" puts the English-only default back (second language off and cleared; the
  contact and coordinator stay). Settings changes are logged per changed key, long text by
  its length.
- **Role editors:** the Sessions, File shares and Activity log sections carry the same kind of
  explanation as the Owner role, and log retention says "keep forever" rather than "no limit".
- **No Legal / Compliance notes:** removed from every admin screen and from the docs (README, SECURITY, CHANGELOG); `AGENTS.md` now says not to add them.
- **Human check:** while the check is pending, "Waiting for the human check…" is shown under the
  protected button (and linked to it for screen readers) instead of only in a tooltip.
- **Everything an account may do is on its role** (migration 12):
  - the session timeouts, the file-share download window and the unfinished-upload deadline are
    role options; the owner's own are edited on the Owner role;
  - the server-wide share-size cap, viewer switch and largest previewable file are gone (role
    options only; their old values are not carried over);
  - the Viewer tab is gone: each file open carries the sender's role's current viewer policy, so
    turning it off in a role still takes effect on existing links at once;
  - a built-in **Public** role (cannot be renamed, deleted or assigned) holds the public account's
    limits, quotas, viewer rules, counting mode, notice and browser ids; Admin → Public access is
    only the on/off switch;
  - Settings keeps only server-wide items (brute-force protection, lockout, log retention, the
    accessibility statement); export files with the removed settings are refused.
- **Human check:** the buttons Turnstile protects stay disabled until the check has passed (again
  after each use).
- **Password policy:** a role's minimum length may be anything from 1 (12 by default).
- **Export passphrase:** optional, with no minimum length (its strength is the owner's call); with
  none, the export form warns that anyone who gets the file can read it.
- **Security hardening** (items reported by the review sweep):
  - **Disabled accounts** get an explicit `403 account_disabled`, and their session cookie is
    cleared, on every authenticated route. The dashboard sends them to login with a message.
  - **Missing bindings** return a generic `503 not_configured` instead of a 500; the binding's
    name is logged, not returned. File shares no longer wedge when R2 is unbound, and file
    uploads, revokes and deletes check R2 first.
  - **Headers:**
    - Trusted Types are enforced, with a single same-origin `secbin` policy that pdf.js's
      worker now goes through.
    - `upgrade-insecure-requests`.
    - COEP `require-corp` and `Origin-Agent-Cluster`, so pages are cross-origin isolated.
    - A full-deny `Permissions-Policy`.
    - `test-node/headers.test.js` keeps `public/_headers` identical to the Worker's headers.
  - **CSRF:** `Sec-Fetch-Site: same-site` is refused on state-changing requests.
  - **`h()`** refuses unsafe URL schemes in URL-valued attributes.
  - **File shares:** download grants are stored outside the share record. Each client holds at
    most 20 live grants (a reopen replaces its oldest), and a share at most 2000 (`429 busy`).
  - **Password change:** never blocked by a login lockout. Repeated wrong current passwords
    end every session of the account, and each attempt counts against the IP's login guard.
  - **Time cost:** account passwords must use the default Argon2id time cost, so prelogin cannot
    reveal which accounts exist.
  - **My shares:** totals honor the search and status filters.
  - **CLI `update`:**
    - requires an npm provenance attestation and a sha512 integrity hash;
    - downloads exactly the version it verified and checks the tarball against that hash;
    - installs that file with `--ignore-scripts`;
    - `secbin version` reports instead of failing when no verified release exists.
  - **Vendoring:** qrcode-generator is pinned at 2.0.4 via `tools/vendor.mjs`.

- Dev dependencies: vitest 4.1.11, @cloudflare/vitest-pool-workers 0.22.0, wrangler 4.124+.
  npm `overrides` pin patched `sharp` (≥ 0.35.4) and `brace-expansion` (≥ 1.1.21), so
  `npm audit` reports no known vulnerabilities.

- **Argon2id** (64 MiB, t=3, p=1, vendored hash-wasm) replaces PBKDF2 for share passwords;
  account passwords use it too (stretched in the browser).
- Wire labels are now `secbin/v2`; `meta.expires` (absolute) is server-set; expiry presets and
  `never` are gone (1 minute – 365 days).
- `/` is a public landing + viewer; the composer moved to `/dashboard/` (session-gated by the
  Worker); restricted APIs live under `/api/private/*`.
- CSP adds `'wasm-unsafe-eval'` (WebAssembly only), `worker-src 'self'`, and `blob:` for viewer
  images/media.
- The CLI is now **`secbin`** (see `cli/README.md`): no default server, API keys, `--views`,
  `--expire`, `--label`, `send` for files/folders, and file-share downloads.

### Removed

- The composer texts "One-time view" and "Auto-deletes in 24 hours".
- The native `CREATE_RL` rate-limit binding (replaced by the Guard).

## [secbin 1.0.0] — 2026-09-25

Forked from binthere at upstream commit `63e5544` (binthere 1.1.0 plus unreleased changes).

### Added

- **Configurable view limits.** The composer has a *Views* control: any whole number from 1 to
  100 000 (default 1), or ∞ for unlimited. Finite limits use the `BurnPaste` Durable Object,
  which now keeps a remaining-view counter and decrements it atomically on each consume; the
  last view deletes the record. Exactly N consumers succeed under any concurrency. Unlimited
  pastes use KV. Viewers see the remaining count ("2 views left", "last view · now deleted"),
  and the reveal and password screens describe the limit. Wire format: optional `meta.views`
  on create; `meta.left` on reads of view-limited pastes (SPEC §5, §8).
- **Configurable expiry.** An *Expires in* control takes any whole number of minutes, hours, or
  days from 1 minute to 365 days (default 24 hours), sent as a custom duration such as `"90m"`,
  `"24h"`, or `"7d"`. The legacy presets remain valid (SPEC §9). Opened notes show a
  "deletes in …" indicator.
- **Cross-site create guard.** `POST /api/paste` rejects `Sec-Fetch-Site: cross-site` with
  `403`, so a hostile page cannot create pastes using a visitor's Cloudflare Access session.
- `test/limits.test.js` — view-limit, custom-expiry, concurrency, alarm, validation, and
  cross-site-guard tests in the real `workerd` runtime.

### Changed

- **Renamed to secbin** (wordmark *sec*bin, with "sec" in italics), including the page title,
  link-preview name, screen-reader labels, wordmark SVGs, and the theme preference key. The
  cryptographic wire labels (`"binthere/v1"`, `"binthere/v1 kek"`) are intentionally unchanged,
  so existing pastes and the frozen test vectors remain valid.
- The success screen, QR seal label, and composer summary line describe the chosen view limit
  and expiry; *Open link* asks for confirmation only when the paste is view-limited.
- Documentation rewritten for secbin, including Cloudflare Access deployment guidance.

### Removed

- The GitHub star badge, its `GET /api/stars` Worker route, and the page script — the Worker
  now makes no outbound requests.
- The announcement banner and its script.
- Footer links (Source, Threat Model, Security, Developer).
- `/.well-known/security.txt`, upstream `og:url`/`og:image` metadata, `opengraph.png`, and
  `cli-preview.png`.

### Compatibility

- The cryptographic protocol is unchanged (`v: 1`). Upstream binthere clients validate `meta`
  strictly and reject secbin pastes that carry `meta.views`/`meta.left` or a custom expiry.
- View-limited records created before this release carry no counter and are treated as having
  one view left.

## [binthere Unreleased] — upstream, at fork point `63e5544`

### Added

- **GitHub star badge in the topbar** — the mark, a hairline divider, a star and the live
  count, linking to the repository. The count comes from `GET /api/stars`, a new Worker route
  that proxies GitHub's public repo endpoint: `connect-src 'self'` rules out calling
  `api.github.com` from the page, and the proxy is edge-cached (30 min, 60s on failure) so a
  burst of visitors costs GitHub one request per colo rather than one per page load. It is the
  only route that is cached instead of `no-store`, carries nothing visitor-specific, and is not
  part of the paste protocol (SPEC §10). Failures degrade to a plain repository link; the last
  count is kept in `localStorage` so a repeat visit paints the badge with the rest of the
  topbar instead of widening it mid-read.

### Security

- **Oversized uploads are rejected incrementally, not after buffering.** `POST /api/paste`
  now streams the request body and stops the moment the running byte count crosses `MAX_BODY`
  (4 MiB), returning `413` without holding more than one chunk beyond the cap. Previously the
  whole body was buffered via `request.arrayBuffer()` before its size was checked, so a client
  that omitted or lied about `Content-Length` (e.g. a chunked upload) could make the Worker
  materialize far more than the cap in memory. The `Content-Length` check remains as an
  honest-client fast path. No protocol change — same 4 MiB limit, same `413` (SPEC §6).

### Changed

- **The CLI TUI has smoother motion and clearer page transitions.** Animation uses
  deadline-based frame pacing; the logo shine starts immediately and repeats every six
  seconds; menu selection, the intro, ember pulse, and progress spinner were refined; and
  each wizard page clears the viewport before drawing. `BINTHERE_NO_ANIMATION=1` disables
  non-essential motion without disabling colors or keyboard interaction. Result-screen
  shine stops after a terminal resize rather than repainting stale absolute coordinates.
- **The CLI can update a global npm installation.** `binthere update` checks the published
  version and installs `binthere@latest`; `binthere version` (or `binthere -v`) performs the
  version check without changing the installation. Repository checkouts and temporary `npx`
  copies are reported but not modified.
- **The light/dark toggle now repaints the interface instead of snapping.** The flip runs inside a
  **View Transition**: the outgoing frame is held still and the new palette is unmasked over it
  along a soft diagonal, from the toggle in the top-right down to the bottom-left, over 520ms.
  Neither frame changes opacity or transform, so components stay exactly where they are and
  nothing fades in or out. Previously only the page background and body text animated (200ms) and
  everything else — icon strokes, shadows, the grain gradient, `color-mix` borders — snapped.
  Snapshots are composited rather than laid out, so there is no reflow and an open password modal,
  a decrypted note, scroll position and focus all survive the flip. One gotcha worth recording:
  the UA cross-fade blends its two snapshots with `plus-lighter`, which *adds* them, so a light
  and a dark palette bloom to grey inside the wave until it is overridden to `normal`. Engines
  without View Transitions (pre-111 Chromium, pre-18 Safari, pre-144 Firefox) get the same
  repaint as a blanket colour transition, minus the direction; `prefers-reduced-motion: reduce`
  flips outright.
- **The two composer controls animate their state changes.** Pressing **Create link** sends the
  button's arrow out through its clipped edge, and the composer slides left as the success screen
  takes over, so the arrow leads the transition rather than just acknowledging the press (~320ms,
  the two halves overlapping). It is a transition rather than a keyframe, so a failed create
  reverses it — the arrow glides back in and the button re-arms with the note untouched. The
  **Password** lock now shows an open padlock at rest (both states drew the same closed one
  before) and draws the shackle shut with a small pop when enabled. Both are a single class
  toggle in CSS — no animation library, and nothing inline, so the CSP is unchanged.
  `prefers-reduced-motion: reduce` skips the travel and the JS delays that wait on it, and still
  shows the open and closed shackle as distinct states.
- **New favicon.** The tab icon is now a simplified guilloché rosette in iron-gall blue
  on Plate paper — drawn from the same mark as the watermark and seal — replacing the
  pre-Iron-Gall brackets-and-keyhole placeholder. It follows the browser's
  `prefers-color-scheme`, flipping to the light Archive palette on light UIs
  (`tools/favicon-check.html` previews it at tab-strip sizes). PNG fallbacks ship
  alongside it — 16/32px tiles for Safari (which ignores SVG favicons), a 180px
  full-bleed `apple-touch-icon` for iOS home screens, and a real root `/favicon.ico`
  (16+32+48) for agents that probe by convention (it previously fell through to the
  SPA HTML).

## [binthere 1.1.0] — 2026-07-20

### Changed

- **One-time notes can no longer be destroyed by a stray GET.** Destructive burn
  consumption moved from `GET /api/paste/:id` to an explicit
  `POST /api/paste/:id/consume` carrying an `X-Burn-Intent: consume` header. The POST is
  CORS non-simple, so a hostile page can never trigger it cross-origin (the preflight
  fails; `Sec-Fetch-Site: cross-site` senders get a 403), and a plain GET on a one-time
  id — an `<img>` tag, a prefetching proxy, a link-scanning bot — now always returns the
  safe, non-consuming head. Both official clients (web + CLI) use the new endpoint;
  `GET /api/paste/:id?meta=1` now returns a ciphertext-free head for every storage class,
  as SPEC §10 always promised.
- **Two protocol errata, applied to both official clients** (see SPEC §1/§2 errata notes):
  base64url decoding now accepts only the canonical encoding (non-zero padding bits are
  rejected, so no two strings alias to the same id/token/key bytes), and passwords are
  Unicode-normalized to NFC before key stretching, so the same password typed on macOS
  (NFD input) and Windows (NFC) unlocks the same note.
- **Irreversible success-screen actions now confirm.** "Open link" (which consumes a
  one-time note) and "Delete now" are two-step: the first press re-labels the button with
  the destructive effect ("Uses the one view — open?" / "Permanently delete?"), a second
  press within 5 s confirms, and the button disarms on timeout or focus loss.
- **New-note passwords are typed twice.** The password modal gained a confirmation field
  (mismatch is caught before sealing — a typo'd password would permanently lock a
  one-time note) and a practical 128-character cap, enforced with a visible error rather
  than a `maxlength` attribute — silent truncation of a pasted longer password would
  seal the note with a password the reader doesn't have. Show/hide toggles reset to
  masked every time a password field is presented.
- **Hostile pastes can no longer freeze the viewer's tab:** syntax highlighting and
  Markdown rendering enforce a render budget (300 KB / 30k DOM nodes — every token
  counts, including plain-text ones); beyond it content is shown verbatim as plain text
  instead of minting hundreds of thousands of DOM nodes.
- **CLI: user aborts (Ctrl+C, Esc at the menu) now exit 130** (the conventional
  128+SIGINT code) instead of 2, so scripts can tell "user cancelled" from "bad
  invocation". Network failures name the host and cause (`ECONNREFUSED`, DNS, TLS)
  instead of a bare "fetch failed"; `binthere <command> --help` prints help instead of
  exiting 2; a bare `-f` dispatches to create like `-t` always did; `--out` files are
  written owner-only (0600); `TERM=dumb` terminals get plain text instead of ANSI.

### Fixed

- **Web accessibility/UX:** view transitions move keyboard and screen-reader focus to the
  shown view (previously focus could remain on a hidden control); informational text
  colors were raised to WCAG AA contrast (≥ 4.5:1) in both themes and are locked by an
  automated contrast test; the burn countdown now disables Reveal and switches to the
  expired state the moment it hits zero, instead of leaving a doomed button enabled.
- **CLI terminal robustness:** the hidden secret prompt reassembles multi-byte UTF-8
  split across raw-mode chunks and backspaces whole code points (half a surrogate pair
  silently derived a different key); keystrokes typed during the wizard intro no longer
  echo over the animation or leak into the first menu read; Ctrl+C on the burn
  confirmation prompt is a defined "no".
- **The wizard is now actually usable on Windows (conpty).** Three interlocking input
  bugs fixed: escape sequences split across reads no longer decode as a spurious Esc
  (which aborted the menu mid-navigation), several keys coalesced into one chunk are
  split and queued instead of silently dropped (fast or held arrows now register every
  press), and the per-keypress pause/raw-mode churn that could wedge the conpty read
  loop — freezing the menu after one keypress with even Ctrl+C dead — is gone. Key
  reading is now a persistent raw-mode reader for the whole wizard session
  (`tui/keys.js`); raw mode is set once and never toggled between screens, because
  conpty applies console-mode changes asynchronously and an off/on race at the
  menu-to-prompt hand-off left the terminal line-buffered with echo off (typing was
  invisible until Enter). The entry point restores the terminal and pauses stdin on the
  way out, so the process still exits cleanly.
- **Web polish:** programmatic focus targets (the view sections) no longer paint a
  focus ring around the entire view on load.
- **A bad link no longer burns a passwordless one-time note:** the web client now verifies
  the key from the link against the note's wrapped key *before* the destructive read, so a
  truncated or corrupted link fails with "the note was not opened and still exists" instead
  of destroying an unreadable note. The verified key is reused for the final decrypt, which
  also removes a duplicated (deliberately slow) key derivation from the password-protected
  reveal, and the key fragment is scrubbed from the address bar once a one-time note is
  revealed.
- **Password screen re-entry race:** rapid Enter presses could start a second password
  verification while one was already in flight; on a password-protected one-time note the two
  destructive reads raced and the reader could land on the "already opened" screen instead of
  the decrypted note (the server's single-consumer guarantee was never at risk). The submit
  handler is now guarded against re-entry — exactly one consuming read per unlock, and a wrong
  password still leaves the note intact and retryable.

### Added

- **Dismissible announcement bar** on the landing page linking to the launch blog post
  (hidden for returning visitors who dismissed it).
- **DOM-mount test project** (happy-dom): the `createElement`/`textContent` sink
  discipline — the load-bearing XSS defense — is now asserted against a real DOM with
  adversarial fixtures, alongside the focus-management and color-contrast checks.
  Coverage thresholds (80% statements / 70% branches) are enforced in the workerd suite.
- **Release automation:** pushing a `cli-v*` tag runs the full suites and publishes the
  CLI to npm with provenance (`.github/workflows/release.yml`).
- **Official CLI** (`cli/`, published to npm as `binthere`): create, get, and delete notes
  from the terminal. Second client of the same frozen protocol v1 — encryption is local
  (Node ≥ 20 WebCrypto + `CompressionStream`), only ciphertext is uploaded, and the SPEC §11
  vectors are re-verified in plain Node. Zero runtime dependencies.
  - **Website-parity lifecycle:** every note is burn-after-read and expires in 24 hours
    (`bar: true, expire: '1day'`), exactly like the web client — no expiry/burn flags.
  - **Full-screen interactive wizard:** a bare `binthere` on a terminal opens a branded
    menu (hand-rolled ANSI, still zero dependencies) — a left-aligned gradient wordmark
    that materialises in on startup (each glyph flickers ░ → ▒ → █ on its own random
    delay over ~0.9 s, TTY-only) with a wax-red ember dotting the "i" (smouldering while
    the menu idles), described
    menu items in a rounded hairline box, and taglines; arrow keys /
    `1`–`3` hotkeys pick **Create**, **View**, or **Delete**, and each action opens its
    own screen. Create lets
    you write the note and seal it with **Ctrl+Q** (optional password with confirmation),
    shows a braille
    spinner while encrypting and uploading, then clears the typed note and prints the
    share link on stdout plus a scannable compact braille
    **terminal QR code** and the delete token on stderr — `binthere | clip` still copies
    only the link. While the result screen waits, a slanted **shine beam periodically
    sweeps the wordmark** (every 7 s, repainted in place; TTY-only, skipped if the screen
    scrolled). On the result screen, **`c` copies the link and `t` the delete token**
    to the system clipboard (native tool — `clip`/`pbcopy`/`wl-copy`/`xclip`/`xsel`,
    `clip.exe` under WSL — fed
    over stdin, with an OSC 52 escape fallback for SSH; still zero dependencies).
    View and Delete reuse the exact `get`/`delete` command flows, so the
    safe burn ordering is shared. Colors follow the website palette with truecolor →
    16-color → `NO_COLOR`/non-TTY degradation. `--qr` adds a larger half-block QR to scripted `create`.
  - Reads mirror the browser's safe burn flow: non-consuming `?meta=1` peek → password
    verification **before** the destructive read → confirmation → consume. A wrong password
    never burns the note; old non-burn `k…` links still decrypt.
  - Passwords and delete tokens are never accepted as flag values — hidden prompt or
    `--password-env` / `--token-env` only. The delete token travels only in the
    `X-Delete-Token` header. `binthere get -` reads the share URL from stdin to keep the
    fragment secret out of argv/shell history.
  - **Quick one-liners:** `--text`/`-t` passes the note inline (`binthere -t "meet at 6"`
    creates directly, even without piped stdin), `binthere view <url>` is an alias for
    `get`, and common flags gained short forms (`-f` file, `-o` out, `-y` yes, `-j` json,
    `-q` qr, `-s` server).
  - `cli/vendor/` holds byte-identical copies of `public/js/{bytes,format,crypto,qrcode}.js`
    (npm cannot pack outside the package root; `qrcode.js` lands as `qrcode.cjs` for Node's
    CommonJS loader); a drift test fails CI on any divergence and
    `node cli/scripts/sync-shared.mjs` re-aligns them.
  - A Node-environment test suite (frozen vectors, URL parsing, mocked-API round trips
    incl. burn-ordering and wrong-token assertions, wizard/menu e2e, TUI renderers incl.
    the intro and shine-sweep animations, QR rendering, failure paths and raw-mode
    prompts) runs as a second vitest project via `npm test` / `npm run test:cli`.

## [binthere 1.0.0] — 2026-07-18

First public, open-source release: a clean-room, security-first, zero-knowledge encrypted
pastebin on a single Cloudflare Worker (Static Assets + KV + a `BurnPaste` Durable Object +
native rate limiting). Content is encrypted and decrypted only in the browser; the server
stores nothing but ciphertext and non-secret metadata.

### Cryptography (zero-knowledge, Web Crypto only)

- Per-paste random 256-bit content key (CEK); AES-256-GCM with fresh 96-bit IVs (never
  reused per key). The key rides in the URL `#fragment` and never reaches the server.
- Documented, domain-separated key hierarchy: `KEK = HKDF-SHA256(F, salt=PBKDF2(password))`
  wraps the CEK. Neither the URL fragment secret alone nor the password alone can decrypt a
  password-protected paste. All KDF parameters are versioned in the format.
- Canonical, fixed-order AAD binds every decryption/rendering/compression/burn field to both
  GCM operations. Frozen crypto test vectors in [`SPEC.md`](./SPEC.md) §11 /
  `test/crypto.test.js`, with a regenerator (`test/genvectors.mjs`) and an independent Python
  cross-check (`tools/verify-vectors.py`).
- Native `CompressionStream` gzip with a hard decompression cap (gzip-bomb defense).

### Backend

- Single Worker + Static Assets serves the frontend and the `/api/*` API.
- **Strict, atomic burn-after-read** via a `BurnPaste` Durable Object (single-consumer;
  concurrent reads → exactly one `200`, the rest `410`). Normal pastes live in KV with
  native TTL.
- Password-protected burn pastes are **verified before the destructive read**: a
  non-consuming metadata peek (`GET /api/paste/:id?meta=1`, returns `adata` + wrapped key,
  never the ciphertext) lets the client check the password first, so a wrong password never
  destroys the note (see [`SPEC.md`](./SPEC.md) §8). The client validates the peeked head
  with the same fail-closed rules before deriving any key.
- 128-bit CSPRNG paste ids (with a storage-class prefix); 256-bit CSPRNG delete tokens stored
  only as `SHA-256`, verified in constant time, and sent in the `X-Delete-Token` header
  (never in the URL, so they cannot land in logged request URLs).
- Native Workers Rate Limiting on create (fail-open). Real HTTP status codes.
  `X-Content-Type-Options: nosniff` on API JSON responses.
- Fail-closed, prototype-pollution-safe format validation; server body-size cap.

### Frontend

- Beginner-first create / success / view / password / status screens.
- **One-time view by default:** every note is single-use and auto-deletes within 24 hours.
  Optional password protection via a plain-language modal.
- Obvious source code is auto-detected and syntax-highlighted at view time by a first-party,
  `textContent`-only highlighter (`public/js/highlight.js`) — no CDN, no `innerHTML`;
  `tokenize()` is proven lossless in `test/highlight.test.js`. A **safe** Markdown subset
  (no raw HTML, `href` scheme allowlist) renders via DOM construction only.
- Copy link, QR code (self-hosted MIT `qrcode-generator`, rendered as a `data:` image),
  delete link, status pills (kind + one-time view), and a live **"Deletes in" countdown** on
  the reveal screen (derived from non-secret metadata; the server-side expiry stays
  authoritative).

### Design — the "Iron Gall" system

- The interface is treated as a piece of security printing:
  archival inks, engraved 1px hairlines, tight print-like radii (3px controls / 6px cards), a
  self-drawing guilloché seal on the success screen, a guilloché rosette watermark, and
  stamp-like status pills.
- Hierarchy is carried by **one owned hue** — iron-gall blue — with **wax-seal red reserved
  strictly for destruction semantics** (the one-time / "now deleted" stamp and delete actions).
- Two themes, one token contract: light "Archive" on `:root`, dark "Plate" on `html.dark`
  (the shipped default).
- Three self-hosted (woff2, CSP-strict, first-party) typefaces: **Newsreader** for the wordmark
  and display titles, **Geist** for body and controls, **JetBrains Mono** for technical text.
- The footer names the actual primitives (AES-256-GCM · HKDF-SHA256 · key rides in the URL
  `#fragment`, never sent) and links to the source, the threat model
  ([`SECURITY.md`](./SECURITY.md)), and `/.well-known/security.txt`.

### Security posture

- Strict CSP (`default-src 'none'`; first-party `script`/`style`/`font`/`img`/`connect`; no
  inline, no eval, no CDN). Self-hosted Newsreader + Geist + JetBrains Mono (SIL OFL 1.1
  notices now in `public/THIRD-PARTY-NOTICES.md`). Security headers via `_headers`.
- [`SECURITY.md`](./SECURITY.md) documents the threat model, the metadata/anonymity non-goals,
  and the deployment-compromise limitation of in-browser E2E encryption, plus a security
  contact — also published at `/.well-known/security.txt`.

### Tests & tooling

- 103 tests in the `workerd` runtime: frozen crypto vectors + round-trip + password hierarchy
  + tamper; adversarial format validation (incl. prototype pollution); id/token handling;
  Markdown XSS suite; syntax-highlighter losslessness; backend API + **burn concurrency** +
  password-peek regression tests.
- GitHub Actions CI (lint + byte-for-byte vector diff against `test/vectors.expected.txt` +
  full test suite); ESLint 9 flat config; `engines.node >= 20` + `.nvmrc`; MIT `LICENSE`,
  `CODE_OF_CONDUCT.md`, issue/PR templates.

[Keep a Changelog]: https://keepachangelog.com/en/1.1.0/
[Semantic Versioning]: https://semver.org/spec/v2.0.0.html
[binthere Unreleased]: https://github.com/nxfu/binthere/compare/v1.1.0...63e5544
[binthere 1.1.0]: https://github.com/nxfu/binthere/compare/v1.0.0...v1.1.0
[binthere 1.0.0]: https://github.com/nxfu/binthere/releases/tag/v1.0.0
[secbin 1.0.0]: https://github.com/kaerez/bin
