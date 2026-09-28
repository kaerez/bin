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
- **Reverse shares** ("Receive files…", [`REVERSE.md`](./REVERSE.md)): anonymous uploads land in
  a Drive folder the user chooses, encrypted to that user's key.
- Terminology: the person who owns a drive is the **user**; "owner" means the admin.

## 2. What the server sees

Visible to the server: the tree's shape (node ids, parent ids, file/folder), each file's exact
ciphertext size and chunk count, timestamps, and which shares reference which nodes.
Never visible: names, file types, contents, file keys, the Drive key.

**Zero knowledge, with one exception.** The server never holds DK, a key that opens DK, or
anything that opens a wrap: every wrap is opened only in a browser, with a secret the server does
not have (the user's password, recovery code or passkey, or the owner's escrow private key, which
is itself sealed under the owner's own DK). The one exception is the owner escrow (§3, §9): the
owner — not the server — can open every user's Drive. There is no other path: no hand-over wrap,
no server-held key, no Drive created for a user by anyone but the user's own browser.

## 3. Keys (client side only)

- **DK** — the Drive key: 32 random bytes per user, created in the user's own browser at their
  first sign-in once the Drive is enabled (automatic set-up, below). Never sent to the server in
  the clear.
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
  `escrowPriv`, node id `drive`; `escrowSignPriv` likewise, field `escrowSign`. `driveSalt` is 16
  bytes, base64url.
- **Wraps of DK** (the server stores them, cannot open them). The browser unlocks DK with the
  first one that works:
  1. `pw` — password: `Argon2id(NFC(password), driveSalt, m = 64 MiB, t = 3, p = 1)` (a second
     derivation with a Drive-only 16-byte salt; the login proof is a different Argon2 output and
     never unlocks the Drive) → HKDF `secbin-drive/v1 kek-pw` → AES-GCM wrap of DK.
  2. `recovery` — one per recovery code: HKDF over the code's normalised text (as the server
     normalises it: upper case, no spaces or dashes, O → 0, I/L → 1),
     `secbin-drive/v1 kek-recovery` → wrap; `ref` = the code's existing server-side hash
     (hex `SHA-256("secbin-recovery/v1:" ‖ code)`). Regenerating recovery codes replaces these
     wraps; a code spent at sign-in has its wrap removed by the server as the sign-in succeeds
     (the sign-in response carries that wrap back once, `driveSpent`, so the same sign-in can
     still unlock the Drive with the code); removing the last passkey (which drops the codes)
     removes them all.
  3. `passkey` — one per passkey that supports the WebAuthn **PRF** extension: PRF output for the
     fixed salt `SHA-256("secbin-drive/v1 prf")` → HKDF `secbin-drive/v1 kek-prf` → wrap;
     `ref` = the credential id. Passkeys without PRF are simply not listed.
  4. `escrow` — **owner escrow**: ECDH P-256 between an ephemeral key and the owner's escrow
     public key → HKDF (salt = the ephemeral public key, raw) `secbin-drive/v1 kek-escrow` →
     wrap; stored with the ephemeral public key and `kid` (the first 16 bytes of SHA-256 over
     the owner's raw public key), `ref` = `escrow`.
     The owner's escrow private key (PKCS#8) is stored encrypted under the **owner's own DK**
     (`escrowPriv` field of the owner's drive). The owner can therefore open any user's Drive
     (after a password reset, and while impersonating the user); how it is recorded: §9.
     **Every user's Drive has an escrow wrap, always.** A user's Drive is set up only once the
     owner's escrow key exists (`409 escrow_not_ready` before; the page says "Drive is not ready
     yet"), and only with an escrow wrap for the current key and a wrap of the user's own
     (`pw`, `recovery` or `passkey`); an escrow wrap is always for the current key (its `kid`);
     the user cannot remove it (`403 escrow_required`, with or without the step-up).
     **The signing key.** The owner also has an ECDSA P-256 signing key: its private key sealed
     under the owner's DK (`escrowSignPriv`), its public key (`escrowSignPub`) and its signature
     over the escrow public key (`escrowSig`, raw r ‖ s over
     `secbin-drive/v1 escrow-endorse\n<x>\n<y>`) in the Directory. Once a signing key exists the
     server accepts a new escrow public key only with a valid signature by it (or, with the
     step-up, a new signing key and its signature).
     **Escrow key integrity.** Changing the owner's escrow key pair or signing key needs the
     owner's password or a passkey (`current` / `reauth`), except the first time (no key yet).
     The owner's browser derives the public key from the opened `escrowPriv` and compares it with
     the server's `escrowPub`, and checks the signing key and its signature; on a mismatch, a key
     that does not open, or none, the Drive page shows an alert (`DriveClient#notice`) and nothing
     is re-created or wrapped silently: restoring the public key or making a new pair needs the
     confirmation.
     **Pin.** Each user's browser pins `{ escrow, sign }` — the kid of the escrow key its wrap is
     for and the kid of the signing key that signed it (null when there was none) — sealed under
     DK as the Drive's `escrowPin` (the names key, field `escrowPin`, node id `drive`), at the
     Drive's first set-up (the server requires it then). It re-wraps to a new escrow key by
     itself only when the pinned signing key signed it; otherwise the Drive page shows the user
     a notice with the new key's fingerprint and "Trust the new key", which re-wraps and
     re-pins. A signing key is never added to a pin silently. **Only the genuine first set-up in
     this browser trusts without a pin:** every Drive has a pin and an escrow wrap from its
     first set-up, and the wrap is always for the pinned key (both change in the same request),
     so at a later unlock a Drive without a pin (or with one that does not open), without an
     escrow wrap, or whose wrap is for another kid than the pinned one gets the tamper notice
     ("Your Drive's escrow record does not match") and nothing is re-wrapped or re-pinned; "Trust
     the new key" then writes the pin (and a wrap, unless the wrap is already for that key). The
     one exception, accepted by the maintainer, is an owner reset (starting over without a kit,
     §3.2): the pin also holds the owner-reset epoch it has seen, and a user's browser moves to
     a reset's key by itself once per reset, every time (no time limit).
     **Rotation.** The owner replaces the escrow key pair from the Drive page (with the step-up);
     the new key is signed by the owner's signing key, so each user's browser re-wraps to it at
     its next unlock. Until then the old private key stays in the owner's Drive, **sealed under the
     owner's DK** (`escrowPrivOld`, by kid; the server moves it there on rotation), and is dropped
     once no user's escrow wrap is for it (the Directory records each user's escrow kid,
     `drive.escrowKid:<userId>`). It is handed only to the owner's own session and opens only
     with the owner's DK, so keeping it gives no one access they did not have: only the owner
     can open it, and only for wraps made before the rotation.
- **Unlock at sign-in:** after a successful password, passkey or recovery-code sign-in, the login
  page fetches the wraps and unlocks DK with what it has (password → `pw`; passkey with PRF →
  `passkey`; recovery code → `recovery`), then keeps DK in the tab's `sessionStorage`
  (`secbin_dk`, base64url, with the user id in `secbin_dk_uid` so another account's page — e.g.
  while impersonating — never uses it) until sign-out or the tab closes. If none works, the
  Drive page asks. A Drive whose root has content but no wraps is never given a new key: the
  browser does not try, and the server refuses a first set-up of a Drive with content, a key
  check value or sealed owner keys but no wrap (`409 drive_keyless`); the ways out are a kit
  restore and, for the owner, starting over, each with the step-up.
- **Automatic set-up.** At a user's first successful sign-in while their role has the Drive
  (no wraps yet), the login page creates DK with no user action: a `pw` wrap (the password just
  accepted), the `escrow` wrap for the owner's current escrow key with the pin, and a `passkey`
  wrap when the sign-in passkey gives a PRF output (with no password, the passkey wrap alone,
  and the `pw` wrap follows at the next password sign-in). Recovery codes get their wraps when
  new ones are made. The owner's escrow key must exist first: until the owner has signed in
  once, a user's sign-in creates nothing and the Drive page says "Drive is not ready yet". The
  owner's own first sign-in creates the owner's Drive with the escrow key pair and the signing
  key. A sign-in with a recovery code, or with a passkey without PRF, sets nothing up (the
  Drive page offers the set-up with the password).
- **Drives the owner sets up.** When the owner creates an account in Admin → Users (or resets
  the password of a user who has no Drive yet), the owner's browser knows the password it set,
  so it sets the user's Drive up at once: a new DK for the user, a `pw` wrap for that password
  (a new driveSalt), the `escrow` wrap for the current escrow key and the user's sealed
  `escrowPin` (the current escrow kid, the signing kid and the owner-reset epoch). It first
  checks the escrow key as the owner's own unlock does (the escrow private key it opens is the
  server's `escrowPub`, and the signing key signed it), needs the owner's Drive unlocked in the
  tab, and keeps nothing of the user's DK. The server accepts this first set-up
  (`PUT /api/private/admin/drive/keys/<userId>` with `first: true`) only from the owner (never
  while impersonating), only for a user whose role has the Drive and whose Drive has no wrap
  yet, and only with exactly one `pw` and one `escrow` wrap for the current kid, the salt, the
  pin and the key check value (below); it is `drive.created_by_owner` in the admin audit and a
  system event (no detail) in the user's activity. The owner's browser first checks that the
  user's role has the Drive (the create response's `user.drive.enabled`; for a reset, the user's
  role options): when it does not, it makes no Drive request for that user and the create form
  says "Drive is not enabled for this role, so no Drive was created."; if the role gets the
  Drive later, it is set up at the user's first sign-in. The server's `409 drive_disabled`
  stays as the guard (a role changed at the same moment), and the page shows it as the same
  case. When the owner's Drive is locked or there is no escrow key yet, the account is still
  created and its Drive is set up at the user's first sign-in; the create form says which
  happened. Imported accounts (a verifier, never a
  password) and a user the owner impersonates never get a Drive this way.
- **The Drive key never changes.** A password change by the user and an admin reset keep the
  same DK: only the `pw` wrap is replaced, so file keys, passkey, recovery-code and escrow
  wraps and recovery kits stay valid. The user's own change opens DK first when the tab lacks
  it (with the current password through the old `pw` wrap, or with the step-up's passkey PRF)
  and writes the new `pw` wrap in the same step; only when DK cannot be opened (a passkey
  without PRF) is the wrap left stale for the next unlock. For an admin reset of a user who has
  a Drive, the reset form asks the owner to unlock their own Drive inline; the owner's browser
  then opens the user's DK through the escrow and writes the new `pw` wrap. The owner may
  continue without unlocking: the reset goes through, DK is untouched, and the form says the
  user then opens the Drive with a recovery code, a passkey or a recovery kit (or the owner
  resets again with the Drive unlocked). **Key check value (`kcv`):** `HMAC-SHA-256(the raw
  HKDF "files" sub-key of DK, "secbin-drive/v1 kcv")`, base64url. It is required with every
  first set-up (the user's own, one the owner makes, the owner's own, starting over) and stored
  with the first wraps in the same transaction; it is never taken from a later change. Every
  later wrap or pin written (a `pw` wrap after the user's own change, an admin reset or a
  restore; a passkey, recovery-code or escrow wrap; the pin) must carry the same value,
  compared in constant time in the Worker and again in the Drive object (`400 kcv_required`,
  `409 kcv_mismatch`); a Drive without one takes no key at all (`409 kcv_missing`). It reveals
  nothing about DK and stops a wrap of another key. No route replaces or removes DK itself.
  **Replacing a wrap** — a passkey or recovery-code wrap with other data, or the escrow wrap
  with another wrap for the same escrow key — needs the step-up, as removing one does; a re-wrap
  to a new escrow key is not a replacement. The owner's own Drive has no escrow wrap
  (`400 escrow_own`).
- **Races.** Every first set-up is a compare-and-set in the Drive object on "a new Drive" (no
  wrap, no content, no key check value, no sealed owner key), with the first wraps, the pin and
  the key check value in one transaction: of two at once (two tabs; or the owner setting up a
  new account's Drive while the user's first sign-in does) one wins and the other gets
  `409 drive_exists`; the browser that lost opens the Drive that won with its password (or
  passkey). The owner's first escrow key is a compare-and-set in the Drive object and the
  Directory (`409 escrow_exists`).
- **Pages with third-party script.** The Account page (Turnstile) moves the tab's keys out of
  `sessionStorage` into its module's memory before anything can load the Turnstile script
  (`holdSessionKeys`), uses them from there, and puts them back only when the server has no
  human check; the login page and the home page's public composer clear them before it loads.
  What remains exposed there: SECURITY.md, "Drive keys".
- **Impersonation.** While the owner acts as a user, the Drive page opens that user's Drive with
  the owner escrow: the tab must hold the owner's own DK (`secbin_dk` with `secbin_dk_uid` = the
  owner); `POST /api/private/drive/escrow` returns the user's escrow wrap with the owner's sealed
  `escrowPriv` and `escrowPub`; the owner's DK opens `escrowPriv` (whose derived public key must
  be the server's `escrowPub`), which opens the wrap. The user's DK is kept in its own slot
  (`secbin_dk_imp`, with `secbin_dk_imp_uid` = the user), never over the owner's, and cleared
  when the impersonation ends (and on any page loaded while not impersonating). A wrap made for
  an earlier escrow key opens with that key (`escrowPrivOld`, also returned by the route). **A
  user with no Drive yet gets none:** the page says "The user hasn't signed in since the Drive
  was enabled" and nothing is created (the server refuses a first set-up while impersonating,
  `403 impersonating`); the user's own next sign-in sets it up. When the owner's Drive is not
  unlocked in the tab, the owner has no escrow key yet, the user's Drive has no escrow wrap, or
  the wrap is for a key the owner no longer holds, the page says so and what to do instead of the
  unlock prompt.
- **Keeping wraps current (always in the browser that has DK):**
  - password change by the user → the server marks the `pw` wrap stale (`pwStale`), and the
    browser writes a new one (new driveSalt) without a second confirmation;
  - a password the owner sets while acting as the user → like a reset: the server drops the old
    `pw` wrap when another wrap (passkey, recovery code or escrow) remains, else marks it stale;
    the owner's tab (holding the user's DK in its own slot, or opening it with the escrow) adds
    the new one; new recovery codes or passkeys the owner creates get their wraps added the same
    way;
  - admin password reset by the owner → the server drops the old `pw` wrap when a passkey or
    recovery-code wrap remains, else marks it stale; the owner's browser opens the user's
    `escrow` wrap (needs the owner's DK unlocked) and writes a fresh `pw` wrap for the new
    password; if the owner's Drive is locked, the reset still works and the user unlocks with a
    recovery code or passkey; the new `pw` wrap is written with
    `PUT /api/private/admin/drive/keys/<userId>` (§6);
  - new passkey with PRF → add its wrap (PRF requested at registration; an authenticator that
    only evaluates PRF on use gets its wrap at its next sign-in); passkey removed → its wrap
    removed by the server (the browser also asks, idempotently);
  - new recovery codes → the server drops the old codes' wraps; the browser adds a wrap per new
    code (without DK in the tab, none);
  - a sign-in whose password the server accepted, when the `pw` wrap is stale or missing and
    another wrap opened DK → a fresh `pw` wrap;
  - the escrow wrap not for the server's current escrow key → re-wrapped on the next unlock
    when the pinned key is the current one or the pinned signing key signed the new one (else
    the notice above).
- The owner's escrow key pair and signing key are created at the owner's first sign-in (when no
  escrow key and no signing key exist anywhere yet). **Nothing else ever creates one:** no
  timer, alarm, sign-in, AUTHN recovery, kit restore or "restore the escrow public key" (which
  refuses when the signing key cannot be opened) makes a new escrow pair or signing key; only
  the owner's explicit rotation ("Replace the escrow key", or a new pair after a notice, both
  with the step-up) and starting over without a kit (below) do. A user's browser re-wrapping to
  a signed new key changes no key on the server.
- **Escrow key version.** The owner's Drive records `escrowVer` `{ version, kid, created }`:
  version 1 at the first creation and one more at each new escrow pair (a rotation, or starting
  over). Putting back the same public key is not a new version. Public data.

### 3.1 Recovery kits

- **What a kit is.** A file made and read only in the browser (`public/js/drivekit.js`), never
  sent to the server. Two kinds share one module: the **owner kit**
  `secbin-owner-kit/1` (the owner's DK and a snapshot of the escrow keys) and, in a later
  change, the **user kit** `secbin-user-kit/1` (a user's DK only; the pages for it come later).
  A user kit is refused for the owner's account and an owner kit for a user's (`kind`). For the
  owner there is one kit only, whichever page it comes from (the export screen or the Drive
  page), with the same status, check and restore.
- **File:** `{ format, ownerId, salt, t, m, iv, ct }` (`userId` for a user kit), nothing else.
  Argon2id over the passphrase with the export's parameters (m = 64 MiB, t = 3, p = 1, a
  16-byte salt; fixed: a file asking for other parameters is refused), then AES-256-GCM; the AAD
  is `<format>\nargon2id\nm=65536\nt=3\np=1\nsalt=<salt>\niv=<iv>\n<owner|user>=<id>\norigin=<origin>\n`,
  so a kit opens only as its kind, for its account, on the server (origin) that made it, and any
  change to the file fails. The passphrase is optional, with no minimum length (as the
  export's); an empty one still goes through Argon2id (from the export's substitute input, a
  single 0xFF byte, because the Argon2 build refuses an empty input), so the file looks the same.
  The page warns when it is empty or under 12 characters: the kit opens every user's Drive and
  belongs offline, like the AUTHN secret.
- **Owner kit content** (inside the ciphertext): `{ v: 1, ownerId, made, version, created,
  kid, dk, escrow, sign, old }` — DK; the escrow key's version and creation date at download;
  the current escrow private key, the signing private key and every earlier escrow private key
  the owner's Drive keeps (`escrowPrivOld`), each as PKCS#8 with its kid and public key. On
  opening, every public key and kid is derived from the private key, never read from the file.
  DK never changes and every escrow key is sealed under it on the server, so an older kit still
  reaches keys made after it through DK and the server's sealed copies; the snapshot covers a
  lost server copy.
- **Download** (owner only, not while impersonating; the owner's Drive unlocked in the tab):
  always available, each time a new file with the whole current snapshot. The browser seals the
  file, then `POST /api/private/drive/kit { event: "exported", current | reauth }`: the server
  checks the step-up (as on Account), records `kit: { version, kid, at }` of the current escrow
  key in the owner's Drive, and `drive.kit_exported` (with the version) in the admin audit; the
  file is given out only then. The step-up gates only that record and the page's download: the
  file is sealed in the page from the DK already in the tab, so script in the tab has DK
  anyway.
- **Status and notice.** The export screen and the owner's Drive page show the escrow key's
  version, its kid's short fingerprint (`xxxx-xxxx`) and creation date, and the latest kit (its
  version and download date, or "never"). When the recorded kit's kid is not the current escrow
  kid (a rotation since, or a start over) the notice says "The escrow key was replaced.
  Download a fresh owner recovery kit: it holds all current and past escrow keys." and that
  older kits still work through the Drive key; when no kit was ever downloaded, a notice says
  so. It is `role="alert"` when it first appears on the page (right after the rotation or start
  over), otherwise a static note with a "Download kit" button, and stays until a kit is
  downloaded for the current escrow key.
- **Verify kit** (read-only): the owner selects the saved kit file (`<input type="file"
  accept=".json,application/json">`, read with `File.text()`; never a copy kept by the page) and
  its passphrase; both are cleared from the inputs afterwards. Per-check results: format and
  owner (this owner, this origin); it decrypts with a valid tag; its DK opens the server's
  sealed escrow key, whose public key is `escrowPub`; the snapshot's current key is the
  server's escrow key and kid; its signing key is `escrowSignPub` and the signature over
  `escrowPub` verifies; every earlier key still in use (each kid in `drive.escrowKid:*` and
  every `escrowPrivOld`) is in it with a matching public key; its version against the current
  one ("Current", or "Older version N: still works through the Drive key, but download a fresh
  kit for a complete snapshot"); and, as a live proof, one user's escrow wrap per kid in use
  opens (`POST /api/private/drive/kit/probe`, each recorded as `drive.escrow_used`, the DK found
  discarded at once; at most 30 calls per owner session per 10 minutes, `429 rate_limited`). The verdict is "Complete backup" or what is missing or stale, with the
  fix (download a fresh kit). Nothing is written but the audit: `POST …/kit { event:
  "verified", verdict, issues?, version? }` → `drive.kit_verified`.
- **Restore from kit** (the export screen, the Drive page, and the Drive page's unlock screen;
  a selected file, its passphrase and the account password). The browser checks the kind and
  owner, derives the key and opens DK, then confirms it: the server's sealed escrow key must
  open with it and be `escrowPub` — or, when that copy is missing or does not open, the
  snapshot must hold the server's current escrow key. `POST …/kit { event: "used" }` checks the
  password (the step-up) and records `drive.kit_used`. Any escrow key whose server copy is
  missing or wrong is re-sealed from the snapshot under DK and put back
  (`PUT /api/private/drive/kit/keys`, with the step-up, `drive.kit_keys_restored`): the escrow
  key only for `escrowPub`, the signing key only for `escrowSignPub`, an earlier key only for a
  kid still in `drive.escrowKid:*`; nothing public changes (no key, no version, no wrap). The
  server checks the public key the browser claims for each sealed key; it cannot check that the
  sealed data is that key (only a browser with DK can), so a wrong blob sent with the step-up
  replaces a good one and the owner's next unlock shows the escrow-key alert. DK goes
  into the tab's slot and a fresh `pw` wrap is written (with the key check value; no second
  confirmation after AUTHN recovery, which marks it stale). A kit for the Drive **before a start
  over** restores that archive instead (§3.2). A kit that does not match is refused with a clear
  error and nothing is written; failed openings are throttled in the page (two free tries, then
  5 s, 10 s, 20 s… up to a minute). That throttle is in the page's memory only (a reload starts
  it again); guessing a kit's passphrase offline needs only the file.
- **AUTHN owner recovery** still removes the owner's passkeys and recovery codes; it also drops
  their Drive wraps and marks the owner's Drive `pwStale` (the old `pw` wrap opens only with the
  old password), and changes no key. After it, the owner's Drive page (nothing the owner signs
  in with opens the Drive) offers the kit restore and starting over.
- Kits are not part of the regular export file, and the Drive stays out of exports.

### 3.2 Starting over without a kit

- Offered only to the owner, only when nothing the owner can sign in with opens the owner's
  Drive (no passkey or recovery-code wrap, no `pw` wrap or only a stale one — the server checks
  the same, `409 drive_unlockable`), never while impersonating. It needs the typed username
  (`400 confirm_required`) and the step-up with the (new) password.
- `POST /api/private/drive/start-over { confirm, driveSalt, set: [pw], escrowPub, escrowPriv,
  escrowSignPub, escrowSignPriv, escrowSig, kcv, current | reauth }`, all made in the browser
  under a new DK: a new escrow pair and a new signing key (the pair signed by it), a `pw` wrap.
  The owner's Drive as it was is **archived, not deleted**: its items, R2 objects, wraps, salt,
  pin, key check value and sealed escrow keys stay exactly as they are, sealed under the old DK,
  in archive `gen` (`archive_nodes`, `archive_wraps`, `archive_meta`), unreadable without that
  DK; unfinished uploads go (as the pending purge would drop them). Shares of archived items
  keep working (their keys are in their links). The archive counts towards the owner's storage
  and nothing deletes it automatically. The Drive is then set up with the new keys; the new
  escrow pair counts as a rotation (the version goes up); the Directory records the **owner
  reset** `drive.ownerReset { epoch, kid, signPub, at }` (public; the epoch is one more than the
  last); `drive.owner_reset` goes to the admin audit; the fresh-kit notice follows. No user's
  Drive or wrap is touched. **Atomic:** the Drive object re-checks "nothing opens it", archives,
  pauses the owner's reverse links (docs/REVERSE.md §9) and writes the new keys and key check
  value in one step, then the Directory sets the new
  public keys and the reset in one transaction, a compare-and-set on the epoch the request read
  (`409 reset_conflict`); a second start over at the same moment gets `409 drive_unlockable`:
  one archive, one epoch. A failure between the two steps leaves the owner's Drive on the new
  keys and the Directory on the old public key: the owner's next unlock shows the escrow-key
  alert, and users get the notice rather than an automatic move.
- **Users move automatically** (the maintainer's accepted exception to the signed-key pin, for
  this case only; all its rules are in `resetApplies`, `public/js/driveclient.js`). At a user's
  next unlock their browser re-wraps DK to the new escrow key and re-pins `{ escrow, sign,
  epoch }` by itself only when the server reports an owner reset whose epoch is exactly one
  more than the pinned one (a pin without an epoch counts as 0) and whose signing key is the
  server's `escrowSignPub` and signed the escrow key. There is no time limit (the maintainer's
  decision: automatic, with no user approval, every time): a second genuine reset soon after
  the first moves the Drive again. The epoch in the sealed pin means the same reset never
  applies twice. The user sees once "Your administrator rotated a security key; nothing
  for you to do."; the server records `drive.escrow_rewrapped` (the new key's fingerprint) as a
  system event in the user's activity and, with the user, in the admin audit (`escrowReset:
  <epoch>` on the key change), once per user and epoch (a repeat writes nothing; at most 5
  `escrowReset` requests per user per 10 minutes, `429 rate_limited`). Any other unsigned change
  — no reset, a skipped or repeated epoch, a signature by another key — keeps the notice and
  "Trust the new key", with no re-wrap. Signed rotations stay automatic as before (and keep the
  pinned epoch).
- **What the exception allows.** It is not limited to a window after a genuine reset: nothing
  a user's browser holds ties a reported reset to a real start over. Anyone able to change the
  server's responses (a compromised Cloudflare account, a malicious deploy or an insider) can
  report a fabricated reset at any time, with their own signing and escrow keys, and receive
  users' Drive keys at their next unlock, and again at each later epoch. So can anyone able to complete AUTHN owner recovery and then start over, which
  means anyone with access to the Worker's `AUTHN` secret configuration. The signed-key pin
  applies to every other unsigned change.
- **The archive back.** A kit for the old DK brings it back with "Restore from kit": the
  browser finds the archive whose sealed escrow key opens with the kit's DK
  (`GET /api/private/drive/archive/<gen>?after=` pages its items and sealed keys), opens the
  Drive's current DK (the tab's, or with the password), re-seals each item's name, metadata
  and file key under it (content is not touched: each file has its own key), a top-level name
  the Drive already has gets " (2)"… as uploads do, and puts them back folders first
  (`PUT …/archive/<gen>/nodes`, with the step-up; `409 parent_first` otherwise). Then
  `POST …/archive/<gen>/finish` (with the step-up) adds the archive's escrow keys, re-sealed
  under the current DK, to `escrowPrivOld` for the kids users' wraps are still made for, so
  those Drives open again, and removes the archive (`drive.archive_restored`). The Drive keeps
  its current DK.
- **Delete the old Drive archive** (the owner's Drive page): the typed username and the step-up;
  its R2 objects, items, wraps and sealed keys go and its shares end; no kit can restore it
  afterwards (`DELETE /api/private/drive/archive/<gen>`, `drive.archive_deleted`). Archive
  numbers never repeat.
- **The owner's reverse links** ([`REVERSE.md`](./REVERSE.md) §9): their private keys are sealed
  under the old DK, so starting over ties each of them to the archive (`reverse.agen`) and
  **pauses** the active ones: no new session or upload (`409 paused`; the uploader page says
  "This link is not accepting files right now"), their open sessions end and their unfinished
  uploads go; the items they received stay in the archive exactly as they arrived, sealed to
  the link's key. A restore of the archive with a kit for the old DK brings those items back as
  they are (`{ id }` only in `PUT …/nodes`), re-seals each link's private key under the Drive's
  DK now (`reverse` in `POST …/finish`) and resumes the links; the kept items are then taken in
  like any received file. Deleting the archive revokes the paused links and deletes their
  received items. Logged as `reverse.paused`, `reverse.resumed` and `reverse.revoked`
  (`reason=archive_deleted`), one entry per link, in the owner's activity and the admin audit.
  No other user's link changes.
- **Changes that need the step-up** (`PUT /api/private/drive/keys` with `current` or `reauth`,
  as on Account): removing a wrap, replacing the `pw` wrap, replacing `driveSalt`, and any
  change of the owner's escrow key pair — except the Drive's first set-up (no wraps yet), a
  stale `pw` wrap (with its salt), and the owner's first escrow key. A change that would leave a
  Drive with content and no wrap is refused (`409 last_wrap`), and so is one that would leave a
  Drive with no wrap of the user's own (`409 last_own_wrap`: the escrow wrap alone is never
  enough). The browser never removes a wrap itself: the server drops the wraps of credentials
  that are gone.
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
  - `wraps(kind TEXT, ref TEXT, data TEXT, PRIMARY KEY(kind, ref))` (kinds `pw`, `recovery`,
    `passkey`, `escrow`) and `meta(k, v)` for `driveSalt`, `escrowPin`, `pwStale`, `kcv` (the
    key check value), `rl` (rate-limit counters: `escrowReset`, the owner's kit check per
    session), and for the owner only `escrowPriv`, `escrowSignPriv` and `escrowPrivOld`
    (each sealed under the owner's DK) and the public records `escrowVer`, `kit` and
    `archiveGen`. Nothing else: no key the server could use to open a Drive.
  - the owner's archives after starting over (§3.2): `archive_nodes(gen, …the nodes columns,
    rs, rfail, rwhy)` (a received item keeps its link),
    `archive_wraps(gen, kind, ref, data)`, `archive_meta(gen, k, v)` (the old salt, pin, key
    check value, sealed keys, kit record, and `at`) — all as they were, sealed under the old DK.
  - `refs(share_id TEXT, node_id TEXT)`: which shares reference which nodes.
- R2 objects: `d/<userId>/<nodeId>/<i>` (never under `f/`). Only the Drive DO deletes them.
- The owner's escrow **public** key lives in the Directory (`meta` key `drive.escrowPub`, JWK),
  with `drive.escrowSignPub`, `drive.escrowSig`, each user's escrow kid
  (`drive.escrowKid:<userId>`; never the owner's), the latest owner reset (`drive.ownerReset`)
  and the latest reset each user's browser moved to (`drive.resetApplied:<userId>`): public data
  only.
- Pending uploads older than the role's `filePendingSec` are purged by the Drive DO's alarm.

## 5. Role options (Admin → Roles; `LIMITS` in `src/lib/settings.js`)

- `driveEnabled` (bool, default **false**); `driveMaxBytes` (bytes, capacity, default 1 GiB,
  null = no limit up to a hard 100 GiB); `driveMaxFileBytes` (bytes, nullable, default null).
- Drive shares obey the same share options as file shares: `files`, `maxViews`,
  `allowUnlimitedViews`, `maxExpireSec`, `maxFilesPerShare`, `openerDelete`, file-type rules,
  quotas (kind `files`), receipts. The owner has no limits. The public account has no Drive.
- New keys join the Default role (a Directory migration materialises them) and appear in the
  role editors under a **Drive** section.

## 6. API (session only; not with API keys)

All bodies JSON unless stated; errors `{ error, message }` as elsewhere.

| Method and path | Purpose |
|---|---|
| `GET /api/private/drive` | `{ enabled, capacity, used, driveSalt, wraps: [{kind, ref, data}], escrowPub, escrowSignPub, escrowSig, escrowPin, pwStale, ownerReset, escrowPriv?, escrowSignPriv?, escrowPrivOld?, escrowKids?, escrowVersion?, kit?, archives? }` (the ones with `?` for the owner only; while impersonating, the `escrow` wrap's `data` is null; `capacity` null = no limit; `driveSalt`, `escrowPub`, `escrowPin` null until set). A role without a Drive: `200 { enabled: false, wraps: [] }` (every other Drive route: `403 drive_disabled`; the public account: `403 drive_unavailable`); the client reads `enabled: false`, `drive_disabled`, any 404 and any 403 other than `impersonating` as "no Drive" |
| `PUT /api/private/drive/keys` | set wraps: `{ driveSalt?, set: [{kind, ref, data}], remove: [{kind, ref}], escrowPin?, escrowPriv?, escrowPub?, escrowSignPriv?, escrowSignPub?, escrowSig?, kcv?, escrowReset?, current? \| reauth? }` (`kcv` with the first set-up and with every later wrap or pin: `400 kcv_required`, `409 kcv_mismatch`, `409 kcv_missing`; a first set-up is a compare-and-set, `409 drive_exists`, and refused for a Drive with content or keys but no wrap, `409 drive_keyless`; `escrowReset`: the owner reset a user's browser moved the Drive to, §3.2, recorded once per epoch, `429 rate_limited` after 5 in 10 minutes; `400 escrow_own` for an escrow wrap in the owner's own Drive) (the `escrow…` keys owner only; the step-up `current` / `reauth` where §3 says, `400 reauth_required` without it; a user's first set-up `409 escrow_not_ready` before the owner's escrow key exists, `400` without an escrow wrap for the current key and a wrap of the user's own; `403 escrow_required` for removing the escrow wrap; `409 last_wrap` / `last_own_wrap`) |
| `POST /api/private/drive/kit` | the owner (not impersonating): `{ event: "exported", current \| reauth }` → `{ ok, kit }` (records `{ version, kid, at }`; `409 no_escrow` without an escrow key); `{ event: "used", version?, current \| reauth }`; `{ event: "verified", verdict: "complete" \| "incomplete" \| "failed", issues?, version? }` (§3.1; all in the admin audit); a user `403 owner_only`, impersonating `403 impersonating` (as every kit, start-over and archive route) |
| `POST /api/private/drive/kit/probe` | the owner, with `{}` and the intent header (it writes to the admin audit): `{ probes: [{ kid, wrap }] }` — one user's escrow wrap per kid in use, each `drive.escrow_used` (the check's live proof); at most 30 per session per 10 minutes (`429 rate_limited`) |
| `PUT /api/private/drive/kit/keys` | the owner, with the step-up: `{ escrowPriv?: { pub, data }, escrowSignPriv?: { pub, data }, escrowPrivOld?: { <kid>: { pub, data } } }` — sealed escrow keys put back from a kit, only for `escrowPub`, `escrowSignPub` and kids in use (`400 key_mismatch`) |
| `POST /api/private/drive/start-over` | the owner, §3.2: `{ confirm, driveSalt, set: [pw], escrowPub, escrowPriv, escrowSignPub, escrowSignPriv, escrowSig, kcv, current \| reauth }` → `{ ok, escrowVersion, archive, ownerReset }` (`409 drive_unlockable`, also for the second of two at once; `409 reset_conflict`; `400 confirm_required`) |
| `GET /api/private/drive/archive/<gen>?after=<id>` | the owner: `{ gen, at, escrowPriv, escrowSignPriv, escrowPrivOld, items, nodes, next }` |
| `PUT /api/private/drive/archive/<gen>/nodes` | the owner, with the step-up: `{ nodes: [{ id, name, meta?, fk? }] }` (at most 500, folders first) → `{ ok, restored, left }` |
| `POST /api/private/drive/archive/<gen>/finish` | the owner, with the step-up: `{ escrowPrivOld?: { <kid>: { pub, data } } }` (`409 archive_not_empty`) |
| `DELETE /api/private/drive/archive/<gen>` | the owner: `{ confirm, current \| reauth }` — the archive deleted for good |
| `POST /api/private/drive/escrow` | the owner impersonating this user only: `{}` → `{ ownerId, escrowPub, escrowPriv, escrowPrivOld, wrap, wraps }` (`wrap` = the user's `escrow` wrap or null, `escrowPriv` / `escrowPrivOld` the owner's own sealed keys, `wraps` how many the user's Drive has); recorded `drive.escrow_used` (§9) when a wrap is returned; `403 not_impersonating` otherwise |
| `GET /api/private/drive/nodes/<id>` | the node and its children: `{ node, children: [...], path: [...ancestors] }` (`root` for the top; `path` root first, the node itself may be included). Each node: `{ id, parent, kind: 'dir' \| 'file', name, meta?, fk?, size, chunks, state, created, updated }` with the sealed fields as stored (`{ iv, ct }` objects or their JSON text), `size` in plaintext bytes, times in seconds; children include `meta` and `fk` for files (else the client fetches each file node). 404 for an unknown id |
| `POST /api/private/drive/folders` | `{ id, parent, name }` → `{ id }` (`id` chosen by the browser, §3; 409 if taken) |
| `POST /api/private/drive/files` | `{ id, parent, name, meta, size, fk }` → `{ id, uploadToken, chunks }` (`size` = plaintext bytes, `chunks = ceil(size / 8 MiB)`, §3; capacity checked) |
| `PUT /api/private/drive/files/<id>/chunk/<i>` | `application/octet-stream`, header `X-Upload-Token`; exact size check |
| `POST /api/private/drive/files/<id>/finalize` | header `X-Upload-Token` → `{ ok }`; `409 busy` while a chunk of the file is still being written (finalize again), `409 incomplete` while one is missing |
| `GET /api/private/drive/files/<id>/chunk/<i>` | ciphertext chunk for the user |
| `PATCH /api/private/drive/nodes/<id>` | `{ parent?, name? }` move / rename → `{ ok }`; 409 when `parent` is the node or inside it; the root cannot be moved, renamed or deleted |
| `DELETE /api/private/drive/nodes/<id>` | recursive; ends referencing shares; frees capacity; also used by the client to drop a failed upload's `pending` node |
| `POST /api/private/drive/shares` | `{ nodes: [file ids], views, expire, deletable?, label?, types?, depth?, paste, acc }` → `{ id, deletetoken }`: `nodes` lists **files** (the browser flattens folders), and `refs[i]` is `nodes[i]`; `types` / `depth` are the file-policy declaration, sent only when a policy applies (as for file shares); `paste` is the `encryptPaste` body (`acc` is also inside it) |
| `GET /api/private/drive/nodes/<id>/shares` | shares referencing the node — for a folder, every share that references a file under it: `{ shares: [{ id, label, kind: 'drive', created, expires, views_total, left, status, locked }] }` (My shares' row fields; `views_total` / `left` null = unlimited) |
| `POST /api/private/admin/drive/escrow/<userId>` | owner: `{ reason }` → `{ wrap, wraps }` (`wrap` = the user's `escrow` wrap or null; `wraps` = how many wraps the Drive has, never their data), recorded `drive.escrow_used` |
| `PUT /api/private/admin/drive/keys/<userId>` | owner, after resetting the user's password: `{ driveSalt, set: [{ kind: 'pw', ref: 'pw', data }], kcv }` (only a `pw` wrap of the same DK, nothing removed), recorded `drive.pw_rewrapped`; for a user with no wrap yet: `{ first: true, driveSalt, set: [pw, escrow], escrowPin, kcv }` (§3, "Drives the owner sets up"; `409 drive_exists`, `409 drive_keyless`, `409 drive_disabled`), recorded `drive.created_by_owner`; a pw wrap for a Drive without a key check value is refused (`409 kcv_missing`) |

While the owner impersonates a user, every Drive route works for the owner as for the user,
except that `PUT /api/private/drive/keys` accepts only wraps **added** for credentials the owner
gives the user (a `pw` wrap when there is none, with its `driveSalt`; `recovery` and `passkey`
wraps for new codes and passkeys); a first set-up (the user has no Drive yet: "has not signed in
since the Drive was enabled") and removing or replacing any of the user's wraps answer
`403 impersonating`. The two admin routes are closed then, as the whole
admin surface is. State-changing routes carry the usual intent header (`public/js/api.js`) and
upload / finalize the `X-Upload-Token` header. Drive shares are revoked with the existing
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
  impersonates a user, `openDrive` opens the user's Drive through the owner escrow (§3,
  Impersonation) and the page shows the Drive with a note that it is the user's, opened with the
  owner's escrow key, and that the user's own keys (password, recovery codes, passkeys) cannot be
  removed or replaced then because they unlock the Drive for the user and only the user can
  confirm such a change. When it cannot be opened, `startDrive` resolves to state
  `impersonating` with the `DriveLocked` reason (`no_drive`: "The user hasn't signed in since the
  Drive was enabled", `owner_locked`, `no_escrow`, `no_wrap`, `escrow_failed`, `escrow_mismatch`)
  and the page says what to do (`#drive-impersonating`).
  The Drive's unlock and key operations are not Account changes and take no human check
  (Turnstile).
- **Recovery kit and start over:** the owner's page shows the kit card (`drivekit-ui.js`
  `kitCard`, status and notice from `client.kit`, the forms in a disclosure), the archive box
  when `client.archives` is not empty (with "Delete the old Drive archive"), and, on the unlock
  screen, "Restore from your owner recovery kit" (`kitRestore`) and — when the `DriveLocked` has
  `ownerRecovery` — "Start over without a kit" (`startOverOwnerDrive`). The client functions:
  `buildOwnerKit`, `verifyOwnerKit`, `restoreOwnerKit`, `ownerKitStatus`, `startOverOwnerDrive`,
  `deleteOwnerArchive`, `ownerSetsUpUserDrive` (§3, §3.1, §3.2).
- **Escrow notices:** after an unlock, `client.notice` may hold `{ kind, text }`:
  `escrow_changed` (a user's Drive: the pinned escrow key is not the server's; "Trust the new
  key" calls `acceptEscrowKey()`), `escrow_rotated` (a user's Drive moved to an owner reset's
  key by itself, §3.2: shown once, no action), or for the owner `escrow_mismatch` (`restoreEscrowKey(step)`),
  `escrow_unreadable` / `escrow_missing` (`newEscrowKey(step)`) and `escrow_unsigned` (the
  escrow key lacks a valid signature by the signing key; `restoreEscrowKey(step)`), where `step`
  is the owner's confirmation. The page shows them above the Drive. The owner's Drive page also
  has "Replace the escrow key" (`rotateEscrowKey(step)`, with the password).
- **Opening:** `openDrive()` resolves to a `DriveClient` or throws `DriveDisabled` (the page says
  "Drive is not enabled for your account") or `DriveLocked` with `reason` and `credentialIds`
  (the passkeys with a Drive wrap). Reason `not_ready` (a user's Drive before the owner's escrow
  key exists): "Drive is not ready yet", no prompt. Reason `setup` (no wraps yet, the automatic
  set-up did not run): the prompt is "Set up your Drive" and offers only the password. Otherwise it offers the
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
- Names (typed, uploaded, or read back) are cleaned: the bidi overrides, embeddings and
  isolates, U+200B, U+FEFF, U+0085, U+2028 and U+2029 are removed, then NFC (`files.js`
  `cleanName`; the page says when a name was changed, and an older stored name shows cleaned).
  Hebrew, Arabic, ZWNJ / ZWJ and LRM / RLM stay. Every name is shown in a bidi isolate with its
  extension as its own LTR isolate (`common.js` `nameEl`). Typed names are also trimmed; empty,
  `.`/`..`, `/`, `\`, control characters and more than 255 UTF-8 bytes are refused (as
  `checkName` in the client), and so is
  a name already used in the same folder when creating or renaming (the server cannot check
  encrypted names). An upload keeps the file's own name unless the folder already has it: then it
  becomes "name (2).ext", "name (3).ext"… (`upload(…, { taken })` with the set from
  `names(folderId)`; `uploadTree` does the same per folder, merges into an existing folder of the
  same name and renames a new folder whose name a file already has).

## 9. Security notes

- Owner escrow means the owner can decrypt every user's Drive: this is a deliberate choice by
  the maintainer.
- **What is recorded, and where.** Drive actions are logged like every other action of the
  user's, and impersonation is invisible to the user (as for the rest of the account):
  - the user's own activity (`GET /api/private/me/activity`) lists their Drive actions —
    `drive.keys_changed` (wraps added or removed, the salt), `drive.folder_created`,
    `drive.file_uploaded`, `drive.file_read` (a file opened: its first chunk read),
    `drive.item_changed` (renamed, moved), `drive.item_deleted`, and for received files of a
    reverse share `drive.received_taken_in`, `drive.received_failed`, `drive.received_retried`
    (one row per link, per actor, per hour, adding up the files; [`REVERSE.md`](./REVERSE.md)
    §7) — and their Drive shares
    (`share.created`, `share.updated`, `share.revoked`). Node ids only, never names. A user's own
    file reads are throttled in the log (one row per file per minute, at most 30 a minute), so
    they cannot push other entries out;
  - what the owner does in the Drive while impersonating the user is recorded exactly the same
    way, as the user's own (`imp`, no `adm`): the user's activity shows it as theirs with no
    actor and no trace of the impersonation, and the owner-only admin audit shows the owner as
    the real actor, with `impersonate.start` and `impersonate.end` (never throttled);
  - the owner's use of the escrow is the owner's own action, recorded in the admin audit only:
    the admin escrow route (`drive.escrow_used`, with the reason), the re-key after a reset
    (`drive.pw_rewrapped`), and opening a Drive with the escrow while impersonating
    (`drive.escrow_used`, "opened while acting as the user"; `imp` and `adm`). Deleting an
    account's Drive with the account is an admin action too;
  - the owner's own recovery, in the admin audit only: `drive.kit_exported` (with the version),
    `drive.kit_used`, `drive.kit_verified` (with the verdict), `drive.kit_keys_restored`,
    `drive.owner_reset`, `drive.archive_restored`, `drive.archive_deleted`; a Drive the owner
    set up for a user is `drive.created_by_owner` there, and a system event with no detail in
    the user's activity; a user's automatic move to an owner reset's key is
    `drive.escrow_rewrapped`, a system event in the user's activity and, with the user, in the
    admin audit.
- DK in `sessionStorage` is readable by script on the origin; the CSP and Trusted Types are what
  keep other script out, as for the rest of the app. The pages that load the Turnstile script
  keep it out of `sessionStorage` (§3); what remains is in SECURITY.md.
- Capacity, sizes and chunk counts are enforced server-side; names and types are not (they are
  encrypted), so file-type rules for drive shares are enforced by the client, as for file shares.

## 10. Server notes (as built)

Details of the server side (`src/drive-do.js`, `src/routes/drive.js`) that the sections above
leave open:

- **Access.** Every `/api/private/drive*` route needs a session (an API key gets
  `403 api_key_not_allowed`); the public account gets `403 drive_unavailable`. With the role's
  Drive off, `GET /api/private/drive` answers `200 { enabled: false, wraps: [], … }` and every
  other Drive route `403 drive_disabled`. `GET /api/private/drive` also returns `maxFile` (the
  largest file allowed); `capacity` and `maxFile` are `null` when the role sets no limit (the
  hard 100 GiB then applies). `GET /api/private/me` has `caps.driveEnabled` (false for the public
  account, true for the owner). While impersonating, `PUT …/drive/keys` accepts only what §6
  says (else `403 impersonating`: never a first set-up); the admin routes are closed as usual.
- **Nodes.** `id` may be omitted (the server then picks one, which cannot be bound into the
  AAD). `PATCH` also accepts `meta`. `path` lists the ancestors as full nodes, root first.
  Children include pending files (`state: 'pending'`, `done` = chunks received). `DELETE`
  answers `{ ok, deleted, sharesEnded }`. Hard ceilings per Drive: 100 000 items, 10 000 per
  folder, 64 folder levels, 64 wraps, 1 000 shares per item.
- **Capacity.** `used` is every file's `size`, pending uploads included (reserved at
  `POST …/files`), plus the characters of every item's sealed fields (name, meta, fk), so they
  cannot store data outside the capacity; a folder, a file or a rename that would not fit is
  `413 drive_full`. Sealed names are at most 512 characters and metadata at most 1024.
- **Files.** Chunks may arrive in any order; sending one again replaces it (internal table
  `upchunks(node_id, i)`; `done` is their count). A pending upload with no chunk received for the
  role's `filePendingSec` is purged by the alarm, with its chunks. A file is readable and
  shareable only once finalized. Finalize answers `409 busy` while a chunk write for the file is
  in flight (the client finalizes again); a chunk write that completes after its upload ended
  (deleted, purged, the Drive destroyed) removes its object, never a chunk of a finished file.
- **Wraps.** Kinds `pw`, `recovery`, `passkey`, `escrow` only (anything else is `400`); `pw` and
  `escrow` have `ref` = their kind; a `passkey` wrap must name one
  of the account's passkeys and a `recovery` wrap one of its current codes. The server drops the
  wraps of passkeys and codes the account no longer has (a passkey removed, codes regenerated, a
  code spent at sign-in, the owner's "remove all passkeys"). A password change marks the `pw`
  wrap stale (`pwStale`); an admin reset drops it when a passkey or recovery wrap remains; writing
  a `pw` wrap clears the mark. An `escrow` wrap must carry the current escrow key's kid (the
  server computes it from `escrowPub`), and the Directory records it per user
  (`drive.escrowKid:<userId>`). Setting `escrowPub` needs a valid `escrowSig` once a signing key
  exists and is recorded (`drive.escrow_key_set`, in the owner's own log). A rotation moves the
  owner's previous `escrowPriv` to `escrowPrivOld` under the old kid (computed by the server);
  the owner's summary and the impersonation escrow route drop from it every kid no user's wrap
  is for.
- **Owner routes.** The escrow route needs a `reason` of 3–500 characters, records every call
  (`drive.escrow_used`, with the reason) and answers only the escrow wrap (`wrap: null` when the
  user has none) and the number of wraps;
  `PUT /api/private/admin/drive/keys/<userId>` refuses the owner's own id (use one's own Drive)
  and records `drive.pw_rewrapped`. Both are direct admin actions: in the admin audit, never in
  the user's own activity.
- **Shares.** A folder id in `nodes` is refused (`400 not_a_file`); files must be finalized
  (`409 not_ready`). `acc`, when sent both inside `paste` and next to it, must be the same. The
  stream-size caps (`maxShareBytes`, `maxFileBytes`) do not apply (nothing is uploaded; the files
  are within the Drive's own limits). The response also carries `expires`.
  `GET …/nodes/<id>/shares` lists the active shares that reference the node or, for a folder,
  any file below it (a shared folder is stored as its files), as My shares rows
  (`id`, `kind`, `label`, `created`, `expires`, `views_total`, `left`, `status`, `locked`) plus the
  aliases `state` (= `status`) and `maxViews` (= `views_total`); revoke them as any share.
  Deleting a node ends its shares (and those of every file below it) even when locked by the
  admin: the data is gone. Share ids are looked up in batches of 90 (the SQLite bound-parameter
  limit), and a Drive share that ends in any way (revoked by the user or the admin, deleted by
  its recipient, used up, expired) is dropped from the Drive's `refs`, so the per-item limit of
  1 000 shares counts live ones.
- **Received files** (reverse shares, [`REVERSE.md`](./REVERSE.md)). `nodes.rs` names the
  reverse share of a file an anonymous uploader sent and the user's browser has not yet
  re-wrapped; such files count in the capacity (their content and, until re-wrapped, their
  sealed path, metadata and wrap) but are left out of `children`, cannot be read,
  moved, renamed or shared, and are listed by `GET /api/private/drive/received` until re-wrapped
  (`POST /api/private/drive/received/<id>`). Their `fk` is `{ kind: 'rs', data }`. Deleting a
  folder ends the reverse shares that target it or anything below it.
- **Accounts.** Deleting an account first ends every share of its Drive, then deletes the Drive
  (every R2 object, its state), each step retried; only then is the account deleted. If the Drive
  cannot be removed the account stays (`503`), and deleting it again retries. The
  Directory mirrors each Drive's usage (`drive_usage`); Admin → Users gets
  `drive: { enabled, used, capacity }` per user (`capacity` null = no limit; `drive` null for the
  public account).

## 11. Browser ↔ server integration checklist

What the browser (`public/js/driveclient.js`, the Drive page, the sign-in) relies on, and how the
server (§10) meets it. The browser side is also tested against an in-memory stand-in of this
API (`test-dom/drive-fake-server.js`), which must stay in step with the server.

1. **Nav:** `/api/private/me` → `caps.driveEnabled` (owner true, public account false).
2. **Account:** login responses keep `user: { id, role }`; `/api/auth/session` keeps `user` and
   `impersonatedBy` (the sign-in unlock and the tab key's user binding use them).
3. **State:** `GET /api/private/drive` as §6; `{ enabled: false }` and the 403s read as "no
   Drive"; `capacity: null` (no limit) shows "no limit" without a meter.
4. **Keys:** `PUT /api/private/drive/keys` by `(kind, ref)`; removing a missing wrap is no
   error; `recovery` refs are the server's code hashes (hex
   `SHA-256("secbin-recovery/v1:" ‖ normalised code)`), `passkey` refs the stored credential ids
   (base64url of the raw id, as `passkeys.js` sends `rawId`); the server drops wraps of passkeys
   and codes that are gone (the client never removes one); `400 reauth_required` for a change
   that needs the step-up without it (§3); `409 escrow_not_ready` before the owner's escrow key;
   `403 escrow_required`, `409 last_own_wrap`; while impersonating only added wraps (§6), else
   `403 impersonating`; `escrowPin`, `pwStale`, `escrowSignPub`, `escrowSig` in the summary.
5. **Ids:** the browser always sends its 22-character node id (the AAD binds it); `409` when taken.
6. **Files:** `chunks = ceil(size / 8 MiB)` exactly (the client refuses any other answer), chunk
   `i` exactly `min(8 MiB, size − i · 8 MiB) + 16` bytes under `X-Upload-Token`, finalize, and
   raw chunk reads; capacity counts pending uploads; a failed upload's pending node is deleted by
   the client (`DELETE`), else purged by the alarm.
7. **Listing:** `path` root first (full nodes); children include `meta` and `fk` for files and
   pending uploads (`state: 'pending'`, hidden by the client); folders have no `size`; times in
   seconds; the root's `name` is null (the client names it).
8. **Moves:** `PATCH` refuses cycles and the root; `DELETE` is recursive and ends the shares of
   everything below.
9. **Shares:** `POST /api/private/drive/shares` takes file ids only (`400 not_a_file` for a
   folder; the client flattens), finalized files only; `types` / `depth` when a policy applies;
   `→ { id, deletetoken }` with an `f…` id. `GET …/nodes/<id>/shares` returns My-shares rows,
   for a folder those of the files below it; revoke is `POST /api/private/shares/<id>/revoke`;
   My shares and Admin → Shares show kind `drive`.
10. **Recipients:** `POST /api/file/<id>/open` adds `refs: [{ chunks, size }]` in `nodes` order;
    `GET /api/file/<id>/chunk/<ref>/<i>` under `X-Download-Grant`.
11. **Owner:** `POST /api/private/admin/drive/escrow/<userId>` `{ reason }` → `{ wrap, wraps }`
    (`wraps`: a count; `wrap: null` → the client reports `no_wrap`, or sets the Drive up when
    `wraps` is 0); `PUT /api/private/admin/drive/keys/<userId>`
    with only a `pw` wrap and `driveSalt`; impersonating, `POST /api/private/drive/escrow` →
    `{ ownerId, escrowPub, escrowPriv, escrowPrivOld, wrap, wraps }`.
12. **Sign-in:** a recovery-code sign-in's response carries `driveSpent` (the spent code's wrap,
    removed on the server) for the sign-in's unlock; the first sign-in with the Drive enabled
    sets the Drive up (§3, automatic set-up).
