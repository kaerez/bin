# Drive: design and interface contract

Status: the contract the Drive is built against (server, keys and client, UI). A change to
anything in this file is a coordinated change: update it first.

## 1. What it is

- Each **user** (not the public account) whose role allows it has a **Drive**: a private folder
  tree of files and folders within a role capacity. It exists as soon as the role allows it:
  there is no set-up and no unlock step.
- A drive file or folder can be **shared** any number of times. Each share has the same options as
  a file share (views, expiry, password, "delete now", label), obeys the same role limits and
  quotas, and shows in My shares. When a share expires, is used up, revoked or deleted, **only the
  share goes; the drive data stays**. Shares reference the drive's stored ciphertext; nothing is
  copied or re-encrypted.
- Deleting a drive item ends every share that references it (recipients get "gone").
- **Reverse shares** ("Receive…", [`REVERSE.md`](./REVERSE.md)): anonymous uploads land in
  a Drive folder the user chooses, encrypted to the link's key until the user's browser takes
  them in.
- Terminology: the person who owns a drive is the **user**; "owner" means the admin.

## 2. What the server sees, and what it can open

**Drive files are not end-to-end encrypted.** Encryption happens in the browser, and the Drive's
storage (R2 and the user's Drive Durable Object) holds only ciphertext and sealed keys. But the
server derives every user's key-encryption keys (KEKs, §3) from keys it keeps itself — the root
MEK and the sub-MEKs, in the Directory Durable Object — so **the server, and anyone with a copy
of the Directory's storage** (a compromised Cloudflare account, a malicious deploy, an insider),
**can decrypt every Drive file**. A leak of R2 or of a Drive Durable Object **without** the
Directory reveals nothing: file content, names, types and file keys are sealed under keys that
exist only in the Directory (and in kits the owner or the users downloaded).

Notes and file shares stay end-to-end encrypted (the key is in the link, never on the server).
A Drive share's manifest is sealed the same way (§7), but its content is the Drive's
ciphertext, whose DEK is also sealed under the user's KEK: the server can open a Drive share's
files as it can any Drive file. Reverse-share uploads are encrypted in the uploader's browser to
the link's key, whose private key is sealed under the user's KEK: the server can open them too,
before and after the user's browser takes them into the Drive (then they are sealed under the
user's KEK like any Drive file).

The server also sees the tree's shape (node ids, parent ids, file/folder), each file's exact
ciphertext size and chunk count, timestamps, and which shares reference which nodes, as before.

## 3. Keys (the key model v2)

| Key | What it is | Where it is kept | Who can have it |
|---|---|---|---|
| **root MEK** | 32 random bytes, one per instance | Directory (meta `mek.root`) | the server; the owner (Show, the key kit, an export) |
| **sub-MEK** | 32 random bytes each, with a start (`from`) and an end (`until`, or open-ended); one is current | Directory (`meks`), sealed under the root MEK | the server; the owner |
| **user salt** | 32 random bytes per account, made with the account, never changed | Directory (`user_salts`) | the server; the owner; the user's personal kit |
| **KEK** | `HKDF-SHA-256(ikm = root MEK ‖ sub-MEK, salt = user salt, info = "secbin-kek/v1\n<userId>")`, one per user per sub-MEK | nowhere (derived when needed) | the server; the user's session (and the owner acting as the user); the user's personal kit |
| **DEK** | 32 random bytes per file, made in the browser; encrypts the content | with the item, sealed under the KEK | whoever has the KEK |
| **user key** (field layer) | `HKDF(ikm = root MEK, salt = user salt, info = "secbin-user/v1\n<userId>")`; each field key `HKDF(user key, "", "secbin-atrest/v1\n<field>")` | nowhere (derived) | the server only |

- **Content.** Each file gets a random DEK in the browser; its content is encrypted in chunks
  exactly like a file share's (`encryptChunk(DEK, i, n, plain)` from `public/js/files.js`, AAD
  `(i, n)`), with no padding: `n = ceil(size / 8 MiB)` (an empty file has no chunks) and chunk
  `i` is exactly `min(8 MiB, size − i · 8 MiB) + 16` bytes.
- **Per-item salt (`ks`).** 32 random bytes per item, chosen by the browser.
- **The DEK seal.** `AES-256-GCM` under `HKDF(ikm = KEK(sub-MEK m), salt = ks, info =
  "secbin-dek/v1")`, AAD `"secbin-dek/v1\n<userId>\n<mekId>"` — `{ iv, ct }`, base64url.
- **Names and metadata.** The same pattern: `HKDF(KEK, ks, "secbin-names/v1")`, AAD
  `"secbin-names/v1\n<userId>\n<mekId>\n<field>"` with field `name` or `meta` (the metadata is
  JSON `{ type, mtime, size }`; `size` lets the client check the server's).
- **The item id is not part of any seal.** A seal is bound to the user, the sub-MEK, the item's
  salt and the field, so it cannot be moved to another user, another sub-MEK, another field or
  another item's salt; moved to another item together with its salt, it still opens (§9).
- **What is stored with each item:** the sealed name and metadata, the sealed DEK, `ks`, the
  sub-MEK's id (`mek`) and fingerprint (`mfp`), and for a file its **ciphertext hash** (`ch`):
  `SHA-256("secbin-ch/v1\n<n>\n" ‖ the chunks' SHA-256s, one per line)`, computed by the server
  from the chunks it received (never a hash of the plaintext). Files uploaded before it existed
  get it from the Drive object's alarm. The browser computes it again from the chunks it
  downloads and refuses a file whose chunks do not give it (the last chunk is never handed over);
  a file with no hash yet is read as before. It is integrity metadata the server keeps, not a
  seal: the per-chunk GCM check under the DEK is what binds the content (§9).
- **Fingerprints and check values.** A key's fingerprint: the first 8 bytes of
  `HMAC-SHA-256(key, "secbin-mek-fp/v1")`, base64url (shown as `xxxx-xxxx-xxx`). A kit's check
  values: `HMAC-SHA-256(key, "secbin-kek-check/v1")` for a KEK, `"secbin-mek-check/v1"` for the
  root MEK or a sub-MEK, and `HMAC-SHA-256(salt, "secbin-salt-check/v1\n<userId>")` for a user
  salt; the server compares them in constant time and answers match or no match only.
- **Sub-MEKs sealed under the root:** `m1.<iv>.<ct>`, AES-256-GCM under
  `HKDF(root MEK, "", "secbin-mek-seal/v1")`, AAD `"secbin-mek/v1\n<mekId>"`.
- **The field layer.** What only the server needs to hold for a user is also sealed at rest in
  the Drive object with the user's field key, as `a1.<iv>.<ct>` with AAD
  `"secbin-atrest/v1\n<userId>\n<field>\n<ref>"`: a reverse link's sealed private key (field
  `linkKey`, ref the link id) and a received file's uploader-sealed path, metadata and wrap
  (field `received`, refs `name:<id>`, `meta:<id>`, `wrap:<id>`). The Worker takes the layer off
  before it hands them to the user's browser.
- **The timeline.** The sub-MEK in effect at a time is the one with the latest start among those
  whose interval holds it; exactly one is open-ended; there is always one in effect now (the
  **current** one) and no gap from now on (`drivekeys.js` `effectiveAt`, `checkTimeline`). New
  items are sealed under the current sub-MEK; reading never depends on dates (every item names
  its sub-MEK).

**Opening the Drive.** After sign-in, `POST /api/private/drive/keys` (`{}`: a change like any
other, with the CSRF token, since it may make the account's salt and is audited for the owner
acting as the user) returns the user's KEK for
every sub-MEK their items use and for the current one (`{ userId, current, keys: [{ mekId, fp,
from, until, kek }] }`). There is no prompt: passwords, passkeys and recovery codes are not
involved (the session is what the server trusts, and the step-up rules for sensitive actions stay
as they are). The browser keeps the KEKs in the page's memory only, never in browser storage,
and asks for them again at every page load; a failure is shown as an error, with no stored key to
fall back on, and nothing read from storage is ever used as a key (a value planted there by other
script on the origin is ignored). Slots a release before used (`secbin_kek`, `secbin_kek_imp`,
`secbin_dk_imp`, `secbin_dk_imp_uid`) are removed at each Drive open and dashboard load. The keyring is created on first need (at set-up, below, or at the first
Drive request) and only if there never was one (`mek.ever`): a keyring that was lost is never
replaced silently — the key kit restores it.

**New items.** The browser makes the DEK and `ks`, seals the DEK, the name and the metadata under
the current KEK and sends them with `ks` and `mek`. The Worker opens each seal once with the
current KEK before it stores it (`400 bad_seal` when it does not open; `409 mek_not_current` for
another sub-MEK — the browser fetches the keys again and seals once more) and keeps nothing it
opened. A rename seals the new name under the item's own `mek` and `ks` (`409 stale_keys` when
the server re-sealed the item meanwhile: the browser reads it again). During a root change a new
name must be sealed under the KEK of the new root: one sealed under the previous root (a page
that fetched its keys before the change) is `409 stale_keys` too, and the browser fetches its keys
again; nothing new is ever stored under a root that is going.

**The owner acting as a user.** `POST /api/private/drive/keys` returns that user's KEKs to the
owner's session (`drive.keys_used` in the admin audit, §9), in the page's memory only.

**Re-sealing (the server alone).** The Worker derives every KEK, so it re-seals on its own —
opening each DEK and name and sealing it again under another KEK, inside the Worker, never
stored or logged in the clear — for:
- a **re-seal** of a sub-MEK: everything under it moves to the current one (Admin → Security →
  Keys, "Re-seal");
- **deleting a sub-MEK**: a re-seal first, then the delete, only when nothing is left under it
  (`409 in_use` otherwise); never the current one (`409 current_key`) or the only one;
- **changing the root MEK**: the sub-MEKs are re-sealed under the new root at once, every KEK and
  field key changes, and every item, link key and field-layer value is re-sealed under the new
  ones (each of an item's fields under either root: a rename during the change seals only the
  name under the new one); until that is done the previous root stays (`mek.rootOld`) and a
  session gets both KEKs (`kekOld`). Then every Drive is checked once more (those made meanwhile
  too): every item, link key and field-layer value must open under the new root only; only then
  is the previous root removed. A root change waits while any Drive still has something of the
  release before in it (`409 migration_pending`, with those Drives; §3.3): link keys of the
  release before are the upgrade's, and a root change leaves them as they are.
- **a root change that cannot finish** (the check found items under neither root, or only under
  the previous one): the previous root is kept for them and the items are listed; the check's
  count is kept with the root change (`mek.rootCheck`), not only with the job, which can be
  cleared. The owner runs the re-seal again (`POST …/keys/jobs { kind: 'root' }`, after putting
  them right: a kit, an import), goes back to the previous root (`POST …/keys/root/undo`: the
  roots swap, the sub-MEKs are sealed under the previous one again and every item is re-sealed
  under it; then the root that was new goes), or removes the previous root and leaves those
  items unreadable (`POST …/keys/root/drop-old`, its fingerprint typed; the page and the answer
  say how many; `keys.root_old_dropped` with that count). "Go back" returns only to a root this
  server worked with (`origin: 'changed'`), or to one put back from a key kit that opens items
  here when it is asked (else `409 unproven_root`). "Remove" needs the root change's check of
  those two roots (else `409 not_checked`: run the re-seal again first). Each needs the step-up.
  The key kit, a restore and an import work during a root change.

These run as a **job** the owner's browser drives (`POST …/keys/jobs/step`, a few seconds of work
per call, with its progress) over every Drive that can hold anything sealed under a KEK or a
field key (every account with a user salt, not only those with a usage row: a Drive whose only
content is a reverse link counts too): Drive by Drive, page by page, each write a compare-and-set
on the item's `mek`, `ks` and sealed fields as stored (a change made meanwhile, such as a rename,
is never overwritten; up to three passes pick such items up). A sub-MEK is deleted only when a
count over those same Drives finds nothing under it. Cancelling a re-seal needs the step-up; a
root change is not cancelled (it is finished, undone or its old root dropped).

**Reverse shares.** The uploader seals to the link's public key as before. The link's private
key is sealed under `HKDF(KEK, "", "secbin-reverse-link/v1")`, AAD
`"secbin-reverse-link/v1\n<userId>\n<mekId>\n<linkId>"`, and stored at rest under the field
layer. At take-in the browser opens the upload with the link key and seals its DEK (the
uploader's file key), name and metadata under the current KEK like any new item.

**Set-up (AUTHN).** The set-up page asks the server to propose the root MEK and the first
sub-MEK (the default: "Generate the keys", `POST /api/auth/setup/candidate` with the setup
token), shows them masked until Show (each with its fingerprint and a copy button), with "Use
these", "Generate again" and "Enter manually" — the same pieces as Security → Keys' key chooser
(`public/js/keychoice.js`) — or takes two keys the owner made out of band (32 bytes each, hex or
base64, e.g. `openssl rand -base64 32`; they must differ). A proposal is two candidates kept
for 10 minutes (the table `mek_candidates`, sid `setup:`), made only for an unspent setup token
while no owner exists (`410 token_used` otherwise) and while there is no keyring and never was
one (`409 keys_exist`); a new one replaces the last, a network gets 20 per 10 minutes (`429
rate_limited`, the Guard's `setup-candidate` scope), and no proposal is logged: only the pair
the set-up adopts is (`keys.created`, by fingerprint). Nothing is stored until the set-up sends
the chosen pair's ids (`keys: { mode: 'generated', root, sub }`), checked before anything is
written (`410 candidate_expired`: nothing is created). The chosen pair — like keys entered by
hand — is written in the same transaction as the owner account: if the keyring cannot be
written, the owner is not made either and the token stays unspent, so a set-up never ends with
other keys than the ones shown. The page refuses to create the owner before "Use these" (or the
keys entered by hand). Copying a key (here and in Security → Keys) empties the clipboard after
60 s only where the page may read it back to check it still holds the key; this site's
Permissions-Policy denies `clipboard-read`, so the page says to clear it instead. An owner
recovery keeps the keys there are. After the set-up the page says to download the key kit.

**Pages with third-party script.** The KEKs are never in the tab's storage. The one Drive key a
tab may keep in `sessionStorage`, the old Drive key of the release before (§3.3), leaves it for
the page's memory before anything can load the Turnstile script (`holdSessionKeys`); the sign-in
page writes it back as it leaves, and the home page's public composer clears it.

### 3.1 Kits

A kit is a file made and read only in the browser (`public/js/drivekit.js`), sealed under a
passphrase with Argon2id (m = 64 MiB, t = 3) and AES-256-GCM; its kind, account and origin are
bound into the AAD, so it opens only for its account on its server. The passphrase is optional,
with no minimum; the page warns when it is empty or short.

- **Personal kit** (`secbin-user-kit/2`, Account → Drive personal kit, every user, the owner
  included): the account id, username, user salt and the KEK of every sub-MEK the Drive uses
  (and the current one). With a copy of the stored ciphertext it opens that user's files and
  reverse-share links offline. The Account page offers Download and Verify only, the same for
  every account (the owner's own included): only the owner restores from a personal kit, in
  Admin → Security → Keys ("Restore a user's personal kit", below), so no user can change what
  opens a Drive (and lock the owner out of its files). Downloading it needs the step-up
  (`drive.kit_exported` in the user's activity); the owner acting as a user cannot download or
  verify one (`403 impersonating`), and the Account routes of a restore
  (`…/drive/kit/restore`, `…/drive/kit/items`) answer `403 owner_only` to everyone.
- **Key kit** (`secbin-key-kit/1`, Admin → Security → Keys): the root MEK, every sub-MEK with its
  dates and every user salt. It restores everything. The download needs the step-up and is
  recorded (`keys.kit_exported`, and what it covers: after a change to the keys or a new account
  the page says to download a fresh one). During a root change it also holds the previous root
  MEK (`rootOld`: items not re-sealed yet open under it), so a backup can always be made.
- **The key version** (both): the Directory counts every key change (meta `mek.version`, `{ n,
  at }`): a sub-MEK added, rotated, deleted, made current or its dates edited, a root change or
  its undo, a restore that writes a root MEK or a sub-MEK. A note, a re-seal finishing or a
  salt put back are not key changes. A new keyring is version 1 (one made before versions were
  kept counts as version 1 until its next change). Both kits hold the version they were made at
  (`keyVersion`: a number in the personal kit, `{ n, at }` in the key kit; the formats stay
  `secbin-user-kit/2` and `secbin-key-kit/1`, and a file without it still opens and verifies),
  and both cards show "Version N, <date>" of the keys now.
- **A personal kit out of date.** Each download is recorded for the account (meta
  `ukit:<userId>`: its date, the key version and the sub-MEKs whose KEKs it holds; removed with
  the account). The kit is **stale** when a later key version exists, or when the current
  sub-MEK is one it does not hold (a scheduled one that has started). Then the Account page
  (near the top, and in the kit card) and the Drive page say "Your Drive’s keys were updated.
  Download a new personal kit and keep it safe." — no key, fingerprint or version in the
  notice. The kit card also shows "Last downloaded: <date> (version N)", or never. A kit never
  downloaded shows no notice. Only the user's own download updates the record: the owner acting
  as the user is refused (`403 impersonating`) and sees no notice on the Drive page.
- **The CAPTCHA** (the personal kit on Account): with Turnstile on, Download and Verify wait for
  the card's widget and each request carries a fresh token for `account` (checked before the
  step-up, as every Account change; SECURITY.md, *Cloudflare Turnstile*). Without Turnstile keys
  there is none.
- **Verify** (both): read-only, on a file the person selects (never a copy the page kept; the
  input and the passphrase are cleared after use). The kit opens in the browser; only check
  values are sent (§3), and the server answers match or no match for each key and the salt. A
  date picker (today by default; a future date too) shows the sub-MEK in effect then and whether
  the kit holds it, and the file's key version is compared with the server's (the same, older —
  the keys changed after it: a warning —, or not recorded). At most 30 checks per session per 10
  minutes (`429 rate_limited`); failed openings are throttled in the page.
- **Restore** (both, the owner only, in Admin → Security → Keys): only what the server lost comes
  back; working keys are never replaced. For the key kit: the root MEK when there is none (or none of the sub-MEKs opens under the one
  there), or — with "Use the kit's root MEK" — on an instance with no Drive item or link key yet
  (never during a root change); the previous root MEK of a kit made during a root change, when
  this server has none and an item, a link key or a link key's field layer here opens under it
  (else it is reported `unused` and not written; then the root change's re-seal runs again);
  sub-MEKs that do not open
  here (with the recorded fingerprint), and a sub-MEK id this server does not have only when it
  opens an item or a link key sealed under that id here (else it is reported `unused` or
  `wrong`); user salts of accounts that have none, only when the salt opens one of that
  Drive's items, link keys or received files (or the Drive holds nothing sealed under it: else
  `wrong`, not written). Keys lost together are checked together (the kit's root and sub-MEKs
  stand in for those this server lacks). The preview and the restore both need the step-up (the
  preview tells which of the file's keys match this server's).
  For a user's personal kit ("Restore a user's personal kit"): the owner picks the user, then the
  kit file and its passphrase. The kit opens in the owner's browser for that user only (another
  account's kit fails there, and the server refuses a kit whose id is not the chosen user's:
  `400 kit_mismatch`); its salt and KEKs are sent, never the file. The server puts the user salt
  back only when the account has none and only when it opens one of that Drive's items, link keys
  or received files (or the Drive holds nothing sealed under it: else `wrong`, not written — the
  same salt proof as the key kit's); then it opens, with the kit's KEK, the items and link keys
  sealed under a sub-MEK it can no longer open (missing, or not opening under the root) and seals
  them again under the current one — the key jobs' re-seal step, compare-and-set; what does not
  open with the kit stays as it is. Items under a sub-MEK the server still opens are never
  touched, and the kit's KEKs are never kept. Each call needs the step-up and works a few seconds
  at most; a large Drive takes more calls, each resuming where the last one stopped (the page
  asks a password once, a passkey again for each call). Admin audit: `drive.kit_restored` and
  `drive.salt_restored`, ids and counts only. Neither the key-kit restore nor the import covers
  this: a personal kit holds KEKs, not the sub-MEKs they are made from, and an import only checks
  a KEK; the salt check (`saltCheck`) and the re-seal step (`sealStep`) are the same code.

### 3.2 Admin → Security → Keys

The owner manages the keyring there, never while acting as a user, each action with its help
text: the **root MEK** (fingerprint and date; Show; Change root…), the **sub-MEKs** (id,
fingerprint, dates, status — current, scheduled, retired or overlapped —, how many items use
each; Show, Edit dates, Set as current, Re-seal, Delete; "Add a sub-MEK…" from a date, "Rotate
now…"), the key kit (Download, Verify, Restore), the upgrade of Drives made before the key
model v2 (§3.3), one user's keys (their salt and KEKs, or their files' DEKs with names:
masked until "Show", hidden again after 60 seconds) and "Restore a user's personal kit" (§3.1). A new key is either **generated** by the
server (a candidate shown with its fingerprint: "Use this key" or "Generate another"; kept for
10 minutes for that session only, used once and only for what it was made for — a root MEK or a
sub-MEK, `409 candidate_purpose` otherwise; an unused one is deleted once its 10 minutes are over,
at the next keyring call or the hourly alarm) or **entered by hand** (hex or base64, 32 bytes,
with the out-of-band help; a key of one repeated byte is refused). Every change and every Show
needs the step-up (the password, or a passkey), and is in the admin audit by fingerprint, never
with a key (`keys.created`, `keys.candidate`, `keys.added`, `keys.rotated`, `keys.dates`,
`keys.current`, `keys.removed`, `keys.viewed`, `keys.root_changed`, `keys.root_change_done`,
`keys.root_old_dropped`, `keys.kit_exported`, `keys.kit_verified`, `keys.restored`,
`keys.exported`, `keys.export_verified`, `keys.imported`).
After a change the page says to download a fresh key kit.

**Import / export** (Admin → Import / export → Drive keys): a file of its own
(`secbin-keys-export/1`), never inside the account export, sealed in the browser under the
export passphrase (optional; the page warns when it is empty). The parts: the root MEK; the
sub-MEKs (all, or those chosen); the user salts of the users picked; and for those users their
KEKs and, optionally, their files' DEKs (all, or the file ids listed). Users are picked with a
search, Select all / Deselect all (of those shown), an uploaded id list (one per line, or a JSON
array) and a download of the chosen ids (a plain text list of user ids, one per line, with no
keys, to choose the same users again later). "Build the export" puts the parts ticked into it;
the server builds the document after the step-up; the page shows it masked (each value behind
"Show"), and "Encrypt and download" seals it under the export passphrase and saves it.
**Verify** (read-only) checks a saved file before it is relied on: it is decrypted in the
browser, and after the step-up the server compares it with its own keys and changes nothing.
The root MEK, the sub-MEKs, the user salts and the KEKs are sent as check values (never the
keys), compared in constant time with what the Directory holds or derives; each DEK is sent and
tried on its file's first chunk (the GCM check). The page lists, per part: the root MEK (match
or not, with both fingerprints); each sub-MEK (match, differs, unknown here, or here but missing
from the file); each user in the file (the salt, each KEK, and how many DEKs open their file,
fail, are for no file here, or are for empty files); and, for a chosen date (today by default),
whether the file holds the sub-MEK in effect then (as a sub-MEK, or as each user's KEK). The
verdict is "Everything in this file matches this server", or what does not match. No key value
is returned; the admin audit (`keys.export_verified`) holds the result, the root's fingerprint
and counts only. An import is
decrypted in the browser, previewed (a dry run, with the step-up: it checks KEKs and names the
users), then applied with the step-up; it never
replaces working keys: the root MEK, sub-MEKs and salts as a key-kit restore; a KEK is derived,
so importing one only checks it (match, mismatch, or no such sub-MEK here); a DEK restores an
item's DEK seal only when it is missing or does not open, and only after it opened the file's
first chunk (the GCM check), sealing it under the current KEK (a name that no longer opens
becomes `restored-<id>`).

### 3.3 The upgrade of Drives made before the key model v2

Drives made by the release before (a random Drive key, DK, in wraps the user's password,
recovery codes, passkeys and the owner's escrow opened) are upgraded once, without losing data.
Migration 16 marks every account that may have one (the owner, and each user with a Drive usage
row or an escrow wrap) as `pending` (`drive_migration`).

- **Opening the old DK.** Only in a browser, with what the old release used
  (`public/js/drivev1.js`): at the user's sign-in (the password, a recovery code or a passkey's
  PRF output), kept in the tab (`secbin_dk`) only while the Drive waits (the tab drops it when it
  opens the Drive and nothing waits any more: upgraded elsewhere, or by the owner; the owner's
  own once the escrow clean-up is done); with a recovery kit of that release
  (`secbin-owner-kit/1`, `secbin-user-kit/1`, opened in the browser only: the Drive page's "Use a
  recovery kit of the previous release", when no wrap opens any more); or in the owner's
  browser, through the owner's escrow of that release (the owner's own old DK, opened at the
  owner's sign-in, opens the owner's sealed escrow private key, which opens the user's escrow
  wrap, handed out with the step-up: `drive.escrow_used` in the admin audit). An old DK read from the tab, and one an escrow
  wrap gives, is used only once it is proven to be that Drive's (`driveupgrade.js`
  `isThisDrivesKey`): its key check value is the server's (`kcv` of the release before); a Drive
  without one must have an item name or link key it opens. A key that fails is removed from the
  tab and the upgrade stops (`wrong`), so a value planted in `sessionStorage` never re-seals, or
  marks as damaged, anything.
- **Re-sealing.** Every item's name, metadata and file key (now its DEK), and every reverse-link
  key, is sealed again in that browser under the user's KEK of the current sub-MEK, opened again
  there, and sent (`PUT …/migrate`). The server checks each opens under the KEK and stores it
  only where the item is still sealed the old way (a compare-and-set): the upgrade can stop at
  any time and resume, and a repeat changes nothing. An item the old key cannot open (damaged in
  storage) is kept under a placeholder name (`damaged-<id>`) and, for a file whose key is lost
  too, a random DEK (its content was already unreadable). A reverse-link key the old DK does not
  open (damaged, or sealed under an archive's key by a start over of that release) holds the
  upgrade: the page lists those links and its user retires them (`POST …/migrate/retire`, the
  step-up; the owner through Admin for a user's Drive): each link ends, its key goes, and the
  files it received that were not taken in are listed as failed, to be deleted
  (`drive.links_retired`). A Drive that is upgraded stays upgraded: a late or repeated
  `PUT …/migrate` is `409 already_upgraded`, and nothing sets it back to waiting.
- **Verifying, then removing.** `POST …/migrate/finish` checks, a page per call from where the
  last call stopped (the cursor is the server's, so no page can be skipped), that every item and
  link key opens under the user's KEKs (items upgraded after the cursor passed them were each
  checked when they were written; neither check opens a file's content, so a "damaged" item's
  random DEK passes). Only after the last page are the old key wraps and the Drive's old salt,
  pin and check value removed; a failure starts the check over and removes nothing. The owner's
  own old wraps and sealed escrow keys stay until every Drive is upgraded (they open the users'
  Drives), and then go with the Directory's escrow records (`drive.migration_done`): after the
  last upgrade, or after the last account still waiting is deleted, or when Admin → Security →
  Keys finds nothing waiting.
- **Where.** The Drive page upgrades the user's own Drive by itself, with its progress (asking
  once for the account password or a recovery code when the tab has no old DK); Admin →
  Security → Keys lists every Drive waiting (a disabled account's too) and upgrades a user's
  Drive through the escrow, per user or all at once (the owner's password asked once). The owner
  acting as a user cannot upgrade that Drive from the Drive page. An item still sealed the old way
  cannot be renamed until then; a tab that holds the old DK reads, downloads and shares it as the
  release before sealed it, and any other shows it as "waiting for the upgrade". The root MEK
  cannot be changed while a Drive waits with something of the release before in it.
  `drive.migrated` is in the admin audit (with the owner as the actor when the owner did it) and
  a system event in the user's activity.
- **While a Drive waits,** the old wraps are kept current as before: a spent recovery code's wrap
  goes (handed once to that sign-in, `driveSpent`), the wraps of removed passkeys and replaced
  codes go, and an admin reset removes the old password wrap when another wrap of the user's own
  remains (else it is marked stale). This holds for the owner too: a passkey the owner removes,
  or codes the owner replaces, lose their wrap at once (Account notes, while Drives wait, that
  they can still be upgraded with the owner's other sign-in methods and the escrow). An AUTHN
  owner recovery keeps the owner's old wraps while any Drive waits (the owner's old DK opens every
  user's escrow wrap, and the paper recovery codes still open their wraps): they are marked held
  (`wrapsHeld`), a later passkey or code change leaves them, and they go with the escrow
  clean-up.
- **The owner's archive** of the release before (a Drive started over, with the uploads its
  paused links had received) is kept as it was, is not counted in the capacity, and opens with
  nothing here. The owner deletes it in Admin → Security → Keys (`DELETE
  /api/private/admin/drive/archive`, the step-up and the username typed): its R2 objects and rows
  go, the links it paused are retired as above (`drive.archive_deleted` in the admin audit).

## 4. Storage (server)

- A **Drive Durable Object per user**: `env.DRIVE.idFromName('drive:' + userId)` (SQLite DO
  class `Drive`, binding `DRIVE`). Tables:
  - `nodes(id, parent, kind, name, meta, size, chunks, state, done, upload_hash, created,
    updated, ks, mek, mfp, dek, ch, …)`: the root has `parent = NULL` and id `root`; a folder
    cannot become its own descendant. `name`, `meta` and `dek` are the sealed fields (JSON
    `{iv, ct}`); `fk` holds an item's file key of the release before until its upgrade.
  - `upchunks(node_id, i, h)`: the chunks of a pending upload, with each chunk's SHA-256.
  - `refs(share_id, node_id)`: which shares reference which nodes.
  - `reverse(…, priv, mek, retired)`: reverse shares; `priv` is the link key sealed under the KEK
    of `mek` and at rest under the field layer; `retired`: a link of the release before whose
    key the upgrade could not open, ended with its key removed (§3.3).
  - `meta(k, v)`: rate-limit counters (`rl`), the upgrade's cursor while it runs, and — only
    while the Drive waits for its upgrade — the old `driveSalt`, `kcv` and pin (for the owner the
    sealed escrow keys); `wraps(kind, ref, data)`: the old wraps, likewise.
- R2 objects: `d/<userId>/<nodeId>/<i>` (never under `f/`). Only the Drive DO deletes them.
- The keyring lives in the Directory: meta `mek.root` (`{ key, fp, created }`), `mek.rootOld`
  while a root change runs (`{ key, fp, created, origin: 'changed' | 'restored' }`),
  `mek.rootCheck` (the root change's last check: `{ oldFp, root, failed, ids, at }`), `mek.ever`, `mek.kit` (what the latest key kit covers, with its version `v`), `mek.version` (`{ n, at }`, §3.1), `mek.job` and, per account, `ukit:<userId>` (the last personal-kit download: `{ at, v, meks }`);
  tables `meks(id, sealed, fp, from_ts, until_ts, created, note)`, `user_salts(user_id, salt,
  created)`, `mek_candidates(id, sid, key, exp, purpose)` and `drive_migration(user_id, state, v1_items,
  v1_links, updated)`.
- Pending uploads older than the role's `filePendingSec` are purged by the Drive DO's alarm.

## 5. Role options (Admin → Roles; `LIMITS` in `src/lib/settings.js`)

- `driveEnabled` (bool, default **false**); `driveMaxBytes` (bytes, capacity, default 1 GiB,
  null = no limit up to a hard 100 GiB); `driveMaxFileBytes` (bytes, nullable, default null).
- Drive shares obey the same share options as file shares: `files`, `maxViews`,
  `allowUnlimitedViews`, `maxExpireSec`, `maxFilesPerShare`, `openerDelete`, file-type rules,
  quotas (kinds `drive`, `files` and `all`), receipts, and the CAPTCHA (`shareCaptcha` / `shareCaptchaDefault`:
  SECURITY.md, *CAPTCHA on shares*). The owner has no limits. The public account has no Drive.
- Uploads: each file added by an upload (a folder upload: each of its files) is counted by the
  role's quotas of kind `drive-upload` when `POST /api/private/drive/files` reserves it
  (`429 quota_exceeded` at the quota), and given back when the Drive refuses it or the upload
  never completes (the browser deletes the unfinished file, or the purge removes it). Files
  taken in from reverse shares are counted under Receive (docs/REVERSE.md §6.2), not here.
- Reverse shares' options (`reverseEnabled`, `reverseMaxActive`, `reverseMaxBytes`,
  `reverseMaxExpireSec`, `reverseNoExpiry`, `reverseMaxViews`, `reverseAllowUnlimitedViews`,
  `reversePassword`, `reversePasswordDefault`, `reverseEdit`, `reverseCaptcha`,
  `reverseCaptchaDefault`): [`REVERSE.md`](./REVERSE.md) §5. The reverse-share
  CAPTCHA is shown in the role editor only while the role has the Drive and reverse shares.
- New keys join the Default role (a Directory migration materialises them) and appear in the
  role editors under a **Drive** section.

## 6. API (session only; not with API keys)

All bodies JSON unless stated; errors `{ error, message }` as elsewhere.

| Method and path | Purpose |
|---|---|
| `GET /api/private/drive` | `{ enabled, capacity, maxFile, used, current, received, receivedFailed, migration, kit }` (`kit`: the personal kit's state, as `GET …/kit`; `current`: the current sub-MEK's id; `migration`: null, or `{ pending, v1Items, v1Links, legacy }` while the Drive waits for its upgrade, §3.3; `capacity` null = no limit). A read with two side effects, both the server's own: the keyring is made on first need, and a Drive waiting for its upgrade with nothing of the release before in it is marked upgraded (the session cookie is `SameSite=Strict`, so no other site can cause either). A role without a Drive: `200 { enabled: false, capacity, maxFile, used }` (every other Drive route: `403 drive_disabled`; the public account: `403 drive_unavailable`); the client reads `enabled: false`, `drive_disabled`, any 404 and any 403 other than `impersonating` as "no Drive" |
| `POST /api/private/drive/keys` | `{}` → the session's KEKs (§3): `{ userId, current, changing, keys: [{ mekId, fp, from, until, kek, kekOld? }], missing, broken }` — every sub-MEK the Drive's items use, and the current one (`kekOld` while the owner changes the root MEK; `missing` / `broken`: sub-MEKs the Directory does not have or cannot open). `503 keys_missing` without a root MEK, `409 salt_missing` without the account's salt. Not to another site (`403`). The owner acting as the user gets the user's (`drive.keys_used`) |
| `GET /api/private/drive/kit` | the personal kit's state (§3.1): `{ version, versionAt, last: { at, version } \| null, stale }` (no key detail) |
| `POST /api/private/drive/kit` | the personal kit's content after the step-up (`current` \| `reauth`) and, with Turnstile on, a token for `account` (`X-Secbin-Turnstile`): `{ kit: { id, username, userSalt, current, keyVersion, keks: [{ mekId, fp, from, until, kek }] }, missing, broken, status }` (`status`: the state after this download, recorded; `drive.kit_exported`); `403 impersonating` for the owner acting as the user (as every kit route) |
| `POST /api/private/drive/kit/verify` | `{ keks: { mekId: check }, salt: check }` (check values, §3; with Turnstile on, a token for `account`) → `{ complete, salt, keks: [{ mekId, fp, from, until, inUse, current, result }], extra, version, now }` (`match` \| `mismatch` \| `absent`; `version`: the key version now; read-only, `drive.kit_verified`); at most 30 per session per 10 minutes (`429 rate_limited`) |
| `POST /api/private/drive/kit/restore` · `GET`, `PUT /api/private/drive/kit/items` | `403 owner_only` for everyone, the owner's own session and the owner acting as a user included: only the owner restores from a personal kit, with `…/admin/keys/users/<userId>/kit-restore` |
| `GET /api/private/drive/migrate` · `GET …/migrate/items?after=` · `PUT …/migrate` · `POST …/migrate/finish` · `POST …/migrate/retire` | the upgrade of the user's own Drive (§3.3): what is left and the user's own old wraps and salt (for the owner also the sealed escrow keys: with a stolen session they allow offline guessing of the old password, as the release before's `GET /drive` did, only while the Drive waits, and never while impersonating); a page of old items (link keys as the release before sealed them, the field layer taken off); `{ items: [{ id, ks, mek, name, meta?, dek? }], links: [{ id, mek, priv }] }` re-sealed (each checked; `409 mek_not_current`, `400 bad_seal`, `409 already_upgraded` once the Drive is upgraded) → `{ done, skipped, v1Items, v1Links }`; the verification a page per call → `{ verified, next }` or `{ done: true, left, cleanup }` (`409 not_upgraded`, `409 verify_failed`); `{ ids, current \| reauth }` → the links of the release before that the old key does not open, retired → `{ retired, failed, v1Items, v1Links }` (`drive.links_retired`). `403 impersonating` for the owner acting as the user |
| `GET /api/private/drive/nodes/<id>` | the node and its children: `{ node, children: [...], path: [...ancestors] }` (`root` for the top; `path` root first). Each node: `{ id, parent, kind: 'dir' \| 'file', name, meta, ks, mek, mfp, size, chunks, state, dek, ch, created, updated }` with the sealed fields as stored; an item of the release before has `v1: true` and `fk` instead of `ks`, `mek`, `mfp`, `dek` and `ch`. 404 for an unknown id |
| `POST /api/private/drive/folders` | `{ id, parent, name, meta?, ks, mek }` → `{ id }` (`id` chosen by the browser; 409 if taken; every seal checked, §3) |
| `POST /api/private/drive/files` | `{ id, parent, name, meta, dek, ks, mek, size }` → `{ id, uploadToken, chunks }` (`size` = plaintext bytes, `chunks = ceil(size / 8 MiB)`; capacity checked) |
| `PUT /api/private/drive/files/<id>/chunk/<i>` | `application/octet-stream`, header `X-Upload-Token`; exact size check |
| `POST /api/private/drive/files/<id>/finalize` | header `X-Upload-Token` → `{ ok, ch }` (the ciphertext hash); `409 busy` while a chunk of the file is still being written (finalize again), `409 incomplete` while one is missing |
| `GET /api/private/drive/files/<id>/chunk/<i>` | ciphertext chunk for the user |
| `PATCH /api/private/drive/nodes/<id>` | `{ parent?, name?, meta?, ks?, mek? }` move / rename → `{ ok }` (a new name or metadata comes with the item's own `ks` and `mek`: `409 stale_keys` when they changed, `400 bad_seal` when it does not open); 409 when `parent` is the node or inside it; the root cannot be moved, renamed or deleted |
| `DELETE /api/private/drive/nodes/<id>` | recursive; ends referencing shares; frees capacity; also used by the client to drop a failed upload's `pending` node |
| `POST /api/private/drive/shares` | `{ nodes: [file ids], views, expire, deletable?, label?, types?, depth?, paste, acc }` → `{ id, deletetoken }`: `nodes` lists **files** (the browser flattens folders), and `refs[i]` is `nodes[i]`; `types` / `depth` are the file-policy declaration, sent only when a policy applies (as for file shares); `paste` is the `encryptPaste` body (`acc` is also inside it) |
| `GET /api/private/drive/nodes/<id>/shares` | shares referencing the node — for a folder, every share that references a file under it: `{ shares: [{ id, label, kind: 'drive', created, expires, views_total, left, status, locked }] }` (My shares' row fields; `views_total` / `left` null = unlimited) |
| `GET /api/private/admin/keys` · `…/usage` | the owner: the keyring's status (fingerprints and dates, never a key: `{ ready, lost, root, subs: [{ id, fp, from, until, status, opens, note }], current, job, kit, kitFresh, version: { n, at }, users, now }`); the items per sub-MEK over every Drive |
| `POST /api/private/admin/keys/candidate` · `…/subs` · `PATCH`/`DELETE …/subs/<id>` · `POST …/subs/<id>/current` · `…/subs/<id>/show` · `…/root` · `…/root/show` | the owner, each with the step-up (§3.2): a generated candidate (`{ purpose: 'root' \| 'sub' }` → `{ id, key, fp, expires }`); add (`{ candidate \| key, from?, note?, rotate? }`); edit dates; delete (`409 in_use`, `409 current_key`); set current; Show; change the root (`{ candidate \| key }` → `{ fp, job }`; `409 migration_pending` with `drives` while a Drive waits with something of the release before; `409 candidate_purpose` for a sub-MEK's candidate) |
| `POST /api/private/admin/keys/jobs` · `POST …/jobs/step` · `DELETE …/jobs` | a re-seal job (`{ from, remove?, current \| reauth }`), or the root change's again (`{ kind: 'root', current \| reauth }`, while the previous root is kept); its next step → `{ job: { kind, from, drives, drive, phase, done, failed, failedIds, pass, verifying, finished, result } }` (`phase` `items`, `atrest`, then for a root change `verify` and `verifyrest`); cancel, with the step-up (not a root change that runs) |
| `POST /api/private/admin/keys/root/undo` · `…/root/drop-old` | a root change that could not finish (§3), each with the step-up: go back to the previous root (→ `{ fp, job }`; `409 unproven_root` for a previous root put back from a kit that opens nothing here); remove the previous root (`{ confirm: <its fingerprint> }` → `{ lost, ids }`, the count from the root change's check; `409 not_checked` before one) |
| `POST /api/auth/setup/candidate` | the set-up page's proposal (§3, "Set-up"), no session: `{ token }` (the setup token) and the intent header → `{ root: { id, key, fp }, sub: { id, key, fp }, expires }`; `403 bad_token` (counted against the network), `410 token_used` (a spent token, or an owner exists), `409 keys_exist`, `429 rate_limited` |
| `POST /api/private/admin/keys/kit` · `…/verify` · `…/restore` | the key kit's content after the step-up (`{ kit, material: { made, current, keyVersion, root, rootOld?, subs, salts } }`; the verify's answer also has `version`); a read-only check by check values (at most 30 per session per 10 minutes); a restore (`{ root?, rootOld?, subs?, salts?, useRoot?, dryRun }`, with the step-up, the preview too → `{ root, rootOld, subs: [{ id, result }], salts: { restored, same, kept, wrong, unknown } }`; `409 in_use` for `useRoot` on an instance with items or link keys) |
| `POST /api/private/admin/keys/export/verify` | a keys export checked, read-only, with the step-up (§3.2): `{ root?: check, subs?: { id: check }, users: [{ id, salt?: check, keks?: { mekId: check }, deks?: [{ id, dek }] }] }` (check values: drivekeys.js `keyCheckValue` / `saltCheckValue`) → `{ matches, root: { result, fp }, subs: { inFile, list: [{ id, fp, from, until, status, result }], unknown: [ids] }, users: [{ id, username, salt, keks: [{ mekId, result }], deks?: { total, opens, fails, missing, empty, unchecked, failed, missingIds } }] }`; results `match` · `mismatch` · `absent` (not in the file) · `missing` (here, not in the file) · `unknown` (in the file, not here) · `none` (no salt here) · `unchecked`; nothing written (a per-session rate limit, as the kit's Verify); no key returned |
| `POST /api/private/admin/keys/export` · `…/import` | the keys parts of Import / export (§3.2): `{ root?, subs?: 'all' \| [ids], salts?: [userIds], users?: [{ id, keks, deks: 'all' \| [nodeIds] \| false }] }` → `{ document }` (at most 10 000 DEKs per user); `{ document, take, useRoot?, dryRun }` (with the step-up, the preview too) → `{ keys, users: [{ keks: { match, mismatch, unknown }, deks: { restored, working, failed, missing } }] }` |
| `POST /api/private/admin/keys/users/<userId>/view` | the owner, with the step-up: `{ what: 'keks' }` → the user's salt and KEKs; `{ what: 'deks', after? }` → a page of their files (id, name, DEK) (`drive.keys_viewed`) |
| `POST /api/private/admin/keys/users/<userId>/kit-restore` | the owner, with the step-up for every call (§3.1): `{ kit: { id, salt, keks: [{ mekId, kek }] }, resume?: { mek, after } }` (the personal kit as the owner's browser opened it; `400 kit_mismatch` when `kit.id` is not `userId`) → `{ salt: 'restored' \| 'same' \| 'kept' \| 'wrong' \| 'absent', unreadable: [mekIds the server cannot open], done, failed, left: [lost mekIds the kit has no KEK for], next: null \| { mek, after } }` (`next`: call again with it as `resume`); `drive.kit_restored`, `drive.salt_restored` in the admin audit |
| `GET /api/private/admin/drive/migration` · `POST …/drive/migrate/<userId>/escrow` · `GET`/`PUT …/drive/migrate/<userId>[/items]` · `POST …/finish` · `POST …/retire` | the owner: every Drive waiting for its upgrade (disabled accounts too), with what is left (it also runs the escrow clean-up once nothing waits); the user's escrow wrap of the release before and their current KEK, with the step-up (`drive.escrow_used`); the upgrade routes above for that user (retire: the owner's step-up, `drive.links_retired` in the admin audit) |
| `GET`/`DELETE /api/private/admin/drive/archive` | the owner's archive of the release before (§3.3): `{ items, bytes, received, links }`; deleted with `{ confirm: <username>, current \| reauth }` → `{ items, bytes, links }` (`drive.archive_deleted`) |

While the owner impersonates a user, every Drive route works for the owner as for the user
(with the user's keys), except the personal kit and the upgrade (`403 impersonating`), and the
admin routes are closed as the whole admin surface is. State-changing routes carry the usual
intent header (`public/js/api.js`) and upload / finalize the `X-Upload-Token` header. Drive
shares are revoked with the existing `POST /api/private/shares/<id>/revoke` (the share ends, the
drive data stays) and appear in My shares and Admin → Shares with `kind = 'drive'`.

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
  `public/js/refsmanifest.js` builds and validates it. Each `fk` is the file's DEK, opened in the
  sender's browser (the manifest's key is in the link; the same DEK stays sealed in the Drive under
  the user's KEK, so the server can open the shared files as any Drive file). The share id starts with `f` and its paste
  has `fmt: 'files'`, like a file share, so the viewer opens it the same way.
- Recipients open it like a file share (`POST /api/file/<id>/open`); the response adds
  `refs: [{ chunks, size }]`. Chunks: `GET /api/file/<id>/chunk/<ref>/<i>` with the download
  grant. `public/js/downloads.js` and the viewer read v3 manifests (per-file keys and chunk
  sequences), including preview, single-file download and zip.
- Deleting a drive node revokes every share whose `refs` include it (or a descendant).
- **The CAPTCHA:** a Drive share can require its recipients to pass a CAPTCHA first, as any
  share (`captcha` on `POST /api/private/drive/shares`, as the role allows; the FileShare
  record's `hc` and the index row's `captcha`): without a grant its head, open, "delete now"
  and every `/chunk/<ref>/<i>` answer `403 captcha_required` (SECURITY.md, *CAPTCHA on shares*).

## 8. UI

- **Dashboard → Drive** (`/dashboard/drive/`), shown when the role allows it:
  - left pane: the folder tree, **collapsed by default**; a **+** (−) button expands (collapses)
    a folder's sub-folders; selecting a folder shows its content in the right pane;
  - right pane: the folder's files and folders (name, size, modified), with upload (files and
    folders, drag and drop), new folder, rename, move, delete, download, and **Share…** (the
    composer's share options), and each item's shares (with revoke);
  - capacity bar (used of total);
  - a notice when the user's personal kit is out of date (§3.1, `#drive-kit-notice`, with a link
    to Account; not while the owner acts as the user);
  - no unlock prompt: the Drive opens with the keys the server hands the session (§3); when they
    cannot be had, a notice says what happened and who fixes it (`#drive-unavailable`).
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
  `impersonating = !!impersonatedBy`) to `openDrive({ user })`, so the client needs no session
  lookup. While the owner impersonates a user, `openDrive` opens the user's Drive with the user's
  keys (§3) and the page shows a note that it is the user's Drive and that the server gave the
  owner the user's keys, recorded in the admin audit (`#drive-imp-note`).
- **Opening:** `openDrive()` resolves to a `DriveClient` or throws `DriveDisabled` (the page says
  "Drive is not enabled for your account") or `DriveUnavailable` with `reason` `keys_missing`
  (the server's keyring is missing: the administrator restores it from the key kit) or
  `salt_missing` (the account's salt is missing: the administrator restores it from the user's
  personal kit or the key kit; the page names no restore of the user's own).
  There is no unlock, set-up or recovery screen. `client.migration` holds what the upgrade of a
  Drive made before the key model v2 still has to do (§3.3): the page shows its progress
  (`#drive-upgrade`) and runs it; items still sealed the old way are `upgrading` and shown as
  "(waiting for the upgrade)".
- **The personal kit** is on the Account page (`public/dashboard/js/userkit.js`, the shared
  pieces in `kit-ui.js`: Download and Verify), the key kit, the keyring and "Restore a user's
  personal kit" in Admin → Security → Keys (`admin-keys.js`), the keys parts of Import / export
  in `admin-keysport.js`. The client functions: `buildPersonalKit`, `verifyPersonalKit`
  (`driveclient.js`), `buildKeyKit`, `verifyKeyKit`, `restoreKeyKit`, `restoreUserKit`,
  `exportKeys`, `openKeysExport`, `importKeys` (`keysclient.js`), `upgradeOwnDrive`, `upgradeUserDrive` (`driveupgrade.js`).
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
- `share(ids, { views, expire, password, deletable, label, limits, view, captcha })` → `{ url, id,
  deletetoken, captcha }` (`captcha`: the Share dialog's "Require CAPTCHA to open", shown as the
  role says — a choice pre-set from its default, ticked and disabled, or hidden): `ids` may be files and folders (the client flattens them to files for the
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

- **Not end-to-end.** The server holds the keys every KEK is derived from (§2). Whoever controls
  the Worker, or reads the Directory's storage, can open every Drive file; the owner can too
  (the key kit, a user's keys in Security → Keys, acting as the user). This is a deliberate
  choice by the maintainer, in place of the escrow design of the release before. What protects
  Drive data is the Directory's storage and the Worker's code, the owner's account (step-up for
  every key action) and the kits kept offline.
- **What the Drive's own storage holds** (R2, the Drive Durable Object): ciphertext, seals and
  salts, and the ciphertext hash — nothing that opens them without the Directory.
- **The item id is not in the AAD.** The server (which can open everything anyway) could move a
  seal to another item together with its salt, and it would open there; a seal cannot be moved
  to another user, sub-MEK, field or salt. The browser checks a file's sealed metadata (its
  size must be the server's and match the chunk count) and the chunk AAD `(i, n)`, so a moved DEK
  opens only content of the same size and chunk count, and a swapped chunk fails. The ciphertext
  hash (`ch`, checked on download) is kept by the server next to the item, bound into no seal:
  it catches stored chunks that changed after the upload, not a server that moves or rolls back
  a whole item (with its hash).
- **Keys handed out.** A session gets its own KEKs (§3); the owner acting as a user gets the
  user's. The root MEK and the sub-MEKs leave the Directory only for the owner after the step-up
  (Show, the key kit, an export), always in the admin audit by fingerprint; generated or entered
  keys are never logged. Re-sealing opens DEKs and names inside the Worker only, never storing
  or logging them.
- **What is recorded, and where.** Drive actions are logged like every other action of the
  user's, and impersonation is invisible to the user (as for the rest of the account):
  - the user's own activity (`GET /api/private/me/activity`) lists their Drive actions —
    `drive.folder_created`, `drive.file_uploaded`, `drive.file_read` (a file opened: its first
    chunk read), `drive.item_changed` (renamed, moved), `drive.item_deleted`, the personal kit
    (`drive.kit_exported`, `drive.kit_verified`), `drive.migrated` (a system event), and for received files of a reverse share
    `drive.received_taken_in`, `drive.received_failed`, `drive.received_retried` (one row per
    link, per actor, per hour, adding up the files; [`REVERSE.md`](./REVERSE.md) §7) — and their
    Drive shares (`share.created`, `share.updated`, `share.revoked`). Node ids only, never names.
    A user's own file reads are throttled in the log (one row per file per minute, at most 30 a
    minute), so they cannot push other entries out;
  - what the owner does in the Drive while impersonating the user is recorded exactly the same
    way, as the user's own (`imp`, no `adm`): the user's activity shows it as theirs with no
    actor and no trace of the impersonation, and the owner-only admin audit shows the owner as
    the real actor, with `impersonate.start` and `impersonate.end` (never throttled);
  - the owner's use of a user's keys is the owner's own action, in the admin audit only:
    `drive.keys_used` (the user's KEKs handed to the owner acting as the user; `imp` and `adm`),
    `drive.keys_viewed` (Security → Keys, or an export), `drive.keys_imported`,
    `drive.kit_restored` and `drive.salt_restored` (a restore from the user's personal kit),
    `drive.escrow_used` (the upgrade through the escrow of the release before),
    `drive.migrated`, `drive.links_retired` and `drive.archive_deleted`; the keyring's actions
    (`keys.*`, §3.2) and `drive.migration_done`, with no subject. Deleting an account's Drive
    with the account is an admin action too. A user retiring their own links of the release
    before (§3.3) is in their activity (`drive.links_retired`).
- **The KEKs in the tab.** In the page's memory only (§3): never written to or read from
  browser storage, so a key planted there is never used. The old Drive key of the release before
  (only while a Drive waits for its upgrade) is kept in `sessionStorage` and used only once its
  key check value matches the server's (§3.3), and it leaves the tab once nothing waits. When the
  page stops acting for its session (the session ended, or the browser is now signed in as
  someone else: another tab signed in, or started or ended impersonation — found on the next
  change, or when the tab is shown again), an open Drive closes: its KEKs are overwritten and
  dropped, and what it showed leaves the page. The CSP and Trusted Types keep other script out,
  as for the rest of the app; what remains is in SECURITY.md.
- Capacity, sizes and chunk counts are enforced server-side; names and types are not (they are
  encrypted), so file-type rules for drive shares are enforced by the client, as for file shares.

## 10. Server notes (as built)

Details of the server side (`src/drive-do.js`, `src/routes/drive.js`) that the sections above
leave open:

- **Access.** Every `/api/private/drive*` route needs a session (an API key gets
  `403 api_key_not_allowed`); the public account gets `403 drive_unavailable`. With the role's
  Drive off, `GET /api/private/drive` answers `200 { enabled: false, … }` and every
  other Drive route `403 drive_disabled`. `GET /api/private/drive` also returns `maxFile` (the
  largest file allowed); `capacity` and `maxFile` are `null` when the role sets no limit (the
  hard 100 GiB then applies). `GET /api/private/me` has `caps.driveEnabled` (false for the public
  account, true for the owner). While impersonating, the personal kit and the upgrade answer
  `403 impersonating`; the admin routes are closed as usual.
- **Nodes.** `id` may be omitted (the server then picks one, which cannot be bound into the
  AAD). `PATCH` also accepts `meta`. `path` lists the ancestors as full nodes, root first.
  Children include pending files (`state: 'pending'`, `done` = chunks received). `DELETE`
  answers `{ ok, deleted, sharesEnded }`. Hard ceilings per Drive: 100 000 items, 10 000 per
  folder, 64 folder levels, 1 000 shares per item.
- **Capacity.** `used` is every file's `size`, pending uploads included (reserved at
  `POST …/files`), plus the characters of every item's sealed fields (name, meta, DEK) and its
  salt, so they
  cannot store data outside the capacity; a folder, a file or a rename that would not fit is
  `413 drive_full`. Sealed names are at most 512 characters and metadata at most 1024.
- **Files.** Chunks may arrive in any order; sending one again replaces it (internal table
  `upchunks(node_id, i)`; `done` is their count). A pending upload with no chunk received for the
  role's `filePendingSec` is purged by the alarm, with its chunks. A file is readable and
  shareable only once finalized. Finalize answers `409 busy` while a chunk write for the file is
  in flight (the client finalizes again); a chunk write that completes after its upload ended
  (deleted, purged, the Drive destroyed) removes its object, never a chunk of a finished file.
- **Keys.** Every seal a browser sends is opened once in the Worker with the current KEK before
  it is stored (`src/lib/mek.js` `checkNewItem`); a sealed DEK is at most 128 characters, a link
  key 256. `POST …/drive/keys` makes the account's salt when the Drive has no item and no link
  key yet and the account has none (a salt lost from a Drive with either is only restored,
  §3.1). The Worker re-seals only with compare-and-set writes in the Drive object
  (`applySealed`, `applyLegacy`, `restoreItem`, each on the stored mek, salt and sealed
  fields), so a change made meanwhile is never overwritten.
- **The wraps of the release before** (only while a Drive waits for its upgrade, §3.3): the
  server drops the wraps of passkeys and codes the account no longer has (a passkey removed,
  codes regenerated, a code spent at sign-in, the owner's "remove all passkeys"); a password
  change marks the `pw` wrap stale; an admin reset drops it when a passkey or recovery wrap
  remains; the owner's wraps an AUTHN owner recovery kept stay while any Drive waits (a removed
  passkey or replaced codes of the owner still lose theirs at once). Nothing writes a new
  wrap.
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
  reverse share of a file an anonymous uploader sent and the user's browser has not yet taken
  in; such files count in the capacity (their content and, until taken in, their sealed path,
  metadata and wrap, stored at rest under the field layer) but are left out of `children`,
  cannot be read, moved, renamed or shared, and are listed by `GET /api/private/drive/received`
  until taken in (`POST /api/private/drive/received/<id>` with the item sealed under the KEK like
  a new file). One whose field layer does not open is listed without its fields (the browser
  records it as failed) and never holds up the rest. Deleting a folder ends the reverse shares
  that target it or anything below it.
- **Accounts.** Deleting an account first ends every share of its Drive, then deletes the Drive
  (every R2 object, its state), each step retried; only then is the account deleted. If the Drive
  cannot be removed the account stays (`503`), and deleting it again retries. The
  Directory mirrors each Drive's usage (`drive_usage`); Admin → Users gets
  `drive: { enabled, used, capacity }` per user (`capacity` null = no limit; `drive` null for the
  public account).

## 11. Browser ↔ server integration checklist

What the browser (`public/js/driveclient.js`, the Drive page, the kits) relies on, and how the
server (§10) meets it. The browser side is also tested against an in-memory stand-in of this
API (`test-dom/drive-fake-server.js`), which must stay in step with the server.

1. **Nav:** `/api/private/me` → `caps.driveEnabled` (owner true, public account false).
2. **Account:** login responses keep `user: { id, role }`; `/api/auth/session` keeps `user` and
   `impersonatedBy` (the keys' slots are bound to the account they were given to).
3. **State:** `GET /api/private/drive` as §6; `{ enabled: false }` and the 403s read as "no
   Drive"; `capacity: null` (no limit) shows "no limit" without a meter.
4. **Keys:** `POST /api/private/drive/keys` (`{}`), at every page load, kept in memory only → `userId` is the session's account (the owner acting
   as a user: the user's); `current` is one of `keys`; `503 keys_missing` / `409 salt_missing`
   read as "the Drive cannot be opened now"; `409 mek_not_current` → fetch the keys again and
   seal once more; `409 stale_keys` on a rename → read the item again.
5. **Ids:** the browser always sends its 22-character node id; `409` when taken.
6. **Files:** `chunks = ceil(size / 8 MiB)` exactly (the client refuses any other answer), chunk
   `i` exactly `min(8 MiB, size − i · 8 MiB) + 16` bytes under `X-Upload-Token`, finalize, and
   raw chunk reads; capacity counts pending uploads; a failed upload's pending node is deleted by
   the client (`DELETE`), else purged by the alarm.
7. **Listing:** `path` root first (full nodes); children include `meta`, `dek`, `ks` and `mek` for
   files, and pending uploads (`state: 'pending'`, hidden by the client); an item of the release
   before has `v1: true`; folders have no `size`; times in seconds; the root's `name` is null
   (the client names it).
8. **Moves:** `PATCH` refuses cycles and the root; `DELETE` is recursive and ends the shares of
   everything below.
9. **Shares:** `POST /api/private/drive/shares` takes file ids only (`400 not_a_file` for a
   folder; the client flattens), finalized files only; `types` / `depth` when a policy applies;
   `→ { id, deletetoken }` with an `f…` id. `GET …/nodes/<id>/shares` returns My-shares rows,
   for a folder those of the files below it; revoke is `POST /api/private/shares/<id>/revoke`;
   My shares and Admin → Shares show kind `drive`.
10. **Recipients:** `POST /api/file/<id>/open` adds `refs: [{ chunks, size }]` in `nodes` order;
    `GET /api/file/<id>/chunk/<ref>/<i>` under `X-Download-Grant`.
11. **Kits:** check values only on verify; the kit file never leaves the browser; the step-up on
    download and restore; a restore is the owner's only (Admin → Security → Keys), for the key kit
    and for a user's personal kit, and the Account routes of one answer `403 owner_only`.
12. **Upgrade:** `GET …/migrate` / `…/items` / `PUT …/migrate` / `POST …/migrate/finish` (own, or
    the owner's `…/admin/drive/migrate/<userId>…`); a recovery-code sign-in's response carries
    `driveSpent` while a Drive waits (the spent code's wrap, for the sign-in to open the old key).
