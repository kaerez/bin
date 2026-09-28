# test-e2e — manual end-to-end checks

Browser tests that drive a real `wrangler dev` with Playwright and Chromium. They document and
repeat the manual test of a feature; they are **not** part of `npm test` or CI (vitest does not
pick them up, and CI does not install a browser).

## `drive-int.mjs` — the Drive, end to end

What it covers ([docs/DRIVE.md](../docs/DRIVE.md)):

- the set-up page making the Drive keys; the Drive opening right after any sign-in (password,
  passkey, recovery code) with no prompt, and no Drive key in the tab's storage;
- a new tab with keys planted in `sessionStorage` / `localStorage`: the Drive opens with the
  server's keys, the planted slots are removed, and what it seals opens in a clean tab;
- the folder tree and right pane (mouse and keyboard), upload of files and folders (a clashing
  name gets " (2)"), new folder, rename, move, delete, download (file and folder ZIP);
- Share… with a password, the recipient's view, the item's shares and revoke;
- the capacity text, the phone layout, a role without a Drive;
- no names, contents or passwords in any Drive request, and the CSRF token on every change;
- no page errors or CSP / Trusted Types violations, and axe (WCAG 2.2 A/AA) on every state.

It creates the owner itself, so it needs a server with **no owner yet**: fresh local state.

```sh
# 1. once: the test's own dependencies (not in package.json) and a Chromium
npm install --no-save playwright-core axe-core
npx playwright-core install chromium        # or point CHROMIUM at an installed one

# 2. a fresh server (.dev.vars holds AUTHN, the setup token; see README.md)
rm -rf .wrangler/e2e-state
npx wrangler dev --port 8787 --persist-to .wrangler/e2e-state

# 3. in another shell, from the repository root (localhost, not 127.0.0.1: passkeys need an RP ID)
WT=$PWD BASE=http://localhost:8787 node test-e2e/drive-int.mjs
# CHROMIUM=/path/to/chrome   use that browser instead of Playwright's
# OUT=/some/dir              keep downloads, screenshots and axe.json there (default: a temp dir)
```

It prints one `PASS` / `FAIL` line per check and `N/M passed`, and exits non-zero on any
failure.

## `drive-impersonate.mjs` — the owner in a user's Drive ("Log in as")

What it covers ([docs/DRIVE.md](../docs/DRIVE.md) §3, §9): the owner, logged in as a user, gets
the user's Drive keys from the server (`drive.keys_used` in the admin audit), in the page's memory
only; reads and downloads the user's file, uploads one and shares it (a recipient opens the
link); the personal kit and the upgrade are refused while acting as the user; a user who has never
signed in has a Drive the owner can use at once; Hebrew and spoofing names in the Drive page; and
the user's own activity listing the Drive actions done as them, as theirs and with no trace of the
impersonation, while the admin audit names the owner. Same set-up as `drive-int.mjs` (a fresh
server with no owner yet):

```sh
WT=$PWD BASE=http://127.0.0.1:8787 node test-e2e/drive-impersonate.mjs
```

## `keys.mjs` — the Drive keys (set-up, Security → Keys, kits, Import / export)

What it covers ([docs/DRIVE.md](../docs/DRIVE.md) §3, §3.1, §3.2): the set-up page with keys
entered by hand (a malformed one refused); Admin → Security → Keys — Show with the step-up (the
values entered at set-up), a generated sub-MEK used only on "Use this key", rotation, a scheduled
sub-MEK entered by hand, a re-seal with progress, deleting a sub-MEK (two steps), a root change;
the key kit (download with the step-up, verify today and on a later date, a wrong passphrase, a
restore preview that replaces nothing); a user's keys (masked, Show); the personal kit on Account
(download and verify; no Restore section for alice or the owner, and the Account restore routes
refused with `403 owner_only`); the restore of a user's personal kit in Security → Keys (another
account's kit refused; on a working server it changes nothing); Import / export → Drive keys (parts, the user search, the masked view,
the sealed file; an import previewed and applied that replaces nothing); every file still opening
after each change; the admin audit holding the key actions and no key value; axe on every state.
It needs a fresh server (no owner yet):

```sh
WT=$PWD BASE=http://localhost:8787 OUT=/tmp/keys node test-e2e/keys.mjs
```

## `kit-fresh.mjs` — the kits' key version and the "download a new kit" notice

What it covers ([docs/DRIVE.md](../docs/DRIVE.md) §3, §3.1), with the real Cloudflare Turnstile
widget and Cloudflare's testing keys: the set-up page proposing the Drive keys (masked until
Show; "Generate again", then "Use these"; the keyring is exactly that pair, version 1); alice's
personal kit on Account (the card's CAPTCHA and a token on each request, "Version 1, <date>",
never downloaded, then a download with its version); the owner rotating a sub-MEK (the key kit
card's "Version 2"); alice's Account and Drive pages then showing the notice, with no key
detail; the owner acting as alice seeing none and refused a download; alice downloading again
and the notices going; her first kit verifying with an older key version (a warning), the new
one with the current one; axe (WCAG 2.2 A/AA) on each new state; no page errors or CSP /
Trusted Types violations. It needs a fresh server with Turnstile's testing keys:

```sh
rm -rf .wrangler/kf-state
npx wrangler dev --port 9220 --persist-to .wrangler/kf-state \
  --var TURNSTILE_SITEKEY:1x00000000000000000000AA --var TURNSTILE_SECRET:1x0000000000000000000000000000000AA
WT=$PWD BASE=http://localhost:9220 node test-e2e/kit-fresh.mjs
# behind an HTTPS-intercepting proxy: PROXY_SPKI=<its CA's SPKI hash> (HTTPS_PROXY is used when set)
```

Every suite that creates the owner on the set-up page generates the Drive keys there and chooses
"Use these" (the release before, in `drive-upgrade.mjs` phase 1, has no such step).

## `port-ids.mjs` — the user id lists of the account export and import

What it covers (Admin → Import / export): on export, each row's user id, the search by name and
by id, Select all / Deselect all of the rows shown, an uploaded id list choosing exactly the users
it names, "Download the chosen ids" (a plain text list, user ids only) and the export sent for
those users (the file holds their ids); on import, the ids in the file shown and downloaded, an
uploaded list taking over the accounts it names (a deleted one created with a new id, an existing
one updated: its role only, its password unchanged) and skipping the others, the preview sending
only those; axe on every new state; no page errors or CSP / Trusted Types violations. It needs a
fresh server (no owner yet):

```sh
npx wrangler dev --port 9230 --inspector-port 9231 --persist-to .wrangler/ids-state
WT=$PWD BASE=http://localhost:9230 node test-e2e/port-ids.mjs
```

## `port-passkey.mjs` — Import / export with a passkey, and a Drive keys export verified

What it covers (SECURITY.md, *Export / import*; [docs/DRIVE.md](../docs/DRIVE.md) §3.2), with
Chromium's virtual WebAuthn authenticator: the owner adds a passkey; the account and system
export and the import (its preview and its apply) each confirm with it when the password field is
left empty (a reauth challenge, then `{ reauth }`, no password proof), and a wrong password is
still refused; Import / export → Drive keys: the labels (the id list holds no keys; what "Build
the export" and "Encrypt and download" do), an export confirmed with the passkey, then Verify of
the saved file ("Everything in this file matches this server") and of a tampered copy (another
root MEK, a wrong KEK, a broken DEK, a sub-MEK unknown here: what does not match), a wrong
passphrase refused in the page; only check values (and the DEKs) sent, the keyring unchanged, the
file still opening, the admin audit with fingerprints and counts only; Admin → Audit → Clear logs
confirmed with the passkey too; axe (WCAG 2.2 A/AA) on
every new state; no page errors or CSP / Trusted Types violations. It needs a fresh server (no
owner yet), on `localhost` (passkeys need an RP ID):

```sh
WT=$PWD BASE=http://localhost:8787 node test-e2e/port-passkey.mjs
```

## `drive-upgrade.mjs` — upgrading Drives made by the release before

What it covers ([docs/DRIVE.md](../docs/DRIVE.md) §3.3), in two phases on one server state:
phase 1, against the release before — the owner, alice and carol with Drives made the old way
(files, a folder, alice's reverse link with one received file taken in and one waiting); phase 2,
against this release on the same state — the owner's Drive upgraded by the owner's own Drive page,
carol's from Admin → Security → Keys (through the escrow of the release before), alice's at her
sign-in; every file reading back with the same bytes, the waiting file taken in, the old link
still receiving; then no Drive left waiting, and the old wraps and escrow records gone.

```sh
# in a checkout of the release before (its own .dev.vars and node_modules), a fresh state
rm -rf /tmp/upgrade-state
npx wrangler dev --port 8787 --persist-to /tmp/upgrade-state
PHASE=1 WT=<that checkout> BASE=http://localhost:8787 OUT=/tmp/upgrade node test-e2e/drive-upgrade.mjs
# stop it, then start this release on the same state
npx wrangler dev --port 8787 --persist-to /tmp/upgrade-state
PHASE=2 WT=$PWD BASE=http://localhost:8787 OUT=/tmp/upgrade node test-e2e/drive-upgrade.mjs
```

## `csrf.mjs` — CSRF tokens

What it covers is in the file's header (a page acting only for the session it was loaded for,
across tabs, back / forward, reloads and impersonation, and the Admin switch). It needs a fresh
server (no owner yet):

```sh
BASE=http://localhost:8787 WT=$PWD node test-e2e/csrf.mjs
```

## `captcha.mjs` — CAPTCHA on shares and reverse shares

What it covers (SECURITY.md, *CAPTCHA on shares*), with the real Cloudflare Turnstile widget and
Cloudflare's testing keys (they always pass): Admin → Roles' CAPTCHA radios (and "Default for new
shares" under "Allow"); the composer's, the Drive Share dialog's and the Receive dialog's
boxes; a protected note, file share, Drive share and reverse link, each through its check page
(the Turnstile CSP; the link's key not in its address, page or `sessionStorage`; Continue disabled
until the CAPTCHA passes) and back on its strict page (the key back, no Turnstile script), a
reload with the kept grant, another session asked again; an unprotected note and link with no
check; an API recipient refused (`403 captcha_required`); the CAPTCHA badges in My shares and
Admin → Shares; a user whose role requires it (the box ticked and disabled); axe (WCAG 2.2 A/AA)
on the new states; no page errors or CSP / Trusted Types violations. It needs a fresh server
with Turnstile's testing keys, on `http://localhost` (the widget needs a hostname):

```sh
rm -rf .wrangler/captcha-state
npx wrangler dev --port 8787 --persist-to .wrangler/captcha-state \
  --var TURNSTILE_SITEKEY:1x00000000000000000000AA --var TURNSTILE_SECRET:1x0000000000000000000000000000000AA
WT=$PWD BASE=http://localhost:8787 node test-e2e/captcha.mjs
# behind an HTTPS-intercepting proxy: PROXY_SPKI=<its CA's SPKI hash> (HTTPS_PROXY is used when set)
```

## `reverse-parity.mjs` — Receive links with the options of regular shares

What it covers ([docs/REVERSE.md](../docs/REVERSE.md) §5, §6.1, §8): the Default role's "no
expiry" option off, with its default hint, in Admin → Roles; a user whose role allows it makes a
Receive link with no expiry, an uploader password and 2 views in the Drive's Receive… dialog; an
anonymous uploader sends a file twice and is refused the third time (the views are used up); My
shares shows "No expiry" and "0 left of 2 views", filters by "no expiry", and Edit changes the
password and the views (4); the old password is then refused and the new one sends; Edit gives
the link an expiry, which the uploader page shows, and a shorter one is refused; the files are in
the Drive; nothing on the wire names a file or carries a password; the audit names what changed,
never a value; axe (WCAG 2.2 A/AA and the AAA contrast rule) on the new dialog and the Edit row;
no page errors or CSP / Trusted Types violations. It needs a fresh server (no owner yet):

```sh
rm -rf .wrangler/rp-state
npx wrangler dev --port 9170 --persist-to .wrangler/rp-state
WT=$PWD BASE=http://localhost:9170 node test-e2e/reverse-parity.mjs
```

## `quotas.mjs` — role quota kinds

What it covers (README "Quotas"): Admin → Roles → a custom role → Quotas — the kind select's
groups (Outgoing shares, Drive, Receive) and labels, "API only" disabled for a Drive or Receive
kind, a quota of each group saved through the editor; the Public role offering only the outgoing
kinds it can use; then, as the user, each quota reached through the UI — a second note refused in
the composer, a second Drive upload refused, a second Receive link refused in its dialog, and the
anonymous uploader's page refusing a second upload session with "This link can’t accept more
uploads right now. Try again later." (nothing of the quota shown); the Account page's quota list;
axe (WCAG 2.2 A/AA) on the editors and every refusal; no page errors or CSP / Trusted Types
violations. It needs a fresh server (no owner yet):

```sh
WT=$PWD BASE=http://localhost:8787 node test-e2e/quotas.mjs
```

## `receive-types.mjs` — Receive links that accept notes, links and credentials

What it covers ([docs/REVERSE.md](../docs/REVERSE.md) §3.1, §8): Admin → Roles' four new options
on the Default role (files and notes on, links and credentials off); a role whose links may accept
every kind, given to alice; the Receive… dialog's "What senders can send" (a box per allowed
kind, files ticked); a link accepting a note, a link and a credential, and one for files only; an
anonymous uploader sending a Markdown note with a title, a link and a credential through the
uploader page's tabs (the credential form's warning that the server can decrypt it); a note to the
files-only link refused (`403 kind_not_accepted`), and — once the role drops credentials — no
Credential tab and a direct `begin` refused; alice's Drive taking them in ("1 note, 1 link and 1
credential"), listing them with their kinds, and opening each in its viewer (the note rendered,
the link with Open, the credential masked, then revealed); nothing on the wire but each start's
declared kind; axe (WCAG 2.2 A/AA and the AAA rules) on the dialog, each uploader tab, the folder
and each viewer; no page errors or CSP / Trusted Types violations. It needs a fresh server (no
owner yet):

```sh
rm -rf .wrangler/rt-state
npx wrangler dev --port 9210 --persist-to .wrangler/rt-state
WT=$PWD BASE=http://localhost:9210 node test-e2e/receive-types.mjs
```

## `drive-rules.mjs` — the Drive's bytes quota, the role's file rules in the Drive, the footer

What it covers (README "Quotas", [docs/DRIVE.md](../docs/DRIVE.md) §5): Admin → Roles → a custom
role → Quotas — "Bytes uploaded" in the Drive group, its max in MiB or GiB (the unit shown for it
only), no "API only", saved in bytes; the role's file rules (a blocked type, a folder-depth limit)
set in its limits; then, as the user, a Drive upload past the bytes quota refused with the size
("Quota reached: 1.0 KB uploaded to the Drive per 1d."), an upload of the blocked type refused
before anything is sent, a folder nested past the limit refused in its dialog, the server asking a
direct upload for its type declaration, and the Account page listing the quota as sizes; the
viewer saying a note is end-to-end and a Drive share is not; the same footer ("Encrypted in your
browser") on every page; axe (WCAG 2.2 A/AA) on every state; no page errors or CSP / Trusted
Types violations. It needs a fresh server (no owner yet):

```sh
rm -rf .wrangler/rules-state
npx wrangler dev --port 9241 --persist-to .wrangler/rules-state
WT=$PWD BASE=http://localhost:9241 node test-e2e/drive-rules.mjs
```
