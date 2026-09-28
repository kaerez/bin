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
shares" under "Allow"); the composer's, the Drive Share dialog's and the Receive files dialog's
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
