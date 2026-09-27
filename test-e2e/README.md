# test-e2e — manual end-to-end checks

Browser tests that drive a real `wrangler dev` with Playwright and Chromium. They document and
repeat the manual test of a feature; they are **not** part of `npm test` or CI (vitest does not
pick them up, and CI does not install a browser).

## `drive-int.mjs` — the Drive, end to end

What it covers ([docs/DRIVE.md](../docs/DRIVE.md)):

- the sign-in setting up and unlocking the Drive (password, a passkey with PRF, a recovery
  code);
- Account keeping the wraps current;
- the Drive page's unlock prompt;
- the folder tree and right pane (mouse and keyboard), upload of files and folders (a clashing
  name gets " (2)"), new folder, rename, move, delete, download (file and folder ZIP);
- Share… with a password, the recipient's view, the item's shares and revoke;
- the capacity text, the phone layout, a role without a Drive;
- no names, contents or secrets in any Drive request;
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
failure. It takes a few minutes: Argon2id runs for every password unlock.

## `drive-impersonate.mjs` — the owner in a user's Drive ("Log in as")

What it covers ([docs/DRIVE.md](../docs/DRIVE.md) §3, §9): the owner, logged in as a user, opens
the user's Drive through the owner escrow (the owner's own Drive unlocked in the tab), reads and
downloads the user's file, uploads one and shares it (a recipient opens the link); the user's key
sits in its own tab slot and goes when the impersonation ends; removing the user's password wrap
is refused; a user with no Drive yet gets one that their next sign-in finishes; the notice when
the owner's Drive is locked; Hebrew and spoofing names in the Drive page; and nothing new in the
user's own activity while the admin audit names the owner. Same set-up as `drive-int.mjs` (a
fresh server with no owner yet):

```sh
WT=$PWD BASE=http://127.0.0.1:8787 node test-e2e/drive-impersonate.mjs
```
