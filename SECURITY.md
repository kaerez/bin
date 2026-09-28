# secbin — Security Policy & Threat Model

secbin is a **zero-knowledge sharing service** for notes and files: content — including file
names, folder structure and MIME types — is encrypted and decrypted only on the client, and the
decryption secret never leaves the client in normal operation. **The one exception is the
Drive**: its files are encrypted in the browser, but the server holds the keys that open them
("Drive keys", §6). This document is the
authoritative statement of what secbin does and does **not** protect. Read it alongside
[`SPEC.md`](./SPEC.md).

secbin is maintained by KSEC - Erez Kalman and is based on
[binthere](https://github.com/nxfu/binthere) by nxfu. Protocol v2 replaced binthere's v1
cryptography (Argon2id, access proofs, file shares) and added built-in accounts.

Treat secbin as a **security-sensitive cryptographic application**, not a normal web app.

---

## 1. Security goals

1. **Confidentiality of content from the server/storage layer.** The Worker, KV, R2, the
   Durable Objects and Cloudflare store only ciphertext and non-secret settings. They cannot
   read note text, file contents, file or folder names, MIME types or per-file sizes: all of
   that is encrypted client-side; the key (`F`, the URL fragment) is never transmitted. (Drive
   files are the exception: the server can open them, "Drive keys".)
2. **Integrity.** AES-256-GCM authenticates ciphertext; the canonical AAD binds every
   security-relevant field (`SPEC.md` §4); file chunks bind their index and the chunk count, so
   reordering and truncation fail closed.
3. **Password gating independent of the URL secret.** Neither the fragment alone nor the
   password alone opens a password-protected share (`SPEC.md` §2). Passwords are stretched with
   memory-hard **Argon2id** (64 MiB).
4. **No view is ever spent on a wrong link or a wrong password.** The server verifies two
   access proofs (`SPEC.md` §2) before releasing ciphertext or decrementing a view. The public
   head carries no wrapped key, so a password cannot be attacked offline by someone who only
   holds the link; online guesses are rate-limited per IP (§6).
5. **Exact view limits** enforced atomically by Durable Objects.
6. **No key exfiltration through the app's own code** (§4): strict CSP, first-party assets only,
   DOM construction only, and a viewer that never executes content.
7. **Accounts that cannot be taken over from the network**: server-verified sessions,
   brute-force protection, single-use setup tokens (§6).

## 2. Explicit non-goals

- **Anonymity / metadata privacy** — see §3.
- **Protection against a compromised or malicious deployment** — see §4.
- **Protection of a secret you disclose.** Anyone with the full link (and the password, if set)
  can open the share up to its view limit. Links can persist in browser history and chat
  previews; this is inherent to fragment-key delivery.
- **Copy protection.** A view limit bounds how often ciphertext is released, not what a reader
  keeps.
- **Guaranteed deletion from all layers/backups.** KV deletes can take ~60 s to propagate.
- **Hiding account metadata from the operator.** Which account created which share, share
  labels, and the audit log are server-side and visible to the owner.
- **Protection against a malicious owner.** The owner can impersonate users and change limits;
  the owner still cannot decrypt shares, but can decrypt every Drive file.
- **Confidentiality of Drive files from the server.** The server, and anyone with a copy of the
  Directory's storage, can decrypt every Drive file ("Drive keys", §6).
- **DoS protection** beyond best-effort guards.

## 3. What the server can and cannot see

**Never visible to the server:** the fragment key `F`, passwords, the KEK/CEK/FK, note text,
file contents, **file and folder names, folder structure, MIME types, per-file sizes and
mtimes**, the viewer opt-in and its policy snapshot (all inside the encrypted manifest).

**Visible to the server (and Cloudflare), and possibly logged:**

- IP addresses, timestamps, User-Agent and access patterns.
- Share ids (they appear in request paths), storage class (note / view-limited / files).
- Ciphertext size: for notes an upper bound on the plaintext size; for file shares only the
  **padded total** (64 KiB granularity) and the chunk count — never individual file sizes.
- Expiry, view limit, remaining views, and lifecycle events; the declared format (`plaintext`,
  `code`, `markdown`, `url`, `secret`, `files`), so the server knows a share *is* a link or a
  credential, never what it contains; and whether recipients may delete it.
- **Account metadata:** usernames, which account created which share id, share **labels**
  (plain text by design — the UI warns not to put secrets in them), quota counters, API-key
  names and use times, the activity/audit log.
- For accounts that have a *files-per-share* or *max-file-size* limit, the creating client
  declares the file count / largest file size at upload time so the server can check it. The
  values are not stored. They cannot be verified by the server (the stream is encrypted);
  only the total size is enforced exactly.
- **File policy (allowed/blocked file types, maximum folder depth).** When — and only when —
  the administrator has set such a policy for an account, the creating client declares the
  de-duplicated set of `{extension, MIME type}` pairs and the deepest folder level at upload
  init. The server checks them against the policy and does not store them. This is a
  deliberate, bounded leak (which *kinds* of files, never their names, count per type, or
  sizes) that exists only for accounts under a policy. Like the file-count limits, the
  declaration is not verifiable: it stops honest mistakes and makes the rule auditable, not a
  modified client. The owner is never subject to it.
- Access-proof *hashes*, delete/upload/grant/API-key *hashes*, and password verifiers
  (`SHA-256("secbin-auth/v2" ‖ Argon2id(password))`).

- **The Drive** (see "Drive keys" and "Drive (server)" below): the shape of each user's folder
  tree (node ids, parents, file or folder), each file's exact size, chunk count and ciphertext
  hash, times, and which shares reference which items. Names, types, contents and file keys are
  sealed, but **the server holds the keys that open them** (the root MEK, the sub-MEKs and the
  user salts in the Directory): Drive files are not end-to-end encrypted.
- **Reverse shares** (see "Reverse shares" below): which folder a link targets, its limits,
  label, times and counters, whether it has a password, and each received file's exact size,
  chunk count and time — never the link key, the note to the uploader, the password, the files'
  names, types, folders or contents.

Tokens (delete, upload, download grant) and proofs travel in request **headers**, never URLs,
so they do not land in logged request URLs.

## 4. Frontend threat model — "XSS = key exfiltration"

Any script on the page can read `location.hash` and the decrypted content, so XSS equals full
compromise. Defenses:

- **Strict CSP** on every page and asset (`public/_headers`, kept identical to
  `src/lib/http.js` for Worker-served pages by `test-node/headers.test.js`):
  ```
  default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self';
  img-src 'self' data: blob:; media-src blob:; connect-src 'self'; font-src 'self';
  worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none';
  frame-src 'none'; object-src 'none'; require-trusted-types-for 'script';
  trusted-types secbin; upgrade-insecure-requests
  ```
  - `'wasm-unsafe-eval'` allows **WebAssembly compilation only** (Argon2id; pdf.js image
    decoders). JavaScript `eval`/`new Function` remain blocked.
  - Where WebAssembly is unavailable (iOS/macOS **Lockdown Mode**, or a policy that refuses it),
    Argon2id falls back to @noble/hashes' audited pure-JavaScript implementation
    (`public/js/kdf.js`). It computes the same function byte for byte (tested against the RFC
    9106 vector and the frozen protocol vectors), so no parameter is weakened. Lockdown Mode
    also turns the JIT off, so one derivation can take up to about a minute there; the page
    shows its progress. Nothing else in the app needs WebAssembly (pdf.js has a JavaScript
    fallback for its image decoders).
  - `blob:` for images/media is used only by the viewer for content it has sniffed itself.
  - `worker-src 'self'` is for pdf.js's parser worker and the service worker (`/sw.js`);
    `manifest-src 'self'` is for the web app manifest. Both are first-party only.
  - **Trusted Types** are enforced. DOM XSS sinks (`innerHTML`, script and worker URLs, and
    similar) refuse plain strings, and exactly one policy, `secbin` (`public/js/tt.js`), may
    exist. It mints script URLs only for this origin's `/js/*.js` and `/sw.js`, and refuses
    to create HTML or script strings at all. pdf.js's worker is created through it.
- **Isolation headers.** Framing is denied both ways: `frame-ancestors 'none'`,
  `X-Frame-Options: DENY`, and `frame-src 'none'` (the app embeds nothing). Beyond that:
  - COOP `same-origin`, COEP `require-corp`, CORP `same-origin` and `Origin-Agent-Cluster`
    make every page cross-origin isolated.
  - `Permissions-Policy` denies every powerful feature (camera, microphone, geolocation,
    payment, USB, and so on) except clipboard writes, fullscreen and picture-in-picture for
    the app itself.
  - `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and a two-year
    HSTS with preload.
- **First-party only.** No CDNs, analytics or third-party scripts. The vendored libraries
  (hash-wasm, @noble/hashes, pdf.js, qrcode-generator) are pinned, SHA-256-verified and rebuilt reproducibly
  by `tools/vendor.mjs` (`public/THIRD-PARTY-NOTICES.md`).
- **DOM construction only.** Decrypted content, file names and server strings are rendered
  with `textContent`. The element helper refuses `innerHTML`, `outerHTML`, `on*`, `style`
  and `srcdoc`. URL-valued attributes (`href`, `src`, …) accept only relative URLs, `http`,
  `https`, `mailto` and `blob:` URLs, plus `data:image/*` for images. Markdown is a
  raw-HTML-free subset with an `http`/`https`/`mailto` link allowlist.
- **File names cannot disguise themselves.** The characters that can make a name display as
  something else — bidi overrides, embeddings and isolates (U+202A–U+202E, U+2066–U+2069) —
  and U+200B, U+FEFF, U+0085, U+2028 and U+2029 are removed from every file and folder name
  (then NFC; `files.js` `cleanName`) when a file share, a Drive item or a CLI share is made and
  when a received one is shown or saved (marked "renamed"); names are never refused for them.
  Every name is shown in a bidi isolate with its extension as its own left-to-right isolate
  (`common.js` `nameEl`), so `invoice<U+202E>fdp.exe` appears as `invoicefdp.exe` with the
  extension `.exe`. Everything real names use stays: Hebrew and Arabic (with niqqud and
  harakat), ZWNJ / ZWJ and LRM / RLM / ALM.
- **Safe viewer** (optional, admin-governed, sender opt-in per share):
  - text/Markdown/code: inert DOM, size-capped;
  - images: the type comes from our own signature sniffing (never the sender's label); the
    dimensions are parsed from the header and oversized images (> 40 megapixels) are refused
    **before** decoding; **SVG is never rendered** (it is not in the allowed raster set);
  - PDF: vendored pdf.js core only — no scripting sandbox, no annotation/form layer, no XFA, no
    eval — rasterized page by page to a canvas with page and pixel caps; embedded PDF
    JavaScript never runs;
  - audio/video: native elements from sniffed `blob:` URLs, no autoplay;
  - one preview at a time; object URLs are revoked on close; global disable takes effect for
    existing links immediately (the page intersects the sender's snapshot with the live
    policy).
- **Link shares** (`fmt: "url"`) are never followed automatically. Only absolute URLs without
  embedded credentials are accepted (on create and again after decryption).
  - **Which links** a sender may share is the role's *URL rules*: `scheme:<name>://` (links
    written with `//`; http and https always are), `scheme:<name>:` (links without `//`, such as
    `tel:` and `mailto:`), `scheme:*` and `re:<regular expression>` against the whole link. The
    default is `scheme:http://` and `scheme:https://`, and the owner may share any safe link.
    Rules saved in the older form (`scheme:tel`) were rewritten by migration 11 to allow exactly
    what they allowed; older export files are upgraded on import. The link is encrypted, so the
    rules are checked by the sender's browser or CLI (the CLI reads them from
    `GET /api/private/policy`) — they keep honest senders within policy, not a modified client.
    Admin-written regular expressions run in senders' browsers (the admin is trusted; a costly
    pattern slows only the composer).
  - **Never allowed**, on either side and whatever the rules say: `javascript:`, `data:`,
    `vbscript:`, `file:`, `blob:`, `about:`, browser-internal and extension schemes.
  - **What a recipient may open.** The recipient does not know the sender's rules, and a modified
    sender client could ignore them. So the page opens only `http:`, `https:`, `mailto:`, `tel:`
    and `sms:` links. Any other scheme the rules may allow (`vscode:`, `ssh:`, `smb:`,
    `search-ms:`, …) is shown in full with **Copy only** and a warning. Otherwise an app link
    offered on this trusted origin could be a malware-delivery step. The composer tells the
    sender so.
  - The recipient sees the host as the browser resolves it (punycode), and **the full link**
  (for app links the host alone would hide the path and query that carry what the link does).
  There is a look-alike warning for internationalized names and a warning for plain HTTP. The
  link opens with a confirmed second
  click through `window.open(…, 'noopener,noreferrer')`, so the destination gets no
  `Referer` and no handle to this page.
- **Credential shares** (`fmt: "secret"`) are validated fail-closed and rendered field by field
  with `textContent`; password and one-time-code seed stay masked until revealed. One-time codes
  are computed in the page (WebCrypto HMAC), never by the server. The CLI never takes a
  credential from its arguments (only a file, stdin or hidden prompts) and, when printing a
  link or credential to a terminal, escapes control characters (newlines and tabs kept);
  `--out` files get the exact value. Plain notes are printed as they are, like `cat`.
- **"Delete now"** by a recipient needs both access proofs (so only someone who can open the
  share), the sender's opt-in *and* the admin's permission — checked again at the moment of
  deletion, so withdrawing it also covers shares created earlier. It is refused while the admin
  has the share locked or after a file share's last view, counts wrong proofs as invalid
  attempts, and spends no view.
- **Downloads** are always `application/octet-stream` / `application/zip` with sanitized
  names; ZIP member names come from validated paths (no absolute or `../` entries).

### Cloudflare Turnstile (optional human check)

Off unless a site key and a secret key are both configured. They are set either as the
deployment's `TURNSTILE_SITEKEY` and `TURNSTILE_SECRET`, or by the owner in Admin → Security
("Human check"). The deployment's keys always win.

- **Keys set in the admin panel** need the owner's password or a passkey, and are logged
  (`turnstile.updated` with the site key; never the secret).
- **Where the panel's secret lives.** It is stored in the Directory Durable Object's SQLite (the
  `meta` table), which Cloudflare encrypts at rest. The Worker reads it; no API returns it, and
  the admin panel shows only whether one is saved. Anyone who can run code in the Worker, or
  read the Durable Object, can read it. A Worker secret (`wrangler secret put TURNSTILE_SECRET`)
  or Cloudflare Secrets Store remains the recommended place (recommendation), so the panel is
  for deployments where editing secrets is not practical. An export includes the panel's keys,
  the secret too, only when the owner ticks "Turnstile keys"; this part is off by default.
- **Propagation.** Each Worker isolate caches the panel's keys for 30 seconds, so a change reaches
  every server within about 30 seconds. If the Directory cannot be read, the last keys seen stay
  in use; a first lookup that fails leaves Turnstile off, but then sign-in fails anyway,
  because it needs the Directory.

When on, it protects the
forms automated attacks target: login, starting an anonymous share and every change a
signed-in browser session makes to its own account on the Account page:

| Account page action | Route | Action name |
|---|---|---|
| Change password | `POST /api/private/me/password` | `password` |
| Change username | `POST /api/private/me/username` | `account` |
| Add a passkey | `POST /api/private/me/passkeys` (the step that stores it) | `account` |
| Remove a passkey | `POST /api/private/me/passkeys/:id/remove` | `account` |
| "Password and passkey" / "Password or passkey" | `POST /api/private/me/second-factor` | `account` |
| New recovery codes | `POST /api/private/me/recovery-codes` | `account` |
| Create an API key | `POST /api/private/me/keys` | `account` |
| Change an API key (name, scopes) | `PATCH /api/private/me/keys/:id` | `account` |
| Revoke an API key | `DELETE /api/private/me/keys/:id` | `account` |

Asking for a challenge changes nothing and needs no token: the passkey registration options
(`POST /api/private/me/passkeys/options`) and the passkey "confirm it's you" challenge
(`POST /api/private/me/reauth`). The step each of them leads to is protected, and a challenge is
not used up by a request that the human check refuses, so the check cannot be skipped by
calling the steps in another order. Setup, admin password resets, the owner's changes in the
admin panel (to other accounts or their own), recipients opening links, file chunks and API
keys are never challenged; API keys cannot reach the account routes at all (`403
api_key_not_allowed`).

- **Client side** (`public/js/turnstile.js`). The protected buttons (log in, sign in with a
  passkey, create an anonymous share, and every button in the table above) stay disabled until
  the widget has issued a token, and again after each token is used (one token per call) until
  the next one arrives; if the widget cannot load they stay disabled and the page says why. On
  the Account page each card that changes something (username, password, passkeys and recovery
  codes, API keys) has its own always-visible widget; one widget serves every button of its card,
  including the Remove and Revoke buttons of each table row. This is a usability guard: the
  server-side check below is what enforces it.
- **Server-side verification** (`src/lib/turnstile.js`). Each protected call must carry
  `X-Secbin-Turnstile`, which is redeemed with Cloudflare's siteverify. The call passes only
  when the token:
  - succeeded;
  - was issued for the request's own hostname;
  - was issued for that form's action (`login`, `password`, `account`, `public-share`), so a
    token from one form cannot be replayed on another;
  - has not been used before (siteverify refuses a reused token).

  The token is checked before the password (at login, and before the "confirm it's you" step of
  an account change), so a bot learns nothing about the password and every guess costs a token.
  If siteverify cannot be reached the request is refused (`503`, fail closed). Cloudflare's
  published testing keys return no hostname or action, so their results are accepted as they
  come; never deploy with testing keys.
- **The only third-party code, confined to those pages.** Login, Account and the home page
  (the last only while anonymous sharing is on) get a CSP that adds
  `https://challenges.cloudflare.com` to `script-src` and `frame-src` and drops
  `Cross-Origin-Embedder-Policy` (the widget's cross-origin iframe cannot load in a
  cross-origin-isolated page). Every other page keeps the strict policy above. That includes
  every `/p/*` link, which is static and never loads the widget.
  - Trusted Types stay enforced: the `secbin` policy (`public/js/tt.js`) mints exactly one
    third-party URL, `https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit`.
  - The Permissions-Policy is unchanged; the widget's requests for extra features are denied,
    and it does not need them.
- **Trust trade-off.** On those pages a compromise of Cloudflare's Turnstile script could read
  the page:
  - on login and Account, the password being typed;
  - on Account, the Drive keys while the personal kit is built there (see "Drive keys", in the
    tab: they are never in the tab's storage); on login, while a Drive waits for its upgrade, the
    old Drive key the sign-in opens there;
  - on the home page, what an anonymous sender types and the link, with its key, that it
    produces;
  - on a reverse share's uploader page (`/r/<id>`), the link key in `location.hash` (it reads the
    note and uploads to the link; it opens nothing received) and the files being sent, before
    they are encrypted.

  Recipients' pages (`/p/*`) and signed-in composers never load it. secbin already runs on
  Cloudflare, so this adds no new trusted party, but it is a second code origin. Leave Turnstile
  off if that is unacceptable.
- **Privacy.** Turnstile runs Cloudflare's client-side challenge and sends browser signals to
  Cloudflare. For GDPR, treat Cloudflare as a processor for this purpose and describe it in
  your privacy notice.

### Accessibility widget and statement

- **First-party code under the same rules as the rest of the site.** The preferences widget
  (`public/js/a11y.js`) and its head script (`public/js/a11y-init.js`) are CSP-safe
  (`script-src 'self'`) and follow the Trusted Types discipline: DOM calls only, no markup
  strings, no third party.
- **What is stored.** Only the viewer's display choices, kept in `localStorage`
  (`secbin:a11y`); malformed values are ignored. Nothing is sent to the server.
- **The statement page.** `/accessibility/` uses the strict policy. The whole statement is
  admin-set plain text (validated settings: lengths, one-line headings, list items, a checked
  language code, `ltr`/`rtl`, a date, 32,000 characters in all), served by `/api/config` and
  built with DOM calls and `textContent` (`public/js/statement.js`), never as markup.

### Service worker and install banner (PWA)

secbin is installable. `public/sw.js` (scope `/`) is registered from `public/js/pwa.js`
through the `secbin` Trusted Types policy (it mints the `/sw.js` URL and nothing else outside
`/js/`), and is served with the same CSP / COEP / CORP headers as every other asset. It is
deliberately **not a content cache**:

- It only ever touches **same-origin `GET` requests without a query string**. Everything else —
  other origins, `POST`/`PUT`/`DELETE`, any URL with `?…`, `Range` requests, encoded or dot
  path segments — is not intercepted at all (no `respondWith()`), so it can neither be served
  from nor written to the cache.
- **`/api/*` and `/p/*` are never intercepted and never cached** — no ciphertext, grants,
  account data or share pages ever reach Cache Storage. (Share keys live in the URL fragment,
  which is never part of a request in the first place.) `/dashboard*` pages are not cached
  either.
- The only things it stores are static assets under `/css/`, `/js/`, `/fonts/`, `/img/`, the
  manifest, the favicon, and the public landing page `/` as the offline shell — and only a
  plain same-origin `200` that is not a redirect and not marked `no-store`/`private`.
- Everything is **network-first**: while online the browser always runs the code the server
  is serving now; a cached copy is used only when the network fails.
- The cache name is versioned (`secbin-static-<n>`); on activation every older secbin cache is
  deleted and open pages are claimed (`skipWaiting` + `clients.claim`). The worker is
  registered with `updateViaCache: 'none'` and served `Cache-Control: no-cache`, and browsers
  never route the update check for `/sw.js` through a service worker, so a new deployment
  replaces the worker on the next navigation.
- The request filter (`requestPolicy`) is unit-tested in `test-node/sw.test.js`.

The install banner (`public/js/install-banner.js`) is built with DOM APIs only and never
appears in the installed app (`display-mode: standalone`, or iOS `navigator.standalone`).
Dismissing it sets one first-party cookie, `secbin_pwa_dismiss=1` (`Max-Age` one year,
`Path=/`, `SameSite=Lax`, `Secure` on HTTPS). It is readable by page script by design (not
`HttpOnly`), carries no identifier, and the server ignores it; it is sent with same-site
requests like any cookie. Declining the browser's own install dialog records the same value.

### Deployment-compromise limitation (important)

The browser downloads and trusts JavaScript from the server. Whoever controls the deployment,
the repository or the Cloudflare account can serve code that reads keys and plaintext. Client-side
encryption protects data from the *storage* layer, not from a compromised *delivery* of the app.

### The CLI

`cli/` (`secbin`) implements the same protocol with the same vendored modules (drift-tested).
Its trust anchor is your local installation. It never follows symlinks when sending, confines
downloads to the output directory, refuses to write through symlinks or overwrite without
`--force`, and reads the API key from `SECBIN_API_KEY` or a file — never a flag value. Share URLs
passed as arguments are visible to other local processes; `secbin get -` reads one from stdin.

## 5. Trust boundaries

| Boundary | Trusted with content? | Notes |
|---|---|---|
| Sender's / recipient's browser + served JS | **Yes** (unavoidable) | §4 |
| CLI process | **Yes** | §4 |
| Network | No | TLS; the fragment is never sent |
| Worker, KV, R2, Durable Objects | No | Ciphertext + metadata (§3) |
| Owner / admin | No (content) | Sees account metadata, can impersonate; cannot decrypt |
| Holder of the full link (+ password) | **Yes** | That is the capability being shared |

## 6. Accounts, sessions and brute-force protection

- **Setup/recovery**: `/dashboard/setup` requires the `AUTHN` secret (≥ 32 chars, constant-time
  compare). A token value works **once** (its hash is recorded); recovery requires a new value.
  With `AUTHN` unset, setup rejects every request with `404` and never errors. Every setup is
  audited; the admin panel warns while `AUTHN` is still set.
- **Password policy** (admin-set, global and per user: minimum length 12–128, upper-case,
  lower-case, digit, symbol) is **enforced only in the browser** — the server receives an
  Argon2id proof, never the password, so it cannot verify the policy. A modified client can set
  a weaker password for its own account; the policy protects honest users from weak choices, not
  the server from a hostile client. It applies only when a user changes their **own** password.
  Passwords the owner sets are exempt: at setup, on the owner's own Account, for a new user, and
  when resetting a user's password. The length counts every character as typed (one per Unicode
  code point, so spaces, emoji and combining marks all count).
- **Passwords** never reach the server: the client sends `Argon2id(password, salt)`; the server
  stores `SHA-256("secbin-auth/v2" ‖ that)`. Prelogin returns a stable, secret-keyed fake salt
  for unknown usernames, and every account uses the same Argon2id time cost, so the response
  never reveals whether an account exists. Minimum length (12) is enforced client-side — the
  server cannot see the password. Trade-off: the stretched value is password-equivalent in
  transit (TLS-protected), as with any client-side stretching scheme.
- **Sessions**: `__Host-` cookie, HttpOnly, Secure, SameSite=Strict, containing a JWS (HS256,
  `SIG`) inside a JWE (A256GCM, `ENC`). Strict parsing (exact headers, no `alg: none`, no
  algorithm confusion). Every request re-checks revocation, disabled state and the per-user
  session version (bumped by password change/reset/disable), plus admin-configured idle and
  absolute timeouts. Missing/invalid `SIG`/`ENC` ⇒ login is unavailable (`503`), public links
  keep working.
- **Disabled accounts** are refused on every authenticated route, including the dashboard,
  My shares, account and share creation, even with a still-valid session cookie or API key.
  - The response is `403 account_disabled`, and the session cookie is cleared.
  - Disabling also bumps the session version, so re-enabling never brings old sessions back.
  - Capabilities held by link holders (a share's delete token, an open download grant) are
    not account credentials, so they keep working.
- **CSRF**: layered guards, every one enforced on its own.
  - The session cookie is `__Host-`, HttpOnly, Secure and SameSite=Strict.
  - State-changing calls must be non-simple: a JSON content type, or `X-Secbin-Intent: 1`
    (every `DELETE` and every action without a body). File chunks are
    `application/octet-stream` with `X-Upload-Token`.
  - Requests with `Sec-Fetch-Site: cross-site` **or `same-site`** are refused (`403
    cross_site`); a sibling subdomain is not trusted.
  - The API sends no CORS headers.
  - **CSRF tokens** (`src/lib/csrf.js`), on top of the guards above. The token is stateless and
    bound to the session: `HMAC-SHA256(K, "secbin-csrf/v1:" ‖ session id ‖ ":" ‖ session
    version)`, base64url. `K = HMAC-SHA256(SIG, "secbin-csrf-key/v1")` is a subkey of the
    session signing secret, used for nothing else. While impersonating, the version is the
    owner's.
    - One token per session, the same in every tab and request. It changes only when the
      session does: sign-in, sign-out, a session-version bump (password change or reset,
      disable), impersonation start or end.
    - Delivered in a readable cookie `__Host-secbin_csrf` (Secure, SameSite=Strict, `Path=/`,
      not HttpOnly) whenever the session cookie is set or refreshed, on every signed-in
      dashboard page load, and in `GET /api/private/me` (`csrf`, with the cookie re-set). Its
      lifetime is always the session cookie's: when it is re-set on its own (a page load, `/me`),
      its `Max-Age` is what the session cookie has left (the idle window from the last activity,
      capped by the absolute expiry). Sign-out and a disabled account clear it. The Worker never
      logs it or puts it in an error message.
    - Every cookie-authenticated `POST`, `PUT`, `PATCH` and `DELETE` (`/api/private/*`,
      `POST /api/auth/logout`) must send it in `X-Secbin-CSRF`. Right after the session is
      resolved (`authenticate()`, and logout), before anything else runs, three checks are made
      in this order:
      1. `Sec-Fetch-Site` (`403 cross_site`);
      2. the request shape: a JSON body, a file chunk (`application/octet-stream`) or
         `X-Secbin-Intent: 1`, and the intent header on every `DELETE`. A body of any other type
         gets `415 unsupported_media_type`; a request with neither a body type nor the header,
         or a `DELETE` without the header, gets `400 missing_intent`;
      3. the token (`403 csrf_mismatch`).

      This covers the Drive and reverse shares too: creating a reverse link (`POST
      /api/private/drive/reverse`), taking a received file in (`POST …/received/<id>`), marking
      it failed (`POST …/received/<id>/failed`) and retrying it (`DELETE …/received/<id>/failed`),
      and extending, revoking and locking a link through My shares and Admin → Shares
      (`/api/private/shares/<id>`, `/api/private/admin/shares/<id>`). They all go through
      `authenticate()`, so the token and the shape check come before the step-up (the password or
      passkey that creating a link needs) and before anything is claimed in the share index. The
      Drive page sends the page's recorded token through `api.js`. The workerd suite
      (`test/csrf.test.js`) reads `src/routes/reverse.js` and fails if a cookie-authenticated
      reverse route or method is missing from its sweep.

      1 and 2 apply with the `csrfTokens` setting off too. So a refused request has changed
      nothing, counted no failure (lockouts, network blocks) and spent no single-use token, and
      it can be retried as it is. The comparison is timing-safe
      (`crypto.subtle.timingSafeEqual`). A missing, wrong, other-session or old-session-version
      token is refused. A request without a live session gets the usual `401`.
    - Every route that takes a Turnstile token checks its request body before it verifies the
      token, so a request of the wrong shape never spends one. The account changes (password,
      username, API keys, passkeys, recovery codes, second step), sign-in, recovery and passkey
      sign-in read and parse their JSON body first. Starting a public share checks the content
      type and the declared size first; its body (up to 4 MiB, from anyone) is still read only
      after the human check.
    - The browser client (`public/js/api.js`) acts for the session its page was loaded for.
      Each dashboard page records, from `GET /api/private/me` at load, the user id, the
      impersonation state (`impersonatedBy`) and that session's token, and sends that token,
      not whatever the shared cookie holds later. (A page that has recorded none records the
      current session before its first change.) When another tab signs in as someone else, or
      starts or ends impersonation, the page's token no longer matches and the server refuses
      its next change. On `403 csrf_mismatch` the client fetches `/api/private/me` and compares
      the user id and impersonation state with the page's own:
      - the same: a new session of the same user (signed out and in again, a password change).
        It takes the new token and retries once. That is safe because the refused request
        changed nothing;
      - different, or a second refusal: no retry. The page stops acting for any session (every
        later change, sign-out included, is refused in the page without a request) and shows
        "Your session changed in another tab; reload the page." with a Reload button. A page
        loaded for one user never changes another user's account, and does not sign the other
        session out.

      A dashboard page restored from the back-forward cache also re-checks the session and
      reloads if it now belongs to someone else. Sign-out goes through the same refresh and
      retry; a failure for any other reason (such as the network) is shown, and the user can
      try again.
    - **Exempt, with their reasons:**
      - API-key (`Authorization: Bearer sbk_…`) requests from the CLI and scripts: the key is
        sent explicitly and never attached by a browser on its own, and no cookie is involved.
      - The anonymous routes: opening, "delete now" and deleting a share by its capabilities,
        public creation, login, passkey and recovery sign-in (and `POST
        /api/auth/passkey/options`, which stores nothing: its challenge is signed, not stored),
        prelogin and setup. There is no session to bind a token to. They keep their own guards
        (the cross-site check, JSON bodies or custom headers, access proofs and tokens,
        Turnstile, rate limits).
      - The reverse-share uploader: the `/r/<id>` page and its calls under `/api/reverse/<id>/`
        (`open`, `begin` (the session start), `files` (reserve), `files/<node>/chunk/<i>`,
        `files/<node>/finalize`, cancel (`DELETE files/<node>`) and `done`). The uploader is
        anonymous: these routes never read the session cookie, so a forged request gains no
        user's authority, and a signed-in user's cookie in the same browser changes nothing. What
        they act on is held by the link, not by a session: the link proof (derived from the key
        in the `#fragment`), then the session grant and the per-file upload token. They keep
        their own guards: the cross-site check (before any Guard accounting), a non-simple
        request (the intent header, a JSON or `application/octet-stream` body, or the
        `X-Reverse-Grant` and `X-Upload-Token` headers), Turnstile on `begin` (before the password),
        the per-link password lockout, the Guard's `invalid` scope and the per-network session
        limit (see "Reverse shares"). The uploader page's client (`public/js/reverseclient.js`,
        through `api.js`'s `reverseApi`) sends no token and never asks `/api/private/me`.
    - **Owner switch:** Admin → Settings → CSRF tokens (`csrfTokens`, on by default,
      server-wide). Off, the server stops requiring `X-Secbin-CSRF` (the header is ignored); the
      cookie is still issued, and every other guard above stays enforced. The value is read
      with the session in the same Directory call, so the switch adds no round trip and takes
      effect on the next request. Turning it on again covers open pages through the one retry.
      Each change is recorded in the owner-only admin audit as `settings.csrf` (old and new
      value). The setting travels in an export's settings part, and the import preview warns
      when an import would turn tokens off.
    - **An import can be applied without a preview.** The dashboard always shows the preview
      (with that warning) before it lets the owner apply an import. The API does not require
      one: `POST /api/private/admin/import` with `dryRun: false` applies the import directly,
      and the preview's warnings are then never shown. It still needs the owner's password (or
      passkey) and a real owner session (not an API key, not while impersonating). The server
      recomputes the plan itself, and the change is recorded in the admin audit
      (`settings.csrf` `import: from=true to=false`, and in `settings.updated`).
    - **Not verified: Cloudflare's production logs.** The Worker never logs the token or the
      `Cookie` header, and locally neither the `wrangler dev` log nor its trace store records
      request headers. With `[observability] enabled = true` (`wrangler.toml`), whether Workers
      Logs, `wrangler tail` or a Logpush job capture request headers such as `Cookie` or
      `X-Secbin-CSRF` in production has not been checked. The session cookie travels in the
      `Cookie` header as well, so the token adds no new kind of exposure. Whoever runs the
      deployment should confirm the fields those logs keep.
- **API keys** (`sbk_…`, stored hashed) authenticate share creation, the policy read and the
  key user's own shares (list, receipts, label, extend, revoke) — never the account itself
  (profile, password, passkeys, keys, activity) or admin endpoints (`403 api_key_not_allowed`).
  The owner decides who may hold keys and how many; API limits and quotas can only narrow the
  account's limits. Revoking API permission disables existing keys at once.
  - **Scopes:** each key carries a subset of `notes`, `files`, `policy` (create), `read` (list
    the user's shares, one share, and its read receipts) and `manage` (label, extend views /
    expiry, revoke). A key created without a choice gets the three creation scopes only; `read`
    and `manage` are always an explicit choice. Scopes are chosen at creation and can be changed
    later (by the user with their password or a passkey, or by the owner); a call
    outside them is `403 scope_denied`. Issue each automation the narrowest key it needs (least
    privilege) and an expiry.
  - **Same rules as the dashboard:** a key sees and changes only its user's shares (anything
    else is `404`), cannot touch a share the owner has locked (`423`), can only grow views and
    expiry, and is held to the account's **API** limits when extending. A revoke needs
    `X-Secbin-Intent: 1`. Every change made with a key is logged with the key's id
    (`apikey=<id>`), never the key.
  - **Exposure:** a leaked `read` key reveals the user's share labels (not encrypted), sizes,
    dates and read receipts (which may include recipients' network addresses, locations and
    browsers, as far as the owner enables receipt details — personal data); a leaked `manage`
    key can revoke the user's shares (availability) but can never read their content, which
    stays encrypted with keys the server never holds.
  - **Storage:** the key is shown once. Keep it in a secrets manager (for example HashiCorp Vault
    or AWS Secrets Manager) and pass it through the environment, never in source code, shell
    history or command-line arguments. The examples in `examples/api/` read `SECBIN_API_KEY`
    only.
  - The built-in public account never holds keys.
- **Roles replace per-user settings.** Every account has exactly one role (the Default role
  unless given another), and the owner's is the locked Owner role. The migration that introduced
  roles deleted any per-user overrides and wrote one audit entry with how many (`roles.migrated`),
  so an account that was restricted individually falls back to the Default role until it is
  given a role. Review Users → Role after upgrading (recommendation).
- **Impersonation** ("log in as"): the owner can do everything the user can, the Drive
  included; it is invisible to the user (the user's activity shows the actions as theirs), and
  the owner-only admin audit keeps the start, end and real actor.
  - **Who:** the owner only, never nested, never of the owner's own account. The session is
    bound to the owner's session version, so it ends when the owner's password changes or the
    owner is disabled; it also ends when the user is disabled.
  - **What stays out of reach:** the admin panel (every `/api/private/admin/*` route but
    "Return to admin" refuses with `impersonating`), and with it minting keys for the owner.
    Keys created on the user's Account page are the user's.
  - **No confirmation:** changes to the account (password, username, passkeys, recovery codes,
    the sign-in choice, API keys) need no password or passkey check: the owner's session is the
    authority. The Directory accepts that only from the enabled owner impersonating another
    account (`{ id, imp: true }`); anyone else still confirms.
  - **Credentials:** a password the owner sets is exempt from the password policy (as in Admin →
    Users); it ends the user's sessions, not the owner's. Passkeys can be added and removed and
    recovery codes regenerated (the new codes are shown to the owner). Existing passkeys and
    recovery codes are never removed unless asked: a password or username change keeps them, and
    only the passkey removed goes (removing the last passkey drops the recovery codes and the
    second step, as it does for the user).
  - **Human check:** with Turnstile on, the Account page's widgets apply to the owner acting as
    the user exactly as to the user (`password` and `account` tokens): the check runs in the
    owner's browser, so nothing in the impersonation flow prevents it.
  - **Logging:** the user's own activity shows each action taken while impersonating as the
    user's own, with no actor, and does not list the start or end of an impersonation. The
    owner-only admin audit records `impersonate.start`, `impersonate.end` and, for each action,
    the owner as the real actor (`imp`).
  - **The Drive:** the owner has the user's whole Drive, opened with the user's keys, which the
    server hands the owner's session (see "Drive keys"). What the owner does there while
    impersonating — reads, uploads, folders, renames, moves, deletions, Drive shares and their
    changes — is logged exactly like the rest of the account: in the user's activity as the
    user's own (no actor, no trace of the impersonation), and in the owner-only admin audit with
    the owner as the real actor (`imp`). Getting the user's keys is the owner's own action
    (`drive.keys_used`, admin audit only). The personal kit and the upgrade are the user's own
    (`403 impersonating`).
- **Admin share management**: the owner sees every user's shares and can change a share's label, views
  and expiry, revoke it, or **lock** it.
  - **Only metadata:** it never gains access to share content, which stays end-to-end
    encrypted.
  - **Bounds:** admin changes are increase-only and bounded by the protocol maxima, not by the
    user's limits.
  - **Logging:** they are recorded in the audit log as direct admin actions, and they do not
    appear in the user's own activity. Impersonation is different: it acts *as* the user and
    shows up as the user's own.
- **The user's own activity** (Account → My activity) lists only what the user did, what was done
  as them while impersonating, and system events about them (for example a lockout). Admin
  actions on the account (created, disabled, enabled, role or limits changed, password reset)
  and on its shares are recorded in the owner-only admin audit and are not shown to the user.
  - **Locks:** a locked share is frozen for its sender (no edits, no revoke) and for its delete
    token, until the owner unlocks it. Natural expiry and view exhaustion still apply. Locked
    rows are kept in the share index; they are not pruned.
- **Brute-force protection** (admin-configurable, per IP; IPv6 aggregated to /64 by default):
  - `login`, `setup`, and `invalid` — share ids that never existed, **wrong `#` keys, wrong share
    passwords**, bad download grants and bad delete/upload tokens. Opening a share that did
    exist but has expired, been used up, revoked or deleted, **with its correct link** (`#`
    key), is a recipient arriving late and is **not** counted. The share index keeps each
    share's link-proof hash (the same value the share's own record held) for the 30 days it
    keeps ended shares, so a **wrong `#` key** for an ended share is still counted, as for a
    live one. The first metadata fetch carries no proof and is not counted for a known share.
    Shares created before this change have no stored hash and are never counted;
  - rule: X failures within a window ⇒ block for a duration; the admin sees and manages blocks
    and tracking;
  - manual allow/block rules for IPv4/IPv6 addresses, CIDR blocks and inclusive ranges
    (`10.0.0.5-10.0.0.20`; allow wins; blocks deny the whole API and dashboard). A block rule
    that covers the owner's own address is refused unless an allow rule covers them first;
  - account lockout after X failed logins (owner exempt — recover via setup if needed). Per-IP
    protection and account lockout are complementary: the first stops one source guessing
    (any account), the second stops many sources guessing one account. Usernames that do not
    exist are counted and locked the same way (under a keyed hash of the name), so "locked"
    versus "wrong password" does not reveal which accounts exist. Anyone can still lock a
    known account by failing its logins (that is what a lockout is); Turnstile and the per-IP
    guard limit how cheaply;
  - **cross-site requests** to the public share routes (`/api/paste/…`, `/api/file/…`) are
    refused before any failure is counted, so another site cannot make a visitor's browser
    spend their "invalid fetch" budget and get their network blocked;
  - **the owner and global settings:** limits, quotas, the global share-size cap, the viewer
    switch and size, and lockout never apply to the owner. Security controls that protect the
    owner do: session timeouts, per-IP brute-force protection and IP rules (so an owner with no
    lockout still cannot be guessed at without limit). The owner's own password cannot be reset
    from the admin UI or API (`403 use_account_page`); it changes on Account, with the current
    password, or through setup recovery;
  - **password change** is never blocked by a lockout, so a stranger failing logins cannot stop
    a user from changing a password they fear is compromised. It still cannot become a guessing
    oracle for a stolen session:
    - after X wrong "current password" attempts within the window, every session of that
      account is ended, the owner's included;
    - each wrong attempt also counts against the caller's IP in the `login` scope.
  - Kill switches: `DISABLE_BFP=true` (everything, including IP rules) and
    `DISABLE_BFP_SETUP=true` (setup only).

### Passkeys and recovery codes

Every account (owner included) can register up to 10 passkeys (WebAuthn discoverable credentials)
on Account. The `passkeys` limit, set globally or per user, decides how they may be used; the owner
is never restricted by it:

| `passkeys` | Passkey alone | Password, then passkey | Recovery code alone |
|---|---|---|---|
| `any` (default) | yes | if the user turns it on | yes |
| `second` | no | always, once the user has one | yes |
| `off` | no | no (the password alone signs in) | yes (codes left from before) |

A recovery code is the way back in when everything else is lost, so it always signs in on its
own: whatever the mode, and even when the user turned on "passkey after password". Only the
guards against guessing still apply (Turnstile, the per-IP login guard and the account lockout),
and a disabled account stays disabled. Anyone holding a code therefore holds the account: keep the
codes as safe as the password.

- **What the server verifies** (`src/lib/webauthn.js`, Web Crypto only, no dependency):
  - the one-time challenge (5 minutes; single use), the ceremony type and the exact origin;
  - the RP ID hash (the site's hostname);
  - **user presence and user verification** (a PIN or biometric on the device), so a passkey
    is two factors;
  - the signature (ES256, EdDSA or RS256 ≥ 2048 bits) with the key stored at registration;
  - the signature counter (see *Counters* below);
  - on usernameless sign-in, a user handle returned by the authenticator must match the
    account's (the credential id selects the account and its key either way).

  Attestation is not requested (`none`), so any authenticator is accepted.
- **Confirming changes to one's own account.** Every change to the signed-in account needs the
  current password or, for an account with a passkey, a fresh passkey check. That covers the
  owner's own account too. The changes are:
  - a password or username change;
  - adding or removing a passkey, the second-step switch and new recovery codes;
  - creating, changing (name, scopes) or revoking an API key.

  The Account page asks again for every change: the field is cleared as soon as it is used. A
  passkey check answers a one-time `reauth` challenge (5 minutes, at most 3 pending per
  account), for that account only, with one of its own passkeys. Failed checks, by password or
  by passkey, count toward the same limit (every session ends after `lockout.max` within the
  window) and against the IP login guard. The owner impersonating the account makes these
  changes without a confirmation (see Impersonation above).
- **The owner, for other users.** As with setting a user's password, the owner changes another
  user's API keys (create, change, revoke) and removes their passkeys without a confirmation.
  On the owner's own account the admin routes ask for it, as Account does. A passkey can only be
  added by its user, on their own device (WebAuthn creates the key there).
- **Recovery codes.** The first passkey comes with 20 codes. Each is 80 random bits, shown once,
  stored as SHA-256 only, and works once, wherever a passkey would. New codes revoke the old set,
  and removing the last passkey removes the codes and the second-step requirement.
- **Counters.** An authenticator that keeps a signature counter (most security keys) adds at
  least 1 to it with every signature and sends it with the assertion. The server stores the last
  value and refuses an assertion whose counter is not higher. The server never *knows* that a key
  was cloned; a counter that did not move forward is the WebAuthn specification's signal that two
  devices may hold the same private key (a copied key, not a synced passkey). Replaying an old
  assertion is already refused by the single-use challenge, so the counter matters only when a
  copy signs a fresh challenge. The counter is updated with a conditional `UPDATE … WHERE counter
  < new RETURNING`, so of two simultaneous sign-ins with the same counter value only one
  succeeds. Synced passkeys (iCloud Keychain, Google Password Manager and similar) always report
  0; for them there is nothing to compare, and the check is skipped.
- **Brute-force protection.**
  - A wrong recovery code, or a failed second step, counts toward the account lockout and the
    per-IP login guard, like a wrong password.
  - The second step allows 5 tries per password entry.
  - Turnstile, when configured, also covers passkey and recovery-code logins.
  - The second step also stops while the account is locked out.
- **Challenges.** Anyone may ask for a usernameless sign-in challenge, so it is not stored: it
  carries its own expiry and an HMAC tag (a key derived from the Directory's secret). It is
  recorded as spent only when it is used with a registered passkey, before verification, so it
  works once. Registration and second-step challenges are stored, but only a signed-in user or
  someone with the right password can create one, and each account keeps at most 3 per purpose.
  A flood of requests therefore cannot push out anyone's pending sign-in.
- **Step-up and Turnstile.** When Turnstile is on, every confirmation above made from the
  Account page also needs a fresh human-check token (see *Cloudflare Turnstile*). The owner's
  confirmations in the admin panel (for example log clearing and the owner's own keys and
  passkeys there) check the password or a passkey, but not Turnstile. All of them need a
  signed-in session, wrong answers count toward the same limit as a password change (all
  sessions end after `lockout.max`), and the IP login guard applies.
- **Losing everything.**
  - The admin can remove any account's passkeys and codes, the owner's included (Users →
    Manage → Passkeys), after which the password alone signs in. This needs the acting
    admin's own current password, so a stolen admin session alone cannot strip anyone's
    second factor; wrong passwords count as for a password change.
  - Passwords and passkeys are separate. An admin password reset and a user's own password
    change keep the passkeys and recovery codes, and an import never changes an existing
    account's password, recovery codes or passkeys (it can only add passkeys). After a takeover, remove them as well. After a user's own change, Account
    says how many still work and asks the user to remove any passkey they do not recognise.
  - Owner recovery through `AUTHN` also removes the owner's passkeys and recovery codes; the
    Drive keys are not tied to them and stay as they are (see "Drive keys").
- Passkeys and recovery codes leave the server only in an export where the owner ticked
  "Passkeys" or "Recovery codes" (separate parts) for that account, the owner's own row
  included. The file carries the public keys (useless without the authenticator), each with the
  WebAuthn user handle it was registered under, and the recovery-code hashes. Passkeys work only
  under the same hostname (WebAuthn binds them to it); recovery codes work anywhere.

### Drive keys

The Drive (design and contract: [`docs/DRIVE.md`](./docs/DRIVE.md) §2, §3) is encrypted in the
browser, but **it is not end-to-end encrypted**: the server holds the keys that open it.

- **What the server can open.** Every file's content is encrypted in the browser under its own
  random DEK, and the DEK, the name and the metadata are sealed under the user's KEK. The KEK is
  `HKDF(root MEK ‖ sub-MEK, user salt, "secbin-kek/v1\n<userId>")`, and the root MEK, the
  sub-MEKs and the user salts are kept in the Directory Durable Object. So **the server — and
  anyone with a copy of the Directory's storage (a compromised Cloudflare account, a malicious
  deploy, an insider) — can decrypt every Drive file.** The owner can too: the key kit, a user's
  keys in Admin → Security → Keys, and acting as the user.
- **What a leak of the Drive's own storage reveals.** R2 and the user's Drive Durable Object hold
  ciphertext, seals, per-item salts and the ciphertext hash only: **without the Directory they
  reveal nothing** (sizes, times and the tree's shape as before, §3).
- **What stays end-to-end.** Notes and file shares (the key is in the link); a Drive share's
  manifest, sealed like a file share (the recipient gets the DEKs from the link, never from the
  server); reverse-share uploads until the user's browser takes them into the Drive.
- **Seals.** Each seal is AES-256-GCM under a key derived from the KEK with the item's 32-byte
  random salt, with AAD naming the user, the sub-MEK and the field; the item id is not in the AAD
  (DRIVE.md §9). File content keeps the file-share chunk format (index and count in the AAD), and
  the sealed metadata carries the size, checked against the server's.
- **Keys handed out.** After sign-in the server hands the session the user's KEKs (no prompt;
  the step-up rules for sensitive actions are unchanged). The owner acting as a user gets the
  user's KEKs (`drive.keys_used`, in the admin audit only), kept in the tab's own slot for them,
  never over the owner's. The root MEK and the sub-MEKs leave the Directory only for the owner,
  after the step-up (Show, the key kit, an export), recorded by fingerprint; generated and
  entered keys are never logged. The Worker opens DEKs and names only to check a new seal and to
  re-seal (rotation, a sub-MEK deleted, a root change), in memory, never stored or logged.
- **Every new seal is checked.** The Worker opens what a browser sends once with the current KEK
  before storing it (`400 bad_seal`, `409 mek_not_current`), so the server can always re-seal it
  later; re-seals are compare-and-set writes, so a change made meanwhile is never overwritten.
- **The keyring.** Created on first need, and only if there never was one: a lost keyring is
  never replaced silently (the Drive says the keys are missing and the key kit restores them).
  Restores and imports never replace a working key.
- **Kits.** The personal kit (every user) holds the user's salt and KEKs; the key kit (the
  owner) the root MEK, every sub-MEK and every user salt. Each is sealed in the browser under an
  optional passphrase (Argon2id, AES-256-GCM, bound to the account and the origin) and never sent
  to the server; verify sends check values only. **A key kit opens every Drive** (with a copy of
  the stored ciphertext): store it offline, like the AUTHN secret. Losing the Directory's keys
  and every key kit loses every Drive file. What these controls can and cannot enforce: the
  step-up on a kit download gates the server's handing out of the keys; the throttle on failed
  kit openings is in the page's memory only (guessing a passphrase offline needs only the file);
  kit checks are limited to 30 per session per 10 minutes.
- **In the tab.** The KEKs are never written to browser storage (`sessionStorage`,
  `localStorage`): each page asks the server for them (`POST /api/private/drive/keys`, cheap,
  since the server derives them) and keeps them in its own memory, gone when the page is left. A
  failed request is shown as an error; there is no stored key to fall back on. Nothing read from
  storage is ever used as a key, so a value that other script on the origin plants there is
  ignored: it can neither seal a new DEK nor stand in for a Drive's keys (a regression test plants
  one). The one Drive key a tab may keep in `sessionStorage` is the old Drive key of the release
  before, only while that Drive waits for its upgrade (the sign-in page opens it, the Drive page
  and Admin use it); it is used only once its key check value matches the server's (a Drive
  without one: once it opens one of the Drive's old items), and a key that fails is removed.
  Every other slot a release before used is removed at each Drive open and dashboard load. The
  CSP and Trusted Types (§4) keep other script out, as for the rest of the app; the pages that
  may load Cloudflare's Turnstile script (the one third-party script, §4) move that old key into
  the page's memory before the script loads (the sign-in page writes it back as it leaves). What
  remains: a compromised Turnstile script on the Account page could read the page's own memory
  while the personal kit is being built there, as it could read the password typed there.
- **The upgrade of Drives made before this model** (DRIVE.md §3.3) opens the old Drive key only
  in a browser — at the user's sign-in, or in the owner's browser through the owner's escrow of
  that release (recorded, `drive.escrow_used`) — re-seals every item under the user's KEK, and
  removes the old wraps only after the server has verified that every item opens under the new
  keys (the owner's escrow keys and records only once every Drive is upgraded). While a Drive
  waits, its old key wraps are kept current as before (spent recovery codes, removed passkeys and
  replaced codes lose theirs; an admin reset drops the old password's wrap when another remains).

### Read receipts

- Every successful open of an account's share (a wrong link or password is not an open) is
  recorded: the time, and what the opener's request itself revealed — the IP address,
  Cloudflare's coarse location (country, region, city), the browser and version, the operating
  system and the `Accept-Language` languages.
- **Throttling and retention.** Recording is throttled so that someone holding a link cannot
  flood the single Directory object or push the genuine receipts out:
  - at most one stored receipt per share and address per minute; beyond 5 opens a minute from
    one address the Worker stops recording that address for the minute;
  - at most 30 receipts per share per minute;
  - at most 1000 per share, where **the first 100 are kept for good** and the rest is a rolling
    window.

  Opens that are not stored individually are still counted (`total`), except for such a flood. Receipts last as long as the activity log (same age limits), and clearing an account's
  log clears its receipts and counters. They are deleted with their share's record, 30 days
  after the share ended.
- The sender sees the time of every open in My shares; the other details only as far as the
  admin allows that account (`receiptIp`, `receiptLocation`, `receiptBrowser`, `receiptOs`,
  `receiptLanguages`, all off by default). The admin always sees everything. Anonymous (public)
  shares are recorded for the admin only.
- The share page tells recipients that opening is recorded: before they reveal or unlock a share,
  and on the note or files view itself (a share without a password or view limit opens at once).
  The admin decides what senders may see; receipts are kept as long as the activity log.

### Activity log retention and clearing

- The activity/audit log is kept for at most `log.maxAgeSec` (default 365 days) and
  `log.maxEntries` (default 500 000, oldest deleted first); a role's limits
  (`logMaxAgeSec`, `logMaxEntries`) can keep less about its users. Pruning runs hourly and
  every 500 writes. Neither the global settings nor role limits ever touch:
  - entries about the owner;
  - entries the owner made, meaning admin actions including impersonation.

  Those follow the owner's own limits instead, `log.ownerMaxAgeSec` and
  `log.ownerMaxEntries` (Admin → Roles → Owner, "Your activity log"). Both default to
  **keep forever** (null); when set (at least 1 day and 1 000 entries), older entries and the
  oldest beyond the count are deleted automatically, counting only these entries.
- **Server-wide configuration changes are never pruned automatically**, whatever any limit
  says: entries with no subject (settings, the Default role, roles, IP rules and blocks, exports
  and imports, Turnstile) and the owner's changes to the public account's configuration (its
  limits, quotas, viewer rules and browser ids). So neither a flood of anonymous activity nor a
  short owner limit can push the record of configuration changes out; only clearing by hand
  removes them.
- The owner can **clear** the log — everything, or one account's entries, optionally only those
  older than a date. It needs the owner's password again (like export), and, as configured, it
  **leaves no record**: after a clear, nothing in the system shows that entries existed or were
  removed. The owner's own limits cover every admin action.

### Admin export / import

- An export can hold password **verifiers** (enough to test guesses offline) and the whole
  configuration, so it exists only encrypted: the server builds the plaintext document for the
  signed-in owner, and the browser encrypts it before saving (`public/js/exportcrypt.js`:
  any passphrase the owner chooses, empty included (no length rule: its strength, and so how
  well the verifiers inside resist an offline guess, is the owner's responsibility; with none,
  anyone who gets the file can read it, and the export form says so) → Argon2id m = 64 MiB, t = 3 → AES-256-GCM, with the fixed KDF
  parameters, salt and IV bound into the AAD). A crafted file cannot ask for more KDF work.
- Export and import both require the **owner's password again** (step-up): a stolen session
  cookie alone cannot exfiltrate verifiers or replace credentials. Wrong passwords count like
  wrong current passwords (the account's sessions end at the lockout threshold) and against the
  IP's login guard.
- **Every part is optional and chosen twice**: when exporting (only what is ticked leaves the
  server) and again when importing (only what is ticked is applied).
  - System parts: settings; roles; IP rules; Turnstile keys, off by default because they
    include the secret; the public account.
  - User parts, per user (a table of users × parts, with Select all / Deselect all): credentials;
    role; API keys; passkeys; recovery codes. The owner's row holds only its passkeys and
    recovery codes.
- **API keys** travel as their stored hashes, so the same keys keep working on the target, and
  revoking a key on one server does not revoke it on the other. The import preview says so,
  and refuses a key that already belongs to another account on the target; a passkey (credential
  id) or recovery code that already belongs to an account there is skipped, never moved.
- **Imports never remove or overwrite an existing account's credentials** (a maintainer rule).
  An account that already exists, the owner included, only gets its role set (if chosen; never
  the owner's, which is always Owner) and the file's passkeys added (if chosen, within the role's
  passkey limit). Its password verifier, disabled flag, recovery codes, API keys, existing
  passkeys, "Password and passkey" choice and sessions are left untouched, so a crafted or stale
  file cannot lock anyone out or replace a credential; the worst it can do to an existing
  account is add a passkey, which the owner sees in the preview (by name) and which is logged.
  New accounts are created from the chosen parts.
- Never exported: the owner's password, role and API keys, sessions, shares, usage counters and
  the activity log. An import can never create or replace an owner; the accounts it creates are
  plain users.
- **Treat an export as a credential store.** One that holds verifiers, API key hashes and the
  Turnstile secret is as sensitive as the database. Keep the file and its passphrase apart,
  export only the parts you need, and delete files you no longer need (recommendation).
- Imports are re-validated field by field on the server with the same checkers as the admin API
  (`src/lib/portable.js`: exact key sets, types and ranges, credential format, `t = 3`), are
  previewed as a dry run, and are applied in one storage transaction or not at all. Replacing
  an account's credentials ends its sessions and revokes its API keys (its shares stay). IP
  rules are only ever added, never removed, and an import that would block the importing
  owner's own address is refused. The preview calls out changes to `guard.*` / `lockout.*`
  settings and added allow rules.
- Exports and imports are audited as fully as the equivalent manual changes: `export.created`
  and `export.users` (which accounts, with or without verifiers), `import.system`,
  `settings.updated`, `limits.updated`, `quotas.updated`, `viewer_rules.updated`,
  `iprule.added` (with the values) and `user.imported`.
- The passphrase is the only protection of the file: keep file and passphrase apart.

### Public (anonymous) access

> [!NOTE]
> Anonymous sharing lets anyone publish content from your domain, and the tracker below stores
> an identifier on the visitor's device for rate limiting (see the notice setting on the Public
> role).

- **Off by default** (`public.enabled`). When off, every `/api/public/*` route except the
  profile answers `403 public_disabled` and the landing page shows no composer.
- **The public account** (`public-user-0000`, shown as `(public)`) is built in and created once.
  It has no password and can never sign in (its name is outside the username alphabet, and
  prelogin/login treat it as unknown); it cannot be deleted, renamed, disabled, impersonated,
  given a password, exported or given API keys, and it has no dashboard or My shares. Its
  limits and quotas are edited like any account's; the admin sees its shares in Admin → Shares.
- **Conservative seeded limits:** notes only (files, links, credentials and "delete now" off),
  at most 10 views, no unlimited views, at most 7 days, 10 shares per day per subject. The
  file policy and every server-side check of the account handlers apply unchanged.
- **Counting subjects** (`public.tracking`):
  - `tracker` (default) — a random 128-bit id issued by the server;
  - `ip` — the network (an IPv6 /64 by default, per `guard.v6Prefix`), nothing stored in the
    browser;
  - `both-restrictive` — both are counted, and a creation is refused when **either** is over a
    quota;
  - `both-permissive` — both are counted, and a creation is refused only when **both** are over.
  Subjects are stored only as HMAC-SHA-256 values keyed with a per-deployment secret held in the
  Directory; the raw id and the address are never stored. An import that changes any `public.*`
  setting is called out in the import preview.
- **The tracker** is a random id the server issues and authenticates with an HMAC tag
  (12 random bytes ‖ issue time ‖ 8-byte tag, keyed with the per-deployment secret). It is
  **stateless until it first creates a share**: page visits store nothing on the server. The
  browser keeps it in four places: the `__Host-secbin_aid` cookie (HttpOnly, Secure,
  SameSite=Strict, 400 days), the ETag of `GET /api/public/t` (`Cache-Control: private,
  no-cache`, so the browser revalidates with `If-None-Match`), `localStorage` and IndexedDB.
  - On every visit all copies are sent (at most one per store). The id presented most often
    wins and every missing, malformed, forged or expired copy is re-seeded from it
    (self-healing). Only ids this server issued count, so random values cannot outvote or block
    anyone, and the HttpOnly cookie keeps a victim's id away from other sites.
  - A tie is broken in favour of the only tied id that has created shares, or else the oldest
    (two tabs racing on a first visit are not an attack). If two or more tied ids have **each**
    created shares, the right one cannot be determined: every one of them is blocked
    (`403 tracker_conflict`, counted as an invalid request for the IP) until the admin
    unblocks it.
  - A creation must carry the id in both the cookie and the `X-Secbin-Aid` header, and they
    must match; a cross-site form can do neither (plus the usual `Sec-Fetch-Site` check).
  - An id is stored on its first creation, at most `public.newTrackersPerIp` (default 5) new ids
    per network per `public.newTrackersWindowSec` (default a day; `429 tracker_rate_limited`)
    and at most 200 000 in all (`429 busy`). Clearing browser storage therefore yields a new id
    and a fresh per-id quota, but only that many times per network per window: tracker mode
    allows up to *new ids × quota* shares per network per window. Use a `both-*` mode to cap the
    network as a whole.
  - Ids idle for `public.trackerIdleSec` (default 90 days) are purged together with their usage
    counters; network counters (`pub:ip:*`) age out with the other usage rows (400 days).
  - Anonymous shares carry no label (anything sent is dropped), and the per-id "shares" count
    in the admin view counts successful creations only.
- **Limits of the design:** these are rate limits, not identity. A determined sender with many
  networks (or many IPv6 /64s) can create more; `ip` mode counts everyone behind one NAT
  together. Pair it with Cloudflare WAF / rate-limiting rules (a Turnstile challenge is planned).
- **Notice:** the composer shows an admin-editable notice (`public.notice`,
  `public.noticeText`, on by default) explaining the identifier; the wording is yours to approve.
- **Administration:** the Public role (Admin → Roles) lists trackers (hash prefix, created, last seen,
  uses, blocked reason) and can unblock, block or forget one (forgetting also clears its
  counters). Conflicts and admin actions are audited.
- File uploads by the public account (when the admin enables files) use the same upload-token
  capability as account uploads; the quota is charged when the upload starts.

### Drive (server)

Design and interface: [`docs/DRIVE.md`](./docs/DRIVE.md); the keys and wraps are described
under "Drive keys" above.

- **What the server sees.** One Durable Object per user holds the tree: node ids (chosen by the
  browser, 128 random bits), parent links, file or folder, each file's exact plaintext size,
  chunk count and ciphertext hash, timestamps, and which shares reference which items. Names,
  file metadata and each file's DEK arrive sealed under the user's KEK; the Worker checks each
  opens (and keeps nothing it opened). Unlike file shares, **Drive files are not padded**: the
  server learns each file's exact size.
- **The keyring** (the root MEK, the sub-MEKs sealed under it, the user salts) is in the Directory
  Durable Object, managed by the owner only (not while acting as a user), every change and view
  with the step-up, in the admin audit by fingerprint. The Worker derives the KEKs and the field
  keys there and uses them in memory only. A user's own KEKs go to the user's session; the
  owner acting as the user gets the user's (`drive.keys_used`). Key material cannot be had with
  an API key (the whole Drive refuses them).
- **Activity.** Drive actions (folders created, uploads, file reads, renames and moves,
  deletions, Drive shares, the personal kit) are in the user's own activity like any other
  action; node ids only, never names. A user's own file reads are throttled in the log (one row per file per
  minute, at most 30 a minute) so they cannot flood it; rows of the owner acting as the user are
  never dropped.
- **Access control.** Every route is session-only and scoped to the caller's own Drive object
  (`idFromName('drive:' + userId)`; the object also refuses calls naming another user), so an id
  from another user's Drive simply does not exist there (IDOR). The role must allow the Drive
  (`driveEnabled`); the public account never has one.
- **Uploads and limits.** Capacity (`driveMaxBytes`, at most 100 GiB) and the largest file
  (`driveMaxFileBytes`) are checked atomically in the Drive object when an upload starts, pending
  uploads included; the sealed names (at most 512 characters), metadata (at most 1024), DEKs and
  salts of every item count towards the capacity too, so they cannot hold data outside it; chunk
  sizes are checked exactly; finalize is refused (`409 busy`) while a chunk of the file is still
  being written, so a late retry never lands on (or removes a chunk of) a finished file; upload tokens are 256-bit and stored as
  hashes; unfinished uploads are purged after the role's `filePendingSec` without progress. The
  state-changing routes use the same CSRF guards as the rest of the API (JSON body or intent
  header, `Sec-Fetch-Site`, the upload token header), and the session's CSRF token, all checked
  in `authenticate()` before any Drive route runs (chunk uploads pass the shape check as
  `application/octet-stream`; the session's keys, `POST /api/private/drive/keys`, which may make
  the account's salt and writes to the admin audit for the owner acting as the user, are a `POST`
  too). R2 keys are built from the server's user id
  and validated node ids only.
- **Deletion.** Only the Drive object deletes Drive ciphertext in R2 (`d/<userId>/<nodeId>/<i>`):
  a recursive delete removes the objects first, then the rows, and ends every share that
  referenced the items (recipients get "gone"). Deleting an account ends its Drive's shares and
  deletes its Drive first (each step retried); only then is the account deleted, so a failure
  leaves the account in place and deleting it again retries. A share that ends in any way also
  leaves the Drive's record of which shares reference which items.
- **Drive shares** reference the Drive's ciphertext (no copy): a FileShare record with `refs`,
  authorized like a file share (limits, file-policy declarations, quotas), whose expiry,
  revocation or deletion never touches the Drive's objects. Recipients get the share's own link
  key; each file's DEK travels inside the share's encrypted manifest, so the share stays
  end-to-end.
- **Export.** The account export carries the Drive role options (with the roles), never Drive
  content or keys. The Drive keys have a file of their own (Import / export → Drive keys), the
  parts the owner picks, sealed in the browser; the key kit is another file.
- **Archives** the owner's Drive kept after starting over in the release before stay in the
  owner's Drive object as they were (sealed under that release's key), counted in the capacity;
  no route opens or restores them any more.

### Reverse shares ("Receive files")

Design and interface: [`docs/REVERSE.md`](./docs/REVERSE.md).

- **Keys.** Each reverse share has its own ECDH P-256 key pair, made in the user's browser. The
  raw public key is the link's `#fragment` (never sent to the server). The private key is stored
  sealed under `HKDF(KEK, "reverse-link")` (bound to the user, the sub-MEK and the share id) and,
  at rest, under the user's field key: like every Drive key it opens with keys the server holds,
  so the server (and the owner) can open it; it is checked to open under the user's current KEK
  when the link is created. The uploads themselves stay end-to-end until they are taken in: the
  server does not keep the link's private key in the clear, and a leak of the Drive object alone
  opens nothing.
- **The owner acting as the user** can do everything the user can, reverse shares included (the
  maintainer's rule), and the owner acting as the user, or anyone holding that impersonation
  session, can create through the API a link in the user's name whose private key they also keep:
  files sent to it are readable by whoever holds that key. The admin audit records the creation
  with the real actor.
- **Link ids.** The browser chooses a link's id; the server claims it in the share index first,
  in one step with the role's checks and the count of active links (so `reverseMaxActive` holds
  under concurrent creates), and refuses an id any account already holds (`409`). An index row
  never moves to another account and its link hash is never replaced (for every share kind). An
  id that was ever a reverse share is never claimed again, even after its index row is pruned
  (30 days after it ended) or its account is deleted: the Directory keeps a SHA-256 of every
  created reverse-share id for good (`reverse_ids`; a hash only, not the id, the account or the
  link), so an old link never opens a later share or shows a later note. A claim that never
  became a link (its confirmation refused) leaves no tombstone.
- **Creating a link** adds key material to the Drive (a key pair that can place files in it), so
  the user confirms it with the account password or a passkey, as for API keys: a stolen session
  alone cannot create one. Failed confirmations count like every other failed confirmation. The
  owner acting as the user confirms nothing, as for every other change to the account; the
  user's activity shows the action as the user's, and the owner-only admin audit records the
  owner as the real actor.
- **What an uploader's browser sends.** Each file is encrypted with a random file key exactly
  like a Drive file (8 MiB chunks, AES-256-GCM, no padding); its relative path and `{ type,
  mtime, size }` are sealed with a random metadata key; both keys are wrapped to the link's public
  key (an ephemeral ECDH key, HKDF, AES-GCM), bound to the share id and the node id. The server
  stores these values and cannot open them. It sees each file's exact size and chunk count, the
  uploader's network address (as for every request) and the number of files per session; not the
  names, the folder structure of an upload or the types. Files are not padded.
- **CSRF.** The user's routes (create, take in, mark failed, retry; extend, revoke and lock
  through the shares routes) are cookie-authenticated and need the session's CSRF token and the
  request shape check, before the step-up and before the id is claimed. The uploader's routes
  under `/api/reverse/<id>/` are anonymous and exempt (they read no session); the link proof, the
  session grant, the upload token, Turnstile, the password lockout and the Guard guard them (see
  "CSRF" above).
- **Declared file types.** When the user limits a link to some file types, the uploader's
  browser declares each file's `{ extension, MIME type }`; the server checks it against the
  link's rules and does not store it (as for file shares: a modified client could lie).
- **Taking files in.** The user's browser opens each received file with the link's private key
  and seals its name, metadata and file key (its DEK) under the user's current KEK, like a new
  Drive file (checked by the Worker); the content chunks are not re-encrypted. From then on it is
  a Drive file (not end-to-end). Until then a received file is counted in the Drive's capacity (its content and
  its sealed path, metadata and wrap, which are capped at 1400, 1024 and a fixed size) but is not
  part of the tree (not listed, readable, movable or shareable). A file that cannot be taken in
  (it does not open, its name cannot be used, the Drive refuses its place) is recorded as failed
  on the server and leaves the queue, so it never holds up later files; the Drive lists it by
  link, size and time, to delete or try again. Received names are cleaned (bidi overrides and
  isolates, U+200B, U+FEFF and the line separators removed, then NFC; real names in any script
  stay), and a renamed file is marked so; a path creates at most 8 folder levels below the link's
  folder and one take-in at most 200 new folders (deeper or further files go into the deepest
  folder allowed), so an uploader cannot make the user's browser build a folder flood.
- **The link proof and the password gate.** The server stores the SHA-256 of a link proof
  derived from the public key: an id alone (it appears in request paths) opens nothing and does
  not reveal the note or whether a password is set. Its status codes do tell a reverse-share id
  from an unknown one (`404` for an unknown id; `400`, `403`, `423` or `410` for a reverse
  share); ids are 128-bit random and each `404` counts in the Guard. The optional password only gates the uploader: its proof
  is Argon2id (64 MiB, t = 3) → HKDF with the link's public key as salt, and the server stores the
  SHA-256 of the proof, the salt and the cost. Because the public key is only in the link, the
  server's data alone cannot be used to test password guesses offline. The password does not
  protect the files: they are always encrypted to the link's key, and the user never needs it.
- **Guessing and abuse.** Unknown ids, wrong link proofs, wrong passwords, bad session grants and
  bad upload tokens count in the Guard's `invalid` scope and block the network like invalid share
  fetches; a late visitor to an ended link with the right link proof is not counted. Cross-site
  requests are refused before any accounting. Wrong passwords are logged for the user
  (`reverse.bad_password`, at most one entry per link per minute). When Turnstile is configured,
  starting an upload session needs a token for the `reverse-upload` action, checked before the
  password, so no password guess is answered without one (the uploader page shows the widget and
  keeps Send disabled until it passes; it gets the Turnstile CSP, and the strict one otherwise).
  Besides the per-network Guard, each link has its own lockout: 10 wrong passwords within 15
  minutes, from any networks, lock its password for 15 minutes (the right one too). The lockout
  is per link on purpose, so that guesses spread over many networks are stopped too; the
  consequence is that one network holding the link can keep its password locked for everyone:
  10 wrong guesses every 15 minutes are well under the Guard's per-network limit (60 invalid
  requests per 10 minutes), so that network is not blocked, and with Turnstile on each guess costs
  one solved challenge. An upload session's deadline slides: while it has a file reserved and
  not finished it stays open for the role's `filePendingSec` after its last progress; as soon as
  nothing is unfinished (the file finished or was cancelled) it is idle again and lapses 10
  minutes later, and it never lasts more than 24 hours after it began. A network may hold at most
  5 open sessions per link (counted by 24 bits of a hash of the link id and the network; no key,
  and the address itself is not stored), besides 100 per link, so idle sessions give their slots
  back and cannot easily lock a link for everyone else.
- **Limits.** Per link: expiry (at most the role's `maxExpireSec`), files, total bytes, largest
  file, file types; per role: `reverseEnabled` (with `driveEnabled`), `reverseMaxActive`,
  `reverseMaxBytes`; always the Drive's capacity and largest file. The role's current
  `reverseMaxBytes` applies to existing links too: a link is held to the smaller of its own
  byte limit and the role's (lowering the role's cap takes effect at once; raising it does not
  raise a link's own). A file's sealed path, metadata and wrap count towards the link's bytes, so
  empty files are not free. Every limit is checked
  atomically in the user's Drive object when a file is reserved; chunk sizes are checked exactly.
  Only the session that reserved a file may finalize or cancel it, and a reservation must finish
  within 24 hours however often its chunks are re-sent (a session, too, ends 24 hours after it
  began).
  Upload-session grants and upload tokens are 256-bit and stored as SHA-256 hashes; unfinished
  uploads are purged after the role's `filePendingSec` without progress and give their
  reservation back. A chunk whose write to R2 is still in flight blocks that file's finalize
  (`409 busy`), so a late chunk write never lands on, or is deleted from, a finished file; a
  write that finishes after its upload ended (cancelled, revoked, purged) is deleted. An uploader can fill the user's Drive up to the link's limits: the user
  chooses those limits, and revokes the link at any time.
- **Ending.** Revoking a link, its expiry, an admin lock (paused), the role losing the option, or
  deleting its folder stops uploads at once; unfinished uploads are deleted; files already
  received stay. Deleting the account deletes everything.
- **Links of the release before.** A link whose key the old Drive key sealed is re-sealed under
  the user's KEK by the Drive's upgrade (docs/DRIVE.md §3.3); until then the Drive shows no link
  for it and its received files wait. Links an owner's start over paused in the release before
  stay paused (`409 paused`).
- **Audit.** `share.created` (`kind=reverse`) and `share.revoked`, `reverse.received` (count and
  bytes only; one entry per link per hour adding up that hour's sessions, so uploads cannot flood
  the user's log or the server-wide log limit), `reverse.bad_password`, and
  the Drive actions on received files: `drive.received_taken_in` (taken into the Drive),
  `drive.received_failed` (could not be taken in) and `drive.received_retried` (put back to try
  again), each one entry per link, per actor, per hour adding up the files, for the same reason.
  Creating, revoking, taking in, marking failed and retrying while the owner acts as the user are
  logged as the Drive actions are: as the user's own in their activity, with the owner as the
  real actor in the owner-only admin audit (`imp`, not `adm`).
- **What uploaders can see of each other.** `open` returns a limited link's `filesLeft` and
  `bytesLeft` to anyone with the link, before any session or human check. Every uploader of a
  link with a file or byte limit can therefore poll it and see when other uploads are reserved,
  and how large they are: a file's exact size plus the length of its sealed path, metadata and
  wrap (which grows with the length of its path). Names, types and content are not revealed. A
  link without limits returns `null` for both.
- **The uploader page** (`/r/<id>`) is built with DOM calls only (no `innerHTML`), shows the
  user's note as text, and is never cached by the service worker.

### API surface hardening

- No CORS headers; JSON bodies are read under a streaming byte cap (4 MiB; 8 MiB + 16 B for
  file chunks, with the exact expected size enforced).
- Every value is re-validated server-side (formats, views, expiry, limits, quotas, settings).
- Reads that spend views need custom headers (non-simple): ambient GETs never consume anything.
- Download grants are stored apart from the share record.
  - One client (an IP, or an IPv6 /64) holds at most 20 live grants per file share; opening
    again replaces its oldest.
  - At most 2000 grants may be live per share; beyond that, opens get `429 busy` with
    `Retry-After`.
  - So repeated opens cannot break a share. Keeping one busy takes at least 100 distinct
    networks, a residual risk for unlimited-view shares shared very widely.
- A missing or invalid binding (KV, R2, a Durable Object namespace) answers a generic
  `503 not_configured`. The binding's name goes to the Worker logs, not to the caller.
  - Uploads, revokes and deletes of file shares check the R2 binding first.
  - A purge never forgets a share whose chunks it could not delete; the alarm retries.
- Missing or garbage environment variables never throw; the feature that needs them reports
  that it is unavailable.

### Edge caching (Workers Caching)

`wrangler.toml` turns on Workers Caching (`[cache] enabled = true`), so Cloudflare consults a
shared cache before invoking the fetch handler. That cache follows RFC 9111: a response
without `Cache-Control` is stored heuristically (a `200` for two hours, a `404` for three
minutes), and the only automatic bypasses are an `Authorization` request header and a
`Set-Cookie` response header. A GET authenticated by the session cookie is **not** bypassed,
so a per-user page or JSON answer without an explicit policy could be served to the next
visitor of the same URL.

The rule: **nothing the Worker returns is stored in the edge cache.**

- The top-level fetch handler (`src/index.js`) passes every response through
  `withCachePolicy` (`src/lib/http.js`): route results, `HttpError`s, the `503` for a missing
  binding, the `500` for an unexpected exception, and a route that returned nothing.
- `withCachePolicy` sets `Cloudflare-CDN-Cache-Control: no-store` on every response.
  Cloudflare's cache reads it before `Cache-Control` and strips it before the browser.
- It sets `Cache-Control: no-store` on any response without a Cache-Control of its own
  (the no-store fallback), so neither the browser nor any other cache keeps it either.
- The routes already mark what they return: every JSON answer (`json` / `err`), redirect,
  dashboard page and chunk download is `no-store`. That covers `/api/private/*`, `/api/auth/*`,
  `/dashboard*`, share heads and opens (notes, burn notes, files), download grants and
  ciphertext chunks, delete-by-token, `/api/config`, and every 404, 405 and error.
- Two responses keep a browser policy of their own and still stay out of the edge cache:
  - the anonymous home page (`/`, `/index.html` without a valid session) keeps the asset
    server's `public, max-age=0, must-revalidate`, so the service worker can keep it as the
    offline shell. A cached copy would skip the signed-in redirect and the owner's Turnstile
    headers;
  - the tracker (`GET /api/public/t`) keeps `private, no-cache`, so the browser holds the ETag
    copy. It also sets a cookie, and `private` alone already keeps it out of shared caches.
- No response is marked cacheable at the edge. `/api/config` is identical for everyone, but it
  honours the manual IP block rules and must follow the owner's changes (the viewer policy,
  Turnstile) at once. It is cached per isolate for 30 seconds instead, and that cache is
  dropped on every admin change.
- There is no per-entrypoint override (`[exports.<name>.cache]`): the default export is the
  only fetch entrypoint, and Durable Object calls are never cached.
- `test/cache-policy.test.js` walks the routes (anonymous and signed in, success and error,
  404, 405, a thrown exception, a missing binding) and checks that every response has a
  Cache-Control, carries the edge `no-store`, and is `no-store` unless it is one of the two
  exceptions. `test-node/headers.test.js` checks the two config files and that the long-lived
  rules in `public/_headers` cover only paths the Worker never runs for.

## 7. Cryptographic summary

Per-share random CEK; AES-256-GCM with fresh IVs; Argon2id (m=64 MiB, p=1, t∈[1,10]) for
passwords; HKDF-SHA256 for the KEK and the two access proofs; per-share FK for file chunks with
index-bound AAD; canonical AAD; strict canonical base64url. Details and test vectors: `SPEC.md`.
The Drive: a random DEK per file (the same chunk format); the DEK, name and metadata sealed with
AES-256-GCM under HKDF of the user's KEK and a 32-byte per-item salt; the KEK is HKDF-SHA256 of
the root MEK and a sub-MEK with the user salt, all held by the server (docs/DRIVE.md §3; fixed
vectors in `test-node/drivekeys.test.js`).

## 8. Reporting a vulnerability

Please report privately via
[GitHub private vulnerability reporting](https://github.com/kaerez/bin/security/advisories/new).
Do not open public issues with exploit details. Include affected version/commit, reproduction
steps and impact.

## 9. Supported versions

Only the latest `main` of secbin receives security fixes. Protocol v1 links are no longer
supported.
