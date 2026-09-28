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
  modified client. The owner is never subject to it. The same policy covers the account's
  **Drive**: each upload's reservation (`POST /api/private/drive/files`) declares that file's one
  `{extension, MIME type}` (an empty or longer list is refused, so nothing passes an allow list
  by declaring nothing), checked in `src/lib/drivepolicy.js` and never stored. Unlike a file
  share, the Drive's rule does not rest on the declaration alone: the Worker already opens a new
  Drive file's sealed name and metadata to check its seal (`checkNewItem`), so it enforces the
  rule on what is stored — the name's extension and the metadata's MIME type, with the same rule
  function (`sealedTypeRefusal`) — and refuses a declaration that does not match them
  (`403 file_type_not_allowed`), as well as metadata whose type cannot be checked. A modified
  client that declares a false type is refused. The opened name and type stay in the Worker's
  memory for that check only: they are zeroed after it, and never logged, stored or returned
  (the refusal names neither). The folder-depth
  limit needs no declaration there — the Drive object checks it against its own tree on an
  upload, a new folder, a move (a folder with the folders inside it) and a take-in. A take-in
  from a Receive link is held to the role's Drive rules as well as the link's own, so a link
  cannot bring into the Drive a type or depth the role refuses there. Files already in a Drive
  are never deleted by a new or tighter rule.
- Access-proof *hashes*, delete/upload/grant/API-key *hashes*, and password verifiers
  (`SHA-256("secbin-auth/v2" ‖ Argon2id(password))`).

- **The Drive** (see "Drive keys" and "Drive (server)" below): the shape of each user's folder
  tree (node ids, parents, file or folder), each file's exact size, chunk count and ciphertext
  hash, times, and which shares reference which items. Names, types, contents and file keys are
  sealed, but **the server holds the keys that open them** (the root MEK, the sub-MEKs and the
  user salts in the Directory): Drive files are not end-to-end encrypted.
- **Reverse shares** (see "Reverse shares" below): which folder a link targets, its limits,
  label, times and counters, whether it has a password, and each received file's exact size,
  chunk count and time. The link's private key is stored sealed under the user's KEK, which the
  server derives (like every Drive key: "Drive keys"), so the server can open the files'
  names, types, folders and contents, before and after they are taken in; a copy of R2 or of the
  Drive object alone cannot. The note to the uploader and the password are never seen.

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
  - **Every response the Worker returns** — API answers, chunk downloads, errors, redirects and
    pages — carries COOP `same-origin` (a page's own COOP is kept: the check page's is
    `same-origin-allow-popups`), CORP `same-origin`, `X-Frame-Options: DENY`, `nosniff`,
    `no-referrer`, the two-year HSTS and the Permissions-Policy below (`withBaselineHeaders`,
    `src/lib/http.js`). Anything that is not HTML gets
    `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; sandbox`: opened as a
    document it has an opaque origin and runs nothing, and a window opened to it (by a script on
    a share's CAPTCHA page, say) lands in its own browsing context group. HTML pages keep their
    own policy. `test/captcha.test.js` walks representative responses.
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
  when a received one is shown or saved, in the browser and by `secbin get` (marked "renamed");
  names are never refused for them. A received path is cleaned first and then checked again
  (`files.js` `cleanPath` / `cleanEntries`): a path that is safe only before cleaning (`.`,
  U+200B, `.` becomes `..`; a leading U+200B segment becomes an absolute path), or two names
  that clean to the same path, refuse the whole manifest.
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
  names; ZIP member names come from cleaned and validated paths, and the ZIP writer
  (`zip.js` `memberName`) cleans and checks every name again right before writing it: no
  absolute, `../`, drive-letter (`C:`), backslash, empty-segment or duplicate entries (file
  shares, Drive shares and Drive folders alike).

### Cloudflare Turnstile (optional human check)

Off unless a site key and a secret key are both configured. They are set either as the
deployment's `TURNSTILE_SITEKEY` and `TURNSTILE_SECRET`, or by the owner in Admin → Security
("CAPTCHA"). The deployment's keys always win.

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
| Download the Drive personal kit | `POST /api/private/drive/kit` | `account` |
| Verify a Drive personal kit | `POST /api/private/drive/kit/verify` | `account` |

Asking for a challenge changes nothing and needs no token: the passkey registration options
(`POST /api/private/me/passkeys/options`) and the passkey "confirm it's you" challenge
(`POST /api/private/me/reauth`). The step each of them leads to is protected, and a challenge is
not used up by a request that the human check refuses, so the check cannot be skipped by
calling the steps in another order. Setup, admin password resets, the owner's changes in the
admin panel (to other accounts or their own), file chunks and API keys are never challenged;
API keys cannot reach the account routes at all (`403 api_key_not_allowed`). Recipients opening
a link, and uploaders using a reverse-share link, are challenged only when that share has the
CAPTCHA (its sender's role and choice: *CAPTCHA on shares*, below).

- **Client side** (`public/js/turnstile.js`). The protected buttons (log in, sign in with a
  passkey, create an anonymous share, and every button in the table above) stay disabled until
  the widget has issued a token, and again after each token is used (one token per call) until
  the next one arrives; if the widget cannot load they stay disabled and the page says why. On
  the Account page each card that changes something (username, password, passkeys and recovery
  codes, API keys) or hands out keys (the Drive personal kit: Download and Verify) has its own
  always-visible widget; one widget serves every button of its card,
  including the Remove and Revoke buttons of each table row. This is a usability guard: the
  server-side check below is what enforces it.
- **Server-side verification** (`src/lib/turnstile.js`). Each protected call must carry
  `X-Secbin-Turnstile`, which is redeemed with Cloudflare's siteverify. The call passes only
  when the token:
  - succeeded;
  - was issued for the request's own hostname;
  - was issued for that form's action (`login`, `password`, `account`, `public-share`,
    `share-open`, `reverse-upload`), so a token from one form cannot be replayed on another;
  - has not been used before (siteverify refuses a reused token).

  The token is checked before the password (at login, and before the "confirm it's you" step of
  an account change), so a bot learns nothing about the password and every guess costs a token.
  If siteverify cannot be reached the request is refused (`503`, fail closed). Cloudflare's
  published testing keys return no hostname or action, so their results are accepted as they
  come; never deploy with testing keys.
- **Metering of these calls.** Every token siteverify **rejects** from these forms (sign-in,
  account changes, anonymous creation) counts towards the network's `turnstile-verify` scope.
  Once a network (the Guard's key) has had 60 tokens rejected within 10 minutes, its tokens get
  `429 rate_limited` with `Retry-After` for 10 minutes, before any call to Cloudflare. Accepted
  tokens are never counted: each one cost a solved CAPTCHA, so many sign-ins behind one busy
  address never use up the scope; only rejected tokens can. A request without a token, with an
  over-long one, or from another site (`Sec-Fetch-Site: cross-site` / `same-site`) is refused
  before anything is counted or sent. The share and reverse-share CAPTCHA routes count theirs under
  `captcha-verify` instead (below), never twice. The owner sees and lifts `turnstile-verify`
  blocks with the others.
- **The only third-party code, confined to those pages.** Login, Account, the home page
  (only while anonymous sharing is on) and the CAPTCHA page of a share that has one
  (`/p/<id>?check`, `/r/<id>?check`, only while Turnstile is on) get a CSP that adds
  `https://challenges.cloudflare.com` to `script-src` and `frame-src` and drops
  `Cross-Origin-Embedder-Policy` (the widget's cross-origin iframe cannot load in a
  cross-origin-isolated page). Every other page keeps the strict policy above. That includes
  every recipient's page `/p/<id>` and every uploader's page `/r/<id>`: the pages where a link's
  key is in the address bar never load the widget.
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
  - on a share's CAPTCHA page, the share's id, the link key sealed under a random key held in
    an HttpOnly cookie that page cannot read (*CAPTCHA on shares*), and the grant the page itself
    obtains: never the link key, the tab's Drive keys (they are removed before the page is
    reached), the content or the files being sent. That page is on the app's origin, so while it
    runs such a script could also call the APIs of a signed-in user of that tab with the session
    cookie, as on Account (*CAPTCHA on shares*, "Same origin").

  Recipients' pages (`/p/<id>`), uploaders' pages (`/r/<id>`) and signed-in composers never load
  it. secbin already runs on
  Cloudflare, so this adds no new trusted party, but it is a second code origin. Leave Turnstile
  off if that is unacceptable.
- **Privacy.** Turnstile runs Cloudflare's client-side challenge and sends browser signals to
  Cloudflare. For GDPR, treat Cloudflare as a processor for this purpose and describe it in
  your privacy notice.

### CAPTCHA on shares

A share can require its recipients (and a reverse-share link its uploaders) to pass a CAPTCHA —
the Turnstile check above — before anything of it is served. It is a role option, not a setting:

- **Role options** (Admin → Roles; `src/lib/settings.js`): `shareCaptcha` for notes, file shares
  and Drive shares, `reverseCaptcha` for reverse shares, each `allow` (the user ticks "Require
  CAPTCHA to open" / "Require CAPTCHA to send files" per share, pre-set from
  `shareCaptchaDefault` / `reverseCaptchaDefault`, `on` or `off`), `require` (every new share has
  it) or `off` (none). The Owner role is locked at `allow` (the box starts off for shares and on
  for reverse shares); the Default role holds `allow` / `off` for shares and `require` for
  reverse shares, because every reverse link had the check before these options existed; custom
  roles inherit; the public account has none (`off`, not settable).
- **The server decides.** Every create path (the composer and the API: `captcha: true|false`
  on `POST /api/private/paste`, `/api/private/file`, `/api/private/drive/shares`,
  `/api/private/drive/reverse`; the CLI's `--captcha` / `--no-captcha`) resolves the flag from
  the creator's role: `require` is on whatever is asked; `off` refuses `captcha: true` (`403
  captcha_disabled`), so a sender is never led to believe a share is protected when it is not;
  anything but a boolean is `400 invalid_captcha`. The flag is stored in the share's own record
  (the KV note, the BurnPaste or FileShare object, the reverse link's Drive row) and in the share
  index (My shares and Admin → Shares show it; `share.created` logs it). It is fixed when the
  share is created: changing the role later does not change existing shares.
- **Inactive without Turnstile.** When the server has no Turnstile keys, a flagged share is
  served without a check (never locked for good); the role editor, the composer and the Drive's
  dialogs say that the CAPTCHA is not active until Turnstile is configured. It is enforced as
  soon as keys are set.
- **Recipients** (`src/routes/public.js`): the head, open, "delete now" and every chunk of a
  protected share answer `403 captcha_required` ("This share requires a CAPTCHA; open it in a
  browser") without a grant, before anything else is said about the share (its format, views,
  lock, whether it may be deleted); no view is spent, and the refusal is not counted as an
  invalid fetch (the Guard's blocks and rate limits still apply). A grant comes from
  `POST /api/(paste|file)/<id>/human` with a Turnstile token for the action `share-open`; that
  call looks nothing up and spends nothing. Views are spent only by the open that follows.
  API and CLI recipients cannot pass it.
- **Nothing about an id before the check.** While Turnstile is on, a request without a grant
  gets exactly the same `403 captcha_required` for a well-formed id whose share does not exist
  or has ended (expired, used up, revoked, deleted) as for a protected share, on every route
  above and for every kind (KV notes, burn notes, file shares, Drive shares). The Guard still
  counts it as before (an id that was never a share, or a wrong link for an ended one, is an
  invalid request). With a grant the true answer follows (`404` / `410`). A live share without
  the CAPTCHA answers as it always did: it is open by design. Reverse links are the exception:
  their `open` (with the link proof) tells a link's state and its note before any check, by
  design (docs/REVERSE.md §6.2), so their routes answer `404` for an unknown id as before.
- **Metering.** The grant routes (`…/(paste|file)/<id>/human`, `/api/reverse/<id>/human`) and a
  reverse session start with a Turnstile token call Cloudflare's siteverify. At most 30 such
  checks per network (the Guard's key) per 10 minutes reach it; beyond that `429 rate_limited`
  for 10 minutes, before any call to Cloudflare. A missing or failed token counts as an invalid
  request, like a wrong link. Renewing a grant (an HMAC check) is not limited. The check page
  is behind the Guard's block and at most 60 loads per network per 10 minutes (`429`), and looks
  nothing up. Only this site's own document navigations to it are served and counted
  (`Sec-Fetch-Dest: document` with `Sec-Fetch-Site: same-origin` or `none`: the viewer's own
  redirect, or a typed or bookmarked address). Any other request (another site's `<img>`,
  `<iframe>` or link, or one without Fetch Metadata) is redirected back to the share's page
  before the Guard is asked, so another site cannot use up a network's check pages. The owner
  sees and lifts these blocks with the others (scopes `captcha-verify`, `captcha-page`).
- **Grants** (`src/lib/human.js`): `h1.<claims>.<HMAC-SHA-256>` under a key derived from `SIG`;
  claims: the kind (share or reverse), the share id, a keyed hash of the caller's network (the
  Guard's key: an IPv4 address or an IPv6 prefix), when the check passed and when the grant
  lapses. A share grant lasts 10 minutes and slides while it is used (each call that passes
  renews it in `X-Secbin-Human`; the recipient's page renews it every 4 minutes while it is open),
  never more than 12 hours after the check. It opens only its share, from its network.
  Stateless: it cannot be revoked before it lapses, but it gives nothing without the link's key.
  - **The network binding is coarse, both ways.** Everyone behind one IPv4 address (a NAT, a
    corporate proxy) or in one IPv6 prefix (`guard.v6Prefix`, a /64 by default) counts as one
    network, so a grant copied to another device there works until it lapses. A client whose
    address changes (a mobile network, a VPN) needs the check again.
  - A share grant can be used any number of times while it lasts. A reverse grant starts one
    session (below).
- **Reverse shares:** when the link has the flag, starting an upload session (`…/begin`) needs a
  grant from `POST /api/reverse/<id>/human` (a token for `reverse-upload`) or, as before, a
  Turnstile token itself, checked before the password. A reverse grant has a random id that the
  session start spends in the user's Drive whatever the answer (a wrong password included), so
  each session start — each password guess — costs one CAPTCHA, as each needed one token
  before. Links without the flag have no check. `open` is not behind the CAPTCHA: a caller with
  the link proof gets the sealed note, the password's salt and cost, the lock state and the
  limits first, because the page needs them to show the link (the password proof itself is
  never returned, so the salt gives no offline test).
- **The key never meets the third-party script.** The link's key is in the address bar
  (`#fragment`), and Turnstile's script would run in the page that loads it. So:
  - `/p/<id>` and `/r/<id>` always get the strict CSP, where no third-party script can load,
    with `Cross-Origin-Opener-Policy: same-origin`, COEP `require-corp` and `frame-ancestors
    'none'` (with `X-Frame-Options: DENY`): no other page can frame them or keep a handle to them.
  - **A random, cookie-bound page key.** A strict navigation to them (`Sec-Fetch-Dest:
    document`, `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Site: none` or `same-origin`) gets a new
    page key: a nonce `n` (16 random bytes) and 32 random bytes, written into that document and
    into a cookie of its own, `__Secure-secbin_pk_<n>` (HttpOnly, Secure, SameSite=Strict,
    `Path=/p/<id>` or `/r/<id>`, 15 minutes; its value is the key and when it was issued). Each
    tab's round trip has its own cookie, so two tabs of one share do not replace each other's;
    at most 4 are kept per share path (a new one clears the oldest). Nothing about the key can be
    derived from the id, the nonce or anything else a page can read. A cross-site navigation, a
    frame, a `fetch()` and a HEAD get none and set none.
  - When the share answers `captcha_required`, the page takes the key out of the address bar
    (`history.replaceState`), removes the tab's Drive keys from `sessionStorage` (they are never
    sealed or carried through the check: the Drive asks to be unlocked again afterwards), seals
    the link's key alone with the page key (AES-256-GCM, bound to the share and `n`), keeps only
    the sealed record in `sessionStorage` (this tab only), and replaces itself with the check
    page. A page opened from another site (whose navigation got no key), or whose key was
    already used, first reloads itself once as a same-origin navigation (`?pk`, the key kept
    after `#`) to get one.
  - The check page (`/p/<id>?check`, `public/js/check.js`) is served for any well-formed id while
    the server has Turnstile keys, else a redirect back. Its CSP is the Turnstile one with
    `worker-src 'none'` (no service worker, no Worker) and no COEP; its COOP is
    `same-origin-allow-popups`, so a popup it opens to a strict page lands in another browsing
    context group and gives it no handle. It never gets a page key. Opened with a `#key` in its
    address, it sends the key to the strict page before any widget code loads. Continue stays
    disabled until the CAPTCHA passes, redeems the token for the grant, keeps the grant for the
    tab and returns to `/p/<id>?n=<n>`.
  - **One use.** That return gets the page key again only when the navigation carries the cookie
    for `n`; the same response clears that cookie, and no new key is issued on a return. The
    server keeps no record of it: one use is the browser applying `Max-Age=0`, which is enough,
    since the cookie's value is the key itself. The strict page opens the sealed record, removes
    it, removes any Drive key the tab holds now (the tab's own were removed before the check, so
    one found now was planted), puts the link's key back into the address bar and opens the
    share with the grant.
  - Why the check page cannot open the record: a client outside the browser can send the Fetch
    Metadata of a navigation but has no cookie; a script in the browser cannot read the cookie
    (HttpOnly), its `fetch()` of the page is not a document navigation, it cannot frame the page,
    and a window it opens is in another browsing context group.
  - Without `sessionStorage` (a restricted window, storage off) or still without a page key (a
    browser that sends no Fetch Metadata) a protected share is not opened, and the page says
    why. `/check/` itself is not served.
- **What a compromised Turnstile script could still do** on the check page: obtain a grant
  (it runs the check), see the share's id and the sealed record, delete the record or navigate
  the tab (a denial of service). It cannot open the record, and a grant opens nothing without
  the key.
- **Same origin (residual risk).** The check page is on the app's own origin (the maintainer's
  decision; a separate hostname would remove this). While a script there runs, it has the
  reach of a script on the Account page: it can call the API as the tab's signed-in user with
  the session cookie (SameSite=Strict does not stop a same-origin request), and read or write
  this origin's `sessionStorage`, `localStorage` and Cache Storage for the tab. What bounds that:
  - the tab's Drive keys are not there, and a Drive key it plants is never used: the Drive
    proves a stored key against the Drive's key check value first (*Drive keys*, "In the tab");
  - it registers no service worker (`worker-src 'none'`), and a window it opens to any Worker
    response is in another browsing context group (COOP everywhere, *Isolation headers*);
  - a copy it writes into Cache Storage is never served: the service worker serves only bodies
    whose SHA-256 its build lists (*Service worker and install banner*).

  Recipients who are not signed in expose no account. Every recipient of a protected share
  visits this page.

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
  plain same-origin `200` that is not a redirect, not marked `no-store`/`private`, and whose
  body is exactly this build's (below).
- Everything is **network-first**: while online the browser always runs the code the server
  is serving now; a cached copy is used only when the network fails.
- **An integrity manifest.** Cache Storage is writable by any script of this origin (a share's
  CAPTCHA page runs Cloudflare's script), so nothing in it is trusted as it is. `sw.js` holds
  the SHA-256 of every asset of its build — the landing page (`public/index.html`), the manifest,
  the favicon and every file under `/css/`, `/js/`, `/fonts/`, `/img/` — and the security headers
  (both generated by `tools/sw-manifest.mjs` from the files and `src/lib/http.js`;
  `test-node/sw.test.js` fails when they are stale). Offline, a cached copy is served only for a
  path in that list and only when its body has that hash; the response is rebuilt from the
  verified body with the build's own content type and security headers, never the stored ones.
  A copy that does not match is deleted and the request fails, as without the worker. A body
  from the network is stored only when it matches too. A new build of the assets is a new
  `sw.js`, which the browser installs on its next update check.
- The cache name is versioned (`secbin-static-<n>`); on activation every older secbin cache is
  deleted and open pages are claimed (`skipWaiting` + `clients.claim`). The worker is
  registered with `updateViaCache: 'none'` and served `Cache-Control: no-cache`, and browsers
  never route the update check for `/sw.js` through a service worker, so a new deployment
  replaces the worker on the next navigation.
- The request filter (`requestPolicy`), the integrity check and a poisoned cache are
  unit-tested in `test-node/sw.test.js`.

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
  for unknown usernames (an HMAC under a key of its own, derived from the Directory's secret with
  HKDF-SHA-256 and the info `secbin-directory/prelogin-salt/v1`, so the salts anyone can ask for
  say nothing about the tracker tags and quota subjects, which have keys of their own), and every account uses the same Argon2id time cost, so the response
  never reveals whether an account exists. Prelogin is limited per network (`prelogin`: at most
  600 per 10 minutes) and per network and username (`prelogin-user`: at most 20 per 10 minutes
  for one name, counted under a keyed hash of the name as typed, lowercased), then
  `429 rate_limited` with `Retry-After` for 10 minutes. Both are counted before the Directory is
  asked and only for same-origin JSON requests (another site cannot send one). Neither depends
  on whether the account exists, and both refuse alike, so the answer says nothing about
  accounts. Only prelogin is refused: no account is locked, and the sign-in routes do not look
  at these scopes. The web client needs prelogin for a password sign-in, so heavy abuse from one
  network can delay password sign-in on that network (for one name, or for every name at the
  network limit) until the window ends; passkey and recovery-code sign-in are unaffected, and
  the owner sees and lifts `prelogin` and `prelogin-user` blocks with the others. Minimum
  length (12) is enforced client-side — the
  server cannot see the password. Trade-off: the stretched value is password-equivalent in
  transit (TLS-protected), as with any client-side stretching scheme.
- **Sessions**: `__Host-` cookie, HttpOnly, Secure, SameSite=Strict, containing a JWS (HS256,
  `SIG`) inside a JWE (A256GCM, `ENC`). Strict parsing (exact headers, no `alg: none`, no
  algorithm confusion). Every request re-checks revocation, disabled state and the per-user
  session version (bumped by password change/reset/disable), plus admin-configured idle and
  absolute timeouts. Starting an impersonation and "Return to admin" each issue a new session
  (a new id, so a new CSRF token) that keeps the absolute end of the sign-in it came from, and
  revoke the session they replace: switching back and forth never extends a session or leaves
  the old cookie usable. Missing/invalid `SIG`/`ENC` ⇒ login is unavailable (`503`), public links
  keep working.
- **When a session ends in an open page** (public/dashboard/js/session-timeout.js): the page
  warns two minutes before (WCAG 2.2.1), measuring its clock against the server's time (`now` in
  `/api/private/me`'s `session`, and in the file-share open and extend answers), so a browser
  clock that is off does not delay the warning. At the end the page locks: it stays in place but
  hidden and inert behind the "signed out" dialog, the tab's Drive key slots are cleared (stored
  or held in memory), an open Drive forgets its key and closes (its names and dialogs leave the
  page), password fields are emptied and the toast is put away. What was typed in other fields
  stays, hidden, so that signing in again in a new tab loses nothing (WCAG 2.2.5). Coming back,
  the page unlocks only if the same user (in the same impersonation state) is signed in; for any
  other account it stays locked and shows "session changed" with Reload, and never takes over
  that session's times or token. Toasts (which may name decrypted items) have no time limit but
  go, with their text, on the next key press or click, when the page is left or its history
  moves, and when the session ends.
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
      server-wide). Turning it off needs the owner's password or a passkey (see "Admin changes
      that weaken a control"); turning it on needs nothing. Off, the server stops requiring `X-Secbin-CSRF` (the header is ignored); the
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
  key user's own shares (list, receipts, label, extend, revoke) and Receive links (list,
  receipts, change, move, pause, resume, revoke; never create) — never the account itself
  (profile, password, passkeys, keys, activity) or admin endpoints (`403 api_key_not_allowed`).
  The owner decides who may hold keys and how many; API limits and quotas can only narrow the
  account's limits. Revoking API permission disables existing keys at once.
  - **Scopes:** each key carries a subset of `notes`, `files`, `policy` (create), `read` (list
    the user's shares and Receive links, one of them, and its receipts) and `manage` (label,
    extend views / expiry, revoke; a Receive link's changes short of weakening it, its folder,
    pause and resume). A key created without a choice gets the three creation scopes only; `read`
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
    browsers, as far as the owner enables receipt details — personal data), and the same of
    Receive links (their folder ids, limits and the senders' receipts); a leaked `manage` key
    can revoke or pause the user's shares and links (availability) and move a link to another
    of the user's folders, but can never read their content, which stays encrypted with keys
    the server never holds (or, for the Drive, keys a key never gets), nor weaken a link.
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
    owner is disabled; it also ends when the user is disabled. It keeps the absolute end of the
    owner's sign-in, and starting it (or returning to admin) revokes the session it replaces
    (see Sessions above).
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
    (`403 impersonating`); a restore from a personal kit is the owner's only, from Admin →
    Security → Keys, never while acting as the user (`403`).
- **Admin share management**: the owner sees every user's shares and can change a share's label, views
  and expiry, revoke it, or **lock** it.
  - **Only metadata:** share management never gains access to share content (notes and file
    shares stay end-to-end; a Drive share's files open with the Drive keys, as any Drive file:
    "Drive keys").
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
    Shares created before this change have no stored hash and are never counted. Chunk
    downloads (`/api/file/<id>/chunk/…`, file and Drive shares) follow the same rule: a share
    that ended while a recipient was still downloading (expired, used up, revoked, deleted) has
    lost its grants, so a chunk fetch with any well-formed grant for a share the index knows
    answers `410` uncounted (as the extend route does), and only an id that was never a share is
    counted. Those uncounted answers each cost a Directory lookup, so they have a generous
    per-network limit of their own (`ended-chunks`: at most 600 per 10 minutes, then
    `429 rate_limited` with `Retry-After`), which is never an invalid fetch and which the owner
    sees and lifts with the others;
  - rule: X failures within a window ⇒ block for a duration; the admin sees and manages blocks
    and tracking;
  - manual allow/block rules for IPv4/IPv6 addresses, CIDR blocks and inclusive ranges
    (`10.0.0.5-10.0.0.20`; allow wins; blocks deny the whole API and dashboard). A block rule
    that covers the owner's own address is refused unless an allow rule covers them first.
    Adding an allow rule, of any size, needs the owner's password or a passkey (its addresses are
    never blocked or rate-limited); a block rule needs nothing;
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
    lockout still cannot be guessed at without limit). The owner's own password cannot be reset,
    and the owner's own username cannot be changed, from the admin UI or API (`403
    use_account_page`); they change on Account, with the password or a passkey (the password
    also through setup recovery);
  - **admin changes that weaken a control** need the owner's password or a passkey, checked as
    every step-up (failures count toward the account's limit and the network's login failures;
    `400 reauth_required` with the list of what the change weakens when it is missing).
    Tightening, and every other change, needs nothing. What counts (`src/lib/settings.js`):
    - Settings: CSRF tokens off; a higher `lockout.max` or `guard.*.max`, a shorter
      `lockout.windowSec`, `lockout.lockSec`, `guard.*.windowSec` or `guard.*.blockSec`; a
      longer `guard.v6Prefix`; longer `session.idleSec` or `session.absSec` (the owner's own
      sessions); `public.enabled` turned on; a higher `public.newTrackersPerIp` or a shorter
      `public.newTrackersWindowSec`; a shorter `log.maxAgeSec` or a smaller `log.maxEntries`;
      a `log.ownerMaxAgeSec` or `log.ownerMaxEntries` where there was none, or a smaller one;
    - role options, the public account's included (each channel, compared on what the scope
      resolves to, so "same as Default" and lifting an API restriction count too):
      - sign-in and sessions: `passkeys` towards off (second → any → off); a lower
        `pwMinLength`, or `pwUpper` / `pwLower` / `pwDigit` / `pwSymbol` turned off; longer
        `sessionIdleSec` or `sessionAbsSec`; a `logMaxAgeSec` or `logMaxEntries` where there
        was none, or a smaller one;
      - the human check and passwords: `shareCaptcha`, `reverseCaptcha` and `reversePassword`
        towards off (require → allow → off); `shareCaptchaDefault`, `reverseCaptchaDefault`
        and `reversePasswordDefault` on → off;
      - lifetimes and views: `maxExpireSec`, `reverseMaxExpireSec`, `maxViews` and
        `reverseMaxViews` raised or removed (no limit); `allowUnlimitedViews`,
        `reverseAllowUnlimitedViews` and `reverseNoExpiry` turned on;
      - what may be shared: `files`, `url`, `secret` and `apiEnabled` turned on; `reverseFiles`,
        `reverseUrl` and `reverseSecret` turned on (Receive links that may take files, links or
        credentials); `fileTypeMode`
        towards any (allow → block → any), or, with the same mode, a type added to an allow
        list or removed from a block list; `urlRules` gaining a rule;
    - IP rules: adding an allow rule.
    The Turnstile keys (Security → CAPTCHA) need the step-up for every change, removing them
    included.
    Imports already need the step-up for every part. The owner acting as a user cannot reach
    any admin route;
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
  confirmations in the admin panel (for example log clearing, the owner's own keys and
  passkeys there, and changes that weaken a control: "admin changes that weaken a control"
  above) check the password or a passkey, but not Turnstile. All of them need a
  signed-in session, wrong answers count toward the same limit as a password change (all
  sessions end after `lockout.max`), and the IP login guard applies.
- **Losing everything.**
  - The admin can remove any account's passkeys and codes, the owner's included (Users →
    Manage → Passkeys), after which the password alone signs in. For another user's account
    this needs no confirmation from the owner (as for setting their password: the owner's
    session is the authority), so a stolen owner session can remove another user's second
    factor. For the owner's own account it needs the owner's password or a passkey, as on
    Account; wrong answers count as for a password change.
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
- **What stays end-to-end.** Notes and file shares (the key is in the link). **Not** a Drive
  share: its manifest is sealed like a file share's (the recipient gets the DEKs from the link),
  but its content is the Drive's ciphertext and each DEK is also sealed in the Drive under the
  user's KEK, so the server can open it as any Drive file. **Not** a reverse-share upload: it is
  encrypted in the uploader's browser to the link's key, whose private key is sealed under the
  user's KEK, so the server can open it before it is taken into the Drive as well as after.
- **Seals.** Each seal is AES-256-GCM under a key derived from the KEK with the item's 32-byte
  random salt, with AAD naming the user, the sub-MEK and the field; the item id is not in the AAD
  (DRIVE.md §9). File content keeps the file-share chunk format (index and count in the AAD), and
  the sealed metadata carries the size, checked against the server's.
- **Keys handed out.** After sign-in the server hands the session the user's KEKs (no prompt;
  the step-up rules for sensitive actions are unchanged). The owner acting as a user gets the
  user's KEKs (`drive.keys_used`, in the admin audit only), in that page's memory only. The same
  holds for a user's current KEK the escrow route hands the owner for an upgrade
  (`drive.escrow_used`, with the step-up, as for Show). The root MEK and the sub-MEKs leave the Directory only for the owner,
  after the step-up (Show, the key kit, an export), recorded by fingerprint; generated and
  entered keys are never logged. The Worker opens DEKs and names only to check a new seal and to
  re-seal (rotation, a sub-MEK deleted, a root change), in memory, never stored or logged.
- **Every new seal is checked.** The Worker opens what a browser sends once with the current KEK
  before storing it (`400 bad_seal`, `409 mek_not_current`; during a root change a rename sealed
  under the previous root is `409 stale_keys`), so the server can always re-seal it later;
  re-seals are compare-and-set writes on the stored keys and sealed fields, so a change made
  meanwhile (a rename) is never overwritten.
- **Key jobs cover every Drive.** A re-seal, a sub-MEK delete and a root change visit every
  account with a user salt (a Drive whose only content is a reverse link included). A sub-MEK is
  deleted only when a count over them finds nothing under it; a root change removes the
  previous root only after a final check that everything opens under the new one, and waits
  while a Drive still has something of the release before. One that cannot finish keeps the
  previous root; the owner runs it again, goes back, or drops the previous root with its
  fingerprint typed (the items listed stay unreadable, and their count, kept with the root
  change, is in the admin audit), each with the step-up; the key kit made meanwhile holds both
  roots. A previous root from a key kit is put back only when it opens something here, and "go
  back" leads only to a root this server worked with or one that opens items here.
- **The keyring.** Created on first need, and only if there never was one: a lost keyring is
  never replaced silently (the Drive says the keys are missing and the key kit restores them).
  Restores and imports never replace a working key, and add only what proved to belong: a
  sub-MEK this server does not have only when it opens an item or link key sealed under its id
  here, a user salt only when it opens something of that Drive's (a Drive that holds a link key
  never gets a new random salt in place of a lost one). A generated key is used only for what it
  was made for (a root MEK or a sub-MEK), and an unused one is deleted after 10 minutes. Every
  keyring change, and the previews of a restore or an import, need the step-up.
- **Set-up keys.** The set-up page shows the root MEK and first sub-MEK the server proposes,
  masked until Show, with "Use these", "Generate again" and "Enter manually". The proposal
  (`POST /api/auth/setup/candidate`) is made only for a request with an unspent setup token
  (checked in constant time; wrong tokens count against the network like the set-up's own) and
  the intent header, only while no owner exists (a spent token, or an owner: `410 token_used`)
  and there is no keyring and never was one. A network gets at most 20 proposals per 10 minutes
  (the Guard's `setup-candidate` scope, which the owner sees and lifts like the others). A
  proposal is kept as two candidates (a sid no session can have) for 10 minutes and a new one
  replaces the last; proposals are not written to the admin audit, so they cannot flood it:
  only the pair the set-up adopts is (`keys.created`, by fingerprint). No keyring exists until
  the set-up sends the pair's ids, checked before anything is written (`410 candidate_expired`
  otherwise); the pair (or keys entered by hand) is then written in the same transaction as the
  owner account, so a failure leaves neither and the set-up can be run again. Copying a key
  (the set-up page, Security → Keys) clears the clipboard after 60 s only where the page may
  read it back and it still holds that key; the site's Permissions-Policy denies
  `clipboard-read`, which is kept, so in practice the page tells the owner to clear the
  clipboard (and any clipboard history) instead.
- **Kits.** The personal kit (every user) holds the user's salt and KEKs; the key kit (the
  owner) the root MEK, every sub-MEK and every user salt. Each is sealed in the browser under an
  optional passphrase (Argon2id, AES-256-GCM, bound to the account and the origin) and never sent
  to the server; verify sends check values only. On the Account page, Download and Verify also
  need a fresh Turnstile token (the action `account`) when Turnstile is on, checked before the
  step-up, as every other Account change. Both kits hold the keyring's version (a counter the
  Directory raises on every key change, never a key or a fingerprint), and Verify compares it
  with the server's. For each account the Directory records the date and key version of its
  last personal-kit download and which sub-MEKs that kit held (meta `ukit:<userId>`, removed
  with the account); from that the Account and Drive pages say, with no key detail, when the
  keys changed after that download. Only the user's own session downloads a kit and so updates
  the record: the owner acting as the user is refused (`403 impersonating`) and cannot clear
  the notice. **Only the owner restores from a kit**, in
  Admin → Security → Keys: the key kit, and a user's personal kit ("Restore a user's personal
  kit": the user chosen there, the kit opened in the owner's browser for that user only, the
  server refusing a kit whose id is another user's). The Account page offers Download and Verify
  only, for every account, and its restore routes answer `403 owner_only` to everyone (the
  owner's own session, the owner acting as a user; API keys never reach the Drive or the admin
  routes), so no user can change what opens a Drive or lock the owner out of its files. A
  personal-kit restore takes only what the server lost — the user salt when the account has
  none, and only if it opens that Drive; the items under a sub-MEK the server can no longer
  open, opened with the kit's KEK and sealed again under the current one (compare-and-set) —
  never replaces a working key, never keeps the kit's KEKs, needs the step-up for every call and
  is in the admin audit by ids and counts only. **A key kit opens every Drive** (with a copy of
  the stored ciphertext): store it offline, like the AUTHN secret. Losing the Directory's keys
  and every key kit loses every Drive file. What these controls can and cannot enforce: the
  step-up on a kit download gates the kit file (and its audit entry), not the keys in it: a
  signed-in session already gets its own user's KEKs from `POST /api/private/drive/keys`
  without a step-up (see "In the tab"), and the user salt the kit adds opens nothing without the
  root MEK; the throttle on failed
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
  old key leaves the tab when its Drive opens and nothing waits any more (the owner's once the
  escrow clean-up is done). When the page stops acting for its session (the session ended; the
  browser is now signed in as someone else — another tab signed in, impersonation started or
  ended — found at the next change or when the tab is shown again), an open Drive closes: its
  KEKs are overwritten and dropped, and what it showed leaves the page. A download checks the
  file's chunks against the ciphertext hash the server recorded and refuses a file that does not
  match (integrity metadata, not a seal: DRIVE.md §9). The
  CSP and Trusted Types (§4) keep other script out, as for the rest of the app; the pages that
  may load Cloudflare's Turnstile script (the one third-party script, §4) move that old key into
  the page's memory before the script loads (the sign-in page writes it back as it leaves). What
  remains: a compromised Turnstile script on the Account page could read the page's own memory
  while the personal kit is being built there, as it could read the password typed there. A
  share's CAPTCHA page never has a Drive key: the share's page removes every Drive key slot
  (`secbin_dk…`, `secbin_kek…`) from `sessionStorage` before it goes there (*CAPTCHA on shares*);
  a Drive still waiting for its upgrade then asks for the password once.
- **The upgrade of Drives made before this model** (DRIVE.md §3.3) opens the old Drive key only
  in a browser — at the user's sign-in, with a recovery kit of that release, or in the owner's
  browser through the owner's escrow of that release (with the step-up; recorded,
  `drive.escrow_used`) — re-seals every item under the user's KEK, and removes the old wraps only
  after the server has verified that every item opens under the new keys (the owner's escrow
  keys and records only once every Drive is upgraded, or the last account still waiting is
  deleted). A link whose old key does not open is retired by its user (the step-up): it ends and
  its key goes. A finished upgrade stays finished. While a Drive waits, its old key wraps are
  kept current as before (spent recovery codes, removed passkeys and replaced codes lose theirs;
  an admin reset drops the old password's wrap when another remains; the owner's are pruned the
  same way, except that those an AUTHN owner recovery kept stay until nothing waits). The owner's archive of that release (a start over) is
  deleted from Admin → Security → Keys (the step-up, the username typed; audited).

### Read receipts

- Every successful open of an account's share (a wrong link or password is not an open), and
  every upload session granted by a Receive link (a view of it: a failed start is none), is
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
  A Receive link's uploader page says that sending is recorded, before anything is sent.
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
  older than a date. It needs the owner to confirm again, with the password or a passkey (like
  export), and, as configured, it
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
- Export and import (its preview and its apply) both require the owner to **confirm again**
  (step-up): the password, or a fresh passkey assertion (`reauth`), as every other step-up. A
  stolen session cookie alone cannot exfiltrate verifiers or replace credentials. Wrong
  passwords and failed passkeys count like wrong current passwords (the account's sessions end
  at the lockout threshold) and against the IP's login guard.
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
  Subjects are stored only as HMAC-SHA-256 values keyed with a key derived from a per-deployment
  secret held in the Directory (HKDF-SHA-256, info `secbin-directory/public-subject/v1`); the raw id and the address are never stored. An import that changes any `public.*`
  setting is called out in the import preview.
- **The tracker** is a random id the server issues and authenticates with an HMAC tag
  (12 random bytes ‖ issue time ‖ 8-byte tag, under a key derived from the per-deployment secret
  for this use alone: HKDF-SHA-256, info `secbin-directory/tracker-tag/v1`). It is
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
  - An id is stored on its first **successful** creation: a create that is refused after the id
    was looked at (a malformed share, a quota) gives its new row, and the network's allowance,
    back. At most `public.newTrackersPerIp` (default 5) new ids per network per
    `public.newTrackersWindowSec` (default a day; `429 tracker_rate_limited`), and, for IPv6,
    at most 16 times that per /48 (the Guard scope `public-trackers`, which the owner sees and
    lifts with the others), so rotating /64s inside one allocation does not multiply it. The /48
    counts an id only once its create has succeeded, so refused creates from one /64 never block
    the rest of its /48; parallel first creates can pass that count by the few in flight. At most
    200 000 are stored: when the table is full, the 1 000 least recently seen ids that are not
    blocked are removed with their usage counters (as if they had idled out; logged as
    `tracker.evicted`), and only a table of blocked ids answers `429 busy`. Clearing browser storage therefore yields a new id
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
  key; each file's DEK travels inside the share's encrypted manifest, and stays sealed in the
  Drive under the user's KEK too: a Drive share is not end-to-end against the server ("Drive
  keys").
- **Export.** The account export carries the Drive role options (with the roles), never Drive
  content or keys. The Drive keys have a file of their own (Import / export → Drive keys), the
  parts the owner picks, sealed in the browser; the key kit is another file.
- **Archives** the owner's Drive kept after starting over in the release before stay in the
  owner's Drive object as they were (sealed under that release's key, uploads received through
  reverse shares included), not counted in the capacity; no route opens or restores them any
  more. The owner deletes one in Admin → Security → Keys (the step-up and the username typed;
  its R2 objects go, the links it paused end; admin audit `drive.archive_deleted`).

### Reverse shares ("Receive")

Design and interface: [`docs/REVERSE.md`](./docs/REVERSE.md).

- **Keys.** Each reverse share has its own ECDH P-256 key pair, made in the user's browser. The
  raw public key is the link's `#fragment` (never sent to the server). The private key is stored
  sealed under `HKDF(KEK, "reverse-link")` (bound to the user, the sub-MEK and the share id) and,
  at rest, under the user's field key: like every Drive key it opens with keys the server holds,
  so the server (and the owner) can open it; it is checked to open under the user's current KEK
  when the link is created. The uploads are therefore **not end-to-end against the server**,
  before or after they are taken in: the server does not keep the link's private key in the
  clear, but it can unseal it; a leak of R2 or of the Drive object alone opens nothing.
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
- **CSRF.** The user's routes (create, take in, mark failed, retry; change, revoke and lock
  through the shares routes) are cookie-authenticated and need the session's CSRF token and the
  request shape check, before the step-up and before the id is claimed. The uploader's routes
  under `/api/reverse/<id>/` are anonymous and exempt (they read no session); the link proof, the
  session grant, the upload token, Turnstile, the password lockout and the Guard guard them (see
  "CSRF" above).
- **Notes, links and credentials** (docs/REVERSE.md §3.1). A link may accept, besides files, the
  types regular shares carry — a note, a link, a credential — as the user chooses per link and
  the role allows (`reverseFiles`, `reverseText`, `reverseUrl`, `reverseSecret`; links and
  credentials off in the Default role). Each is one item of its own upload session, encrypted in
  the uploader's browser exactly like a file, with its kind inside the metadata sealed to the
  link's key. The uploader's browser **declares the kind of each session** at `begin`: the server
  sees that kind (it checks it against the link and the user's role as it is at that moment, and
  again at every reservation; it counts it in the quotas; it keeps it with the session until the
  session ends, and with each item it reserves — sealed at rest, never in plain text — until the
  item is taken in) and each item's ciphertext size, never its text, URL, fields, title or
  format, and a stored item carries no plaintext kind. Per-kind quotas (`receive-file`,
  `receive-note`, `receive-url`, `receive-secret`, where the owner sets them) keep counts only —
  sessions per kind per quota window, no content — each count row until 400 days after its
  window's first count. The server holds a declared note, link or credential session to one
  item of its kind's size, but cannot see what the item is: **the user's browser fails at take-in
  an item whose sealed kind is not the one its session declared, that exceeds its kind's cap, or
  that the link no longer accepts under the user's role as it is then** (so a modified uploader
  cannot pass a file off as a note to escape the file limits or quotas, or send a credential
  once the role stopped allowing them). The server refuses the take-in too (`409
  kind_not_accepted`) unless the declared kind, opened from the wrap sealed at rest, is one the
  link accepts and the role allows then; a received item's name, metadata or wrap stored in
  plain text is never trusted (no fallback: it fails as `kind`). Like every Drive item a received credential is **not
  end-to-end encrypted**: the recipient's server can decrypt it, and the uploader page says so on
  the credential form ("The recipient's server can decrypt this"). In the Drive each opens only
  in the inert viewers of regular shares (`public/js/typedview.js`): a note as text or through
  the safe Markdown subset, a link spelled out with its warnings and opened only through a
  confirmed click, only for the schemes a page may open and only when the user's own URL rules
  allow it (else Copy only, with the reason), a credential masked. A download is a text file: a
  link as a plain `.txt` with its URL, never an Internet Shortcut (`.url`), whose target the
  shell would follow; a credential as a plain-text export that says what it holds, after a
  confirmation; ZIPs never include credentials. A viewer never renders an item past its kind's
  size. A Drive share records what the sender's role allowed it to share as notes, links and
  credentials when it was made, and the recipient's page shows an entry as one only where that
  allows it (the manifest's markers are the sender's own). A marker or content that does not parse
  is never rendered as a link or a credential.
- **Declared file types.** When the user limits a link to some file types, the uploader's
  browser declares each file's `{ extension, MIME type }`; the server checks it against the
  link's rules and does not store it (as for file shares: a modified client could lie). Unlike a
  file share, the declarer is the anonymous party the rules restrain, so the **user's browser
  enforces them on what really arrived** when it takes an item in: the real, decrypted name and
  type against the link's file types, a file's size against its largest file, and the item's
  kind (a file, or a note, link or credential) against what the link accepts. A mismatch is
  never added to the Drive: it is recorded as failed (`type`, `size`, `kind`) and listed, to
  delete.
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
  (`reverse.bad_password`, at most one entry per link per minute). When the link has the
  CAPTCHA (its user's role and choice; *CAPTCHA on shares*) and Turnstile is configured,
  starting an upload session needs a CAPTCHA grant (or a token) for the `reverse-upload`
  action, checked before the password, so no password guess is answered without one; each grant
  starts one session, whatever the answer. The uploader page always keeps the strict CSP: the
  widget is on the link's check page, and Continue there stays disabled until it passes.
  Besides the per-network Guard, each link has its own lockout: 10 wrong passwords within 15
  minutes, from any networks, lock its password for 15 minutes (the right one too). The lockout
  is per link on purpose, so that guesses spread over many networks are stopped too; the
  consequence is that one network holding the link can keep its password locked for everyone:
  10 wrong guesses every 15 minutes are well under the Guard's per-network limit (60 invalid
  requests per 10 minutes), so that network is not blocked, and with the CAPTCHA on the link each
  guess costs one solved challenge. An upload session's deadline slides: while it has a file reserved and
  not finished it stays open for the role's `filePendingSec` after its last progress; as soon as
  nothing is unfinished (the file finished or was cancelled) it is idle again and lapses 10
  minutes later, and it never lasts more than 24 hours after it began. A network may hold at most
  5 open sessions per link (counted by 24 bits of a hash of the link id and the network; no key,
  and the address itself is not stored), besides 100 per link, so idle sessions give their slots
  back and cannot easily lock a link for everyone else.
- **Limits.** Per link: expiry (at most the role's `reverseMaxExpireSec`, or none where
  `reverseNoExpiry` allows it), views, files, total bytes, largest file, file types; per role:
  `reverseEnabled` (with `driveEnabled`), `reverseMaxActive`, `reverseMaxBytes`,
  `reverseMaxExpireSec`, `reverseNoExpiry`, `reverseMaxViews`, `reverseAllowUnlimitedViews`,
  `reversePassword`, `reverseEdit`, `reverseCaptcha`, and the kinds a link may accept
  (`reverseFiles`, `reverseText`, `reverseUrl`, `reverseSecret`, checked on create, on each kind a
  change adds, and at every upload with the role as it is then); always the Drive's capacity and
  largest file. The server holds a note, link or credential session to one item of bounded size
  (a note 2 MiB, a link 2048 characters, a credential the regular credential's fields), and the
  user's browser holds what really arrives to the declared kind and that size at take-in. The server checks every one on create and on every change (for an API key, with the
  role's API limits on top); the pages only reflect them. The role's current
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
- **Views.** A view of a link is one upload session granted (the link proof, the CAPTCHA and
  the password passed); opening the page is not one, and a failed start spends none. The count
  is taken in the user's Drive object in one step with the session it grants, so concurrent
  starts never exceed it. Once the views are used up, new sessions are refused (`410`, before
  the CAPTCHA or the password is looked at, so a used-up link answers no password guess);
  sessions already started may finish. The user may raise the views (the link takes uploads
  again) or lower them, never below those used.
- **Links with no expiry.** Only where the role's `reverseNoExpiry` allows it (off in the
  Default role): such a link takes files until it is revoked, its views run out, its folder is
  deleted or the role no longer allows reverse shares — so an indefinite link that leaks can
  be used for as long as nobody revokes it; a views limit, the password and the CAPTCHA bound
  that. It is stored as a far-future time (`NO_EXPIRY`), so every expiry check reads it as not
  expired, and the API shows `expires: null`. Admin → Shares lists and filters these links
  ("no expiry"), and the owner can revoke or lock any of them. **Retention:** its share index
  row (label, times, status, counters) is kept while it is active and 30 days after it ended,
  and the link's key, limits and counters in the user's Drive are kept as long as the link
  exists (as for every link: until 30 days after it ended, once its received files are taken
  in or deleted); nothing expires them on its own. Turning `reverseNoExpiry` off later does not
  end or bound the links that already have no expiry: they keep taking files until they are
  revoked; the owner finds them with the Expiry filter ("no expiry") of Admin → Shares.
- **Changing a link.** Where `reverseEdit` allows it, the user changes a link's expiry (as
  regular shares, only extended — or made indefinite, or given an expiry when it had none),
  views, limits, CAPTCHA (within `reverseCaptcha`), password (within `reversePassword`) and
  note. The password and the note are made in the user's browser from the link's key: neither
  is sent in plain text, but like the uploads to the link they are not end-to-end (the server
  holds the keys that open the link's key, so it can read the note and test guesses at the
  password; a copy of the Drive object alone cannot). A change that weakens the link — its
  password removed or changed, its CAPTCHA turned off, no expiry, unlimited views, or accepting
  files, links or credentials it did not (each a new way for an anonymous sender to reach the
  user: a file of any type, a link to follow, a secret entrusted to a channel that is not
  end-to-end; a note is plain text shown inertly, so adding one is not weakening) — needs the
  account password or a passkey, as creating a link does (a stolen session alone cannot turn a
  link into an open, lasting upload channel), and is refused for API keys even with `manage`
  (`403 step_up_required`); the owner acting as the user confirms nothing. Tightening a link
  (a password added where it had none, the CAPTCHA on, an expiry, fewer views, tighter limits)
  and the label need no confirmation, through the API too. Changing the password keeps the link's lockout state and its
  sessions already started. The owner changing a link directly (Admin → Shares) may change its
  views and expiry only (a link with no expiry only where the user's role allows it); the
  password, the note, the limits and the CAPTCHA are the user's. Changes are refused on revoked,
  ended or locked links, and need the CSRF token and the role checks like every change. The
  activity log names what changed (`share.updated`: expiry, views, CAPTCHA, `password=set` /
  `removed`, `note=set` / `removed`, `limits`, `accept=<kinds>`, `folder=<node id>`), never a
  value the user typed.
- **Moving a link.** The user (the Edit form, or an API key with `manage`) can point a link at
  another folder of their own Drive: the Drive object checks the folder is one of its own (a
  folder, not a received item, not deleted — another user's ids do not exist there), within the
  role's folder depth (for a key, its API limit), and moves the link's items not yet taken in
  with it in the same step, so its take-in places them there; the owner changing a link directly
  cannot. It changes where anonymous uploads land, not what may reach the user, so it is not a
  weakening change.
- **Pausing a link.** The user (or an API key with `manage`) can pause a link and resume it.
  Paused, `open` and `begin` answer `409 paused` once the link proof matched (never counted by
  the Guard, like a late visitor of an ended link; a wrong link proof is, as always), the sessions
  open then end and their unfinished uploads are deleted at once; received items stay and are
  taken in. Resuming restores the link as it was (no protection changes), so neither needs the
  step-up; a link an owner's start over paused cannot be resumed.
- **Receipts.** Each upload session granted is recorded as a read receipt for the link's user
  (*Read receipts*): the uploader page says so, and the same visibility, throttling and
  retention apply.
- **The Receive links' API** (`/api/private/receive`, docs/API.md) is the My shares surface for
  links: the scopes `read` (list, one link, receipts) and `manage` (change, move, pause, resume,
  revoke), only the caller's own links, the role's reverse shares required, the lock and the
  API limits applied, and weakening changes refused for keys (`403 step_up_required`). A link is
  listed without its key, note or password (only whether it has them). A key cannot create a
  link: the link's private key is sealed under the user's Drive keys, which a key never gets, and
  creating one needs the step-up.
- **Quotas on Receive.** The owner can cap, per role, the upload sessions a user's links receive
  (`receive-upload`, and `receive` with new links; and by what a session sends: `receive-file`,
  `receive-note`, `receive-url`, `receive-secret`) in a fixed window. A session is counted for
  the user when it starts (before the password is checked), atomically in the Directory, and
  given back when it does not start or ends having sent no file. At the quota `begin` answers
  `429 not_accepting` ("This link can’t accept more uploads right now. Try again later."): the
  uploader learns nothing of the quota (no numbers, no window, no `Retry-After`).
- **Ending.** Revoking a link, its expiry, an admin lock (paused), the role losing the option, or
  deleting its folder stops uploads at once; unfinished uploads are deleted; files already
  received stay. Deleting the account deletes everything.
- **Links of the release before.** A link whose key the old Drive key sealed is re-sealed under
  the user's KEK by the Drive's upgrade (docs/DRIVE.md §3.3); until then the Drive shows no link
  for it and its received files wait. Links an owner's start over paused in the release before
  stay paused (`409 paused`).
- **Audit.** `share.created` (`kind=reverse`, with `expires=none` and `views=N` where set),
  `share.updated` (what changed, as above) and `share.revoked`, `reverse.received` (count and
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
- **Quotas** (role option lists; public/js/quotakinds.js) are checked and counted in one
  synchronous Directory step, so concurrent creations cannot pass a quota: outgoing shares
  (every share, or by type), Drive uploads (`drive-upload`, each file, and `drive-bytes`, its
  size, checked together in the same step at the upload's start: one refused, neither counted) and
  Receive (`receive-link`, `receive-upload`, and `receive-file`, `receive-note`, `receive-url`,
  `receive-secret` by what an upload session sends). An API-only quota narrows API creations only; the
  Drive and Receive have no API channel. The public account's quotas count per anonymous
  subject and take only the kinds it can use. The owner is never counted.
- Reads that spend views need custom headers (non-simple): ambient GETs never consume anything.
- Download grants are stored apart from the share record.
  - One client (an IP, or an IPv6 /64) holds at most 20 live grants per file share; opening
    again replaces its oldest.
  - At most 2000 grants may be live per share; beyond that, opens get `429 busy` with
    `Retry-After`.
  - So repeated opens cannot break a share. Keeping one busy takes at least 100 distinct
    networks, a residual risk for unlimited-view shares shared very widely. Extensions do not
    make it cheaper: when the table is full, a grant past its first window (one living on an
    extension) gives way to a new open, so a busy share still needs a fresh open for every slot
    in every window, as before extensions existed.
  - The viewer's tab may extend a live grant's download window (`POST /api/file/:id/extend`,
    for WCAG 2.2.1). The grant is the only credential (a custom header; cross-site requests are
    refused). Each extension ends the window the role's download window from now, at most 10
    times per grant, never past the share's expiry, and spends no view.
  - Every extend call counts towards the route's own per-network limit (`download-extend`: 120
    calls per 10 minutes, then `429 rate_limited` with `Retry-After` for 10 minutes), checked
    first, so a loop is refused before the Directory is asked. What a guesser produces also counts
    as invalid, as on the chunk route: a bad grant, and an id that was never a share (answered
    from the share index without creating a FileShare object). The right credential arriving late
    or once too often is never counted as invalid: a share that has ended (`410`) and a grant past
    its tenth extension (`409 extend_limit`; the viewer stops asking after the first). The owner
    sees and lifts `download-extend` blocks with the others.
  - After a file share's last view its ciphertext is purged when the last live grant ends. So
    extensions keep a one-view share's encrypted data in R2, and downloadable with that grant,
    for up to 10 more windows after the only view, never past the share's expiry. The sender is
    told so when the share is created, and every extension is recorded in the share owner's
    activity log (`share.download_extended`: the share id, which extension of that window, and
    the new end; never the grant or an address). Revoking the share ends it at once.
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
