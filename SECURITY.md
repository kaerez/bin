# secbin — Security Policy & Threat Model

secbin is a **zero-knowledge sharing service** for notes and files: content — including file
names, folder structure and MIME types — is encrypted and decrypted only on the client, and the
decryption secret never leaves the client in normal operation. This document is the
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
   that is encrypted client-side; the key (`F`, the URL fragment) is never transmitted.
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
  the owner still cannot decrypt shares.
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
  - **Which links** a sender may share is the admin's *URL rules* (global and per user):
    `scheme:https`, `scheme:tel`, … and `re:<regular expression>` against the whole link;
    default `http` and `https`; the owner may share any safe link. The link is encrypted, so the
    rules are checked by the sender's browser or CLI (the CLI reads them from
    `GET /api/private/policy`) — they keep honest senders within policy, not a modified client.
    Admin-written regular expressions run in senders' browsers (the admin is trusted; a costly
    pattern slows only the composer).
  - **Never allowed**, on either side and whatever the rules say: `javascript:`, `data:`,
    `vbscript:`, `file:`, `blob:`, `about:`, browser-internal and extension schemes. The recipient
    does not know the sender's rules, so it accepts any other scheme, shows a host-less link
    (`tel:`, `mailto:`, …) in full and says it opens another app.
  - The recipient sees the host as the browser resolves it (punycode) with a look-alike warning for
  internationalized names and a warning for plain HTTP, and opens it with a confirmed second
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
  the server from a hostile client. The owner always has the built-in policy (12 characters).
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
- **CSRF**: state-changing calls must be non-simple (JSON content type or `X-Secbin-Intent`), are
  refused when `Sec-Fetch-Site` is `cross-site` **or `same-site`** (a sibling subdomain is not
  trusted), and cookies are SameSite=Strict. The API has no CORS.
- **API keys** (`sbk_…`, stored hashed) authenticate share creation only — never account or
  admin endpoints. The owner decides who may hold keys and how many; API limits and quotas can
  only narrow the account's limits. Revoking API permission disables existing keys at once.
- **Impersonation** ("log in as"): owner only, never nested, no admin access or key minting
  while impersonating; each action is logged with the real actor (the user's own activity view
  shows it as theirs).
- **Admin share management**: the owner sees every user's shares and can change a share's label, views
  and expiry, revoke it, or **lock** it.
  - **Only metadata:** it never gains access to share content, which stays end-to-end
    encrypted.
  - **Bounds:** admin changes are increase-only and bounded by the protocol maxima, not by the
    user's limits.
  - **Logging:** they are recorded in the audit log as direct admin actions, and they do not
    appear in the user's own activity. Impersonation is different: it acts *as* the user and
    shows up as the user's own.
  - **Locks:** a locked share is frozen for its sender (no edits, no revoke) and for its delete
    token, until the owner unlocks it. Natural expiry and view exhaustion still apply. Locked
    rows are kept in the share index; they are not pruned.
- **Brute-force protection** (admin-configurable, per IP; IPv6 aggregated to /64 by default):
  - `login`, `setup`, and `invalid` — share ids that never existed, **wrong `#` keys, wrong share
    passwords**, bad download grants and bad delete/upload tokens. Fetching a share that did
    exist but has expired, been used up, revoked or deleted (it is still in the share index,
    which keeps ended shares for 30 days) is a recipient arriving late and is **not** counted;
  - rule: X failures within a window ⇒ block for a duration; the admin sees and manages blocks
    and tracking;
  - manual allow/block rules for IPv4/IPv6 addresses, CIDR blocks and inclusive ranges
    (`10.0.0.5-10.0.0.20`; allow wins; blocks deny the whole API and dashboard);
  - account lockout after X failed logins (owner exempt — recover via setup if needed). Per-IP
    protection and account lockout are complementary: the first stops one source guessing
    (any account), the second stops many sources guessing one account;
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

### Read receipts

- Every successful open of an account's share (a wrong link or password is not an open) is
  recorded: the time, and what the opener's request itself revealed — the IP address,
  Cloudflare's coarse location (country, region, city), the browser and version, the operating
  system and the `Accept-Language` languages. At most 1000 per share are kept (oldest first), for
  as long as the activity log (same age limits; clearing an account's log clears its receipts).
- The sender sees the time of every open in My shares; the other details only as far as the
  admin allows that account (`receiptIp`, `receiptLocation`, `receiptBrowser`, `receiptOs`,
  `receiptLanguages`, all off by default). The admin always sees everything. Anonymous (public)
  shares are recorded for the admin only.
- The share page tells recipients before they reveal or unlock a share that opening is recorded.
  These are recipients' personal data (GDPR): decide what senders may see, the retention period
  and the notice wording with your Legal / Compliance team.

### Activity log retention and clearing

- The activity/audit log is kept for at most `log.maxAgeSec` (default 365 days) and
  `log.maxEntries` (default 500 000, oldest deleted first); per-user limits
  (`logMaxAgeSec`, `logMaxEntries`) can keep less about an account. Pruning runs hourly and
  every 500 writes. Entries about the owner are exempt (global settings never apply to the
  owner) and are removed only by hand.
- The owner can **clear** the log — everything, or one account's entries, optionally only those
  older than a date. It needs the owner's password again (like export), and, as configured, it
  **leaves no record**: after a clear, nothing in the system shows that entries existed or were
  removed. Audit trails can be subject to retention duties (for example SOX record-keeping for
  systems in scope); decide the retention settings and who may clear with your Legal / Risk /
  Compliance team — this document is not legal or compliance advice.

### Admin export / import

- An export can hold password **verifiers** (enough to test guesses offline) and the whole
  configuration, so it exists only encrypted: the server builds the plaintext document for the
  signed-in owner, and the browser encrypts it before saving (`public/js/exportcrypt.js`:
  passphrase ≥ 12 characters → Argon2id m = 64 MiB, t = 3 → AES-256-GCM, with the fixed KDF
  parameters, salt and IV bound into the AAD). A crafted file cannot ask for more KDF work.
- Export and import both require the **owner's password again** (step-up): a stolen session
  cookie alone cannot exfiltrate verifiers or replace credentials. Wrong passwords count like
  wrong current passwords (the account's sessions end at the lockout threshold) and against the
  IP's login guard.
- Never exported: the owner account, sessions, API keys, shares, usage counters, the activity
  log. An import can never create or replace an owner; accounts it creates are plain users.
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
- The passphrase is the only protection of the file: keep file and passphrase apart. Whether
  exported verifiers may leave the environment at all is a policy decision for your Security /
  Compliance function.

### Public (anonymous) access

> [!IMPORTANT]
> **Legal / Compliance review required before enabling.** Anonymous sharing lets anyone publish
> content from your domain, and the tracker below stores an identifier on the visitor's device
> for rate limiting. Storing or reading such an identifier is regulated in the EU/UK (ePrivacy
> Directive art. 5(3), PECR) and the identifier and the keyed network hash are pseudonymous
> personal data under GDPR. Whether the "strictly necessary" exemption applies, which lawful
> basis and retention period apply, what the on-page notice must say, and how abuse reports are
> handled are decisions for your Legal, Risk and Compliance functions — this document is not
> legal or compliance advice.

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
- **Administration:** Admin → Public access lists trackers (hash prefix, created, last seen,
  uses, blocked reason) and can unblock, block or forget one (forgetting also clears its
  counters). Conflicts and admin actions are audited.
- File uploads by the public account (when the admin enables files) use the same upload-token
  capability as account uploads; the quota is charged when the upload starts.

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

## 7. Cryptographic summary

Per-share random CEK; AES-256-GCM with fresh IVs; Argon2id (m=64 MiB, p=1, t∈[1,10]) for
passwords; HKDF-SHA256 for the KEK and the two access proofs; per-share FK for file chunks with
index-bound AAD; canonical AAD; strict canonical base64url. Details and test vectors: `SPEC.md`.

## 8. Reporting a vulnerability

Please report privately via
[GitHub private vulnerability reporting](https://github.com/kaerez/bin/security/advisories/new).
Do not open public issues with exploit details. Include affected version/commit, reproduction
steps and impact.

## 9. Supported versions

Only the latest `main` of secbin receives security fixes. Protocol v1 links are no longer
supported.
