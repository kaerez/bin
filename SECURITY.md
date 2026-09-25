# secbin — Security Policy & Threat Model

secbin is a **zero-knowledge pastebin**: paste content is encrypted and decrypted only on the
client, and the decryption secret never leaves the client in normal operation. This document
is the authoritative statement of what secbin does and does **not** protect. Read it alongside
`SPEC.md` (the cryptographic protocol).

secbin is maintained by KSEC - Erez Kalman and is based on
[binthere](https://github.com/nxfu/binthere) by nxfu; the threat model below is inherited from
binthere and updated for secbin's changes (view limits, custom expiry, no outbound requests,
deployment behind Cloudflare Access).

Treat secbin as a **security-sensitive cryptographic application**, not a normal web app.

---

## 1. Security goals

1. **Confidentiality of plaintext from the storage/server layer.** The server, the KV store,
   the Durable Object, and Cloudflare's infrastructure store only ciphertext and non-secret
   metadata. They cannot read paste plaintext, because the decryption secret (`F`, the URL
   fragment) is never transmitted to them.
2. **Integrity / authenticity of ciphertext and its security-relevant metadata.** AES-256-GCM
   authenticates the ciphertext, and the canonical AAD (`SPEC.md` §4) binds every field that
   affects decryption, rendering, compression, or the view-limited flag. Tampering fails
   closed.
3. **Password gating that is independent of the URL secret.** For password-protected pastes,
   neither the URL fragment secret alone nor the password alone can decrypt (`SPEC.md` §2).
4. **Exact view limits.** A view-limited paste (1 to 100 000 views) is delivered to at most
   that many readers, enforced atomically by a Durable Object; every later read gets
   `410 Gone` and the record is deleted on the last view (`SPEC.md` §8). A password on a
   view-limited paste is verified against a **non-consuming metadata peek** *before* any view
   is spent, so a wrong or missing password never uses up a view. The peek returns the wrapped
   key but never the ciphertext; the trade-off (offline password guessing for someone who
   already holds the URL secret) is documented in `SPEC.md` §8 — use a strong password.
5. **No client-side key exfiltration via the app's own code.** A strict CSP, self-hosted
   assets, DOM-construction-only rendering, and a raw-HTML-free Markdown renderer prevent the
   application from turning attacker-controlled paste content into script execution — which,
   in a zero-knowledge app, would be equivalent to leaking the key (see §4).

## 2. Explicit non-goals

secbin does **not** provide, and does not claim:

- **Anonymity or metadata privacy.** See §3.
- **Protection against a compromised or malicious deployment.** See §4.
- **Protection of a secret you disclose.** Anyone with the full URL (id **and** fragment) — and
  the password, if set — can read the paste, up to its view limit. Sharing the link shares the
  content. Fragments may be retained in browser history, referrer chains (mitigated by
  `Referrer-Policy`), chat-app link previews, etc. This is inherent to URL-fragment key
  delivery.
- **View limits as a confidentiality control against the link holder.** A view limit bounds
  how many times the server releases the ciphertext; it cannot stop an authorised reader from
  copying the plaintext. Unlimited-view pastes can be read by anyone with the link until they
  expire.
- **Guaranteed deletion from all layers/backups.** Expiry, the last view, and delete remove
  data from the live store; operational copies/logs are outside this boundary. For
  unlimited-view (KV) pastes, a delete or expiry can take up to ~60 s to be visible at every
  edge location.
- **Authentication inside the app.** secbin has no accounts. Who may *create* pastes is
  decided by the deployment's access layer (§6), not by the application.
- **Denial-of-service protection.** Rate limiting is best-effort abuse mitigation (§6), not a
  DoS defense.
- **Forward secrecy, deniability, or post-compromise recovery** of individual pastes.

## 3. Zero-knowledge boundary & metadata leakage

The zero-knowledge property covers **plaintext only**. secbin is **not** anonymous and **not**
metadata-free. The service and Cloudflare can still observe, and may log:

- Client **IP addresses** and approximate geolocation.
- **Timestamps** of creation, reads, and deletion.
- **Paste IDs** (they are the storage keys and appear in request paths).
- **Ciphertext size** (an upper bound on, and correlate of, plaintext size).
- **Expiry**, the **view limit**, the **remaining view count**, and lifecycle events.
- **Access patterns** (how often / from where a paste is fetched).
- **User-Agent** and other standard request metadata.
- When deployed behind Cloudflare Access: the **identity** of users who authenticate to create
  pastes, as recorded in Access logs. Anonymous link recipients on bypassed paths are not
  identified by Access.

The **delete token is deliberately kept out of this metadata**: it is sent in the
`X-Delete-Token` request header, never in the URL, so it does not appear in logged request
URLs; the server stores and compares only its SHA-256 (`SPEC.md` §7, §10). The decryption
secret `F` never appears in **any** request — URL, header, or body.

If you need anonymity or traffic-analysis resistance, use additional tooling (e.g. Tor); it is
outside secbin's scope.

## 4. Frontend / XSS threat model — "XSS = key exfiltration"

Because the decryption key is in `location.hash`, **any script running on the page can read the
key and the decrypted plaintext.** A cross-site-scripting bug is therefore equivalent to a full
key/plaintext compromise. secbin treats XSS as a top-severity class and defends in depth:

- **Strict Content-Security-Policy** on every static-asset response (`public/_headers`):
  ```
  default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:;
  connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self';
  frame-ancestors 'none'; object-src 'none'
  ```
  No `unsafe-inline`, no `unsafe-eval`, no third-party origins. This CSP governs the HTML
  document and every asset the browser executes; the JSON `/api/*` responses (which the
  browser never renders as a document) instead carry `cache-control: no-store` and
  `x-content-type-options: nosniff` (`src/index.js`).
- **No third-party JavaScript, no CDN scripts, no analytics, no outbound calls.** All
  scripts, styles, and fonts are first-party and self-hosted, and the Worker itself makes no
  outbound requests.
- **Decrypted content is rendered by DOM construction only** (`document.createElement` +
  `textContent`). Decrypted user content is **never** assigned to `innerHTML`.
- **Markdown supports a safe subset with no raw HTML.** Link `href`s are restricted to an
  `http` / `https` / `mailto` scheme allowlist; `javascript:`, `data:`, and unknown schemes are
  dropped. A dedicated adversarial test suite (`test/markdown.test.js`) exercises `<script>`,
  `onerror`, `javascript:` URLs, `data:` images, and raw-HTML injection.
- **No dangerous sinks:** no `eval`, `new Function`, `document.write`, inline event handlers,
  `javascript:` URLs, or dynamic `<script>` creation anywhere in the codebase.

### Deployment-compromise limitation (important)

secbin's client-side encryption protects plaintext from the **storage/server** layer, but the
browser still **downloads and trusts JavaScript from the server**. An attacker who can modify
what the server serves (a compromised deployment or repository, a malicious operator, a
supply-chain compromise, or a TLS/CDN MITM) could serve **malicious JavaScript that reads the
fragment key and the decrypted plaintext**. Zero-knowledge server storage does **not** defend
against a compromised delivery of the application itself. This is a fundamental limitation of
all in-browser end-to-end encryption delivered over the web. Mitigations (HTTPS-only, strict
CSP, minimal first-party surface, no third-party code, restricted write access to the
repository and the Cloudflare account) reduce but cannot eliminate this trust.

### The CLI client

`cli/` is the upstream binthere CLI, kept in the repository for test coverage of the shared
modules. It is **not published by secbin** and defaults to the upstream public server; point
it at your own deployment explicitly if you use it. Its trust anchor is the npm supply chain
rather than the paste server. Share URLs passed as command-line arguments are visible to other
local processes and may enter shell history; `binthere get -` (URL on stdin) avoids this.

## 5. Trust boundaries

| Boundary | Trusted with plaintext? | Notes |
|---|---|---|
| The user's browser + the served JS | **Yes** (unavoidable) | See the deployment-compromise limitation, §4. |
| The CLI process + its installed code | **Yes** (unavoidable) | See "The CLI client", §4. |
| Network in transit | No | TLS protects transport; the fragment is never sent regardless. |
| Cloudflare Access | No (plaintext) | Decides who may reach the create side; sees request metadata only. |
| Cloudflare Worker / edge | No (plaintext) | Sees ciphertext + metadata (§3). |
| KV store / `BurnPaste` DO | No (plaintext) | Stores ciphertext + `SHA-256(deleteToken)` + metadata. |
| Anyone holding the full URL (+password) | **Yes** | By design — that is the capability being shared, up to the view limit. |

## 6. Access control and rate limiting

### Who can create pastes

secbin has no built-in authentication. The intended deployment puts the whole hostname behind
**Cloudflare Access** (Allow policy for your users) and exempts only the paths a link recipient
needs with a **Bypass** policy (`p/*`, `api/paste/*`, `js/*`, `css/*`, `fonts/*`, `img/*`). The
create endpoint `POST /api/paste` is not in the bypass set and therefore requires login. See
`ARCHITECTURE.md` → *Access control* and `README.md` for the exact configuration and a
verification test. Misconfiguring these paths — in particular entering `api/paste` without the
`/*` wildcard, or using an Allow policy instead of Bypass on the public paths — either exposes
creation publicly or breaks share links.

Also disable the `workers.dev` route and preview URLs unless they are covered by the same
Access applications, so the site is not reachable at an unprotected address.

### Rate limiting

Paste creation is rate-limited using Cloudflare's native Workers Rate Limiting binding, keyed by
client IP. This is **abuse mitigation, not authentication**, and is **fail-open**: if the
limiter is unavailable, requests are allowed rather than blocked. Limits are configured in
`wrangler.toml`.

### API surface hardening

- **No CORS headers, deliberately.** The API never sends `Access-Control-Allow-Origin`, so
  browsers on other origins cannot read API responses. The web app is same-origin and needs no
  CORS; adding CORS would only widen the abuse surface.
- **`POST /api/paste` requires `Content-Type: application/json`** (else `415`). A cross-origin
  `application/json` POST is not a CORS "simple request", so the browser sends a preflight —
  which fails without CORS headers.
- **Cross-site create requests are rejected.** A create request with
  `Sec-Fetch-Site: cross-site` gets `403`. This is defense in depth for Access-protected
  deployments: a hostile page must never be able to create pastes using a signed-in visitor's
  Access session.
- **Consumption is never a simple request.** `GET` on a view-limited id only ever returns the
  non-consuming head; spending a view requires `POST /api/paste/:id/consume` with the custom
  `X-Burn-Intent: consume` header (CORS non-simple ⇒ cross-origin preflight fails), and
  `Sec-Fetch-Site: cross-site` senders are rejected with `403`. Merely knowing an id — via an
  `<img>` tag, a prefetching proxy, or a link-scanning bot — grants no power to spend a view.
- **The request body is read under a hard cap, incrementally.** `POST /api/paste` streams the
  body and aborts as soon as the running byte count exceeds `MAX_BODY` (4 MiB), returning
  `413`. The `Content-Length` header, when present, is only an honest-client fast path.
- **All settings are validated server-side.** Expiry (1 minute – 365 days or a preset) and
  view limits (1 – 100 000) are re-validated by the Worker with the same fail-closed rules as
  the client; the remaining-view counter is owned by the server and cannot be set by a client.

## 7. Cryptographic summary

See `SPEC.md` for exact byte-level details. In brief: per-paste random 256-bit CEK; AES-256-GCM
with fresh 96-bit IVs (never reused per key); password stretched with PBKDF2-HMAC-SHA256
(310 000 iterations, versioned); high-entropy fragment secret combined with the stretched
password via HKDF-SHA256 to wrap the CEK; canonical AAD binding all security-relevant metadata;
128-bit CSPRNG paste IDs; 256-bit CSPRNG delete tokens stored only as `SHA-256` and compared in
constant time; decompression bounded to defend against gzip bombs. All parsing fails closed and
is prototype-pollution-safe. The cryptographic protocol, including its `"binthere/v1"` wire
labels, is unchanged from binthere v1.

## 8. Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub's private vulnerability reporting
for this repository: **<https://github.com/kaerez/bin/security/advisories/new>**. Do not open
a public issue with exploit details. Please include reproduction steps and the affected commit.
There is no bug-bounty program.

Vulnerabilities in the original binthere code that also affect upstream should additionally be
reported to the binthere maintainer as described in the upstream repository.

## 9. Supported versions

Only the latest `main` branch of <https://github.com/kaerez/bin> is supported. The paste format
is versioned (`v`); format-breaking cryptographic changes ship under a new `v` with an updated
`SPEC.md` and new test vectors.
