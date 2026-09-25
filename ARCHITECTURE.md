# Architecture

secbin — by KSEC - Erez Kalman, based on [binthere](https://github.com/nxfu/binthere) — is a
**single Cloudflare Worker** that serves both the static frontend and the paste API, backed by
KV and a Durable Object. Consolidating everything into one Worker (one deploy, one
`wrangler.toml`) keeps the security-sensitive integration surface small.

## Request path

```
                    ┌──────────────────────────── Cloudflare Worker ────────────────────────────┐
                    │                                                                            │
 GET /              │  run_worker_first = ["/api/*"]                                              │
 GET /p/<id>        │       │                                                                     │
 GET /css/ /js/     │       ├─ path NOT /api/* ─▶ Static Assets (public/)                         │
 GET /fonts/ /img/  │       │                     • exact file, else SPA fallback index.html      │
                    │       │                                                                     │
 POST   /api/paste  │       └─ path /api/*    ─▶ src/index.js router                              │
 GET    /api/paste/:id                            ├─ POST   create  ─▶ KV or BurnPaste DO         │
 POST   /api/paste/:id/consume                    ├─ GET    read    ─▶ KV or BurnPaste DO (head)  │
 DELETE /api/paste/:id                            ├─ POST   consume ─▶ BurnPaste DO (spends 1)    │
                    │                             └─ DELETE delete  ─▶ KV or BurnPaste DO         │
                    └────────────────────────────────────────────────────────────────────────────┘
```

- `_headers` (in `public/`) applies the strict CSP + security headers to every asset response.
- `not_found_handling = "single-page-application"` makes `/p/<id>` serve `index.html`; the
  client reads the id from the path and the key from the `#fragment`.
- The Worker makes **no outbound requests** and the page loads nothing from any other origin.
  The upstream GitHub star-count route (`/api/stars`), the announcement banner, and
  `/.well-known/security.txt` were removed in secbin.

## Access control (deployment)

secbin itself has no login. Access to the *create* side is enforced in front of the Worker by
**Cloudflare Access**:

- one self-hosted application covers the whole hostname (empty path) with an **Allow** policy
  for your users;
- a second self-hosted application with a **Bypass** policy (Include: Everyone) exempts the
  paths an anonymous link recipient needs: `p/*`, `api/paste/*`, `js/*`, `css/*`, `fonts/*`,
  `img/*`.

Access applies the most specific matching path, so `POST /api/paste` (create) stays behind
login while share links work for anyone. Two details matter:

- The public paths need **Bypass**, not Allow. An Allow policy that includes Everyone still
  requires the visitor to authenticate.
- `api/paste/*` does not match the bare `/api/paste` create endpoint. Never enter `api/paste`
  without the wildcard: a wildcard-less Access path also covers the path itself, which would
  make creation public.

Step-by-step setup and a verification test are in `README.md` → *Protecting a deployment with
Cloudflare Access*.

## Zero-knowledge boundary

The decryption key is a random 256-bit **fragment secret `F`**, base64url-encoded after `#`.
The browser never puts `F` (or the plaintext) into any request. The Worker only ever sees:
ciphertext, a wrapped content key, non-secret `adata` (IVs, KDF params, format flags), the
expiry and view-limit settings, and — server-side only — a `SHA-256` of the delete token. See
`SPEC.md`.

## Storage routing (by id prefix)

Paste ids carry a 1-char class prefix so the read path picks the backend with **no extra
lookup**, and the client knows a paste is view-limited *before* fetching it:

- `k…` → **KV** (`PASTES`) — **unlimited views**. Immutable value `{ p: paste, dth }`, native
  `expirationTtl`. Reads are idempotent; eventual consistency is fine because the value never
  changes (a delete or expiry can take up to ~60 s to be visible at every edge location).
- `b…` → **`BurnPaste` Durable Object**, addressed `idFromName(id)` — **1 to 100 000 views**.
  The record `{ paste, dth, exp, left }` lives in DO storage. Every mutation runs inside
  `blockConcurrencyWhile`, so read-and-decrement is atomic: each `consume()` returns the
  ciphertext and decrements `left`, the consume that reaches 0 deletes the record, and later
  reads get `gone` → HTTP `410`. Exactly `views` consumers succeed under any concurrency. A
  **non-consuming peek** (`GET …?meta=1`) returns `adata`, the wrapped key and `meta`
  (including `views` and `left`) — never the ciphertext — so the client can verify a password
  *before* spending a view (`SPEC.md` §8). Expiry is a DO `alarm` plus a lazy check on read.

KV cannot perform an atomic read-and-decrement, which is why every finite view limit — not
only single-use — is stored in the Durable Object.

```
create ─┬─ bar=false (∞ views) ─▶ id="k…" ─▶ PASTES.put(id, {p, dth}, {expirationTtl})
        └─ bar=true  (N views) ─▶ id="b…" ─▶ BURN.get(idFromName(id)).create(paste, dth, ttl, N)

read   ─┬─ id[0]="k"                     ─▶ PASTES.get → 200 | 404
        ├─ id[0]="b" + POST …/consume    ─▶ BURN…consume() → 200 (left − 1) | 410 once left = 0
        └─ id[0]="b" + GET (or ?meta=1)  ─▶ BURN…peek()    → 200 head, no view spent | 410
```

## Modules

Shared, format-defining code lives in `public/js/` so the **browser imports it as a static
asset** and the **Worker bundles the same file** — one source of truth for the wire format:

| Module | Runs in | Responsibility |
|---|---|---|
| `public/js/bytes.js` | browser + worker + tests | base64url, SHA-256, CSPRNG bytes, constant-time hex compare |
| `public/js/format.js` | browser + worker + tests | paste format v1 validation (fail-closed), canonical AAD, expiry presets + custom-duration parser, view-limit bounds |
| `public/js/crypto.js` | browser + tests | the protocol: PBKDF2/HKDF/AES-GCM, gzip with decompression cap |
| `public/js/markdown.js` | browser + tests | safe Markdown → DOM (no raw HTML, href allowlist) |
| `public/js/highlight.js` | browser + tests | code detection + `textContent`-only syntax highlighting |
| `public/js/{api,ui,app}.js` | browser | fetch client, DOM helpers, controller/router (incl. view/expiry controls) |
| `public/js/{theme,theme-init}.js` | browser | light/dark toggle; pre-paint theme apply (no flash) |
| `public/js/qrcode.js` | browser | vendored MIT `qrcode-generator` (rendered as a `data:` image) |
| `src/index.js` | worker | API routing, size guard, cross-site guard, id allocation, error mapping |
| `src/burn-do.js` | worker | `BurnPaste` Durable Object (view counter, expiry alarm) |
| `src/lib/{ids,store,ratelimit}.js` | worker | id/token gen + hashing, KV/DO routing + expiry, rate-limit wrapper |

### The CLI client

`cli/` is the upstream binthere command-line client, kept so the shared modules stay covered by
its tests. secbin does **not** rebrand or publish it: it still installs as `binthere` and
defaults to the upstream public server (`cli/src/url.js`). Because npm cannot pack files outside
the package root, `cli/vendor/` holds **byte-identical copies** of
`public/js/{bytes,format,crypto,qrcode}.js` (`qrcode.js` lands as `qrcode.cjs`); a drift test
fails on any divergence, and `node cli/scripts/sync-shared.mjs` re-aligns them. Against an
Access-protected secbin deployment the CLI can read share links (the public paths are
bypassed) but cannot create pastes without an Access service token.

## Error semantics

Unlike the legacy PrivateBin API (which returned HTTP 200 for everything and signaled errors
in the JSON body to appease jQuery), secbin uses **real status codes**: `201` create, `200`
read/delete, `400` invalid, `403` wrong delete token or cross-site request, `404` missing,
`410` no views left/expired (view-limited), `413` too large, `415` wrong content-type, `429`
rate-limited. API JSON responses also carry `cache-control: no-store` and
`x-content-type-options: nosniff` (static assets get their security headers from
`public/_headers`).

## Testing

`@cloudflare/vitest-pool-workers` runs the Worker suites in the real `workerd` runtime, so Web
Crypto, `CompressionStream`, KV, and the Durable Object behave as in production.

- `test/burn.test.js` fires 25 simultaneous consumes at a single-view paste and asserts exactly
  one `200`.
- `test/limits.test.js` fires 20 at a 4-view paste and asserts exactly four `200`s, and covers
  the decreasing `left` count, custom-expiry bounds, the DO expiry alarm, unlimited-view KV
  pastes, create-time validation, and the cross-site create guard.
- The frozen crypto vectors are regenerated with `node test/genvectors.mjs` (spec-first, never
  hand-edited) and independently cross-checked by a from-scratch Python implementation
  (`tools/verify-vectors.py`). secbin does not change them.
- `test-dom/` runs DOM mount and accessibility checks (including WCAG AA contrast of the
  theme tokens) under happy-dom.
- The CLI suites under `cli/test/` run in plain Node, including the vendor-drift byte-compare
  against `public/js/`.

`npm test` runs all three projects; `npm run lint` runs ESLint. CI
(`.github/workflows/ci.yml`) runs lint, a byte-for-byte diff of the regenerated vectors
against `test/vectors.expected.txt`, and the suites on every push/PR.
