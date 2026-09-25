# Architecture

secbin — by KSEC - Erez Kalman, based on [binthere](https://github.com/nxfu/binthere) — is a
**single Cloudflare Worker** serving the static frontend, the share API, accounts and
administration, backed by KV, R2 and four Durable Object classes. One deploy, one
`wrangler.toml`.

## Request path

```
                  ┌────────────────────────────── Cloudflare Worker ──────────────────────────────┐
 GET /, /p/<id>   │ run_worker_first = ["/api/*", "/dashboard", "/dashboard/*"]                   │
 GET /js /css …   │   ├─ anything else ──────────▶ Static Assets (public/), SPA fallback           │
                  │   │                                                                            │
 /dashboard*      │   ├─ /dashboard* ─▶ session check (Directory) ─▶ assets + security headers    │
                  │   │     (login/ and setup/ are public; admin/ needs the owner)                 │
 /api/auth/*      │   ├─ /api/auth/*    session probe, setup/recovery, prelogin, login, logout     │
 /api/private/*   │   ├─ /api/private/* session or API key ─▶ create notes/files, me, keys,        │
                  │   │                  my shares, admin/*                                        │
 /api/paste/*     │   └─ public share API: heads, proof-gated opens, chunk downloads, deletes      │
 /api/file/*      │        every request: manual IP rules + Guard (brute-force) checks             │
                  └───────────────────────────────────────────────────────────────────────────────┘
```

- `public/_headers` applies the strict CSP to static assets; `src/lib/http.js` applies the same
  headers (plus `no-store`) to everything the Worker serves, including dashboard pages.
- The Worker makes no outbound requests; pages load nothing from other origins.

## Storage routing

| Id prefix / object | Store | Notes |
|---|---|---|
| `k…` | KV `PASTES` | Unlimited-view notes, native TTL; `{paste, dth, acc}` |
| `b…` | `BurnPaste` DO (per id) | View-limited notes; proof check + view spend in one critical section; alarm expiry |
| `f…` | `FileShare` DO (per id) + R2 `FILES` (`f/<id>/<i>`) | Upload state, view counting, download grants, alarm purges R2 |
| accounts & config | `Directory` DO (singleton, SQLite) | users, revoked sessions, API keys, limits, quotas + usage, settings, viewer rules, IP rules, share index, activity |
| brute-force state | `Guard` DOs (8 shards by IP hash) | per-scope failure counters and blocks with alarm cleanup |

The Directory is a Durable Object rather than KV because limits, quotas, lockouts and counters
need atomic, immediately consistent read-modify-write.

## Modules

| Path | Role |
|---|---|
| `src/index.js` | Router, dashboard gate, error mapping |
| `src/routes/public.js` | Heads, opens (proofs), chunk downloads, delete-by-token, public config |
| `src/routes/auth.js` | Session probe, setup/recovery, prelogin/login/logout |
| `src/routes/private.js` | Note creation, file upload, account, API keys, My shares |
| `src/routes/admin.js` | Owner administration |
| `src/lib/auth.js`, `jwt.js` | Sessions (JWS-in-JWE cookie), API-key auth |
| `src/lib/guard.js`, `ip.js` | Manual IP rules, Guard scopes, IPv4/IPv6/CIDR |
| `src/lib/settings.js` | Settings/limits/quotas schema and resolution |
| `src/lib/config.js` | Tolerant env-var readers (`AUTHN`, `SIG`, `ENC`, `DISABLE_BFP*`) |
| `src/*-do.js` | The four Durable Object classes |
| `public/js/{bytes,format,crypto,kdf,files,zip,mime}.js` | Shared protocol modules (browser + CLI, vendored and drift-tested) |
| `public/js/{view,viewer,pdfview,downloads}.js` | Public viewer, safe renderers, downloads |
| `public/dashboard/js/*.js` | Composer, My shares, account, admin, chrome |
| `public/sw.js`, `public/js/{pwa,install-banner}.js`, `public/manifest.webmanifest` | PWA: service worker (network-first, static assets only; never `/api/*` or `/p/*`), registration, install banner |
| `public/js/vendor/` | Pinned hash-wasm Argon2 and pdf.js builds (`tools/vendor.mjs`) |

## Zero-knowledge boundary

The browser (or CLI) derives everything secret from the fragment and the optional password and
sends the server only ciphertext, proof hashes, and non-secret settings. See `SECURITY.md` §3
for the exact list of what the server can observe.

## Testing

| Project | Runs | Covers |
|---|---|---|
| `vitest.config.js` | workerd (real KV/R2/DOs) | notes, files, auth, admin, quotas, guard, shares, formats, ids |
| `vitest.node.config.js` | Node | protocol vectors, Argon2id KAT, files/zip/mime |
| `vitest.dom.config.js` | happy-dom | XSS mount surfaces, viewer safety, a11y, folder walker |
| `cli/vitest.config.js` | Node | the `secbin` CLI |

`tools/verify-vectors.py` re-derives the vectors independently in Python.
