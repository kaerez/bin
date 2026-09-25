# secbin — Protocol Specification (v2)

> **Status: v2, frozen by test vectors.** This document defines share format **v2** — the exact
> byte-level cryptographic protocol, the note and file-share formats, and the HTTP API. v2
> replaces v1 (inherited from [binthere](https://github.com/nxfu/binthere)) and is **not
> backward compatible**: v1 links (`"binthere/v1"` labels, PBKDF2) can no longer be opened.
> Any change to §1–§5 or §12 requires a new `v`, an updated spec and regenerated vectors
> (`node test/genvectors.mjs`, cross-checked by `python tools/verify-vectors.py`) *before*
> code changes.

Everything that describes shared content is encrypted and decrypted **only on the client** (the
browser, or the official CLI — both implement this spec and are verified against the same
vectors). The decryption secret lives in the URL **fragment** (`#…`) and is never sent to the
server. See `SECURITY.md` for the threat model.

---

## 1. Notation & primitives

- Randomness: `crypto.getRandomValues()` only.
- `b64url(x)` = unpadded, URL-safe Base64 (RFC 4648 §5). Decoders accept only the **canonical**
  encoding (no characters outside the alphabet, no length ≡ 1 mod 4, zero unused bits in the
  final character), so no byte string has two encodings.
- `UTF8(s)` = UTF-8 encoding; `NFC(s)` = Unicode NFC normalization; `‖` = concatenation.
- Primitives:
  - **AES-256-GCM** — 96-bit IV, 128-bit tag.
  - **Argon2id** (RFC 9106, version 0x13) — password stretching; memory `m = 65536 KiB` (64 MiB),
    lanes `p = 1`, time cost `t` (1…10, default 3), output 32 bytes.
  - **HKDF-SHA256** — 32-byte outputs; an empty salt means the RFC 5869 all-zero salt.
  - **SHA-256** — proof hashes, token hashes.

### Random values (per share)

| Value | Size | Purpose |
|---|---|---|
| `CEK` | 32 B | Content-encryption key. |
| `F` | 32 B | Fragment secret, placed in the URL fragment. |
| `iv_content`, `iv_wrap` | 12 B each | GCM nonces for content and CEK wrap. |
| `salt_kdf` | 16 B | Argon2id salt (password-protected shares only). |
| `id` | 16 B | 128-bit share id entropy. |
| `deleteToken`, upload token, download grant | 32 B each | Capability tokens (server stores SHA-256 only). |
| `FK` | 32 B | File-share stream key (inside the encrypted manifest, §12). |

---

## 2. Key hierarchy and access proofs

```
pw_ikm    = password ? Argon2id(UTF8(NFC(password)), salt_kdf, m=64 MiB, t=adata.iter, p=1, 32 B) : "" (0 bytes)
KEK       = HKDF(ikm = F,   salt = pw_ikm, info = "secbin/v2 kek",        32 B)
linkProof = HKDF(ikm = F,   salt = "",     info = "secbin/v2 link-proof", 32 B)
keyProof  = HKDF(ikm = KEK, salt = "",     info = "secbin/v2 key-proof",  32 B)

wk = AES-256-GCM(key = KEK, iv = iv_wrap,    plaintext = CEK,     aad = AAD)
ct = AES-256-GCM(key = CEK, iv = iv_content, plaintext = payload, aad = AAD)

acc.lh = b64url(SHA-256(linkProof))
acc.kh = b64url(SHA-256(keyProof))
```

- The server stores `acc` and never returns it. A reader sends `linkProof` and `keyProof`
  (`X-Link-Proof`, `X-Key-Proof`); the server compares their SHA-256 with `acc` in constant time
  **before** releasing `wk`/`ct`, spending a view or issuing a download grant (§10).
- `linkProof` depends only on `F`: a mismatch means the link is wrong (`bad_link`). `keyProof`
  depends on `F` and the password: a mismatch with a matching link proof means the password is
  wrong (`bad_password`). Neither spends a view.
- Knowing `acc` (or observing proofs) does not reveal `F`, the password, `KEK` or `CEK`. Guessing
  a password needs `F` *and* an online, rate-limited request; the head never contains `wk`.

### Security properties

- `F` alone opens a password-less share; with a password, `F` and the password are both needed.
- Distinct HKDF labels separate the KEK and the two proofs; no key is reused across roles.
- All security-relevant `adata` is bound by the canonical AAD (§4) to both GCM operations.

---

## 3. Compression

`payload = gzip(UTF8(text))` if that is shorter than `UTF8(text)` (`adata.comp = "gzip"`), else
the raw bytes (`"none"`). Decompression is capped at `MAX_PLAINTEXT` (1 MiB) — gzip-bomb defense.

---

## 4. Canonical AAD

Fixed order, newline-terminated, independent of JSON key order:

```
secbin/v2\n
alg=A256GCM\n
kdf=<hkdf|argon2id-hkdf>\n
iter=<adata.iter>\n
comp=<gzip|none>\n
fmt=<plaintext|code|markdown|url|secret|files>\n
bar=<0|1>\n
ivc=<b64url iv_content>\n
ivw=<b64url iv_wrap>\n
skdf=<b64url salt_kdf, or empty>\n
```

---

## 5. Share format v2

### 5.1 `adata` (non-secret, AAD-bound)

| Field | Type | Rules |
|---|---|---|
| `alg` | string | `"A256GCM"` |
| `kdf` | string | `"hkdf"` (no password) or `"argon2id-hkdf"` |
| `iter` | int | `0` for `hkdf`; Argon2id `t` ∈ [1, 10] for `argon2id-hkdf` |
| `comp` | string | `"gzip"` or `"none"` |
| `fmt` | string | `"plaintext"`, `"code"`, `"markdown"`, `"url"`, `"secret"` (notes, §5.6) or `"files"` (file-share manifest, §12) |
| `bar` | bool | `true` = view-limited, `false` = unlimited views |
| `ivc`, `ivw` | b64url | 12 bytes each |
| `skdf` | b64url | 16 bytes for `argon2id-hkdf`, empty string for `hkdf` |

### 5.2 Create body (client → server)

```json
{ "v": 2, "ct": "…", "wk": "…", "adata": { … }, "meta": { "expire": "24h", "views": 3 }, "acc": { "lh": "…", "kh": "…" } }
```

- `meta.expire`: `"<n>m" | "<n>h" | "<n>d"`, 60 s … 365 days. `meta.views` (1…100 000) only when
  `bar` is true (absent ⇒ 1). `created`, `expires`, `left` are server-set and rejected on create.
- `meta.deletable`: optional, only ever `true` — the sender lets whoever opens the share delete
  it at once (§10 `POST …/expire`). Allowed only when the account's `openerDelete` limit is on;
  a file share's manifest must carry the same flag as its upload init.
- `acc.lh`, `acc.kh`: 32-byte hashes (43 b64url chars).

### 5.3 Head (public, `GET`)

`{ v, adata, meta }` — never `wk`, `ct` or `acc`. `meta` gains `created`, `expires` (absolute
Unix seconds) and, for view-limited shares, `views` and `left` (`null` = raised to unlimited).

### 5.4 Opened note (`POST …/open` with matching proofs)

`{ v, ct, wk, adata, meta }`.

### 5.5 Validation

Every object is validated fail-closed: exact key sets, prototype-pollution-shaped keys
rejected, types/ranges/lengths checked, `v` must be 2, `views`/`left` only with `bar`. Clients
validate heads *before* any key derivation (bounded `iter` ⇒ bounded Argon2 work).

### 5.6 Typed notes: links and credentials

Both are ordinary notes whose plaintext has a fixed shape (`public/js/sharetypes.js`). The
server sees only `fmt`; recipients validate the decrypted payload fail-closed and fall back to
showing it as inert text.

- **`url`** — exactly one absolute URL, at most 2048 characters, no whitespace or control
  characters, **no user name or password** (`https://user:pw@…` is refused: use a credential
  share). The sender's client checks it against the account's `urlRules` (`scheme:<name>`,
  `scheme:*`, `re:<pattern>` matched case-insensitively against the `href`; default
  `["scheme:http", "scheme:https"]`); `javascript:`, `data:`, `vbscript:`, `file:`, `blob:`,
  `about:` and browser-internal schemes are refused by senders and recipients alike. `http:` /
  `https:` links need a host. Clients store the parsed `href`. Recipients are shown the host as the
  browser resolves it (punycode, e.g. `xn--80ak6aa92e.com`) with a warning when it differs from
  its Unicode form or is not HTTPS; opening needs an explicit second click and uses
  `noopener,noreferrer`. There is **never** an automatic redirect.
- **`secret`** — JSON `{ "v": 1, title?, username?, password?, url?, notes?, totp? }`, at least
  one field, all strings (max lengths 200 / 500 / 4096 / 2048 / 20000 / 1024), no other keys.
  `url` follows the `url` rules; `totp` is a base32 seed (≥ 80 bits) or an `otpauth://totp/…`
  URI (SHA-1/256/512, 6–8 digits, period 1–300 s). One-time codes are computed locally per
  RFC 6238. Recipients see the password and seed masked until revealed.

---

## 6. Limits

| Constant | Value | Where |
|---|---|---|
| `MAX_PLAINTEXT` | 1 MiB | notes / manifest plaintext, and decompression cap |
| `MAX_CT_B64` | 3 000 000 | server: max `ct` length (else 413) |
| `MAX_BODY` | 4 MiB | server: max JSON request body |
| `MAX_BURN_RECORD` | 1 900 000 | server: max serialized DO record (view-limited notes, manifests) |
| `MAX_VIEWS` | 100 000 | client + server |
| `MIN_TTL` / `MAX_TTL` | 60 s / 365 d | client + server |
| `CHUNK` | 8 MiB | file-share plaintext chunk |
| `PAD` | 64 KiB | file-share stream padding unit |
| `HARD_MAX_SHARE_BYTES` | 2 GiB | ceiling for the admin-configured share cap (default 100 MiB) |
| `MAX_ENTRIES` | 10 000 | manifest entries |

Per-user limits (§13) may be lower.

---

## 7. Identifiers and tokens

- **Share id** = class prefix ‖ `b64url(random(16))` (23 chars):
  `k` — unlimited-view note (KV) · `b` — view-limited note (`BurnPaste` DO) · `f` — file share
  (`FileShare` DO + R2).
- **Delete token / upload token / download grant** = `b64url(random(32))`. The server stores only
  `hex(SHA-256(token))` and compares in constant time. Tokens travel in headers, never URLs.
- **API key** = `"sbk_" ‖ b64url(random(32))`, stored as SHA-256. Sent as
  `Authorization: Bearer <key>`, and accepted only on the endpoints marked "key" in §10.
- **Share URL** = `<origin>/p/<id>#<b64url(F)>`.

---

## 8. Views

- View-limited shares live in a Durable Object, one per id. Each open verifies both proofs and
  decrements `left` atomically; exactly `views` openers succeed, the rest get `410`.
- The last view purges a note immediately. A file share becomes *closed*: no new opens, but
  download grants already issued keep working until they expire, then the share and its R2
  objects are purged.
- Owners may raise `views` (or switch to unlimited if allowed) and extend `expires`; never lower.
- `404` vs `410`: a malformed id is `404`; a well-formed DO id that is gone (never existed,
  consumed, expired, revoked) is `410`; KV notes answer `404` when missing.

## 9. Expiry

Notes in KV use `expirationTtl`; DO-backed shares use an alarm at `meta.expires`. File-share
alarms also delete the R2 objects; an unfinished upload is purged at its deadline (admin
setting, default 1 h).

---

## 10. HTTP API

All responses are JSON with real status codes; errors are `{ "error": "<code>", "message": "…" }`.
The API sends **no CORS headers**. State-changing requests must be non-simple (JSON content
type, or a custom header), and `Sec-Fetch-Site` values `cross-site` and `same-site` are refused
(`403 cross_site`).

Common errors on any route:
- `503 not_configured`: a required Cloudflare binding is missing. The name is logged, not returned.
- `503 server_not_configured`: `SIG`/`ENC` are missing or invalid (auth and private routes only).
- `403 account_disabled`: a disabled account's session or API key. The session cookie is also
  cleared.
- **Human check (Cloudflare Turnstile)**, only when `TURNSTILE_SITEKEY` and `TURNSTILE_SECRET`
  are both set: `POST /api/auth/login`, `POST /api/private/me/password` and
  `POST /api/public/paste` / `POST /api/public/file` need `X-Secbin-Turnstile: <token>`, issued
  for the action `login`, `password` or `public-share` respectively on this hostname. Each token
  is accepted once. Errors: `403 turnstile_required` (no token), `403 turnstile_failed` (rejected,
  expired, reused, or for another action or hostname), `503 turnstile_unavailable` (siteverify
  unreachable; fails closed). Setup, admin resets, file chunks/finalize and API keys are exempt.
- `403 scope_denied`: an API key without the scope the route needs (`notes` for
  `POST /api/private/paste`, `files` for the file routes, `policy` for `GET /api/private/policy`).

### Public (capability-gated)

| Method & path | Notes | Success | Errors |
|---|---|---|---|
| `GET /api/config` | public viewer policy; `turnstile`: the Turnstile site key, or `null` when the human check is off | 200 | |
| `GET /api/paste/:id` | head (§5.3) | 200 | 404, 410, 429 |
| `POST /api/paste/:id/open` | `X-Link-Proof`, `X-Key-Proof`; spends a view if limited | 200 opened note | 400 `missing_proof`, 403 `bad_link` / `bad_password` / `cross_site`, 404, 410, 429 |
| `DELETE /api/paste/:id` | `X-Delete-Token` | 200 | 400, 403 `bad_token`, 404 |
| `GET /api/file/:id` | head | 200 | 410, 429 |
| `POST /api/file/:id/open` | proofs; spends a view; issues a grant | 200 `{paste, grant, grantExpires, chunks, padded}` | as notes; at most 20 live grants per client (a reopen replaces its oldest); 429 `busy` (+ `Retry-After`) when 2000 are live |
| `GET /api/file/:id/chunk/:i` | `X-Download-Grant` | 200 `application/octet-stream` | 403 `bad_grant`, 404, 410 |
| `DELETE /api/file/:id` | `X-Delete-Token` | 200 | as notes |
| `POST /api/{paste,file}/:id/expire` | "delete now" by a recipient: the same two proofs as `open`; only when `meta.deletable` and the sender's account still has `openerDelete`; not after a file share's last view; spends no view | 200 `{status:"deleted"}` | 400 `missing_proof`, 403 `bad_link` / `bad_password` / `not_allowed`, 423 `share_locked`, 404/410 |
| `POST /api/paste` | v1 anonymous create — removed | — | 410 |

Every `404`/`410` for an id that was never a share, `bad_link`, `bad_password`, `bad_grant` and
`bad_token` counts as an **invalid** failure for the caller's IP (§13). A `404`/`410` for a share
that existed (still in the share index: expired, used up, revoked or deleted within the last 30
days) is not counted.

### Public creation (anonymous, off by default)

Only when the admin sets `public.enabled`; otherwise `403 public_disabled` (the profile answers
`{enabled:false}`). Shares are created as the built-in public account; the bodies, validation
and results are exactly those of the private routes. See SECURITY.md "Public (anonymous)
access" for the counting modes.

| Method & path | Notes | Success | Errors |
|---|---|---|---|
| `GET /api/public/profile` | what the composer needs | 200 `{enabled, tracking, notice, limits, caps, viewer, quotas}` | |
| `GET /api/public/t` | resolve the tracker: cookie `__Host-secbin_aid`, `If-None-Match`, and `X-Secbin-Aid-Copies: ls=<id>;idb=<id>` | 200 `{mode, aid, status: new\|ok\|healed}` + cookie + `ETag`; 304 when every copy agrees; `{mode:"ip", aid:null}` in `ip` mode | 403 `tracker_conflict` / `tracker_blocked` |
| `POST /api/public/paste` `{paste}` (any `label` is dropped) | tracker modes: the cookie and `X-Secbin-Aid` must match | 201 as §10 private | 428 `tracker_required`, 403 `tracker_blocked` or any creation limit, 429 `quota_exceeded` / `tracker_rate_limited` (a new id's first creation over the per-network limit) / `busy` |
| `POST /api/public/file` | as the private route | 201 | as above |
| `PUT /api/public/file/:id/chunk/:i`, `POST …/finalize` | `X-Upload-Token` | as the private routes | as the private routes |

Admin: `GET /api/private/admin/public[?blocked=true]` → `{profile, trackers: {rows, total,
blocked}}`; `POST /api/private/admin/public/trackers/:prefix` `{action: unblock|block|forget}`.

### Auth

| Method & path | Body | Result |
|---|---|---|
| `GET /api/auth/session` | — | `{configured, authenticated, user, impersonatedBy}` |
| `GET /api/auth/setup` | — | `{enabled, ownerExists?, configured}` |
| `POST /api/auth/setup` | `{token, username, salt, t, proof}` | owner created or recovered; 404 if `AUTHN` unset; 403 wrong token; 410 token already used |
| `POST /api/auth/prelogin` | `{username}` | `{salt, t}` (a stable fake salt for unknown users; `t` is always the default, 3) |
| `POST /api/auth/login` | `{username, proof}` (+ `X-Secbin-Turnstile` when on) | session cookie; 401, 423 locked, 403 disabled, 403 `turnstile_*`, 429, 503 not configured |
| `POST /api/auth/logout` | `X-Secbin-Intent: 1` | session revoked |

`proof = b64url(Argon2id(UTF8(NFC(password)), salt, m=64 MiB, t, p=1, 32 B))`. The server stores
`verifier = hex(SHA-256(UTF8("secbin-auth/v2") ‖ proof_bytes))`. Account passwords must use
`t = 3`, so prelogin reveals nothing about which accounts exist.

### Private (session, or API key where marked)

| Method & path | Auth | Purpose |
|---|---|---|
| `POST /api/private/paste` `{paste, label?}` | session / key | create a note → 201 `{id, deletetoken, expires}` |
| `POST /api/private/file` `{views, expire, padded, files?, maxFile?, types?, depth?}` | session / key | start a file share → 201 `{id, uploadtoken, deletetoken, chunks}` |
| `PUT /api/private/file/:id/chunk/:i` (octet-stream, `X-Upload-Token`) | session / key | upload chunk `i` (exact size, §12) |
| `POST /api/private/file/:id/finalize` `{paste, label?}` (`X-Upload-Token`) | session / key | activate with the encrypted manifest |
| `GET /api/private/policy` | session / key | what the client must check itself before creating: `{url, urlRules}` for the channel used |
| `GET /api/private/me` | session | profile, effective limits, quotas, viewer policy, `passwordPolicy` `{pwMinLength, pwUpper, pwLower, pwDigit, pwSymbol}` (the browser enforces it; the server cannot) |
| `POST /api/private/me/password` `{current, salt, t, proof}` | session | change password (ends other sessions). Never blocked by a login lockout. A wrong `current` → 403 `wrong_password`, also counted against the IP's login guard. The 10th wrong attempt in the window (default) → 401 `session_revoked`, which ends every session of the account |
| `GET /api/private/me/activity` | session | own activity (never shows the actor) |
| `GET/POST /api/private/me/keys` `{name, expiresInSec?, scopes?}`, `DELETE …/keys/:id` | session | API keys; `scopes` is a subset of `notes`, `files`, `policy` (default all three; empty or unknown → 400 `invalid_scopes`). Listing returns each key's `scopes` |
| `GET /api/private/shares`, `PATCH /api/private/shares/:id`, `POST …/:id/revoke` | session | My shares |
| `/api/private/admin/*` | owner session, not impersonating | overview, settings, limits, quotas, viewer rules, users (+ password, unlock, impersonate, keys), unimpersonate, audit, guard, ip-rules, shares |
| `GET /api/private/shares/:id/opens` | session | read receipts of my share → `{total, fields, rows: [{ts, …allowed fields}]}` (newest first, at most 200) |
| `GET /api/private/admin/shares/:id/opens` | owner | the same with every field: `ip, country, region, city, browser, browser_ver, os, langs` |
| `POST /api/private/admin/logs/clear` `{current, scope: "all"\|"user", user?, before?}` | owner | delete activity entries (all, or about `user`; only `ts < before` when given) → `{deleted}`; `current` is the owner's password proof (403 `wrong_password`); leaves no record |
| `GET /api/private/admin/shares` `?users=id,id&kind=&status=&q=&locked=true\|false&createdFrom=&createdTo=&expiresFrom=&expiresTo=&limit=&offset=` | owner | every user's shares, filtered (times in unix seconds, each bound optional) → `{rows, total}` |
| `GET/PATCH /api/private/admin/shares/:id`, `POST …/:id/revoke`, `POST …/:id/lock` `{locked}` | owner | inspect, change (increase-only, protocol maxima), revoke, lock/unlock — logged as admin actions |
| `POST /api/private/admin/export` `{current, system?, users?: "all"\|[id…], credentials?, config?}` | owner | the plaintext `secbin-export/v1` document for the browser to encrypt (never the owner) |
| `POST /api/private/admin/import` `{current, document, decisions: {system, users: {name: {as?, overwrite?}}}, dryRun}` | owner | `dryRun` (default) → `{plan}`; otherwise applied atomically → `{applied: true, plan}`; `409 import_conflicts` with the plan when anything would conflict |

`current` is the owner's password proof (as for a password change); a wrong one is `403
wrong_password`. The export file format is described in `src/lib/portable.js` (document) and
`public/js/exportcrypt.js` (envelope).

A **locked** share answers `423 share_locked` to its sender's `PATCH`/revoke, to delete-by-token
and to a recipient's "delete now".

Creation limits: `url` and `secret` notes need the account's `text` limit **and** `url` /
`secret` respectively (`403 url_disabled` / `secret_disabled`); `meta.deletable` needs
`openerDelete` (`403 opener_delete_disabled`). All three are off by default. They count as notes
for quotas; the share index records `kind` `url` / `secret`.

---

## 11. Test vectors

Fixed inputs: `F = 00…1f`, `CEK = 20…3f`, `iv_content = 11×12`, `iv_wrap = 22×12`,
`salt_kdf = 33×16`, plaintext `"secbin vector — zero knowledge ✓"`, password `"correct horse"`,
`t = 3`. `test/vectors.expected.txt` pins the AAD, `pw_ikm`, both proofs and their hashes, `wk`
and `ct` for the no-password and password branches; `test-node/crypto.test.js` asserts them, and
`tools/verify-vectors.py` re-derives them independently in Python (`cryptography` +
`argon2-cffi`). Argon2id itself is checked against the phc-winner-argon2 reference vector
(`password`/`somesalt`, t=2, m=64 MiB, p=1 →
`09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7`).

---

## 12. File shares

### 12.1 Manifest

A file share's manifest is a v2 share (§5) with `adata.fmt = "files"`. Its plaintext is JSON:

```json
{ "v": 2, "fk": "<b64url 32 B>", "chunk": 8388608, "total": 12345,
  "entries": [ { "path": "docs/a.txt", "type": "text/plain", "size": 5, "mtime": 0, "off": 0 },
               { "path": "empty", "dir": true } ],
  "view": null }
```

- `entries`: files in stream order with contiguous `off`; `dir` entries record (empty) folders.
- `path`: relative POSIX path; each segment non-empty, not `.`/`..`, ≤ 255 UTF-8 bytes; whole
  path ≤ 4096 bytes; no leading `/`, backslash, NUL or control characters; no duplicates; a path
  may not be both a file and a folder. Invalid manifests are rejected (never repaired).
- `type`: lowercase `type/subtype`, no parameters.
- `view`: `null`, or the sender's viewer-policy snapshot `{ maxBytes, rules: [{match, value, renderer}] }`
  (`match` ∈ mime | ext | any; `renderer` ∈ text | markdown | code | image | pdf | media).

### 12.2 Packed stream and chunks

All files are concatenated in entry order (`total` bytes), then zero-padded to
`padded = max(PAD, ceil(total / PAD) · PAD)`. The stream is cut into `n = ceil(padded / CHUNK)`
chunks; chunk `i` is encrypted as

```
chunk_ct[i] = AES-256-GCM(key = FK, iv = BE96(i), aad = UTF8("secbin-file/v2\nidx=" ‖ i ‖ "\ntotal=" ‖ n ‖ "\n"), chunk_pt[i])
```

`FK` is unique per share, so the deterministic IV never repeats; the AAD binds position and
count (no reordering or truncation). The server sees only `padded` and `n`, and enforces the
exact ciphertext size of every chunk: `min(CHUNK, padded − i·CHUNK) + 16`.

### 12.3 Upload and read

1. `POST /api/private/file` with `views` (or `null`), `expire`, `padded`; `files` (count) and
   `maxFile` (largest file size) only when the account has such limits; `types` (the
   de-duplicated `[{ext, mime}]` of the files, `ext` lower-case without the dot, `""` for none)
   only under a file-type policy and `depth` (the deepest folder level: `a.txt` → 0,
   `x/y/a.txt` → 2, an empty folder counts itself) only under a folder-depth policy. A missing
   required declaration is `400 declaration_required` with the policy
   `{mode, rules, maxFolderDepth}` attached, so clients can check locally and resend; a refused
   type is `403 file_type_not_allowed` (with `refused`), too deep is `403 folder_too_deep`.
   Rules are `ext:<ext>` or `mime:<type>/<subtype|*>`; mode `allow` refuses types matching no
   rule, `block` refuses types matching any (`public/js/filepolicy.js`). The server checks
   capabilities, limits, policy and quotas, then creates a pending share (upload deadline).
2. `PUT …/chunk/:i` for every `i` (retries are idempotent — same bytes).
3. `POST …/finalize` with the manifest share; `bar`, `views` and `expire` must match step 1.
4. Readers open with proofs (§10) and receive a **download grant** (default 60 min, capped at
   expiry); chunks are fetched with `X-Download-Grant`, decrypted, and files sliced out of the
   stream.

---

## 13. Accounts, limits and protection (server-side, non-cryptographic)

- **Sessions**: cookie `__Host-secbin_sess` (HttpOnly, Secure, SameSite=Strict) holding a
  compact JWE (`alg: dir`, `enc: A256GCM`, key `ENC`) that wraps a JWS (`HS256`, key `SIG`) with
  claims `{sid, uid, act?, ver, iat, lat, exp}`. Checked against current state on every request
  (revoked `sid`, disabled user, `ver` = the user's session version — bumped by password changes,
  resets and disables); idle and absolute timeouts are admin settings.
- **Limits** resolve per request: user override → global default → built-in default. API-channel
  limits and quotas can only restrict further. Quota windows are fixed buckets (UTC calendar
  for months/years); every creation counts toward all-channel quotas, API creations also toward
  API quotas.
- **Guard**: per-IP (IPv6 aggregated to a configurable prefix, default /64) failure counters for
  `login`, `setup` and `invalid`; *X failures within n seconds ⇒ block for n seconds*. Manual
  IP allow/block rules as an address, a CIDR block or an inclusive range `a-b` (same family;
  stored as CIDR when the range is exactly one aligned block; allow wins). Account lockout after
  X failed logins (owner exempt). Limits, quotas and the global caps never apply to the owner;
  `apiMaxKeys` `null` means no limit (at most 1000 keys). `POST /api/private/admin/users/:id/password`
  on the owner is `403 use_account_page`.
  `DISABLE_BFP=true` disables all of it; `DISABLE_BFP_SETUP=true` only for setup.
