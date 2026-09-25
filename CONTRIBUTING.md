# Contributing to secbin

Thanks for your interest in secbin (based on [binthere](https://github.com/nxfu/binthere)). Issues and PRs are welcome at <https://github.com/kaerez/bin>.

**Read this first:** secbin is a **security-sensitive cryptographic application, not a normal
web app.** A bug here can leak the very secrets the app exists to protect. Before touching
anything, skim [`SPEC.md`](./SPEC.md) (the protocol + share format v2) and
[`SECURITY.md`](./SECURITY.md) (threat model and non-goals). [`ARCHITECTURE.md`](./ARCHITECTURE.md)
covers the request path.

## The two hard rules

Everything else is negotiable. These are not:

1. **Crypto is spec-first.** Any change to the cryptographic protocol, the paste format, or the
   canonical AAD **must** update [`SPEC.md`](./SPEC.md) **first** — never silently — then
   regenerate the frozen test vectors with `node test/genvectors.mjs`: paste its output into
   `test-node/crypto.test.js` **and** refresh the pinned copy
   (`node test/genvectors.mjs > test/vectors.expected.txt`), then cross-check with
   `python tools/verify-vectors.py`. Never edit the pinned hexes by hand. The format is
   versioned (`v`); a format-breaking change ships under a new `v`.
2. **Keep the CSP strict and rendering XSS-safe.** In this app, **XSS = key exfiltration.** No
   inline styles or scripts, no CDNs, no `innerHTML` on user content. Decrypted/user content is
   rendered with `createElement` + `textContent` only. Any new rendering path needs a case in
   `test/markdown.test.js` or `test-dom/`. Viewer renderers must never execute content.

## Getting set up

Requires Node.js ≥ 20 (`.nvmrc` pins 22) and npm. From the repository root:

```bash
npm install
cp .dev.vars.example .dev.vars   # AUTHN / SIG / ENC for local dev
npm run dev      # wrangler dev → http://localhost:8787 (KV, R2 and DOs emulated locally)
npm test         # vitest: workerd, Node and DOM projects
npm run test:watch   # workerd suites, watch mode
npm run test:coverage  # istanbul coverage (v8 provider can't run inside workerd)
npm run lint     # ESLint 9 flat config (eslint.config.js)
```

There is **no frontend build step**: `public/js/*.js` and `public/dashboard/js/*.js` are native ES modules served as-is (vendored libraries are rebuilt only by `node tools/vendor.mjs`). The
Worker under `src/` is bundled by wrangler. In `wrangler dev`, `request.cf` is absent, so
country/edge-only behavior won't show locally.

## Where things live

| Area | Files |
|---|---|
| **Format & AAD** (shared browser + Worker) | `public/js/format.js`, `public/js/files.js` — change ⇒ bump `v`, update `SPEC.md`, add vectors |
| **Crypto primitives** | `public/js/crypto.js`, `public/js/kdf.js` (Argon2id), `public/js/bytes.js` |
| **Backend** | `src/index.js` (router), `src/routes/*`, the DOs `src/{burn,fileshare,directory,guard}-do.js`, `src/lib/*` |
| **Frontend** | `public/index.html` + `public/js/view.js` (viewer), `public/dashboard/**` (signed-in app), `public/css/styles.css` |
| **CSP** | `public/_headers` and `src/lib/http.js` (keep them identical) |
| **Config** | `wrangler.toml` (assets, KV, R2, four DOs + migrations) — tracked in git; replace the KV ids for your own deployment (template: `wrangler.toml.example`); secrets via `wrangler secret put` |
| **Tests** | `test/` (workerd), `test-node/` (Node), `test-dom/` (happy-dom) (+ `test/genvectors.mjs`, `test/vectors.expected.txt`, `tools/verify-vectors.py`) |
| **CI** | `.github/workflows/ci.yml` — lint + byte-for-byte vector diff + full suite on every push/PR |

`public/js/{bytes,crypto,format,files,kdf,zip,mime,markdown}.js` are **shared** — the browser imports them as static
assets, the Worker bundles the pure ones, so the format stays a single source of truth.
Keep these modules dependency-light and free of Node/DOM globals *at import time* (functions may
use `document`; top-level code must not).

## Non-negotiable invariants

Beyond the two hard rules, preserve these (see [`SECURITY.md`](./SECURITY.md) and [`SPEC.md`](./SPEC.md) for the full rationale):

- **Fail closed.** All parsing/validation rejects on any anomaly. `public/js/format.js` is the
  single source of truth for format v2 and is prototype-pollution-safe. Keep it that way.
- **CSPRNG only.** Every key/IV/salt/id/token uses `crypto.getRandomValues` — never
  `Math.random`. IVs are never reused per key.
- **View counting and proof checks stay atomic.** They live in the `BurnPaste` / `FileShare`
  Durable Objects under `blockConcurrencyWhile`. Accounts, limits and quotas live in the
  `Directory` DO for the same reason. Don't move these to KV.
- **Real HTTP status codes** — don't revert to a PrivateBin-style "always 200".
- **No new third-party runtime dependencies** on the client beyond the pinned, vendored
  `qrcode.js`, hash-wasm Argon2 and pdf.js (rebuilt by `tools/vendor.mjs`). Fonts stay
  self-hosted in `public/fonts/`.

## Tests

Every PR must keep `npm run lint` and `npm test` green (CI enforces both, plus a byte-for-byte
diff of `node test/genvectors.mjs` output against `test/vectors.expected.txt`). The main suites
(all run in `workerd`):

| Suite | Covers |
|---|---|
| `test-node/crypto.test.js` | Frozen v2 vectors + Argon2id KAT (Node; workerd cannot compile WASM) |
| `test-node/files.test.js` | File-share format, chunk crypto, ZIP, MIME |
| `test/format.test.js` | Share format v2 parsing / fail-closed behavior |
| `test/markdown.test.js` | Markdown XSS safety — **add a case for any new rendering path** |
| `test/highlight.test.js` | Code tokenizer / classification |
| `test/ids.test.js` | ID and delete-token generation |
| `test/notes.test.js`, `test/files.test.js` | Notes and file shares end to end, proofs, view counting |
| `test/auth.test.js`, `test/admin.test.js`, `test/shares.test.js` | Accounts, sessions, admin, limits, quotas, guard, My shares |
| `test-dom/*.test.js` | XSS mount surfaces, viewer safety, a11y, folder walker |

Add or update tests alongside behavior changes. New rendering paths and any crypto/format change
**require** test coverage, not just passing existing suites.

**Coverage honesty:** the page controllers (`public/js/view.js`, `public/dashboard/js/*.js`) are
not unit-tested; changes there need a manual (or Playwright) pass against `wrangler dev`.
Backend, crypto, and the shared pure modules are covered by the suites above.

> [!NOTE]
> **Windows:** after the suite passes you may see `vitest-pool-worker: Unable to remove
> temporary directory: EBUSY …` lines at teardown. This is cosmetic miniflare temp-dir cleanup
> noise on Windows — the tests have already passed; it does not indicate a failure.

## Pull requests

1. Keep changes focused; one logical concern per PR.
2. Update the relevant docs when behavior changes: `SPEC.md` (protocol/format), `SECURITY.md`
   (threat model), `ARCHITECTURE.md` (request path), `README.md` (user-facing), and add a
   `## [Unreleased]` entry to [`CHANGELOG.md`](./CHANGELOG.md).
3. Run `npm run lint` and `npm test` and confirm everything passes before opening the PR.
4. Describe **what** changed and **why**, and call out anything you could not verify.

### Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/): `type(scope): summary`
(e.g. `feat(burn): verify password before consuming`, `fix(...)`, `docs(...)`, `test(...)`,
`chore(...)`, `refactor(...)`). Prefer a few small, self-contained commits over one large one.

## Releasing

The **application** (root `package.json`) is tagged `vX.Y.Z`. The paste
format is versioned separately, in `SPEC.md` (currently v2).

**Application release** (`vX.Y.Z`):

1. Move the `## [Unreleased]` CHANGELOG entries under a new version heading with today's
   date, and update the compare/release links in the footer.
2. Bump the root `package.json` version to match, commit, and tag: `git tag vX.Y.Z && git
   push --tags`.
3. Deploy with `npm run deploy` (the app deploys from the working tree, not from the tag —
   tag first so the release is anchored to a ref).

## Reporting vulnerabilities

**Do not open a public issue with exploit details.** Report suspected vulnerabilities privately
via GitHub private vulnerability reporting (<https://github.com/kaerez/bin/security/advisories/new>) with reproduction steps and
affected versions, per [`SECURITY.md`](./SECURITY.md) §8. There is no bug-bounty program.

## License

By contributing, you agree that your contributions are licensed under the project's
[MIT License](./LICENSE).
