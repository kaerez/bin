# AGENTS.md — working on secbin

Instructions for coding agents (and people) working in this repository. The product itself is
described in [README.md](./README.md); the threat model and security design in
[SECURITY.md](./SECURITY.md).

## How to work

- **Plan → plan sharding → fan out.** Always work this way, for every plan and every task (and
  subtask), to finish them faster:
  1. **Plan:** break the request into atomic tasks (and subtasks) in the task list, with their
     dependencies.
  2. **Plan sharding:** group the tasks into independent units of work that do not touch the same core
     files in conflicting ways.
  3. **Fan out:** run the shards at the same time, as parallel agents / sessions / tasks (one per task,
     each in its own git worktree and branch from `main`, with its own `wrangler dev` port range
     and its own local state), parallel subtasks, and parallel background commands and
     subcommands. Shard long checks too: split the end-to-end suites across several dev-server
     ports instead of running them one after another, and run the four test projects in
     parallel.
  Read-only work (audits, reviews, write-ups, requirement checks) can always run in parallel.
  Keep work serial only where it has to be: changes that conflict in the same core files, and
  features that depend on each other (e.g. reverse share needs the Drive). The coordinator
  reviews each branch, merges one at a time and resolves conflicts; while agents run, the
  coordinator keeps working on the next shard instead of waiting.
- **Durable Object migrations** (`MIGRATIONS` in `src/directory-do.js`) are numbered by position:
  parallel branches must not both append one; the second to merge renumbers after rebasing on
  `main`.
- **One PR per coherent change**, as a draft first, from a branch off `main`. Merge only when CI
  is green (the maintainer allows merging your own green PRs); use a merge commit. Turn on
  auto-merge for each PR (when the repository allows it) so it merges itself once green, and
  delete the branch after the merge (GitHub's "Automatically delete head branches"). After a PR is
  merged, follow-up work starts on a new branch from the latest `main`.
- **Merging:** turn on auto-merge for each PR (when the repository allows it) and delete the
  branch after the merge. Never merge two PRs back to back: every merge to `main` triggers a
  production build, and builds that finish out of order deploy an older commit last. Wait until
  the previous merge's production build ("Workers Builds" on the `main` commit) has finished
  before merging the next, and after merging check that production serves the new code.
- **Track every request.** Break the maintainer's messages into atomic requirements, keep them in
  the task list, and before calling work finished check each one against the code (not against
  commit messages). Answer questions explicitly; say plainly when something is not done.
- **Never** skip, disable or weaken a test to get green, and never claim a check you did not run.
- **Security audit (standing requirement).** After every major feature, and before calling a
  wave of work finished, run a full OWASP-style audit (OWASP Top 10 / ASVS) of `main` with an
  explicit verdict and code evidence for each of: **CSRF**, **XSS**, **command injection**,
  **SQL injection**, **NoSQL / KV / R2 key injection**, plus authentication and sessions, access
  control (IDOR, privilege escalation), cryptography, SSRF and open redirects, security headers,
  file upload / download, denial of service and rate limiting, secrets and logging, and
  dependencies. Confirm findings with tests or proof-of-concept requests against `wrangler dev`
  (synthetic data only), fix confirmed findings in a PR, and report what was not verified.

## Checks before every push

```sh
npm run lint
npm test                                  # four vitest projects: workerd, node, dom, cli
node cli/scripts/sync-shared.mjs --check  # the CLI's copies of shared browser modules
```

Then the end-to-end suites (Playwright + Chromium against `wrangler dev`) for the areas you
touched, and all of them for broad changes. A new worktree needs `.dev.vars` (local secrets,
never committed) and `node_modules`.

## Conventions

- **Frontend:** vanilla JS modules, DOM built with the `h()` helper; no `innerHTML` or inline
  scripts/styles (strict CSP with Trusted Types). Match the surrounding style and comment density.
- **Security defaults:** least privilege; every state-changing route checks intent/origin and the
  caller's role; SQL is always parameterised; user input never becomes HTML; secrets never in code,
  logs or error messages (use Worker secrets or a secrets manager).
- **Settings vs roles:** everything an account may do is a role option (Admin → Roles). The Owner
  role is locked (everything allowed, no limits) and belongs to the owner only; the Default role
  holds a value for every option; custom roles inherit what they leave unset; the built-in Public
  role belongs to the public (anonymous) account and cannot be renamed, deleted or assigned.
  Admin → Settings holds only server-wide items.
- **Terminology:** "owner" means the admin. For the person who owns a drive or share, say "user".
- **Backward compatibility:** not required for now (no migration of old data or old export files
  unless asked).

## Product rules confirmed by the maintainer

- **Security first:** the security requirements must not be changed or impacted by any other
  requirement (accessibility, impersonation, convenience, access). No change may weaken an
  existing control: human check, step-up, CSRF / cross-site guards, rate limits and lockouts,
  session limits, token and grant scoping, CSP / Trusted Types, audit logging, and the
  zero-knowledge design (the server never holds a key that opens user content; the Drive is the
  one documented exception, below). When two requirements conflict, keep the security control and
  ask the maintainer.
- **Recovery codes** always work instead of the password and/or passkey (a full override).
- **Admin password resets never remove** an account's passkeys or recovery codes.
- **Step-up:** anyone changing their own password, passkeys or API keys re-confirms with their
  password or a passkey; the owner acting on other accounts does not. Passwords the owner sets are
  exempt from the password policy; every character counts towards length.
- **Imports never remove or overwrite an existing account's credentials.** For an account that
  already exists (the owner included) an import only sets its role (if that part is selected)
  and adds the imported passkeys (if that part is selected); its password, recovery codes and
  existing passkeys are left untouched. New accounts are created from the selected parts.
- **Export passphrase:** optional, no minimum length; the UI warns when it is empty.
- **Human check (Turnstile):** protected buttons stay disabled until the check has passed.
- **Accessibility:** WCAG 2.2 level AA is the minimum for every page and state; meet level AAA
  wherever possible. Default accessibility texts (statement, admin help, docs) name no country,
  region or national standard.
- **Reverse shares:** an optional password gates the anonymous uploader only; uploads land in the
  user's chosen drive folder; the user never needs that password.
- **The Drive is not end-to-end (an accepted exception to the zero-knowledge design, the Drive
  only):** Drive files are encrypted in the browser, but the server derives every user's KEK
  from keys it keeps (the root MEK and the sub-MEKs in the Directory, with the user salt), so the
  server, the owner, and anyone with a copy of the Directory's storage can decrypt every Drive
  file (docs/DRIVE.md §2, SECURITY.md "Drive keys"). A leak of R2 or of a Drive object without the
  Directory reveals nothing. Notes, file shares, Drive shares (the keys travel in the link) and
  reverse-share uploads until they are taken in stay end-to-end. Every other control stays: the
  step-up for every key action, keys in the admin audit by fingerprint only, never a key in a
  log, and the Worker opening DEKs and names only in memory.
- **The Drive keys never change** on a password change, an admin reset or an AUTHN owner
  recovery: they are not tied to any credential. Only the owner changes them (Admin → Security →
  Keys), and restores and imports never replace a working key.
- **Impersonation:** the owner can do everything the user can, the Drive included; it is
  invisible to the user (the user's activity shows the actions as theirs), and the owner-only
  admin audit keeps the start, end and real actor.

## No Legal / Compliance notes

Do not add Legal / Compliance review notes, sign-off reminders or "not legal advice" disclaimers
to the code, the UI, the docs or the CHANGELOG. Describe the behaviour factually (what is stored,
for how long, who can see it) and leave it there.
