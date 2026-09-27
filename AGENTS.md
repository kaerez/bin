# AGENTS.md — working on secbin

Instructions for coding agents (and people) working in this repository. The product itself is
described in [README.md](./README.md); the threat model and security design in
[SECURITY.md](./SECURITY.md).

## How to work

- **Fan out.** Split independent work and run it in parallel: one agent (or session) per task,
  each in its own git worktree and branch from `main`, with its own `wrangler dev` port and its
  own local state. Read-only work (audits, reviews, write-ups, requirement checks) can always run
  in parallel. Keep work serial only where it has to be: changes that touch the same core files
  in conflicting ways, and features that depend on each other (e.g. reverse share needs the
  Drive). The coordinator reviews, merges one branch at a time and resolves conflicts.
- **Durable Object migrations** (`MIGRATIONS` in `src/directory-do.js`) are numbered by position:
  parallel branches must not both append one; the second to merge renumbers after rebasing on
  `main`.
- **One PR per coherent change**, as a draft first, from a branch off `main`. Merge only when CI
  is green (the maintainer allows merging your own green PRs); use a merge commit. After a PR is
  merged, follow-up work starts on a new branch from the latest `main`.
- **Track every request.** Break the maintainer's messages into atomic requirements, keep them in
  the task list, and before calling work finished check each one against the code (not against
  commit messages). Answer questions explicitly; say plainly when something is not done.
- **Never** skip, disable or weaken a test to get green, and never claim a check you did not run.

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
- **Reverse shares:** an optional password gates the anonymous uploader only; uploads land in the
  user's chosen drive folder; the user never needs that password.

## Compliance note

The operator works in a regulated environment (PCI DSS v4, SOX, GDPR, SEC). Flag anything that
touches personal data, retention, tracking or audit trails, and leave final determinations to
Legal / Risk / Compliance. Nothing produced here is legal or compliance advice.
