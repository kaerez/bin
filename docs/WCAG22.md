# WCAG 2.2 conformance report

This is the record of secbin's WCAG 2.2 audit: every success criterion at levels A, AA and AAA,
with a verdict, the evidence (a `file:line` in this repository, or the check that proves it) and
the pages it concerns. The product rule (see `AGENTS.md`) is that WCAG 2.2 level AA is the
minimum for every page and state, and level AAA is met wherever possible.

**Scope.** secbin's own pages and every state they can show: the landing page and the public
composer, the share viewer (password, note, link, credential, files, preview, gone), log in, owner
setup, the dashboard composer, My shares, Account, every Admin tab and the role editor, the
accessibility statement (with its site map and glossary), the accessibility settings widget
(English and Hebrew), and the Drive (folder tree, table, dialogs, upload, unlock, the automatic
set-up at sign-in, "Drive is not ready yet", and the owner's notice for a user with no Drive), and
the owner recovery kit with what came with it (its status and notices, Download / Verify / Restore
from kit and their results, the unlock screen's restore and "Start over without a kit", the
archive of the Drive from before a start over, the create-user form's Drive note, the reset's
"unlock your own Drive" box, and a user's Drive moved to a reset's escrow key), and reverse
shares ("Receive files": the anonymous uploader page `/r/<id>` ready, with a password, with the
CAPTCHA, uploading, done, paused and ended; the Drive's "Receive files…" dialog, the received
files' line, their review, and the unlock screen's count of files waiting). Content that
users share (notes, files, PDFs, images, audio and video) is theirs, not secbin's: this report
covers how secbin presents it, not the content itself.

**Date and build.** 2026-09-28, branch `claude/wcag-audit` after merging `main` 9d11b66 (the
Drive, with the owner recovery kit, start over and owner-created Drives), 3df2e6f (reverse
shares) and 5ae4f93 (CSRF tokens, with their "session changed" banner; the stray-text fix).

**The Drive key model v2** (after this report). It removes views this report checked: the
Drive's unlock and set-up screens, "Drive is not ready yet" and the owner's notice for a user with
no Drive, the owner recovery kit, starting over and its archive box on the Drive page, the
create-user form's Drive note, the reset's "unlock your own Drive" box and the automatic move to a
reset's escrow key. The rows below that name them describe the release before. Their
replacements — the upgrade box of a Drive made before (with its password, recovery-kit and
"Retire these links" forms), the Drive's notices when its keys cannot be had, the personal kit
(Account), and Admin → Security → Keys (the keyring, a root change that could not finish, the key
kit, the Drive upgrade and the archive of the release before) and Import / export → Drive keys —
follow the same fixes: every form's message sits in a status line present from the start
(`public/dashboard/js/kit-ui.js` `liveMsg`), a kit's passphrase warning describes its field while
it shows, a notice in place of the Drive is said by the page's own status line, and an open Drive
closes, with its keys and dialogs, when the session ends or the browser is signed in as someone
else (`test-dom/drive-kits.test.js`, `test-dom/drive.test.js`, `test-dom/reverse.test.js`). The
Playwright passes of this report (`axe-audit`, `a11y-tree`, `wcag22.mjs`) have not been run on
those new views yet.

**How it was checked** (all in Chromium, driven by Playwright, against `wrangler dev`):

- *axe-core*, WCAG 2.0/2.1/2.2 A and AA rules, every page and state, both themes, desktop and
  phone widths (`axe-audit` suite); and the AAA rules `color-contrast-enhanced` in both themes and
  in the high-contrast mode (`wcag22.mjs --aaa`).
- *The accessibility tree* that Chromium passes to screen readers: names, roles, states,
  landmarks, headings, live regions, dialogs, form errors, the Drive's tree (`a11y-tree` suite).
- *The criteria automation cannot judge*, measured by `wcag22.mjs` (a scratch suite kept with
  the audit, see "Tests" below) on 45 states at 1280×900, at 320×640 (320 CSS px), at 320×256
  and at 400 % zoom of 1280×1024 (320×256 CSS px at 4 device pixels each):
  - reflow (no horizontal page scroll, nothing cut off);
  - text spacing, with the WCAG 1.4.12 values injected as a user style sheet;
  - target sizes, by measuring every pointer target's box;
  - focus not obscured, by pressing Tab through every page with the fixed accessibility button,
    the toast and the install banner present, and, once the page has settled (two animation
    frames), hit-testing a 3 px grid over every overlap of the focused element with a fixed or
    sticky element: any covered point fails 2.4.12;
  - a visible focus ring on every Tab stop;
  - label in name, visible labels, autocomplete tokens and paste on every credential field;
  - duplicate ids in the DOM built at runtime, and balanced tags and unique ids in the HTML
    the server sends;
  - the time-limit warnings, end to end (session warning and "Stay signed in"; download window
    warning and "Keep downloads open"; "Stop the countdown").
- *Unit and DOM tests* for what the fixes guarantee (`test-dom/wcag22.test.js`,
  `test/files.test.js`, `test/auth.test.js`).
- *Reading the code* for everything else (the "Evidence" column).

**What this is not.** Automated and manual checks in Chromium are not a test with a screen reader,
voice control, switch access or another browser. The verdicts below are what this audit could
establish; "What remains for people with assistive technology" at the end lists what still has
to be confirmed by people, and how.

**Verdicts.** *Supports*: the criterion is met on every page and state in scope. *Partially
supports*: met in some places, not all. *Does not support*: not met. *Not applicable*: nothing
in scope that the criterion is about.

**Pages** (last column): **All** every page; **Up** the uploader page of a reverse share (`/r/`); **Land** landing page and public composer; **View**
share viewer; **Login**; **Setup**; **Comp** dashboard composer; **Shares** My shares; **Acct**
Account; **Admin** every Admin tab and the role editor; **Stmt** accessibility statement;
**Widget** accessibility settings; **Drive** tree, table, dialogs, upload, unlock, notices, the
owner recovery kit, start over and the archive.

**WCAG 2.1** column: the level the criterion has in WCAG 2.1, or *2.2 only* for the criteria
WCAG 2.2 added (six at A/AA: 2.4.11, 2.5.7, 2.5.8, 3.2.6, 3.3.7, 3.3.8; three at AAA).

## Summary

| Level | Criteria | Supports | Partially supports | Does not support | Not applicable |
|---|---|---|---|---|---|
| WCAG 2.1 A | 30 | 26 | 0 | 0 | 4 |
| WCAG 2.1 AA | 20 | 18 | 0 | 0 | 2 |
| WCAG 2.2 A | 31 | 27 | 0 | 0 | 4 |
| WCAG 2.2 AA | 24 | 22 | 0 | 0 | 2 |
| WCAG 2.2 AAA | 31 | 23 | 0 | 2 (2.2.3, 3.1.5) | 6 |

WCAG 2.1 A counts 4.1.1 Parsing (which WCAG 2.2 removed) and not 3.2.6 or 3.3.7; WCAG 2.1 AA
does not have 2.4.11, 2.5.7, 2.5.8 or 3.3.8. The 4.1.1 row below was verified all the same.

## Level A

| Criterion | 2.1 | Verdict | Evidence | Pages |
|---|---|---|---|---|
| 1.1.1 Non-text Content | A | Supports | Decorative SVGs are `aria-hidden` (`public/index.html:38`); icon buttons have names (`public/index.html:59`, `public/js/a11y.js:105`); the QR code has alt text (`public/index.html:675`); image previews use the file name (`public/js/viewer.js:150`). **Fixed:** a PDF page (a canvas) now has a name and its text as real text under "Text of this page" (`public/js/pdfview.js:106`); a page with no text says so and points to the download. axe `image-alt`, `svg-img-alt`, `button-name`: 0. | All, View |
| 1.2.1 Audio-only and Video-only (Prerecorded) | A | Not applicable | secbin has no audio or video of its own. Audio and video that users share are their content; the viewer plays them with the browser's own controls (`public/js/viewer.js:164`) and always offers the download. | View |
| 1.2.2 Captions (Prerecorded) | A | Not applicable | As 1.2.1. | View |
| 1.2.3 Audio Description or Media Alternative (Prerecorded) | A | Not applicable | As 1.2.1. | View |
| 1.3.1 Info and Relationships | A | Supports | Landmarks, one `h1` per view, `h2` sections; tables with `th` and a caption (`public/dashboard/js/drive-app.js:514`); fieldsets and legends for radio groups (`public/dashboard/account/index.html:252`); the Drive tree is an ARIA tree (`public/js/tree.js:44`). **Fixed:** fields labelled only by a placeholder now have a `<label>` (see 3.3.2); duration and quota fields in the role editor are named in context instead of "Amount"/"Unit" (`public/dashboard/js/admin.js:703`, `public/dashboard/js/admin.js:393`). **Fixed:** the Drive page's footer was inside `<main>` (no contentinfo landmark); it now follows `<main>` as on every other page (`public/dashboard/drive/index.html`). **Fixed:** the owner recovery kit's card named a plain `<div>` (a name ARIA does not allow there); it and the archive box are now sections named by their headings (regions: `public/dashboard/js/drivekit-ui.js` `kitCard`, `public/dashboard/js/drive-app.js` `archiveBox`); the reset's "Continue without unlocking" box is described by its warning (`public/dashboard/js/admin.js` `openUser`). **Fixed** (the uploader page from `main`): its footer was inside `<main>` and named a plain paragraph; it is now the same footer as on every other page, after `<main>` (`public/r/index.html`, checked by `test-dom/wcag22.test.js`). axe and the `a11y-tree` suite: 0 violations. | All, Up |
| 1.3.2 Meaningful Sequence | A | Supports | The DOM order is the reading order; the only positioned content (dialogs, the widget panel, the toast) is announced or takes focus. Right-to-left text in the widget and statement carries `dir` (`public/js/a11y.js:108`). | All |
| 1.3.3 Sensory Characteristics | A | Supports | Instructions name the control, not only its place or shape ("Drop files here" always comes with "Add files" / "Add folder" buttons: `public/index.html:343`). | Comp, Land, Drive |
| 1.4.1 Use of Color | A | Supports | Links in text are underlined (`public/css/styles.css:1070`); errors are text (and `aria-invalid`); pressed and selected states have a check mark, weight or position as well as colour (`public/css/styles.css:1020`, `public/css/styles.css:1163`). | All |
| 1.4.2 Audio Control | A | Supports | Nothing plays on its own: media previews start only from their controls (no `autoplay` anywhere). | View |
| 2.1.1 Keyboard | A | Supports | Every function works from the keyboard (`a11y-tree`: keyboard-only walks of every page, the Drive tree's arrow keys, tabs, dialogs). Drag and drop is never the only way: upload buttons (`public/dashboard/js/drive-app.js:524`), "Move" with a folder picker. | All |
| 2.1.2 No Keyboard Trap | A | Supports | Dialogs keep focus inside while open and release it on Escape, Cancel or close (`public/dashboard/js/drive-app.js:141`, `public/dashboard/js/session-timeout.js:139`). The Turnstile widget is a frame that Tab enters and leaves. | All |
| 2.1.4 Character Key Shortcuts | A | Supports | The only single-key input is type-ahead in the Drive tree, active only while the tree has focus (`public/js/tree.js:245`). | Drive, Comp, View |
| 2.2.1 Timing Adjustable | A | Supports | Every time limit on what a person is doing can be extended. **Fixed:** (1) *the signed-in session*: two minutes before it would time out for inactivity, an alert dialog warns and "Stay signed in" (or Escape) extends it, as often as needed (`public/dashboard/js/session-timeout.js:33`; deadlines from `src/lib/auth.js:47`); the absolute session limit (default 7 days, beyond the 20-hour exception) is announced 2 minutes ahead. (2) *the download window* of a file share (default 1 hour): 5 minutes before it closes, a warning with "Keep downloads open" extends it by the window again, at least ten times, never past the share's expiry, spending no view (`src/fileshare-do.js:261`, `src/routes/public.js:262`, `public/js/view.js:438`). Both warnings go by the server's clock (the `now` sent with the session and with the download grant), so they come on time when the browser's clock is off (checked with a clock 5 minutes behind: `test-dom/wcag22.test.js`, `wcag22.mjs`). (3) *the toast* no longer disappears on a timer: it stays until the next key press or click (`public/js/ui.js:97`). A share's own expiry is a property of the content the sender chose (like an event that ends), not a limit on the recipient's task. Checked: `wcag22.mjs` "2.2.1" checks; `test-dom/wcag22.test.js`; `test/files.test.js` "extending a download window". | All signed-in pages, View |
| 2.2.2 Pause, Stop, Hide | A | Supports | **Fixed:** every countdown that updates each second (a share's "Deletes in", the download window, the one-time code's seconds) has a "Stop the countdown" switch that shows the fixed time instead (`public/js/ui.js:160`); it starts stopped when "Stop animations" is on. Animations run once and under 5 s; the last-minutes pulse of the expiry timer stops with the switch. The one-time code itself keeps changing (that is its purpose). | View |
| 2.3.1 Three Flashes or Below Threshold | A | Supports | Nothing flashes. | All |
| 2.4.1 Bypass Blocks | A | Supports | "Skip to main content" on every page (`public/index.html:36`), landmarks. | All |
| 2.4.2 Page Titled | A | Supports | Every page has its own title; **fixed:** the viewer's and composer's views now name themselves in the title ("Enter the password · secbin", "Shared files · secbin"…: `public/js/ui.js:20`, `public/index.html:116`); the uploader page's ended, paused or broken link does too ("This link no longer accepts files · secbin": `public/js/reverse.js` `errorCard`). | All, Up |
| 2.4.3 Focus Order | A | Supports | Focus follows the DOM; a new view moves focus to it, dialogs to their first control and back to the opener when they close. **Fixed:** a view change no longer takes focus from the header, footer or accessibility settings (`public/js/ui.js:16`). **Fixed:** when the Drive replaces the form that had focus (an unlock, a restore from the kit, a start over), focus went to the page; it now goes to the folder's heading, and after deleting the old Drive's archive to the archive box's heading or, with none left, the folder's heading (`public/dashboard/js/drive-app.js` `mountApp`, `archiveBox`); "Show more" in the review of received files moves focus to the first row it loaded. **Fixed** (the uploader page): "Send files" is disabled while it runs and once the list is empty, so focus fell to the page; it now goes to "Cancel" while sending and to "Choose files" (or back to "Send files" after an error) afterwards (`public/js/reverse.js`). | All, Up |
| 2.4.4 Link Purpose (In Context) | A | Supports | Every link's text says where it goes (see 2.4.9). | All |
| 2.5.1 Pointer Gestures | A | Supports | No path-based or multi-point gestures; the PDF preview pages with buttons. | All |
| 2.5.2 Pointer Cancellation | A | Supports | Actions run on click (the up-event). **Fixed:** the accessibility panel and the Drive dialogs used to close on mouse-down outside them; now on click, and a dialog only when the press also began on its backdrop (`public/js/a11y.js:161`, `public/dashboard/js/drive-app.js:158`, `public/js/composer.js:593`). | All, Drive, Comp |
| 2.5.3 Label in Name | A | Supports | **Fixed:** fields whose `aria-label` differed from their visible label (the setup page's "Owner password" was named "New password"; Turnstile keys; export passphrase; Drive "Select all") now use the visible words (`public/dashboard/setup/index.html:189`, `public/dashboard/js/admin.js:1077`, `public/dashboard/js/admin-portable.js:19`, `public/dashboard/js/drive-app.js:512`); a reverse link's "Copy link" was named "Copy the link …" (it is "Copy link …" now). `wcag22.mjs` "2.5.3 label in name": 0 on every state. | All |
| 2.5.4 Motion Actuation | A | Not applicable | Nothing responds to device motion. | — |
| 3.1.1 Language of Page | A | Supports | `<html lang="en">` on every page; the statement's second language article has its own `lang`. | All |
| 3.2.1 On Focus | A | Supports | Focus alone changes no context (the accessibility panel closes when focus leaves it: a change of content, not of context). | All |
| 3.2.2 On Input | A | Supports | Changing a field never navigates or submits; settings save on their button. Tabs switch panels in place. | All |
| 3.2.6 Consistent Help | 2.2 only | Supports | Every page has the same footer in the same order: Source code, Threat model, Accessibility statement (the contact), Glossary (checked for every page by `test-dom/wcag22.test.js` "in every page footer"). The accessibility settings button is in the same place on every page. | All |
| 3.3.1 Error Identification | A | Supports | Errors are text in an alert region, tied to the field (`aria-invalid`, `aria-describedby`) and focused (`public/dashboard/js/drive-app.js:177`, `public/js/setup.js:47`). **Fixed:** "Start over without a kit" marked only a wrong username; an empty password is now marked the same way, and "Delete the old Drive archive" marks its username field too (`public/dashboard/js/drive-app.js` `ownerRecoveryView`, `archiveBox`). | All |
| 3.3.2 Labels or Instructions | A | Supports | **Fixed:** every field now has a visible label: the share password fields (`public/index.html:126`, `public/index.html:553`), the repeat-password fields on setup and account, passkey and API key names, API key lifetime, the My shares filters (`public/dashboard/shares/index.html:113`), and the admin panel's fields through one helper that shows the field's name above it (`public/js/common.js:57`), now also the reset's "Your password, to unlock your own Drive" (`public/dashboard/js/admin.js` `openUser`) and the "Receive files…" dialog's list of file types (`public/dashboard/js/drive-app.js` `receiveSel`). `wcag22.mjs` "3.3.2 no visible label": 0. | All |
| 3.3.7 Redundant Entry | 2.2 only | Supports | Nothing already entered in a process is asked again, except where it is essential or for security: a new password is typed twice; your password confirms changes to your own account (step-up); the Drive unlocks at sign-in from what was used to sign in, and the first time is set up there with no prompt (`public/js/login.js:13`, `public/js/driveclient.js` `unlockAtSignIn`). | Login, Acct, Comp, Drive |
| 4.1.1 Parsing (obsolete in 2.2) | A | Supports | WCAG 2.2 removed this criterion (always satisfied). Verified anyway: the HTML the server sends has balanced tags, no duplicate attributes and unique ids (`wcag22.mjs` "4.1.1 served HTML", 10 pages), and the DOM built at runtime has no duplicate ids in any of the 42 states. **Fixed:** two admin renders could run at once and duplicate a panel's content and ids (`user-detail`); renders of a panel are now queued (`public/dashboard/js/admin.js:163`). | All |
| 4.1.2 Name, Role, Value | A | Supports | Native controls first; ARIA where needed (tabs, switches, tree, dialogs, `aria-pressed`, `aria-expanded`, `aria-current`). axe and `a11y-tree`: names, roles and states on every page. **Fixed** (the uploader page): its drop zone was a Tab stop with the role of a group that opened the file picker on Enter, an action its role does not say; it is a named group (as in the composer) and its "Choose files" and "Choose a folder" buttons are the keyboard way (`public/js/reverse.js`). | All, Up |

## Level AA

| Criterion | 2.1 | Verdict | Evidence | Pages |
|---|---|---|---|---|
| 1.2.4 Captions (Live) | AA | Not applicable | No live media. | — |
| 1.2.5 Audio Description (Prerecorded) | AA | Not applicable | As 1.2.1. | View |
| 1.3.4 Orientation | AA | Supports | No orientation lock (no `orientation` in the manifest or CSS); every page works in portrait and landscape. | All |
| 1.3.5 Identify Input Purpose | AA | Supports | Fields about the user carry their token: `username`, `current-password`, `new-password`, `one-time-code` (`public/dashboard/login/index.html:103`, `public/dashboard/js/drive-app.js:290`; **fixed:** the Drive's recovery code field: `public/dashboard/js/drive-app.js:291`). Fields about someone else (a credential being shared) are rightly `off`. Checked for every static page by `test-dom/wcag22.test.js`. | Login, Setup, Acct, Drive, Admin |
| 1.4.3 Contrast (Minimum) | AA | Supports | Every text colour is ≥7:1 (see 1.4.6), so ≥4.5:1. **Fixed:** the error toast's white text on the dark theme's red was 3.7:1; it now has its own fill (`public/css/styles.css:89`). axe `color-contrast`: 0 in both themes. | All |
| 1.4.4 Resize Text | AA | Supports | Text scales with browser zoom to 400 % without loss (see 1.4.10), and with the widget's text sizes. | All |
| 1.4.5 Images of Text | AA | Supports | No images of text (the wordmark is text). | All |
| 1.4.10 Reflow | AA | Supports | `wcag22.mjs` "1.4.10 reflow" at 320×640 and 320×256: 0 on every state. **Fixed:** long links and generated keys wrap instead of scrolling (`public/css/styles.css:420`, `public/css/styles.css:603`); the role editor's selects no longer widen the page (`public/css/styles.css:586`); the footer links wrap (`public/css/styles.css:551`). Data tables become one card per row below 640 px; code blocks and the PDF canvas (2-D content) scroll in their own box. | All |
| 1.4.11 Non-text Contrast | AA | Supports | **Fixed:** the borders of text fields, option groups and the editor were 1.5:1; they now use a field colour ≥3:1 on every surface in both themes (`public/css/styles.css:36`, `public/css/styles.css:75`). The focus ring is ≥7:1 (`public/css/styles.css:86`). Checked by `test-dom/wcag22.test.js` "field boundaries and the focus ring". | All |
| 1.4.12 Text Spacing | AA | Supports | `wcag22.mjs` "1.4.12 text spacing" (line height 1.5, paragraph spacing 2 em, letter spacing 0.12 em, word spacing 0.16 em, as a user style sheet): no clipped or hidden text on any state at 1280 and 320 px. **Fixed:** the "Receive files…" dialog's "Accept files for" box was cut off in its grid cell; it takes a whole row (`public/css/styles.css` `.drive-reverse-grid > .opt`). | All |
| 1.4.13 Content on Hover or Focus | AA | Supports | No custom tooltips; the "not encrypted" hint shown on focus is in the flow, not over other content (`public/css/styles.css:800`). | Comp, Shares, Drive |
| 2.4.5 Multiple Ways | AA | Supports | The navigation on every dashboard page, the links between related pages, and (**added**) a site map on the accessibility statement, linked from every footer (`public/accessibility/index.html:104`). Share links are the result of a process. | All |
| 2.4.6 Headings and Labels | AA | Supports | Headings name their sections; labels name their fields (see 3.3.2); duration fields in the role editor now say what they are for (see 1.3.1). | All |
| 2.4.7 Focus Visible | AA | Supports | Every Tab stop draws a ring (`wcag22.mjs` "2.4.7 no focus ring": 0; the Drive tree draws it on its row). **Fixed:** in forced colours (Windows High Contrast) the box-shadow rings were dropped; a system-coloured outline replaces them (`public/css/styles.css:1186`). **Added:** the CAPTCHA's container draws the ring while focus is inside Cloudflare's widget, which may draw none (`public/css/styles.css` `.turnstile:focus-within, .turnstile.focus-in`; the class is set from the page's focus changes, as `:focus-within` does not match inside the widget's frame: `public/js/turnstile.js`). | All |
| 2.4.11 Focus Not Obscured (Minimum) | 2.2 only | Supports | **Fixed:** the fixed accessibility button no longer covers what has focus: the page scrolls it clear, the toast moves to the top, the panel closes when focus leaves it, and the button sits below dialogs (`public/js/a11y.js:201`, `public/css/styles.css:986`, `public/js/a11y.js:172`). **Fixed** (found on the owner's view of a user with no Drive): the impersonation banner, sticky at the top, covered the focused theme button at 320×256; it no longer sticks on short viewports, and focus is scrolled clear of it elsewhere (`public/css/styles.css` `.imp-banner`, `public/js/a11y.js` `FIXED`). **Fixed** (found on the kit's and the create-user form's states, which show a toast): at 320×256 a toast that had moved to the top stayed there and covered, entirely, the controls that Tab reached next (the role select, "Manage", the navigation, the footer links); it now moves back to the other edge when focus goes under it, and is put away when it would cover the focused control at either edge (it has been announced) (`public/js/a11y.js` `unobscure`). `wcag22.mjs` "2.4.11 focus obscured" (Tab through every page at 1280×900, 320×256 and 400 % zoom): 0. | All |
| 2.5.7 Dragging Movements | 2.2 only | Supports | Nothing needs dragging: files dropped onto the composer or the Drive can also be chosen with "Add files" / "Upload"; items move with "Move" and a folder picker (`public/dashboard/js/drive-app.js:697`). | Comp, Land, Drive |
| 2.5.8 Target Size (Minimum) | 2.2 only | Supports | `wcag22.mjs` "2.5.8 target size": every target ≥24×24 or spaced; 0 on every state. **Fixed:** the widget's statement link, and the Drive's selection boxes, whose `<label>` is now the target (24 px, 44 px on phones: `public/css/styles.css:1171`). | All |
| 3.1.2 Language of Parts | AA | Supports | Hebrew in the widget and a second-language statement carry `lang` and `dir` (`public/js/a11y.js:116`). Shared notes are the sender's content. | Widget, Stmt |
| 3.2.3 Consistent Navigation | AA | Supports | The header, the dashboard navigation and the footer are the same, in the same order, on every page (footers checked by `test-dom/wcag22.test.js`). | All |
| 3.2.4 Consistent Identification | AA | Supports | The same function has the same name and icon everywhere (Copy, Delete now, Show password, the lock). | All |
| 3.3.3 Error Suggestion | AA | Supports | Messages say how to fix it ("Passwords do not match — repeat the same password in both fields."; the password policy is spelled out). | All |
| 3.3.4 Error Prevention (Legal, Financial, Data) | AA | Supports | Deleting asks for a second press (`public/js/common.js:146`); an import is shown as a plan before it runs; a share can be deleted at once after creation. | Comp, Shares, Acct, Admin, Drive |
| 3.3.8 Accessible Authentication (Minimum) | 2.2 only | Supports | No step of signing in or confirming it is you asks for a cognitive function test. Passwords and recovery codes can be pasted and filled in by password managers: they carry the right `autocomplete` tokens and nothing blocks paste (`test-dom/wcag22.test.js:251`) — the criterion's *mechanism* alternative. A passkey signs in without any password. The CAPTCHA, when the owner turns it on, is Cloudflare Turnstile: it asks no puzzle, no transcription and no object recognition (usually it passes on its own, at most it asks for a box to be ticked), so it is not a cognitive function test either, and every sign-in (password, passkey, recovery code) and every account change goes through it. For someone who cannot complete the widget itself, the way through is the contact: the note under each protected button links to it (`public/js/turnstile.js:58`). The widget's own operability is third-party content: see “The CAPTCHA (third-party)” below. Share passwords (a secret between two people, not a login) can be pasted; password managers are kept from saving them as the site's login. | Login, Acct, Land, View, Drive |
| 4.1.3 Status Messages | AA | Supports | Saves, copies and errors are announced (`role="status"` toast, alert regions, progress live regions, the CAPTCHA note); the new warnings are an alert dialog (session) and an alert (download window). **Fixed:** the sign-in's "Signing in…" (while it, and the Drive's unlock or automatic set-up, run) was only a button label; it is now also said by a status line that is in the page from the start (`public/dashboard/login/index.html`, `public/js/login.js` `busy`). The Drive page's notices ("Drive is not ready yet", the owner's "The user hasn’t signed in since the Drive was enabled", "not enabled") were a live region inserted together with its text, which screen readers often do not read; the page's own "Opening your Drive…" status line now says the notice's title, and the notice is content with its heading (`public/dashboard/js/drive-app.js` `startDrive`). **Fixed** (the owner recovery kit, from `main`): each kit form's message (Download, Verify, Restore) was a live region shown together with its text; it now appears inside a status line that is in the page from the start (`public/dashboard/js/drivekit-ui.js` `liveMsg`); the empty or short passphrase warning describes the passphrase field while it shows; the create-user form's Drive note, drawn again with the form, is also said through the page's toast (`public/dashboard/js/admin.js`); a user's Drive moved by itself to a reset's escrow key was a live region drawn with its text, and is now said by the Drive page's status line, which stays in place (the same node) through the unlock screen and the Drive (`public/dashboard/js/drive-app.js` `swap`). A check's verdict takes focus; the notice to download a fresh kit is an alert when a rotation or a start over has just caused it, and a note otherwise. **Fixed** (reverse shares, from `main` 3df2e6f): the uploader's "Sent …" and the Drive's received-files line were live regions shown together with their text; each now appears inside a status line that is in the page from the start (`public/js/reverse.js`, `public/dashboard/js/drive-app.js` `receivedLive`); the unlock screen's "N new received files" was a live region drawn with its text; it is content, and the page's status line says it with "Unlock your Drive". | Login, Drive, Admin, Up, All |

## Level AAA

| Criterion | 2.1 | Verdict | Evidence | Pages |
|---|---|---|---|---|
| 1.2.6 Sign Language (Prerecorded) | AAA | Not applicable | No media of secbin's own (see 1.2.1). | — |
| 1.2.7 Extended Audio Description (Prerecorded) | AAA | Not applicable | As 1.2.6. | — |
| 1.2.8 Media Alternative (Prerecorded) | AAA | Not applicable | As 1.2.6. | — |
| 1.2.9 Audio-only (Live) | AAA | Not applicable | As 1.2.6. | — |
| 1.3.6 Identify Purpose | AAA | Supports | Regions are landmarks, controls have names and roles, fields their `autocomplete` purpose, icons are named or hidden. | All |
| 1.4.6 Contrast (Enhanced) | AAA | Supports | **Fixed:** the palette now gives every text colour ≥7:1 on paper, sheet and raised surfaces, in both themes (`public/css/styles.css:40`); the high-contrast mode is white or yellow on black. **Fixed** (found on the start over's and the archive's error states): an armed or hovered danger button, red on its red-tinted fill, was 6.5:1 in the light theme; the light red is now `#772d25`, 7.4:1 on that fill (`public/css/styles.css:50`). axe `color-contrast-enhanced`: 0 on 23 states × dark, light and high-contrast (`wcag22.mjs --aaa`); tokens checked by `test-dom/wcag22.test.js`. | All |
| 1.4.7 Low or No Background Audio | AAA | Not applicable | No audio of secbin's own. | — |
| 1.4.8 Visual Presentation | AAA | Supports | Colours can be chosen (light, dark, high contrast); text is never justified; lines are at most about 80 characters (`.wrap` 680 px, subtitles 52 ch); line height 1.65; text resizes to 400 % without horizontal scrolling. **Added:** the widget's "Text spacing" mode sets line spacing 1.8, paragraph spacing 1.5 times that and lines of at most 70 characters (`public/css/styles.css:1216`). | All |
| 1.4.9 Images of Text (No Exception) | AAA | Supports | No images of text. | All |
| 2.1.3 Keyboard (No Exception) | AAA | Supports | As 2.1.1, with no exception: dropping files has button equivalents. | All |
| 2.2.3 No Timing | AAA | Does not support | Timing is part of what secbin is: shares expire and self-destruct after their views, a view opens a download window, and sessions end for security. All of them can be extended (2.2.1), but they exist by design. | View, signed-in pages |
| 2.2.4 Interruptions | AAA | Supports | The only unsolicited message, the install suggestion, never takes focus and can be dismissed for a year (`public/js/install-banner.js:18`); toasts are results of the person's own actions. | All |
| 2.2.5 Re-authenticating | AAA | Supports | **Added:** when a session ends, the page keeps what was typed and offers "Sign in again" in a new tab; back in the first tab the session is picked up again and the work can be saved (`public/dashboard/js/session-timeout.js`). While signed out the page is locked (hidden and inert behind the dialog; the tab's Drive keys cleared, an open Drive closed, password fields emptied), and it unlocks only for the same user; the text typed in other fields stays through it. | Signed-in pages |
| 2.2.6 Timeouts | AAA | Supports | **Added:** the login page says that inactivity signs you out and that a warning comes first (`public/dashboard/login/index.html:156`); Account shows the exact inactivity time and the latest end (`public/dashboard/js/account.js:158`); the warning dialog repeats the time. Nothing typed is lost when a session ends (2.2.5). | Login, Acct, signed-in pages |
| 2.3.2 Three Flashes | AAA | Supports | Nothing flashes. | All |
| 2.3.3 Animation from Interactions | AAA | Supports | Every motion stops with the system's "reduce motion" and with the widget's "Stop animations" (`public/css/styles.css:510`, `public/css/styles.css:1029`). | All |
| 2.4.8 Location | AAA | Supports | Page titles, `aria-current` in the navigation (`public/dashboard/js/nav.js:44`), the Drive's folder path (`public/dashboard/js/drive-app.js:508`). | All |
| 2.4.9 Link Purpose (Link Only) | AAA | Supports | **Fixed:** link texts that needed context now stand alone: "Source code", "Threat model", "Accessibility statement", "new share", "Create another share", "API documentation (docs/API.md)", and links opening a new tab say so (`public/index.html:711`). Links inside shared notes are the sender's text (they too say they open a new tab: `public/js/markdown.js:187`). | All |
| 2.4.10 Section Headings | AAA | Supports | Sections have headings (account cards, admin panels, statement, glossary, site map, Drive panes, dialogs); views without a visible heading have a hidden one (`public/index.html:202`). | All |
| 2.4.12 Focus Not Obscured (Enhanced) | 2.2 only | Supports | As 2.4.11, for any part of the focused control. **Fixed:** the note editor is shorter on short screens, so it fits between the edges (`public/css/styles.css:257`). **Explained and closed** (the intermittent overlap recorded after the Drive integration's merge, once per run at 320×256 in a different state: the role editor's file type list, the note editor with the Hebrew settings panel): Chromium does not scroll a text field that is already inside the viewport when it gets focus (it ignores `scroll-padding`), so a textarea near the bottom stays, for the rest of that task, partly under the accessibility button; the page scrolls it clear in the next animation frame, before that frame is painted (`public/js/a11y.js:185`, `unobscure`). The old probe sampled five points synchronously after the key press and saw the uncorrected layout whenever it ran before that frame. The check is now strict and deterministic: it waits two frames and hit-tests a 3 px grid over every overlap with a fixed or sticky element (a layer painted below the focused element, or a rounded corner's outside, does not count); any covered point is a failure. `wcag22.mjs` "2.4.12 focus partly obscured": 0 in each of four complete `--aaa` runs (45 states, every Tab stop, at 1280×900, 320×256 and 400 % zoom). A negative control (`DBG_REGRESS=1`, the page without that correction) fails it with 8 findings (the note editor, the role editor's link and file type lists). Not covered by the Tab walk: the widget's text-size and large-target modes at 400 % zoom, and fields a person resizes taller than the space between the button and the top of the screen (the page cannot scroll those clear). | All |
| 2.4.13 Focus Appearance | 2.2 only | Supports | The focus indicator is a 2 px ring with a 2 px gap (`public/css/styles.css:119`, `public/css/styles.css:308`): at least a 2 px perimeter, ≥3:1 against the unfocused state (the ring is ≥7:1 on every surface). | All |
| 2.5.5 Target Size (Enhanced) | AAA | Supports | **Added:** the widget's "Large buttons and links" mode makes every target at least 44×44 (`public/css/styles.css:1194`; inline links in text are exempt). Measured: `wcag22.mjs --aaa` "2.5.5": 0 on 23 states. The accessibility button itself is 44×44 on every page. | All |
| 2.5.6 Concurrent Input Mechanisms | AAA | Supports | Keyboard, mouse, touch and pen all work together; nothing is restricted to one input. | All |
| 3.1.3 Unusual Words | AAA | Supports | **Added:** a glossary of the technical words (`public/accessibility/index.html:120`), linked from every page's footer; its "Drive", "KEK", "DEK" and "MEK" say that the server (and the administrator) can open every Drive, and "Receive files (link)" that uploads are not end-to-end either. What a user reads in the Drive calls the owner "the administrator" everywhere ("Drive is not ready yet" included). | All |
| 3.1.4 Abbreviations | AAA | Supports | **Added:** the glossary expands every abbreviation the interface uses (AES-256-GCM, API, CAPTCHA, CIDR, CLI, HKDF, IP, KB/MB/GB, m/h/d, PDF, QR, TOTP, URL, WCAG). | All |
| 3.1.5 Reading Level | AAA | Does not support | The interface text is short and plain, but its subject (encryption, access keys, administration) needs words beyond lower-secondary reading level, and there is no simplified version. The glossary explains the terms. Shared notes are the senders' own text. | All |
| 3.1.6 Pronunciation | AAA | Not applicable | No words whose meaning depends on their pronunciation in context. | — |
| 3.2.5 Change on Request | AAA | Supports | Nothing changes page on its own. **Fixed:** when a session ends the page no longer depends on a redirect: the dialog offers "Sign in again" (2.2.5); links that open a new tab say so (2.4.9). **Fixed** (found by the accessibility-tree suite on the reverse shares' states): when received files were taken in just as the person opened a folder, the Drive's refresh re-listed the folder they were leaving, so the Drive stayed there and focus fell to the page; a refresh now re-lists the folder being opened and keeps its focus (`public/dashboard/js/drive-app.js` `open`, `refresh`; `test-dom/reverse.test.js`). **Fixed** (found by the end-to-end suite on a loaded machine): an Admin tab opened while the page was still loading was replaced by the default tab (Users) when the loading finished; the default now applies only if no tab was chosen (`public/dashboard/js/admin.js`; `test-dom/admin-tabs.test.js`). | All |
| 3.3.5 Help | AAA | Supports | Instructions next to the fields that need them (password policy, link rules, file policy, expiry), help panels in the admin, the glossary and the statement's contact on every page. | All |
| 3.3.6 Error Prevention (All) | AAA | Supports | Input is checked before it is sent; deleting asks twice; imports show a plan; a share can be deleted after creation; settings can be changed back. | All |
| 3.3.9 Accessible Authentication (Enhanced) | 2.2 only | Supports | As 3.3.8, without relying on the object-recognition or personal-content exceptions: none of the steps uses either. The same third-party caveat applies to the CAPTCHA. | Login, Acct, Drive |

## The CAPTCHA (third-party)

When the owner turns it on (Admin → Security, or the deployment's keys), Cloudflare Turnstile
guards every sign-in (password, passkey and recovery code), every change to one's own account,
and anonymous sharing; the protected buttons stay disabled until it passes (a product rule).
The widget is Cloudflare's code in a frame on secbin's page: *third-party content* in WCAG's
terms.

- **What Cloudflare states:** “Turnstile is WCAG 2.2 AA compliant” (developers.cloudflare.com/turnstile,
  read on 2026-09-27). Cloudflare's documentation describes no separate accessible mode: the
  widget is meant to pass without interaction, and at most shows a box to tick.
- **What this audit could not check:** the tests use Cloudflare's testing keys, which pass at
  once without showing a challenge, so the interactive challenge (keyboard use, its target size,
  what a screen reader announces) was not exercised. Public reports exist of keyboard and
  target-size problems with it.
- **What secbin does:** it shows the widget with a visible, named container; while the check is
  pending, the note under the protected button says so and links to the site's contact
  ("If you cannot complete it, contact the administrator"); if the widget cannot load, the page
  says why, with the same link (`public/js/turnstile.js:58`). The owner can make
  account changes for a user, and can turn the check off.

So: with the CAPTCHA **off**, the verdicts above hold for every page. With it **on**, they
hold for secbin's own content on the login, Account and public composer pages, and the widget is
covered by a statement of partial conformance for third-party content: secbin relies on
Cloudflare's claim for the widget's own conformance, and the contact is the way through for
anyone it fails. Criterion 3.3.8 itself is met either way, because the widget asks for no
cognitive function test.

## Security controls and accessibility

A rule of this project: no accessibility fix weakens a security control. Where a criterion and a
control pull in different directions, the control stays and the criterion gets the verdict that
follows:

- **The CAPTCHA** stays on every sign-in (password, passkey, recovery code), every change to
  one's own account and anonymous sharing. 3.3.8 and 3.3.9 are still met (it asks for no
  cognitive function test); its own operability is third-party (see the section above).
- **The absolute session limit** cannot be extended: the warning only says when it comes. At the
  default (7 days) 2.2.1 is met by its 20-hour exception; an owner who sets it under 20 hours
  makes that limit a security time limit that 2.2.1's "extend" option does not cover (the idle
  limit can still be extended).
- **"Stay signed in"** is an ordinary signed-in request: the server slides the idle window as
  for any other request, never past the absolute limit, and only for a live session
  (`src/lib/auth.js:77`; test `test/auth.test.js:102`).
- **The download window** can be extended only by the holder of a live grant, at most ten times,
  never past the share's expiry, and without spending a view; the route has the chunk route's
  guards (cross-site refusal, the Guard's invalid-request blocking) and the grant as its only
  credential (`test/files.test.js:244`). After the last view, the purge
  of the ciphertext waits for an extended window (still at most the share's expiry).
- **Expiry and view limits** stay: 2.2.3 is not met.
- **Share passwords** can be pasted, but password managers are kept from saving them as the
  site's login (they would overwrite the account's saved password).
- **CSP and Trusted Types**: every change builds DOM with `h()` / `textContent`; `wcag22.mjs`
  checks that no page logs a CSP or Trusted Types violation.

## What was fixed in this audit

Level A and AA failures (all fixed):

- **1.4.3** the error toast's text on the dark theme's red (3.7:1) → its own fill.
- **1.4.10** long links, generated keys and the role editor's selects widened the page at
  320 px; the footer links did not wrap → they wrap.
- **1.4.11** text field, option group and editor borders were 1.5:1 → a field colour ≥3:1.
- **2.2.1** the session timed out for inactivity without warning; a file share's download window
  closed without warning and could not be extended; toasts vanished on a timer → the session
  warning with "Stay signed in", the download-window warning with "Keep downloads open" (a new
  server route, at most ten times, spending no view, never past the share's expiry), toasts stay
  until the next key press or click.
- **2.2.2** per-second countdowns (share expiry, download window, one-time code) could not be
  stopped → "Stop the countdown" (on by default with "Stop animations").
- **2.4.2** the share viewer and composer views all had the same title → each view names itself.
- **2.4.3** a view change could take focus away from the header, the footer or the accessibility
  settings → it now moves focus only when focus was on a hidden view or nowhere.
- **2.4.7** focus rings drawn as box-shadows disappeared in forced colours → a system outline.
- **2.4.11** the fixed accessibility button (above dialogs too), the toast and the open settings
  panel could cover the focused control → focus is scrolled clear, the toast moves to the top,
  the panel closes when focus leaves it, dialogs cover the button.
- **2.5.2** the settings panel and the Drive's dialogs closed on mouse-down outside them → on
  click, and only when the press began on the backdrop.
- **2.5.3** several fields' names differed from their visible labels (setup "Owner password",
  Turnstile keys, export passphrase, Drive "Select all", the public role's tracking fields) →
  the visible words are the name.
- **2.5.8** the widget's statement link and the Drive's checkboxes were under 24 px → 24 px
  targets (44 px on phones).
- **3.3.2** fields labelled only by a placeholder (share passwords, repeat-password fields,
  passkey and API key names, API key lifetime, My shares filters, admin fields) → visible labels.
- **3.3.8** (help route) the CAPTCHA's note under each protected button now links to the
  site's contact, while it waits and when it fails. (A passkey route around the check was built
  and then withdrawn at the maintainer's decision: every sign-in keeps the check.)
- **4.1.1** (verified although obsolete) two admin renders could duplicate a panel and its ids
  → renders of a panel are queued.
- **1.1.1** (improvement) a PDF preview page is now named and its text given as text.
- **2.4.11** (found on the owner's view of a user with no Drive) the sticky impersonation banner
  covered the focused control at 400 % zoom → it stays at the top of the page on short
  viewports, and focus is scrolled clear of it.
- **2.4.12** (after the Drive integration's merge) an intermittent partial overlap under the
  accessibility button at 320×256 → explained: Chromium leaves a text field that is already in
  view where it is, and the page scrolls it clear in the next frame, before it is painted; the
  probe had raced that frame. The check now waits for it and tests every point of each overlap
  with a fixed or sticky element, and fails on any (0 in four runs; a negative control fails).
- **1.3.1** (found by the accessibility-tree suite's new Drive states) the Drive page's footer was
  inside `<main>`, so the page had no contentinfo landmark → it follows `<main>`, as on every
  other page (checked for every page by `test-dom/wcag22.test.js`).
- **4.1.3** (after the Drive integration's automatic set-up) the sign-in's "Signing in…" was
  only a button label, and the Drive's new notices were live regions inserted with their text →
  a status line on the login page, and the Drive page's own status line says each notice's title.
- **4.1.3, 4.1.2, 3.3.2, 2.5.3, 2.4.3, 2.4.2, 1.4.12, 1.3.1** (reverse shares, merged from `main`
  3df2e6f): the uploader's "Sent …" and the Drive's received-files line were live regions shown
  with their text, and the unlock screen's count of waiting files one drawn with its text → status
  lines present from the start (the page's own, on the unlock screen); the uploader's drop zone
  was a Tab stop acting as a button with the role of a group → a named group, with its buttons as
  the keyboard way; focus fell to the page while and after sending → "Cancel", then "Choose files"
  (or "Send files" after an error); an ended or paused link's page kept the title "Send files" →
  it names the state; the uploader's footer was inside `<main>` with old link texts → the footer
  of every other page; the dialog's list of file types had no visible label, its "Copy link" was
  named "Copy the link …" and its "Accept files for" box was cut off with text spacing → a label,
  the visible words, a whole row; "Show more" in the review lost focus → the first row it loaded;
  a take-in of received files finishing while a folder opened sent the Drive back to the folder
  being left, and focus to the page (3.2.5, 2.4.3) → the refresh goes to the folder being opened.
- **1.3.1 / 4.1.2** (found by the accessibility-tree suite: a toast from before a Drive dialog
  opened stayed shown and in the tree outside the modal dialog) → a dialog opening puts it away.
  Received files taken in (in the background) after a dialog opened no longer raise their toast
  outside it; the Drive's status line says the same and stays (`public/dashboard/js/drive-app.js`
  `takeInReceived`; `test-dom/reverse.test.js`).
- **1.4.3** (the reverse shares' suite with Turnstile's testing keys, 2 runs in 5 after `main`
  8889932): "Send files" failed colour contrast right after it was enabled. Buttons transitioned
  `opacity` from their disabled 0.45 over 0.2 s, so an enabled button was drawn part-way
  transparent (reproduced deterministically: opacity 0.57 and 2.24:1, 40 ms after enabling, light
  theme) → no opacity transition on `.cta`, `.send` or the toast (`public/css/styles.css`;
  `test-dom/wcag22.test.js`), so an enabled control is at full contrast at once.
- **1.4.3 / 1.4.6 in every frame** (the same kind of failure, elsewhere in the style sheet): the
  entrances (`.reveal`, the dialogs and their scrim, the seal label, the install banner) and the
  view exit faded text in or out through opacity; the countdown's last minutes pulsed the clock
  to half opacity every second, with no end (2.2.2 too); the theme flip's wave had a soft band
  where the two palettes blended, and without View Transitions the fallback interpolated text and
  background colours together (grey on grey half-way). Now: motion without fading, the scrim
  darkening by its colour, the clock bold instead of pulsing, the wave with a hard edge, and the
  fallback switching palettes at once (`public/css/styles.css`; `test-dom/wcag22.test.js`: no
  `@keyframes` or transition changes opacity).
- **1.3.1, 3.2.3** (the CAPTCHA check page from `main`): its footer was inside `<main>` with the
  old link texts and no glossary link → every page's footer, after `<main>`.
- **2.4.7** (the CAPTCHA, found with Turnstile's testing keys) focus inside Cloudflare's widget
  showed no ring on secbin's side → its container draws one. In Chromium `:focus-within` does not
  match while focus is in the widget's frame (behind a closed shadow root), and the page gets no
  focus event for it, only its window's blur; the container is now marked whenever the page's focus
  changes (`public/js/turnstile.js`, `.focus-in`), and the ring was confirmed with the testing keys
  on the uploader page's three widget Tab stops (`test-dom/turnstile.test.js`).
- **2.4.11, 2.4.12** (found on the new states that show a toast) at 320×256 a toast moved to the
  top covered the controls Tab reached next → it moves to the other edge when focus goes under
  it, and is put away when it would cover focus at both edges.
- **4.1.3, 1.3.1, 3.3.1, 3.3.2, 2.4.3** (the owner recovery kit, start over and the archive,
  merged from `main` 9d11b66): the kit forms' messages were live regions shown with their text →
  inside a status line present from the start; the passphrase warning was not tied to its field
  → it describes the field while it shows; the kit card named a plain `<div>` → it and the archive
  box are sections named by their headings; the reset's unlock field had no visible label and its
  "Continue without unlocking" box no description → a label and its warning; the create-user
  note appeared in a new live region → also said through the toast; a user's automatic move to a
  reset's escrow key was a live region drawn with its text → the Drive page's status line says it
  (and stays in place through the unlock screen); start over and the archive's delete form marked
  only some wrong fields → the field at fault is invalid and described; focus fell to the page
  after an unlock, a restore, a start over or an archive deletion → a heading.

AAA criteria implemented: 1.4.6 (7:1 palette, both themes), 1.4.8 (Text spacing mode), 2.2.5
(sign in again in a new tab without losing work), 2.2.6 (session length stated on login and
Account), 2.4.9 (self-describing links, new-tab notices), 2.4.12 (tall editor fits short
screens), 2.5.5 (Large buttons and links mode), 3.1.3 and 3.1.4 (glossary), 3.2.5 (no automatic
change of page; new tabs announced), plus the site map (2.4.5).

## What is not fully met, and why

- **2.2.3 No Timing (AAA): does not support.** Expiry is the product: shares self-destruct after
  their views or time, a view opens a limited download window, and sessions end for security.
  Each can be extended (2.2.1); none can be removed without removing the feature.
- **3.1.5 Reading Level (AAA): does not support.** The subject needs specialist words; there is
  no simplified version. The glossary explains them. Shared notes are the senders' text.
- **1.2.1–1.2.9, 1.4.7, 2.5.4, 3.1.6: not applicable.** secbin has no audio or video of its own,
  nothing responds to motion, and no word's meaning depends on pronunciation. Audio and video
  that users share play with the browser's controls and can always be downloaded.
- **Outside secbin's control**, with the app side made accessible:
  - *content users share* (PDFs, documents, images, media): secbin cannot make it accessible;
    it can always be downloaded, a PDF preview gives its text, an image preview its file name;
  - *the Turnstile widget* (third party, when the owner turns it on): every sign-in needs it;
    Cloudflare states it conforms to WCAG 2.2 AA, which this audit could not verify (its test keys
    show no challenge). The note under each protected button links to the contact; the owner can
    make account changes for a user or turn the check off. See “The CAPTCHA (third-party)”.
- **Configuration**: the owner can set the absolute session limit below 20 hours (the default is
  7 days); the app then warns two minutes ahead but cannot extend it, as that limit is a security
  control.

## Conclusion

On the evidence of this audit (Chromium, automated and manual checks, code review), secbin's own
pages and states:

- **WCAG 2.1 level A**: meet every criterion (all *Supports* or *Not applicable*).
- **WCAG 2.1 level AA**: meet every criterion.
- **WCAG 2.2 level A**: meet every criterion, including 3.2.6 and 3.3.7.
- **WCAG 2.2 level AA**: meet every criterion, including 2.4.11, 2.5.7, 2.5.8 and 3.3.8.

These level results hold for every page with the CAPTCHA off. With it on, the login,
Account and public composer pages also contain the third-party Turnstile widget, whose own
conformance secbin takes from Cloudflare's statement and could not test: for those pages the
result is WCAG's *partial conformance, third-party content*, with the contact as the way
through.
- **WCAG 2.2 level AAA**: 23 of the 31 criteria are met; 2.2.3 and 3.1.5 are not;
  the rest are not applicable. 1.4.8 and 2.5.5 are met through the widget's "Text spacing" and
  "Large buttons and links" modes (a style switcher on every page).

This is not yet confirmed with assistive technology by people: see below. Until it is, treat the
AA result as a strong expectation, not a guarantee.

## What remains for people with assistive technology

Everything above was measured in Chromium. It has not been confirmed by people using:

- screen readers: **NVDA** (Windows, with Firefox and Chrome), **JAWS** (Windows, Chrome and
  Edge), **VoiceOver** on macOS (Safari) and on iOS (Safari), **TalkBack** on Android (Chrome);
- **voice control** (Voice Control on macOS/iOS, Dragon), which depends on label in name;
- **switch access** and **screen magnifiers** (ZoomText, macOS Zoom);
- **Safari** and **Firefox** as browsers: focus rings, `inert`, the `details` element, the PDF
  text panel, forced colours in Firefox, and text-only zoom in Firefox (View → Zoom Text Only).

### Test script

Do each task with the keyboard and a screen reader, then with voice control, then at 400 % zoom.
Note anything that is not announced, announced wrongly, hard to reach or hard to understand.

1. **Landing and statement.** Open `/`. Find "Skip to main content"; follow the footer to the
   accessibility statement, its site map and its glossary. Open the accessibility settings;
   switch every option, change language to Hebrew and back, close with Escape.
2. **Sign in.** Log in with a password (paste it from a password manager), then with a passkey,
   then with a recovery code. Make a mistake first: is the error announced and tied to the field?
   With the CAPTCHA on (real keys, not the testing keys): can the widget and its challenge
   be completed by keyboard, by voice and with a screen reader? Is the note under the button,
   with its contact link, read?
3. **Create a note** in the dashboard with a password: the password dialog's two labelled fields,
   the confirmation, the link, the QR code's text alternative, "copy link".
4. **Open it as the recipient** in a private window: the password prompt, the note, "Stop the
   countdown", "Delete now".
5. **Files.** Share a folder with the viewer on; as the recipient, walk the folder tree and the
   file table, preview an image and a PDF (read "Text of this page"), download all. Wait for the
   download-window warning (the owner can set the window to 5 minutes): is it announced, and does
   "Keep downloads open" work?
6. **Drive.** Unlock it, create a folder, upload files, select items (by the whole row checkbox
   target), move them with the folder picker, share, see the shares of an item, delete. Walk the
   folder tree with the arrow keys and type-ahead. As a new user, sign in before the owner has
   ever signed in (is "Drive is not ready yet" announced when the Drive page opens?), then after
   (is "Signing in…" announced, and does the Drive open with no prompt?). As the owner, log in as
   a user who has never signed in and open Drive: is the notice announced?
   As the owner: on the Drive page and on Admin → Import / export, read the kit status and the
   "no kit yet" notice; download a kit with no passphrase (is the warning read with the field?),
   verify the saved file (is the verdict read, then each check with its status in words?), restore
   from it. Replace the escrow key: is the notice to download a fresh kit announced? After an
   AUTHN recovery, open Drive: restore from the kit, then start over (type a wrong username first:
   is the error read with the field?); delete the old Drive's archive. Where is focus after each?
   Create a user with your Drive unlocked and locked: is the note about their Drive announced?
   Reverse shares: on a Drive folder, "Receive files…" (make a link with a password and a list of
   file types); open the link in a private window: read the note and the limits, choose files by
   keyboard, give a wrong password (is the error read with the field?), send (is progress, then
   "Sent …" read; where is focus?). Back in the Drive while it is locked: is the count of waiting
   files read? Unlock: is "… added to your folders" read, and can "Review them" be reached?
7. **My shares and Account.** Filter shares, extend one, revoke one. Change your password
   (paste), add a passkey, make recovery codes, create an API key.
8. **Admin.** Create a user and a role, edit the Default role's session timeouts, open every tab.
   Set the idle timeout to 5 minutes, wait: is the warning dialog announced, can you stay signed
   in, and after it expires, can you sign in again in a new tab and save what you typed?
9. **Windows High Contrast** (forced colours): repeat 1, 3 and 6 and check every focus ring.

## Tests

- `test-dom/wcag22.test.js`: the session warning (idle and absolute, extend twelve times, focus
  and `inert`, no navigation on its own), "Stop the countdown", focus not obscured, view titles,
  new-tab links, labels and autocomplete on the static pages, no paste blocking, the CAPTCHA
  help, and the palette (7:1 text, 3:1 field boundaries) in both themes.
- `test/files.test.js` "extending a download window": ten extensions and no more, no view
  spent, never past the share's expiry, the purge waits for an extended window; an id that was
  never a share counts as invalid (as on the chunk route), a share that ended does not.
- `test-dom/drive.test.js` "a notice instead of the Drive": the page's status line (the same
  node, in the page from the start) says the notice's title for "not ready yet", the owner's
  no-Drive notice and "not enabled"; the notice has no live role; the user's text says "the
  administrator".
- `test-dom/wcag22-drive.test.js`: the kit card (a named section; every form's message inside a
  status line that is there before it; the passphrase warning describing its field only while it
  shows), the unlock screen and start over (the page's status line the same node throughout; the
  field at fault invalid and described; focus on the folder's heading after the start over, a
  restore and the archive's deletion), and a user's automatic move to a reset's key said by the
  status line; `test-dom/reverse.test.js` "WCAG 2.2: reverse shares": the uploader's drop zone (a
  group, not a Tab stop), "Sent …" inside a status line there from the start, focus on "Choose
  files" after a send, the error state's page title, the dialog's labelled type list, "Copy link"'s
  name, the received-files status line and the unlock screen's count said by the page's status
  line; `test-dom/admin-new-user-drive.test.js`: the create-user note also in the toast, the
  reset's unlock field labelled and its box described.
- `test/turnstile.test.js` (unchanged): every sign-in, the passkey included, needs a token when
  the CAPTCHA is on.
- `wcag22.mjs` (scratch Playwright suite used for this report; it is not part of CI): the probes
  described above, on every page and state, at three viewports, and `--aaa`. The kit's states
  come from one scratch module (`kitstates.mjs`) that `wcag22`, `axe-audit`, `a11y` and the
  accessibility-tree suite share, in two phases on one server state: phase 1 on a fresh server,
  phase 2 after restarting it with a new `AUTHN` value (AUTHN owner recovery, start over, the
  archive, a user's automatic move). A state that can be reached only once (the start over, the
  automatic move) is checked at one viewport, or at 1280×900, 320×640 and 320×256 on one page.
  The reverse shares' states come from a second shared module (`revstates.mjs`) used by `wcag22`,
  `axe-audit` and the accessibility-tree suite: links made through the Drive's dialog on the
  owner's own Drive, uploads from fresh browser contexts (one with its key wrap spoiled on the way,
  so that a received file cannot be added and can be reviewed), chunk uploads held back to see the
  "uploading" state, and the owner's start over in phase 2 pausing the links; the CAPTCHA with
  Cloudflare's public testing keys in a pass of its own (`REV_TS=1`, Chromium through the agent
  proxy).

Results of the final run after merging `main` 5ae4f93 (the owner recovery kit, reverse shares, CSRF
tokens), on 032c081: `npm test` 502 + 127 + 362 + 261 passed, `npm run lint` and `sync-shared --check`
clean. End to end:
- `wcag22 --aaa`: 28/28 in phase 1 (79 states, the kit's and the reverse shares' included), 3/3 in
  phase 2 (10 states: AUTHN recovery, start over, the archive, the paused uploader) and 3/3 with
  Turnstile's testing keys; 0 AAA findings, 0 A/AA findings, no CSP or Trusted Types errors;
- `axe-audit`: 0 violations (147/147, 34/34 and 8/8 states reached in both themes at desktop and
  phone widths);
- `a11y`: 84/84 and 29/29;
- the accessibility-tree suite: 344/344, 30/30 and 6/6;
- `run`: 39/39; `drive-int`: 105/105; `owner-kit`: 33/33 and 12/12;
- `reverse`: 41/41, and 43/43 with the testing keys.

Four fixes came from this round: the light theme's danger-button contrast on its tinted fill
(1.4.6), no take-in toast outside a modal dialog (1.3.1, 4.1.2), the CAPTCHA container's focus ring
(2.4.7; `:focus-within` does not match inside Cloudflare's frame), and an Admin tab chosen while the
page loads staying chosen (3.2.5). Each has a test that fails without it.

The scratch suites needed two harness changes, neither of them to a check:
- their raw requests send the session's CSRF token, which `main` now requires on every
  signed-in change, logout included;
- each held-back "uploading" visit comes from an uploader network of its own, as the server allows
  5 open upload sessions per network on a link.

Attempts that lost their `wrangler dev` server part-way (wrangler's dev proxy exits with "Network
connection lost" on a loaded machine) are not counted.

Results of the final run after merging the Drive integration cdcc5c7 (with `main` 6c5e2fc):
`npm test` 393 + 116 + 246 + 261 passed, `npm run lint` and `sync-shared --check` clean; end to
end: `wcag22 --aaa` 27/27 with 0 AAA findings and 0 A/AA findings (45 states, the Drive
integration's three included), `axe-audit` 0 violations (the three new states in both themes at
desktop and phone widths: 12/12 reached), `a11y` 30/30, the accessibility-tree suite 220/220 (the
copy updated for the merged UI, with the new states), `run` 39/39, `drive-int` 104/104 and
`drive-impersonate` 36/36 (the branch's own `test-e2e/`). One earlier `wcag22` attempt failed its
download-window check on timing (the suite's 300 s window equals the 5-minute warning, so an
extension one second later is rightly warned about again); the check now waits past a second and
asserts that the end moved.

Results after closing 2.4.12 (the strict check, with 400 % zoom at 4 device pixels as a fourth
viewport): `npm test` 393 + 116 + 246 + 261 passed, `npm run lint` and `sync-shared --check`
clean; `wcag22 --aaa` 27/27 in each of four complete runs (180 state × viewport checks each; 0
AAA, 0 A/AA findings, 0 "2.4.12 focus partly obscured"), and 8 findings with the negative
control; `axe-audit` 0 violations (12/12 Drive-integration states reached), `a11y` 30/30, the
accessibility-tree suite 220/220, `run` 39/39. Four other `wcag22` attempts lost their
`wrangler dev` server part-way (the dev proxy exited with an error; the pages then refused the
connection) and are not counted; none of them recorded a 2.4.12 finding before that.

Results of the previous final run (2026-09-27, this branch after merging `main` 986d6cb and the
Drive integration 87e2d74): `npm test` 383 + 116 + 237 + 261 passed, `npm run lint` and
`sync-shared --check` clean; end to end: `wcag22 --aaa` 17/17 with 0 findings (A/AA probes, the
time-limit checks and AAA), `axe-audit` 0 violations, `a11y` 30/30, `run` 39/39 (one earlier
attempt timed out on a click while another suite loaded the machine; the rerun passed), and
`drive-int` 104/104 (the branch's own `test-e2e/drive-int.mjs`). Before these merges the
accessibility-tree suite passed 207/207 in a copy updated for the merged UI (the original, written
before the Drive integration, fails the same 5 checks on the commit before this audit).