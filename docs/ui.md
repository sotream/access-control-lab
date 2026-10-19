# User interface (stages 10 and 12)

A modern defence console for the Casefile Vault: dark first, refined near-black layers with soft depth, one steel-blue accent, olive, amber and brick for classification, a clear sans for the interface and a mono for identifiers, hashes, timestamps and classification labels. It is server-rendered; the only script is a 20-line countdown. Stage 10 built the first version (a flat, bordered "dry gov console"); stage 12 redesigned it (ADR-26). Nothing in either stage weakens a control of stages 6 to 9: the CSP, the CSRF token on every state-changing form and the escaped output are unchanged, and a real browser checks them (`tests/e2e`).

Screenshots are generated, never edited by hand: `pnpm screenshots` starts a **fresh** prod-like stack, signs in as the seed users, creates the demo case files of `tests/e2e/src/screenshots.spec.ts` (German-titled, with one attachment, one approval, a CONFIDENTIAL and a SECRET file), renders every page in light and dark into [docs/screenshots/](screenshots/) and tears the stack down. The spec refuses to run when the case list is not empty, so leftovers of other suites can never end up in an image. Pages: landing, case list, case detail, new case, secret case, review queue, break-glass, session, audit log, chain verification, 404.

## Principles

1. **Classification is never colour alone.** The level is always a word (OFFICIAL, CONFIDENTIAL, SECRET). The badge also differs in border (solid, dashed, heavy), the banner is a rounded strip that stays at the top while scrolling, and status chips carry a glyph (check, exclamation, cross) next to the word.
2. **Identifiers are monospaced and short.** Ids and hashes are shown as a prefix with the full value in the `title` and, where it matters, in the page itself.
3. **Break-glass looks like nothing else.** A double red frame, the word "Break-glass", the warning that the access is recorded, a required justification. The result page repeats the frame and says the access was recorded.
4. **Refusals leak nothing.** A hidden case file and a missing one render the same 404 page (ADR-9). The page never says "forbidden" for a case file. 429 and 503 give advice, not internals.
5. **One decision per control.** What a page shows is a convenience; the API decides. Buttons that cannot work in the current status are disabled, never hidden, and say why.
6. **No decoration.** No gradients, shadows, illustrations or motion. `prefers-reduced-motion` switches off whatever animation exists (there is none today).

The skill-driven design pass is summarised in the pull request description (what it recommended and what was rejected, with reasons).

## Layout

- **Sidebar** (every signed-in page): brand, role-based navigation with an icon per entry and the current page marked by a bar and a fill, and at the bottom the theme choice and sign-out. Below 52rem it becomes a block above the content.
- **Top bar:** one row of session chips: user (short id), roles, clearance badge, unit, compartments, sign-in strength (**MFA verified** or **pwd only**) and the session expiry (absolute time, a live countdown when the script runs). Signed out, it carries the brand, the theme choice and the sign-in button.
- **Side navigation by role** (`src/ui/nav.ts`, unit-tested): analyst: my cases, new case; reviewer: review queue; unit-admin: unit cases, new case, break-glass; auditor: audit log, chain verification; everyone: overview, session. platform-admin has no page of its own yet (there is no users page).
- **Classification banner** on every case page (list: highest level shown; detail: the case's level; break-glass result: the case's level).
- **Skip link**, landmarks (`header`, `nav`, `main`, `footer`, labelled `aside` and `section`), one `h1` per page.

## Tokens

All design values are CSS variables in `apps/web/styles/ui.css`, mapped into the Tailwind theme with `@theme inline`. **Dark is the default**, also when the browser states no preference. Light follows `prefers-color-scheme: light` unless the user chose dark; an explicit choice (`data-theme` on `<html>`) always wins. Depth comes from layering (`--bg` < `--surface` < `--surface-2` < `--surface-3`) and one soft shadow (`--shadow`); hairline borders (`--line`) separate, and form controls use `--line-strong`, which is held at 3:1 against the surface.

| Token group | Names |
|---|---|
| Surfaces | `--bg`, `--surface`, `--surface-2`, `--surface-3`, `--field` (inputs), `--line`, `--line-strong`, `--shadow`, `--shadow-sm` |
| Text and links | `--text`, `--muted`, `--link` (underlined everywhere, also in tables), `--accent` (primary button), `--accent-bright` (active navigation, brand mark), `--accent-text`, `--focus` |
| Shape and motion | radius 4 px (chips), 6 px (controls), 10 px (panels, tables, banner); 140 ms colour transitions, none under `prefers-reduced-motion` |
| Tones | `--danger`, `--warn`, `--ok`, `--info` (each with `-bg`) |
| Classification | `--cls-official`, `--cls-confidential`, `--cls-secret` (badge, each with `-bg`); `--bar-*` and `--bar-text` (banner) |
| Type | Inter Variable (text), JetBrains Mono Variable (identifiers, timestamps, content), both self-hosted |

Fonts: variable woff2 files in `apps/web/public/fonts/` (latin, latin-ext, cyrillic subsets; German umlauts are in latin), with the SIL OFL texts next to them (`Inter-OFL.txt`, `JetBrainsMono-OFL.txt`). No CDN.

The stylesheet is compiled at build time (`pnpm --filter @acl/web css`, run by `predev` and `prebuild`) into `public/ui.css`, which is generated and not committed. The image copies `public/` explicitly (`Dockerfile.web`).

## Theme

A plain form posts the choice to `/actions/theme`, which sets a host-only cookie (`__Host-casefile_theme` when secure) and redirects to a page from a fixed list. With a session the CSRF token is required like on every form; without one (the sign-in page) Origin and Sec-Fetch-Site are still checked. The layout renders `data-theme` from the cookie. No script, no inline style, no storage in JavaScript: the CSP is untouched.

## Components

`src/ui/components.tsx`: `Badge`, `Banner`, `Chip`, `Status`, `StatusChip`, `ScanChip`, `Alert` (with an icon), `Panel`, `KV`, `Field`, `Mono`, `Page`, `TableWrap` (a named, focusable scroll region around a table), `Empty` (icon and sentence). `src/ui/icons.tsx`: one inline-SVG set of hand-drawn stroke icons on a 24 px grid (`currentColor`, `aria-hidden`, always next to a text label): no icon font, no sprite file, no request, nothing for the CSP to allow. `src/ui/chrome.tsx`: `Chrome`, `TopBar`, `SideNav`. `src/ui/case-list.tsx`: the list used by my cases, unit cases and the review queue. `src/ui/stepup.tsx`: the step-up explanation. `src/ui/errors.tsx`: `ErrorView`.

Selects use a chevron drawn with two gradient strokes (no image, no `data:` URI, no script; the CSP is untouched): 14 px wide, 0.75rem from the right edge, with `padding-right: 2.5rem` so a label never runs under it; the colour is a token (`--muted`, `--text` on hover), disabled selects are dimmed, and in forced-colors mode the browser's own arrow is used. `tests/e2e/src/controls.spec.ts` pins the numbers in both themes.

Every string is in `src/ui/i18n.ts` (English). A German dictionary is a second object of the type `Dict` and a locale switch in `dict()`; nothing else needs to change. Data (titles, units) is never in the dictionary and is always rendered through React (escaped); there is no `dangerouslySetInnerHTML`, and `ui.test.ts` checks that no dictionary string contains markup.

## Pages

| Path | Page | Notes |
|---|---|---|
| `/` | Landing | sign in, or open my work |
| `/cases` | Case list | filters (text, status, classification, unit), sortable headers with `aria-sort`, pagination of 25, all via GET |
| `/review` | Review queue | the same list fixed to submitted |
| `/cases/new` | Create | labelled fields with hints |
| `/cases/{id}` | Detail | details, content, attachments with scan status, workflow stepper and actions |
| `/cases/{id}/edit` | Edit | drafts only |
| `/cases/{id}/break-glass`, `/break-glass` | Emergency access | entry by case-file id, framed form |
| `/cases/{id}/break-glass/result` | Result | the audited read (see below) |
| `/audit`, `/audit/verify` | Audit log, chain verification | filters, proof panel (latest checkpoint), export, verdict |
| `/session` | Session | the API's own view of the session |
| any | Errors | one generic page per status (400, 401, 403, 404, 429, 500, 503) |

Step-up: a case file that needs a second factor shows an explanation (why, what happens next) and a button; it shows no case data.

## Choices worth questioning

- **Break-glass hand-over.** The form POST (CSRF-checked) answers 303 and puts the justification in a 2 minute `HttpOnly` host-only cookie; the result page does the audited read. This lets the page share the layout (a route handler cannot render React in Next.js 16). A reload of the result is a second audited read. Alternative considered: hand-written HTML in the route handler (a second copy of the frame).
- **Top bar from the token.** Roles, clearance, unit and compartments are read from the access token for display (no extra upstream call per page). They never feed a decision.
- **`Referrer-Policy: same-origin`** instead of `no-referrer` on the web app (ADR-25).

## Accessibility (WCAG 2.2 AA target)

Measured, not asserted:

- `tests/e2e/src/roles.spec.ts`: axe-core (rules `wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa`, `wcag22aa`) on every page of every seed role, in system light and system dark: no serious or critical finding. The case detail, the break-glass result and the audit log are checked in the workflow tests too.
- `apps/web/src/ui/contrast.test.ts`: every text and background pair of the tokens, in dark, light and light-by-system, against 4.5:1 (text) and 3:1 (focus ring, control borders, the navigation marker). The numbers are in the test, not repeated here.
- `tests/e2e/src/keyboard.spec.ts`: the skip link is the first stop and moves focus to `main`; every stop has a visible outline of at least 2 px; the tab order of the create form follows reading order; the filters are reachable in order; Enter submits.
- Form controls have visible labels, hints are associated with `aria-describedby`, notices use `role="status"` or `role="alert"` and a leading word (Problem, Notice, OK), tables have captions, column and row headers, and sort state.

Not covered: screen readers (no assistive technology was run), 200 percent zoom and reflow at 320 px (the layout collapses to one column below 52rem; not measured), forced-colours mode, and German text length.

## Tests and CI

- `apps/web/src/ui/*.test.ts` and `src/server/ui-server.test.ts`: navigation by role, list query parsing (fixed lists, bounds), error pages, dictionary, break-glass cookie, token display, theme cookie, contrast.
- `tests/e2e` (Playwright 1.64.1, Chromium only, ADR-25): one real sign-in per seed user, then the specs above plus the main flows and `browser-security.spec.ts`: cookie attributes (`__Host-`, Secure, HttpOnly, SameSite=Lax, path `/`, host-only), no token in `document.cookie`, storage or the DOM, an injected inline script, handler and foreign image refused and reported by the browser, no framing from another origin, headers on a real load, theme toggle under the CSP. CI job `e2e-browser`.
- All earlier suites still run: the BFF tests (updated for the break-glass hand-over), the attack suite, the prod-like test, the lint guards.

## How to add a page

1. Create `apps/web/app/<path>/page.tsx` (a server component). Call `requireSession("<path>")` first; add the path to `ALLOWED` in `src/server/redirect.ts` (and its test) if it is a valid return-to target.
2. Put every string in `src/ui/i18n.ts`. Build the page from `Page`, `Panel`, `KV`, `Field` and friends; use `ErrorView` for refusals and `notFound()` for hidden or missing case files.
3. A state-changing form posts to a route handler under `app/actions/` that uses `formAction` (session, CSRF, size bound) and carries `<input type="hidden" name="csrf" value={session.csrfToken} />`.
4. Add the page to `navFor` in `src/ui/nav.ts` for the roles that need it, and to `tests/e2e/src/roles.spec.ts` (axe and the CSP collector run on it).
5. No inline style, no inline handler, no `dangerouslySetInnerHTML`, no remote asset: the browser tests fail on all of them.

## Not verified

- No assistive-technology testing; no mobile device testing; Chromium only (Firefox and Safari behaviour of the CSP, cookies and forms is assumed to match, not run).
- The countdown script is the only client code; its behaviour with a skewed client clock is not specified (the server remains the authority on expiry).
- Screenshots are generated on one machine with Chromium's default fonts for anything not in the self-hosted set; they are documentation, not a visual regression suite.

## Forced colors, zoom and narrow screens

Checked by looking at the rendered pages (Chromium emulation), not by an assertion: in `forced-colors: active` surfaces that are told apart by fill get a border, the current navigation entry gets an outline instead of the coloured bar, and selects show the browser's own arrow; at 200 percent zoom (640 CSS px) and at 390 px the sidebar becomes a block above the content, chips and filters wrap, tables scroll inside their focusable region, and the page itself does not scroll sideways. A loading skeleton was deliberately not added: with a loading boundary Next.js has already sent the status line when a page calls `redirect()` or `notFound()`, so a hidden case file would answer 200 instead of the 404 that ADR-9 and the BFF tests require.
