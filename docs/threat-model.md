# Threat model

Method: STRIDE per component (Spoofing, Tampering, Repudiation, Information disclosure, Denial of service, Elevation of privilege). Written before feature code (stage 1). Living document: every threat gets a mitigation, the stage that implements it, and a link to the test that covers it once that test exists.

Status legend: items marked **(unverified)** are assumptions or library/product behaviour not yet checked against the actual version in use.

## Assets

| ID | Asset | Why it matters |
|----|-------|----------------|
| A-1 | Case file content and attachments | The product; confidentiality by classification and compartment |
| A-2 | Case file metadata (classification, unit, compartments, status) | Inputs to ABAC decisions; tampering changes who may read |
| A-3 | User identity and attributes (roles, clearance, unit, compartments) | Inputs to every authorization decision |
| A-4 | Tokens (access, refresh, ID) and BFF session | Bearer credentials; theft means impersonation |
| A-5 | Audit log | Evidence; integrity matters more than secrecy |
| A-6 | Keycloak admin access, realm config, signing keys | Control plane of identity |
| A-7 | Secrets (DB passwords, client secrets, session keys) | Lateral movement |

## Attackers

| ID | Attacker | Capability |
|----|----------|------------|
| X-1 | Anonymous internet user | Network access to the web app only |
| X-2 | Authenticated low-privilege user (insider) | Valid session, wrong role/clearance/compartment; tries IDOR and escalation |
| X-3 | Malicious web content / other origin | Makes the victim's browser send requests (CSRF, XSS payload in uploaded files) |
| X-4 | Compromised or malicious `unit-admin` / `platform-admin` | Legitimate elevated rights, abuses them (separation-of-duties, audit tampering) |
| X-5 | Attacker with network position between components | Sniff or alter traffic inside the deployment (relevant outside local dev) |
| X-6 | Supply chain attacker | Malicious dependency, action or image |

Out of scope for this lab: physical access, compromised host OS or hypervisor, nation-state attacks on Keycloak itself, denial of service at network layer.

## Components and trust boundaries

```
 [Browser] --TB1--> [Next.js BFF] --TB2--> [NestJS API] --TB3--> [Postgres]
     |                    |                     |   \--TB5--> [File storage]
     |                    \----TB4---------------+--> [Keycloak]
     \--TB4 (redirect login, end-session)-------->[Keycloak]
```

| ID | Boundary | Crossing data | Rule |
|----|----------|---------------|------|
| TB1 | Internet / browser to BFF | Session cookie, form posts, redirects | Untrusted. Cookie only, no tokens in the browser. All input validated. |
| TB2 | BFF to API | Access token (Bearer) | API trusts only a validated JWT, never the BFF's say-so. |
| TB3 | API to Postgres | SQL, session attributes for RLS | App role has no BYPASSRLS, not table owner. Parameterised queries only. |
| TB4 | BFF and API to Keycloak | Code exchange, refresh, JWKS, end-session | TLS outside dev, issuer pinned, algorithm allow-list. |
| TB5 | API to file storage | Attachment bytes | Storage is not directly reachable by users; access only through authorised API. |

## STRIDE per component

### Browser (untrusted client)

| STRIDE | Threat |
|--------|--------|
| S | Session cookie stolen or fixed (T-04, T-05) |
| T | User edits requests, hidden fields, client-side checks bypassed (T-12) |
| R | User denies an action (T-24) |
| I | Tokens in JS-readable storage; leakage via XSS (T-04, T-07) |
| D | Request floods from one client (T-27) |
| E | Hiding UI controls treated as authorization (T-12) |

### Next.js BFF

| STRIDE | Threat |
|--------|--------|
| S | Login CSRF, OAuth `state` / PKCE bypass, open redirect after login (T-02, T-03) |
| T | CSRF on state-changing routes (T-05) |
| R | Logout not propagated, session lives on in Keycloak (T-06) |
| I | Tokens or session payload logged or sent to the client; missing security headers / CSP (T-04, T-07) |
| D | Session store exhaustion, refresh storms (T-27) |
| E | BFF forwards a token with more scope than needed; BFF used as confused deputy (T-09) |

### NestJS API (resource server)

| STRIDE | Threat |
|--------|--------|
| S | Forged/tampered JWT: `alg=none`, algorithm confusion, wrong `iss`/`aud`, expired token, key-id games (T-08, T-09, T-10) |
| T | Mass assignment changes classification, unit or status (T-13) |
| R | Decisions not logged, so denials and break-glass leave no trace (T-24, T-25) |
| I | IDOR on case files and attachments; list endpoints leak rows; verbose errors (T-11, T-14, T-15) |
| D | Unbounded queries, large uploads (T-27, T-28) |
| E | Role check without ABAC; missing guard on one route; reviewer approves own file; step-up (`acr`) not enforced (T-11, T-12, T-16, T-17) |

### Keycloak

| STRIDE | Threat |
|--------|--------|
| S | Weak admin password, default realm settings, MFA not enforced for high clearance (T-18, T-19) |
| T | Realm config changed by hand and drifts from code; protocol mapper edited to add claims (T-20) |
| R | Admin events not recorded (T-24) |
| I | Refresh token replay after theft; over-broad client scopes (T-21, T-09) |
| D | Brute force on login (T-22) |
| E | Attribute (clearance, compartments) self-editable by user; client allowed to set own roles (T-19) |

### Postgres

| STRIDE | Threat |
|--------|--------|
| S | Shared credentials between app and Keycloak (T-23) |
| T | SQL injection; direct write to audit table (T-14, T-26) |
| R | Audit rows altered or deleted (T-26) |
| I | A code path forgets the ABAC check and returns foreign rows (T-15); backups or dev volumes readable |
| D | Connection exhaustion (T-27) |
| E | App role is owner or has BYPASSRLS, so RLS is moot (T-15) |

### File storage

| STRIDE | Threat |
|--------|--------|
| S | Download URL guessable or shareable beyond the authorised user (T-29) |
| T | Attachment replaced after approval; hash not checked (T-30) |
| R | Download not audited (T-24) |
| I | Direct object access bypasses the API; path traversal via filename (T-29) |
| D | Disk filled by uploads; zip bombs (T-28) |
| E | Uploaded active content (HTML, SVG, script) served inline and executes in app origin (T-07, T-31) |

## Threats

"Covered by test" lists the tests and checks that fail when the mitigation breaks, including the black-box attacks of stage 9 (`docs/attack-catalogue.md`), or points at an accepted risk (`docs/accepted-risks.md`). `scripts/check-threat-coverage.mjs` (part of `pnpm lint`) fails when a threat has neither an existing test or check nor an accepted risk, or refers to a file that does not exist. Stage numbers refer to `docs/plan.md`.

| ID | Threat | Mitigation | Stage | Covered by test |
|----|--------|------------|-------|-----------------|
| T-01 | Secrets committed to the repo | `.env` gitignored, `.env.example` only with dev-only values, gitleaks in CI | 1 | `.github/workflows/ci.yml` (job `secret-scan`: gitleaks over the full history, `.gitleaksignore` entries are exact and justified), `scripts/prod-like-setup.mjs` (secrets generated per run, `secrets-dev/` git-ignored) |
| T-02 | OAuth code interception, login CSRF | Authorization Code + PKCE, `state` and `nonce` verified, exact redirect URI match in Keycloak client | 2, 6 | `tests/identity/src/identity.test.ts` › clients: no-PKCE, `plain`, wrong redirect, code reuse, wrong verifier (Keycloak side; BFF `state`/`nonce` stage 6); `tests/bff/src/auth-flow.test.ts` (S256 challenge, state/nonce per attempt, state mismatch, wrong `iss`, replayed callback, cross-flow code, pre-auth cookie tampering), `apps/web/src/server/preauth.test.ts` Attack: `tests/attack/src/session-bff.test.ts` (A-15, A-16); `tests/attack/src/jwt-api.test.ts` (A-09) |
| T-03 | Open redirect after login or logout | Post-login redirect restricted to same-origin relative paths; Keycloak valid redirect URIs without wildcards | 2, 6 | `tests/identity/src/identity.test.ts` › clients: redirect URI variants rejected (Keycloak side; BFF post-login redirect stage 6); `apps/web/src/server/redirect.test.ts` (70 hostile and allowed return-to values), `tests/bff/src/auth-flow.test.ts` (end to end: callback redirects only to app paths) Attack: `tests/attack/src/session-bff.test.ts` (A-15) |
| T-04 | Token theft from the browser (XSS, localStorage) | BFF: tokens stay server-side, browser holds only an `httpOnly`, `Secure`, `SameSite` session cookie | 6 | `tests/bff/src/auth-flow.test.ts` (no token or JWT-shaped string in any page, response, header, cookie, static bundle or server log; cookie is opaque), `tests/bff/src/session-store.test.ts` (tokens encrypted at rest, cookie value not stored) Attack: `tests/attack/src/session-bff.test.ts` (A-12); `tests/attack/src/injection-xss.test.ts` (A-31) |
| T-05 | CSRF on state-changing requests; session fixation | `SameSite` cookie plus CSRF token or origin check on non-GET; new session id on login | 6 | `tests/bff/src/csrf-proxy.test.ts` (10 forged variants on logout, form actions and JSON proxy; GET is 405; no CORS grant), `apps/web/src/server/csrf.test.ts`, `tests/bff/src/auth-flow.test.ts` (session fixation: planted cookie never adopted, old id destroyed, per-user cap) Attack: `tests/attack/src/session-bff.test.ts` (A-11, A-13, A-14) |
| T-06 | Logout leaves a live Keycloak session | Logout calls Keycloak end-session with `id_token_hint`; server-side session destroyed | 6 | `tests/bff/src/auth-flow.test.ts` (POST-only logout destroys all sessions, clears cookies, ends the Keycloak session, old refresh token dead); `tests/bff/src/audit-bff.test.ts` (sign-out and killed sessions are audited) Attack: `tests/attack/src/session-bff.test.ts` (A-13); `tests/attack/src/jwt-api.test.ts` (A-08) Accepted risk AR-02 (`docs/accepted-risks.md`) |
| T-07 | XSS via app or uploaded content | CSP without `unsafe-inline` where feasible, output encoding by React, attachments served with `Content-Disposition: attachment` and `nosniff` | 6, 8 | `tests/bff/src/pages-headers.test.ts` (stored XSS inert on list, detail, edit form and break-glass page; CSP with per-request nonce, no unsafe-inline/eval, every response kind; no third-party origins) Attack: `tests/attack/src/injection-xss.test.ts` (A-31..A-34); `tests/attack/src/uploads.test.ts` (A-43); `tests/attack/src/leakage.test.ts` (A-80) |
| T-08 | Forged or tampered JWT (`alg=none`, HS/RS confusion) | Verify signature against JWKS, algorithm allow-list (RS256/ES256 only, **unverified** which Keycloak default is used), reject `none` | 3 | `tests/identity/src/identity.test.ts` › access token claims: RS256, JWKS verify, tampered payload fails (issuer side; API validation stage 3); `apps/api/src/token.test.ts` (tampered payload, `alg=none`, HS256 with the public key as secret, HS*/PS*/RS512, unknown or reused kid, missing kid); `tests/identity/src/api-auth.test.ts` (real tokens: tamper, `alg=none`) Attack: `tests/attack/src/jwt-api.test.ts` (A-01..A-04) |
| T-09 | Token valid for another audience or issuer accepted; over-broad token | Check `iss`, `aud`, `exp`, `nbf` with bounded clock skew; separate API client; minimal scopes | 3 | `tests/identity/src/identity.test.ts` › access token claims: `iss`, `aud` contains `casefile-api`, `azp`, lifetime <= 300s (issuer side; API checks stage 3); `apps/api/src/token.test.ts` (wrong `aud`/`iss`/`azp`, ID and refresh token as bearer, expired, not yet valid, missing claims); `tests/identity/src/api-auth.test.ts` (real ID, refresh, other-client and master-realm tokens refused) Attack: `tests/attack/src/jwt-api.test.ts` (A-05, A-06) |
| T-10 | Signing key rotation breaks validation or accepts stale key | JWKS cache with refresh on unknown `kid` (rate-limited); no fallback to unsigned claims | 3 | `apps/api/src/rotation.test.ts` (new kid after bounded refetch, retired kid refused, 60 random kids cause <= 2 fetches); `apps/api/src/token.test.ts` (JWKS down fails closed) Attack: `tests/attack/src/jwt-api.test.ts` (A-03, A-04) |
| T-11 | Missing authorization on a route (forgot a guard) | Global guard, default deny, routes opt in via decorators; test enumerates all routes | 4 | `apps/api/src/routes.test.ts` (route inventory fails on a route without declared access; only `GET /health` public; undeclared route is 401/403); `packages/policy/src/evaluate.test.ts` (full role x action matrix, default deny); `apps/api/src/policy.test.ts`, `tests/identity/src/policy-e2e.test.ts` (roles outside the matrix, token without role) Attack: `tests/attack/src/authz.test.ts` (A-22); `tests/attack/src/leakage.test.ts` (A-81) |
| T-12 | Client-side check treated as authorization | All decisions server-side in `packages/policy`; UI hiding is cosmetic only | 4, 6 | `apps/api/src/token.test.ts` (identity never taken from headers); `apps/api/src/http.test.ts` (CORS allow-list); `apps/api/src/policy.test.ts` (decisions server side from the verified token only); `tests/bff/src/csrf-proxy.test.ts` (proxy allow-list, UI hiding is cosmetic: the BFF and API decide); `tests/api-db/src/audit-api.test.ts` (auditor endpoints: only the auditor role, filters validated, cursors tamper-evident) Attack: `tests/attack/src/authz.test.ts` (A-24); `tests/attack/src/jwt-api.test.ts` (A-06) |
| T-13 | Mass assignment alters classification, unit, status or owner | Explicit DTO allow-lists with validation; update rules in policy, not in the DTO | 4 | `apps/api/src/http.test.ts` (ValidationPipe whitelist + forbidNonWhitelisted, transform off). Domain DTOs follow in stages 4/5; `packages/policy/src/evaluate.test.ts` (INVALID_INPUT cases, create ownership); `apps/api/src/policy.test.ts`, `tests/identity/src/policy-e2e.test.ts` (mass assignment 400, unit/author/status set from the principal); `tests/api-db/src/e2e.test.ts` (mass assignment 400 on real tables; unit, author, status set from the principal), `tests/api-db/src/roles.test.ts` (column-level grants: version, submitter, id, timestamps not writable) Attack: `tests/attack/src/authz.test.ts` (A-24); `tests/attack/src/fuzz.test.ts` (A-94, A-95) |
| T-14 | SQL injection | Parameterised queries only, no string-built SQL, lint rule or review check | 5 | `tests/api-db/src/drift.test.ts` (no template-literal SQL; every query is a `sql` constant), `tests/api-db/src/e2e.test.ts` (hostile title/body/id/compartments, second order), `tests/api-db/src/rls.test.ts` (hostile context values, constraints), ESLint rule in `eslint.config.mjs` Attack: `tests/attack/src/injection-xss.test.ts` (A-30); `tests/attack/src/fuzz.test.ts` (A-91) |
| T-15 | Row leak when app code misses an ABAC check (IDOR, list endpoints) | Postgres RLS keyed on session attributes; app role non-owner, no BYPASSRLS; negative tests per role | 5 | `packages/policy/src/evaluate.test.ts` (clearance grid, compartments, unit scope, ownership); `packages/policy/src/properties.test.ts` (clearance floor, compartment monotonicity); `apps/api/src/policy.test.ts`, `tests/identity/src/policy-e2e.test.ts` (IDOR: 404 when hidden, same body as missing id; list parity); `tests/api-db/src/parity.test.ts` (policy vs RLS: full grids and properties), `tests/api-db/src/rls.test.ts`, `tests/api-db/src/roles.test.ts` (app role cannot ALTER/DROP/disable RLS, no rows without context, FORCE), `tests/api-db/src/e2e.test.ts` (IDOR 404, buggy handler still limited by RLS) Attack: `tests/attack/src/authz.test.ts` (A-20, A-21); `tests/attack/src/uploads.test.ts` (A-44); `tests/attack/src/leakage.test.ts` (A-82) |
| T-16 | Separation-of-duties violation (reviewer approves own file) | Policy rule `author != approver`, enforced in policy and verified in DB constraint where possible | 4 | `packages/policy/src/evaluate.test.ts` (approver != author, submitter); `packages/policy/src/properties.test.ts` (approval never to author or submitter); `apps/api/src/policy.test.ts`, `tests/identity/src/policy-e2e.test.ts` (lifecycle with real tokens); `tests/api-db/src/parity.test.ts` (approve), `tests/api-db/src/concurrency.test.ts` (author vs reviewer race, double approve) Attack: `tests/attack/src/authz.test.ts` (A-23) |
| T-17 | `SECRET` read without strong authentication | Policy requires `acr` of MFA; API rejects otherwise with step-up challenge | 2, 4 | `tests/identity/src/identity.test.ts` › MFA: SECRET gets TOTP, `acr=mfa`, `amr` has `otp`, `acr_values=pwd` cannot downgrade (issuer side; API enforcement stage 4); `tests/identity/src/api-auth.test.ts` (API surfaces `acr`/`amr` from real SECRET tokens; enforcement is stage 4); `packages/policy/src/evaluate.test.ts`, `packages/policy/src/properties.test.ts` (every action on SECRET needs acr=mfa and amr otp); `apps/api/src/policy.test.ts`, `tests/identity/src/policy-e2e.test.ts` (403 + RFC 9470 challenge; real token with acr=pwd); `tests/api-db/src/parity.test.ts` (SECRET step-up in SELECT/INSERT/UPDATE/DELETE policies), `tests/api-db/src/e2e.test.ts` (real token acr=pwd) Attack: `tests/attack/src/breakglass-stepup.test.ts` (A-61) Accepted risk AR-03 (`docs/accepted-risks.md`) |
| T-18 | Weak or default Keycloak admin credentials | Dev-only credentials marked; production values from a secret store, not compose defaults | 1, 8 | `apps/api/src/config.test.ts`, `apps/web/src/server/config.test.ts` (production refuses development values), `scripts/prod-like-test.mjs` (the stack runs with generated secrets, images refuse dev values); Keycloak admin credentials in a real deployment are the platform's: accepted risk AR-14 |
| T-19 | User edits own clearance, compartments or roles; MFA not enforced | Attributes admin-managed only, user profile attributes non-editable by user, TOTP required for high clearance | 2 | `tests/identity/src/identity.test.ts` › attributes are admin-only (Account API cannot change clearance, unit, compartments); MFA tests Accepted risk AR-14 (`docs/accepted-risks.md`) |
| T-20 | Realm config drift or hand edits | Realm as code, imported on start, reviewed in PRs | 2 | `tests/identity/src/identity.test.ts` › realm hardening as configured (realm and client baseline read back from Keycloak); `tests/api-db/src/migrations.test.ts` (from empty, idempotent, tamper-evident, atomic, serialised) |
| T-21 | Refresh token replay after theft | Refresh rotation with reuse detection (**unverified** Keycloak setting name and behaviour), short access token lifetime | 2, 6, 9 | `tests/identity/src/identity.test.ts` › refresh token rotation: old token dead, reuse revokes the chain (Keycloak side; BFF stage 6, attack test stage 9); `tests/bff/src/auth-flow.test.ts` (refresh rotation, parallel requests refresh once, replayed refresh token ends the session, refused refresh destroys it), `tests/bff/src/session-store.test.ts` (row lock) Attack: `tests/attack/src/session-bff.test.ts` (A-10) Accepted risk AR-02 (`docs/accepted-risks.md`) |
| T-22 | Brute force on login | Keycloak brute-force detection enabled, rate limiting at BFF | 2, 8 | `tests/identity/src/identity.test.ts` › realm hardening: lockout after repeated failures (Keycloak side); `tests/bff/src/hardening-bff.test.ts` (BFF login, callback and logout limited per client address; forged or wrong-secret proxy headers buy no budget) Attack: `tests/attack/src/ratelimit-proxy.test.ts` (A-70, A-73); `tests/attack/src/leakage.test.ts` (A-83) Accepted risk AR-13 (`docs/accepted-risks.md`) |
| T-23 | Cross-database access between app and Keycloak | Separate role and database for Keycloak (done in compose init script), distinct credentials | 1 | `scripts/prod-like-test.mjs`; attack A-53: `tests/attack/src/audit-tamper.test.ts` (the Keycloak role cannot enter the application database and the application roles cannot enter Keycloak's) |
| T-24 | Repudiation: actions and decisions not recorded | Decision log with reason for allow and deny; audit entry before response | 4, 7 | `apps/api/src/http.test.ts` (no token, header, claim or query value in logs or errors; server-made request id). Decision log stage 4; `apps/api/src/policy.test.ts` (decision log: sub, action, resource, effect, reason, no claim dump); `tests/api-db/src/audit-api.test.ts` (every decision audited with the real reason, correlated by request id; break-glass justification sanitised; canary scan; fail closed: 503 and no action when the audit table is unwritable), `tests/bff/src/audit-bff.test.ts` (sign-in/step-up/logout/session-kill/CSRF events; sign-in fails closed, sign-out never blocked) Attack: `tests/attack/src/audit-tamper.test.ts` (A-51, A-52) |
| T-25 | Break-glass abuse | Justification required, alert raised, always audited | 4, 7 | `packages/policy/src/evaluate.test.ts` (break-glass matrix: roles, justification, floor, step-up, read only); `packages/policy/src/properties.test.ts`; `apps/api/src/policy.test.ts`, `tests/identity/src/policy-e2e.test.ts` (alert log with justification); `tests/api-db/src/rls.test.ts`, `tests/api-db/src/parity.test.ts` (break-glass in the database: need-to-know only); `tests/api-db/src/audit-api.test.ts` (break-glass allow row with alert marker, justification and the real subject) Attack: `tests/attack/src/breakglass-stepup.test.ts` (A-60) Accepted risk AR-09 (`docs/accepted-risks.md`) |
| T-26 | Audit log tampering or deletion | Append-only table (no UPDATE/DELETE grants), hash chain, verification command, auditor-only read | 7 | `tests/api-db/src/audit-db.test.ts` (append-only for every role incl. owner and superuser, linear chain enforced by the database, concurrent writers produce one chain, rolled-back writes leave no gap), `tests/api-db/src/audit-api.test.ts` (CLI against tampered databases: edited row, DB-only re-hash, deleted middle row, deleted tail, deleted tail + head + checkpoints (external copy), forged checkpoint, forged row), `packages/audit/src/audit.test.ts` (verifier unit tests, independent spec check, golden vector) Attack: `tests/attack/src/audit-tamper.test.ts` (A-50..A-52) Accepted risk AR-08 (`docs/accepted-risks.md`) |
| T-27 | Resource exhaustion (requests, queries, sessions) | Rate limiting, pagination caps, query timeouts, body size limits | 8 | `apps/api/src/http.test.ts` (body limit 413, general throttle 429, auth-failure limiter 429 incl. X-Forwarded-For spoof). Per-subject limit behind the BFF: `apps/api/src/http.test.ts` (one noisy user does not starve another); BFF per-user limit: `hardening-bff.test.ts`; bounded memory under a key flood: `packages/netguard/src/netguard.test.ts`. Query/pagination caps stage 5; `tests/api-db/src/concurrency.test.ts` (statement timeout, lock timeout 409, pool exhaustion fails fast, connection limit) Attack: `tests/attack/src/ratelimit-proxy.test.ts` (A-70..A-76); `tests/attack/src/fuzz.test.ts` (A-90..A-93) Accepted risk AR-04, AR-06 (`docs/accepted-risks.md`) |
| T-28 | Oversized or hostile uploads | Size cap (body parser and BFF content-length), allow-list of PDF, PNG, JPEG, plain text decided from the bytes (signatures, PNG chunk and CRC walk, JPEG markers, PDF header and trailer, UTF-8 text), no archives, markup and active-content markers refused anywhere in the file, malware-scan hook with a fail-closed pending/quarantined state | 8 | `apps/api/src/attachments/content.test.ts` (wrong magic, polyglots, SVG/HTML, executables, archives, PNG dimension bomb, PDF JavaScript, bidi text), `scanner.test.ts` (clamd answers, stub refuses in production), `tests/api-db/src/attachments-api.test.ts` (15 hostile uploads, scanner infected and unavailable). **Not met:** no storage quota per user or in total (disk fill by many allowed uploads is limited only by the rate limit and the 5 MB cap) Attack: `tests/attack/src/uploads.test.ts` (A-40, A-41); `tests/attack/src/fuzz.test.ts` (A-92) Accepted risk AR-06, AR-10 (`docs/accepted-risks.md`) |
| T-29 | Direct or guessable access to stored files; path traversal | Files stored under random 128-bit keys on a dedicated directory outside any web root (0700/0600, created exclusively, symlinks not followed), served only through the API with the parent case file's policy and row-level security, display name sanitised and never a path | 5, 8 | `attachments-api.test.ts` (traversal and RTL names, IDOR across parents, SECRET without step-up, other compartments), `tests/api-db/src/parity.test.ts` (attachment visibility and insert equal the parent's read and update rule, incl. break-glass), `scanner.test.ts` (store keys, symlink) Attack: `tests/attack/src/uploads.test.ts` (A-42, A-44) |
| T-30 | Attachment swapped after review | SHA-256 stored at upload, checked on every read, size and hash in the audit rows; verdict columns are the only mutable ones and a verdict is final | 7, 8 | `attachments-api.test.ts` (file changed on disk is not served; database refuses edits, deletes, flipped verdicts) |
| T-31 | Active content in attachments runs in app origin | Serve as download, `nosniff`, CSP `sandbox` on file responses | 6, 8 | `tests/bff/src/pages-headers.test.ts` (nosniff on assets and pages, CORP same-origin; `attachments-bff.test.ts` and `attachments-api.test.ts` (attachment disposition, sandbox CSP, nosniff, allow-listed type, no caching)) Attack: `tests/attack/src/uploads.test.ts` (A-43) |
| T-32 | Vulnerable or malicious dependency, action or image | Lockfile frozen in CI, `pnpm audit --prod`, actions pinned by SHA, Dependabot, image scanning, SBOM | 1, 8 | CI: Trivy on the images built here (api, web, keycloak, caddy, clamd) and the pinned ones, SBOM per image, dependency-review, Scorecard, `.trivyignore.yaml` with expiry (`scripts/check-trivyignore.mjs`) Accepted risk AR-15 (`docs/accepted-risks.md`) |
| T-33 | Token tampering abuse cases regress unnoticed | Scripted attack tests in CI (alg=none, wrong aud, expired, replayed refresh, IDOR, escalation) | 9 | the attack suite itself: `docs/attack-catalogue.md` (60 scripted attacks), `tests/attack/src/jwt-api.test.ts`, `tests/attack/src/session-bff.test.ts`, `tests/attack/src/authz.test.ts`, run in CI as job `attack-tests` |
| T-34 | Traffic between components sniffed or altered (outside local dev) | TLS between all components in any non-local deployment; local compose is HTTP and loopback-bound by design | 8 | Partial: browser to proxy is TLS and tested (`scripts/prod-like-test.mjs`); inside the prod-like stack the traffic is plain http on internal networks that have no way out. **Not met:** TLS or mutual TLS between proxy, BFF, API, Keycloak and Postgres Accepted risk AR-01 (`docs/accepted-risks.md`) |
| T-35 | Check/use race: the decision is made on a state that changes before the write (edit lands on a submitted file, double approve, author wins a race) | Load, decide and write in one transaction on a `FOR UPDATE` row lock with an optimistic `version`; the database trigger independently enforces the status machine and separation of duties | 5 | `tests/api-db/src/concurrency.test.ts` (deterministic interleaving, 10 to 25 iteration races, double submit, stale version 409) Attack: `tests/attack/src/uploads.test.ts` (A-46) |
| T-36 | Request context leaks between requests on a pooled connection | Context is set with `is_local => true` in the request's own transaction, never per session; test with one physical connection | 5 | `tests/api-db/src/concurrency.test.ts` (SECRET then none then OFFICIAL on one connection; rollback; break-glass flag; 60 concurrent mixed requests on 2 connections) |
| T-37 | The API runs as a role that makes RLS meaningless (superuser, BYPASSRLS, table owner) or the app role gains DDL | Separate migrator and app roles, column-level grants, startup check refuses an unsafe role, no `SECURITY DEFINER`, `search_path` pinned | 5 | `tests/api-db/src/roles.test.ts`, `tests/api-db/src/inventory.test.ts` (startup refusal) |
| T-38 | The BFF proxy becomes an open proxy or SSRF gadget; browser headers, cookies or the break-glass header are smuggled to the API | Allow-list of nine method+path pairs against a fixed host, upstream request built from scratch, no redirects, size/time limits, break-glass header only on its own route (ADR-16) | 6 | `tests/bff/src/csrf-proxy.test.ts` (recording upstream: headers, traversal, SSRF paths, redirect, oversized and slow upstream) Attack: `tests/attack/src/session-bff.test.ts` (A-17); `tests/attack/src/leakage.test.ts` (A-81); `tests/attack/src/ratelimit-proxy.test.ts` (A-76) Accepted risk AR-07 (`docs/accepted-risks.md`) |
| T-39 | Concurrent refresh with a single-use refresh token kills or duplicates the session; a stolen refresh token keeps working | Row lock around the refresh, rotation by Keycloak, refusal destroys the session | 6 | `tests/bff/src/session-store.test.ts`, `tests/bff/src/auth-flow.test.ts` Attack: `tests/attack/src/session-bff.test.ts` (A-10) |
| T-40 | A database dump or a read-only SQL injection yields usable sessions or tokens | Only the SHA-256 of the cookie value is stored; tokens AES-256-GCM encrypted with a key ring outside the database, AAD bound to the row; separate role `casefile_web` | 6 | `tests/bff/src/session-store.test.ts` (no clear secrets in the row, blob moved between rows fails, role isolation both ways) |
| T-41 | Audit gaps: concurrent writers fork or skip ids, a rolled-back write leaves a hole, the log silently stops while actions continue | Writer-assigned gap-free ids, advisory lock plus a database trigger that refuses any row not extending the head, audit-before-action with 503 on failure for allowed decisions (ADR-17, ADR-18) | 7 | `tests/api-db/src/audit-db.test.ts` (60 concurrent writers, writers with rollbacks, writer without the lock), `tests/api-db/src/audit-api.test.ts` (fail closed) Attack: `tests/attack/src/audit-tamper.test.ts` (A-50, A-52) Accepted risk AR-08 (`docs/accepted-risks.md`) |
| T-42 | Injection through the audit trail: formulas in a CSV export, hostile text in the log or the auditor page, log injection through the justification | Fixed `details` schema and column patterns (database and application), sanitised justification (control, bidi and invisible characters removed), CSV formula neutralisation, React escaping on the auditor page | 7 | `packages/audit/src/audit.test.ts`, `tests/api-db/src/audit-api.test.ts` (CSV), `tests/api-db/src/audit-db.test.ts` (hostile rows refused by the table), `tests/bff/src/audit-bff.test.ts` Attack: `tests/attack/src/injection-xss.test.ts` (A-34); `tests/attack/src/audit-tamper.test.ts` (A-51) |
| T-43 | The denial-reason function widens what the API role can learn about hidden files | Narrow definer role (3 columns), code-only result, execute for the API role only, parity-tested against the policy (ADR-19) | 7 | `tests/api-db/src/audit-db.test.ts`. **Accepted (stage 8):** for a compromised API role the function is still a narrow existence and class oracle (does this id exist, and is it hidden by clearance, compartment or role); ids are random UUIDs, so guessing one is infeasible and the result is a code, never data Accepted risk AR-12 (`docs/accepted-risks.md`) |
| T-44 | Forged network zone: a client or a caller other than the BFF claims the managed zone to pass the export rule | Zone decided by the BFF from a proxy-vouched client address, sent as an HMAC-signed, per-user, 30-second header; the API believes nothing else, not the socket, not forwarded headers (ADR-20) | 8 | `packages/netguard/src/netguard.test.ts`, `apps/api/src/policy.test.ts`, `apps/web/src/server/client.test.ts`, `tests/bff/src/hardening-bff.test.ts`. A compromised BFF can claim any zone for its users Attack: `tests/attack/src/jwt-api.test.ts` (A-07); `tests/attack/src/authz.test.ts` (A-26) Accepted risk AR-05 (`docs/accepted-risks.md`) |
| T-45 | Rate-limit evasion or abuse: forged forwarded headers, key flooding, one shared bucket for every user behind the BFF | Forwarded headers believed only with the proxy's secret, per-user and per-address limits, bounded tables (oldest key evicted), per-process counters documented | 8 | `netguard.test.ts`, `hardening-bff.test.ts`, `http.test.ts`. A key flood larger than the table can reset counters; several instances multiply limits Attack: `tests/attack/src/ratelimit-proxy.test.ts` (A-70, A-71) Accepted risk AR-04 (`docs/accepted-risks.md`) |
| T-46 | Development values, short keys or missing secrets reach production | `ACL_ENV=production` refuses dev markers, short or low-entropy keys, plain http, insecure cookies and missing secrets; secrets as files; no secret in logs | 8 | `apps/api/src/config.test.ts`, `apps/web/src/server/config.test.ts`, `packages/netguard/src/secrets.test.ts`, canary scan in `hardening-bff.test.ts`. The switch is `ACL_ENV`, not `NODE_ENV` |
| T-47 | Attachments stuck unscanned, or served before a verdict | Only `clean` is downloadable; a scanner error or timeout leaves the file `pending`; the stub scanner refuses to answer in production | 8 | `attachments-api.test.ts` (scanner down, infected), `scanner.test.ts`. No re-scan job exists: pending files stay pending until one is built Attack: `tests/attack/src/uploads.test.ts` (A-41) Accepted risk AR-11 (`docs/accepted-risks.md`) |

## Stage 2 notes

- Dev-only Keycloak `start-dev` still runs over HTTP; tests prove the realm configuration, not a production deployment (T-34 open).
- Keycloak default realm clients that are unused (`admin-cli`, `security-admin-console`) are disabled in the realm; the master realm admin console is reachable only on 127.0.0.1.
- Image tags moved to latest verified releases (Keycloak 26.8.1, Postgres 17.11) and pinned by digest; Trivy exception for the postgres image's bundled gosu is in `docs/supply-chain.md` (T-32).

## Stage 3 notes

- Token validation lives in `apps/api/src/auth`; threats are covered on the API side here and on the issuer side in `docs/identity.md` tests.
- A key retired at Keycloak keeps verifying until the cached JWKS is refreshed (`JWKS_MAX_AGE_MS`, default 10 min) or an unknown kid triggers a refetch (`JWKS_COOLDOWN_MS`, default 30 s). No token revocation check yet: access tokens live <= 5 min (T-04 residual).
- The auth-failure limiter is per process and keyed on the socket address; it assumes the API is only reachable from the BFF (T-27 residual for multi-instance).

## Stage 4 notes

- Policy: `docs/policy.md`. Break-glass and the 404-vs-403 rule are decisions recorded there and in ADR-9.
- **Accepted risk: no token revocation (T-04, T-21 residual).** A stolen access token works until it expires (<= 5 min); a retired signing key until the JWKS cache
  refreshes (<= 10 min). Upgrade path when this is no longer acceptable: for SECRET reads, introspect the token at Keycloak (or check `sid` against a revocation
  list fed by Keycloak back-channel logout) before allowing; keep ordinary reads on local validation. Not built; owner decision 2026-10-17.
- Failed-authentication limiter and general throttle are per process and keyed on the socket address (ceiling: single instance, API reachable only from the BFF).
  Multi-instance needs a shared store and a trusted-proxy policy (stage 8).
- Check/use race: closed in stage 5 (T-35): load, decide and write in one transaction on a locked row.

## Stage 5 notes

- RLS protects against missing checks, wrong queries and SQL injection; it does not protect against code that sets a forged context (same role). Documented in ADR-11 and `docs/data-layer.md`.
- Break-glass is represented in the SELECT policy (need-to-know only). A blank justification never reaches the database (app refuses first); listed in the known parity differences.
- Dev data and test fixtures are written as the dev superuser (RLS is forced even for the owner); seeds refuse non-local databases.

## Stage 6 notes

- The user's network zone stays unproven behind the BFF (the API sees the BFF's address); the BFF does not forward `X-Forwarded-For`. Export from a "managed" zone is therefore only as strong as the BFF's placement (stage 8 design).
- Real browsers are not driven (no Playwright): hydration, real `Origin`/`Sec-Fetch-*` emission and `__Host-` handling over plain http are unverified; the HTTP-level tests prove what the server sends and accepts.
- No rate limit on the login and callback routes yet (stage 8).

## Stage 7 notes

- The audit chain proves integrity against anyone without the HMAC key; a compromised writer holding the key can write false rows, and an attacker who also deletes the stored checkpoints can truncate the tail unnoticed unless an exported checkpoint copy exists (`docs/audit.md`, "What is NOT guaranteed").
- Stage 5's "no SECURITY DEFINER function" became "exactly two" (audit chain trigger, denial-reason lookup), each documented and pinned by a test.
- Finding while testing: a break-glass justification containing a control character made the request fail with 500 (the database context refused it). The justification is now sanitised once, at the edge, for the policy, the database context and the audit row alike.

## Stage 8 notes

- Attachments: a draft that has attachments cannot be deleted (409) and there is no attachment delete: evidence stays. There is no re-scan of pending files and no storage quota.
- The PDF check is a header, trailer and marker scan, not a sanitiser: object streams can hide active content. The real defences are the scanner hook (clamd, off in dev) and the download headers (attachment, nosniff, sandbox). Text files containing markup markers are refused on purpose.
- Rate limits and the proxy contract are per process; a shared store is the upgrade (docs/hardening.md).

## Stage 8b notes

- The prod-like stack proves the shape (TLS proxy, networks without a way out, non-root read-only capability-free containers, secrets as files, production profile by default, real ClamAV): `docs/deployment.md`, `scripts/prod-like-test.mjs`. It is not a deployment; TLS between internal components, log shipping, backups and key management are open (`docs/asvs.md`, "Not met").
- Docker ignores published ports for a container attached only to internal networks, so "web publishes a port" is inert on its own; the stack test therefore also checks that no service sits on the routable network beyond the proxy.

## Stage 9 notes

- The attack suite went in from outside and found five defects the unit and integration tests had not: methods the application does not use gave 500 (TRACE), an invalid percent-escape gave 500, JSON keys such as `toString`, `__proto__` and `""` were silently accepted as unknown fields, a break-glass justification with a control character or a non-Latin character failed with 502, and `openid-client` could be loaded twice. All fixed; each is pinned by the attack that found it (`docs/attack-catalogue.md`, "What the suite found").
- Every threat now has an existing test or check; 15 risks are accepted in one place with owner, reason and upgrade path (`docs/accepted-risks.md`). AR-06 (no storage quota), AR-11 (no re-scan of pending attachments) and AR-14 (identity-provider features that are off) are **open**, not decided.
- Measured, not assumed: an access token is accepted by the API after logout for up to its remaining lifetime (at most 300 s), a hidden resource and a missing one answer identically and in the same time (median 7 ms each).

## Known gaps accepted at stage 1

- Compose stack runs Keycloak in `start-dev` over plain HTTP. Loopback-bound only. Not a deployment model. (T-34)
- Image tags and library versions are chosen by what resolved at scaffold time; not independently verified against advisories. **(unverified)**
- File storage component has no implementation yet; its threats are placeholders until stage 5/8.
