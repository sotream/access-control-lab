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

"Covered by test" stays empty until the implementing stage lands a test. Stage numbers refer to `docs/plan.md`.

| ID | Threat | Mitigation | Stage | Covered by test |
|----|--------|------------|-------|-----------------|
| T-01 | Secrets committed to the repo | `.env` gitignored, `.env.example` only with dev-only values, gitleaks in CI | 1 | |
| T-02 | OAuth code interception, login CSRF | Authorization Code + PKCE, `state` and `nonce` verified, exact redirect URI match in Keycloak client | 2, 6 | |
| T-03 | Open redirect after login or logout | Post-login redirect restricted to same-origin relative paths; Keycloak valid redirect URIs without wildcards | 2, 6 | |
| T-04 | Token theft from the browser (XSS, localStorage) | BFF: tokens stay server-side, browser holds only an `httpOnly`, `Secure`, `SameSite` session cookie | 6 | |
| T-05 | CSRF on state-changing requests; session fixation | `SameSite` cookie plus CSRF token or origin check on non-GET; new session id on login | 6 | |
| T-06 | Logout leaves a live Keycloak session | Logout calls Keycloak end-session with `id_token_hint`; server-side session destroyed | 6 | |
| T-07 | XSS via app or uploaded content | CSP without `unsafe-inline` where feasible, output encoding by React, attachments served with `Content-Disposition: attachment` and `nosniff` | 6, 8 | |
| T-08 | Forged or tampered JWT (`alg=none`, HS/RS confusion) | Verify signature against JWKS, algorithm allow-list (RS256/ES256 only, **unverified** which Keycloak default is used), reject `none` | 3 | |
| T-09 | Token valid for another audience or issuer accepted; over-broad token | Check `iss`, `aud`, `exp`, `nbf` with bounded clock skew; separate API client; minimal scopes | 3 | |
| T-10 | Signing key rotation breaks validation or accepts stale key | JWKS cache with refresh on unknown `kid` (rate-limited); no fallback to unsigned claims | 3 | |
| T-11 | Missing authorization on a route (forgot a guard) | Global guard, default deny, routes opt in via decorators; test enumerates all routes | 4 | |
| T-12 | Client-side check treated as authorization | All decisions server-side in `packages/policy`; UI hiding is cosmetic only | 4, 6 | |
| T-13 | Mass assignment alters classification, unit, status or owner | Explicit DTO allow-lists with validation; update rules in policy, not in the DTO | 4 | |
| T-14 | SQL injection | Parameterised queries only, no string-built SQL, lint rule or review check | 5 | |
| T-15 | Row leak when app code misses an ABAC check (IDOR, list endpoints) | Postgres RLS keyed on session attributes; app role non-owner, no BYPASSRLS; negative tests per role | 5 | |
| T-16 | Separation-of-duties violation (reviewer approves own file) | Policy rule `author != approver`, enforced in policy and verified in DB constraint where possible | 4 | |
| T-17 | `SECRET` read without strong authentication | Policy requires `acr` of MFA; API rejects otherwise with step-up challenge | 2, 4 | |
| T-18 | Weak or default Keycloak admin credentials | Dev-only credentials marked; production values from a secret store, not compose defaults | 1, 8 | |
| T-19 | User edits own clearance, compartments or roles; MFA not enforced | Attributes admin-managed only, user profile attributes non-editable by user, TOTP required for high clearance | 2 | |
| T-20 | Realm config drift or hand edits | Realm as code, imported on start, reviewed in PRs | 2 | |
| T-21 | Refresh token replay after theft | Refresh rotation with reuse detection (**unverified** Keycloak setting name and behaviour), short access token lifetime | 2, 6, 9 | |
| T-22 | Brute force on login | Keycloak brute-force detection enabled, rate limiting at BFF | 2, 8 | |
| T-23 | Cross-database access between app and Keycloak | Separate role and database for Keycloak (done in compose init script), distinct credentials | 1 | |
| T-24 | Repudiation: actions and decisions not recorded | Decision log with reason for allow and deny; audit entry before response | 4, 7 | |
| T-25 | Break-glass abuse | Justification required, alert raised, always audited | 4, 7 | |
| T-26 | Audit log tampering or deletion | Append-only table (no UPDATE/DELETE grants), hash chain, verification command, auditor-only read | 7 | |
| T-27 | Resource exhaustion (requests, queries, sessions) | Rate limiting, pagination caps, query timeouts, body size limits | 8 | |
| T-28 | Oversized or hostile uploads | Size and type limits, content sniffing, malware-scan hook, storage quota | 8 | |
| T-29 | Direct or guessable access to stored files; path traversal | Files stored under random ids outside web root, served only via authorised API stream, filename never used as path | 5, 8 | |
| T-30 | Attachment swapped after review | Store content hash at upload, verify on read, hash in audit | 7, 8 | |
| T-31 | Active content in attachments runs in app origin | Serve as download, `nosniff`, CSP `sandbox` on file responses | 6, 8 | |
| T-32 | Vulnerable or malicious dependency, action or image | Lockfile frozen in CI, `pnpm audit --prod`, actions pinned by SHA, Dependabot, image scanning, SBOM | 1, 8 | |
| T-33 | Token tampering abuse cases regress unnoticed | Scripted attack tests in CI (alg=none, wrong aud, expired, replayed refresh, IDOR, escalation) | 9 | |
| T-34 | Traffic between components sniffed or altered (outside local dev) | TLS between all components in any non-local deployment; local compose is HTTP and loopback-bound by design | 8 | |

## Known gaps accepted at stage 1

- Compose stack runs Keycloak in `start-dev` over plain HTTP. Loopback-bound only. Not a deployment model. (T-34)
- Image tags and library versions are chosen by what resolved at scaffold time; not independently verified against advisories. **(unverified)**
- File storage component has no implementation yet; its threats are placeholders until stage 5/8.
