# OWASP ASVS 4.0.3, level 2: where this system stands

A mapping of the requirements that apply to this system to a status and to the test or file that proves it, and an honest list of what is **not met**. Written at the end of stage 8.

**Read this first.** Since stage 9 many rows are also proven from the outside by the black-box attack suite (`docs/attack-catalogue.md`, `tests/attack`); where a row names a unit test, an attack in that catalogue usually exercises the same property end to end.

**Read this first, continued.**
- Requirement IDs and wording follow ASVS 4.0.3 as the author recalls them; the wording is shortened. The numbering was not diffed against the official CSV: **unverified**. Use the ID as a pointer, not as a citation.
- Status: **met** (a test or a checked artefact proves it), **partial** (some of it, the gap is stated), **delegated** (Keycloak or the platform provides it; what we configured is stated, and "unverified" when not tested), **n/a** (does not apply, with the reason), **not met**.
- "Proof" names a file in this repository. A claim without proof says so. This is a self-assessment by the people who built the system, not an audit.
- The system is a lab: Keycloak runs in `start-dev` in the dev compose and as a production-mode container only in the prod-like stack (`docs/deployment.md`). Nothing here was run in a real deployment.

## Summary

| Chapter | met | partial | delegated | n/a | not met |
|---------|-----|---------|-----------|-----|---------|
| V1 Architecture, design and threat modelling | 18 | 5 | 0 | 0 | 3 |
| V2 Authentication | 3 | 2 | 9 | 6 | 3 |
| V3 Session management | 14 | 2 | 0 | 0 | 1 |
| V4 Access control | 8 | 1 | 0 | 0 | 0 |
| V5 Validation, sanitisation and encoding | 14 | 2 | 0 | 6 | 0 |
| V6 Cryptography | 5 | 2 | 0 | 1 | 1 |
| V7 Error handling and logging | 10 | 2 | 0 | 0 | 1 |
| V8 Data protection | 6 | 4 | 0 | 0 | 4 |
| V9 Communication | 4 | 2 | 0 | 0 | 1 |
| V10 Malicious code | 2 | 2 | 0 | 3 | 0 |
| V11 Business logic | 6 | 2 | 0 | 0 | 0 |
| V12 Files and resources | 11 | 2 | 0 | 1 | 1 |
| V13 API and web service | 9 | 1 | 0 | 2 | 0 |
| V14 Configuration | 23 | 4 | 0 | 0 | 1 |
| **Total** | 133 | 33 | 9 | 19 | 16 |

(Counted from the rows below by a script, not from the ASVS: a row can stand for several requirements, and requirements that do not apply and are not listed are not counted.)

## V1 Architecture, design and threat modelling

| ID | Requirement (short) | Status | Proof or gap |
|----|---------------------|--------|--------------|
| 1.1.1 | Secure development lifecycle | partial | stage plan with negative tests per stage (`docs/plan.md`), required CI checks, CODEOWNERS, PR template; no formal SDLC document |
| 1.1.2 | Threat modelling | met | `docs/threat-model.md` (STRIDE, 47 threats, each mapped to a test or an accepted gap) |
| 1.1.4 | Trust boundaries and data flows documented | met | `docs/threat-model.md` components and boundaries, `docs/deployment.md` networks |
| 1.1.5 | Security architecture of the application | met | `docs/decisions.md` ADR-1..21 |
| 1.1.6 | Centralised, simple, vetted security controls | met | one policy package (`packages/policy`), one guard, one writer for the audit chain |
| 1.2.1 | Unique low-privilege accounts per component | met | database roles `casefile_app`, `casefile_web`, `casefile_audit`, `casefile_migrator`, `casefile_lookup`; container users (`tests/api-db/src/roles.test.ts`, `scripts/prod-like-test.mjs`) |
| 1.2.2 | Component-to-component communication authenticated | partial | BFF to API: bearer token plus HMAC-signed zone; API to Postgres: password; proxy to BFF: shared-secret header. BFF to API on the internal network is plain http (`API_INTERNAL_HTTP`), no mutual TLS |
| 1.2.3, 1.2.4 | One vetted authentication mechanism, same strength on every path | met | Keycloak only; the API accepts only its tokens (`apps/api/src/token.test.ts`), the BFF has no password path |
| 1.4.1 | Access control enforced at a trusted layer | met | route guard, service transaction, row-level security: three layers (`docs/policy.md`, `docs/data-layer.md`) |
| 1.4.4 | One vetted access control mechanism | met | `packages/policy` and the parity tests against the database (`tests/api-db/src/parity.test.ts`) |
| 1.4.5 | Attribute or feature based access control at a trusted layer | met | ABAC in the policy and in row-level security |
| 1.5.1, 1.5.3, 1.5.4 | Input and output requirements, validation at a trusted layer, encoding near the interpreter | met | DTO whitelist and `forbidNonWhitelisted`, `sql` tagged template without substitutions, React escaping, CSP |
| 1.6.1, 1.6.3 | Key management policy, keys replaceable | partial | rings with ids and rotation procedures (`docs/hardening.md` section 3); no key management service, no tested live rotation |
| 1.6.2 | Cryptographic operations isolated (KMS, HSM) | not met | keys are files or environment variables read by the application |
| 1.7.1 | Common log format | met | JSON lines with request id (`apps/api/src/http/logger.ts`) |
| 1.7.2 | Logs sent to a remote system | not met | stdout only; shipping is the deployment's (`docs/deployment.md`) |
| 1.8.1, 1.8.2 | Sensitive data classified and protected per level | partial | classification is the product (OFFICIAL, CONFIDENTIAL, SECRET) and drives access; no data-at-rest encryption beyond the session table |
| 1.9.1 | Communications between components encrypted | partial | browser to proxy TLS (prod-like); inside the stack plain http on internal networks |
| 1.10.1 | Source code control | met | git, protected main, signed-commit guidance (`docs/signed-commits.md`) |
| 1.11.1, 1.11.2 | Business logic flows documented and tested | met | `docs/policy.md`, `tests/api-db/src/e2e.test.ts` |
| 1.12.1 | Uploads stored outside the web root | met | `ATTACHMENT_DIR` volume (`apps/api/src/attachments/storage.ts`, `tests/api-db/src/attachments-api.test.ts`) |
| 1.12.2 | Uploads served as downloads or from another origin | met | attachment disposition, nosniff, sandbox CSP (`tests/bff/src/attachments-bff.test.ts`) |
| 1.14.1 | Components of different trust segregated | met | networks `edge`, `app`, `data`, `scan` (`scripts/prod-like-test.mjs`) |
| 1.14.2 | Deployment binaries signed or verified | not met | image digests are pinned, images are not signed, no provenance attestation |
| 1.14.3 | Pipeline warns about outdated or insecure components | met | `pnpm audit`, OSV-Scanner, Trivy on built images, dependency-review, Dependabot (`.github/workflows`) |
| 1.14.5 | Sandboxing or containment | met | non-root, read-only, capability-free containers (`scripts/prod-like-test.mjs`) |

## V2 Authentication

Authentication is Keycloak's. The rows say what the realm is configured to do (`infra/keycloak/realm-casefile.json`, `docs/identity.md`); "delegated" means the control is Keycloak's and our proof is the realm file and the tests named, not a review of Keycloak.

| ID | Requirement (short) | Status | Proof or gap |
|----|---------------------|--------|--------------|
| 2.1.1 | Passwords at least 12 characters | delegated | `length(14)` in the realm password policy; changing a password to a short one is not tested (unverified) |
| 2.1.2, 2.1.3 | Long passwords allowed, no truncation | delegated | Keycloak behaviour, unverified |
| 2.1.5, 2.1.6 | Users can change their password | delegated | `account-console` enabled; not tested |
| 2.1.7 | Breached-password check | not met | no breached-password list in the realm |
| 2.1.9 | No composition rules | delegated | policy has length, not-username, history only |
| 2.1.10, 2.1.11 | No periodic rotation, paste allowed | delegated | no expiry policy; Keycloak login form allows paste (unverified) |
| 2.2.1 | Anti-automation (rate limit, lockout) | met | Keycloak brute-force (5 failures, up to 15 min) tested in `tests/identity/src/identity.test.ts`; BFF address limit in `tests/bff/src/hardening-bff.test.ts` |
| 2.2.2 | Weak authenticators not the only factor for sensitive data | met | SECRET clearance forces TOTP (`tests/identity/src/identity.test.ts`) |
| 2.2.3 | Notification of authentication events | not met | login events are stored (Keycloak and audit chain), no user notification |
| 2.3.1 | Initial passwords random, single use | n/a | no user creation flow in the application; dev users are fixtures |
| 2.4.1, 2.4.2, 2.4.3, 2.4.4, 2.4.5 | Password storage: salted, slow hash with parameters | delegated | Keycloak (PBKDF2 by default), unverified; we store no passwords |
| 2.5.1, 2.5.2, 2.5.3 | Credential recovery | n/a | `resetPasswordAllowed` is off; no recovery flow |
| 2.5.4 | No default or shared accounts | partial | dev users exist in the dev realm by design; the prod-like stack generates random passwords for them; a real deployment must not import them (`docs/dev-users.md`) |
| 2.5.5 | User notified of credential change | not met | |
| 2.5.6 | Recovery uses secure mechanism | n/a | no recovery |
| 2.5.7 | OTP or MFA can be reset only with proof | delegated | unverified |
| 2.6.x | Lookup secrets | n/a | not used |
| 2.7.x | Out-of-band authenticators (SMS, push) | n/a | not used |
| 2.8.1 | Time-based OTP has a lifetime | delegated | Keycloak TOTP 30 s, replay refused: `tests/identity/src/kc.ts` works around the replay check, which shows it is on |
| 2.8.2-2.8.7 | OTP strength and storage | delegated | unverified |
| 2.9.x | Cryptographic authenticators | n/a | not used |
| 2.10.1-2.10.4 | Service authentication: no secrets in source, secrets in a vault | partial | no secrets in the repository (gitleaks, `tests/api-db/src/audit-api.test.ts` canary scan, `hardening-bff.test.ts` log canary); secrets are files, not a vault |
| 2.1.x (MFA step-up) | Step-up for sensitive data | met | `acr` check, RFC 9470 challenge (`tests/identity/src/policy-e2e.test.ts`, `tests/api-db/src/attachments-api.test.ts`) |

## V3 Session management

| ID | Requirement (short) | Status | Proof or gap |
|----|---------------------|--------|--------------|
| 3.1.1 | Session tokens never in URLs | met | cookie only; token in query refused (`tests/bff/src/csrf-proxy.test.ts`) |
| 3.2.1 | New session on authentication | met | session id always fresh, old ones destroyed (`tests/bff/src/auth-flow.test.ts`) |
| 3.2.2 | At least 64 bits of entropy | met | 256 random bits (`apps/web/src/server/session-store.ts`, `crypto.test.ts`) |
| 3.2.3 | Token stored with secure browser features | met | `__Host-` cookie, HttpOnly, Secure, SameSite=Lax (`apps/web/src/server/cookies.ts`, `tests/bff/src/pages-headers.test.ts`) |
| 3.2.4 | Generated with an approved CSPRNG | met | `crypto.randomBytes` |
| 3.3.1 | Logout and expiry invalidate the session | met | server-side destroy of every session of the user, Keycloak end-session (`tests/bff/src/auth-flow.test.ts`) |
| 3.3.2 | Re-authentication after a time limit (L2: 30 days or idle 12 h) | met | idle 30 min, absolute 8 h (`apps/web/src/server/config.ts`, `session-store.test.ts`) |
| 3.3.3 | Option to terminate other sessions | partial | logout ends all sessions of the user; no "log out other devices" without logging out |
| 3.3.4 | Users can view and log out of sessions | not met | no session list for users |
| 3.4.1 | Secure attribute | met | `__Host-` implies Secure |
| 3.4.2 | HttpOnly | met | |
| 3.4.3 | SameSite | met | Lax; Strict would break the return from the identity provider |
| 3.4.4 | `__Host-` prefix | met | |
| 3.4.5 | Path attribute limits exposure | met | `Path=/`, required by `__Host-` |
| 3.5.x | Token-based sessions (JWT) | partial | the API validates JWT access tokens (algorithm allow-list, issuer, audience, expiry, azp: `apps/api/src/token.test.ts`); the browser holds none (BFF) |
| 3.7.1 | Full session required for sensitive transactions | met | CSRF plus session on every state change (`tests/bff/src/csrf-proxy.test.ts`) |
| 3.7.2 (concurrency) | Concurrent session limits | met | `MAX_SESSIONS_PER_USER` (`session-store.test.ts`) |

## V4 Access control

| ID | Requirement (short) | Status | Proof or gap |
|----|---------------------|--------|--------------|
| 4.1.1 | Enforced on a trusted service layer | met | `tests/api-db/src/inventory.test.ts` (every route declares access, default deny), `apps/api/src/routes.test.ts` |
| 4.1.2 | User and permission attributes cannot be manipulated by users | met | claims come from verified tokens only (`apps/api/src/token.test.ts`); zone from a signed header (`apps/api/src/policy.test.ts`) |
| 4.1.3 | Least privilege | met | role matrix in `packages/policy`, mirrored in `role_grants` (`tests/api-db/src/drift.test.ts`) |
| 4.1.5 | Fail securely | met | deny on error, fail-closed audit (`tests/api-db/src/audit-api.test.ts`) |
| 4.2.1 | No IDOR | met | existence hiding (404), attachments scoped to their parent (`tests/api-db/src/e2e.test.ts`, `attachments-api.test.ts`) |
| 4.2.2 | CSRF protection | met | origin, fetch metadata, synchronizer token (`tests/bff/src/csrf-proxy.test.ts`) |
| 4.3.1 | Administrative interfaces need MFA | partial | no administrative interface in the application; the Keycloak admin console is not exposed by the proxy (`scripts/prod-like-test.mjs`), its own MFA is not configured (unverified) |
| 4.3.2 | Directory browsing off, no metadata files | met | no static file server beyond Next's build output; `tests/bff/src/pages-headers.test.ts` |
| 4.3.3 | Step-up for high-value transactions | met | SECRET read needs MFA, break-glass needs a justification |

## V5 Validation, sanitisation and encoding

| ID | Requirement (short) | Status | Proof or gap |
|----|---------------------|--------|--------------|
| 5.1.1 | HTTP parameter pollution defended | met | single `Authorization` header enforced, duplicate headers refused, query allow-list (`apps/api/src/token.test.ts`, `tests/bff/src/csrf-proxy.test.ts`) |
| 5.1.2 | Mass assignment protection | met | whitelist and `forbidNonWhitelisted` DTOs |
| 5.1.3 | Positive validation | met | DTO decorators, UUID patterns, enum checks, `validateDetails` |
| 5.1.4 | Structured data validated | met | audit `details`, attachment inspection |
| 5.1.5 | URL redirects only to allow-listed targets | met | `returnTo` allow-list (`apps/web/src/server/redirect.test.ts`) |
| 5.2.1 | HTML sanitised | n/a | no user HTML is rendered; React escapes text |
| 5.2.2 | Unstructured data sanitised | met | justification and names sanitised (`packages/audit/src/audit.test.ts`, `apps/api/src/attachments/content.test.ts`) |
| 5.2.3 | Sanitised for SMTP, SSI | n/a | none |
| 5.2.4, 5.2.5 | No eval, template injection | met | no dynamic code evaluation (lint, CodeQL) |
| 5.2.6 | SSRF protection | met | fixed upstream host, allow-listed paths (`tests/bff/src/csrf-proxy.test.ts`) |
| 5.2.7 | SVG and script content in uploads | met | refused (`content.test.ts`) |
| 5.2.8 | Sandboxed scripting | n/a | none |
| 5.3.1 | Output encoding for context | met | React, CSP with nonce |
| 5.3.3 | Context-aware escaping (XSS) | met | `tests/bff/src/pages-headers.test.ts` |
| 5.3.4, 5.3.5 | Parameterised queries, no dynamic SQL | met | `sql` tag, `tests/api-db/src/drift.test.ts`, `e2e.test.ts` injection tests |
| 5.3.6 | JavaScript and JSON injection | met | |
| 5.3.7 | LDAP injection | n/a | |
| 5.3.8 | OS command injection | partial | no shell-outs in the application; the migration and verify CLIs take no user input |
| 5.3.9 | Local and remote file inclusion | n/a | |
| 5.3.10 | XPath, XML injection | n/a | no XML parsing |
| 5.4.x | Memory, string, unmanaged code | partial | managed languages; Buffer sizes bounded |
| 5.5.1-5.5.4 | Deserialisation | met | JSON only, `JSON.parse` of bounded input |

## V6 Cryptography

| ID | Requirement (short) | Status | Proof or gap |
|----|---------------------|--------|--------------|
| 6.1.1-6.1.3 | Data at rest classification and encryption | partial | session tokens AES-256-GCM with row-bound AAD (`apps/web/src/server/crypto.test.ts`); case files are not encrypted at rest by the application (disk or database encryption is the platform's) |
| 6.2.1 | Failures fail securely | met | |
| 6.2.2 | Industry-proven algorithms | met | AES-256-GCM, HMAC-SHA256, SHA-256, RS256/ES256 verify |
| 6.2.3 | Approved modes and IV handling | met | random 96-bit IV per record (`crypto.test.ts`) |
| 6.2.4 | Crypto agility | partial | key rings with ids; algorithm changes need code |
| 6.2.5-6.2.8 | No weak modes, constant-time compare | met | `timingSafeEqual` for MACs, secrets and tokens (`netguard.test.ts`, `crypto.test.ts`) |
| 6.3.1-6.3.3 | Random values from a CSPRNG | met | `crypto.randomBytes`, `randomUUID` |
| 6.4.1 | Secret management solution | not met | files and environment; the stance is in `docs/hardening.md` section 3 |
| 6.4.2 | Key material not exposed to the application | n/a | not applicable without an HSM |

## V7 Error handling and logging

| ID | Requirement (short) | Status | Proof or gap |
|----|---------------------|--------|--------------|
| 7.1.1 | No credentials or payment data in logs | met | canary scans (`tests/bff/src/hardening-bff.test.ts`, `tests/api-db/src/audit-api.test.ts`) |
| 7.1.2 | No other sensitive data in logs | met | decisions log ids, reasons and codes, no claims or tokens (`tests/api-db/src/e2e.test.ts`) |
| 7.1.3 | Security-relevant events logged | met | decisions, authentication events, exports, uploads (`docs/audit.md`) |
| 7.1.4 | Enough information for investigation | met | request id, subject, action, resource, reason |
| 7.2.1, 7.2.2 | All authentication and access control decisions logged | met | every decision is an audit row (`tests/api-db/src/audit-api.test.ts`) |
| 7.3.1 | Log injection prevented | met | JSON encoding, sanitised free text |
| 7.3.3 | Logs protected from unauthorised access and modification | met | append-only table, hash chain, auditor-only reads (`tests/api-db/src/audit-db.test.ts`) |
| 7.3.4 | Time sources synchronised, UTC | partial | UTC timestamps in the code; host clock synchronisation is the platform's |
| 7.4.1 | Generic error message with an id | met | generic bodies, request id (`apps/api/src/http.test.ts`) |
| 7.4.2 | Exception handling everywhere | met | global error filter |
| 7.4.3 | Last-resort handler | met | |
| 1.7.2 / 7.x | Central log shipping and retention | not met | see V1.7.2 |
| 7.x | Alerting | partial | break-glass writes an alert marker; nothing consumes it |

## V8 Data protection

| ID | Requirement (short) | Status | Proof or gap |
|----|---------------------|--------|--------------|
| 8.1.1 | Sensitive data not cached by servers | met | `Cache-Control: no-store` on everything dynamic |
| 8.1.2 | Client-side caching disabled | met | `tests/bff/src/pages-headers.test.ts` |
| 8.1.3 | Parameters in the body or headers, not the URL | partial | read endpoints use ids in the URL (not sensitive); the audit filters travel in the query string |
| 8.1.4 | Anti-caching headers on sensitive pages | met | |
| 8.1.5 | Regular backups, tested restore | not met | none |
| 8.1.6 | Backups encrypted | not met | none |
| 8.2.1 | Client-side storage of sensitive data avoided | met | no tokens in the browser |
| 8.2.2 | No sensitive data in browser storage | met | cookie only, no `localStorage` use |
| 8.3.1 | Sensitive data in the body, not the URL | partial | as 8.1.3 |
| 8.3.2 | Users can delete their data | not met | no deletion of case files once submitted; no attachment deletion |
| 8.3.4 | Sensitive data classified, access controls per class | met | the product |
| 8.3.5, 8.3.6 | Access to sensitive data audited, memory cleared | partial | access audited (`docs/audit.md`); memory clearing not attempted |
| 8.3.7 | Encryption of sensitive data | partial | see V6.1 |
| 8.3.8 | Retention rules | not met | none; audit retention and partitioning are open (`docs/plan.md`) |

## V9 Communication

| ID | Requirement (short) | Status | Proof or gap |
|----|---------------------|--------|--------------|
| 9.1.1 | TLS for all client connectivity | met | proxy terminates TLS 1.2+ (Caddy defaults), plain http not published (`scripts/prod-like-test.mjs`); the dev stack is http on loopback by design |
| 9.1.2 | Strong cipher suites only | partial | Caddy defaults; not scanned with a TLS scanner (unverified) |
| 9.1.3 | Only TLS 1.2 and 1.3 | partial | Caddy default minimum; not tested |
| 9.2.1 | TLS between services | not met | internal networks use plain http (BFF to API, Keycloak behind the proxy); mutual TLS is the upgrade |
| 9.2.2 | Encrypted connections to external services | met | the BFF talks to Keycloak over https through the proxy; Postgres is internal and plain (see 9.2.1) |
| 9.2.3-9.2.5 | Certificate validation, failures logged | met | Node verifies certificates against the stack's CA (`NODE_EXTRA_CA_CERTS`); no `rejectUnauthorized: false` anywhere (grep) |
| HSTS (14.4.5) | see V14 | met | |

## V10 Malicious code

| ID | Requirement (short) | Status | Proof or gap |
|----|---------------------|--------|--------------|
| 10.1.1 | Code analysis tool | met | CodeQL security-extended on every run, results uploaded to code scanning |
| 10.2.1 | No unauthorised phone-home or data collection | met | no third-party calls, no CDN, no telemetry (`NEXT_TELEMETRY_DISABLED`), fonts and assets self-hosted |
| 10.2.2 | Application asks for permissions only as needed | n/a | |
| 10.2.3-10.2.6 | No back doors, time bombs, Easter eggs | partial | review and tests; no independent code audit |
| 10.3.1 | Auto-update with signatures | n/a | |
| 10.3.2 | Integrity protections (subresource, signed code) | partial | lockfile with integrity hashes, digests; no signed artefacts (see 1.14.2) |
| 10.3.3 | Subdomain takeover protection | n/a | |

## V11 Business logic

| ID | Requirement (short) | Status | Proof or gap |
|----|---------------------|--------|--------------|
| 11.1.1 | Sequential step order enforced | met | draft, submitted, approved enforced in the database trigger and the policy (`tests/api-db/src/e2e.test.ts`) |
| 11.1.2 | Realistic human timing, no mass abuse | met | rate limits |
| 11.1.3 | Business limits enforced | met | size caps, body limits, page caps |
| 11.1.4 | Anti-automation | met | rate limits, lockout |
| 11.1.5 | Business logic limits and validation | met | |
| 11.1.6 | TOCTOU | met | decision and write in one locked transaction (`tests/api-db/src/concurrency.test.ts`) |
| 11.1.7 | Monitoring of unusual events | partial | audit trail and alert marker; no alerting pipeline |
| 11.1.8 | Alerts on automated attacks | partial | rate limits return 429 and are logged; no alert is raised |

## V12 Files and resources

| ID | Requirement (short) | Status | Proof or gap |
|----|---------------------|--------|--------------|
| 12.1.1 | Large files do not fill storage | partial | per-file cap and rate limits; **no quota** (not met for total storage) |
| 12.1.2 | Compressed files checked for size after decompression | met | archives are refused (`content.test.ts`), PNG pixel cap |
| 12.1.3 | Per-user quota | not met | none |
| 12.2.1 | File type verified | met | bytes decide (`content.test.ts`, `attachments-api.test.ts`) |
| 12.3.1 | User filename not used in paths | met | random keys (`scanner.test.ts` store tests, traversal names in `attachments-api.test.ts`) |
| 12.3.2 | No local file inclusion | met | |
| 12.3.3 | No remote file inclusion | n/a | |
| 12.3.4 | Reflected file download | met | name sanitised, disposition from the detected type |
| 12.3.5 | No untrusted file executed | met | |
| 12.3.6 | No unsafe include functionality | met | |
| 12.4.1 | Uploads outside the web root | met | |
| 12.4.2 | Uploads scanned | partial | scanner hook with a fail-closed pending state, real ClamAV in the prod-like stack (`scripts/prod-like-test.mjs` EICAR); the dev default is a stub that says clean |
| 12.5.1 | Only required file types served | met | |
| 12.5.2 | Direct requests to uploads served as download | met | `Content-Disposition: attachment`, nosniff, sandbox CSP |
| 12.6.1 | SSRF protection | met | see 5.2.6 |

## V13 API and web service

| ID | Requirement (short) | Status | Proof or gap |
|----|---------------------|--------|--------------|
| 13.1.1 | All components use the same encoding and parsers | met | JSON everywhere |
| 13.1.3 | API URLs expose no sensitive information | met | ids only |
| 13.1.4 | Authorisation at the controller and the resource level | met | three layers |
| 13.1.5 | Content types validated | met | 415 on unexpected types (`tests/api-db/src/attachments-api.test.ts`, `tests/bff/src/csrf-proxy.test.ts`) |
| 13.2.1 | HTTP methods restricted | met | method allow-list in the proxy, route inventory |
| 13.2.2 | JSON schema validation | met | DTOs |
| 13.2.3 | CSRF protection for cookie-based APIs | met | |
| 13.2.5 | Content-Type matches the body | met | |
| 13.2.6 | Message integrity of the SOAP, REST calls | partial | the zone header is signed; request bodies are not |
| 13.3.x | SOAP | n/a | |
| 13.4.x | GraphQL | n/a | |
| 13.1.x | Rate limiting of the API | met | per subject and per address (`apps/api/src/http.test.ts`) |

## V14 Configuration

| ID | Requirement (short) | Status | Proof or gap |
|----|---------------------|--------|--------------|
| 14.1.1 | Build is repeatable and secure | met | frozen lockfile, pinned bases, `pnpm deploy --prod` |
| 14.1.2 | Compiler flags and warnings | met | strict TypeScript, lint |
| 14.1.3 | Server configuration hardened | met | prod-like stack, `docs/deployment.md` |
| 14.1.4 | Automated, repeatable deployment | partial | compose and scripts; no pipeline deploys anything |
| 14.1.5 | Authorised changes to configuration | partial | review and CODEOWNERS; no config integrity check at runtime |
| 14.2.1 | Components up to date, no known vulnerabilities | met | Trivy, OSV, `pnpm audit` gates; exceptions listed with expiry (`.trivyignore.yaml`) |
| 14.2.2 | Unneeded features, samples, documentation removed | met | distroless images, no dev tooling in the final stage |
| 14.2.3 | Third-party assets from our own origin | met | no CDN, CSP `default-src 'none'` |
| 14.2.4 | Third-party components from trusted sources, pinned | met | digests, SHA-pinned actions |
| 14.2.5 | Software bill of materials | met | CycloneDX of production dependencies and one SBOM per image (CI artifacts) |
| 14.2.6 | Attack surface of libraries reduced | partial | install scripts off; no sandboxing of libraries |
| 14.3.1 | Detailed errors not shown | met | |
| 14.3.2 | Debug modes off | met | production builds; dev mode only in the dev compose |
| 14.3.3 | No version information in headers | met | no `Server`, `X-Powered-By` (`scripts/prod-like-test.mjs`, `next.config.ts`) |
| 14.4.1 | Content-Type with a charset on all responses | partial | JSON and HTML set by the frameworks; not asserted for every route |
| 14.4.2 | Content-Disposition on API responses that download | met | attachments |
| 14.4.3 | CSP | met | strict nonce policy (`tests/bff/src/pages-headers.test.ts`) |
| 14.4.4 | X-Content-Type-Options | met | |
| 14.4.5 | HSTS | met | BFF and proxy (`scripts/prod-like-test.mjs`) |
| 14.4.6 | Referrer-Policy | met | `same-origin` on the web app (see docs/bff.md), `no-referrer` on the API |
| 14.4.7 | Frame protection | met | `frame-ancestors 'none'`, `X-Frame-Options: DENY` |
| 14.5.1 | Only defined HTTP methods | met | |
| 14.5.2 | Origin header not used for authentication | met | used only as one CSRF signal next to the token |
| 14.5.3 | CORS allow-list | met | empty by default (`apps/api/src/http.test.ts`) |
| 14.5.4 | Trusted proxy headers | met | forwarded headers believed only with the proxy's secret (`tests/bff/src/hardening-bff.test.ts`, `scripts/prod-like-test.mjs`) |
| 14.x | Secrets and keys not in source control | met | gitleaks, `.env.example` only |
| 14.x | Production configuration verified at start | met | `ACL_ENV=production` refusals (`apps/api/src/config.test.ts`) |
| 14.1.x | Signed commits or provenance of releases | not met | guidance only (`docs/signed-commits.md`); no releases |

## Not met, in plain words

1. **No central log shipping, alerting or retention** (1.7.2, 7.x, 8.3.8, 11.1.7/11.1.8). Logs go to stdout; the audit table has no retention or partitioning; break-glass alerts have no consumer.
2. **No mutual TLS or TLS between internal components** (1.2.2, 1.9.1, 9.2.1). Internal networks carry plain http between the BFF and the API and from the proxy to the upstreams.
3. **No secret management service or key isolation** (1.6.2, 6.4.1). Secrets are files and environment variables; key rotation is a documented procedure, not a tested one.
4. **No signed artefacts or provenance** (1.14.2, 10.3.2). Digests are pinned and verified; images and commits are not signed, there are no releases.
5. **Credential hygiene gaps that belong to the identity provider's configuration** (2.1.7 breached-password check, 2.2.3 and 2.5.5 notifications, MFA for the Keycloak admin console).
6. **No user-facing session list** (3.3.4) and no "log out other devices".
7. **No backups, restore tests or retention rules** (8.1.5, 8.1.6, 8.3.8) and **no deletion of case files or attachments once submitted** (8.3.2).
8. **No storage quota** (12.1.1, 12.1.3): total storage is bounded only by per-file caps and rate limits.
9. **No external anchoring of the audit chain** (`docs/audit.md`): someone with database superuser and the HMAC key can rewrite history.

## Unverified (claimed, not tested here)

- The numbering and wording of the ASVS rows (see the top of this file).
- Keycloak's own behaviour for password length enforcement, hashing parameters, TOTP internals, account recovery and its admin console (rows marked delegated).
- TLS protocol versions and cipher suites of the proxy (defaults, no scanner run), a certificate from a public CA, HTTP/3.
- Live rotation of any key ring or database password; Keycloak client-secret rotation.
- Behaviour behind a cloud load balancer, with more than one replica, or under load.
- ClamAV detection beyond the EICAR test file.
- Anything about the host the containers run on.

## How this file is kept honest

A change that adds or weakens a control must change a row here in the same pull request. Rows whose proof is a test name are verified by that test passing in CI; rows whose proof is "Caddy defaults", "Keycloak" or a document are not.
