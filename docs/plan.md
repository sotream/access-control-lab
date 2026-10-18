# Plan

## Product

Case file vault. Users upload and read case files. Each file has a classification (`OFFICIAL`, `CONFIDENTIAL`, `SECRET`), an owning unit and compartments (need-to-know tags). Nothing fancy: CRUD plus attachments.

## Access model

- Roles (RBAC, from Keycloak realm roles): `analyst`, `reviewer`, `unit-admin`, `auditor`, `platform-admin`.
- Attributes (ABAC): user `clearance`, `unit`, `compartments[]`; resource `classification`, `unit`, `compartments[]`, `status`; environment `acr` (authentication strength), time, network zone.
- Decision order: authenticated -> role allows the action -> ABAC allows this record -> audit written. Default deny.
- Examples: read needs `clearance >= classification` and all file compartments in user compartments; `SECRET` read needs `acr` of MFA (multi-factor authentication) (step-up); a reviewer cannot approve a file they authored (separation of duties); break-glass read needs a justification and raises an alert.

## Stages

1. **Foundation**: pnpm monorepo, docker compose (Postgres, Keycloak with an imported dev realm), CI (lint, typecheck, test, audit, secret scan), `docs/threat-model.md` (STRIDE) written before code.
2. **Identity**: Keycloak realm as code, users and attributes via protocol mappers, MFA (TOTP, Time-based One-Time Password) for high clearance, client for web (confidential, PKCE), client for API.
3. **API as resource server**: NestJS validates JWT (JSON Web Token) against JWKS (JSON Web Key Set): signature, `iss`, `aud`, `exp`, `nbf`, algorithm allow-list; clock skew; key rotation; no trust of unsigned claims.
4. **Authorization**: policy module in `packages/policy` (pure functions, table-driven tests), guard and decorators in NestJS, default deny, decision log with reason.
5. **Data layer defence in depth**: Postgres Row-Level Security keyed on session attributes, so a missed check in code still cannot leak rows; parameterised queries only; migrations tested.
6. **Web as BFF** (Backend For Frontend): Next.js holds tokens server-side, browser gets only an httpOnly, Secure, SameSite session cookie; CSRF (Cross-Site Request Forgery) protection, refresh rotation, logout with Keycloak end-session, CSP (Content Security Policy) and security headers.
7. **Audit and integrity**: append-only audit log with hash chain, verification command, auditor-only read; export.
8. **Hardening**: rate limiting, upload validation (type, size, malware scan hook), secret handling, dependency and image scanning, SBOM (software bill of materials), OWASP ASVS (Application Security Verification Standard) level 2 checklist mapped to tests.
9. **Attack tests**: scripted abuse cases (token tampering, `alg=none`, wrong audience, expired token, IDOR (insecure direct object reference), privilege escalation, replayed refresh token) run in CI.
10. **Frontend design** (last): Tailwind design pass on a working, secure UI. **Not started: frontend design, to be discussed with the owner first.**

## Definition of done per stage

Tests pass, negative tests exist for the new control, docs updated, threat model entries linked to the tests that cover them.

## Security additions and owning stage

Added after stage 1 review ("maximum security, honest and verified"). Each item has one owning stage.

| Addition | Stage | Status |
|----------|-------|--------|
| CI: CodeQL, OSV-Scanner, Trivy image scan, SBOM artifact, actionlint, zizmor, identity job | 2 | done in stage 2 PR |
| Supply chain: install scripts off, minimum release age, image digests, Dependabot cooldown | 2 | done |
| Repo hygiene: SECURITY.md, CODEOWNERS, PR checklist, editorconfig, signed-commit guidance | 2 | done |
| Dependabot auto-merge (minor/patch) | 2 | file present, inert until owner sets main ruleset and `DEPENDABOT_AUTOMERGE=true` |
| OpenSSF Scorecard | 8 | not enabled: needs repo-read token on a private repo, revisit if repo goes public |
| dependency-review-action | 8 | needs Advanced Security on private repos; OSV and audit cover lockfile; enable if repo goes public |
| Image SBOM and image scan in a release build | 8 | |
| helmet/CSP/headers, strict CORS, rate limiting, DTO whitelist with `forbidNonWhitelisted`, headers tested | 3 (API: done), 6 (BFF CSP and headers), 8 (distributed rate limiting) | API part done in stage 3 |
| Realm: TLS (`sslRequired=all`), production hostname | 8 | dev exception documented |

Stage 4 delivered: `packages/policy` (pure evaluator, 100% coverage gate), `@Policy` enforcement in the API guard, decision log, 404/403 rule (docs/policy.md, ADR-9).
Carried forward: stage 5 must pass the same read decision to SQL/RLS (`readFilter` parity) and decide-and-write in one transaction; stage 6 must design how the
BFF conveys the client's network zone (today `MANAGED_ADDRESSES` on the socket address); stage 7 persists the `audit` obligation.

Stage 5 delivered: Postgres schema with forced RLS and a guard trigger, migrator/app roles, decide-and-write in one transaction, parity tests against `packages/policy`
(docs/data-layer.md, ADR-10..12). Carried forward: stage 6 must decide how the BFF conveys the client network zone; stage 7 persists the `audit` obligation and break-glass
justification (append-only table, hash chain); stage 8 adds attachments/file storage threats (T-28..T-31), distributed rate limiting and TLS between components.

Stage 6 delivered: Next.js BFF with server-side OIDC (openid-client), encrypted Postgres sessions, CSRF scheme, allow-listed API client, strict CSP, functional pages (docs/bff.md, ADR-13..16).
Carried forward: stage 7 persists the `audit` obligation and break-glass justification and should log BFF login/logout/refresh-failure events; stage 8 adds login-route rate limiting, TLS between components, key-ring rotation procedure,
and a decision on conveying the client network zone; stage 10 designs the UI (the pages here are intentionally unstyled).

Stage 7 delivered: HMAC-chained append-only audit log (decisions, break-glass, BFF authentication events, auditor reads/exports), database-enforced linearity, checkpoints, `audit:verify` and `audit:checkpoint`, auditor endpoints and page (docs/audit.md, ADR-17..19).
Carried forward to stage 8: key management for `AUDIT_HMAC_KEYS`, `SESSION_ENCRYPTION_KEYS` and the DB passwords (secret store, rotation procedure), external anchoring of checkpoints (WORM or second system), retention/partitioning of the audit table, audit-write throughput measurement, rate limiting of login and the auditor endpoints, TLS between components.

Stage 8a delivered (PR "hardening, part 1"): `@acl/netguard` (rate limiter, trusted-proxy contract, signed network zone), per-user and per-address limits at the BFF and per-subject limits at the API, production profile (`ACL_ENV`) with secret checks and `*_FILE` secrets, rotation procedures, attachments (content inspection, quarantine, scanner hook, RLS following the parent, audit rows) with mutation results (docs/hardening.md, ADR-20 and ADR-21).
Stage 8b (next PR): Dockerfiles, prod-like compose with a TLS proxy, image scanning, CI additions (dependency-review, CodeQL upload, Scorecard), `docs/asvs.md`.

Stage 8b delivered: hardened images (api, web, keycloak, caddy, clamd), the prod-like stack with a TLS proxy and its attack test, Trivy on the built images, dependency-review, Scorecard, ASVS mapping (`docs/deployment.md`, `docs/asvs.md`, ADR-22/23).

Stage 9 delivered: a black-box attack suite (`tests/attack`, 60 catalogued attacks, fuzzing, ZAP baseline) against the prod-like stack through its proxy, run in CI; a threat-coverage gate in `pnpm lint`; one place for accepted risks; mutation spot-check of the suite (`docs/attack-catalogue.md`, `docs/accepted-risks.md`, ADR-24). Five defects it found were fixed in the same PR.

**Status: stages 1 to 9 are done. Stage 10 (frontend design) has not started and needs a design discussion with the owner.**
