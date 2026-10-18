# Plan

## Product

Case file vault. Users upload and read case files. Each file has a classification (`OFFICIAL`, `CONFIDENTIAL`, `SECRET`), an owning unit and compartments (need-to-know tags). Nothing fancy: CRUD plus attachments.

## Access model

- Roles (RBAC, from Keycloak realm roles): `analyst`, `reviewer`, `unit-admin`, `auditor`, `platform-admin`.
- Attributes (ABAC): user `clearance`, `unit`, `compartments[]`; resource `classification`, `unit`, `compartments[]`, `status`; environment `acr` (authentication strength), time, network zone.
- Decision order: authenticated -> role allows the action -> ABAC allows this record -> audit written. Default deny.
- Examples: read needs `clearance >= classification` and all file compartments in user compartments; `SECRET` read needs `acr` of MFA (multi-factor authentication) (step-up); a reviewer cannot approve a file they authored (separation of duties); break-glass read needs a justification and raises an alert.

## Stages

All ten stages are done. Each was one branch, one pull request squash-merged into `main`, and ended with tests that try to break the new control.

| # | Stage | What it delivered | Where to read more |
|---|-------|-------------------|--------------------|
| 1 | Foundation | pnpm monorepo, docker compose (Postgres, Keycloak with an imported dev realm), CI (lint, typecheck, test, audit, secret scan), the STRIDE threat model written before code | `docs/threat-model.md` |
| 2 | Identity | Keycloak realm as code, users and attributes via protocol mappers, TOTP (time-based one-time password) for high clearance, a confidential web client with PKCE, an API client | `docs/identity.md` |
| 3 | API as resource server | NestJS validates the JWT (JSON Web Token) against the JWKS (JSON Web Key Set): signature, `iss`, `aud`, `exp`, `nbf`, algorithm allow-list, clock skew, key rotation, no trust of unsigned claims | `docs/api-auth.md` |
| 4 | Authorization | `packages/policy` (pure functions, table-driven tests, coverage gate), `@Policy` guard, decision log with reasons, the 404-versus-403 rule | `docs/policy.md`, ADR-9 |
| 5 | Data layer defence in depth | Postgres row-level security keyed on session attributes, guard trigger, migrator and app roles, decide-and-write in one transaction, parity tests against the policy package | `docs/data-layer.md`, ADR-10 to 12 |
| 6 | Web as BFF (backend for frontend) | Next.js holds tokens server-side; the browser gets only an httpOnly, Secure, SameSite session cookie; CSRF scheme, refresh rotation, logout with Keycloak end-session, CSP and security headers | `docs/bff.md`, ADR-13 to 16 |
| 7 | Audit and integrity | HMAC-chained, append-only audit log (decisions, break-glass, authentication events, auditor reads and exports), database-enforced linearity, checkpoints, verification command, auditor-only read and export | `docs/audit.md`, ADR-17 to 19 |
| 8 | Hardening | rate limiting, signed network zone, production profile, secret handling, attachments (content inspection, quarantine, scanner hook), hardened images, the prod-like stack, image scanning, SBOM, ASVS self-assessment | `docs/hardening.md`, `docs/deployment.md`, `docs/asvs.md`, ADR-20 to 23 |
| 9 | Attack tests | a black-box attack suite against the prod-like stack, fuzzing, ZAP baseline, threat-coverage gate in `pnpm lint`, accepted risks in one place, mutation spot-check of the suite | `docs/attack-catalogue.md`, `docs/accepted-risks.md`, ADR-24 |
| 10 | Frontend design | the design system and every page of the console, self-hosted fonts, a build-time stylesheet under the unchanged strict CSP, a real-browser test stage (Playwright, axe, CSP violation collector, cookie and storage checks, keyboard order, generated screenshots) | `docs/ui.md`, ADR-25 |

Defects found late are recorded where they were found: stage 9 attacks found five (`docs/attack-catalogue.md`); the first real-browser run in stage 10 found that `Referrer-Policy: no-referrer` made Chromium send `Origin: null` on same-origin form posts, so every form was refused (ADR-25); a flaky test found that the zone MAC accepted four spellings of the same bytes (`docs/hardening.md`).

## Definition of done per stage

Tests pass, negative tests exist for the new control, docs updated, threat model entries linked to the tests that cover them.

## Security additions after the stage 1 review

Added after the stage 1 review, each with one owning stage.

| Addition | Stage | Status |
|----------|-------|--------|
| CI: CodeQL, OSV-Scanner, Trivy image scan, SBOM artifact, actionlint, zizmor, identity job | 2 | done |
| Supply chain: install scripts off, minimum release age, image digests, Dependabot cooldown | 2 | done |
| Repo hygiene: SECURITY.md, CODEOWNERS, PR checklist, editorconfig, signed-commit guidance | 2 | done |
| Dependabot auto-merge (minor/patch) | 2 | active: the `protect-main` ruleset requires checks and the variable `DEPENDABOT_AUTOMERGE` is `true` |
| OpenSSF Scorecard | 8 | done: the repository is public; the workflow runs on `main` and weekly |
| dependency-review-action | 8 | done: runs on every pull request (the repository's Dependency graph is enabled) |
| Image SBOM and image scan | 8 | done (`images` job) |
| helmet/CSP/headers, strict CORS, rate limiting, DTO whitelist with `forbidNonWhitelisted`, headers tested | 3, 6, 8 | done (API in stage 3, BFF in stage 6, distributed limiting stage 8) |
| Realm: TLS (`sslRequired=all`), production hostname | 8 | done in the prod-like stack; the dev realm keeps its documented exception |

## Notes handed from stage to stage

Until stage 8 the network zone was taken from a configured address list (`MANAGED_ADDRESSES`) on the socket address; stage 8 replaced it with `MANAGED_CIDRS` and a zone header signed by the BFF (ADR-20).
