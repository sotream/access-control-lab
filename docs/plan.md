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
10. **Frontend design** (last): Tailwind design pass on a working, secure UI.

## Definition of done per stage

Tests pass, negative tests exist for the new control, docs updated, threat model entries linked to the tests that cover them.
