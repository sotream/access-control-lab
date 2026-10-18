# access-control-lab

**Casefile Vault** (repo: `access-control-lab`). Security-first monorepo: a small "case file vault" where who may see what is decided by OAuth2/OIDC identity, roles (RBAC) and attributes (ABAC). The product is deliberately plain (case files with attachments); the point is the security design and the evidence that it works.

Status: stage 8 hardening ([docs/hardening.md](docs/hardening.md): rate limits, signed network zone, production profile, attachments; [docs/deployment.md](docs/deployment.md): images and the prod-like stack); stage 7 audit and integrity ([docs/audit.md](docs/audit.md)); stage 6 web as BFF ([docs/bff.md](docs/bff.md)); stage 5 data layer with row-level security ([docs/data-layer.md](docs/data-layer.md)); stage 4 authorization policy ([docs/policy.md](docs/policy.md)); stages 2 identity and 3 API auth done ([docs/api-auth.md](docs/api-auth.md)). Keycloak realm as code, dev users in [docs/dev-users.md](docs/dev-users.md), design in [docs/identity.md](docs/identity.md). Run `cp .env.example .env && docker compose up -d --wait && pnpm test:identity`. The prod-like stack (TLS proxy, internal networks, non-root read-only containers, ClamAV) and its attack tests: `node scripts/prod-like-test.mjs`. See [docs/plan.md](docs/plan.md).

## Stack

- pnpm workspaces monorepo: `apps/api` (NestJS), `apps/web` (Next.js, Tailwind), `packages/*` (shared types, policy)
- Postgres, Keycloak (identity provider), both in `docker compose`
- Design of the frontend comes last; security and API first

## Concepts in one minute

- **OAuth 2.0** is delegation: an app gets a token to act for a user without seeing the password. **OIDC** (OpenID Connect) adds identity on top (the ID token says who logged in). Flow used here: Authorization Code + PKCE (Proof Key for Code Exchange).
- **Authentication (authn)** = who are you. **Authorization (authz)** = what may you do.
- **RBAC** (role-based): permissions attach to roles, users get roles. Simple and auditable; "analyst can read, admin can manage". Breaks down when rules depend on context (role explosion).
- **ABAC** (attribute-based): a rule over attributes of user, resource, action and environment: "clearance >= classification AND user is in the case's compartment AND request comes from the managed network". Flexible, harder to audit, needs a policy engine.
- This repo uses both: RBAC for coarse actions, ABAC for the per-record decision.
