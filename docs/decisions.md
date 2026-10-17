# Decisions

Short ADR-style notes. Status of each is "accepted" unless stated. Claims about product behaviour are **unverified** until a test or a doc reference is linked.

## ADR-1: BFF holds tokens, browser holds only a session cookie

- **Context.** An SPA that keeps access and refresh tokens in JS-reachable storage exposes them to any XSS (T-04).
- **Decision.** Next.js acts as a Backend For Frontend: it runs the Authorization Code + PKCE flow as a confidential client, keeps tokens server-side, and gives the browser an `httpOnly`, `Secure`, `SameSite` session cookie. The API still validates the JWT itself (T-08, T-09).
- **Consequences.** Needs CSRF protection (cookie auth) and a server-side session store. One more hop. The API is never exposed to browsers directly, so it binds to loopback in dev.

## ADR-2: Keycloak as identity provider

- **Context.** Writing login, MFA, token issuing and key rotation ourselves is the largest avoidable risk.
- **Decision.** Keycloak, run in `docker compose`, with its own Postgres database and role (T-23). Realm as code from stage 2 (T-20). Keycloak owns authentication; the app owns authorization.
- **Consequences.** Heavy dev dependency, slow start (healthcheck `start_period` 40s). Claims we rely on (roles, clearance, unit, compartments, `acr`) must be mapped explicitly; mapper behaviour **unverified** until stage 2. Dev runs `start-dev` over HTTP; not a deployment model (T-34).

## ADR-3: RBAC for coarse actions, ABAC for the per-record decision

- **Context.** Roles alone explode when rules depend on record attributes (classification, compartments, unit) and context (`acr`, network zone).
- **Decision.** Decision order: authenticated, role allows the action (RBAC), ABAC allows this record, audit written, default deny. Policy lives as pure functions in `packages/policy` with table-driven tests, used by the API guard.
- **Consequences.** Two layers to keep consistent; the table-driven tests are the audit evidence. Pure functions keep the policy testable without Nest or a database.

## ADR-4: Postgres RLS as defence in depth

- **Context.** One forgotten check in application code leaks rows (T-15).
- **Decision.** Row-Level Security keyed on session attributes set per request by the API; app role is neither owner nor `BYPASSRLS`. RLS is a second line, not a replacement for ABAC in code.
- **Consequences.** Per-request session settings and a transaction discipline; migrations must be tested for policy presence. Performance impact **unverified**.

## ADR-5: pnpm monorepo, TypeScript strict, ESM

- **Decision.** pnpm workspaces (`apps/api`, `apps/web`, `packages/policy`). `strict` plus `noUncheckedIndexedAccess`. Node pinned via `.nvmrc` and `engines`, `engine-strict=true`.
- **Notes.** TypeScript is pinned to `~6.0` because `typescript-eslint` 8.71 rejects TS 7 at runtime. `apps/api` and `packages/policy` are `"type": "module"` (NestJS resolved to an ESM-only release at scaffold time, so CommonJS output failed to compile). Revisit the TS pin when typescript-eslint supports 7.

## ADR-6: Claim design, what lives in the token and what is fetched

- **Context.** The API must decide per request without a round trip to Keycloak, but a bloated token leaks data and goes stale.
- **Decision.** The access token carries only authorization inputs: role (`realm_access.roles`), `clearance`, `unit`,
  `compartments`, `aud`, `acr`, `amr`, plus standard claims. No name, email or username. Everything else (profile, display
  names) is fetched by the BFF from Keycloak when the UI needs it. Attributes are admin-managed in Keycloak, never user-editable.
- **Consequences.** Attribute changes take effect at the next token (<= 5 min, shorter than a revoked session lingering).
  The token is the only source of ABAC user attributes; the API must never read them from a request body or unsigned input.
  `amr` and `acr` are both exposed because forced MFA for SECRET and step-up on request are different mechanisms (see `docs/identity.md`).
  Resource attributes (classification, unit, compartments) come from Postgres, never from the client.

## ADR-7: Supply-chain gates run in CI without GitHub Advanced Security

- **Context.** The repo is private on a free plan, so code scanning upload and dependency-review are unavailable.
- **Decision.** Run the same scanners but keep results as artifacts and fail the job on findings (CodeQL SARIF gate, OSV,
  Trivy, zizmor, actionlint). Dependabot auto-merge exists but is inert until main requires these checks.
- **Consequences.** No alerts tab; a failing job is the signal. Exceptions (postgres gosu) are written down in `docs/supply-chain.md`.
