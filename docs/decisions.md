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

## ADR-8: jose for JWT verification, fail-closed principal parsing

- **Context.** Hand-rolled JWT code is where `alg=none`, key confusion and kid tricks live (T-08, T-10).
- **Decision.** Use `jose` (maintained, zero dependencies, pinned exactly) for signature, `iss`, `aud`, `exp`/`nbf` and JWKS caching with
  cooldown. Layer our own checks on top where Keycloak semantics matter: algorithm allow-list (RS256, ES256), mandatory `kid`, payload `typ`
  `Bearer`, `azp` allow-list. Claims become a typed `Principal` through one strict parser; any deviation is 401, never a partial principal.
- **Alternatives.** `passport-jwt` (adds a strategy layer, no stricter), `@nestjs/jwt` (symmetric-first API), hand-rolled (rejected).
- **Consequences.** Retired keys linger until the JWKS cache refreshes (<= 10 min). No revocation before `exp`. Role and clearance vocabularies live
  in the API for now; stage 4 moves the shared types to `packages/policy`.

## ADR-9: Default deny, deny overrides, 404 versus 403

- **Context.** Authorization bugs are usually a missing check or an unclear precedence (T-11, T-15). Responses can also leak that a record exists.
- **Decision.** (1) Default deny: no declared access, no grant, unknown input or unknown value all deny. (2) Deny overrides allow: every rule is
  evaluated; any violation denies; role grants never rescue an ABAC failure; break-glass may override need-to-know only, never the clearance floor or step-up.
  (3) The decision is a pure function in `packages/policy` so it is table-testable, property-testable and shareable with the data layer. (4) Refusals
  hide existence: 404 when the subject may not read the resource (also for nonexistent ids, identical body), 403 when they can read it but not do the action,
  403 with an RFC 9470 challenge when only MFA is missing and the subject is cleared.
- **Alternatives.** An OPA/Rego engine (more expressive, but another runtime and language to verify; reconsider when rules outgrow code), CASL (attribute
  conditions in a library, weaker default-deny story), 403 everywhere (simpler, but confirms which ids exist).
- **Consequences.** A user who is legitimately refused a write on a file they cannot read sees 404, which can confuse support; the decision log carries the true reason.
  The reason codes are an API for logs and tests and must stay stable.

## ADR-10: PostgreSQL access with `pg`, plain SQL migrations, no ORM

- **Context.** The database layer is a security control. Query building and migration tooling should be small enough to read, with nothing that
  assembles SQL behind our back (T-14).
- **Decision.** `pg` (node-postgres, exact pin) with parameterised queries only. SQL is written through a tagged template `sql\`...\`` that accepts no
  substitutions (compile error and runtime error), so values can only travel as `$n`. An ESLint rule and a test (`tests/api-db/src/drift.test.ts`) forbid
  SQL-looking template literals with interpolation anywhere in `apps/api/src`. Migrations are plain `.sql` files run by a ~60 line forward-only runner
  (`apps/api/src/db/migrate.ts`): one transaction per file, SHA-256 recorded, an edited or missing applied file stops the run, a Postgres advisory lock serialises runners.
- **Alternatives.** node-pg-migrate (more features, larger dependency tree, JS migration DSL we do not need), Prisma/Drizzle/Kysely (an ORM or query builder
  makes row-level security and `set_config` per transaction awkward and adds a generated-SQL surface), Flyway/dbmate (another runtime or binary).
- **Consequences.** We own the runner and its tests. No down migrations (a security schema is never "rolled back" by dropping policies); fixes are new migrations.
  Row-mapping is hand written.

## ADR-11: Row-Level Security as a second, independent implementation of the read and write rules

- **Context.** One forgotten check in application code leaks rows (T-15). The policy package is the specification, but a bug in the app layer must not become a data leak.
- **Decision.** `case_files` has RLS **enabled and forced**. The API connects as `casefile_app` (not owner, no BYPASSRLS, column-level grants, no DDL); migrations run as
  `casefile_migrator` (owner). Policies read the request context from transaction-local settings (`set_config(..., is_local => true)`) written by the API in the same
  transaction; missing, empty or malformed context denies everything. Read, create and delete are policies. Update, submit and approve are one UPDATE policy plus a
  `BEFORE UPDATE` trigger, because the per-action rules need OLD and NEW (status transition, ownership, separation of duties). No `SECURITY DEFINER` function exists
  (a test pins that); helpers are invoker functions with a pinned `search_path`. The RBAC matrix is data (`role_grants`) copied from the policy package and checked for drift by a test.
  Policy-vs-database **parity tests** (grid and property based) fail the build when the two implementations disagree; intentional differences are listed in code.
- **Alternatives.** Application checks only (single point of failure), `SECURITY DEFINER` API functions (a second privileged code path), per-user Postgres roles (does not fit
  a pooled API and Keycloak-issued identities), RLS keyed on `current_user`.
- **Consequences.** Two implementations to keep in step (the parity tests are the price and the evidence). The application can still lie about the context: RLS protects against
  missing checks, wrong queries and injected SQL, not against code that deliberately sets someone else's identity (that code runs as the same role). FORCE means even the owner sees
  nothing without a context, so dev data and test fixtures are written as the dev superuser, never as the migrator.

## ADR-12: Decide and write in one transaction, on the locked row

- **Context.** The stage 4 fixture decided in the guard and wrote later: a check/use race (T-35).
- **Decision.** Each case-file operation is one transaction: set context, `SELECT ... FOR UPDATE` the row, evaluate the policy on that locked row, write with an optimistic
  `version` condition, commit. The route guard's decision stays as an advisory fast refusal and for the 404/403 choice; the service repeats the decision authoritatively. A second
  transaction waits on the row lock (`lock_timeout` 3 s, then 409) and decides on the new state. If the app allows but the database refuses, the caller gets 403 and an error is
  logged (the two layers disagree). Existence hiding with RLS: a row the caller cannot read is invisible to the query, so it is 404 by construction; a cleared caller without MFA is
  told apart by a savepoint probe that pretends MFA and returns only a boolean.
- **Consequences.** Writes take a row lock, so a slow client request cannot hold it for long (statement and idle-in-transaction timeouts). The decision runs twice per request; the cost is small
  and the guard decision is never trusted for the write.
