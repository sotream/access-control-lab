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

## ADR-13: `openid-client` for the OIDC flow in the BFF

- **Context.** A hand-written authorization code flow is where `state`, `nonce`, PKCE and ID token validation mistakes live (T-02, T-03).
- **Decision.** `openid-client` 6.8.8 (exact pin; built on `oauth4webapi`, by the author of `jose`). It performs discovery against the pinned issuer, builds the authorization URL, checks `state`, the RFC 9207 `iss` parameter,
  PKCE, ID token signature, `iss`, `aud`, `nonce` and expiry, and does the token and refresh grants and the end-session URL. Our code adds what a library cannot know: where `state`/`nonce`/verifier live (an encrypted single-use cookie),
  the return-to allow-list, the session model.
- **Alternatives.** `oauth4webapi` directly (lower level, we would re-implement the glue), `next-auth`/Auth.js (opinionated session handling, JWT-in-cookie defaults that conflict with server-side token storage), hand-rolled (rejected).
- **Consequences.** Plain http to the identity provider needs the library's explicit `allowInsecureRequests`, enabled only for a loopback issuer (dev).

## ADR-14: Sessions in Postgres, encrypted, dedicated role

- **Context.** Tokens must not reach the browser, and a restart or a second instance must not log everyone out. A signed cookie holding tokens (stateless) would put them in the browser; an in-memory store loses sessions and cannot enforce revoke-all across instances.
- **Decision.** Table `bff_sessions` in the existing Postgres, owned by the migrator, accessed only by role `casefile_web` (and invisible to `casefile_app`, which cannot see it either way). The cookie carries only a random id; the row stores its SHA-256, so a database dump yields no usable cookie.
  Tokens are AES-256-GCM encrypted with a key ring from the environment (key id per row, AAD bound to the row). Refresh runs under a row lock. Cap per user, idle and absolute expiry, revoke-all on logout.
- **Alternatives.** Redis (another component to secure and operate), in-memory behind an interface (single instance, loses sessions, no cross-process lock), signed JWT session cookie (tokens in the browser).
- **Consequences.** Every request does a primary-key lookup (cheap). The key ring is a secret to manage (stage 8); a compromised BFF can use live sessions.

## ADR-15: CSRF scheme: synchronizer token + Origin + Sec-Fetch-Site on top of SameSite=Lax

- **Context.** The session cookie authenticates state-changing requests, so forged cross-site requests must fail even where SameSite is unreliable (same-site subdomains, old browsers, GET-to-POST gadgets).
- **Decision.** Every state-changing BFF route requires an `Origin` equal to our origin (absent means refused), `Sec-Fetch-Site: same-origin` when present, and a per-session synchronizer token compared in constant time (hidden form field or `X-CSRF-Token`). Logout is POST only and covered too. The token is delivered inside server-rendered pages and by `GET /api/auth/session`, both unreadable cross-origin.
- **Alternatives.** Double-submit cookie (a planted sibling-subdomain cookie defeats it unless signed), SameSite alone, Origin alone (header can be missing behind some proxies), Next server actions' built-in check (only covers actions, not route handlers).
- **Consequences.** A non-browser client must send an Origin header. Login (GET) is not CSRF-protected by a token; login CSRF is addressed by `state` and the single-use pre-auth cookie.

## ADR-16: A narrow, explicit API client instead of a generic reverse proxy

- **Context.** A BFF that forwards arbitrary paths and headers is an open proxy and an SSRF and header-smuggling surface (T-38).
- **Decision.** One client builds every upstream request from scratch from an allow-list of nine method+path pairs against a fixed host. The browser's cookies, query string, forwarded and custom headers are never copied; the break-glass header exists only on its own route; responses are reduced to status, content type, `WWW-Authenticate` and `Retry-After`; size, time and redirect limits apply.
- **Consequences.** Adding an API route to the UI is a one-line allow-list change plus a test, which is the point.

## ADR-17: HMAC hash chain with a head table, a database-enforced linear chain, and an advisory lock

- **Context.** The audit log must show who did what and resist tampering by someone with database access (T-24, T-26). A plain SHA-256 chain can be recomputed by anyone who can write the table.
- **Decision.** Rows are chained with HMAC-SHA256 over a canonical, versioned serialisation (`acl-audit/v1`, specified in `docs/audit.md` so a third party can re-verify), keyed by a key ring outside the database (key id per row). The database enforces what it can without the key: no UPDATE/DELETE/TRUNCATE for
  anyone (grants and triggers), forced row-level security, and linearity (`id = head + 1`, `prev_hash = head hash`) in a trigger that moves a head row, so no role can write a fork or a gap. Writers serialise on a transaction-scoped advisory lock taken before they read the head; the trigger is the backstop.
  Signed checkpoints of the head make a deleted tail detectable; an exported copy makes deleting the checkpoints detectable. Ids are assigned by the writer, not by an identity column, so a rolled-back write leaves no gap.
- **Alternatives.** Plain SHA-256 chain (recomputable by a DB admin), a hash chain with no head (a deleted tail is invisible), a per-actor chain (no total order, more complex verification), a sequence for ids (gaps on rollback make "deleted" and "rolled back" indistinguishable), an external ledger or WORM store (out of scope, named in the limits), `pgaudit`/logical decoding (records statements, not decisions).
- **Consequences.** One lock and one head row serialise audited requests; fine at this scale, a ceiling later (batching or a single writer service would be the upgrade). The HMAC key is a secret to protect and rotate (stage 8); a compromised writer can write false but well-formed rows.

## ADR-18: Audit before the action, fail closed for allows, best effort for refusals and sign-out

- **Context.** "No audit, no action" is only true if the audit row exists before the effect and its failure stops the effect; but refusing to refuse (or to sign out) because the log is down would help an attacker (T-24).
- **Decision.** The route guard writes the decision row (own short transaction) before the handler runs; an ALLOW whose row cannot be written becomes 503 and nothing happens (reads included, because a read is an effect). A DENY is refused regardless; a failed row is logged to stdout. BFF sign-in is fail closed (no row, no session); sign-out, session kills and CSRF refusals are
  best effort. Refusals decided inside a transaction are written after it ended (a row inside would roll back with it, and a second connection per request could exhaust the pool). The audit row is not part of the business transaction: it records the decision, so a handler failure after an ALLOW leaves an allow row (documented).
- **Alternatives.** Audit row inside the business transaction (a rollback would erase the evidence of the attempt), asynchronous audit queue (an action could happen without a row), fail open (rejected).
- **Consequences.** An allow row means "allowed", not "succeeded". An audit outage is an availability outage for case files, which is the intended trade.

## ADR-20: Network zone is signed by the BFF, rate limits are per subject behind it

- **Context.** The zone used to come from the socket address, which behind the BFF is always the BFF; the API-wide per-address throttle had the same flaw (all users share one address). Next.js route handlers also cannot see the socket.
- **Decision.** The BFF decides the zone from a proxy-vouched client address (shared-secret header contract) and signs it per user and per call with an HMAC key ring; the API trusts only a verifying, fresh header for the token's subject. Authenticated API traffic is limited per verified subject, BFF traffic per user and per address, all with bounded in-memory tables.
- **Alternatives.** Trust `X-Forwarded-For` from a configured peer (the BFF cannot see its peer), mTLS between proxy and BFF (heavier, kept as the upgrade path), accept the zone as a plain header from the BFF's token (`azp`) only (a user token with `azp=casefile-web` is only ever held by the BFF today, but the signature does not depend on that staying true), a shared store for counters (not needed yet).
- **Consequences.** Two more secrets to manage and rotate; per-process counters; a compromised BFF can claim any zone for its users.

## ADR-19: A narrow SECURITY DEFINER function to log the true reason for a hidden file

- **Context.** Row-level security makes a hidden file invisible to the API, so the API cannot evaluate the policy on it and would log "not found" for "clearance too low". The brief for the audit log is to keep the real reason internally while the client sees 404.
- **Decision.** `audit_read_denial_reason(uuid)` runs as `casefile_lookup`, a NOLOGIN role that can read exactly three columns (`id`, `classification`, `compartments`) and the role matrix, evaluates the read rule for the caller's own request context in SQL, and returns only a code. Only `casefile_app` (the API role) may execute it (not the web or verifier roles, not PUBLIC). Its result is checked against `packages/policy` on a grid
  (parity test). This is the second SECURITY DEFINER function in the schema (the first is the audit chain trigger); the earlier "no SECURITY DEFINER" property of stage 5 is relaxed to "exactly these two", pinned by a test.
- **Alternatives.** Log `RESOURCE_NOT_FOUND` for everything hidden (loses the information the log exists for), give the API a privileged metadata read (a bypass of RLS with data), run a second connection as a privileged role (same bypass, more moving parts).
- **Consequences.** The API role can now ask "does this id exist and why can't I see it" in a form that returns no data; a bug or injection in the API could use it as an existence oracle (one bit, the same bit the audit log records). Documented and tested; the rules in SQL are a third copy of the read rule, covered by the same parity discipline.

## ADR-21: Attachments on a plain filesystem volume, bytes decide the type, row security follows the parent

- **Context.** The plan asks for uploads with type, size and malware-scan controls. File content is untrusted, names are attacker-controlled, and a download is the easiest way to run active content in the application's origin.
- **Decision.** Store bytes on a dedicated directory under random keys (MinIO or another object store is not justified for a handful of small files and would add a service, credentials and a network hop). Decide the type from the bytes against a four-type allow-list and require the declared type to agree; refuse archives so there is nothing to decompress. Keep metadata in Postgres with row-level security that asks `case_files` (the parent's own policy), a scanner interface whose only success is an explicit clean verdict, quarantine/pending states that can never be served, and downloads as attachment with nosniff and a sandbox CSP, through the API only, audit row first.
- **Alternatives.** Trust the declared type or extension (the classic bypass), sniff only the first bytes (polyglots), MinIO with presigned URLs (bearer URLs that outlive a revoked session and bypass the policy), serve inline with a sanitiser (a sanitiser is a second product to trust), copy the parent's rule into the attachments policy (drift: parity tests would have to chase two copies).
- **Consequences.** A draft with attachments cannot be deleted and attachments cannot be removed; no quota and no re-scan job yet; the PDF scan is best effort; text files with markup markers are refused; the dev stub scanner means development proves the plumbing, not the detection.

## ADR-22: A prod-like stack that is attacked by a test, and a production profile that cannot be forgotten

- **Context.** Hardening that is only described is not hardening. Stage 8a added a production profile selected by `ACL_ENV`; an operator who forgets it would run with the lenient rules.
- **Decision.** Ship `docker-compose.prod-like.yml` (TLS proxy, four networks of which three are internal, every container non-root, read-only, capability-free, limited, secrets as files) and `scripts/prod-like-test.mjs`, which builds and starts it and checks the properties from the outside (not via the proxy, forged headers, no way out, no root process, EICAR through a real login). The application images set `ACL_ENV=production` themselves, the compose file repeats it, and the test starts the images with the development values and requires a refusal.
- **Alternatives.** Document the shape only (drifts silently), Kubernetes manifests (more machinery than the claim needs, nothing here to run them), a browser-driven test (see CI notes in `docs/deployment.md`).
- **Consequences.** A slow job (about 10 to 15 minutes) and a stack that exists only for tests. The test uses throw-away secrets and a throw-away CA. The properties it proves are those of this compose file, not of a particular cloud.

## ADR-23: Build the proxy and the scanner images ourselves

- **Context.** Trivy found 3 fixable HIGH findings in the stock Caddy image (Go standard library and x/net) and 26 fixable HIGH/CRITICAL in the stock ClamAV image (old Alpine libraries), both on a path that touches untrusted input (TLS termination, uploaded bytes).
- **Decision.** `Dockerfile.caddy` builds Caddy 2.11.7 with a current Go toolchain and a patched x/net; `Dockerfile.clamd` installs the Alpine clamav package on a current Alpine and bakes signatures in at build time (the running container has no network). Both run as non-root with no added capability.
- **Alternatives.** Ignore the findings with an expiry (26 entries would train people to ignore the list), wait for upstream (no date), a distroless scanner (no maintained one).
- **Consequences.** We own the rebuild schedule: a security fix upstream reaches us when we rebuild, and clamd signatures are as old as the image. A deployment needs a scheduled rebuild; none is built here. The Caddy build trusts the Go module proxy and the Alpine mirrors at build time (checksums come from `go.sum` and the package index, not from our review).

## ADR-24: Attack tests are black-box, against the production images, with a few test-only doors

- **Context.** Stages 1 to 8 tested each control close to its code. What was never tested is the assembled system as an attacker meets it: through the proxy, with real tokens, a real scanner and the real configuration. The five defects the stage 9 suite found (docs/attack-catalogue.md) all lived in the seams between layers.
- **Decision.** `tests/attack` drives the prod-like stack from outside (HTTPS to the proxy, a scripted browser, plain HTTP clients, raw TLS sockets), signed in as the seed users. Where an attack needs a surface the proxy hides (the API, for token attacks and fuzzing; the BFF and API without rate limits, so that hundreds of sign-ins from one address do not trip the limits under test) the test compose file adds test-only doors: `/__api`, `/__echo`, and a header that selects strict instances. They exist only in `docker-compose.prod-like.test.yml` and `infra/caddy/test/`. Fixtures are inserted by the operator (psql), never by an attack. A fixed fuzz seed runs in CI, a random one nightly; ZAP runs on the fresh stack; a gate ties the suite to the threat model.
- **Alternatives.** Attack tests inside the existing suites (they share the harness and the assumptions of the code they test), a browser-driven suite (slow, and the UI is not designed yet), Burp or ZAP only (finds classes, not the application's rules: who may read which file).
- **Consequences.** A 10 to 15 minute job; the test doors are a standing risk if they are ever copied into a deployment (the file names say TEST ONLY and the stack test would fail on them: they are not in the base files); the suite proves the absence of the attacks it contains, nothing more (`docs/attack-catalogue.md`, "Not attacked here").
