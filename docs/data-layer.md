# Data layer (stage 5)

Postgres holds the case files and enforces, on its own, the same read and write rules as `packages/policy`. The application decides first; the
database is the second, independent implementation. Threat IDs refer to `docs/threat-model.md`. **Unverified** marks things no test covers.

```
request -> JWT (stage 3) -> route guard: @Policy (advisory decision, 404/403 choice, stage 4)
        -> CaseFileService: BEGIN; set_config(app.*, is_local) ; SELECT ... FOR UPDATE ; evaluate() on the locked row ; write ; COMMIT
        -> Postgres as casefile_app: row-level security + guard trigger decide again, independently
```

## Schema (`apps/api/migrations/001_case_files.sql`)

`case_files(id uuid, title, body, classification, unit, compartments text[], status, author_id, submitted_by_id, version, created_at, updated_at)`.
`classification` and `case_status` are Postgres enums equal to the policy vocabulary (`CLEARANCES`, `STATUSES`; a drift test compares them, order included, because
enum order is the clearance rank). CHECK constraints: title 1..100, body <= 100000, `unit`/author/submitter shape, `compartments` at most 16 tags of `[A-Za-z0-9_-]{1,32}`,
and `(status = 'draft') = (submitted_by_id IS NULL)`. `role_grants(role, action, cross_unit, own_only, break_glass)` is the RBAC matrix as data, copied from `ROLE_GRANTS` and
checked for drift. `schema_migrations` (owner only) records applied files and checksums.

## Roles and grants (`infra/postgres/init-app-roles.sh`)

| Role | Purpose | Attributes |
|------|---------|-----------|
| `casefile_migrator` | owns all objects, runs migrations only | LOGIN, not superuser, no BYPASSRLS, no createdb/createrole |
| `casefile_app` | the API | LOGIN, not superuser, **no BYPASSRLS**, not owner of anything, connection limit 25, `statement_timeout` 5s, `lock_timeout` 3s, `idle_in_transaction_session_timeout` 15s (role level, so every connection has them) |
| `postgres` (dev superuser) | dev seed and test fixtures only | never used by the API |

`casefile_app` grants: `SELECT` on `role_grants`; `SELECT, DELETE` on `case_files`; `INSERT` on (title, body, classification, unit, compartments, author_id, status);
`UPDATE` on (title, body, status). Nothing else: no `version`, `submitted_by_id`, `id`, timestamps, no TRUNCATE/TRIGGER/REFERENCES, no DDL, no `schema_migrations`, `PUBLIC` has no
privileges, exactly two `SECURITY DEFINER` functions exist (the audit chain trigger and the audit denial-reason lookup, both described in `docs/audit.md`), every function pins `search_path`. At startup the API refuses to run if its role is a superuser, has BYPASSRLS or owns tables (T-37).
Passwords come from `.env` (dev only values in `.env.example`). Existing dev volumes do not re-run the init script: `docker compose down -v` once.

## Request context

The API sets these in the request's own transaction with `set_config(name, value, true)` (transaction-local: they vanish at COMMIT/ROLLBACK, so a pooled connection cannot carry them
over, T-36). Missing, empty or malformed values make every policy deny; an unknown clearance, role or marker matches nothing.

| Setting | Value |
|---------|-------|
| `app.ctx` | `v1`, set last; anything else is "no context" |
| `app.sub`, `app.unit`, `app.clearance` | token subject, unit, clearance (must be a valid enum value) |
| `app.roles`, `app.compartments`, `app.amr` | comma separated; a member containing a comma or a control character is refused before the query |
| `app.acr` | token `acr` |
| `app.break_glass`, `app.bg_justification` | `on` plus the trimmed justification, only for `read` and only when non-blank |

## Policies and the policy-package rule each mirrors

| Where | Rule in SQL | Mirrors (`packages/policy`) |
|-------|-------------|-----------------------------|
| SELECT policy | role has `read`; `classification <= app.clearance`; SECRET needs `app_mfa()` (acr = mfa and otp in amr); compartments `<@` the subject's; **or** break-glass (flag, justification, role with the grant) in place of the compartment test only | `rbac.role-grants-action`, `abac.clearance-floor`, `abac.step-up`, `abac.need-to-know`, break-glass (need-to-know only) |
| INSERT policy | role has `create`; floor, need-to-know, step-up (`app_cleared`); `unit = app.unit` unless a cross-unit role; `author_id = app.sub`; `status = draft`; no submitter; version 1 | create rules incl. author binding (`NOT_OWNER`), `abac.unit-scope`, status machine |
| UPDATE policy (USING and WITH CHECK) | role has update, submit or approve; `app_cleared`; unit scope (or any cross-unit grant) | coarse row filter: floor, need-to-know, step-up, unit scope |
| `case_files_guard` trigger (BEFORE UPDATE) | derives the action from the status change (same status = update, draft to submitted = submit, submitted to approved = approve, anything else refused); role has it; unit scope; ownership for own-only roles; separation of duties on approve (not author, not recorded submitter); update only in draft; immutable id, author, classification, unit, compartments, created_at; records `submitted_by_id` from the context; bumps `version` and `updated_at` | `abac.status-machine`, `abac.unit-scope`, `abac.ownership`, `abac.separation-of-duties`, role grants |
| DELETE policy | role has `delete`; `app_cleared`; draft only; unit scope; ownership for own-only roles | delete rules |

`export` is not expressible (zone, UTC window, approved-only): the database sees a read, the app enforces the rest.

## Service flow and existence hiding (`casefiles/case-file.service.ts`)

1. `withContext`: BEGIN, set the context, run, COMMIT (ROLLBACK on any error). 2. Writes `SELECT ... FOR UPDATE` first (the UPDATE policy applies to it); if the row is visible but not
lockable the decision below says why. 3. `evaluate()` runs on that locked row. 4. The write carries `WHERE version = $n`. 5. A concurrent transaction waits on the lock (3 s, then 409), then
decides on the new state (T-35). A row the caller cannot read is invisible to the query: 404 by construction. For a cleared caller without MFA a savepoint probe pretends MFA, looks for the id,
rolls back (restoring the context) and returns only a boolean: yes gives 403 with the step-up challenge, no gives 404. If the app allows but the database refuses (42501), the caller gets 403 and an
error line `db_denied_after_policy_allowed` is logged: the layers disagree. Lists apply RLS and then the same read filter again in the app; a difference logs `rls_returned_rows_policy_denies`.

## Parity: how it is proven (`tests/api-db/src/parity.test.ts`)

For every subject x environment x row combination the test asks `evaluate()` and asks Postgres as `casefile_app` under the same context (SELECT for read; INSERT, UPDATE of title, status
change, DELETE inside a savepoint that is rolled back) and compares allow/deny. Grids: 7 role sets (incl. a multi-role and an unknown role) x clearances x compartment sets x units x ids x
{password, MFA} against 240 rows (3 classifications x 4 compartment sets x 2 units x 5 status/submitter variants x 2 authors), plus break-glass reads; then fast-check properties with random
subjects, environments and rows for every action. A mismatch fails with a table showing the action, both answers, the policy reason, the subject, the environment and the row.

**Intentional differences** (also in `KNOWN_DIFFERENCES` in `tests/api-db/src/parity.ts`, each with where it is tested instead): export is app-only; a break-glass request with a blank
justification is refused by the app before any query; invalid or unknown input cannot exist in typed columns or is "no context"; `readAudit` and `manageUsers` have no table yet; the database
forbids changing classification, unit, compartments, author (the policy has no such action); the database ignores the break-glass flag for writes.

## Pool and limits

`pg.Pool` max 10 (`DB_POOL_MAX`, 1..50), `connectionTimeoutMillis` 5 s (an exhausted pool fails the request instead of queueing), idle timeout 30 s. Statement, lock and idle-in-transaction
timeouts are role settings. SQL injection: only `sql` constants with `$n` parameters (ADR-10); hostile title/body/id/compartments, second-order reuse and hostile context values are tested.

## Dev workflow

```sh
cp .env.example .env && docker compose down -v && docker compose up -d --wait
pnpm db:migrate      # as casefile_migrator (builds first)
pnpm db:seed         # dev only, as the superuser, refuses non-local databases
pnpm test:db         # DB tests against <POSTGRES_DB>_test (migrations applied by the suite itself)
```

## Mutation check (by hand, against the database)

Each change below was applied alone to the migration in a scratch database and the suites roles, rls, drift, parity and concurrency were run against it
(`--bail 1`): **all 40 were killed** (at least one test failed). Several are deliberately redundant-layer mutants (for example M39, the unit scope in the UPDATE policy,
which the trigger also enforces): they are killed anyway because the parity grids include the multi-role subjects that reach the trigger's own check.

- M01 cleared(): no clearance floor
- M02 cleared(): no need-to-know
- M03 cleared(): no step-up
- M04 select: no clearance floor
- M05 select: no step-up
- M06 select: no need-to-know
- M07 break-glass for any role
- M08 break-glass beats the floor and step-up
- M09 break-glass beats step-up only
- M10 break-glass accepts blank justification
- M11 insert: author not bound to caller
- M12 insert: any unit
- M13 insert: no role check
- M14 insert: no floor/need-to-know/step-up
- M15 update policy: no floor/need-to-know/step-up (USING)
- M16 trigger: no unit rule
- M17 trigger: no separation of duties
- M18 trigger: submitter may approve
- M19 trigger: no ownership
- M20 trigger: no role check
- M21 trigger: edit after submit
- M22 delete: any status
- M23 delete: no ownership
- M24 delete: no unit scope
- M25 role_own_only: union semantics inverted
- M26 grants: reviewer approve not cross-unit
- M27 grants: analyst submit not own-only
- M28 grants: unit-admin has no break-glass
- M29 app_mfa(): no otp in amr
- M30 app_mfa(): no acr check
- M31 role_allows(): any role
- M32 trigger: submitter taken from nowhere
- M33 trigger: version not bumped
- M34 ctx marker not required
- M35 FORCE row security removed
- M36 grant: UPDATE(classification) added
- M37 grant: TRUNCATE added
- M38 trigger: classification mutable
- M39 update policy: no unit scope (USING; trigger still checks)
- M40 role_grants readable table replaced: SECURITY DEFINER-free check removed (search_path unpinned on app_mfa)

Application layer (apps/api and e2e) mutants were not repeated for this stage beyond those listed in `docs/policy.md`; the service's authoritative recheck is covered by the
concurrency and end-to-end tests but **not mutation-tested**.

## Limits and not verified

- RLS cannot stop code that sets a forged context (it runs as the same role): it covers missing checks, wrong queries and injection. ADR-11.
- Break-glass justification text is not stored by the database (the app logs the alert); the audit table is stage 7.
- Concurrency is tested on one Postgres with READ COMMITTED; behaviour under replication, pgbouncer in transaction mode (settings are transaction-local so it should be safe) or higher
  isolation levels is **unverified**.
- Performance of the policies (several function calls per row, `role_grants` lookups) is **unverified**; lists are capped at 200 rows.
- No pagination or full-text search yet; attachments and file storage are not part of this stage.
