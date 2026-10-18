# Audit and integrity (stage 7)

An append-only, hash-chained audit log in Postgres records every authorization decision of the API and every authentication event of the BFF. Threat IDs refer to
`docs/threat-model.md`. **Not guaranteed** and **unverified** statements are collected at the end.

## What is recorded

| Event | Written by | When | `action`, `reason_code` |
|-------|------------|------|-------------------------|
| every policy decision on a `@Policy` route, allow and deny | API route guard | before the handler runs (an ALLOW with no audit row does not proceed: 503) | the policy action (`read`, `create`, `update`, `submit`, `approve`, `delete`, `export`, `readAudit`, `manageUsers`), the policy reason (`ALLOWED`, `CLEARANCE_TOO_LOW`, ...) |
| a file hidden from the caller (client sees 404) | API | the **real** reason is recorded (`CLEARANCE_TOO_LOW`, `COMPARTMENT_MISSING`, `ROLE_NOT_PERMITTED`, `STEP_UP_REQUIRED`, or `RESOURCE_NOT_FOUND`), with the id the client asked for | via `audit_read_denial_reason` (ADR-19) |
| a refusal decided inside the transaction (state changed after the guard, separation of duties) | API service | after the transaction ended, best effort | same codes, `details.authoritative = true` |
| break-glass | API | the allow row has `ALLOWED_BREAK_GLASS`, obligations `audit`+`alert`, `details.alert = true` and the **sanitised justification**; a refused attempt is a deny row | |
| audit reads and exports (auditing the auditors) | API | `readAudit` rows for every read; an `audit.export` row (format, count, filters, id range, truncated) **before** the data is returned | |
| sign-in, step-up | BFF | `auth.login` / `auth.stepup`, reason `LOGIN_OK`, `details.acr`; **fail closed**: no audit row, no session | |
| failed sign-in | BFF | `auth.login_failed`, actor `anonymous`, reason `NO_PREAUTH`, `CALLBACK_REJECTED`, `IDP_ERROR`, `SUB_INVALID` | best effort |
| sign-out | BFF | `auth.logout` | best effort: signing out is never blocked by the log |
| session killed by a refused refresh (expired, revoked, replayed refresh token) | BFF | `auth.session_killed`, reason `REFRESH_REFUSED`, actor = the user | best effort |
| refused CSRF check | BFF | `auth.csrf_denied`, reason `ORIGIN_MISSING`, `ORIGIN_MISMATCH`, `FETCH_SITE`, `TOKEN_MISSING`, `TOKEN_MISMATCH` | best effort |
| user management | API | would be an ordinary policy decision (`manageUsers`); no such routes exist yet | |
| unauthenticated requests | nobody | no identity to record; the structured stdout log has them (without secrets) | |

`/health` and `/me` are not policy routes and are not audited. Break-glass justification is the only free text stored.
Never stored: tokens, claims, cookies, headers, query strings, request bodies, IP addresses, URLs, state/nonce/code. `details` is limited by a fixed whitelist of keys and types
(`packages/audit/src/details.ts` and the table's `audit_details_ok` check, kept equal by a test); the tests inject canaries into every request channel and scan the rows.

## Schema (`apps/api/migrations/003_audit_log.sql`)

`audit_log(id, ts, actor_sub, actor_roles[], action, resource_type, resource_id, effect, reason_code, obligations[], request_id, source, details jsonb, prev_hash, key_id, hash)`,
every column with a CHECK. `id` is **not** an identity column: it is assigned by the chain writer (1, 2, 3, ...) because sequences skip values when a transaction rolls back and
a gap-free id is what lets a verifier tell "row deleted" from "insert rolled back". `request_id` is the id the API returns in `X-Request-Id`, so a row can be matched to a client request.
`audit_head(last_id, last_hash)` is where the next row must attach. `audit_checkpoints(ts, last_id, last_hash, key_id, mac)` holds signed snapshots of the head.

## Chain format `acl-audit/v1` (so a third party can re-verify)

For a row, the authenticated bytes are the UTF-8 encoding of the JSON text (no whitespace, as produced by `JSON.stringify`) of this array, in this order:

```
[ "acl-audit/v1", <id as decimal STRING>, <ts as ISO-8601 UTC with milliseconds, e.g. "2026-10-18T12:00:00.000Z">,
  <actor_sub>, <actor_roles sorted by UTF-16 code unit>, <action>, <resource_type>, <resource_id or null>, <effect>, <reason_code>,
  <obligations sorted>, <request_id>, <source>, <details as canonical JSON TEXT (a string)>, <prev_hash as lower-case hex>, <key_id> ]
```

`details` canonical JSON: object keys sorted by UTF-16 code unit at every depth, no whitespace, integers only (no floats), array order kept. The row hash is
`HMAC-SHA256(key[key_id], bytes)` (32 bytes). The first row (id 1) has `prev_hash` = SHA-256 of the ASCII string `acl-audit/v1 genesis` =
`4c28ebab5bc198ff48266a7625eaaeddd4f860656eaa34dd2f89b8579441a465`. Each later row's `prev_hash` is the previous row's `hash`.

A checkpoint's `mac` is `HMAC-SHA256(key[key_id], UTF-8 JSON of ["acl-audit-checkpoint/v1", <ts ISO>, <last_id as string>, <last_hash hex>, <key_id>])`.

**Golden vector** (key = 32 bytes of `0x01`, id `k1`; row: id 1, ts `2026-10-18T12:00:00.000Z`, actor `user-1`, roles `["analyst"]`, action `read`, resource_type `case_file`,
resource_id `0f1e2d3c-4b5a-4968-8776-655443322110`, effect `allow`, reason `ALLOWED`, obligations `["audit"]`, request id `req-00000001`, source `api`,
details `{"rule_ids":["rbac.role-grants-action"]}`, prev_hash genesis):
`hash = 0a7ca7a8026824380156366d16adcff06e601ee9b0747ea2fd5fa11ca61f7de4`. `packages/audit/src/audit.test.ts` pins it, and recomputes the same value with an independent
re-implementation of this specification written directly against `node:crypto`.

## What the chain proves, and what a plain hash chain would not

A plain SHA-256 chain only shows that rows were not edited **by someone who cannot recompute hashes**. A database administrator can edit a row and recompute every later hash.
This chain is keyed: the hashes are HMACs with a key that is **not in the database** (`AUDIT_HMAC_KEYS`, held by the API and the BFF process), so a database-only attacker cannot produce a row that verifies
(tested: an edited row re-hashed with plain SHA-256 is reported; a row signed with another key is reported; a valid-looking row appended by a DB-only attacker is reported).
The key ring has an id per key (`key_id` in the row, covered by the HMAC): new rows are signed with the first key of the ring, old rows keep verifying while their key stays in the ring.

| Attack | Detected by |
|--------|-------------|
| edit any field of a row | `HASH` at that row |
| edit a row and recompute the hash without the key | `HASH` |
| delete a middle row | `GAP` (and `PREV_HASH`) at the next row |
| duplicate or fork an id, reorder rows | `FORK`, `REORDER`, `GAP` |
| swap the `key_id`, use an unknown key | `HASH`, `KEY_UNKNOWN` |
| delete the tail, leave the head | `HEAD_MISMATCH` |
| delete the tail and rewrite the head | a checkpoint taken earlier: `TAIL_TRUNCATED` |
| delete the tail, the head fix and the stored checkpoints | **only an external copy of the checkpoints** (`--checkpoint-file`) |
| insert a malformed `details` | `SCHEMA` |
| forge a checkpoint | `CHECKPOINT_MAC` |

## Immutability and who can do what (tests: `tests/api-db/src/audit-db.test.ts`)

| Role | `audit_log` | `audit_head` | `audit_checkpoints` |
|------|-------------|--------------|---------------------|
| `casefile_app` (API) | INSERT (source `api` only), SELECT only with an auditor request context | SELECT | INSERT, SELECT only for auditors |
| `casefile_web` (BFF) | INSERT (source `bff` only) | SELECT | nothing |
| `casefile_audit` (verifier CLI) | SELECT all | SELECT | INSERT, SELECT all |
| `casefile_migrator` (owner) | nothing visible or writable (FORCE RLS, no policy) | - | - |
| everyone, owner and superuser included | **no UPDATE, DELETE or TRUNCATE**: no grant, plus triggers that raise for every role | changed only by the insert trigger | same as `audit_log` |

Linearity is enforced by the database for every writer: the `audit_chain` trigger (SECURITY DEFINER, the reason is in the migration) requires `id = head + 1` and `prev_hash = head hash`, then moves the head. A fork or gap
from any role is refused (tested), even with a valid signature. The database cannot verify the HMAC (the key is not there); the verifier does.

**Concurrent writers** take a transaction-scoped advisory lock on the chain before reading the head, so writes are serialised across processes (API and BFF) without any application-level queue; the trigger is the backstop for a writer
that forgets the lock (tested: it fails instead of forking). The cost is that audited requests contend on one lock for the duration of one tiny transaction (a read of one row, one insert): fine at this scale, a ceiling
at high throughput (see below). A rolled-back business transaction leaves no gap (the audit row is in its own transaction, or rolls back with it).

**Break procedure.** A superuser (or the owner) can disable triggers (`SET session_replication_role = replica`, `ALTER TABLE ... DISABLE TRIGGER`). This is the only way to change or delete rows, it is not available to any application role,
and it cannot be hidden: the chain verification reports the edit. Use it only for a documented maintenance window; record it outside the database; run `pnpm audit:verify` afterwards. Tests use it on a throwaway database to simulate an attacker.

## Failure behaviour (fail closed)

- Allowed decisions on policy routes: the audit row is written **before** the handler runs. If it cannot be written the response is `503` and nothing happened (reads and lists included: tested by revoking INSERT from the role).
- Denials stay denials when the audit write fails (a refusal needs no log to be safe); the failure is written to the stdout log as `audit_write_failed`.
- BFF sign-in: no audit row, no session (503). Sign-out, session kills and CSRF refusals are recorded best effort: refusing them would only help an attacker.
- Audit export: the `audit.export` row is written first; no row, no export.

## Reading, exporting, verifying

- `GET /audit-log` (role `auditor` only: policy action `readAudit`; everyone else 403 and the database returns them no rows): filters `from`, `to`, `actor`, `resource`, `action`, `effect`, `limit` (1..500). Unknown or malformed parameters are 400.
  Pagination uses **stable cursors** `keyId.afterId.mac` (HMAC over key id, id and the filter fingerprint): ids only grow so new rows never shift a page; a tampered, truncated or other-query cursor is 400.
- `GET /audit-log/export?format=ndjson|csv` (same filters, `cursor`): at most 2000 rows per call, then `nextCursor`. NDJSON: one row per line, then a last line `{"proof": ..., "nextCursor": ...}`; CSV: header plus rows in a file download, with the proof in the `X-Audit-Proof`
  header (base64 JSON) for both. The proof has the chain id and algorithm, row count, first id and its `prev_hash`, last id and hash, the head, and the latest checkpoint; with the key ring, `verifyChain` re-verifies the file from `firstPrevHash` offline (tested).
  CSV cells that start (after optional whitespace) with `=`, `+`, `-`, `@`, tab or CR get a leading apostrophe so spreadsheets show them as text.
- `GET /audit-log/checkpoints`, `GET /audit-log/verify` (bounded recomputation inside the API).
- BFF pages for auditors: `/audit` (filters, pagination, export forms with CSRF), `/audit/verify`. Unstyled.
- `pnpm audit:verify [--from N] [--to M] [--prev-hash HEX] [--checkpoint-file PATH]`: recomputes the chain in batches as `casefile_audit`, prints a JSON summary (`ok`, `checked`, `lastId`, `firstBad`, `issues`), exit **0** verified, **1** problem found (the first bad row is printed), **2** could not run.
  A range (`--from`) trusts the stored row before it unless `--prev-hash` supplies an external anchor.
- `pnpm audit:checkpoint [--out PATH]`: writes a signed checkpoint of the head into the table and appends the same line to a file. The API also writes one every `AUDIT_CHECKPOINT_SECONDS` (default 300, 0 disables) and before each export.
  **Keep the `--out` file (or the export proofs) somewhere the database host cannot write**: that copy is what detects a deleted tail when the attacker also deleted the stored checkpoints.

## Operations

Dev: existing volumes do not re-run the init script (new roles `casefile_audit`, `casefile_lookup`): `docker compose down -v`, then `pnpm db:migrate`. New environment variables: `CASEFILE_AUDIT_PASSWORD`, `AUDIT_DATABASE_URL`, `AUDIT_HMAC_KEYS` (API and web must have the **same** ring), `AUDIT_CHECKPOINT_SECONDS`.
Key rotation: put the new key first in `AUDIT_HMAC_KEYS`, keep the old ones; new rows use the new key, verification accepts both. Never remove a key that signed rows you still want to verify.

## Mutation check (by hand)

Each mutant below was applied to the source (or to a scratch copy of the migrations run against a scratch database), the matching suite was run, and the file was restored. A mutant counts as killed when at least one test fails. The mutation scripts are not in the repository.

- **`packages/audit` (26 mutants, unit tests):** key id not authenticated; roles, obligations or details keys not sorted; `prev_hash` link, row hash, gap, fork, head mismatch, tail truncation, unknown key, checkpoint MAC, details schema not checked; MAC comparison always true; short keys accepted; chain lock not taken; CSV formulas and leading-whitespace trick not neutralised; cursor MAC not verified, cursor not bound to the filters; bidi, control characters kept by `sanitizeText`; any details key accepted; justification not sanitised; genesis hash changed; entry not validated in `buildRow`. All killed. One mutant (newlines kept) was equivalent because the whitespace collapse removes them anyway; it was replaced by one that keeps low control characters, and a test was added for it.
- **SQL (23 mutants, `audit-db.test.ts`):** missing UPDATE/DELETE/TRUNCATE trigger on `audit_log`, missing UPDATE trigger on `audit_checkpoints`; chain guard without the `prev_hash` or `id` check or with an unpinned `search_path`; head updatable directly; API or BFF role may insert any source; any request context may read the log or the checkpoints; API role may UPDATE; web role may read; FORCE RLS removed; details whitelist or request id pattern removed; denial-reason function missing the clearance or compartment branch, executable by PUBLIC, usable without request context; lookup role keeping CREATE or reading all columns. All killed.
- **API and BFF (15 mutants, `audit-api.test.ts`, `audit-bff.test.ts`):** ALLOW proceeding after a failed audit write; hidden reason always `RESOURCE_NOT_FOUND`; break-glass justification unsanitised; export without its audit row or without the pre-export checkpoint; cursor not verified; wrong policy action on an auditor route; writer swallowing failures; wrong `lastHash` in the proof; sign-in audit not strict; logout, CSRF-denial, session-kill and failed-login audits removed. All killed after one test was added: the first run of the "authoritative denials not audited" mutant survived because the route guard writes its own row for the same request, so a service-level test now checks that the in-transaction refusal reaches the writer.

Not mutation-tested: the auditor page markup, the Next.js export route, the timer in `CheckpointService`.

## What is NOT guaranteed

- **A compromised API or BFF process that holds the HMAC key** can write false rows (they will verify). The chain proves integrity after the fact, not honesty of the writer.
- **Tail truncation with the checkpoints deleted too** is undetectable inside the database. Real external anchoring (WORM storage, a second system, a transparency log) is out of scope; the exported checkpoint file is the substitute and only as good as where it is kept.
- **Not every event is an audit row:** unauthenticated requests, `/health`, `/me`; and denials are best-effort when the audit table is down.
- **An allow row means "the guard allowed it", not "it succeeded":** the handler may still fail afterwards (conflict, validation); the service records an authoritative refusal if the state changed, but a success has no separate row.
- **Time** comes from the API/BFF host clock (millisecond UTC); there is no trusted timestamp. A skewed host writes skewed `ts`; `id` order is the authoritative order.
- **Throughput:** all writers serialise on one lock and one head row; verified here only at the scale of the tests (hundreds of concurrent writes). No partitioning or archival of old rows; the verifier reads the whole chain in batches.
- **Exports are bounded** (2000 rows per call); big exports are paged with cursors.
- The `audit_read_denial_reason` function lets the API role learn whether an id exists (it already can: a missing row and a hidden row differ in the log). It returns only codes (ADR-19).
- Not verified: behaviour under a database failover in the middle of a chain write; clock changes; very long chains (millions of rows) for the verifier's run time; the BFF and API running with different key rings (the verifier would report `HASH` for the rows of the one that does not match, which is the intended loud failure).
