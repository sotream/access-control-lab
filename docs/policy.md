# Authorization policy (stage 4)

`packages/policy` decides; `apps/api` enforces. The package is pure TypeScript with no dependencies, no I/O and no clock
(time and network zone arrive in `Environment`). Threat IDs refer to `docs/threat-model.md`.

```
evaluate(subject, action, resource | null, env) -> { effect, reason, obligations[], matchedRules[] }
```

Order: authenticated (API guard) -> role allows the action (RBAC) -> ABAC rules against this resource -> obligations (audit).
Default deny. **Deny overrides allow**: every applicable rule is evaluated and one violation denies; a role grant never rescues an
ABAC violation. The reported `reason` is the highest-priority violation (list below) and `matchedRules` lists all of them.
Malformed or unknown input (unknown clearance, missing field, unknown action or status) is `INVALID_INPUT` -> deny. Unknown roles carry no grants.

## Vocabulary (single source of truth: `packages/policy/src/model.ts`)

- Clearance, ordered: `OFFICIAL` < `CONFIDENTIAL` < `SECRET`. Roles: `analyst`, `reviewer`, `unit-admin`, `auditor`, `platform-admin`.
- Actions: `create read update submit approve delete export readAudit manageUsers`. Status: `draft` -> `submitted` -> `approved`.
- Subject: id, roles, clearance, unit, compartments (from the verified token). Resource: classification, ownerUnit, compartments, status,
  authorId, submittedById. Environment: acr, amr, now, networkZone, optional breakGlass.

## RBAC matrix (`matrix.ts`, data not code)

| Role | create | read | update | submit | approve | delete | export | readAudit | manageUsers | cross-unit | own only | break-glass |
|------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|---|---|:-:|
| analyst | x | x | x | x | | x | x | | | none | update, submit, delete | no |
| reviewer | | x | | | x | | x | | | approve | none | no |
| unit-admin | x | x | x | x | x | x | x | | x | none | none | yes |
| auditor | | | | | | | | x | | none | none | no |
| platform-admin | | | | | | | | | x | none | none | no |

- **analyst**: works on case files in their own unit; changes only drafts they authored.
- **reviewer**: reads and approves, also across units (a central review role); never edits.
- **unit-admin**: manages files of their own unit regardless of author; the only role with break-glass.
- **auditor**: audit log only. No case content, even OFFICIAL (hidden: 404).
- **platform-admin**: operations (user management). **No implicit case access**: platform administration is not need-to-know.
- A subject with several roles gets the union; ownership binds only if every granting role is own-only.

## ABAC rules and reason codes (priority order)

| # | Reason | Rule | Applies to |
|---|--------|------|-----------|
| 1 | `INVALID_INPUT` | `input.well-formed`: all inputs known and typed | all |
| 2 | `ROLE_NOT_PERMITTED` | `rbac.role-grants-action` | all |
| 3 | `CLEARANCE_TOO_LOW` | `abac.clearance-floor`: subject rank >= classification rank | resource actions |
| 4 | `COMPARTMENT_MISSING` | `abac.need-to-know`: every resource compartment is in the subject's | resource actions |
| 5 | `UNIT_MISMATCH` | `abac.unit-scope`: resource unit equals subject unit, unless a granting role has the action in `crossUnit` | create update submit approve delete (reads are not unit-scoped) |
| 6 | `NOT_OWNER` | `abac.ownership`: author is the subject. Binds `create` always (a file is authored by its creator) and own-only actions | create, update, submit, delete |
| 7 | `STATUS_FORBIDS` | `abac.status-machine`: update, submit, delete, create need `draft`; approve needs `submitted`; export needs `approved`; read any | resource actions |
| 8 | `SEPARATION_OF_DUTIES` | `abac.separation-of-duties`: approver is neither author nor submitter | approve |
| 9 | `STEP_UP_REQUIRED` | `abac.step-up`: any action on a SECRET file needs `acr == "mfa"` AND `amr` contains `otp` | resource actions on SECRET |
| 10 | `NETWORK_ZONE_FORBIDS` | `abac.export-network-zone`: zone is `managed` | export |
| 11 | `OUTSIDE_EXPORT_WINDOW` | `abac.export-window`: UTC hour of `env.now` in [06, 20) | export (example of a time condition) |

Allow reasons: `ALLOWED`, `ALLOWED_BREAK_GLASS`. Break-glass reasons: `BREAK_GLASS_NOT_PERMITTED`, `BREAK_GLASS_JUSTIFICATION_REQUIRED`.
Codes are stable (logs, tests, API depend on them): add, never rename.

Step-up applies to every action on SECRET, not only read, because a write by a password-only session is as bad as a read.
`acr` alone is not enough (it is a level-of-authentication bookkeeping value, see `docs/identity.md`); `amr` alone is not enough either
(a client can downgrade `acr`, tested).

### Obligations

`audit` on every allow (stage 7 persists it), `alert` on break-glass allows, `step-up` on `STEP_UP_REQUIRED` denials,
`require-justification` when break-glass was asked without a justification.

### Break-glass (decision recorded here, tested in `evaluate.test.ts`)

Explicit request (`X-Break-Glass-Justification` header at the API) + non-empty trimmed justification + a role with the grant (unit-admin)
+ action `read`. It overrides **only** `COMPARTMENT_MISSING` (and `UNIT_MISMATCH`, unreachable for reads). It never overrides the clearance
floor, step-up, role or input checks: a CONFIDENTIAL unit-admin cannot break-glass a SECRET file, and a SECRET file still needs MFA.
Allow carries `audit` + `alert`. If normal access would already succeed, the normal path is used (no alert); an empty justification is
refused even then, because it is an explicit request. Break-glass never changes visibility (404 rules are evaluated without it).

## 404 versus 403 (decision)

For a resource that exists, the API answers **404** when the subject may not read it (`visibility() == "hidden"`: role cannot read, clearance too
low, or a compartment missing) and **403** when the subject can read it but the action is refused (wrong unit, not owner, wrong status,
separation of duties, export conditions). A cleared user who only lacks MFA gets **403 with a challenge** (`WWW-Authenticate: Bearer
error="insufficient_user_authentication", acr_values="mfa"`, body code `STEP_UP_REQUIRED`, RFC 9470): they may know the file exists. An uncleared
user gets 404 even without MFA, so the challenge does not confirm existence. A nonexistent id and a hidden one return the identical body.
Unauthenticated callers get 401 before any lookup. Role-only routes (list, audit, user management) have no resource: 403.
`create` has no existing resource: refusals are 403.

## Enforcement in `apps/api`

```ts
@Policy({ action: "update", resource: ExistingFileLoader })   // loader provides the Resource
@Patch("files/:id") update(...)

@Policy({ action: "read", resource: null })                    // list: role only, handler filters rows with readFilter()
@Get("files") list(@PolicyContext() ctx) { ... }
```

- The existing default-deny guard runs the policy for `@Policy` routes; a route with no declaration is still denied and fails the inventory test.
- `ResourceLoader.load(req)` returns the `Resource` or `undefined` (404). For `create`, a candidate loader builds the resource from the request
  with **unit, author and status taken from the verified principal**, never from the body.
- `@Policy({ resource: null })` is refused at declaration time for create, update, submit, approve, delete and export, so a role-only check
  cannot be mistaken for a full one.
- Environment is built from the token (`acr`, `amr`) and the request: zone is `managed` only when the request carries `x-acl-zone` signed by the BFF for this token's subject (`ZONE_SIGNING_KEYS`, stage 8, docs/hardening.md); the socket address and every forwarded header are ignored; `now` comes from an injected clock.
- Decision log, one line per decision: `reqId, sub, action, resourceId, effect, reason, rules, obligations`. No claims, no token. Break-glass adds
  a `break_glass_alert` line with the justification.
- The in-memory case-file controller is a **test fixture** in `apps/api/test/`, not part of the build.

## Data layer parity (stage 5)

`readFilter(subject, env)` returns `{ roleAllowed, classifications[], compartmentsSubsetOf[] }`: the read decision as plain attributes
(no unit, status or ownership condition applies to read). `matchesReadFilter` applies it in memory. A property test pins
`matchesReadFilter(readFilter(s,e), r) == (evaluate(s,"read",r,e) allows)` for random inputs; stage 5 expresses the same three predicates as SQL/RLS
and tests parity against this.

## How to add a rule

1. Add a `ReasonCode` and, if it needs vocabulary, extend `model.ts`/`matrix.ts` (data first).
2. Add the check in `analyse()` with `check(reason, ok)`, give it a `RULE_ID` and a place in `PRIORITY`.
3. Decide whether break-glass may override it (default: no) and whether it changes visibility (read rules only).
4. Tests: a table case that fails without the rule, a grid or property if it is monotonic, and a mutation run. Coverage gate is 95% and currently 100%.
5. Update this file and the threat model.

## Tests and evidence

- `packages/policy`: 100% lines/branches (gate 95% in `vitest.config.ts`, enforced by `pnpm test` in CI): full role x action matrix (and
  role-only variant), clearance grid, compartment subset/superset/empty/duplicates/case, 33 malformed-input cases, step-up cases, unit, ownership, status
  machine, separation of duties, export zone and window boundaries, break-glass, deny-overrides, purity/determinism (clock stubbed, inputs frozen).
- Property tests (fast-check 4.10.2, 1500 runs each): deny when clearance < classification for any input incl. break-glass; adding a resource
  compartment never turns deny into allow; adding a subject compartment never turns a read allow into deny; no allow without a role grant (independent matrix);
  no SECRET allow without mfa+otp; approval never to author or submitter; cross-unit writes only for the reviewer's approve; allowed changes only from the
  state machine's source status; break-glass allow implies read + unit-admin + justification + floor; garbage input never throws; read filter parity.
- `apps/api`: guard + policy with signed tokens and the fixture: existence hiding, step-up challenge, roles outside the matrix, unit/ownership/mass
  assignment, lifecycle and separation of duties, export zone/window, break-glass, decision log, route inventory.
- `tests/identity`: the same scenarios with real Keycloak tokens of the seed users.

### Mutation check (by hand)

Each change below was applied alone and made at least one test fail (counts of failing tests in parentheses):
clearance `>=` to `>` (45); clearance check removed (13); compartments `every` to `some` (5); unit rule removed (8); step-up `&&` to `||` (8);
separation of duties without the submitter (2) or removed (6); update allowed in `approved` (3); delete allowed in `submitted` (3); break-glass
overriding the clearance floor (4) or step-up (2); break-glass for any reading role (4); allow whenever any role grants (77); export zone check removed (6);
export window end 20 to 21 (1); role lookup via `in` instead of own-property (12); auditor given `read` (4); unknown clearance ranked as OFFICIAL (5);
create ownership removed (1); step-up only for read (3); read filter ignoring step-up (3); visibility treating everything as visible (5);
invalid-input early return removed (1); `crossUnit` outside `actions` (1, after adding a matrix consistency test: this mutant was first equivalent and survived).
API layer: 404 hiding removed (12); step-up challenge removed (2); decision ignored (23); policy not called (27); zone always managed (2); missing resource not 404 (3);
RBAC-only instead of full evaluation (20); unit taken from the body in the fixture (1); list filter removed (1); `acr` forced to mfa (1); `amr` forced to otp (1, after adding
the `acr=mfa` without otp case); step-up code removed (2).

Not verified: concurrency (the fixture is single-threaded; the real loader and the write must be in one transaction in stage 5, otherwise a check/use race
exists between `load` and the update), (the network zone is decided in stage 8: signed by the BFF, see docs/hardening.md), and a policy-as-data audit export for the auditor.
