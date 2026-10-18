# API as resource server (stage 3)

`apps/api` (NestJS) accepts only access tokens issued by the `casefile` realm for `casefile-api`. Threat IDs refer to
`docs/threat-model.md`. Behaviour marked **(unverified)** was not confirmed by a test.

## Request path

1. `requestContext`: server-generated request id (never taken from the client), JSON log line on finish without query string.
2. helmet (deny-all CSP, nosniff, no-referrer, HSTS), CORS allow-list (`CORS_ORIGINS`, empty by default = no CORS headers), JSON body limit (`BODY_LIMIT`, 64kb).
3. Rate limits (inside `AuthGuard`, from `@acl/netguard`): public routes per socket address, authenticated requests per verified subject (`THROTTLE_LIMIT` per `THROTTLE_WINDOW_MS`).
4. `AuthGuard` (global): `@Public()` routes pass; everything else needs a valid token, then a declared access.
5. `ValidationPipe` (whitelist, `forbidNonWhitelisted`, `forbidUnknownValues`, transform off).
6. `ErrorFilter`: fixed bodies, no stack, no token or claim content.

## Token validation (`auth/token-verifier.ts`, library: jose 6.2.12)

| Check | Rule | Failure reason (log only) |
|-------|------|---------------------------|
| header | decodes; `alg` in {RS256, ES256}; `kid` present | `malformed`, `alg_not_allowed`, `missing_kid` |
| signature | key from the realm JWKS selected by `kid` | `unknown_key`, `bad_signature` |
| `iss` | exactly `KEYCLOAK_ISSUER` | `bad_issuer` |
| `aud` | contains `API_AUDIENCE` (`casefile-api`) | `bad_audience` |
| `exp`, `iat`, `sub`, `iss`, `aud` | required; `exp`/`nbf` with `CLOCK_SKEW_SECONDS` tolerance (default 5, max 60) | `expired`, `not_yet_valid`, `bad_claims` |
| payload `typ` | `Bearer` (ID tokens are `ID`, refresh tokens `Refresh`) | `wrong_token_type` |
| `azp` | in `ALLOWED_AZP` (`casefile-web`) | `bad_azp` |
| claims | strict principal parsing (below) | `bad_claims` |
| JWKS fetch fails | refusal, never an allow | `jwks_unavailable` |

`none` and every `HS*` are refused by omission from the allow-list; HS256 with the public key as secret is tested.
The token is read only from one `Authorization: Bearer` header (checked on the raw header list: two headers are refused,
because Node would silently keep the first). Never from query, body or any other header; `X-User`-style headers are ignored (tested).

### Key rotation and refetch

jose caches the JWKS for `JWKS_MAX_AGE_MS` (10 min) and refetches on an unknown `kid` at most once per
`JWKS_COOLDOWN_MS` (30 s). So: a rotated-in key is accepted after at most one cooldown, clients that hit the gap get 401 and retry;
a flood of random kids produces at most one refetch per cooldown (tested: 60 random kids, <= 2 fetches).
A retired key keeps verifying until the cache is replaced. **There is no revocation check**: a stolen access token is valid
until `exp` (<= 5 min). Session revocation would need introspection or a `sid` deny-list (not planned before stage 8).

## Principal (`auth/principal.ts`)

```
Principal { sub, sessionId?, roles: Role[], clearance: OFFICIAL|CONFIDENTIAL|SECRET, unit, compartments: string[],
            acr, amr: string[], authTime }
```

Parsing is all-or-nothing. A wrong type, missing required claim, unknown clearance, lower-case clearance, odd characters in
`unit`/compartments, or an oversized list yields 401 (`bad_claims`); there is no partial principal. Roles are filtered to the five
application roles (default roles are dropped). Absent `compartments` means none; present but malformed is an error.
`GET /me` echoes the principal and is the only identity route.

## Default deny (`auth/access.ts`, `auth/auth.guard.ts`)

Each route must declare `@Public()`, `@Authenticated()` or `@Policy(...)` (see `docs/policy.md`). An undeclared route returns 401 without a
token and 403 with one, and `routes.test.ts` fails the build if any production route lacks metadata. Only `GET /health` may be public (pinned by a test).

## Errors, logging

401: `WWW-Authenticate: Bearer realm="casefile-api"`, plus `error="invalid_token"` when a credential was presented (RFC 6750). Bodies are
`{statusCode, error}` only; validation errors add field-level messages (names, never values). 429 carries `Retry-After`. Unhandled errors
become a generic 500 and log the error class only. Logs are one JSON object per line through `redact()` (sensitive keys, JWT-shaped strings);
tests assert that no token, signature, cookie or claim value reaches logs or responses.

## Rate limiting

Per-subject throttle (the BFF carries every user over one socket address, so the address is no key for authenticated traffic; public routes use the address) plus a failed-authentication budget (`AUTH_FAIL_LIMIT` per `AUTH_FAIL_WINDOW_MS`, default 10/min) keyed on the socket
address; `X-Forwarded-For` is not trusted (`trust proxy` off, tested). Over the budget even a valid token gets 429 until the window drains.
Limits are in memory and per process (**ponytail**: shared store needed for several instances).

## Configuration (all fail fast on bad values)

`KEYCLOAK_ISSUER` (https required unless loopback), `KEYCLOAK_JWKS_URI`, `API_AUDIENCE`, `ALLOWED_AZP`, `CLOCK_SKEW_SECONDS`,
`JWKS_COOLDOWN_MS`, `JWKS_MAX_AGE_MS`, `CORS_ORIGINS` (exact origins, no `*`), `BODY_LIMIT`, `THROTTLE_LIMIT`, `THROTTLE_WINDOW_MS`,
`AUTH_FAIL_LIMIT`, `AUTH_FAIL_WINDOW_MS`, `API_PORT`. The API binds 127.0.0.1.

## Tests

- `pnpm test` (apps/api, unit tests, locally generated keys and a fake JWKS server): tokens, rotation, claims, routes, HTTP hardening, config.
- `pnpm test:identity` (needs compose): `api-auth.test.ts` boots the API against the live realm and checks every seed user, plus real ID,
  refresh, other-client and master-realm tokens, tampering and log hygiene.
- Mutation check done by hand: removing the algorithm allow-list, `typ`, `kid`, `aud`, default deny, clearance enum, duplicate-header
  check, `forbidNonWhitelisted` or the CORS allow-list each made at least one test fail.

Not verified: behaviour behind a reverse proxy or TLS terminator, HTTP/2, very large JWKS, clock skew against a drifting Keycloak, Keycloak
key rotation performed on the live server (rotation is tested with a fake JWKS endpoint).
