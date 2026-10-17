# Identity (stage 2)

Keycloak 26.8.1, realm `casefile`, defined as code in `infra/keycloak/realm-casefile.json` and imported read-only at
compose start (`--import-realm`). Import runs only when the realm does not exist (`IGNORE_EXISTING`): after editing the
file run `docker compose down -v` to re-import. JSON has no comments, so rationale lives here.

Threat IDs refer to `docs/threat-model.md`. Behaviour marked **(unverified)** was not confirmed by a test.

## Realm settings

| Setting | Value | Threat |
|---------|-------|--------|
| Access token lifespan | 300 s | T-04, T-21 |
| SSO idle / max | 30 min / 10 h | T-21 |
| Refresh | revoke on use, `refreshTokenMaxReuse` 0 (rotation, reuse revokes the chain) | T-21 |
| Brute force | on, 5 failures, wait increment 60 s up to 900 s | T-22 |
| Password policy | length 14, not username, not email, history 3 | T-22 |
| Registration, reset by email, remember-me, login by email | off | T-19 |
| `sslRequired` | `external`: HTTP only accepted from private addresses. **Dev exception**: compose runs `start-dev` on HTTP at 127.0.0.1. Production must be `all` plus TLS | T-34 |
| Issuer | `KC_HOSTNAME=http://127.0.0.1:8080` fixes the public URL, so `iss` is stable and other Host headers are not honoured | T-09 |
| Events | login and admin events stored 7 days | T-24 |
| Browser headers | `X-Frame-Options: DENY`, `frame-ancestors 'none'`, nosniff, no-referrer | T-07 |
| Disabled features | `device-flow`, `ciba`, `impersonation`; unused built-in clients `admin-cli`, `security-admin-console` disabled; no offline tokens (default role has no `offline_access`) | T-20 |
| Network exposure | ports 8080 and 9000 bound to 127.0.0.1 in compose | T-18 |

Default role grants only account self-service (`view-profile`, `manage-account`).

## Roles

Realm roles `analyst`, `reviewer`, `unit-admin`, `auditor`, `platform-admin`. No composite roles: each user carries exactly
one application role, which keeps the RBAC layer auditable (composites would hide privilege in the role graph).
They appear in `realm_access.roles` (the web client is scope-limited to these five, so default roles do not leak into the token).

## Clients

| Client | Type | Notes |
|--------|------|-------|
| `casefile-web` | confidential, standard flow only | PKCE `S256` required; one exact redirect URI `http://127.0.0.1:3000/api/auth/callback` (**stage 6 may change the path**); no implicit, direct grant, service account; no web origins (token exchange is server side) |
| `casefile-api` | bearer-only | no login flows; only exists so `aud` can name it |
| built-ins | `account`, `account-console`, `broker`, `realm-management` | `account-console` stays enabled so users can manage password and TOTP; its Account API cannot edit attributes (tested) |

Client secret and user passwords are `${ENV}` placeholders substituted at import from `.env` (dev-only values).

## Claims in the access token

Mapped on `casefile-web` and present in the access token only (not ID token, not userinfo):

| Claim | Source | Notes |
|-------|--------|-------|
| `realm_access.roles` | realm roles | RBAC input |
| `clearance` | user attribute, `OFFICIAL` / `CONFIDENTIAL` / `SECRET` | ABAC input |
| `unit` | user attribute | ABAC input |
| `compartments` | multivalued user attribute, absent when empty | ABAC input |
| `aud` | audience mapper, `casefile-api` | API must check it (stage 3) |
| `acr` | `pwd` or `mfa` | see below |
| `amr` | `["pwd"]` or `["pwd","otp"]` | what actually happened |
| `iss`, `exp`, `iat`, `azp`, `sub`, `sid` | standard | no email, name or username on purpose |

Attributes are declared in the realm user profile with `edit: admin` only. Tested: a user logged in to the account console
cannot change any of them through the Account API, and the test fails when the permission is relaxed (checked by mutation).

## Authentication flow `browser-casefile`

1. Cookie (SSO), or username and password.
2. If `clearance == SECRET`: TOTP is required. This subflow has **no level-of-authentication condition**, so a client
   cannot skip it by sending `acr_values=pwd` (tested). A SECRET user without TOTP is forced to enrol.
3. LoA bookkeeping: non-SECRET users record level 1 (`pwd`). The level 2 subflow records `mfa` for SECRET users and asks
   non-SECRET users for TOTP when a client sends `acr_values=mfa` (step-up).

`acr.loa.map` is `{"pwd": 1, "mfa": 2}`. Authenticator references (`default.reference.value`) feed `amr`.

Observed results (tests): non-SECRET: `acr=pwd`, `amr=[pwd]`. SECRET with TOTP: `acr=mfa`, `amr=[pwd,otp]`.
SECRET with `acr_values=pwd`: TOTP still demanded; `acr` then reports the lower level (**the exact claim value in this
downgrade case is not asserted**, only that TOTP is demanded and `amr` contains `otp`).
Replay: Keycloak rejects a TOTP step already used by that user, which the test helper accounts for.

**How the API should use it (stage 3/4):** treat `amr` containing `otp` AND `acr == "mfa"` as MFA for `SECRET` reads;
`acr` alone is a LoA bookkeeping value. Step-up for other actions: redirect the user to authorize again with `acr_values=mfa`.
Keycloak constraint found: each LoA level may appear only once per flow (a duplicate made the discovery endpoint return 500).

## Verification

`pnpm test:identity` (needs `docker compose up -d --wait` and `.env`): 39 tests that log in through the real HTML forms
with PKCE and TOTP and assert claims, MFA, redirect and PKCE rejection, code single use, refresh rotation and reuse,
admin-only attributes, brute-force lockout, and the realm baseline read back from the admin API. Runs in CI job `identity`.

Not verified: behaviour on browsers (no UI yet), clock skew handling in the API (stage 3), production TLS and hostname setup,
behaviour of the Keycloak admin console in the master realm beyond being bound to loopback.
