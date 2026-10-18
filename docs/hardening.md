# Hardening (stage 8)

What was added to make the system harder to abuse, how each piece fails, and what is not verified. Threat IDs refer to `docs/threat-model.md`.

## 1. Rate limits and abuse controls (T-22, T-27)

`packages/netguard` holds the shared pieces: `RateLimiter` (fixed window per key, hard bound on the number of keys), `clientIp` / `parseNetworks` (trusted proxy chain), `signZone` / `verifyZone`.

| Where | What is limited | Key | Default |
|-------|-----------------|-----|---------|
| BFF `/api/auth/login`, `/callback`, `/logout` | requests | client address | `RATE_AUTH_PER_MINUTE` 20 |
| BFF `/bff/*`, `/actions/*`, `/api/auth/session` | requests behind a session | user (session's `sub`) | `RATE_USER_PER_MINUTE` 300 |
| BFF, all of the above | backstop | client address | `RATE_IP_PER_MINUTE` 600 |
| BFF refresh grant | token endpoint calls | user | 10 per minute, over budget keeps the old tokens |
| API authenticated routes | requests | verified `sub` | `THROTTLE_LIMIT` per `THROTTLE_WINDOW_MS` |
| API public routes (`/health`) | requests | socket address | same |
| API failed authentication | failures | socket address | `AUTH_FAIL_LIMIT` per `AUTH_FAIL_WINDOW_MS` |

- **Why per user at the API.** The BFF is the only caller, so every user shares its socket address. The stage 3 per-address throttle would have throttled all users together; it is replaced by a per-subject limit applied after the token is verified.
- **Bounded memory.** `RateLimiter` holds at most 10 000 keys. When full, expired keys go first, then the oldest key. A caller who can present more distinct keys than that inside one window can reset other keys' counters. Behind a trusted proxy that needs that many distinct client addresses, so the ceiling is accepted and stated here.
- **Per process.** Counters live in the process. Several instances multiply every limit by their number. A shared store (Redis) is the upgrade; not built.
- **Keycloak interplay.** Realm brute-force detection (`failureFactor` 5, wait increments up to 15 minutes) locks the account per user. The BFF limit sits in front of it per client address and caps how many login redirects and callbacks one address can start; it cannot lock a user out (the key is the address, not the account), so an attacker cannot use it to deny service to a named user. The account lockout can still be used to lock a user out; that is a property of Keycloak's brute-force detection (documented trade-off, `docs/identity.md`).
- **Response.** `429`, `{"error":"rate_limited"}`, `Retry-After`. No detail about which limit.

### Trusted proxy contract (BFF)

Next.js route handlers cannot see the socket, so the BFF cannot check that a forwarded address came from a proxy by looking at the peer. The contract is instead a shared secret:

1. The reverse proxy overwrites `x-acl-proxy-secret` (value `TRUSTED_PROXY_SECRET`, at least 32 bytes) and `x-acl-client-ip` (its own view of the client address) on every request and strips any client-supplied copy.
2. The BFF believes `x-acl-client-ip` only when the secret matches (constant-time compare) and the value is a plain IP address.
3. Without `TRUSTED_PROXY_SECRET`, or with a wrong secret, every forwarded header (`x-forwarded-for`, `x-real-ip`, `forwarded`, `x-acl-client-ip`) is ignored and all such clients share the bucket `direct`.

`direct` fails towards stricter limits and the unmanaged zone, never towards trust. In development all clients are `direct`: one noisy browser can use the shared auth budget of the dev machine; the dev limits are therefore generous only where tests need them.
The API has no proxy contract: `trust proxy` stays off, its only caller is the BFF, and `X-Forwarded-For` is never read (tested). `clientIp` in `packages/netguard` implements the right-to-left walk over a forwarded chain for deployments that terminate at a proxy the API can see; it is unit-tested but not used by the API today.

## 2. Network zone (T-44, T-45)

The policy needs "managed" or "unmanaged" for exports. Before stage 8 the API compared the socket address with `MANAGED_ADDRESSES`; behind the BFF that is the BFF's own address, so the check meant nothing. Now:

1. The BFF derives the zone from the proxy-vouched client address and `MANAGED_CIDRS` (IPs and CIDRs). No vouched address, or an address outside the list, is `unmanaged`.
2. For each upstream call the BFF sends `x-acl-zone: v1.<keyId>.<unix seconds>.<zone>.<mac>`, an HMAC-SHA256 over `acl-zone/v1`, timestamp, zone and the **user's `sub`**, with a key from `ZONE_SIGNING_KEYS` (ring `id:base64`, first key signs, all verify, at least 32 bytes each).
3. The API accepts the zone only when the header verifies for the subject of the verified access token and is at most 30 seconds old (5 seconds of future skew). Anything else, including no header, no key ring configured, a header for another user, a forged or stale one, is `unmanaged`, and a rejected header is logged (`zone_header_rejected`, no header value).
4. The end user never sees the key. A browser can send any `x-acl-zone`, but the BFF builds upstream headers from scratch.

Tested: `packages/netguard` (forgery, wrong subject, flipped zone, stale, future, wrong key, malformed, rotation), `apps/api/src/policy.test.ts` (plain headers, forged MAC, other subject, other key, stale), `apps/web/src/server/client.test.ts` and `tests/bff/src/hardening-bff.test.ts` (live BFF: forged proxy headers, wrong secret, header copied to another user, browser-supplied zone), `tests/api-db` and `tests/identity` export flows with a real token and a signed header.

**Not verified in dev:** a real reverse proxy that strips and sets the two headers (the prod-like compose in section 5 does it, tested only to the extent stated there); the deployment's own network topology (that nothing but the proxy can reach the BFF port); a compromised BFF can sign any zone for any user it holds a token for, which is inherent in trusting the BFF.

Key rotation: add the new key first in both the BFF and the API rings (`new:...,old:...` on the verifier, `new` first on the signer), then drop `old` after 30 seconds plus a deploy cycle.

## 3. Secrets and configuration (T-23, T-29)

One validated configuration module per app (`apps/api/src/config.ts`, `apps/web/src/server/config.ts`). A bad value stops the start; nothing falls back to a weaker default.

**Profile.** `ACL_ENV=production` switches on the production rules; a value other than `production` or `development` (a typo such as `prod`) is an error. `NODE_ENV` is not used as the switch: `next start` sets `NODE_ENV=production` for every deployment, including the CI tests that run on development secrets. Decision for the orchestrator: if `NODE_ENV=production` should also imply the profile, the CI test servers need real secrets.

In production the API and the BFF refuse to start when:

- a secret is missing (API: database URL, audit and zone key rings; BFF: client secret, database URL, session, audit and zone key rings, proxy secret);
- a key in any ring is shorter than 32 bytes, is a repeated byte or has fewer than 12 distinct bytes, decodes to text containing a development marker, or has an id starting with `dev-`;
- a secret string is shorter than 32 bytes, has fewer than 10 distinct characters or contains a development marker (`dev-only`, `changeme`, `example`, `password`);
- a database password is shorter than 16 characters or contains a development marker;
- the issuer, the origin or the API URL is plain http (loopback is not an exception in production; the API URL may be plain http on a private network only with `API_INTERNAL_HTTP=true`, an accepted trade-off because TLS between the BFF and the API is not built), or cookies are not `Secure`.

Error messages name the variable and the rule, never the value (tested with canary values in `config.test.ts` of both apps).

**Secrets as files.** `NAME_FILE=/path` replaces `NAME` for the listed secrets (container secrets keep values out of the process environment and `docker inspect`). Both forms at once, an unreadable file and an empty file are errors.

**No secrets in logs.** Structured logs carry ids, reasons and codes only. `tests/bff/src/hardening-bff.test.ts` runs a live BFF and API through sign-in, a CSRF refusal, a failed callback, forged proxy headers and rate limiting, then scans every log line for every configured secret value (base64 and decoded forms), the database passwords, the proxy secret and the session cookie.

**What to inject, from where (stance, not a vault).** Production secrets come from the platform's secret store (Docker/Kubernetes secrets or a sealed file store such as SOPS with age keys), mounted as files and read with `NAME_FILE`. Generate keys with `openssl rand -base64 32`, passwords with at least 24 random characters. Nothing goes into the image, the compose file, the repository or CI logs. Least privilege per component:

| Secret | API | BFF | Verifier CLI | Proxy |
|--------|-----|-----|--------------|-------|
| `DATABASE_URL` (casefile_app) | yes | | | |
| `WEB_DATABASE_URL` (casefile_web) | | yes | | |
| `AUDIT_DATABASE_URL` (casefile_audit) | | | yes | |
| `AUDIT_HMAC_KEYS` | yes | yes | yes | |
| `ZONE_SIGNING_KEYS` | yes | yes | | |
| `SESSION_ENCRYPTION_KEYS` | | yes | | |
| `CASEFILE_WEB_SECRET` (OIDC client secret) | | yes | | |
| `TRUSTED_PROXY_SECRET` | | yes | | yes |

The migrator and admin database URLs are used by deployment jobs only and never mounted into a running service.

### Rotation procedures

| Secret | Procedure | Verified |
|--------|-----------|----------|
| Session key ring (`SESSION_ENCRYPTION_KEYS`) | Put the new key first, keep the old ones: new sessions and every token refresh seal with the new key, all keys still open old rows. Remove the old key after `SESSION_ABSOLUTE_SECONDS` (default 8 h). Removing it earlier makes the sessions sealed with it unreadable: those users sign in again. The pre-auth cookie is sealed with the same ring (minutes of lifetime). | unit test (`crypto.test.ts`), procedure not exercised live |
| Cookie signing | There is none: the session cookie is a random 256-bit id stored hashed, the pre-auth cookie is AES-GCM under the session ring. Nothing to rotate beyond the session ring. | by construction |
| Audit HMAC ring (`AUDIT_HMAC_KEYS`) | Put the new key first on the API and the BFF, keep every old key for as long as rows signed with it exist: the verifier needs them (`docs/audit.md`). Never delete a key id that is on a row. Archive retired keys with the audit data. | unit and CLI tests |
| Zone ring (`ZONE_SIGNING_KEYS`) | Add the new key to the API ring first (verifies both), then make it first in the BFF ring, then drop the old key from the API after 30 seconds plus a deploy cycle. | unit test (`netguard`) |
| Proxy secret | Change it on the proxy and the BFF together. Until both are changed, requests count as `direct` (shared rate-limit bucket, unmanaged zone): stricter, not weaker. | `hardening-bff.test.ts` (wrong secret) |
| Database passwords | `ALTER ROLE ... PASSWORD`, update the secret, restart the service (pools reconnect). | not exercised |
| OIDC client secret | Set a new secret on the Keycloak client, update `CASEFILE_WEB_SECRET`, restart the BFF. Keycloak's secret-rotation policy allows an overlap window. | **unverified** (Keycloak behaviour not tested here) |
