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
