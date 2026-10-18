# Accepted risks

Everything the project knowingly lives with, in one place. A risk is accepted when it is named here with an owner, a reason it is tolerable today, and the step that would remove it. `scripts/check-threat-coverage.mjs` (in `pnpm lint`) requires each entry to have all three, and requires every threat in `docs/threat-model.md` to have an existing test or to point at an entry here. Owner "platform" means whoever operates a deployment, "app" means the development team.

Status: **accepted** means it was decided, **open** means nobody has decided to fix or accept it yet and it should not be read as a decision.

## AR-01 No TLS between internal components
**Threats:** T-34. **Status:** accepted for the prod-like stack, **open** for a real deployment.
**Owner:** platform.
**Rationale:** the prod-like stack carries proxy to BFF, BFF to API, Keycloak behind the proxy and Postgres traffic as plain http/TCP on networks that are `internal: true` (no way out, nothing outside can join). Browser to proxy is TLS and tested. The BFF to API call still carries a bearer token.
**Upgrade path:** mutual TLS between proxy, BFF, API and Keycloak (Caddy and Node both support it), `sslmode=verify-full` to Postgres; then remove `API_INTERNAL_HTTP`.

## AR-02 An access token outlives logout by up to its lifetime
**Threats:** T-06, T-21. **Status:** accepted.
**Owner:** app.
**Rationale:** the API validates JWTs offline. Measured by attack A-08: right after logout the refresh token is dead and the access token (300 s lifetime) is still accepted with its remaining validity, never beyond its `exp`. Shortening the lifetime costs more refreshes.
**Upgrade path:** introspection or a token-id deny list in the API for SECRET actions; or a shorter lifetime (60 s) with the BFF's refresh already in place.

## AR-03 No step-up freshness
**Threats:** T-17. **Status:** accepted.
**Owner:** app.
**Rationale:** SECRET access needs `acr=mfa`, but a session that stepped up once keeps SECRET access until it ends (idle 30 min, absolute 8 h). There is no `auth_time` or `max_age` check (attack A-61 documents it).
**Upgrade path:** require `auth_time` within N minutes for SECRET reads (the policy already receives the claims) and make the API ask for a fresh step-up (RFC 9470 `max_age`).

## AR-04 Rate-limit counters are per process, one address is one bucket
**Threats:** T-27, T-45. **Status:** accepted.
**Owner:** platform.
**Rationale:** counters live in the BFF and API processes; several replicas multiply every limit. Behind one NAT or proxy address all users share the login budget, so one noisy client can lock others out of signing in for a minute (the per-user limits behind the login are not shared). The table is bounded (10 000 keys, oldest evicted): more distinct addresses than that inside one window can reset counters.
**Upgrade path:** a shared store (Redis) with the same interface; per-account throttling at the identity provider.

## AR-05 A compromised BFF can claim any network zone for its users
**Threats:** T-44. **Status:** accepted.
**Owner:** app.
**Rationale:** the zone is decided and signed by the BFF; the API trusts the signature. An attacker who owns the BFF process owns the signing key and the users' tokens anyway.
**Upgrade path:** the proxy signs the client address itself and the API verifies it directly (two signers, no trust in the BFF for the zone).

## AR-06 No storage quota for attachments
**Threats:** T-27, T-28. **Status:** open.
**Owner:** app.
**Rationale:** each file is capped at 5 MB, uploads are rate-limited and only drafts accept them, but there is no per-user or total quota: a patient insider can fill the volume.
**Upgrade path:** per-case and per-user byte quotas in the upload transaction, and a volume alert.

## AR-07 Next.js answers a TRACE with 500 when reached directly
**Threats:** T-38. **Status:** accepted.
**Owner:** app.
**Rationale:** reaching the BFF without the proxy needs a foothold on the internal network; the proxy answers 405 for every method the application does not use (attack A-76). The 500 carries no detail.
**Upgrade path:** a custom server in front of Next.js, or the next Next.js release if it fixes the unsupported-method error.

## AR-08 The audit chain is not anchored outside the database
**Threats:** T-26, T-41. **Status:** accepted.
**Owner:** platform.
**Rationale:** someone with database superuser and the HMAC key can rewrite history and recompute the chain; tail truncation is only detected against a checkpoint exported off the box (`docs/audit.md`).
**Upgrade path:** ship checkpoints to a write-once store or a second system on a schedule.

## AR-09 Break-glass has no second approver and no alert consumer
**Threats:** T-25. **Status:** accepted.
**Owner:** app and platform.
**Rationale:** any unit admin may break glass on any file up to their clearance with a justification; every use is a row with an alert marker (attack A-60), but nothing watches the marker and nobody has to approve.
**Upgrade path:** an alert consumer (mail or chat) on `alert: true` rows and an optional four-eyes approval for high-volume use.

## AR-10 The PDF check is a marker scan, not a sanitiser; ClamAV detection is only shown for EICAR
**Threats:** T-28. **Status:** accepted.
**Owner:** app.
**Rationale:** active PDF content in object streams can hide from the scan; downloads are attachments with a sandbox CSP and the scanner hook is the second defence. The real scanner is exercised with the EICAR test file only.
**Upgrade path:** convert or flatten PDFs on upload, a second scanner, known-malware corpora in a nightly test.

## AR-11 Attachments stuck in `pending` are never re-scanned
**Threats:** T-47. **Status:** open.
**Owner:** app.
**Rationale:** when the scanner is down an upload stays `pending` (never served). There is no job that retries.
**Upgrade path:** a re-scan CLI over `pending` rows with a bounded retry and an alert.

## AR-12 The denial-reason function is a narrow existence oracle for a compromised API role
**Threats:** T-43. **Status:** accepted (decided in stage 8).
**Owner:** app.
**Rationale:** for a compromised API role `audit_read_denial_reason` tells whether an id exists and why it is hidden (clearance, compartment, role); ids are random UUIDs, the answer is a code, never data.
**Upgrade path:** log the true reason from the database trigger side instead, with no function the API can call.

## AR-13 Keycloak's brute-force lockout can be used to lock a user out
**Threats:** T-22. **Status:** accepted.
**Owner:** platform.
**Rationale:** after five failures the account waits (up to 15 minutes); an attacker who knows a username can keep it waiting (attack A-73). The alternative, no lockout, is worse.
**Upgrade path:** lockout per user and address, CAPTCHA or proof-of-work on the login form, alerts on lockouts.

## AR-14 Account recovery, user notification, breached-password check, MFA for the Keycloak admin console
**Threats:** T-18, T-19. **Status:** open.
**Owner:** platform.
**Rationale:** these identity-provider features are off or unconfigured (`docs/asvs.md`, "Not met"); the lab has no real users.
**Upgrade path:** configure them in the realm and add realm-read-back tests.

## AR-15 Dependencies and base images are trusted at build time
**Threats:** T-32. **Status:** accepted.
**Owner:** platform.
**Rationale:** the Caddy and ClamAV images are built here from the Go module proxy and Alpine mirrors; digests and lockfile hashes pin what is fetched, not whether upstream was already compromised. Trivy, OSV, dependency review and Scorecard reduce, not remove, the risk.
**Upgrade path:** signed provenance (SLSA, cosign) for the images and a reproducible-build check.
