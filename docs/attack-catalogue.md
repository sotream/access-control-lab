# Attack catalogue (stage 9)

A black-box "red team" suite: it behaves like an attacker who only has network access to the prod-like stack through its reverse proxy, plus the eight seed users as legitimate low-privilege accounts. It does not re-test internals (the unit, database and BFF suites do that): every attack goes in from outside, end to end, against the production images, with a real Keycloak, a real scanner and the real proxy.

- **Where:** `tests/attack` (vitest, one stack started once). Run it with `pnpm test:attack` (docker and openssl needed; first run builds the images). `ATTACK_KEEP=1` leaves the stack up, `ATTACK_NO_UP=1` reuses a running one.
- **Threat model link:** every row below names the threat IDs it exercises (`docs/threat-model.md`); `scripts/check-threat-coverage.mjs` (in `pnpm lint`) checks that each attack ID in a test file is in this table, that each table row points at a test file that exists and contains the ID, and that every threat has an existing test or an accepted risk (`docs/accepted-risks.md`).
- **Model of the attacker:** outside the proxy only the BFF and the identity provider's realm are reachable. For the attacks that need the API itself (tokens, headers, fuzzing) the test stack adds a test-only route `/__api` that models an attacker with a foothold on the internal network (a compromised container, an SSRF gadget): the API must defend itself without the BFF in front of it. Two more test-only routes: `/__echo` (shows what the BFF would receive) and `x-attack-instance: strict` (selects the BFF and API instances with the production rate limits; the default instances have them lifted because the suite signs in dozens of times from one address).
- **Fuzzing:** `fuzz.test.ts` uses fast-check with a fixed seed in CI (20261018, printed) and 60 runs per property; the nightly workflow runs a random seed with 300 runs and prints it for reproduction (`FUZZ_SEED=<n>`).
- **Dynamic scan:** `zap.test.ts` (A-97, `ATTACK_ZAP=1`) runs OWASP ZAP's baseline (image pinned by digest) through the proxy with a session cookie; Medium and High alerts fail unless `.zap-allow.json` lists them with a reason and an expiry (checked by `pnpm lint`). Run it on a fresh stack: the hostile titles other attacks store would otherwise be flagged as "SQL source disclosure" (they are the suite's own test data, escaped on the page).
- **Slow mode:** `ATTACK_SLOW=1` adds the check that an access token is refused after its own expiry (a five minute wait).

## Measured results

| What | Result |
|------|--------|
| A-08 token after logout | the refresh token is dead at once (400); the access token (lifetime 300 s) is still accepted by the API right after logout, with its full remaining validity, and never beyond its own `exp` (slow mode). This is the documented window of a stateless token: at most 300 s (AR-02) |
| A-75 dribbling connections | 50 half-open connections: a normal request still answers in a few milliseconds |
| A-82 hidden versus missing | median response time 7 ms for both, over 40 interleaved requests each |

## Attacks

| ID | Goal | Preconditions | How it is scripted | Expected defence | Threats | Test file |
|----|------|---------------|--------------------|------------------|---------|-----------|
| A-01 | Make the API accept a token the realm did not issue or one whose claims were changed | a valid access token (any user) | tamper sub, roles, clearance, compartments, unit, acr, exp, aud, iss keeping the old signature | every change is a 401 with a generic body | T-08 | `tests/attack/src/jwt-api.test.ts` |
| A-02 | Make the API accept an unsigned token with admin claims | a valid token to copy claims from | alg none in every spelling, empty and non-empty signature, missing third segment | 401 | T-08 | `tests/attack/src/jwt-api.test.ts` |
| A-03 | Algorithm confusion: HS256 with the realm's public key, RS256 with the attacker's key | the realm's public JWKS | HS256/384/512 keyed with PEM, JWK JSON and modulus; RS256 with an own key under the realm's kid, an own kid, embedded jwk, jku, x5u, x5c | 401 | T-08, T-10 | `tests/attack/src/jwt-api.test.ts` |
| A-04 | Crash or confuse the verifier with header and structure tricks | a valid token | kid with path, injection and control characters, 5000 characters; crit, b64 false; extra, empty, non-base64 segments; array or null claims; 9 KB and 20 KB tokens | 401 (431 for an oversized header block), never a 5xx, no stack | T-08, T-10 | `tests/attack/src/jwt-api.test.ts` |
| A-05 | Use a real token that was not meant for the API | a login as a seed user | ID token and refresh token as bearer; an access token of another client (account-console); a token of the master realm | 401 | T-09 | `tests/attack/src/jwt-api.test.ts` |
| A-06 | Present a token in a way the API does not take | a valid token | two Authorization headers, token in query, cookie, form body, Basic/Token schemes; identity headers (x-user, x-sub, x-roles) next to a valid token | none authenticates; the identity stays the token's | T-09, T-12 | `tests/attack/src/jwt-api.test.ts` |
| A-07 | Claim the managed network zone to pass the export rule | a valid token, access to the API | forged x-acl-zone header on a valid token | export refused | T-44 | `tests/attack/src/jwt-api.test.ts` |
| A-08 | Keep using a token after logout | a login and a logout | end-session with the id token hint, then refresh and call the API with the old access token; the window is measured | refresh token dead; the access token is accepted until its own exp (measured: 300 s lifetime, accepted right after logout), never beyond; slow mode (ATTACK_SLOW=1) checks the refusal after exp | T-06, T-21 | `tests/attack/src/jwt-api.test.ts` |
| A-09 | Abuse the identity provider's token endpoint | an authorization code | reuse a code, exchange without or with a wrong verifier, without the client secret, direct password grant | all refused | T-02 | `tests/attack/src/jwt-api.test.ts` |
| A-10 | Replay a stolen refresh token | a refresh token | use it twice | the second use fails and the chain is revoked: the legitimate successor dies too | T-21, T-39 | `tests/attack/src/session-bff.test.ts` |
| A-11 | Session fixation | none | plant a session cookie before the victim signs in | a new id is issued, the planted value opens nothing | T-05 | `tests/attack/src/session-bff.test.ts` |
| A-12 | Forge or tamper with the session cookie | a valid cookie to copy | altered, truncated, extended, empty, foreign, duplicated cookies; other cookie names; attacker-first duplicates | every variant is anonymous; cookie is host-only, HttpOnly, Secure, SameSite=Lax | T-04, T-05, T-40 | `tests/attack/src/session-bff.test.ts` |
| A-13 | Keep a session alive after logout, or log a victim out | a victim session | GET and forged POST logout; reuse of a copied cookie after logout | GET 405, forged POST 403, session survives; after a real logout the copied cookie is dead | T-05, T-06 | `tests/attack/src/session-bff.test.ts` |
| A-14 | Cross-site request forgery | a victim session | eight Origin and fetch-metadata variants and token variants on the create form, the JSON proxy and logout; GET as state change; CORS preflights | every variant refused, nothing created, session survives, no CORS grant | T-05, T-12 | `tests/attack/src/session-bff.test.ts` |
| A-15 | Open redirect after login, at the identity provider, after logout | none | fourteen hostile returnTo values; foreign redirect_uri and post-logout URI variants | the browser stays on a path of this site; the provider refuses foreign URIs | T-03 | `tests/attack/src/session-bff.test.ts` |
| A-16 | Manipulate the login callback | a login in progress | replay a callback, swap state, drop state or code, foreign code, error and wrong issuer parameters, login CSRF without the pre-auth cookie, tampered pre-auth cookie | no session in any case; S256, state, nonce and a fixed redirect URI in the authorization request | T-02 | `tests/attack/src/session-bff.test.ts` |
| A-17 | Turn the BFF proxy into an open proxy or inject into responses | a session | traversal, encoded slashes, absolute URLs, //host, null bytes, CRLF in paths; unusual methods | nothing off the allow-list reaches the API; no header splitting | T-38 | `tests/attack/src/session-bff.test.ts` |
| A-20 | Read what one is not entitled to (BOLA, horizontal and vertical) | all eight seed users | every user against every class of case file (classification, compartment, unit) | 200 exactly for the entitled, the identical 404 for everyone else | T-15 | `tests/attack/src/authz.test.ts` |
| A-21 | Learn of hidden files from a list | all seed users | the list of each user compared with the files that user can open | identical sets; roles without read get 403 | T-15 | `tests/attack/src/authz.test.ts` |
| A-22 | Perform actions the role lacks | seed users | approve as analyst, create and edit as reviewer, any write as auditor and platform admin, cross-unit writes | 403 or the hidden-resource 404 | T-11, T-15 | `tests/attack/src/authz.test.ts` |
| A-23 | Approve one's own work, skip the status machine | a unit admin and a reviewer | approve a draft, approve own submission, edit a frozen file, approve twice | each refused; another person may approve once | T-16 | `tests/attack/src/authz.test.ts` |
| A-24 | Mass assignment and prototype pollution in create and update | an analyst or unit admin | extra author_id, unit, status, roles, version, id, __proto__, constructor; classification change on update; create above clearance | 400 (or 403 for the clearance); nothing changed | T-13 | `tests/attack/src/authz.test.ts` |
| A-25 | Read the audit trail or export it without being an auditor | all seed users | every audit endpoint and page for every user; the auditor against case files | only the auditor reads the trail, and cannot read case files | T-24, T-26 | `tests/attack/src/authz.test.ts` |
| A-26 | Export from outside the managed zone | an analyst | export an approved file with forged zone, client address and proxy-secret headers | 403 | T-44 | `tests/attack/src/authz.test.ts` |
| A-30 | SQL injection, first and second order | a unit admin, an auditor | twelve injection strings in titles, bodies, compartments, ids, paths, audit filters, cursors, limits | stored as data or refused, no SQL error text, schema and grants intact | T-14 | `tests/attack/src/injection-xss.test.ts` |
| A-31 | Stored XSS in every rendered field | a unit admin | thirteen payloads in titles and bodies, shown on the list, detail, edit and break-glass pages | escaped, no event-handler attribute, every script carries the response's nonce; CSP strict on every response kind | T-07 | `tests/attack/src/injection-xss.test.ts` |
| A-32 | Reflected XSS and injection | a session | payloads in the path, ?m=, ?e=, ?returnTo=, and in User-Agent, Referer, X-Forwarded-Host, Accept-Language | never reflected as markup; message codes come from a fixed set | T-07 | `tests/attack/src/injection-xss.test.ts` |
| A-33 | Response splitting | none | CR, LF and NUL in values that end up in headers | no injected header or cookie | T-07 | `tests/attack/src/injection-xss.test.ts` |
| A-34 | Stored XSS via file names, justifications and the auditor's pages | an analyst, a unit admin, an auditor | script payloads as file names and break-glass justifications, then the case page, audit pages, CSV export | names and justifications defanged; pages inert; no formula cell | T-07, T-42 | `tests/attack/src/injection-xss.test.ts` |
| A-40 | Upload hostile content | an analyst with a draft | EICAR (also labelled as PNG), PNG+HTML polyglot, HTML as image, SVG, ZIP, gzip bomb, executable, 400-megapixel PNG, PDF with JavaScript, type disagreeing with bytes, empty, bidi text, oversize | every one refused with the fixed message and no clean row; oversize refused before the body is read | T-28 | `tests/attack/src/uploads.test.ts` |
| A-41 | Get the scanner's verdict ignored | an analyst | upload the EICAR test file, then list and download | stored as quarantined only, no download link, download refused, no storage key exposed | T-28, T-47 | `tests/attack/src/uploads.test.ts` |
| A-42 | Path traversal and name tricks in file names | an analyst | eleven names: traversal, double extension, RTL override, NUL, 400 characters, device names, markup | stored name is safe with the extension of the real type; nothing escapes the store | T-29 | `tests/attack/src/uploads.test.ts` |
| A-43 | Run an uploaded file in the application's origin | a clean attachment | inspect download headers | attachment, nosniff, sandbox CSP, no-store, CORP same-origin, allow-listed type | T-31 | `tests/attack/src/uploads.test.ts` |
| A-44 | IDOR on attachments | seven seed users | real attachment ids under other parents, ids of files one cannot read, malformed ids, SECRET attachments; uploads to files one may not update | 404 or refusal; nothing stored | T-29, T-15 | `tests/attack/src/uploads.test.ts` |
| A-45 | Use the generic proxy for uploads or downloads | a session | raw bytes through /bff, attachment bytes under /bff | 404 | T-38 | `tests/attack/src/uploads.test.ts` |
| A-46 | Races around uploads | an analyst | twenty parallel uploads of one name; uploads racing a submit | every success is one clean row and one file, no orphan; nothing added after the file stopped being a draft | T-35, T-28 | `tests/attack/src/uploads.test.ts` |
| A-50 | Rewrite, delete or disable the audit trail with a stolen database credential | the API, BFF or verifier credential, or a superuser | 23 statements: UPDATE, DELETE, TRUNCATE, ALTER, DROP, GRANT, trigger and policy changes, session_replication_role, COPY PROGRAM, forged INSERT | refused or a no-op, for each of the three roles; superuser stopped by triggers | T-26, T-41 | `tests/attack/src/audit-tamper.test.ts` |
| A-51 | Change or hide the trail through the application | an auditor, a unit admin | POST, PUT, PATCH, DELETE on every audit route through the BFF and on the API; export and CSV | no write route exists; an export is itself a row; CSV carries no formula; failed attempts are rows | T-24, T-26, T-42 | `tests/attack/src/audit-tamper.test.ts` |
| A-52 | Leave the chain broken | after all of the above | run the verifier CLI with the audit role and key ring | exit 0, no gap, fork, wrong key or altered row | T-26, T-41 | `tests/attack/src/audit-tamper.test.ts` |
| A-53 | Cross database boundaries | the Keycloak or application credential | connect the Keycloak role to the application database and the application roles to Keycloak's | refused | T-23 | `tests/attack/src/audit-tamper.test.ts` |
| A-60 | Abuse break-glass | a unit admin and everyone else | empty, blank, control-only, 100 000 character, markup justifications; non-eligible roles; SECRET floor; header through the proxy; repeated use | blank refused, long cut to 500, sanitised, SECRET stays hidden, header never forwarded, every use a row with an alert | T-25 | `tests/attack/src/breakglass-stepup.test.ts` |
| A-61 | Bypass or downgrade step-up | a SECRET user, an OFFICIAL user | ask Keycloak for acr pwd; BFF login with acr=pwd; tamper acr and clearance claims; reuse a session for the whole day | a weaker token gets a step-up challenge on SECRET data; the BFF never asks for the weaker level; tampered claims fail; no step-up freshness check (accepted risk AR-03) | T-17 | `tests/attack/src/breakglass-stepup.test.ts` |
| A-70 | Rotate the apparent client address to avoid the login limit | none | forty login starts with forged x-forwarded-for, x-real-ip, x-acl-client-ip, Forwarded, proxy secret | the same real address is cut off after the budget, with Retry-After | T-22, T-45 | `tests/attack/src/ratelimit-proxy.test.ts` |
| A-71 | Starve other users or hide in a shared bucket | two sessions | 340 requests as one user on the strict instance | that user is limited, the other still served | T-27, T-45 | `tests/attack/src/ratelimit-proxy.test.ts` |
| A-72 | Hammer the API with bad tokens | none | fourteen bad tokens, then a valid one, then wait out the window | locked out after ten, valid token included, then recovered | T-27 | `tests/attack/src/ratelimit-proxy.test.ts` |
| A-73 | Guess a password | a username | seven wrong passwords with rotating forwarded addresses, then the right one | the account is locked, the right password refused during the lock | T-22 | `tests/attack/src/ratelimit-proxy.test.ts` |
| A-74 | Smuggling-style and oversized requests at the proxy | none | CL/TE conflicts both ways, duplicate and malformed lengths, folding, bad chunks, absolute-URI and wrong Host, 70 KB URL, 200 KB header, 4000 headers, huge cookie, 7 MB body | at most one response, no 5xx from the application, never a second request executed | T-27 | `tests/attack/src/ratelimit-proxy.test.ts` |
| A-75 | Slowloris-lite | none | fifty connections dribbling a request | a normal request is still served in milliseconds (measured) | T-27 | `tests/attack/src/ratelimit-proxy.test.ts` |
| A-76 | Unusual methods | none | TRACE, PROPFIND, PURGE, LOCK, OPTIONS with a foreign Origin, HEAD | 405 at the proxy, no CORS grant, no body on HEAD | T-27, T-38 | `tests/attack/src/ratelimit-proxy.test.ts` |
| A-80 | Make the system say more than it should | a session and a token | seventeen malformed, oversized and hostile requests to the BFF, the API and the identity provider; banners on every response | short generic bodies, no stack, path, SQL or library name; one error shape; no version header | T-07, T-24 | `tests/attack/src/leakage.test.ts` |
| A-81 | Find files and endpoints that should not exist | none | 31 paths: configuration, source, source maps, build metadata, debug and framework routes; the image optimiser and data routes with internal and external URLs (SSRF) | 404 or a redirect to this site, never content | T-38, T-32 | `tests/attack/src/leakage.test.ts` |
| A-82 | Tell hidden from missing | an analyst | status, body and headers of hidden versus missing ids on reads, attachments, exports, writes and pages; median response time over 40 interleaved pairs (tolerance 150 ms) | identical; timing difference far below the tolerance (measured) | T-15 | `tests/attack/src/leakage.test.ts` |
| A-83 | Learn which usernames exist | none | unknown user versus wrong password at the login form | the same message | T-22 | `tests/attack/src/leakage.test.ts` |
| A-90 | Crash the API with arbitrary JSON | an unit admin token | fast-check: arbitrary nested values, nasty strings, numbers, as bodies of create, update, submit; non-JSON, truncated and wrongly typed bodies | client error with the common shape, never a 5xx or a leak | T-13, T-27 | `tests/attack/src/fuzz.test.ts` |
| A-91 | Crash the API with arbitrary ids, queries and headers | an auditor token | arbitrary strings in ids, filters, cursors, limits, formats, headers | same properties | T-14, T-27 | `tests/attack/src/fuzz.test.ts` |
| A-92 | Crash the upload path with arbitrary bytes, types and names | a unit admin token | random bytes, declared types and encoded names | 201, 4xx only, never a 5xx | T-28 | `tests/attack/src/fuzz.test.ts` |
| A-93 | Crash the BFF with arbitrary JSON, forms, queries, cookies and paths | sessions | arbitrary values through the proxy, create/update/break-glass forms, page queries, cookies, paths under every route family | never a 5xx or a leak | T-27, T-38 | `tests/attack/src/fuzz.test.ts` |
| A-94 | Smuggle an unknown field past validation | a unit admin token | a valid create or update plus one extra field of any name and value | always 400 | T-13 | `tests/attack/src/fuzz.test.ts` |
| A-95 | Prototype pollution | a unit admin token | __proto__, constructor, prototype in bodies, queries, nested and escaped | 400 or inert; nothing leaks into later responses | T-13 | `tests/attack/src/fuzz.test.ts` |
| A-97 | What a dynamic scanner finds | a signed-in session | OWASP ZAP baseline (spider and passive rules) through the proxy with the session cookie | no medium or high alert outside the expiring allow-list | T-07, T-27 | `tests/attack/src/zap.test.ts` |

## What the suite found

Each of these was found by an attack, fixed in the same pull request, and is now pinned by the attack that found it (and, where cheap, by a unit test):

1. **TRACE (and other unused methods) gave a 500** from Next.js on any path; the proxy now answers 405 for methods the application does not use (A-76).
2. **An invalid percent-escape in a path (`/cases/%ff%fe`) gave a 500**; the BFF answers 400 (A-80).
3. **Prototype-pollution keys, an empty key and `Object.prototype` member names (`toString`, `hasOwnProperty`, ...) in a JSON body were silently accepted** (class-transformer drops them before the whitelist sees them); the API refuses them with 400 at any depth (A-24, A-94, A-95). The last two were found by the fuzzer with a random seed, not by a hand-written case.
4. **A break-glass justification with a control character gave a 502, and one in a non-Latin script (Cyrillic, emoji) could never be sent** because an HTTP header is Latin-1; the BFF now cleans it and sends it percent-encoded, the API decodes (A-60).
5. **`openid-client` could end up as one copy per route bundle**, so a login could fail with "config must be an instance of Configuration" depending on which route ran first; it is now an external package, one instance per process.

## Mutation spot-check of the suite

`scripts/attack-mutation.mjs` (manual workflow `attack-mutation`) breaks 17 defences one at a time, rebuilds what each lives in, runs the attack file that should notice and puts the stack back before the next one. Results, run on the CI runner (about 1.5 hours for all 17):

| ID | Defence broken | Result |
|----|----------------|--------|
| M01 | the API checks neither audience nor authorised party of a token | survives, **redundant layers**: the account-console token also lacks the application claims (clearance, unit) the API requires, so it is refused three times over |
| M02 | the audit list needs only the right to read case files | killed (A-25) |
| M03 | prototype-pollution and empty keys no longer refused | killed (A-94, A-95, A-24) |
| M04 | uploads stored without inspecting the bytes | killed (A-40, 11 tests) |
| M05 | a quarantined or pending attachment can be downloaded | killed (A-41) |
| M06 | an attachment id works under any readable case file (IDOR) | killed (A-44) |
| M07 | the BFF's CSRF check always passes | killed (A-14, A-13) |
| M08 | the session cookie is not HttpOnly | killed (A-12) |
| M09 | the post-login redirect accepts any returnTo | killed (A-15) |
| M10 | the callback compares the state with the URL's own instead of the pre-auth cookie's | killed (A-16) |
| M11 | no rate limit on the login endpoint | killed (A-70) |
| M12 | the API's failed-authentication budget is off | killed (A-72) |
| M13 | the generic proxy forwards a break-glass header | killed (A-60) |
| M14 | the break-glass justification is not cleaned in the API | **survived the first time** (the BFF cleans the text before the API sees it, so every attack through the BFF was blind to it); a test straight at the API was added to A-60; killed |
| M15 | an invalid percent-escape in a path gives a 500 again | killed (A-80) |
| M16 | the proxy lets unused methods through | killed (A-76, A-17) |
| M17 | the policy engine no longer checks the clearance floor | survives, **redundant layer**: row-level security hides the row before the policy is asked (the stage 5 parity tests are what pin the policy itself) |

17 mutants: 15 killed, 2 survive on purpose. Lessons from getting the harness right: a mutant that stays built poisons the next one (the script now restores the stack after each), a rebuild that never reached the running container reports nothing (the script now compares image ids), and a second factor can be refused when two processes sign the same user in within one 30 second step (the login retries with the next step).

## Not attacked here

Exploits that need a real browser (CSP enforcement as the browser implements it, `__Host-` cookie handling, clickjacking in practice: the headers are asserted, the browser is not driven), denial of service beyond the lite cases above, anything that needs more than one replica, attacks on the host or the container runtime, social engineering, and attacks on Keycloak's own code beyond its configuration. See `docs/accepted-risks.md` and the "Not verified" lists in `docs/hardening.md` and `docs/asvs.md`.
