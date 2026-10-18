# Deployment shape (stage 8b)

How the system is meant to run when it is not a developer laptop, and the test that attacks that shape. The stack here is **prod-like**: the same structure on one machine with throw-away secrets, a throw-away CA and the name `vault.localhost`. It is not a deployment guide for a cloud, and it holds no real data.

## Images

| Image | Base (pinned by digest) | Notes |
|-------|-------------------------|-------|
| `Dockerfile.api` | build `node:24-slim`, run `gcr.io/distroless/nodejs24-debian13:nonroot` | `pnpm deploy --prod`: production dependencies only, no shell, no package manager, no curl; user 65532; `ACL_ENV=production` baked in |
| `Dockerfile.web` | same | Next.js production server; `ACL_ENV=production` baked in; Turbopack's hashed `pg` external is re-linked for the deployed layout (without it the BFF cannot load `pg`, the stack test catches that) |
| `Dockerfile.keycloak` | Keycloak 26.8.1 | `kc.sh build` at image build time, so the container runs `start --optimized` with a read-only root filesystem |

Digests were read with `docker buildx imagetools inspect` on 2026-10-18 and are bumped by Dependabot's docker ecosystem. pnpm is installed by corepack from `packageManager` (version only, no integrity hash pinned there: unverified). The web image is large (about 860 MB) because it carries the production `node_modules` of Next.js.

**ACL_ENV cannot be forgotten.** Both application images set `ACL_ENV=production` themselves, the prod-like compose states it again for `api`, `web` and the migration job, and `scripts/prod-like-test.mjs` asserts both and then starts the built images with the development values of `.env.example`: they must exit non-zero with "development value" in their output.

## The prod-like stack

```
 browser ──443──▶ caddy ──app──▶ web ──app──▶ api ──scan──▶ clamd
                    │            │            │
                    └─app──▶ keycloak ◀──data─┴──▶ postgres
 networks:  edge (routable, only caddy)   app, data, scan: internal (no way out)
```

- **Proxy** (`infra/caddy/Caddyfile`, caddy pinned by digest, runs as 65532): the only published port, `127.0.0.1:443`. TLS ends here, HSTS, no `Server`, `Via`, `Alt-Svc` (HTTP/3 off, UDP is not published). For the BFF it **sets** `x-acl-proxy-secret` (read from a mounted file) and `x-acl-client-ip` (its own view of the client) and `X-Forwarded-For`/`-Proto`, and **removes** inbound `x-acl-zone`, `x-real-ip`, `Forwarded`, `X-Forwarded-Host`, `X-Forwarded-Port`. `set` replaces any client-supplied value, including duplicates. Request bodies are capped at 6 MB. For the identity provider only `/realms/casefile/*`, `/resources/*` and `/robots.txt` are served; the admin console, the master realm, `/health` and `/metrics` answer 404.
- **Networks:** `app`, `data` and `scan` are `internal: true`: a container on them cannot reach the internet and nothing outside can reach it. `web` and `api` publish nothing. The BFF and the API reach the identity provider by its public name through the proxy (a network alias), trusting the stack's CA through `NODE_EXTRA_CA_CERTS`, so the token issuer is the same string everywhere.
- **Every container:** `cap_drop: ALL`, `no-new-privileges`, read-only root filesystem (tmpfs for scratch, named volumes for data), memory, CPU and pids limits, `init`. No process runs as root: api and web as 65532, postgres as 70, clamd as 100, Keycloak as its own user, the proxy as 65532. The one capability added back is `NET_BIND_SERVICE` for the proxy (it listens on 443 and its binary carries the file capability). Keycloak and Postgres run as non-root without any added capability.
- **Secrets:** one file each under `secrets-dev/prod-like/` (git-ignored), mounted by compose `secrets:` and read with `NAME_FILE`. Two services take credentials from an env file only because their images have no file option: Postgres (init script role passwords) and Keycloak (database and bootstrap-admin passwords, realm placeholders). The migration job gets `MIGRATOR_DATABASE_URL` the same way; no running service holds the schema owner's credential. The test asserts that no secret value of the application services shows up in `docker inspect`.
- **Migrations:** a one-shot `migrate` service, then `api` and `web` start.
- **Scanner:** `clamd` (`Dockerfile.clamd`: current Alpine plus the Alpine clamav package, native on amd64 and arm64) on its own internal network, reachable by the API only. Signatures are downloaded and verified by `freshclam` at **image build time** and baked in (the network is internal, the running container cannot update). Refreshing them means rebuilding the image (`SIGNATURES_DATE=$(date +%F) docker compose ... build clamd`); a scheduled rebuild or an update job with its own egress is the deployment's to build.
- **Attachment volume:** a named volume owned by 65532, mounted at `/var/lib/casefile/attachments`.
- **Realm:** `scripts/prod-like-setup.mjs` rewrites the dev realm for the proxy's origin and `sslRequired=all`. Users keep their dev names; their passwords and TOTP secrets are random per generated setup.

## The test: `node scripts/prod-like-test.mjs`

Needs docker and openssl; first run builds the images (a few minutes), a later run is faster. It starts the stack with `docker-compose.prod-like.test.yml` (an echo upstream and a route `/__echo` that shows the headers the BFF would receive, test only), runs the checks, and tears everything down (`--keep` leaves it up, `--only=<regex>` runs a subset).

| Check | What it proves |
|-------|----------------|
| services healthy | the stack comes up from a cold start with migrations applied |
| containers | non-root processes, read-only root, caps dropped (only the listed ones back), no-new-privileges, limits |
| networks | internal flags, only the proxy publishes a port, on loopback |
| not via the proxy | the host cannot connect to 3000, 3001, 5432, 8080, 9000, 3310, 80; a container on the edge network cannot reach web, api, postgres, keycloak or clamd |
| no way out | a container on app, data or scan cannot reach the internet |
| TLS and headers | HTTPS with the stack's CA only, HSTS, no `Server`/`Via`/`Alt-Svc` |
| identity provider | only the realm is reachable; the issuer equals the public name |
| proxy headers | forged `x-acl-client-ip`, `x-acl-proxy-secret`, `x-acl-zone`, `x-real-ip`, `Forwarded`, `X-Forwarded-*` (also duplicated) never arrive; the secret and the address are the proxy's |
| production profile | images default to `ACL_ENV=production`, compose sets it, dev values stop api and web |
| secrets | no secret value in `docker inspect` of api, web, caddy |
| attachment volume | owned by the unprivileged user |
| real scanner | clamd flags the EICAR test file and passes a clean file (client from the API image) |
| end to end | real Keycloak login through the proxy, case file created, clean file stored and downloaded with attachment headers, EICAR quarantined and never served, database and volume agree |
| rate limit | forged client addresses through the real proxy share the real bucket (429) |

**Not verified here:** a certificate from a public CA, HTTP/3, the behaviour behind a cloud load balancer that adds its own `X-Forwarded-For` (the proxy would need `trusted_proxies` and the BFF contract reviewed), more than one replica (limits are per process), Keycloak or Postgres tuning, backups, log shipping, host hardening, time synchronisation, clamd signature freshness, and the realm secrets of a real deployment. The web image's size and the amd64 emulation of clamd on arm64 are conveniences of the test machine, not findings.
