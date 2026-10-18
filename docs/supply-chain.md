# Supply chain controls

What exists, where it is enforced, and what is **unverified**. Stage 8 extended this: images are built here and scanned, SBOM per image, public-repo features are on (`docs/deployment.md`, `docs/asvs.md`).

| Control | Where | Notes |
|---------|-------|-------|
| Frozen lockfile | CI `pnpm install --frozen-lockfile` | |
| Install scripts off | `.npmrc` `ignore-scripts=true` | lint, typecheck, test, build verified to work without dependency scripts |
| Minimum release age 24h | `pnpm-workspace.yaml` `minimumReleaseAge` | pnpm 12.9.1 enforces it on frozen install (observed: a 7 day value failed the lockfile). Floor is low because the lockfile was resolved with recent releases |
| Dependabot cooldown 7 days | `.github/dependabot.yml` | grouped minor/patch, weekly |
| Actions pinned by SHA | all workflows | version in a comment; Dependabot updates them |
| Least privilege tokens | `permissions: contents: read` top level | write scopes only on the inert automerge job |
| Image digests | `docker-compose.yml` | tag plus `@sha256`; digests taken 2026-10-17 |
| CodeQL (security-extended) | `security.yml` | SARIF uploaded to code scanning and kept as an artifact; any finding fails the job |
| OSV-Scanner | `security.yml` | lockfile; complements `pnpm audit --prod` |
| Trivy image scan | `security.yml` `images` | the five images built here plus the compose-pinned ones; HIGH/CRITICAL with fix available fail; exceptions only in `.trivyignore.yaml` with reason and expiry (checked by `pnpm lint`) |
| actionlint, zizmor | `security.yml` | workflow correctness and workflow security |
| gitleaks | `ci.yml` | full history |
| SBOM CycloneDX | `ci.yml` artifact `sbom-cyclonedx`, `security.yml` artifact `sbom-images` | production dependencies, and one SBOM per image built here |
| dependency-review | `dependency-review.yml` | pull requests, fails on HIGH |
| OpenSSF Scorecard | `scorecard.yml` | main and weekly, published |
| Dependabot auto-merge | `dependabot-automerge.yml` | inert until variable `DEPENDABOT_AUTOMERGE=true`, set only after main requires checks |

## Known exceptions

- **postgres image, gosu.** Official `postgres` images (17.11 alpine and debian, 18.4 alpine, checked 2026-10-17) bundle
  `usr/local/bin/gosu` built with an old Go stdlib: 1 CRITICAL and 24 HIGH fixable findings in Trivy. gosu runs once at
  container start to drop root and is not network facing, so the Trivy step skips that single file. Everything else in
  the image is still gated. Revisit when upstream rebuilds gosu.
- **Images built here are patched by building them.** The stock `caddy` and `clamav` images had 3 and 26 fixable HIGH/CRITICAL findings on 2026-10-18; `Dockerfile.caddy` and `Dockerfile.clamd` replace them (`docs/deployment.md`). The cost is that their rebuild schedule is ours.
- **The repository is public**, so dependency-review, code scanning upload and Scorecard are on (they were not possible while it was private).
