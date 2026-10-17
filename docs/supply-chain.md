# Supply chain controls

What exists, where it is enforced, and what is **unverified**. Stage 8 extends this (image scanning in release
builds, ASVS mapping).

| Control | Where | Notes |
|---------|-------|-------|
| Frozen lockfile | CI `pnpm install --frozen-lockfile` | |
| Install scripts off | `.npmrc` `ignore-scripts=true` | lint, typecheck, test, build verified to work without dependency scripts |
| Minimum release age 24h | `pnpm-workspace.yaml` `minimumReleaseAge` | pnpm 12.9.1 enforces it on frozen install (observed: a 7 day value failed the lockfile). Floor is low because the lockfile was resolved with recent releases |
| Dependabot cooldown 7 days | `.github/dependabot.yml` | grouped minor/patch, weekly |
| Actions pinned by SHA | all workflows | version in a comment; Dependabot updates them |
| Least privilege tokens | `permissions: contents: read` top level | write scopes only on the inert automerge job |
| Image digests | `docker-compose.yml` | tag plus `@sha256`; digests taken 2026-10-17 |
| CodeQL (security-extended) | `security.yml` | SARIF kept as artifact; private repo without Advanced Security cannot upload to code scanning |
| OSV-Scanner | `security.yml` | lockfile; complements `pnpm audit --prod` |
| Trivy image scan | `security.yml` | HIGH/CRITICAL with fix available fail; see below |
| actionlint, zizmor | `security.yml` | workflow correctness and workflow security |
| gitleaks | `ci.yml` | full history |
| SBOM CycloneDX | `ci.yml` artifact `sbom-cyclonedx` | production dependencies only; image SBOM not yet |
| Dependabot auto-merge | `dependabot-automerge.yml` | inert until variable `DEPENDABOT_AUTOMERGE=true`, set only after main requires checks |

## Known exceptions

- **postgres image, gosu.** Official `postgres` images (17.11 alpine and debian, 18.4 alpine, checked 2026-10-17) bundle
  `usr/local/bin/gosu` built with an old Go stdlib: 1 CRITICAL and 24 HIGH fixable findings in Trivy. gosu runs once at
  container start to drop root and is not network facing, so the Trivy step skips that single file. Everything else in
  the image is still gated. Revisit when upstream rebuilds gosu.
- **Not run in CI because of the private free-tier repo:** `dependency-review-action` (needs Advanced Security on
  private repos; OSV plus `pnpm audit` cover the lockfile instead), code scanning upload for CodeQL (SARIF artifact
  instead), OpenSSF Scorecard (needs a token with read access to repo settings; not enabled, see PR notes).
