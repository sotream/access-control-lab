## What and why

## Security checklist

- [ ] Threat model entries touched or added (`docs/threat-model.md`), linked by T-ID
- [ ] Negative tests added: a test that tries to break the new control and fails without it
- [ ] Default deny preserved; no route, query or token path added without an authorization check
- [ ] No secrets, tokens or real personal data in code, tests, logs, fixtures or docs
- [ ] Input validated at the boundary (DTO whitelist, size limits); output encoded
- [ ] New dependencies justified, pinned, and `pnpm audit --prod` clean; actions pinned by SHA
- [ ] Anything unverified is marked as such in the docs

## Verified locally

<!-- commands run and their results, and what was NOT verified -->
