# Rules for agents

- Read `docs/plan.md` first; work one stage per branch, one commit per task, PR into `main`, squash merge.
- Security over features: every stage ends with tests that try to break the control (negative tests), not only happy paths.
- pnpm only. Tailwind for styles. No frontend design work until the last stage; the UI before that is functional and unstyled.
- No secrets in the repo. `.env.example` only, dev-only credentials marked as such.
- Self-host fonts and assets, no CDN.
- Commit author `andrii.prisniak+github@gmail.com`. Push with remote host `github2.com`.
- Anything unverified (versions, library behaviour) is marked as such in the docs.
