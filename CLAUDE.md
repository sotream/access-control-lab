# Rules for agents

- Read `docs/plan.md` first; work one stage per branch, one commit per task, PR into `main`, squash merge.
- Security over features: every stage ends with tests that try to break the control (negative tests), not only happy paths.
- pnpm only. Tailwind for styles. No frontend design work until the last stage; the UI before that is functional and unstyled.
- No secrets in the repo. `.env.example` only, dev-only credentials marked as such.
- Self-host fonts and assets, no CDN.
- Commit author is the owner's GitHub identity (set `user.email` per repository). Push with the SSH host alias configured for the owner's GitHub account.
- Anything unverified (versions, library behaviour) is marked as such in the docs.
- No Co-Authored-By trailers and no AI-attribution lines in commits or PR bodies; the commit author is the owner only.
