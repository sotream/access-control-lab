# Signed commits (guidance, not enforced)

Signing proves a commit came from a key its author controls; it does not prove the change is safe.
Nothing here is enforced by CI or branch rules. Squash merges made in the GitHub UI are signed by GitHub.

SSH signing, one-time setup:

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
```

Then add the same public key to GitHub as a **signing key** (Settings, SSH and GPG keys). Verify a commit
locally with `git log --show-signature -1` (needs `gpg.ssh.allowedSignersFile`) or look for "Verified" on GitHub.

To enforce later: ruleset "Require signed commits" on `main`. Squash merges by GitHub stay valid.
