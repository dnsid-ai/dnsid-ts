# Contributing to dnsid-ts

Thanks for contributing! This is the TypeScript client SDK for the DNSid protocol.

## Development

```bash
npm ci
npm run build
npm test
```

## Pull requests

- Branch off `main`; open a PR against `main`.
- All PRs require **1 approving review** from a code owner and all conversations resolved before merge.
- Keep changes focused; add tests for behavior changes.

### Signed commits

As of 2026-07-09, contributors are expected to sign local commits for this
repository. Commits made in GitHub's web UI are signed by GitHub, but commits
made from your local Git CLI need local signing setup. GitHub branch enforcement
must be enabled separately before saying `main` rejects unsigned commits.

SSH commit signing is the default path for this repository. It requires Git
2.34 or newer:

```bash
git --version
```

Configure your Git identity first. The email must be verified on GitHub:

```bash
git config user.name
git config user.email

GIT_EMAIL="$(git config user.email)"
test -n "$GIT_EMAIL"
gh api user/emails --jq ".[] | select(.email == \"$GIT_EMAIL\" and .verified == true) | .email" | grep -qx "$GIT_EMAIL"
```

If the `gh api user/emails` command needs permission to read private email
metadata, refresh the GitHub CLI token and run the check again:

```bash
gh auth refresh -s user:email
```

Generate a signing key, or reuse an existing SSH key. This example uses the
standard Ed25519 key path:

```bash
GIT_EMAIL="$(git config user.email)"
SIGNING_KEY="${HOME}/.ssh/id_ed25519"
mkdir -p "${HOME}/.ssh"
chmod 700 "${HOME}/.ssh"
test -f "$SIGNING_KEY" || ssh-keygen -t ed25519 -C "$GIT_EMAIL" -f "$SIGNING_KEY"
```

Upload the public key to GitHub as a signing key:

```bash
SIGNING_KEY="${HOME}/.ssh/id_ed25519"
gh ssh-key add "${SIGNING_KEY}.pub" --type signing --title "$(hostname)-git-signing"
```

Configure Git to sign commits and tags with that SSH key:

```bash
SIGNING_KEY="${HOME}/.ssh/id_ed25519"
git config --global gpg.format ssh
git config --global user.signingkey "${SIGNING_KEY}.pub"
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

For local `git verify-commit` checks, add the key to Git's SSH allowed signers
file:

```bash
GIT_EMAIL="$(git config user.email)"
SIGNING_KEY="${HOME}/.ssh/id_ed25519"
SIGNERS_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/git/allowed_signers"
mkdir -p "$(dirname "$SIGNERS_FILE")"
grep -qxF "${GIT_EMAIL} namespaces=\"git\" $(cat "${SIGNING_KEY}.pub")" "$SIGNERS_FILE" 2>/dev/null || \
  printf '%s namespaces="git" %s\n' "$GIT_EMAIL" "$(cat "${SIGNING_KEY}.pub")" >> "$SIGNERS_FILE"
git config --global gpg.ssh.allowedSignersFile "$SIGNERS_FILE"
```

Create and verify a throwaway signed branch before opening a real PR:

```bash
(
  set -e

  BASE_BRANCH="$(git branch --show-current)"
  TEST_BRANCH="signed-commit-smoke-test-$(date +%Y%m%d%H%M%S)"
  PUSHED=0

  cleanup() {
    status=$?
    git switch "$BASE_BRANCH" >/dev/null 2>&1 || true
    if [ "$PUSHED" = "1" ]; then
      git push origin --delete "$TEST_BRANCH" >/dev/null 2>&1 || true
    fi
    git branch -D "$TEST_BRANCH" >/dev/null 2>&1 || true
    exit "$status"
  }
  trap cleanup EXIT

  test -z "$(git status --porcelain)" || { echo "Working tree must be clean"; exit 1; }
  git switch -c "$TEST_BRANCH"
  git commit --allow-empty -S -m "test: verify signed commit setup"
  git verify-commit HEAD

  git push -u origin "$TEST_BRANCH"
  PUSHED=1

  GITHUB_VERIFICATION="$(gh api "repos/:owner/:repo/commits/$(git rev-parse HEAD)" \
    --jq '.commit.verification | "\(.verified) \(.reason)"')"
  test "$GITHUB_VERIFICATION" = "true valid"
  printf 'GitHub verification: %s\n' "$GITHUB_VERIFICATION"
)
```

The GitHub verification output should be `GitHub verification: true valid`. For
more detail, see GitHub's docs for
[commit signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification),
[telling Git about your signing key](https://docs.github.com/en/authentication/managing-commit-signature-verification/telling-git-about-your-signing-key)
and [signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits).

## Reporting security issues

See [SECURITY.md](SECURITY.md) — do not file public issues for vulnerabilities.
