# Contributing

Thanks for helping. log-decypher is free software under the GNU Affero General Public License v3.0 only (see `LICENSE`).

## Ground rules

- Open an issue before a large change. Small fixes can go straight to a pull request.
- Keep changes minimal: standard library first, no new dependency for what a few lines do, no placeholder code.
- The tool stays project-agnostic and offline: no project names, no network code, no mail protocol.
- The sealed format is a contract. `testdata/golden.txt` must keep opening; changing it is a breaking release.
- Never commit secrets, real hostnames or real IP addresses. Use documentation values (`example.com`, `203.0.113.0/24`).
- Security issues: follow `SECURITY.md`, not a public issue.

## Development

```sh
go vet ./...
go test -race -count=1 ./...
go test -run '^$' -fuzz FuzzOpen -fuzztime 20s ./seal
```

Every Go file starts with `// SPDX-License-Identifier: AGPL-3.0-only`.

## Workflow

`main` is protected: no direct pushes. Every change is a pull request.

1. Branch from `main` as `type/short-slug` (`feat/`, `fix/`, `docs/`, `ci/`, `chore/`). External contributors fork.
2. Commit with sign-off: `git commit -s`.
3. Open a PR. The title must be a Conventional Commit (`feat: add X`, `fix(seal): Y`); it becomes the squash commit on `main`. Breaking change: `feat!: ...`.
4. Required checks (tests, security, PR title, DCO) must pass. Merges are squash-only with a linear history.
5. Releases are automated: release-please opens a release PR from the Conventional Commits on `main`. Merging it creates the tag `vX.Y.Z` and the release; the tag triggers the signed build. Never tag by hand.

## Licence of contributions

By submitting a contribution you agree that it is licensed under the same terms as the repository (AGPL-3.0-only), and that you have the right to submit it. Sign off commits with `git commit -s` (Developer Certificate of Origin).
