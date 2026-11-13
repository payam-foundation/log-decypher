# log-decypher

Generic sealed-report library and offline operator tool. Module `github.com/payam-foundation/log-decypher`, binary `decypher`. License AGPL-3.0-only.

## Commands

```sh
go vet ./... && go test -race -count=1 ./...
LD_GOLDEN=1 go test ./seal   # regenerate testdata/golden.txt: only for a deliberate format break
```

## Layout

- `seal`, `envelope`, `armor`: public packages a sender links. Keep them small and stable.
- `cmd/decypher`, `internal/*`: operator side. Not importable by other modules.

## Invariants

- Crypto is stdlib `crypto/hpke` only: `MLKEM768X25519`, HKDF-SHA256, ChaCha20-Poly1305. No negotiation, no new suite without a new key prefix (`ldk2`).
- A blob has no magic or plaintext header. Do not add one.
- `info = "ld1/" + project`. A key never opens another project's blobs.
- No network code anywhere. No project-specific names in code, tests or docs.
- Decrypted text is untrusted: sanitise before output, never execute or auto-act on it.
- Never log plaintext or key material.
- Every Go file starts with `// SPDX-License-Identifier: AGPL-3.0-only`.

## Shared rules

- Static builds: `CGO_ENABLED=0`, `-trimpath`.
- Go style: stdlib first, no new dependency for what a few lines do, no placeholder code. Mark deliberate shortcuts with a `ponytail:` comment naming the ceiling and the upgrade path.
- Pull requests only, never push to `main`. PR title is a Conventional Commit, commits are signed off (`git commit -s`), merges are squash-only. Releases come from release-please.
