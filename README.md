# log-decypher

Seal a diagnostic report to a public key, email it, open it offline. Project-agnostic: nothing here is specific to one app.

[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)

- **Senders** link `seal`, `envelope` and `armor` and attach one opaque file to a mail.
- **Operators** run `decypher` on an offline machine to verify and read what arrives.
- No network code, no mail protocol, no server. Receiving is manual: download the mail or attachment and give it to `decypher`.

## Format

HPKE (RFC 9180) from the standard library `crypto/hpke`, one fixed suite, no negotiation:

| part | value |
|---|---|
| KEM | `MLKEM768X25519` (X-Wing, hybrid post-quantum) |
| KDF | HKDF-SHA256 |
| AEAD | ChaCha20-Poly1305 |
| info | `"ld1/" + project`, so a key for one project cannot open another project's blobs |

A blob is exactly `enc || ciphertext`. There is no magic, version or key id outside the AEAD, so the file is indistinguishable from random bytes. The receiver trial-decrypts against its keyring. Inside the AEAD:

```
ver(1) | flags(1, bit0 gzip) | len(4, big endian) | gzip(payload) | zero padding
```

The frame is padded to 4, 16, 64 or 256 KB (then multiples of 256 KB) so the length leaks only a bucket. Hard cap 1 MB on both sides.

Public keys are strings `ldk1.<base64url>` (about 1.6 KB). `ldk1` is the only agility hook. `testdata/golden.txt` is a pinned vector: every release must keep opening it.

Armor text (`-----BEGIN LOG-----`, 76-column base64) is the same blob for pasting into chat apps. `armor.Decode` tolerates `>` quote prefixes and stray whitespace.

## Library

```go
pub, _ := seal.ParsePublic(keyString)
env := &envelope.Envelope{Project: "myapp", Kind: "report", ID: "K7M2QX9P", Created: time.Now().UTC(),
    Meta: map[string]string{"os": "linux"}, Sections: []envelope.Section{{Name: "log", Data: logs}}}
plain, _ := envelope.Marshal(env)
blob, _ := seal.Seal(pub, "myapp", plain)   // attach as r-K7M2QX9P.dat
text := armor.Encode(blob)                  // or paste this
```

`Seal` returns `ErrTooLarge` when the compressed payload exceeds 768 KB.

## decypher

```
decypher keygen --project NAME --keyring FILE [--pub-out FILE]
decypher keys   list|retire --keyring FILE [FINGERPRINT]
decypher verify PATH... --keyring FILE
decypher open   PATH... --keyring FILE [--out DIR | --stdout]
decypher watch  DIR     --keyring FILE --out DIR [--interval 5s] [--on-report CMD]
```

`PATH` is a file, a directory, or `-` for stdin: raw blob, `.eml`, `.mbox`, Maildir, or armor text. For mail, the text body and every attachment are tried; parts that do not decrypt are skipped.

- The keyring is one file wrapped with scrypt (N=2^17, r=8, p=1) and ChaCha20-Poly1305. The passphrase comes from the terminal or from the file named by `LD_PASSPHRASE_FILE`, never from a flag.
- `keygen` for an existing project marks the older key `retired`. Retired keys still open old reports.
- `verify` writes nothing. It checks the AEAD tag, project binding, padding, length, envelope caps, that the envelope project equals the key project, and that `created` is not in the future and not older than a year. Exit 2 if any file fails.
- `open` writes `OUT/<project>/<date>/<id>.md` and `.json` (0600), never overwriting. Decrypted text has control characters replaced before it reaches a terminal or file.
- `watch` processes a file once its size is stable for one interval, dedupes by blob SHA-256 in `.seen`, and moves sources to `done/` or `failed/`. `--on-report CMD` runs `CMD <output-path>` without a shell.
- Exit codes: 0 ok, 1 usage or error, 2 nothing decrypted.

Key custody and rotation: [docs/KEYS.md](docs/KEYS.md).

## Threat model

Protects report contents from the sender's mail provider, network observers and a leaked mailbox, including harvest-now-decrypt-later. Does not authenticate the sender: the public key ships in the sending app, so anyone can produce a valid report. Treat decrypted content as untrusted text and never act on it automatically. The recipient address is visible to the sender's mail provider.

## Build

```sh
go test -race -count=1 ./...
go build -trimpath ./cmd/decypher
```

Go 1.27 or newer (`crypto/hpke` with `MLKEM768X25519`). Dependencies: `golang.org/x/crypto/scrypt` and `golang.org/x/term`.

## License

[GNU AGPL-3.0-only](LICENSE). Every Go file carries `// SPDX-License-Identifier: AGPL-3.0-only`.
