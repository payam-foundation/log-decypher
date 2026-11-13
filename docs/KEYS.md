# Key ceremony and custody

The private key is the only thing that reads reports. Treat it as a long-term secret.

## Generate

1. Use an offline machine (no network, fresh OS session) with a release `decypher` verified against `checksums.txt` and its sigstore bundle.
2. `decypher keygen --project NAME --keyring reports.keyring --pub-out NAME.pub`. Choose a long random passphrase and store it in the team password manager.
3. Record the printed 8-byte fingerprint and the public key string. The public key goes into the sending app as a string constant; the fingerprint goes into its release notes.

## Back up

Make two copies of `reports.keyring` on separate encrypted media in separate places. The file is passphrase-wrapped, but the passphrase must not be stored next to it.

## Use

Copy the keyring to the triage machine only when needed. Run `decypher verify`, `open` or `watch` there. The key never touches the mail server, a CDN, CI or the application backend.

## Rotate

Rotate every year or on suspected compromise.

1. Run `decypher keygen` again for the same project with the same keyring. The previous key is marked `retired` and keeps opening old reports.
2. Ship the new public key in the sending app as the first (active) entry.
3. After the last release that seals to the old key is out of support, `decypher keys retire` is already done; keep the entry for old mail.

## Compromise

Generate a new key, ship it, and assume reports sealed to the old key are readable by the attacker. Retired keys stay in the keyring only to read your own archive.
