# Security policy

log-decypher seals diagnostic data and opens it offline. Please report vulnerabilities privately.

## Reporting

Use GitHub private vulnerability reporting: <https://github.com/payam-foundation/log-decypher/security/advisories/new>.

Do not open a public issue for a vulnerability. Include the affected version, a reproduction, and the impact you expect. We aim to acknowledge reports within 72 hours.

## Supported versions

Only the latest tagged release receives security fixes.

## Scope

In scope: confidentiality and integrity of sealed blobs, the padded frame parser, the keyring file, input parsing in `decypher` (mail, mbox, armor), terminal output sanitising.

Out of scope: sender authenticity (the public key is public by design), a compromised operator machine or passphrase, and traffic analysis beyond the documented size buckets.
