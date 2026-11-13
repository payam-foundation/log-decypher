// SPDX-License-Identifier: AGPL-3.0-only

// Package opener decrypts candidate blobs with a keyring and runs the checks
// that `decypher verify` promises.
package opener

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/payam-foundation/log-decypher/envelope"
	"github.com/payam-foundation/log-decypher/internal/keyring"
)

// MaxAge is how old a report's created time may be.
const MaxAge = 366 * 24 * time.Hour

// Report is a decrypted, validated report.
type Report struct {
	Env         *envelope.Envelope
	JSON        []byte // the envelope as sealed
	Fingerprint string // key that opened it
	Hash        string // SHA-256 of the blob, for dedupe
}

// Try opens blob with any key in kr and validates the result. now is injected
// for tests.
func Try(kr *keyring.Keyring, blob []byte, now time.Time) (*Report, error) {
	plain, e, err := kr.Open(blob)
	if err != nil {
		return nil, err
	}
	env, err := envelope.Unmarshal(plain)
	if err != nil {
		return nil, err
	}
	if env.Project != e.Project {
		return nil, fmt.Errorf("envelope project %q does not match key project %q", env.Project, e.Project)
	}
	if env.Created.After(now.Add(24 * time.Hour)) {
		return nil, fmt.Errorf("created %s is in the future", env.Created.Format(time.RFC3339))
	}
	if env.Created.Before(now.Add(-MaxAge)) {
		return nil, fmt.Errorf("created %s is older than a year", env.Created.Format(time.RFC3339))
	}
	h := sha256.Sum256(blob)
	return &Report{Env: env, JSON: plain, Fingerprint: e.Fingerprint, Hash: hex.EncodeToString(h[:])}, nil
}
