// SPDX-License-Identifier: AGPL-3.0-only

// Package keyring stores private keys in one file wrapped with a passphrase:
// scrypt derives a key, ChaCha20-Poly1305 seals the JSON body.
//
// File layout: "LDKR1" | log2(N) | salt(16) | nonce(12) | ciphertext.
package keyring

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/payam-foundation/log-decypher/seal"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

// LogN is log2 of the scrypt cost used when saving. Tests lower it.
var LogN uint8 = 17

const (
	magic    = "LDKR1"
	saltLen  = 16
	hdrLen   = len(magic) + 1 + saltLen + chacha20poly1305.NonceSize
	minLogN  = 10
	maxLogN  = 22
	maxFile  = 1 << 20
	statusOK = "active"
	// StatusRetired keys still open old reports but are never used for new ones.
	StatusRetired = "retired"
)

// ErrPassphrase means the file did not decrypt: wrong passphrase or corrupt file.
var ErrPassphrase = errors.New("keyring: wrong passphrase or corrupt file")

// Entry is one private key.
type Entry struct {
	Fingerprint string    `json:"fingerprint"`
	Project     string    `json:"project"`
	Created     time.Time `json:"created"`
	Status      string    `json:"status"`
	Priv        []byte    `json:"priv"`

	key *seal.PrivateKey
}

// Keyring is the decrypted key set.
type Keyring struct {
	Entries []*Entry `json:"entries"`
}

// Add generates a key for project and returns its entry and public key.
func (k *Keyring) Add(project string) (*Entry, *seal.PublicKey, error) {
	priv, err := seal.Generate()
	if err != nil {
		return nil, nil, err
	}
	b, err := priv.Bytes()
	if err != nil {
		return nil, nil, err
	}
	pub := priv.Public()
	e := &Entry{Fingerprint: pub.Fingerprint(), Project: project, Created: time.Now().UTC(), Status: statusOK, Priv: b, key: priv}
	k.Entries = append(k.Entries, e)
	return e, pub, nil
}

// Retire marks the key with the given fingerprint retired.
func (k *Keyring) Retire(fp string) error {
	for _, e := range k.Entries {
		if e.Fingerprint == fp {
			e.Status = StatusRetired
			return nil
		}
	}
	return fmt.Errorf("keyring: no key %q", fp)
}

// Open tries every key (active and retired) against blob. It returns the
// payload and the entry that opened it.
func (k *Keyring) Open(blob []byte) ([]byte, *Entry, error) {
	for _, e := range k.Entries {
		if e.key == nil {
			key, err := seal.ParsePrivate(e.Priv)
			if err != nil {
				continue
			}
			e.key = key
		}
		if plain, err := seal.Open(e.key, e.Project, blob); err == nil {
			return plain, e, nil
		}
	}
	return nil, nil, seal.ErrOpen
}

// Exists reports whether a keyring file is present.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Load reads and decrypts a keyring file.
func Load(path string, pass []byte) (*Keyring, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > maxFile {
		return nil, errors.New("keyring: file too large")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(raw) < hdrLen+chacha20poly1305.Overhead || string(raw[:len(magic)]) != magic {
		return nil, errors.New("keyring: not a keyring file")
	}
	logN := raw[len(magic)]
	if logN < minLogN || logN > maxLogN {
		return nil, errors.New("keyring: bad scrypt cost")
	}
	salt := raw[len(magic)+1 : len(magic)+1+saltLen]
	nonce := raw[len(magic)+1+saltLen : hdrLen]
	aead, err := newAEAD(pass, salt, logN)
	if err != nil {
		return nil, err
	}
	body, err := aead.Open(nil, nonce, raw[hdrLen:], raw[:len(magic)+1])
	if err != nil {
		return nil, ErrPassphrase
	}
	var k Keyring
	if err := json.Unmarshal(body, &k); err != nil {
		return nil, fmt.Errorf("keyring: %w", err)
	}
	return &k, nil
}

// Save encrypts the keyring and writes it atomically with mode 0600.
func (k *Keyring) Save(path string, pass []byte) error {
	body, err := json.Marshal(k)
	if err != nil {
		return err
	}
	out := make([]byte, hdrLen, hdrLen+len(body)+chacha20poly1305.Overhead)
	copy(out, magic)
	out[len(magic)] = LogN
	salt := out[len(magic)+1 : len(magic)+1+saltLen]
	nonce := out[len(magic)+1+saltLen : hdrLen]
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	aead, err := newAEAD(pass, salt, LogN)
	if err != nil {
		return err
	}
	out = aead.Seal(out, nonce, body, out[:len(magic)+1])
	tmp, err := os.CreateTemp(filepath.Dir(path), ".keyring-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func newAEAD(pass, salt []byte, logN uint8) (cipherAEAD, error) {
	if len(pass) == 0 {
		return nil, errors.New("keyring: empty passphrase")
	}
	key, err := scrypt.Key(pass, salt, 1<<logN, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, err
	}
	return chacha20poly1305.New(key)
}

type cipherAEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}
