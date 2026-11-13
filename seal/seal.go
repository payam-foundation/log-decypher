// SPDX-License-Identifier: AGPL-3.0-only

// Package seal encrypts a payload to a public key so that only the holder of
// the matching private key can read it. The output is raw HPKE (RFC 9180)
// ciphertext with no magic bytes, so it is indistinguishable from random data.
//
// Suite (fixed, no negotiation): MLKEM768X25519 (X-Wing, hybrid post-quantum),
// HKDF-SHA256, ChaCha20-Poly1305, from the standard library crypto/hpke.
//
// Blob = enc || ciphertext. Inside the AEAD the plaintext is
//
//	ver(1) | flags(1, bit0 gzip) | len(4, big endian) | gzip(payload) | zero padding
//
// padded to a size bucket (4, 16, 64, 256 KB, then multiples of 256 KB) so the
// length reveals only the bucket. info = "ld1/" + project binds a blob to one
// project.
package seal

import (
	"bytes"
	"compress/gzip"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

const (
	// KeyPrefix starts every public key string. It is the only versioning hook.
	KeyPrefix = "ldk1."
	// MaxBlob is the largest blob Open accepts.
	MaxBlob = 1 << 20
	// MaxPlain is the largest payload Seal accepts and Open returns.
	MaxPlain = 1 << 20

	maxFrame = 768 << 10 // keeps enc+frame+tag under MaxBlob
	frameVer = 1
	flagGzip = 1
	hdrLen   = 6
)

var (
	// ErrOpen means the blob did not decrypt: wrong key, wrong project, or tampered.
	ErrOpen = errors.New("seal: cannot open")
	// ErrFormat means the blob decrypted but its frame is malformed.
	ErrFormat = errors.New("seal: bad frame")
	// ErrTooLarge means a payload or blob exceeds the caps.
	ErrTooLarge = errors.New("seal: too large")
	// ErrKey means a key string or key bytes are invalid.
	ErrKey = errors.New("seal: bad key")
)

var buckets = [...]int{4 << 10, 16 << 10, 64 << 10, 256 << 10}

// PublicKey is a sealing key.
type PublicKey struct{ k hpke.PublicKey }

// PrivateKey is an opening key.
type PrivateKey struct{ k hpke.PrivateKey }

// Generate creates a new key pair.
func Generate() (*PrivateKey, error) {
	k, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		return nil, err
	}
	return &PrivateKey{k}, nil
}

// ParsePrivate restores a private key from Bytes output.
func ParsePrivate(b []byte) (*PrivateKey, error) {
	k, err := hpke.MLKEM768X25519().NewPrivateKey(b)
	if err != nil {
		return nil, ErrKey
	}
	return &PrivateKey{k}, nil
}

// ParsePublic parses the "ldk1.<base64url>" string form.
func ParsePublic(s string) (*PublicKey, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, KeyPrefix) {
		return nil, ErrKey
	}
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, KeyPrefix))
	if err != nil {
		return nil, ErrKey
	}
	k, err := hpke.MLKEM768X25519().NewPublicKey(b)
	if err != nil {
		return nil, ErrKey
	}
	return &PublicKey{k}, nil
}

// Bytes serializes the private key.
func (p *PrivateKey) Bytes() ([]byte, error) { return p.k.Bytes() }

// Public returns the matching public key.
func (p *PrivateKey) Public() *PublicKey { return &PublicKey{p.k.PublicKey()} }

// String is the "ldk1.<base64url>" form.
func (p *PublicKey) String() string {
	return KeyPrefix + base64.RawURLEncoding.EncodeToString(p.k.Bytes())
}

// Fingerprint is 8 bytes of SHA-256 over the public key, hex encoded.
func (p *PublicKey) Fingerprint() string {
	h := sha256.Sum256(p.k.Bytes())
	return hex.EncodeToString(h[:8])
}

func info(project string) []byte { return []byte("ld1/" + project) }

// pad returns the padded frame size for n bytes.
func pad(n int) int {
	for _, b := range buckets {
		if n <= b {
			return b
		}
	}
	const step = 256 << 10
	return (n + step - 1) / step * step
}

// Seal encrypts plain to pub, bound to project.
func Seal(pub *PublicKey, project string, plain []byte) ([]byte, error) {
	if len(plain) > MaxPlain {
		return nil, ErrTooLarge
	}
	var z bytes.Buffer
	zw, err := gzip.NewWriterLevel(&z, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(plain); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	n := hdrLen + z.Len()
	if n > maxFrame {
		return nil, ErrTooLarge
	}
	frame := make([]byte, pad(n))
	frame[0], frame[1] = frameVer, flagGzip
	binary.BigEndian.PutUint32(frame[2:], uint32(z.Len()))
	copy(frame[hdrLen:], z.Bytes())
	return hpke.Seal(pub.k, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info(project), frame)
}

// Open decrypts blob with priv for project and returns the payload.
func Open(priv *PrivateKey, project string, blob []byte) ([]byte, error) {
	if len(blob) > MaxBlob {
		return nil, ErrTooLarge
	}
	frame, err := hpke.Open(priv.k, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), info(project), blob)
	if err != nil {
		return nil, ErrOpen
	}
	if len(frame) < hdrLen || frame[0] != frameVer || frame[1] != flagGzip {
		return nil, ErrFormat
	}
	n := int(binary.BigEndian.Uint32(frame[2:hdrLen]))
	if n > len(frame)-hdrLen || len(frame) != pad(hdrLen+n) {
		return nil, ErrFormat
	}
	for _, b := range frame[hdrLen+n:] {
		if b != 0 {
			return nil, ErrFormat
		}
	}
	zr, err := gzip.NewReader(bytes.NewReader(frame[hdrLen : hdrLen+n]))
	if err != nil {
		return nil, ErrFormat
	}
	out, err := io.ReadAll(io.LimitReader(zr, MaxPlain+1))
	if err != nil {
		return nil, ErrFormat
	}
	if len(out) > MaxPlain {
		return nil, ErrTooLarge
	}
	return out, nil
}
