// SPDX-License-Identifier: AGPL-3.0-only

package seal

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"testing"
)

func newKey(t *testing.T) *PrivateKey {
	t.Helper()
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRoundTrip(t *testing.T) {
	k := newKey(t)
	for _, n := range []int{0, 1, 100, 5000, 100_000, 700_000} {
		plain := make([]byte, n)
		rand.Read(plain)
		blob, err := Seal(k.Public(), "p", plain)
		if err != nil {
			t.Fatalf("n=%d seal: %v", n, err)
		}
		got, err := Open(k, "p", blob)
		if err != nil || !bytes.Equal(got, plain) {
			t.Fatalf("n=%d open: %v", n, err)
		}
	}
}

func TestBuckets(t *testing.T) {
	k := newKey(t)
	sizes := map[int]bool{}
	for _, n := range []int{10, 500, 1000, 2000} {
		blob, err := Seal(k.Public(), "p", bytes.Repeat([]byte("a"), n))
		if err != nil {
			t.Fatal(err)
		}
		sizes[len(blob)] = true
	}
	if len(sizes) != 1 {
		t.Fatalf("small payloads leak size: %v", sizes)
	}
	big := make([]byte, 20_000)
	rand.Read(big)
	b1, _ := Seal(k.Public(), "p", big)
	if len(b1) < 64<<10 || len(b1) > 64<<10+4096 {
		t.Fatalf("20 KB random payload should fall in the 64 KB bucket, got %d", len(b1))
	}
}

func TestWrongKeyProjectTamperTruncate(t *testing.T) {
	k, other := newKey(t), newKey(t)
	blob, _ := Seal(k.Public(), "p", []byte("secret"))
	if _, err := Open(other, "p", blob); !errors.Is(err, ErrOpen) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := Open(k, "q", blob); !errors.Is(err, ErrOpen) {
		t.Fatalf("wrong project: %v", err)
	}
	for _, i := range []int{0, 1500, len(blob) - 1} {
		c := bytes.Clone(blob)
		c[i] ^= 1
		if _, err := Open(k, "p", c); err == nil {
			t.Fatalf("tamper at %d accepted", i)
		}
	}
	if _, err := Open(k, "p", blob[:len(blob)-1]); err == nil {
		t.Fatal("truncated blob accepted")
	}
	if _, err := Open(k, "p", nil); err == nil {
		t.Fatal("empty blob accepted")
	}
}

func TestSealsDiffer(t *testing.T) {
	k := newKey(t)
	a, _ := Seal(k.Public(), "p", []byte("x"))
	b, _ := Seal(k.Public(), "p", []byte("x"))
	if bytes.Equal(a, b) {
		t.Fatal("two seals identical")
	}
}

func TestCaps(t *testing.T) {
	k := newKey(t)
	if _, err := Seal(k.Public(), "p", make([]byte, MaxPlain+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("plain cap: %v", err)
	}
	if _, err := Open(k, "p", make([]byte, MaxBlob+1)); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("blob cap: %v", err)
	}
	// Incompressible input near the frame cap must be refused, not truncated.
	big := make([]byte, 800<<10)
	rand.Read(big)
	if _, err := Seal(k.Public(), "p", big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("frame cap: %v", err)
	}
	// Largest accepted blob stays under MaxBlob.
	ok := make([]byte, 740<<10)
	rand.Read(ok)
	blob, err := Seal(k.Public(), "p", ok)
	if err != nil || len(blob) > MaxBlob {
		t.Fatalf("near-cap seal: len=%d err=%v", len(blob), err)
	}
}

func TestKeyStrings(t *testing.T) {
	k := newKey(t)
	s := k.Public().String()
	if !strings.HasPrefix(s, KeyPrefix) {
		t.Fatal(s)
	}
	p, err := ParsePublic(" " + s + "\n")
	if err != nil || p.Fingerprint() != k.Public().Fingerprint() || len(p.Fingerprint()) != 16 {
		t.Fatalf("parse: %v", err)
	}
	for _, bad := range []string{"", "ldk2.AAAA", "ldk1.", "ldk1.!!!", "ldk1.AAAA"} {
		if _, err := ParsePublic(bad); !errors.Is(err, ErrKey) {
			t.Fatalf("%q: %v", bad, err)
		}
	}
	b, err := k.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ParsePrivate(b)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := Seal(k.Public(), "p", []byte("hi"))
	if got, err := Open(k2, "p", blob); err != nil || string(got) != "hi" {
		t.Fatalf("restored key: %v", err)
	}
	if _, err := ParsePrivate([]byte("short")); !errors.Is(err, ErrKey) {
		t.Fatal(err)
	}
}

// The golden vector pins the wire format: a future release must keep opening
// it. Regenerate only on a deliberate format change: LD_GOLDEN=1 go test ./seal.
func TestGolden(t *testing.T) {
	const path = "../testdata/golden.txt"
	if os.Getenv("LD_GOLDEN") == "1" {
		k := newKey(t)
		priv, _ := k.Bytes()
		blob, err := Seal(k.Public(), "golden", []byte("golden payload"))
		if err != nil {
			t.Fatal(err)
		}
		out := hex.EncodeToString(priv) + "\n" + hex.EncodeToString(blob) + "\n"
		if err := os.WriteFile(path, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Fields(string(raw))
	priv, _ := hex.DecodeString(lines[0])
	blob, _ := hex.DecodeString(lines[1])
	k, err := ParsePrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(k, "golden", blob)
	if err != nil || string(got) != "golden payload" {
		t.Fatalf("golden: %q %v", got, err)
	}
}

func FuzzOpen(f *testing.F) {
	k, err := Generate()
	if err != nil {
		f.Fatal(err)
	}
	blob, _ := Seal(k.Public(), "p", []byte("seed"))
	f.Add(blob)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		if out, err := Open(k, "p", b); err == nil && !bytes.Equal(b, blob) && len(out) > MaxPlain {
			t.Fatal("oversized output")
		}
	})
}
