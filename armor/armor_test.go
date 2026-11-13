// SPDX-License-Identifier: AGPL-3.0-only

package armor

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	for _, n := range []int{1, 57, 58, 5000} {
		b := make([]byte, n)
		rand.Read(b)
		s := Encode(b)
		for _, l := range strings.Split(strings.TrimSpace(s), "\n")[1:] {
			if len(l) > width && l != end {
				t.Fatalf("line too long: %d", len(l))
			}
		}
		got, err := Decode(s)
		if err != nil || !bytes.Equal(got, b) {
			t.Fatalf("n=%d: %v", n, err)
		}
	}
}

func TestDecodeMessy(t *testing.T) {
	b := []byte("some blob bytes that are long enough to wrap onto lines, yes yes yes yes yes yes")
	quoted := "Hi,\n> " + strings.ReplaceAll(Encode(b), "\n", "\n> ") + "\nthanks"
	got, err := Decode(quoted)
	if err != nil || !bytes.Equal(got, b) {
		t.Fatalf("quoted: %v", err)
	}
	for _, bad := range []string{"", "no block", begin + "\nabc", begin + "\n!!!\n" + end, begin + "\n" + end} {
		if _, err := Decode(bad); err != ErrNoBlock {
			t.Errorf("%q: %v", bad, err)
		}
	}
}

func FuzzArmor(f *testing.F) {
	f.Add(Encode([]byte("seed")))
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		if b, err := Decode(s); err == nil {
			if got, err := Decode(Encode(b)); err != nil || !bytes.Equal(got, b) {
				t.Fatal("re-encode mismatch")
			}
		}
	})
}
