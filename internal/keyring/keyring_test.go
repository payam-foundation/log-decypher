// SPDX-License-Identifier: AGPL-3.0-only

package keyring

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/payam-foundation/log-decypher/seal"
)

func init() { LogN = 10 }

func TestSaveLoadOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kr")
	k := &Keyring{}
	_, pub, err := k.Add("demo")
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Save(path, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if _, err := Load(path, []byte("nope")); !errors.Is(err, ErrPassphrase) {
		t.Fatalf("wrong pass: %v", err)
	}
	k2, err := Load(path, []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := seal.Seal(pub, "demo", []byte("hello"))
	plain, e, err := k2.Open(blob)
	if err != nil || string(plain) != "hello" || e.Fingerprint != pub.Fingerprint() {
		t.Fatalf("open: %v", err)
	}
	other, _ := seal.Seal(pub, "other", []byte("x"))
	if _, _, err := k2.Open(other); err == nil {
		t.Fatal("project binding ignored")
	}
}

func TestTamperAndGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kr")
	k := &Keyring{}
	k.Add("demo")
	if err := k.Save(path, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	for _, i := range []int{3, 6, 10, hdrLen + 2, len(raw) - 1} {
		c := bytes.Clone(raw)
		c[i] ^= 1
		os.WriteFile(path, c, 0o600)
		if _, err := Load(path, []byte("pw")); err == nil {
			t.Fatalf("tamper at %d accepted", i)
		}
	}
	os.WriteFile(path, []byte("garbage"), 0o600)
	if _, err := Load(path, []byte("pw")); err == nil {
		t.Fatal("garbage accepted")
	}
	if err := k.Save(path, nil); err == nil {
		t.Fatal("empty passphrase accepted")
	}
}

func TestRotationRetiredStillOpens(t *testing.T) {
	k := &Keyring{}
	_, oldPub, _ := k.Add("demo")
	old, _ := seal.Seal(oldPub, "demo", []byte("old"))
	e2, newPub, _ := k.Add("demo")
	if err := k.Retire(oldPub.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	if k.Entries[0].Status != StatusRetired || k.Entries[1].Status != statusOK || e2.Fingerprint != newPub.Fingerprint() {
		t.Fatal("status")
	}
	if p, _, err := k.Open(old); err != nil || string(p) != "old" {
		t.Fatalf("retired key must still open: %v", err)
	}
	if k.Retire("zzzz") == nil {
		t.Fatal("unknown fingerprint accepted")
	}
}
