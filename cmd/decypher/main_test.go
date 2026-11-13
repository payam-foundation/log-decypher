// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/payam-foundation/log-decypher/armor"
	"github.com/payam-foundation/log-decypher/envelope"
	"github.com/payam-foundation/log-decypher/internal/keyring"
	"github.com/payam-foundation/log-decypher/seal"
)

func init() { keyring.LogN = 10 }

type env struct {
	t       *testing.T
	dir     string
	keyring string
	out     bytes.Buffer
	err     bytes.Buffer
}

func newEnv(t *testing.T) *env {
	d := t.TempDir()
	return &env{t: t, dir: d, keyring: filepath.Join(d, "kr")}
}

func (e *env) run(args ...string) int {
	e.out.Reset()
	e.err.Reset()
	c := &cli{stdin: strings.NewReader(""), stdout: &e.out, stderr: &e.err, now: time.Now,
		pass: func(bool) ([]byte, error) { return []byte("pw"), nil }}
	return c.run(context.Background(), args)
}

func (e *env) keygen(project string) *seal.PublicKey {
	e.t.Helper()
	pubFile := filepath.Join(e.dir, project+".pub")
	if code := e.run("keygen", "--project", project, "--keyring", e.keyring, "--pub-out", pubFile); code != 0 {
		e.t.Fatalf("keygen: %d %s", code, e.err.String())
	}
	b, _ := os.ReadFile(pubFile)
	pub, err := seal.ParsePublic(string(b))
	if err != nil {
		e.t.Fatal(err)
	}
	return pub
}

func sealed(t *testing.T, pub *seal.PublicKey, project, id string) []byte {
	t.Helper()
	b, err := envelope.Marshal(&envelope.Envelope{Project: project, Kind: "report", ID: id, Created: time.Now().UTC(),
		Meta: map[string]string{"os": "linux"}, Sections: []envelope.Section{{Name: "log", Data: "hello world"}}})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := seal.Seal(pub, project, b)
	if err != nil {
		t.Fatal(err)
	}
	return blob
}

func TestKeygenOpenVerify(t *testing.T) {
	e := newEnv(t)
	pub := e.keygen("demo")
	dat := filepath.Join(e.dir, "in", "r-ABCD2345.dat")
	os.MkdirAll(filepath.Dir(dat), 0o700)
	os.WriteFile(dat, sealed(t, pub, "demo", "ABCD2345"), 0o600)
	junk := filepath.Join(e.dir, "in", "spam.dat")
	os.WriteFile(junk, bytes.Repeat([]byte{7}, 5000), 0o600)

	if code := e.run("verify", dat, "--keyring", e.keyring); code != 0 || !strings.HasPrefix(e.out.String(), "ok ABCD2345 demo ") {
		t.Fatalf("verify: %d %q", code, e.out.String())
	}
	if code := e.run("verify", junk, "--keyring", e.keyring); code != 2 {
		t.Fatalf("verify junk: %d", code)
	}
	outDir := filepath.Join(e.dir, "out")
	if code := e.run("open", filepath.Dir(dat), "--keyring", e.keyring, "--out", outDir); code != 0 {
		t.Fatalf("open: %d %s", code, e.err.String())
	}
	day := time.Now().UTC().Format("2006-01-02")
	md, err := os.ReadFile(filepath.Join(outDir, "demo", day, "ABCD2345.md"))
	if err != nil || !strings.Contains(string(md), "hello world") {
		t.Fatalf("md: %v", err)
	}
	st, _ := os.Stat(filepath.Join(outDir, "demo", day, "ABCD2345.json"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", st.Mode())
	}
	if !strings.Contains(e.err.String(), "opened 1, skipped 1") {
		t.Fatalf("summary: %q", e.err.String())
	}
	// Second open must not overwrite.
	e.run("open", dat, "--keyring", e.keyring, "--out", outDir)
	if _, err := os.Stat(filepath.Join(outDir, "demo", day, "ABCD2345-2.md")); err != nil {
		t.Fatal("second open overwrote or skipped")
	}
	if code := e.run("open", dat, "--keyring", e.keyring, "--stdout"); code != 0 || !strings.Contains(e.out.String(), "hello world") {
		t.Fatalf("stdout: %d", code)
	}
	if code := e.run("open", junk, "--keyring", e.keyring, "--stdout"); code != 2 {
		t.Fatalf("nothing decrypted must exit 2, got %d", code)
	}
}

func TestEmlAndArmorInputs(t *testing.T) {
	e := newEnv(t)
	pub := e.keygen("demo")
	blob := sealed(t, pub, "demo", "MAIL2345")
	att := base64.StdEncoding.EncodeToString(blob)
	eml := "From: u@example.com\r\nSubject: Support request MAIL2345\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n" +
		"--B\r\nContent-Type: text/plain\r\n\r\nhi\r\n--B\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n" + att + "\r\n--B--\r\n"
	p := filepath.Join(e.dir, "m.eml")
	os.WriteFile(p, []byte(eml), 0o600)
	txt := filepath.Join(e.dir, "chat.txt")
	os.WriteFile(txt, []byte("> "+strings.ReplaceAll(armor.Encode(sealed(t, pub, "demo", "CHAT2345")), "\n", "\n> ")), 0o600)
	if code := e.run("verify", p, txt, "--keyring", e.keyring); code != 0 || !strings.Contains(e.out.String(), "MAIL2345") || !strings.Contains(e.out.String(), "CHAT2345") {
		t.Fatalf("verify: %d %q", code, e.out.String())
	}
}

func TestRotationAndRetire(t *testing.T) {
	e := newEnv(t)
	old := e.keygen("demo")
	oldBlob := sealed(t, old, "demo", "OLD12345")
	cur := e.keygen("demo") // rotates: old becomes retired
	p := filepath.Join(e.dir, "old.dat")
	os.WriteFile(p, oldBlob, 0o600)
	if code := e.run("verify", p, "--keyring", e.keyring); code != 0 {
		t.Fatalf("retired key must still open: %d %q", code, e.out.String())
	}
	e.run("keys", "list", "--keyring", e.keyring)
	lines := strings.Split(strings.TrimSpace(e.out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "retired") || !strings.Contains(lines[1], "active") || !strings.Contains(lines[1], cur.Fingerprint()) {
		t.Fatalf("list: %q", lines)
	}
	if code := e.run("keys", "retire", cur.Fingerprint(), "--keyring", e.keyring); code != 0 {
		t.Fatalf("retire: %d %s", code, e.err.String())
	}
	if code := e.run("keys", "retire", "nope", "--keyring", e.keyring); code != 1 {
		t.Fatalf("retire unknown: %d", code)
	}
}

func TestProjectMismatchAndBadArgs(t *testing.T) {
	e := newEnv(t)
	pub := e.keygen("demo")
	// Sealed for project "demo" but the envelope claims another project.
	b, _ := envelope.Marshal(&envelope.Envelope{Project: "other", Kind: "report", ID: "ABCD2345", Created: time.Now()})
	blob, _ := seal.Seal(pub, "demo", b)
	p := filepath.Join(e.dir, "x.dat")
	os.WriteFile(p, blob, 0o600)
	if code := e.run("verify", p, "--keyring", e.keyring); code != 2 || !strings.Contains(e.out.String(), "does not match") {
		t.Fatalf("%d %q", code, e.out.String())
	}
	for _, args := range [][]string{
		{}, {"bogus"}, {"keygen"}, {"keygen", "--project", "Bad Name", "--keyring", e.keyring},
		{"open", p, "--keyring", e.keyring}, {"open", p, "--keyring", e.keyring, "--out", "x", "--stdout"}, {"verify", "--keyring", e.keyring},
	} {
		if code := e.run(args...); code != 1 {
			t.Errorf("%v: exit %d", args, code)
		}
	}
}

func TestOldAndFutureReportsRejected(t *testing.T) {
	e := newEnv(t)
	pub := e.keygen("demo")
	for name, ts := range map[string]time.Time{"old": time.Now().Add(-400 * 24 * time.Hour), "future": time.Now().Add(72 * time.Hour)} {
		b, _ := envelope.Marshal(&envelope.Envelope{Project: "demo", Kind: "report", ID: "ABCD2345", Created: ts})
		blob, _ := seal.Seal(pub, "demo", b)
		p := filepath.Join(e.dir, name+".dat")
		os.WriteFile(p, blob, 0o600)
		if code := e.run("verify", p, "--keyring", e.keyring); code != 2 {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestWatchDedupes(t *testing.T) {
	e := newEnv(t)
	pub := e.keygen("demo")
	in, out := filepath.Join(e.dir, "in"), filepath.Join(e.dir, "out")
	os.MkdirAll(in, 0o700)
	blob := sealed(t, pub, "demo", "WATCH234")
	os.WriteFile(filepath.Join(in, "a.dat"), blob, 0o600)
	os.WriteFile(filepath.Join(in, "b.dat"), blob, 0o600) // same blob, different name
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	c := &cli{stdin: strings.NewReader(""), stdout: &e.out, stderr: &e.err, now: time.Now,
		pass: func(bool) ([]byte, error) { return []byte("pw"), nil }}
	if code := c.run(ctx, []string{"watch", in, "--keyring", e.keyring, "--out", out, "--interval", "100ms"}); code != 0 {
		t.Fatalf("watch: %d %s", code, e.err.String())
	}
	if n := strings.Count(e.out.String(), "opened WATCH234"); n != 1 {
		t.Fatalf("opened %d times:\n%s", n, e.out.String())
	}
	for _, n := range []string{"a.dat", "b.dat"} {
		if _, err := os.Stat(filepath.Join(in, "done", n)); err != nil {
			t.Errorf("%s not in done/", n)
		}
	}
}

func TestCheckProject(t *testing.T) {
	for _, ok := range []string{"a", "dotvpn", "a-b_c.1"} {
		if checkProject(ok) != nil {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", "-a", "A", "a b", "a/b", strings.Repeat("a", 65)} {
		if checkProject(bad) == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
