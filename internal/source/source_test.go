// SPDX-License-Identifier: AGPL-3.0-only

package source

import (
	"bytes"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/payam-foundation/log-decypher/armor"
)

var blob = bytes.Repeat([]byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01}, 900)

func has(blobs [][]byte, want []byte) bool {
	for _, b := range blobs {
		if bytes.Equal(b, want) {
			return true
		}
	}
	return false
}

func b64wrap(b []byte) string {
	s := base64.StdEncoding.EncodeToString(b)
	var out strings.Builder
	for len(s) > 76 {
		out.WriteString(s[:76] + "\r\n")
		s = s[76:]
	}
	return out.String() + s + "\r\n"
}

func eml(body string) string {
	return "From: u@example.com\r\nTo: report@example.com\r\nSubject: Support request ABCD\r\nMIME-Version: 1.0\r\n" + body
}

func TestRawAndArmor(t *testing.T) {
	if got := Extract(blob); !has(got, blob) {
		t.Fatal("raw blob lost")
	}
	if got := Extract([]byte("hello\n" + armor.Encode(blob))); !has(got, blob) {
		t.Fatal("armor lost")
	}
	if got := Extract(nil); len(got) != 0 {
		t.Fatal("empty input produced blobs")
	}
}

func TestEMLAttachment(t *testing.T) {
	m := eml("Content-Type: multipart/mixed; boundary=XX\r\n\r\n--XX\r\nContent-Type: text/plain\r\n\r\nplease help\r\n--XX\r\n" +
		"Content-Type: application/octet-stream; name=r-ABCD.dat\r\nContent-Transfer-Encoding: base64\r\n" +
		"Content-Disposition: attachment; filename=r-ABCD.dat\r\n\r\n" + b64wrap(blob) + "--XX--\r\n")
	if got := Extract([]byte(m)); !has(got, blob) {
		t.Fatalf("attachment lost: %d candidates", len(got))
	}
}

func TestEMLArmoredBodyQuotedPrintable(t *testing.T) {
	a := strings.ReplaceAll(armor.Encode(blob), "=", "=3D")
	m := eml("Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" + strings.ReplaceAll(a, "\n", "\r\n"))
	if got := Extract([]byte(m)); !has(got, blob) {
		t.Fatal("armored body lost")
	}
}

func TestNestedForward(t *testing.T) {
	inner := eml("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64wrap(blob))
	outer := eml("Content-Type: message/rfc822\r\n\r\n" + inner)
	if got := Extract([]byte(outer)); !has(got, blob) {
		t.Fatal("forwarded attachment lost")
	}
}

func TestMbox(t *testing.T) {
	other := bytes.Repeat([]byte{1, 2, 3}, 2000)
	mk := func(b []byte) string {
		return "From a@example.com Mon Jan  1 00:00:00 2026\r\n" + eml("Content-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n"+b64wrap(b)) + "\r\n"
	}
	got := Extract([]byte(mk(blob) + mk(other)))
	if !has(got, blob) || !has(got, other) {
		t.Fatalf("mbox: %d candidates", len(got))
	}
}

func TestLoadDirAndStdin(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "a.dat"), blob, 0o600)
	os.WriteFile(filepath.Join(dir, ".hidden"), blob, 0o600)
	os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte(armor.Encode(blob)), 0o600)
	items := Load(dir, nil)
	if len(items) != 2 {
		t.Fatalf("want 2 files, got %d", len(items))
	}
	for _, it := range items {
		if it.Err != nil || !has(it.Blobs, blob) {
			t.Fatalf("%s: %v", it.Path, it.Err)
		}
	}
	if it := Load("-", bytes.NewReader(blob)); !has(it[0].Blobs, blob) {
		t.Fatal("stdin")
	}
	if it := Load(filepath.Join(dir, "missing"), nil); it[0].Err == nil {
		t.Fatal("missing path not reported")
	}
}

func FuzzEML(f *testing.F) {
	f.Add([]byte(eml("Content-Type: multipart/mixed; boundary=XX\r\n\r\n--XX\r\n\r\nx\r\n--XX--\r\n")))
	f.Add([]byte("From a Mon\r\n\r\nFrom b Tue\r\nSubject: x\r\n\r\ny"))
	f.Add([]byte(armor.Encode(blob)))
	f.Fuzz(func(t *testing.T, b []byte) { Extract(b) })
}
