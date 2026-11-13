// SPDX-License-Identifier: AGPL-3.0-only

package render

import (
	"strings"
	"testing"
	"time"

	"github.com/payam-foundation/log-decypher/envelope"
)

func TestCleanStripsEscapes(t *testing.T) {
	got := Clean("a\x1b[31mred\x1b[0m\r\nb\tc\x00")
	if strings.ContainsAny(got, "\x1b\r\x00") || !strings.Contains(got, "\n") || !strings.Contains(got, "\t") {
		t.Fatalf("%q", got)
	}
}

func TestMarkdown(t *testing.T) {
	e := &envelope.Envelope{
		Project: "demo", Kind: "report", ID: "ABCD2345", Created: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Meta:     map[string]string{"b": "x|y", "a": "1"},
		Sections: []envelope.Section{{Name: "log", Data: "line ```inside``` \x1b[2J\nsecond\n"}},
	}
	md := Markdown(e, "0011223344556677")
	for _, want := range []string{"# demo ABCD2345", "2026-01-02 03:04:05Z", "| a | 1 |", `x\|y`, "````\nline", "second\n````"} {
		if !strings.Contains(md, want) {
			t.Errorf("missing %q in:\n%s", want, md)
		}
	}
	if strings.Contains(md, "\x1b") {
		t.Fatal("escape survived")
	}
	if strings.Index(md, "| a |") > strings.Index(md, "| b |") {
		t.Fatal("meta not sorted")
	}
}
