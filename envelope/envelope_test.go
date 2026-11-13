// SPDX-License-Identifier: AGPL-3.0-only

package envelope

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func sample() *Envelope {
	return &Envelope{
		Project: "demo", Kind: "report", ID: "ABCD2345",
		Created:  time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Meta:     map[string]string{"os": "linux"},
		Sections: []Section{{Name: "log", MIME: "text/plain", Data: "hello"}},
	}
}

func TestRoundTrip(t *testing.T) {
	b, err := Marshal(sample())
	if err != nil {
		t.Fatal(err)
	}
	e, err := Unmarshal(b)
	if err != nil || e.ID != "ABCD2345" || e.Sections[0].Data != "hello" || !e.Created.Equal(sample().Created) {
		t.Fatalf("%+v %v", e, err)
	}
}

func TestInvalid(t *testing.T) {
	cases := map[string]func(*Envelope){
		"project":  func(e *Envelope) { e.Project = "Bad Name" },
		"kind":     func(e *Envelope) { e.Kind = "" },
		"id":       func(e *Envelope) { e.ID = "../etc" },
		"created":  func(e *Envelope) { e.Created = time.Time{} },
		"section":  func(e *Envelope) { e.Sections[0].Name = "A/B" },
		"metalong": func(e *Envelope) { e.Meta["k"] = strings.Repeat("x", MaxString+1) },
		"sections": func(e *Envelope) { e.Sections = make([]Section, MaxSections+1) },
	}
	for name, mut := range cases {
		e := sample()
		mut(e)
		if _, err := Marshal(e); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestUnmarshalStrict(t *testing.T) {
	good, _ := Marshal(sample())
	for _, in := range []string{"", "{}", "null", string(good) + " {}", strings.Replace(string(good), `"kind"`, `"extra":1,"kind"`, 1)} {
		if _, err := Unmarshal([]byte(in)); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v", in, err)
		}
	}
}

func FuzzEnvelope(f *testing.F) {
	good, _ := Marshal(sample())
	f.Add(good)
	f.Add([]byte("{"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if e, err := Unmarshal(b); err == nil {
			if err := e.Validate(); err != nil {
				t.Fatal(err)
			}
		}
	})
}
