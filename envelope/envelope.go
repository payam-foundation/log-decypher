// SPDX-License-Identifier: AGPL-3.0-only

// Package envelope is the generic payload carried inside a sealed blob: one
// report from one project, as a metadata map plus named sections of data.
package envelope

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Caps bound what Unmarshal accepts so a forged report cannot exhaust memory.
const (
	MaxSections = 32
	MaxMeta     = 64
	MaxString   = 256
)

// Section is one named block of data, for example the log lines.
type Section struct {
	Name string `json:"name"`
	MIME string `json:"mime,omitempty"`
	Data string `json:"data"`
}

// Envelope is the decrypted payload.
type Envelope struct {
	Project  string            `json:"project"`
	Kind     string            `json:"kind"`
	ID       string            `json:"id"`
	Created  time.Time         `json:"created"`
	Meta     map[string]string `json:"meta,omitempty"`
	Sections []Section         `json:"sections,omitempty"`
}

var (
	reName = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	reID   = regexp.MustCompile(`^[A-Za-z0-9]{4,32}$`)
)

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("envelope: invalid")

func bad(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Validate checks names, sizes and counts. The ID is used as a file name by
// decypher, so it is restricted to letters and digits.
func (e *Envelope) Validate() error {
	if !reName.MatchString(e.Project) {
		return bad("project")
	}
	if !reName.MatchString(e.Kind) {
		return bad("kind")
	}
	if !reID.MatchString(e.ID) {
		return bad("id")
	}
	if e.Created.IsZero() {
		return bad("created")
	}
	if len(e.Meta) > MaxMeta {
		return bad("too many meta entries")
	}
	for k, v := range e.Meta {
		if len(k) > MaxString || len(v) > MaxString {
			return bad("meta entry too long")
		}
	}
	if len(e.Sections) > MaxSections {
		return bad("too many sections")
	}
	for _, s := range e.Sections {
		if !reName.MatchString(s.Name) {
			return bad("section name")
		}
		if len(s.MIME) > MaxString {
			return bad("section mime")
		}
	}
	return nil
}

// Marshal validates and encodes e.
func Marshal(e *Envelope) ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

// Unmarshal decodes and validates. Unknown fields are rejected.
func Unmarshal(b []byte) (*Envelope, error) {
	var e Envelope
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&e); err != nil {
		return nil, bad("%v", err)
	}
	if d.More() {
		return nil, bad("trailing data")
	}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return &e, nil
}
