// SPDX-License-Identifier: AGPL-3.0-only

// Package armor is a text form of a sealed blob, for pasting into chat apps
// when no mail client is available.
package armor

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
)

const (
	begin = "-----BEGIN LOG-----"
	end   = "-----END LOG-----"
	width = 76
)

// ErrNoBlock means no armored block was found or its base64 was invalid.
var ErrNoBlock = errors.New("armor: no block")

// Encode wraps blob in BEGIN/END markers with 76-column base64 lines.
func Encode(blob []byte) string {
	s := base64.StdEncoding.EncodeToString(blob)
	var b strings.Builder
	b.WriteString(begin + "\n")
	for len(s) > width {
		b.WriteString(s[:width] + "\n")
		s = s[width:]
	}
	b.WriteString(s + "\n" + end + "\n")
	return b.String()
}

// Decode finds the first armored block in text and returns its bytes. Quote
// prefixes (">"), indentation and stray whitespace from mail clients and chat
// apps are ignored.
func Decode(text string) ([]byte, error) {
	i := strings.Index(text, begin)
	if i < 0 {
		return nil, ErrNoBlock
	}
	rest := text[i+len(begin):]
	j := strings.Index(rest, end)
	if j < 0 {
		return nil, ErrNoBlock
	}
	var clean bytes.Buffer
	for _, r := range rest[:j] {
		switch {
		case r == '>' || r == ' ' || r == '\t' || r == '\r' || r == '\n':
		default:
			clean.WriteRune(r)
		}
	}
	b, err := base64.StdEncoding.DecodeString(clean.String())
	if err != nil || len(b) == 0 {
		return nil, ErrNoBlock
	}
	return b, nil
}
