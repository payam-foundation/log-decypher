// SPDX-License-Identifier: AGPL-3.0-only

// Package render turns an envelope into markdown for an operator to read.
package render

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/payam-foundation/log-decypher/envelope"
)

// Clean replaces control characters (except tab and newline) so decrypted,
// attacker-controllable text cannot drive a terminal with escape sequences.
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r == '\r' {
			return -1
		}
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return '\uFFFD'
		}
		return r
	}, s)
}

// Markdown renders the meta table and every section as a fenced block.
func Markdown(e *envelope.Envelope, fingerprint string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s %s\n\n", Clean(e.Project), Clean(e.ID))
	fmt.Fprintf(&b, "- kind: %s\n- created: %s\n- key: %s\n\n", Clean(e.Kind), e.Created.UTC().Format("2006-01-02 15:04:05Z"), fingerprint)
	if len(e.Meta) > 0 {
		keys := make([]string, 0, len(e.Meta))
		for k := range e.Meta {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("| key | value |\n|---|---|\n")
		for _, k := range keys {
			fmt.Fprintf(&b, "| %s | %s |\n", cell(k), cell(e.Meta[k]))
		}
		b.WriteString("\n")
	}
	for _, s := range e.Sections {
		data := Clean(s.Data)
		fence := "```"
		for strings.Contains(data, fence) {
			fence += "`"
		}
		fmt.Fprintf(&b, "## %s\n\n%s\n%s\n%s\n\n", Clean(s.Name), fence, strings.TrimRight(data, "\n"), fence)
	}
	return b.String()
}

func cell(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ").Replace(Clean(s))
}
